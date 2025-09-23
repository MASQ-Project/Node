// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
use crate::accountant::db_access_objects::utils;
use crate::accountant::db_access_objects::utils::{
    sum_i128_values_from_table, to_unix_timestamp, AssemblerFeeder, CustomQuery, DaoFactoryReal,
    PayableAccountWithTxInfo, RangeStmConfig, RowId, TopStmConfig, VigilantRusqliteFlatten,
};
use crate::accountant::db_big_integer::big_int_db_processor::KeyVariants::WalletAddress;
use crate::accountant::db_big_integer::big_int_db_processor::{
    BigIntDbProcessor, BigIntDbProcessorReal, BigIntSqlConfig, DisplayableRusqliteParamPair,
    ParamByUse, SQLParamsBuilder, TableNameDAO, WeiChange, WeiChangeDirection,
};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use ethabi::Address;
#[cfg(test)]
use itertools::Either;
use masq_lib::messages::CurrentTxInfo;
use masq_lib::utils::ExpectValue;
#[cfg(test)]
use rusqlite::OptionalExtension;
use rusqlite::{Error, Row};
use std::fmt::Debug;
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq, Eq)]
pub enum PayableDaoError {
    SignConversion(u128),
    RusqliteError(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance_wei: u128,
    pub last_paid_timestamp: SystemTime,
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount_minor: u128,
    ) -> Result<(), PayableDaoError>;

    fn transactions_confirmed(&self, confirmed_payables: &[SentTx]) -> Result<(), PayableDaoError>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;

    fn custom_query(&self, custom_query: CustomQuery<u64>)
        -> Option<Vec<PayableAccountWithTxInfo>>;

    fn total(&self) -> u128;

    #[cfg(test)]
    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount>;
}

pub trait PayableDaoFactory {
    fn make(&self) -> Box<dyn PayableDao>;
}

impl PayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PayableDao> {
        Box::new(PayableDaoReal::new(self.make_connection()))
    }
}

pub struct MarkPendingPayableID {
    pub receiver_wallet: Address,
    pub rowid: RowId,
}

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    big_int_db_processor: BigIntDbProcessorReal<Self>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(
        &self,
        timestamp: SystemTime,
        wallet: &Wallet,
        amount_minor: u128,
    ) -> Result<(), PayableDaoError> {
        let main_sql = "insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) \
                values (:wallet, :balance_high_b, :balance_low_b, :last_paid_timestamp, null) on conflict (wallet_address) do update set \
                balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where wallet_address = :wallet";
        let update_clause_with_compensated_overflow = "update payable set \
                balance_high_b = :balance_high_b, balance_low_b = :balance_low_b where wallet_address = :wallet";

        let last_paid_timestamp = to_unix_timestamp(timestamp);
        let params = SQLParamsBuilder::default()
            .key(WalletAddress(wallet))
            .wei_change(WeiChange::new(
                "balance",
                amount_minor,
                WeiChangeDirection::Addition,
            ))
            .other_params(vec![ParamByUse::BeforeOverflowOnly(
                DisplayableRusqliteParamPair::new(":last_paid_timestamp", &last_paid_timestamp),
            )])
            .build();

        self.big_int_db_processor.execute(
            Either::Left(self.conn.as_ref()),
            BigIntSqlConfig::new(main_sql, update_clause_with_compensated_overflow, params),
        )?;

        Ok(())
    }

    fn transactions_confirmed(&self, confirmed_payables: &[SentTx]) -> Result<(), PayableDaoError> {
        confirmed_payables.iter().try_for_each(|confirmed_payable| {
            let main_sql = "update payable set \
                    balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b, \
                    last_paid_timestamp = :last_paid, pending_payable_rowid = null where wallet_address = :wallet";
            let update_clause_with_compensated_overflow = "update payable set \
                    balance_high_b = :balance_high_b, balance_low_b = :balance_low_b, last_paid_timestamp = :last_paid, \
                    pending_payable_rowid = null where wallet_address = :wallet";

            let wallet = format!("{:?}", confirmed_payable.receiver_address);
            let params = SQLParamsBuilder::default()
                .key( WalletAddress(&wallet))
                .wei_change(WeiChange::new("balance", confirmed_payable.amount_minor, WeiChangeDirection::Subtraction))
                .other_params(vec![ParamByUse::BeforeAndAfterOverflow(DisplayableRusqliteParamPair::new(":last_paid", &confirmed_payable.timestamp))])
                .build();

            self.big_int_db_processor.execute(Either::Left(self.conn.as_ref()), BigIntSqlConfig::new(
                main_sql,
                update_clause_with_compensated_overflow,
                params))?;

            Ok(())
        })
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let sql = "\
        select wallet_address, balance_high_b, balance_low_b, last_paid_timestamp from \
        payable where pending_payable_rowid is null";
        let mut stmt = self.conn.prepare(sql).expect("Internal error");
        stmt.query_map([], |row| {
            let wallet_result: Result<Wallet, Error> = row.get(0);
            let high_b_result: Result<i64, Error> = row.get(1);
            let low_b_result: Result<i64, Error> = row.get(2);
            let last_paid_timestamp_result = row.get(3);
            match (
                wallet_result,
                high_b_result,
                low_b_result,
                last_paid_timestamp_result,
            ) {
                (Ok(wallet), Ok(high_b), Ok(low_b), Ok(last_paid_timestamp)) => {
                    Ok(PayableAccount {
                        wallet,
                        balance_wei: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                            high_b, low_b,
                        )),
                        last_paid_timestamp: utils::from_unix_timestamp(last_paid_timestamp),
                    })
                }
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .vigilant_flatten()
        .collect()
    }

    fn custom_query(
        &self,
        custom_query: CustomQuery<u64>,
    ) -> Option<Vec<PayableAccountWithTxInfo>> {
        let variant_top = TopStmConfig{
            limit_clause: "limit :limit_count",
            gwei_min_resolution_clause: "where (balance_high_b > 0) or ((balance_high_b = 0) and (balance_low_b >= 1000000000))",
            age_ordering_clause: "last_paid_timestamp asc",
        };
        let variant_range = RangeStmConfig {
            where_clause: "where ((last_paid_timestamp <= :max_timestamp) and (last_paid_timestamp >= :min_timestamp)) \
            and ((balance_high_b > :min_balance_high_b) or ((balance_high_b = :min_balance_high_b) and (balance_low_b >= :min_balance_low_b))) \
            and ((balance_high_b < :max_balance_high_b) or ((balance_high_b = :max_balance_high_b) and (balance_low_b <= :max_balance_low_b)))",
            gwei_min_resolution_clause: "and ((balance_high_b > 0) or ((balance_high_b = 0) and (balance_low_b >= 1000000000)))",
            secondary_order_param: "last_paid_timestamp asc"
        };

        custom_query.query::<_, i64, _, _>(
            self.conn.as_ref(),
            Self::stm_assembler_of_payable_cq,
            variant_top,
            variant_range,
            Self::create_payable_account_with_tx_info,
        )
    }

    fn total(&self) -> u128 {
        let value_completer = |row_number: usize, row: &Row| {
            let high_bytes = row.get::<usize, i64>(0).expectv("high bytes");
            let low_bytes = row.get::<usize, i64>(1).expectv("low_bytes");
            let big_int = BigIntDivider::reconstitute(high_bytes, low_bytes);
            if high_bytes < 0 {
                panic!(
                    "database corrupted: found negative value {} in payable table for row id {}",
                    big_int, row_number
                )
            };
            Ok(big_int)
        };
        sign_conversion::<i128, u128>(sum_i128_values_from_table(
            self.conn.as_ref(),
            &Self::table_name(),
            "balance",
            value_completer,
        ))
        .unwrap_or_else(|num| {
            panic!(
                "database corrupted: negative sum ({}) in payable table",
                num
            )
        })
    }

    #[cfg(test)]
    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        let stm = "\
            select balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid \
            from payable \
            where wallet_address = ?";
        let mut stmt = self.conn.prepare(stm).unwrap();
        stmt.query_row(&[&wallet], |row| {
            let high_bytes_result = row.get(0);
            let low_bytes_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            match (
                high_bytes_result,
                low_bytes_result,
                last_paid_timestamp_result,
            ) {
                (Ok(high_bytes), Ok(low_bytes), Ok(last_paid_timestamp)) => Ok(PayableAccount {
                    wallet: wallet.clone(),
                    balance_wei: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                        high_bytes, low_bytes,
                    )),
                    last_paid_timestamp: utils::from_unix_timestamp(last_paid_timestamp),
                }),
                e => panic!(
                    "Database is corrupt: PAYABLE table columns and/or types: {:?}",
                    e
                ),
            }
        })
        .optional()
        .unwrap()
    }
}

impl PayableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> PayableDaoReal {
        PayableDaoReal {
            conn,
            big_int_db_processor: BigIntDbProcessorReal::default(),
        }
    }

    fn create_payable_account_with_tx_info(
        row: &Row,
    ) -> rusqlite::Result<PayableAccountWithTxInfo> {
        let wallet_result: Result<Wallet, Error> = row.get(0);
        let balance_high_bytes_result = row.get(1);
        let balance_low_bytes_result = row.get(2);
        let last_paid_timestamp_result = row.get(3);
        let tx_hash_opt_result = row.get(4);
        let previous_failures = row.get(5);
        match (
            wallet_result,
            balance_high_bytes_result,
            balance_low_bytes_result,
            last_paid_timestamp_result,
            tx_hash_opt_result,
            previous_failures,
        ) {
            (
                Ok(wallet),
                Ok(high_bytes),
                Ok(low_bytes),
                Ok(last_paid_timestamp),
                Ok(tx_hash_opt),
                Ok(previous_failures),
            ) => Ok(PayableAccountWithTxInfo {
                account: PayableAccount {
                    wallet,
                    balance_wei: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                        high_bytes, low_bytes,
                    )),
                    last_paid_timestamp: utils::from_unix_timestamp(last_paid_timestamp),
                },
                tx_opt: Self::maybe_construct_tx_info(tx_hash_opt, previous_failures),
            }),
            e => panic!(
                "Database is corrupt: PAYABLE table columns and/or types: {:?}",
                e
            ),
        }
    }

    fn maybe_construct_tx_info(
        tx_hash_opt: Option<String>,
        previous_failures: usize,
    ) -> Option<CurrentTxInfo> {
        if tx_hash_opt.is_some() || previous_failures > 0 {
            Some(CurrentTxInfo {
                pending_tx_hash_opt: tx_hash_opt.map(|tx_hash_str| {
                    H256::from_str(&tx_hash_str[2..])
                        .unwrap_or_else(|_| panic!("Wrong tx hash format: {}", tx_hash_str))
                }),
                failures: previous_failures,
            })
        } else {
            None
        }
    }

    fn stm_assembler_of_payable_cq(feeder: AssemblerFeeder) -> String {
        let stm = format!(
            "SELECT
            p.wallet_address,
            p.balance_high_b,
            p.balance_low_b,
            p.last_paid_timestamp,
            CASE WHEN s.status LIKE '%Pending%'
                THEN s.tx_hash
                ELSE NULL
            END AS pending_tx_hash,
            /*
               The following case stm counts the failing attempts for a tx processing that hasn't
               ended yet and is ongoing.
            */
            CASE WHEN EXISTS (
                    SELECT 1
                    FROM failed_payable
                    WHERE status NOT LIKE '%Concluded%'
                        AND receiver_address = p.wallet_address
                )
                THEN (
                    WITH nonces_of_failures_by_wallet AS
                    (
                        SELECT nonce
                        FROM failed_payable
                        WHERE receiver_address = p.wallet_address
                    )
                    SELECT COUNT(*)
                    FROM nonces_of_failures_by_wallet
                    WHERE nonce = (SELECT MAX(nonce) FROM nonces_of_failures_by_wallet)
                )
                ELSE 0
            END AS recent_failures_count
        FROM
            payable p
        LEFT JOIN
            sent_payable s on p.wallet_address = s.receiver_address
        {} {}
        ORDER BY
           {},
           {}
        {}",
            feeder.main_where_clause,
            feeder.where_clause_extension,
            feeder.order_by_first_param,
            feeder.order_by_second_param,
            feeder.limit_clause
        );
        eprintln!("{}", stm);
        stm
    }
}

impl TableNameDAO for PayableDaoReal {
    fn table_name() -> String {
        String::from("payable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDao, FailedPayableDaoReal, FailedTx, FailureStatus,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{
        SentPayableDao, SentPayableDaoReal, SentTx, TxStatus,
    };
    use crate::accountant::db_access_objects::utils::{
        current_unix_timestamp, from_unix_timestamp, to_unix_timestamp, TxHash,
    };
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::{
        assert_account_creation_fn_fails_on_finding_wrong_columns_and_value_types, make_failed_tx,
        make_sent_tx, trick_rusqlite_with_read_only_conn,
    };
    use crate::blockchain::errors::validation_status::ValidationStatus;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use masq_lib::messages::CurrentTxInfo;
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use rusqlite::ToSql;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_new_address",
        );
        let now = SystemTime::now();
        let wallet = make_wallet("booga");
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(boxed_conn);

        subject.more_money_payable(now, &wallet, 1234).unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, 1234);
        assert_eq!(
            to_unix_timestamp(status.last_paid_timestamp),
            to_unix_timestamp(now)
        );
    }

    #[test]
    fn more_money_payable_works_for_existing_address_without_overflow() {
        //asserting on correctness of the main sql clause
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_existing_address_without_overflow",
        );
        let wallet = make_wallet("booga");
        let wallet_unchanged_account = make_wallet("hurrah");
        let now = SystemTime::now();
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let initial_value = 1234;
        //in db (0, 1234)
        let balance_change = 2345;
        //in db (0, 2345)
        let subject = PayableDaoReal::new(boxed_conn);
        let prepare_account = |wallet: &Wallet, initial_value| {
            subject
                .more_money_payable(SystemTime::UNIX_EPOCH, wallet, initial_value)
                .unwrap();
        };
        prepare_account(&wallet, initial_value);
        //making sure the SQL will not affect a different wallet
        prepare_account(&wallet_unchanged_account, 12345);

        subject
            .more_money_payable(now, &wallet, balance_change)
            .unwrap();

        let assert_account = |wallet, expected_balance| {
            let status = subject.account_status(&wallet).unwrap();
            assert_eq!(status.wallet, wallet);
            assert_eq!(status.balance_wei, expected_balance);
            assert_eq!(
                to_unix_timestamp(status.last_paid_timestamp),
                to_unix_timestamp(SystemTime::UNIX_EPOCH)
            );
        };
        assert_account(wallet, initial_value + balance_change);
        assert_account(wallet_unchanged_account, 12345);
    }

    #[test]
    fn more_money_payable_works_for_existing_address_hitting_overflow() {
        //asserting on correctness of the overflow update clause
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_existing_address_hitting_overflow",
        );
        let wallet = make_wallet("booga");
        let now = SystemTime::now();
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let initial_value = i64::MAX as u128 - 1000;
        //in db (0, i64::MAX - 1000)
        let balance_change = 2345;
        //in db (0, 2345)
        let subject = PayableDaoReal::new(boxed_conn);
        subject
            .more_money_payable(SystemTime::UNIX_EPOCH, &wallet, initial_value)
            .unwrap();

        subject
            .more_money_payable(now, &wallet, balance_change)
            .unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, initial_value + balance_change);
        assert_eq!(
            to_unix_timestamp(status.last_paid_timestamp),
            to_unix_timestamp(SystemTime::UNIX_EPOCH)
        );
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn more_money_payable_works_for_128_bits_value_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_128_bits_value_overflow",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_payable(SystemTime::now(), &wallet, u128::MAX);
    }

    #[test]
    fn more_money_payable_handles_error() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "more_money_payable_handles_error");
        let wallet = make_wallet("booga");
        let conn = payable_read_only_conn(&home_dir);
        let wrapped_conn = ConnectionWrapperReal::new(conn);
        let subject = PayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.more_money_payable(SystemTime::now(), &wallet, 123456);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError("Error from invalid upsert command for payable table \
            and change of 123456 wei to 'wallet_address = 0x000000000000000000000000000000626f6f6761' \
            with error 'attempt to write a readonly database'".to_string())
            )
        )
    }

    struct TestSetupValuesHolder {
        account_1: TxWalletAndTimestamp,
        account_2: TxWalletAndTimestamp,
    }

    struct TxWalletAndTimestamp {
        pending_payable: SentTx,
        previous_timestamp: SystemTime,
    }

    struct TestInputs {
        hash: TxHash,
        previous_timestamp: SystemTime,
        new_payable_timestamp: SystemTime,
        receiver_wallet: Address,
        initial_amount_wei: u128,
        balance_change: u128,
    }

    fn insert_initial_payable_records_and_return_sent_txs(
        conn: &dyn ConnectionWrapper,
        (initial_amount_1, balance_change_1): (u128, u128),
        (initial_amount_2, balance_change_2): (u128, u128),
    ) -> TestSetupValuesHolder {
        let now = SystemTime::now();
        let (account_1, account_2) = [
            TestInputs {
                hash: make_tx_hash(12345),
                previous_timestamp: now.checked_sub(Duration::from_secs(45_000)).unwrap(),
                new_payable_timestamp: now.checked_sub(Duration::from_secs(2)).unwrap(),
                receiver_wallet: make_wallet("bobbles").address(),
                initial_amount_wei: initial_amount_1,
                balance_change: balance_change_1,
            },
            TestInputs {
                hash: make_tx_hash(54321),
                previous_timestamp: now.checked_sub(Duration::from_secs(22_000)).unwrap(),
                new_payable_timestamp: now.checked_sub(Duration::from_secs(2)).unwrap(),
                receiver_wallet: make_wallet("yet more bobbles").address(),
                initial_amount_wei: initial_amount_2,
                balance_change: balance_change_2,
            },
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, test_inputs)| {
            insert_payable_record_fn(
                conn,
                &format!("{:?}", test_inputs.receiver_wallet),
                i128::try_from(test_inputs.initial_amount_wei).unwrap(),
                to_unix_timestamp(test_inputs.previous_timestamp),
            );
            let mut sent_tx = make_sent_tx((idx as u64 + 1) * 1234);
            sent_tx.hash = test_inputs.hash;
            sent_tx.amount_minor = test_inputs.balance_change;
            sent_tx.receiver_address = test_inputs.receiver_wallet;
            sent_tx.timestamp = to_unix_timestamp(test_inputs.new_payable_timestamp);
            sent_tx.amount_minor = test_inputs.balance_change;

            TxWalletAndTimestamp {
                pending_payable: sent_tx,
                previous_timestamp: test_inputs.previous_timestamp,
            }
        })
        .collect_tuple()
        .unwrap();

        TestSetupValuesHolder {
            account_1,
            account_2,
        }
    }

    #[test]
    fn transaction_confirmed_works_without_overflow() {
        //asserting on the main sql
        let initial = i64::MAX as u128 + 10000;
        //initial (1, 9999)
        let initial_changing_end_resulting_values = (initial, 11111, initial as u128 - 11111);
        //change (-1, abs(i64::MIN) - 11111)
        test_transaction_confirmed_works(
            "transaction_confirmed_works_without_overflow",
            initial_changing_end_resulting_values,
        )
    }

    #[test]
    fn transaction_confirmed_works_hitting_overflow() {
        //asserting on the overflow update clause
        let initial_changing_end_resulting_values = (10000, 111, 10000 - 111);
        //initial (0, 10000)
        //change (-1, abs(i64::MIN) - 111)
        //10000 + (abs(i64::MIN) - 111) > i64::MAX -> overflow
        test_transaction_confirmed_works(
            "transaction_confirmed_works_hitting_overflow",
            initial_changing_end_resulting_values,
        )
    }

    fn test_transaction_confirmed_works(
        test_name: &str,
        (initial_amount_1, balance_change_1, expected_balance_after_1): (u128, u128, u128),
    ) {
        let home_dir = ensure_node_home_directory_exists("payable_dao", test_name);
        // A hardcoded set that just makes a complement to the crucial, supplied first one; this
        // shows the ability to handle multiple transactions together
        let initial_amount_2 = 5_678_901;
        let balance_change_2 = 678_902;
        let expected_balance_after_2 = 4_999_999;
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let setup_holder = insert_initial_payable_records_and_return_sent_txs(
            boxed_conn.as_ref(),
            (initial_amount_1, balance_change_1),
            (initial_amount_2, balance_change_2),
        );
        let subject = PayableDaoReal::new(boxed_conn);
        let wallet_1 = Wallet::from(setup_holder.account_1.pending_payable.receiver_address);
        let wallet_2 = Wallet::from(setup_holder.account_2.pending_payable.receiver_address);
        let status_1_before_opt = subject.account_status(&wallet_1);
        let status_2_before_opt = subject.account_status(&wallet_2);

        let result = subject.transactions_confirmed(&[
            setup_holder.account_1.pending_payable.clone(),
            setup_holder.account_2.pending_payable.clone(),
        ]);

        assert_eq!(result, Ok(()));
        let expected_last_paid_timestamp_1 =
            from_unix_timestamp(to_unix_timestamp(setup_holder.account_1.previous_timestamp));
        let expected_last_paid_timestamp_2 =
            from_unix_timestamp(to_unix_timestamp(setup_holder.account_2.previous_timestamp));
        let expected_status_before_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: initial_amount_1,
            last_paid_timestamp: expected_last_paid_timestamp_1,
        };
        let expected_status_before_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: initial_amount_2,
            last_paid_timestamp: expected_last_paid_timestamp_2,
        };
        let expected_resulting_status_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: expected_balance_after_1,
            last_paid_timestamp: from_unix_timestamp(
                setup_holder.account_1.pending_payable.timestamp,
            ),
        };
        let expected_resulting_status_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: expected_balance_after_2,
            last_paid_timestamp: from_unix_timestamp(
                setup_holder.account_2.pending_payable.timestamp,
            ),
        };
        assert_eq!(status_1_before_opt, Some(expected_status_before_1));
        assert_eq!(status_2_before_opt, Some(expected_status_before_2));
        let resulting_account_1_opt = subject.account_status(&wallet_1);
        assert_eq!(resulting_account_1_opt, Some(expected_resulting_status_1));
        let resulting_account_2_opt = subject.account_status(&wallet_2);
        assert_eq!(resulting_account_2_opt, Some(expected_resulting_status_2))
    }

    #[test]
    fn transaction_confirmed_works_for_generic_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_generic_sql_error",
        );
        let conn = payable_read_only_conn(&home_dir);
        let conn_wrapped = Box::new(ConnectionWrapperReal::new(conn));
        let mut confirmed_transaction = make_sent_tx(5);
        confirmed_transaction.amount_minor = 12345;
        let wallet_address = confirmed_transaction.receiver_address;
        let subject = PayableDaoReal::new(conn_wrapped);

        let result = subject.transactions_confirmed(&[confirmed_transaction]);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(format!(
                "Error from invalid update command for payable table and change of -12345 wei to \
                 'wallet_address = {:?}' with error 'attempt to write a readonly database'",
                wallet_address
            )))
        )
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn transaction_confirmed_works_for_overflow_from_sent_tx_record() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_overflow_from_sent_tx_record",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let mut sent_tx = make_sent_tx(456);
        sent_tx.amount_minor = u128::MAX;
        //The overflow occurs before we start modifying the payable account so we can have the database empty

        let _ = subject.transactions_confirmed(&[sent_tx]);
    }

    #[test]
    fn transaction_confirmed_returns_error_from_another_cycle_which_happens_to_fail() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_returns_error_from_another_cycle_which_happens_to_fail",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let setup_holder = insert_initial_payable_records_and_return_sent_txs(
            conn.as_ref(),
            (1_111_111, 111_111),
            (2_222_222, 222_222),
        );
        let wallet_1 = Wallet::from(setup_holder.account_1.pending_payable.receiver_address);
        let wallet_2 = Wallet::from(setup_holder.account_2.pending_payable.receiver_address);
        conn.prepare("delete from payable where wallet_address = ?")
            .unwrap()
            .execute(&[&wallet_2.to_string()])
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.transactions_confirmed(&[
            setup_holder.account_1.pending_payable,
            setup_holder.account_2.pending_payable,
        ]);

        let expected_err_msg = format!(
            "Expected 1 row to be changed for the unique key \
                {} but got this count: 0",
            wallet_2
        );
        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(expected_err_msg))
        );
        let expected_resulting_balance_1 = 1_111_111 - 111_111;
        let account_1 = subject.account_status(&wallet_1).unwrap();
        assert_eq!(account_1.balance_wei, expected_resulting_balance_1);
        let account_2_opt = subject.account_status(&wallet_2);
        assert_eq!(account_2_opt, None);
    }

    #[test]
    fn non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let result = subject.non_pending_payables();

        assert_eq!(result, vec![]);
    }

    #[test]
    fn non_pending_payables_should_return_payables_with_no_pending_transaction() {
        // TODO waits for the merge from GH-605
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "non_pending_payables_should_return_payables_with_no_pending_transaction",
        // );
        // let subject = PayableDaoReal::new(
        //     DbInitializerReal::default()
        //         .initialize(&home_dir, DbInitializationConfig::test_default())
        //         .unwrap(),
        // );
        // let mut flags = OpenFlags::empty();
        // flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        // let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        // let conn = ConnectionWrapperReal::new(conn);
        // let insert = |wallet: &str, pending_payable_rowid: Option<i64>| {
        //     insert_payable_record_fn(
        //         &conn,
        //         wallet,
        //         1234567890123456,
        //         111_111_111,
        //         pending_payable_rowid,
        //     );
        // };
        // insert("0x0000000000000000000000000000000000666f6f", Some(15));
        // insert(&make_wallet("foobar").to_string(), None);
        // insert("0x0000000000000000000000000000000000626172", Some(16));
        // insert(&make_wallet("barfoo").to_string(), None);
        //
        // let result = subject.non_pending_payables();
        //
        // assert_eq!(
        //     result,
        //     vec![
        //         PayableAccount {
        //             wallet: make_wallet("foobar"),
        //             balance_wei: 1234567890123456 as u128,
        //             last_paid_timestamp: from_unix_timestamp(111_111_111),
        //         },
        //         PayableAccount {
        //             wallet: make_wallet("barfoo"),
        //             balance_wei: 1234567890123456 as u128,
        //             last_paid_timestamp: from_unix_timestamp(111_111_111),
        //         },
        //     ]
        // );
    }

    #[test]
    fn custom_query_handles_empty_table_in_top_records_mode() {
        let main_test_setup =
            |payable_dao_real: PayableDaoReal, _: SentPayableDaoReal, _: FailedPayableDaoReal| {
                payable_dao_real
            };
        let subject = custom_query_test_body_for_payable(
            "custom_query_handles_empty_table_in_top_records_mode",
            main_test_setup,
        );

        let result = subject.custom_query(CustomQuery::TopRecords {
            count: 6,
            ordered_by: Balance,
        });

        assert_eq!(result, None)
    }

    fn insert_payable_record_fn(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
        balance: i128,
        timestamp: i64,
    ) {
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(balance);
        let params: &[&dyn ToSql] = &[&wallet, &high_bytes, &low_bytes, &timestamp];
        conn
            .prepare("insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp) values (?, ?, ?, ?)")
            .unwrap()
            .execute(params)
            .unwrap();
    }

    fn accounts_for_tests_of_top_records(
        now: i64,
    ) -> Box<dyn FnOnce(PayableDaoReal, SentPayableDaoReal, FailedPayableDaoReal) -> PayableDaoReal>
    {
        Box::new(
            move |payable_dao_real: PayableDaoReal,
                  _: SentPayableDaoReal,
                  _: FailedPayableDaoReal| {
                let insert_payable = |unix_time: i64, wallet_addr: &str, amount_minor: u128| {
                    payable_dao_real
                        .more_money_payable(
                            from_unix_timestamp(unix_time),
                            &Wallet::new(wallet_addr),
                            amount_minor,
                        )
                        .unwrap()
                };
                insert_payable(
                    now - 86_401,
                    "0x1111111111111111111111111111111111111111",
                    1_000_000_002,
                );
                insert_payable(
                    now - 86_001,
                    "0x2222222222222222222222222222222222222222",
                    7_562_000_300_000,
                );
                insert_payable(
                    now - 86_000,
                    "0x3333333333333333333333333333333333333333",
                    999_999_999, //balance smaller than 1 gwei
                );
                insert_payable(
                    now - 86_300,
                    "0x4444444444444444444444444444444444444444",
                    10_000_000_100,
                );
                insert_payable(
                    now - 86_401,
                    "0x5555555555555555555555555555555555555555",
                    10_000_000_100,
                );

                payable_dao_real
            },
        )
    }

    #[test]
    fn custom_query_in_top_records_mode_with_default_ordering() {
        // Accounts of balances smaller than one gwei don't qualify.
        // Two accounts differ only in the debt age but not the balance, which allows checking
        // double ordering, primarily by balance and then age.
        let now = current_unix_timestamp();
        let main_test_setup = accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_payable(
            "custom_query_in_top_records_mode_with_default_ordering",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::TopRecords {
                count: 3,
                ordered_by: Balance,
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                        balance_wei: 7_562_000_300_000,
                        last_paid_timestamp: from_unix_timestamp(now - 86_001),
                    },
                    tx_opt: None
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                        balance_wei: 10_000_000_100,
                        last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    },
                    tx_opt: None
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                        balance_wei: 10_000_000_100,
                        last_paid_timestamp: from_unix_timestamp(now - 86_300),
                    },
                    tx_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_in_top_records_mode_ordered_by_age() {
        // Accounts of balances smaller than one gwei don't qualify.
        // Two accounts differ only in the debt age but not the balance, which allows checking
        // double ordering, primarily by balance and then age.
        let now = current_unix_timestamp();
        let main_test_setup = accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_payable(
            "custom_query_in_top_records_mode_ordered_by_age",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::TopRecords {
                count: 3,
                ordered_by: Age,
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                        balance_wei: 10_000_000_100,
                        last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    },
                    tx_opt: None
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                        balance_wei: 1_000_000_002,
                        last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    },
                    tx_opt: None
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                        balance_wei: 10_000_000_100,
                        last_paid_timestamp: from_unix_timestamp(now - 86_300),
                    },
                    tx_opt: None
                }
            ]
        );
    }

    #[test]
    fn custom_query_top_records_mode_can_report_tx_info() {
        let now = current_unix_timestamp();
        let wallet_addr = "0x1111111111111111111111111111111111111111";
        let mut sent_tx_1 = make_sent_tx(789);
        sent_tx_1.receiver_address = Wallet::new(wallet_addr).address();
        let sent_tx_hash_1 = sent_tx_1.hash;
        let wallet_addr = "0x3333333333333333333333333333333333333333";
        let mut sent_tx_2 = make_sent_tx(345);
        sent_tx_2.receiver_address = Wallet::new(wallet_addr).address();
        let sent_tx_hash_2 = sent_tx_2.hash;
        let mut failed_tx_1 = make_failed_tx(123);
        let wallet_addr = "0x2222222222222222222222222222222222222222";
        failed_tx_1.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_1.status = FailureStatus::Concluded;
        failed_tx_1.nonce = 99;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_2.nonce = 99;
        failed_tx_2.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        // Will be ignored as it is not of the highest nonce for this wallet
        let mut failed_tx_3 = make_failed_tx(678);
        failed_tx_3.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_3.nonce = 98;
        failed_tx_3.status = FailureStatus::Concluded;
        let mut failed_tx_4 = make_failed_tx(567);
        let wallet_addr = "0x3333333333333333333333333333333333333333";
        failed_tx_4.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_4.status = FailureStatus::RetryRequired;
        failed_tx_4.nonce = 100;
        let main_test_setup = Box::new(
            move |payable_dao_real: PayableDaoReal,
                  sent_payable_dao_real: SentPayableDaoReal,
                  failed_payable_dao_real: FailedPayableDaoReal| {
                let insert_payable = |unix_time: i64, wallet_addr: &str, amount_minor: u128| {
                    payable_dao_real
                        .more_money_payable(
                            from_unix_timestamp(unix_time),
                            &Wallet::new(wallet_addr),
                            amount_minor,
                        )
                        .unwrap()
                };
                insert_payable(
                    now - 80_000,
                    "0x1111111111111111111111111111111111111111",
                    222_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x2222222222222222222222222222222222222222",
                    333_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x3333333333333333333333333333333333333333",
                    111_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x4444444444444444444444444444444444444444",
                    1_000_000_000,
                );
                failed_payable_dao_real
                    .insert_new_records(&vec![failed_tx_1, failed_tx_2, failed_tx_3, failed_tx_4])
                    .unwrap();
                sent_payable_dao_real
                    .insert_new_records(&vec![sent_tx_1, sent_tx_2])
                    .unwrap();
                payable_dao_real
            },
        );
        let subject = custom_query_test_body_for_payable(
            "custom_query_top_records_mode_can_report_tx_info",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::TopRecords {
                count: 3,
                ordered_by: Balance,
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                        balance_wei: 333_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: None,
                        failures: 2
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                        balance_wei: 222_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: Some(sent_tx_hash_1),
                        failures: 0
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                        balance_wei: 111_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: Some(sent_tx_hash_2),
                        failures: 1
                    })
                }
            ]
        );
    }

    #[test]
    fn custom_query_range_mode_can_report_tx_info() {
        let now = current_unix_timestamp();
        let wallet_addr = "0x2222222222222222222222222222222222222222";
        let mut sent_tx_1 = make_sent_tx(789);
        sent_tx_1.receiver_address = Wallet::new(wallet_addr).address();
        let sent_tx_hash_1 = sent_tx_1.hash;
        let wallet_addr = "0x4444444444444444444444444444444444444444";
        let mut sent_tx_2 = make_sent_tx(345);
        sent_tx_2.receiver_address = Wallet::new(wallet_addr).address();
        let sent_tx_hash_2 = sent_tx_2.hash;
        let mut failed_tx_1 = make_failed_tx(123);
        let wallet_addr = "0x3333333333333333333333333333333333333333";
        failed_tx_1.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_1.nonce = 99;
        let wallet_addr = "0x2222222222222222222222222222222222222222";
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_2.nonce = 100;
        let mut failed_tx_3 = make_failed_tx(567);
        failed_tx_3.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_3.nonce = 100;
        let mut failed_tx_4 = make_failed_tx(222);
        let wallet_addr = "0x5555555555555555555555555555555555555555";
        failed_tx_4.receiver_address = Wallet::new(wallet_addr).address();
        failed_tx_4.nonce = 98;
        failed_tx_4.status = FailureStatus::Concluded;
        let main_test_setup = Box::new(
            move |payable_dao_real: PayableDaoReal,
                  sent_payable_dao_real: SentPayableDaoReal,
                  failed_payable_dao_real: FailedPayableDaoReal| {
                let insert_payable = |unix_time: i64, wallet_addr: &str, amount_minor: u128| {
                    payable_dao_real
                        .more_money_payable(
                            from_unix_timestamp(unix_time),
                            &Wallet::new(wallet_addr),
                            amount_minor,
                        )
                        .unwrap()
                };
                insert_payable(
                    now - 80_000,
                    "0x1111111111111111111111111111111111111111",
                    5_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x2222222222222222222222222222222222222222",
                    4_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x3333333333333333333333333333333333333333",
                    3_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x4444444444444444444444444444444444444444",
                    2_000_000_000,
                );
                insert_payable(
                    now - 80_000,
                    "0x5555555555555555555555555555555555555555",
                    1_000_000_000,
                );
                failed_payable_dao_real
                    .insert_new_records(&vec![failed_tx_1, failed_tx_2, failed_tx_3, failed_tx_4])
                    .unwrap();
                sent_payable_dao_real
                    .insert_new_records(&vec![sent_tx_1, sent_tx_2])
                    .unwrap();
                payable_dao_real
            },
        );
        let subject = custom_query_test_body_for_payable(
            "custom_query_range_mode_can_report_tx_info",
            main_test_setup,
        );

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                max_age_s: 80_100,
                min_age_s: 79_900,
                max_amount_gwei: 4,
                min_amount_gwei: 1,
                timestamp: from_unix_timestamp(now),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                        balance_wei: 4_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: Some(sent_tx_hash_1),
                        failures: 2
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                        balance_wei: 3_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: None,
                        failures: 1
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                        balance_wei: 2_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: Some(sent_tx_hash_2),
                        failures: 0
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                        balance_wei: 1_000_000_000,
                        last_paid_timestamp: from_unix_timestamp(now - 80_000),
                    },
                    // No CurrentTxInfo despite existing FailedTx records (The record has the failure
                    // status = 'Concluded')
                    tx_opt: None
                }
            ]
        );
    }

    #[test]
    fn custom_query_handles_empty_table_in_range_mode() {
        let main_test_setup =
            |payable_dao: PayableDaoReal, _: SentPayableDaoReal, _: FailedPayableDaoReal| {
                payable_dao
            };
        let subject = custom_query_test_body_for_payable(
            "custom_query_handles_empty_table_in_range_mode",
            main_test_setup,
        );

        let result = subject.custom_query(CustomQuery::RangeQuery {
            min_age_s: 20000,
            max_age_s: 200000,
            min_amount_gwei: 500000000,
            max_amount_gwei: 3500000000,
            timestamp: SystemTime::now(),
        });

        assert_eq!(result, None)
    }

    #[test]
    fn custom_query_in_range_mode() {
        // Two accounts differ only in the debt age but not the balance which allows to check double
        // ordering, primarily by balance and then age.
        let now = current_unix_timestamp();
        let main_setup = |payable_dao: PayableDaoReal,
                          sent_payable_dao: SentPayableDaoReal,
                          _: FailedPayableDaoReal| {
            let insert_payable_record = |time: i64, wallet_addr: &str, amount: u64| {
                payable_dao
                    .more_money_payable(
                        from_unix_timestamp(time),
                        &Wallet::new(wallet_addr),
                        gwei_to_wei::<_, u64>(amount), //too small
                    )
                    .unwrap();
            };
            insert_payable_record(
                now - 70_000,
                "0x1111111111111111111111111111111111111111",
                499_999_999, //too small
            );
            insert_payable_record(
                now - 55_120,
                "0x2222222222222222222222222222222222222222",
                1_800_456_000,
            );
            insert_payable_record(
                now - 200_001, //too old
                "0x3333333333333333333333333333333333333333",
                600_123_456,
            );
            insert_payable_record(
                now - 19_999, //too young
                "0x4444444444444444444444444444444444444444",
                1_033_456_000,
            );
            insert_payable_record(
                now - 30_786,
                "0x5555555555555555555555555555555555555555",
                35_000_000_001, //too big
            );
            insert_payable_record(
                now - 100_401,
                "0x6666666666666666666666666666666666666666",
                1_800_456_000,
            );
            insert_payable_record(
                now - 80_333,
                "0x7777777777777777777777777777777777777777",
                2_500_647_000,
            );
            sent_payable_dao
                .insert_new_records(&vec![SentTx {
                    hash: make_tx_hash(0xABC),
                    receiver_address: Wallet::new("0x6666666666666666666666666666666666666666")
                        .address(),
                    amount_minor: 0,
                    timestamp: 0,
                    gas_price_minor: 0,
                    nonce: 0,
                    status: TxStatus::Pending(ValidationStatus::Waiting),
                }])
                .unwrap();
            payable_dao
        };
        let subject = custom_query_test_body_for_payable("custom_query_in_range_mode", main_setup);

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 20000,
                max_age_s: 200000,
                min_amount_gwei: 500_000_000,
                max_amount_gwei: 35_000_000_000,
                timestamp: from_unix_timestamp(now),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x7777777777777777777777777777777777777777"),
                        balance_wei: gwei_to_wei(2_500_647_000_u32),
                        last_paid_timestamp: from_unix_timestamp(now - 80_333),
                    },
                    tx_opt: None
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                        balance_wei: gwei_to_wei(1_800_456_000_u32),
                        last_paid_timestamp: from_unix_timestamp(now - 100_401),
                    },
                    tx_opt: Some(CurrentTxInfo {
                        pending_tx_hash_opt: Some(make_tx_hash(0xABC)),
                        failures: 0
                    })
                },
                PayableAccountWithTxInfo {
                    account: PayableAccount {
                        wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                        balance_wei: gwei_to_wei(1_800_456_000_u32),
                        last_paid_timestamp: from_unix_timestamp(now - 55_120),
                    },
                    tx_opt: None
                },
            ]
        );
    }

    #[test]
    fn range_query_does_not_display_values_from_below_1_gwei() {
        let now = current_unix_timestamp();
        let timestamp_1 = from_unix_timestamp(now - 11_001);
        let timestamp_2 = from_unix_timestamp(now - 5000);
        let main_setup =
            |payable_dao: PayableDaoReal, _: SentPayableDaoReal, _: FailedPayableDaoReal| {
                payable_dao
                    .more_money_payable(
                        timestamp_1,
                        &Wallet::new("0x1111111111111111111111111111111111111111"),
                        400_005_601,
                    )
                    .unwrap();
                payable_dao
                    .more_money_payable(
                        timestamp_2,
                        &Wallet::new("0x2222222222222222222222222222222222222222"),
                        30_000_300_000,
                    )
                    .unwrap();
                payable_dao
            };
        let subject = custom_query_test_body_for_payable(
            "range_query_does_not_display_values_from_below_1_gwei",
            main_setup,
        );

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 0,
                max_age_s: 200000,
                min_amount_gwei: u64::MIN,
                max_amount_gwei: 35,
                timestamp: SystemTime::now(),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![PayableAccountWithTxInfo {
                account: PayableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 30_000_300_000,
                    last_paid_timestamp: timestamp_2,
                },
                tx_opt: None
            }]
        )
    }

    #[test]
    fn total_works() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "total_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let timestamp = utils::current_unix_timestamp();
        insert_payable_record_fn(
            &*conn,
            "0x1111111111111111111111111111111111111111",
            999_999_999,
            timestamp - 1000,
        );
        insert_payable_record_fn(
            &*conn,
            "0x2222222222222222222222222222222222222222",
            1_000_123_123,
            timestamp - 2000,
        );
        insert_payable_record_fn(
            &*conn,
            "0x3333333333333333333333333333333333333333",
            1_000_000_000,
            timestamp - 3000,
        );
        insert_payable_record_fn(
            &*conn,
            "0x4444444444444444444444444444444444444444",
            1_000_000_001,
            timestamp - 4000,
        );
        let subject = PayableDaoReal::new(conn);

        let total = subject.total();

        assert_eq!(total, 4_000_123_123)
    }

    #[test]
    #[should_panic(
        expected = "database corrupted: found negative value -999999 in payable table for row id 2"
    )]
    fn total_takes_negative_value_as_error() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "total_takes_negative_value_as_error");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        insert_payable_record_fn(
            &*conn,
            "0x1111111111111111111111111111111111111111",
            123_456,
            111_111_111,
        );
        insert_payable_record_fn(
            &*conn,
            "0x2222222222222222222222222222222222222222",
            -999_999,
            222_222_222,
        );
        let subject = PayableDaoReal::new(conn);

        let _ = subject.total();
    }

    #[test]
    fn correctly_totals_zero_records() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "correctly_totals_zero_records");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: PAYABLE table columns and/or types: (Err(FromSqlConversionFailure(0, Text, InvalidAddress)), Err(InvalidColumnIndex(1))"
    )]
    fn create_payable_account_panics_on_database_error() {
        assert_account_creation_fn_fails_on_finding_wrong_columns_and_value_types(
            PayableDaoReal::create_payable_account_with_tx_info,
        );
    }

    #[test]
    fn payable_dao_implements_dao_table_identifier() {
        assert_eq!(PayableDaoReal::table_name(), "payable")
    }

    fn payable_read_only_conn(path: &Path) -> Connection {
        trick_rusqlite_with_read_only_conn(path, DbInitializerReal::create_payable_table)
    }

    fn custom_query_test_body_for_payable<F>(test_name: &str, main_setup_fn: F) -> PayableDaoReal
    where
        F: FnOnce(PayableDaoReal, SentPayableDaoReal, FailedPayableDaoReal) -> PayableDaoReal,
    {
        let home_dir = ensure_node_home_directory_exists("payable_dao", test_name);
        let conn = || {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap()
        };
        let failed_payable_dao = FailedPayableDaoReal::new(conn());
        let sent_payable_dao = SentPayableDaoReal::new(conn());
        let payable_dao = PayableDaoReal::new(conn());
        main_setup_fn(payable_dao, sent_payable_dao, failed_payable_dao)
    }

    #[test]
    fn maybe_construct_tx_info_with_tx_hash_present_and_no_errors() {
        let tx_hash = make_tx_hash(123);

        let result = PayableDaoReal::maybe_construct_tx_info(Some(format!("{:?}", tx_hash)), 0);

        assert_eq!(
            result,
            Some(CurrentTxInfo {
                pending_tx_hash_opt: Some(tx_hash),
                failures: 0
            })
        );
    }

    #[test]
    fn maybe_construct_tx_info_with_tx_hash_present_and_also_errors() {
        let tx_hash = make_tx_hash(123);
        let errors = 3;

        let result =
            PayableDaoReal::maybe_construct_tx_info(Some(format!("{:?}", tx_hash)), errors);

        assert_eq!(
            result,
            Some(CurrentTxInfo {
                pending_tx_hash_opt: Some(make_tx_hash(123)),
                failures: errors
            })
        );
    }

    #[test]
    fn maybe_construct_tx_info_with_only_errors_present() {
        let errors = 1;

        let result = PayableDaoReal::maybe_construct_tx_info(None, errors);

        assert_eq!(
            result,
            Some(CurrentTxInfo {
                pending_tx_hash_opt: None,
                failures: errors
            })
        );
    }

    #[test]
    fn maybe_construct_tx_info_returns_none() {
        let result = PayableDaoReal::maybe_construct_tx_info(None, 0);

        assert_eq!(result, None);
    }
}
