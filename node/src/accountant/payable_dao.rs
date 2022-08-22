// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::big_int_db_processor::WeiChange::{Addition, Subtraction};
use crate::accountant::big_int_db_processor::{
    collect_and_sum_i128_values_from_table, BigIntDbProcessor, BigIntDivider, BigIntSqlConfig,
    DAOTableIdentifier, SQLParamsBuilder,
};
use crate::accountant::dao_utils;
use crate::accountant::dao_utils::{
    to_time_t, AssemblerFeeder, CustomQuery, DaoFactoryReal, RangeStmConfig, TopStmConfig,
};
use crate::accountant::{checked_conversion, sign_conversion, PendingPayableId};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
#[cfg(test)]
use ethereum_types::{BigEndianHash, U256};
use itertools::Either::Left;
use masq_lib::utils::ExpectValue;
use rusqlite::types::ToSql;
#[cfg(test)]
use rusqlite::OptionalExtension;
use rusqlite::{Error, Row};
use std::fmt::Debug;
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq)]
pub enum PayableDaoError {
    SignConversion(u64),
    RusqliteError(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance_wei: u128,
    pub last_paid_timestamp: SystemTime,
    pub pending_payable_opt: Option<PendingPayableId>,
}

//TODO two to three of these fields can be technically eliminated now but I think my old plan was not to do that because it could be potentially a useful set of information,
// I somehow didn't trust unconditionally to the pending payable record to be always secure - and so I still think this might wait for GH-576
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payable {
    pub to: Wallet,
    pub amount: u128,
    pub timestamp: SystemTime,
    pub tx_hash: H256,
}

impl Payable {
    pub fn new(to: Wallet, amount: u128, txn: H256, timestamp: SystemTime) -> Self {
        Self {
            to,
            amount,
            timestamp,
            tx_hash: txn,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), PayableDaoError>;

    fn mark_pending_payable_rowid(
        &self,
        wallet: &Wallet,
        pending_payable_rowid: u64,
    ) -> Result<(), PayableDaoError>;

    fn transaction_confirmed(
        &self,
        payment: &PendingPayableFingerprint,
    ) -> Result<(), PayableDaoError>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;

    fn custom_query(&self, custom_query: CustomQuery<u64>) -> Option<Vec<PayableAccount>>;

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

#[derive(Debug)]
pub struct PayableDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    big_int_db_processor: BigIntDbProcessor<Self>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(
        &self,
        timestamp: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), PayableDaoError> {
        Ok(self.big_int_db_processor.execute(
            Left(self.conn.as_ref()),
            BigIntSqlConfig::new(
                "insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) values (:wallet, :balance_high_b, :balance_low_b, :last_paid_timestamp, null) on conflict (wallet_address) do",
                Some(|table|format!("update {} set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b where wallet_address = :wallet", table)),
                SQLParamsBuilder::default()
                          .key("wallet_address", ":wallet",wallet)
                          .wei_change( Addition("balance",amount))
                          .other(vec![(":last_paid_timestamp",&to_time_t(timestamp))])
                          .build()
                      ))?
        )
    }

    fn mark_pending_payable_rowid(
        &self,
        wallet: &Wallet,
        pending_payable_rowid: u64,
    ) -> Result<(), PayableDaoError> {
        let mut stm = self
            .conn
            .prepare("update payable set pending_payable_rowid=? where wallet_address=?")
            .expect("Internal Error");
        let params: &[&dyn ToSql] = &[
            &i64::try_from(pending_payable_rowid)
                .expect("SQLite counts up to i64::MAX; should never happen"),
            wallet,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(num) => panic!(
                "Marking pending payable rowid for {}: affected {} rows but expected 1",
                wallet, num
            ),
            Err(e) => Err(PayableDaoError::RusqliteError(e.to_string())),
        }
    }

    fn transaction_confirmed(
        &self,
        fingerprint: &PendingPayableFingerprint,
    ) -> Result<(), PayableDaoError> {
        let key =
            checked_conversion::<u64, i64>(fingerprint.rowid_opt.expectv("initialized rowid"));
        Ok(self
            .big_int_db_processor
            .execute(Left(self.conn.as_ref()), BigIntSqlConfig::new(
                "update payable set balance_high_b = balance_high_b + :balance_high_b, balance_low_b = balance_low_b + :balance_low_b, last_paid_timestamp = :last_paid, pending_payable_rowid = null where pending_payable_rowid = :rowid",
                None,
                   SQLParamsBuilder::default()
                    .key( "pending_payable_rowid", ":rowid",&key)
                    .wei_change(Subtraction("balance",fingerprint.amount))
                    .other(vec![(":last_paid", &to_time_t(fingerprint.timestamp))])
                    .build()))?)
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select wallet_address, balance_high_b, balance_low_b, last_paid_timestamp from payable where pending_payable_rowid is null")
            .expect("Internal error");
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
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payable_opt: None,
                    })
                }
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    fn custom_query(&self, custom_query: CustomQuery<u64>) -> Option<Vec<PayableAccount>> {
        let variant_top = TopStmConfig::new("last_paid_timestamp asc");

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
            Self::form_payable_account,
        )
    }

    fn total(&self) -> u128 {
        sign_conversion::<i128, u128>(collect_and_sum_i128_values_from_table(
            self.conn.as_ref(),
            &Self::table_name(),
            "balance",
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
        let mut stmt = self.conn
            .prepare("select balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid from payable where wallet_address = ?")
            .unwrap();
        stmt.query_row(&[&wallet], |row| {
            let high_bytes_result = row.get(0);
            let low_bytes_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            let pending_payable_rowid_result: Result<Option<i64>, Error> = row.get(3);
            match (
                high_bytes_result,
                low_bytes_result,
                last_paid_timestamp_result,
                pending_payable_rowid_result,
            ) {
                (Ok(high_bytes), Ok(low_bytes), Ok(last_paid_timestamp), Ok(rowid)) => {
                    Ok(PayableAccount {
                        wallet: wallet.clone(),
                        balance_wei: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                            high_bytes, low_bytes,
                        )),
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payable_opt: match rowid {
                            Some(rowid) => Some(PendingPayableId {
                                rowid: u64::try_from(rowid).unwrap(),
                                hash: H256::from_uint(&U256::from(0)), //garbage
                            }),
                            None => None,
                        },
                    })
                }
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
            big_int_db_processor: BigIntDbProcessor::default(),
        }
    }

    fn form_payable_account(row: &Row) -> rusqlite::Result<PayableAccount> {
        let wallet_result: Result<Wallet, Error> = row.get(0);
        let balance_high_bytes_result = row.get(1);
        let balance_low_bytes_result = row.get(2);
        let last_paid_timestamp_result = row.get(3);
        let pending_payable_rowid_result: Result<Option<i64>, Error> = row.get(4);
        let pending_payable_hash_result: Result<Option<String>, Error> = row.get(5);
        match (
            wallet_result,
            balance_high_bytes_result,
            balance_low_bytes_result,
            last_paid_timestamp_result,
            pending_payable_rowid_result,
            pending_payable_hash_result,
        ) {
            (
                Ok(wallet),
                Ok(high_bytes),
                Ok(low_bytes),
                Ok(last_paid_timestamp),
                Ok(rowid_opt),
                Ok(hash_opt),
            ) => Ok(PayableAccount {
                wallet,
                balance_wei: checked_conversion::<i128, u128>(BigIntDivider::reconstitute(
                    high_bytes, low_bytes,
                )),
                last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                pending_payable_opt: rowid_opt.map(|rowid| {
                    let hash_str =
                        hash_opt.expect("database corrupt; missing hash but existing rowid");
                    PendingPayableId {
                        rowid: u64::try_from(rowid).unwrap(),
                        hash: H256::from_str(&hash_str[2..])
                            .unwrap_or_else(|_| panic!("wrong form of tx hash {}", hash_str)),
                    }
                }),
            }),
            e => panic!(
                "Database is corrupt: PAYABLE table columns and/or types: {:?}",
                e
            ),
        }
    }

    fn stm_assembler_of_payable_cq(feeder: AssemblerFeeder) -> String {
        format!(
            "select
               wallet_address,
               balance_high_b,
               balance_low_b,
               last_paid_timestamp,
               pending_payable_rowid,
               pending_payable.transaction_hash
           from
               payable
           left join pending_payable on
               pending_payable.rowid = payable.pending_payable_rowid
           {} {}
           order by
               {},
               {}
           {}",
            feeder.main_where_clause,
            feeder.where_clause_extension,
            feeder.order_by_first_param,
            feeder.order_by_second_param,
            feeder.limit_clause
        )
    }
}

impl DAOTableIdentifier for PayableDaoReal {
    fn table_name() -> String {
        String::from("payable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::dao_utils::{from_time_t, now_time_t, to_time_t};
    use crate::accountant::test_utils::{
        assert_database_blows_up_on_an_unexpected_error, make_pending_payable_fingerprint,
    };
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::sub_lib::accountant::WEIS_OF_GWEI;
    use crate::test_utils::make_wallet;
    use ethereum_types::BigEndianHash;
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::types::Value::Null;
    use rusqlite::Connection as RusqliteConnection;
    use rusqlite::{Connection, OpenFlags};
    use std::path::Path;
    use std::str::FromStr;
    use web3::types::U256;

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_new_address",
        );
        let now = SystemTime::now();
        let wallet = make_wallet("booga");
        let status = {
            let boxed_conn = DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap();
            let subject = PayableDaoReal::new(boxed_conn);

            subject.more_money_payable(now, &wallet, 1234).unwrap();

            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, 1234);
        assert_eq!(to_time_t(status.last_paid_timestamp), to_time_t(now));
    }

    #[test]
    fn more_money_payable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let now = SystemTime::now();
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let subject = {
            let subject = PayableDaoReal::new(boxed_conn);
            subject.more_money_payable(now, &wallet, 1234).unwrap();
            subject
        };

        subject
            .more_money_payable(SystemTime::UNIX_EPOCH, &wallet, 2345)
            .unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance_wei, 3579);
        assert_eq!(to_time_t(status.last_paid_timestamp), to_time_t(now));
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn more_money_payable_works_for_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_overflow",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_payable(SystemTime::now(), &wallet, u128::MAX);
    }

    fn insert_single_record_into_payable(conn: &dyn ConnectionWrapper, params: &[&dyn ToSql]) {
        let mut stm = conn.prepare("insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) values (?,?,?,?,?)").unwrap();
        stm.execute(params).unwrap();
    }

    #[test]
    fn mark_pending_payment_marks_a_pending_transaction_for_a_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payment_marks_a_pending_transaction_for_a_new_address",
        );
        let wallet = make_wallet("booga");
        let pending_payable_rowid = 656;
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        {
            insert_single_record_into_payable(
                &*boxed_conn,
                &[&wallet, &0, &5000, &150_000_000, &Null],
            );
        }
        let subject = PayableDaoReal::new(boxed_conn);
        let before_account_status = subject.account_status(&wallet).unwrap();

        subject
            .mark_pending_payable_rowid(&wallet, pending_payable_rowid)
            .unwrap();

        let before_expected_status = PayableAccount {
            wallet: wallet.clone(),
            balance_wei: 5000,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        };
        assert_eq!(before_account_status, before_expected_status);
        let after_account_status = subject.account_status(&wallet).unwrap();
        let mut after_expected_status = before_expected_status;
        after_expected_status.pending_payable_opt = Some(PendingPayableId {
            rowid: pending_payable_rowid,
            hash: H256::from_uint(&U256::from(0)), //garbage
        });
        assert_eq!(after_account_status, after_expected_status)
    }

    #[test]
    #[should_panic(
        expected = "Marking pending payable rowid for 0x000000000000000000000000000000626f6f6761: affected 0 rows but expected 1"
    )]
    fn mark_pending_payment_returned_different_row_count_than_expected() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payment_returned_different_row_count_than_expected",
        );
        let wallet = make_wallet("booga");
        let rowid = 656;
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let _ = subject.mark_pending_payable_rowid(&wallet, rowid);
    }

    #[test]
    fn mark_pending_payment_handles_general_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payment_handles_general_sql_error",
        );
        let wallet = make_wallet("booga");
        let rowid = 656;
        let conn = how_to_trick_rusqlite_for_an_error(&home_dir);
        let conn_wrapped = ConnectionWrapperReal::new(conn);
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));

        let result = subject.mark_pending_payable_rowid(&wallet, rowid);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn transaction_confirmed_works() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "transaction_confirmed_works");
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;
        let previous_timestamp = from_time_t(190_000_000);
        let payable_timestamp = from_time_t(199_000_000);
        let attempt = 5;
        let starting_amount = 10000;
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(starting_amount);
        let payment = 6666;
        let wallet = make_wallet("bobble");
        {
            insert_single_record_into_payable(
                &*boxed_conn,
                &[
                    &wallet,
                    &high_bytes,
                    &low_bytes,
                    &to_time_t(previous_timestamp),
                    &sign_conversion::<u64, i64>(rowid).unwrap(),
                ],
            );
        }
        let subject = PayableDaoReal::new(boxed_conn);
        let pending_payable_fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: payable_timestamp,
            hash,
            attempt_opt: Some(attempt),
            amount: payment,
            process_error: None,
        };
        let status_before = subject.account_status(&wallet);

        let result = subject.transaction_confirmed(&pending_payable_fingerprint);

        assert_eq!(result, Ok(()));
        assert_eq!(
            status_before,
            Some(PayableAccount {
                wallet: wallet.clone(),
                balance_wei: starting_amount as u128,
                last_paid_timestamp: previous_timestamp,
                pending_payable_opt: Some(PendingPayableId {
                    rowid,
                    hash: H256::from_uint(&U256::from(0))
                }) //hash is just garbage
            })
        );
        let status_after = subject.account_status(&wallet);
        assert_eq!(
            status_after,
            Some(PayableAccount {
                wallet,
                balance_wei: starting_amount as u128 - payment,
                last_paid_timestamp: payable_timestamp,
                pending_payable_opt: None
            })
        )
    }

    #[test]
    fn transaction_confirmed_works_for_generic_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_generic_sql_error",
        );
        let conn = how_to_trick_rusqlite_for_an_error(&home_dir);
        let conn_wrapped = Box::new(ConnectionWrapperReal::new(conn));
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;
        pending_payable_fingerprint.hash = hash;
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        let subject = PayableDaoReal::new(conn_wrapped);

        let result = subject.transaction_confirmed(&pending_payable_fingerprint);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError(
                "Wei change: error after invalid update command for payable of -12345 Wei to 789 with error 'attempt to write a readonly database'".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn transaction_confirmed_works_for_overflow_from_amount_stored_in_pending_payable_fingerprint()
    {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_overflow_from_amount_stored_in_pending_payable_fingerprint",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;
        pending_payable_fingerprint.hash = hash;
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.amount = u128::MAX;
        //The overflow occurs before we start modifying the payable account so we can have the database empty

        let _ = subject.transaction_confirmed(&pending_payable_fingerprint);
    }

    fn how_to_trick_rusqlite_for_an_error(path: &Path) -> Connection {
        let db_path = path.join("experiment.db");
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::default()).unwrap();
        {
            let mut stm = conn
                .prepare(
                    "\
                create table payable (\
                    wallet_address text primary key,
                    balance_high_b integer not null,
                    balance_low_b integer not null,
                    last_paid_timestamp integer not null,
                    pending_payable_rowid integer null)\
                    ",
                )
                .unwrap();
            stm.execute([]).unwrap();
        }
        conn.close().unwrap();
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
        conn
    }

    #[test]
    fn non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_an_empty_vec_when_the_database_is_empty",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let result = subject.non_pending_payables();

        assert_eq!(result, vec![]);
    }

    #[test]
    fn non_pending_payables_should_return_payables_with_no_pending_transaction() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_payables_with_no_pending_transaction",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let conn = ConnectionWrapperReal::new(conn);
        let insert = |wallet: &str,
                      balance_high_b: i64,
                      balance_low_b: i64,
                      last_paid_timestamp: i64,
                      pending_payable_rowid: Option<i64>| {
            let params: &[&dyn ToSql] = &[
                &wallet,
                &balance_high_b,
                &balance_low_b,
                &last_paid_timestamp,
                &pending_payable_rowid,
            ];
            insert_single_record_into_payable(&conn, params);
        };
        insert(
            "0x0000000000000000000000000000000000666f6f",
            42,
            454,
            1111111111,
            Some(15),
        );
        insert(
            "0x0000000000000000000000000000000000626172",
            24,
            11111,
            2222211111,
            Some(16),
        );
        insert(
            &make_wallet("foobar").to_string(),
            44,
            10000,
            3333333333,
            None,
        );
        insert(
            &make_wallet("barfoo").to_string(),
            458422,
            45,
            4444433333,
            None,
        );

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance_wei: BigIntDivider::reconstitute(44, 10000) as u128,
                    last_paid_timestamp: from_time_t(3333333333),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance_wei: BigIntDivider::reconstitute(458422, 45) as u128,
                    last_paid_timestamp: from_time_t(4444433333),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128"
    )]
    fn payable_amount_panics_on_insert_when_with_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_amount_panics_on_insert_when_with_overflow",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, DbInitializationConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_payable(SystemTime::now(), &make_wallet("foobar"), u128::MAX);
    }

    #[test]
    fn custom_query_handles_empty_table_in_top_records_mode() {
        let main_test_setup = |_insert: &dyn Fn(&str, i128, i64, Option<i64>)| {};
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

    fn common_setup_of_accounts_for_tests_of_top_records(
        now: i64,
    ) -> Box<dyn Fn(&dyn Fn(&str, i128, i64, Option<i64>))> {
        let timestamp1 = now - 86_401;
        let timestamp2 = now - 86_001;
        let timestamp3 = now - 86_000;
        let timestamp4 = now - 86_300;
        let timestamp5 = now - 86_401;
        Box::new(move |insert: &dyn Fn(&str, i128, i64, Option<i64>)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                1_000_000_002,
                timestamp1,
                None,
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                7_562_000_300_000,
                timestamp2,
                None,
            );
            insert(
                "0x3333333333333333333333333333333333333333",
                999_999_999, //balance smaller than 1 Gwei
                timestamp3,
                None,
            );
            insert(
                "0x4444444444444444444444444444444444444444",
                10_000_000_100,
                timestamp4,
                None,
            );
            insert(
                "0x5555555555555555555555555555555555555555",
                10_000_000_100,
                timestamp5,
                Some(1),
            );
        })
    }

    #[test]
    fn custom_query_in_top_records_mode_with_default_sorting() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in debt's age but not balance which allows to check doubled ordering,
        //here by balance and then by age.
        let now = now_time_t();
        let main_test_setup = common_setup_of_accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_payable(
            "custom_query_in_top_records_mode_with_default_sorting",
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
                PayableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 7_562_000_300_000,
                    last_paid_timestamp: from_time_t(now - 86_001),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_time_t(now - 86_401),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: 1,
                        hash: H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    })
                },
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_time_t(now - 86_300),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_in_top_records_mode_sorted_by_age() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in balance but not in the debt's age which allows to check doubled ordering,
        //here by age and then by balance.
        let now = now_time_t();
        let main_test_setup = common_setup_of_accounts_for_tests_of_top_records(now);
        let subject = custom_query_test_body_for_payable(
            "custom_query_in_top_records_mode_sorted_by_age",
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
                PayableAccount {
                    wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_time_t(now - 86_401),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: 1,
                        hash: H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    })
                },
                PayableAccount {
                    wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                    balance_wei: 1_000_000_002,
                    last_paid_timestamp: from_time_t(now - 86_401),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_time_t(now - 86_300),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_handles_empty_table_in_range_mode() {
        let main_test_setup = |_insert: &dyn Fn(&str, i128, i64, Option<i64>)| {};
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
        //Two accounts differ only in debt's age but not balance which allows to check doubled ordering,
        //by balance and then by age.
        let now = now_time_t();
        let timestamp1 = now - 70_000;
        let timestamp2 = now - 55_120;
        let timestamp3 = now - 200_001;
        let timestamp4 = now - 19_999;
        let timestamp5 = now - 30_786;
        let timestamp6 = now - 100_401;
        let timestamp7 = now - 80_333;
        let main_setup = |insert: &dyn Fn(&str, i128, i64, Option<i64>)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                499_999_999 * WEIS_OF_GWEI, //too small
                timestamp1,
                None,
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                1_800_456_000 * WEIS_OF_GWEI,
                timestamp2,
                Some(1),
            );
            insert(
                "0x3333333333333333333333333333333333333333",
                600_123_456 * WEIS_OF_GWEI,
                timestamp3, //too old
                None,
            );
            insert(
                "0x4444444444444444444444444444444444444444",
                1_033_456_000 * WEIS_OF_GWEI,
                timestamp4, //too young
                None,
            );
            insert(
                "0x5555555555555555555555555555555555555555",
                35_000_000_001 * WEIS_OF_GWEI, //too big
                timestamp5,
                None,
            );
            insert(
                "0x6666666666666666666666666666666666666666",
                1_800_456_000 * WEIS_OF_GWEI,
                timestamp6,
                None,
            );
            insert(
                "0x7777777777777777777777777777777777777777",
                2_500_647_000 * WEIS_OF_GWEI,
                timestamp7,
                None,
            );
        };
        let subject = custom_query_test_body_for_payable("custom_query_in_range_mode", main_setup);

        let result = subject
            .custom_query(CustomQuery::RangeQuery {
                min_age_s: 20000,
                max_age_s: 200000,
                min_amount_gwei: 500_000_000,
                max_amount_gwei: 35_000_000_000,
                timestamp: from_time_t(now),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: Wallet::new("0x7777777777777777777777777777777777777777"),
                    balance_wei: 2_500_647_000_000_000_000,
                    last_paid_timestamp: from_time_t(timestamp7),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                    balance_wei: 1_800_456_000_000_000_000,
                    last_paid_timestamp: from_time_t(timestamp6),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 1_800_456_000_000_000_000,
                    last_paid_timestamp: from_time_t(timestamp2),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: 1,
                        hash: H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    })
                }
            ]
        );
    }

    #[test]
    fn range_query_does_not_display_values_from_below_1_gwei() {
        let timestamp = now_time_t() - 5000;
        let main_setup = |insert: &dyn Fn(&str, i128, i64, Option<i64>)| {
            insert(
                "0x1111111111111111111111111111111111111111",
                400_005_601,
                dao_utils::now_time_t() - 11_001,
                None,
            );
            insert(
                "0x2222222222222222222222222222222222222222",
                30_000_300_000,
                timestamp,
                None,
            );
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
            vec![PayableAccount {
                wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                balance_wei: 30_000_300_000,
                last_paid_timestamp: from_time_t(timestamp),
                pending_payable_opt: None
            },]
        )
    }

    fn insert_record(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
        balance: i128,
        timestamp: i64,
        pending_payable_rowid: Option<i64>,
    ) {
        let (high_bytes, low_bytes) = BigIntDivider::deconstruct(balance);
        let params: &[&dyn ToSql] = &[
            &wallet,
            &high_bytes,
            &low_bytes,
            &timestamp,
            &pending_payable_rowid,
        ];
        conn
        .prepare("insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?, ?)")
        .unwrap()
        .execute(params)
        .unwrap();
    }

    #[test]
    fn total_works() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "total_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let timestamp = dao_utils::now_time_t();
        insert_record(
            &*conn,
            "0x1111111111111111111111111111111111111111",
            999_999_999,
            timestamp - 1000,
            None,
        );
        insert_record(
            &*conn,
            "0x2222222222222222222222222222222222222222",
            1_000_123_123,
            timestamp - 2000,
            None,
        );
        insert_record(
            &*conn,
            "0x3333333333333333333333333333333333333333",
            1_000_000_000,
            timestamp - 3000,
            None,
        );
        insert_record(
            &*conn,
            "0x4444444444444444444444444444444444444444",
            1_000_000_001,
            timestamp - 4000,
            Some(3),
        );
        let subject = PayableDaoReal::new(conn);

        let total = subject.total();

        assert_eq!(total, 4_000_123_123)
    }

    #[test]
    #[should_panic(expected = "database corrupted: negative sum (-999999) in payable table")]
    fn total_takes_negative_sum_as_error() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "total_takes_negative_sum_as_error");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let timestamp = dao_utils::now_time_t();
        insert_record(
            &*conn,
            "0x1111111111111111111111111111111111111111",
            -999_999,
            timestamp - 1000,
            None,
        );
        let subject = PayableDaoReal::new(conn);

        let _ = subject.total();
    }

    #[test]
    fn correctly_totals_zero_records() {
        let home_dir =
            ensure_node_home_directory_exists("payable_dao", "correctly_totals_zero_records");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: PAYABLE table columns and/or types: (Err(FromSqlConversionFailure(0, Text, InvalidAddress)), Err(InvalidColumnIndex(1))"
    )]
    fn form_payable_account_panics_on_database_error() {
        assert_database_blows_up_on_an_unexpected_error(PayableDaoReal::form_payable_account);
    }

    #[test]
    fn payable_dao_implements_dao_table_identifier() {
        assert_eq!(PayableDaoReal::table_name(), "payable")
    }

    fn custom_query_test_body_for_payable<F>(test_name: &str, main_setup_fn: F) -> PayableDaoReal
    where
        F: Fn(&dyn Fn(&str, i128, i64, Option<i64>)),
    {
        let home_dir = ensure_node_home_directory_exists("payable_dao", test_name);
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, DbInitializationConfig::test_default())
            .unwrap();
        let insert = |wallet: &str,
                      wei_balance: i128,
                      timestamp: i64,
                      pending_payable_rowid: Option<i64>| {
            let (high_bytes, low_bytes) = BigIntDivider::deconstruct(wei_balance);
            let params: &[&dyn ToSql] = &[
                &wallet,
                &high_bytes,
                &low_bytes,
                &timestamp,
                &pending_payable_rowid,
            ];
            eprintln!("timestamp before: {}", timestamp);
            conn
                .prepare("insert into payable (wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid) values (?,?,?,?,?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        main_setup_fn(&insert);
        let params: &[&dyn ToSql] = &[
            &String::from("0xabc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"),
            &40,
            &478945,
            &177777777,
            &1,
        ];
        conn
            .prepare("insert into pending_payable (transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt) values (?,?,?,?,?)")
            .unwrap()
            .execute(params)
            .unwrap();
        PayableDaoReal::new(conn)
    }
}
