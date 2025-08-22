// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
use crate::accountant::db_access_objects::utils;
use crate::accountant::db_access_objects::utils::{
    sum_i128_values_from_table, to_unix_timestamp, AssemblerFeeder, CustomQuery, DaoFactoryReal,
    RangeStmConfig, RowId, TopStmConfig, TxHash, VigilantRusqliteFlatten,
};
use crate::accountant::db_big_integer::big_int_db_processor::KeyVariants::WalletAddress;
use crate::accountant::db_big_integer::big_int_db_processor::{
    BigIntDbProcessor, BigIntDbProcessorReal, BigIntSqlConfig, DisplayableRusqliteParamPair,
    ParamByUse, SQLParamsBuilder, TableNameDAO, WeiChange, WeiChangeDirection,
};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, sign_conversion, PendingPayableId};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use ethabi::Address;
#[cfg(test)]
use ethereum_types::{BigEndianHash, U256};
use itertools::Either;
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
    pub pending_payable_opt: Option<PendingPayableId>,
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount_minor: u128,
    ) -> Result<(), PayableDaoError>;

    fn mark_pending_payables_rowids(
        &self,
        mark_instructions: &[MarkPendingPayableID],
    ) -> Result<(), PayableDaoError>;

    fn transactions_confirmed(&self, confirmed_payables: &[SentTx]) -> Result<(), PayableDaoError>;

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

pub struct MarkPendingPayableID {
    pub wallet: Address,
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

    fn mark_pending_payables_rowids(
        &self,
        _mark_instructions: &[MarkPendingPayableID],
    ) -> Result<(), PayableDaoError> {
        todo!("Will be an object of removal in GH-662")
        // if wallets_and_rowids.is_empty() {
        //     panic!("broken code: empty input is not permit to enter this method")
        // }
        //
        // let case_expr = compose_case_expression(wallets_and_rowids);
        // let wallets = serialize_wallets(wallets_and_rowids, Some('\''));
        // //the Wallet type is secure against SQL injections
        // let sql = format!(
        //     "update payable set \
        //         pending_payable_rowid = {} \
        //      where
        //         pending_payable_rowid is null and wallet_address in ({})
        //      returning
        //         pending_payable_rowid",
        //     case_expr, wallets,
        // );
        // execute_command(&*self.conn, wallets_and_rowids, &sql)
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
                        pending_payable_opt: None,
                    })
                }
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .vigilant_flatten()
        .collect()
    }

    fn custom_query(&self, custom_query: CustomQuery<u64>) -> Option<Vec<PayableAccount>> {
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
            Self::create_payable_account,
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
                        last_paid_timestamp: utils::from_unix_timestamp(last_paid_timestamp),
                        pending_payable_opt: match rowid {
                            Some(rowid) => Some(PendingPayableId::new(
                                u64::try_from(rowid).unwrap(),
                                H256::from_uint(&U256::from(0)), //garbage
                            )),
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
            big_int_db_processor: BigIntDbProcessorReal::default(),
        }
    }

    fn create_payable_account(row: &Row) -> rusqlite::Result<PayableAccount> {
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
                last_paid_timestamp: utils::from_unix_timestamp(last_paid_timestamp),
                pending_payable_opt: rowid_opt.map(|rowid| {
                    let hash_str =
                        hash_opt.expect("database corrupt; missing hash but existing rowid");
                    PendingPayableId::new(
                        u64::try_from(rowid).unwrap(),
                        H256::from_str(&hash_str[2..])
                            .unwrap_or_else(|_| panic!("wrong form of tx hash {}", hash_str)),
                    )
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

impl TableNameDAO for PayableDaoReal {
    fn table_name() -> String {
        String::from("payable")
    }
}

// TODO Will be an object of removal in GH-662
// mod mark_pending_payable_associated_functions {
//     use crate::accountant::comma_joined_stringifiable;
//     use crate::accountant::db_access_objects::payable_dao::{MarkPendingPayableID, PayableDaoError};
//     use crate::accountant::db_access_objects::utils::{
//         update_rows_and_return_valid_count, VigilantRusqliteFlatten,
//     };
//     use crate::database::rusqlite_wrappers::ConnectionWrapper;
//     use crate::sub_lib::wallet::Wallet;
//     use itertools::Itertools;
//     use rusqlite::Row;
//     use std::fmt::Display;
//
//     pub fn execute_command(
//         conn: &dyn ConnectionWrapper,
//         wallets_and_rowids: &[(&Wallet, u64)],
//         sql: &str,
//     ) -> Result<(), PayableDaoError> {
//         let mut stm = conn.prepare(sql).expect("Internal Error");
//         let validator = validate_row_updated;
//         let rows_affected_res = update_rows_and_return_valid_count(&mut stm, validator);
//
//         match rows_affected_res {
//             Ok(rows_affected) => match rows_affected {
//                 num if num == wallets_and_rowids.len() => Ok(()),
//                 num => mismatched_row_count_panic(conn, wallets_and_rowids, num),
//             },
//             Err(errs) => {
//                 let err_msg = format!(
//                     "Multi-row update to mark pending payable hit these errors: {:?}",
//                     errs
//                 );
//                 Err(PayableDaoError::RusqliteError(err_msg))
//             }
//         }
//     }
//
//     pub fn compose_case_expression(wallets_and_rowids: &[(&Wallet, u64)]) -> String {
//         //the Wallet type is secure against SQL injections
//         fn when_clause((wallet, rowid): &(&Wallet, u64)) -> String {
//             format!("when wallet_address = '{wallet}' then {rowid}")
//         }
//
//         format!(
//             "case {} end",
//             wallets_and_rowids.iter().map(when_clause).join("\n")
//         )
//     }
//
//     pub fn serialize_wallets(
//         wallets_and_rowids: &[MarkPendingPayableID],
//         quotes_opt: Option<char>,
//     ) -> String {
//         wallets_and_rowids
//             .iter()
//             .map(|(wallet, _)| match quotes_opt {
//                 Some(char) => format!("{}{}{}", char, wallet, char),
//                 None => wallet.to_string(),
//             })
//             .join(", ")
//     }
//
//     fn validate_row_updated(row: &Row) -> Result<bool, rusqlite::Error> {
//         row.get::<usize, Option<u64>>(0).map(|opt| opt.is_some())
//     }
//
//     fn mismatched_row_count_panic(
//         conn: &dyn ConnectionWrapper,
//         wallets_and_rowids: &[(&Wallet, u64)],
//         actual_count: usize,
//     ) -> ! {
//         let serialized_wallets = serialize_wallets(wallets_and_rowids, None);
//         let expected_count = wallets_and_rowids.len();
//         let extension = explanatory_extension(conn, wallets_and_rowids);
//         panic!(
//             "Marking pending payable rowid for wallets {serialized_wallets} affected \
//             {actual_count} rows but expected {expected_count}. {extension}"
//         )
//     }
//
//     pub(super) fn explanatory_extension(
//         conn: &dyn ConnectionWrapper,
//         wallets_and_rowids: &[(&Wallet, u64)],
//     ) -> String {
//         let resulting_pairs_collection =
//             query_resulting_pairs_of_wallets_and_rowids(conn, wallets_and_rowids);
//         let resulting_pairs_summary = if resulting_pairs_collection.is_empty() {
//             "<Failing again: accounts with such wallets not found>".to_string()
//         } else {
//             pairs_in_pretty_string(&resulting_pairs_collection, |rowid_opt: &Option<u64>| {
//                 match rowid_opt {
//                     Some(rowid) => Box::new(*rowid),
//                     None => Box::new("N/A"),
//                 }
//             })
//         };
//         let wallets_and_non_optional_rowids =
//             pairs_in_pretty_string(wallets_and_rowids, |rowid: &u64| Box::new(*rowid));
//         format!(
//             "\
//                 The demanded data according to {} looks different from the resulting state {}!. Operation failed.\n\
//                 Notes:\n\
//                 a) if row ids have stayed non-populated it points out that writing failed but without the double payment threat,\n\
//                 b) if some accounts on the resulting side are missing, other kind of serious issues should be suspected but see other\n\
//                 points to figure out if you were put in danger of double payment,\n\
//                 c) seeing ids different from those demanded might be a sign of some payments having been doubled.\n\
//                 The operation which is supposed to clear out the ids of the payments previously requested for this account\n\
//                 probably had not managed to complete successfully before another payment was requested: preventive measures failed.\n",
//             wallets_and_non_optional_rowids, resulting_pairs_summary)
//     }
//
//     fn query_resulting_pairs_of_wallets_and_rowids(
//         conn: &dyn ConnectionWrapper,
//         wallets_and_rowids: &[(&Wallet, u64)],
//     ) -> Vec<(Wallet, Option<u64>)> {
//         let select_dealt_accounts =
//             format!(
//                 "select wallet_address, pending_payable_rowid from payable where wallet_address in ({})",
//                 serialize_wallets(wallets_and_rowids, Some('\''))
//             );
//         let row_processor = |row: &Row| {
//             Ok((
//                 row.get::<usize, Wallet>(0)
//                     .expect("database corrupt: wallet addresses found in bad format"),
//                 row.get::<usize, Option<u64>>(1)
//                     .expect("database_corrupt: rowid found in bad format"),
//             ))
//         };
//         conn.prepare(&select_dealt_accounts)
//             .expect("select failed")
//             .query_map([], row_processor)
//             .expect("no args yet binding failed")
//             .vigilant_flatten()
//             .collect()
//     }
//
//     fn pairs_in_pretty_string<W: Display, R>(
//         pairs: &[(W, R)],
//         rowid_pretty_writer: fn(&R) -> Box<dyn Display>,
//     ) -> String {
//         comma_joined_stringifiable(pairs, |(wallet, rowid)| {
//             format!(
//                 "( Wallet: {}, Rowid: {} )",
//                 wallet,
//                 rowid_pretty_writer(rowid)
//             )
//         })
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
    use crate::accountant::db_access_objects::utils::{
        current_unix_timestamp, from_unix_timestamp, to_unix_timestamp,
    };
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::{
        assert_account_creation_fn_fails_on_finding_wrong_columns_and_value_types, make_sent_tx,
        trick_rusqlite_with_read_only_conn,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::ToSql;
    use rusqlite::{Connection, OpenFlags};
    use std::path::Path;
    use std::str::FromStr;
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

    #[test]
    fn mark_pending_payables_marks_pending_transactions_for_new_addresses() {
        //the extra unchanged record checks the safety of right count of changed rows;
        //experienced serious troubles in the past
        // TODO Will be an object of removal in GH-662
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "mark_pending_payables_marks_pending_transactions_for_new_addresses",
        // );
        // let wallet_0 = make_wallet("wallet");
        // let wallet_1 = make_wallet("booga");
        // let pending_payable_rowid_1 = 656;
        // let wallet_2 = make_wallet("bagaboo");
        // let pending_payable_rowid_2 = 657;
        // let boxed_conn = DbInitializerReal::default()
        //     .initialize(&home_dir, DbInitializationConfig::test_default())
        //     .unwrap();
        // {
        //     let insert = "insert into payable (wallet_address, balance_high_b, balance_low_b, \
        //      last_paid_timestamp) values (?, ?, ?, ?), (?, ?, ?, ?), (?, ?, ?, ?)";
        //     let mut stm = boxed_conn.prepare(insert).unwrap();
        //     let params = [
        //         [&wallet_0 as &dyn ToSql, &12345, &1, &45678],
        //         [&wallet_1, &0, &i64::MAX, &150_000_000],
        //         [&wallet_2, &3, &0, &151_000_000],
        //     ]
        //     .into_iter()
        //     .flatten()
        //     .collect::<Vec<&dyn ToSql>>();
        //     stm.execute(params.as_slice()).unwrap();
        // }
        // let subject = PayableDaoReal::new(boxed_conn);
        //
        // subject
        //     .mark_pending_payables_rowids(&[
        //         (&wallet_1, pending_payable_rowid_1),
        //         (&wallet_2, pending_payable_rowid_2),
        //     ])
        //     .unwrap();
        //
        // let account_statuses = [&wallet_0, &wallet_1, &wallet_2]
        //     .iter()
        //     .map(|wallet| subject.account_status(wallet).unwrap())
        //     .collect::<Vec<PayableAccount>>();
        // assert_eq!(
        //     account_statuses,
        //     vec![
        //         PayableAccount {
        //             wallet: wallet_0,
        //             balance_wei: u128::try_from(BigIntDivider::reconstitute(12345, 1)).unwrap(),
        //             last_paid_timestamp: from_unix_timestamp(45678),
        //             pending_payable_opt: None,
        //         },
        //         PayableAccount {
        //             wallet: wallet_1,
        //             balance_wei: u128::try_from(BigIntDivider::reconstitute(0, i64::MAX)).unwrap(),
        //             last_paid_timestamp: from_unix_timestamp(150_000_000),
        //             pending_payable_opt: Some(PendingPayableId::new(
        //                 pending_payable_rowid_1,
        //                 make_tx_hash(0)
        //             )),
        //         },
        //         //notice the hashes are garbage generated by a test method not knowing doing better
        //         PayableAccount {
        //             wallet: wallet_2,
        //             balance_wei: u128::try_from(BigIntDivider::reconstitute(3, 0)).unwrap(),
        //             last_paid_timestamp: from_unix_timestamp(151_000_000),
        //             pending_payable_opt: Some(PendingPayableId::new(
        //                 pending_payable_rowid_2,
        //                 make_tx_hash(0)
        //             ))
        //         }
        //     ]
        // )
    }

    #[test]
    // #[should_panic(expected = "\
    //     Marking pending payable rowid for wallets 0x000000000000000000000000000000626f6f6761, \
    //     0x0000000000000000000000000000007961686f6f affected 0 rows but expected 2. \
    //     The demanded data according to ( Wallet: 0x000000000000000000000000000000626f6f6761, Rowid: 456 ), \
    //     ( Wallet: 0x0000000000000000000000000000007961686f6f, Rowid: 789 ) looks different from \
    //     the resulting state ( Wallet: 0x000000000000000000000000000000626f6f6761, Rowid: 456 )!. Operation failed.\n\
    //     Notes:\n\
    //     a) if row ids have stayed non-populated it points out that writing failed but without the double payment threat,\n\
    //     b) if some accounts on the resulting side are missing, other kind of serious issues should be suspected but see other\n\
    //     points to figure out if you were put in danger of double payment,\n\
    //     c) seeing ids different from those demanded might be a sign of some payments having been doubled.\n\
    //     The operation which is supposed to clear out the ids of the payments previously requested for this account\n\
    //     probably had not managed to complete successfully before another payment was requested: preventive measures failed.")]
    fn mark_pending_payables_rowids_returned_different_row_count_than_expected_with_one_account_missing_and_one_unmodified(
    ) {
        // TODO Will be an object of removal in GH-662
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "mark_pending_payables_rowids_returned_different_row_count_than_expected_with_one_account_missing_and_one_unmodified",
        // );
        // let conn = DbInitializerReal::default()
        //     .initialize(&home_dir, DbInitializationConfig::test_default())
        //     .unwrap();
        // let first_wallet = make_wallet("booga");
        // let first_rowid = 456;
        // insert_payable_record_fn(
        //     &*conn,
        //     &first_wallet.to_string(),
        //     123456,
        //     789789,
        //     Some(first_rowid),
        // );
        // let subject = PayableDaoReal::new(conn);
        //
        // let _ = subject.mark_pending_payables_rowids(&[
        //     (&first_wallet, first_rowid as u64),
        //     (&make_wallet("yahoo"), 789),
        // ]);
    }

    #[test]
    fn explanatory_extension_shows_resulting_account_with_unpopulated_rowid() {
        // TODO Will be an object of removal in GH-662
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "explanatory_extension_shows_resulting_account_with_unpopulated_rowid",
        // );
        // let wallet_1 = make_wallet("hooga");
        // let rowid_1 = 550;
        // let wallet_2 = make_wallet("booga");
        // let rowid_2 = 555;
        // let conn = DbInitializerReal::default()
        //     .initialize(&home_dir, DbInitializationConfig::test_default())
        //     .unwrap();
        // let record_seeds = [
        //     (&wallet_1.to_string(), 12345, 1_000_000_000, None),
        //     (&wallet_2.to_string(), 23456, 1_000_000_111, Some(540)),
        // ];
        // record_seeds
        //     .into_iter()
        //     .for_each(|(wallet, balance, timestamp, rowid_opt)| {
        //         insert_payable_record_fn(&*conn, wallet, balance, timestamp, rowid_opt)
        //     });
        //
        // let result = explanatory_extension(&*conn, &[(&wallet_1, rowid_1), (&wallet_2, rowid_2)]);
        //
        // assert_eq!(result, "\
        // The demanded data according to ( Wallet: 0x000000000000000000000000000000686f6f6761, Rowid: 550 ), \
        // ( Wallet: 0x000000000000000000000000000000626f6f6761, Rowid: 555 ) looks different from \
        // the resulting state ( Wallet: 0x000000000000000000000000000000626f6f6761, Rowid: 540 ), \
        // ( Wallet: 0x000000000000000000000000000000686f6f6761, Rowid: N/A )!. \
        // Operation failed.\n\
        // Notes:\n\
        // a) if row ids have stayed non-populated it points out that writing failed but without the double \
        // payment threat,\n\
        // b) if some accounts on the resulting side are missing, other kind of serious issues should be \
        // suspected but see other\npoints to figure out if you were put in danger of double payment,\n\
        // c) seeing ids different from those demanded might be a sign of some payments having been doubled.\n\
        // The operation which is supposed to clear out the ids of the payments previously requested for \
        // this account\nprobably had not managed to complete successfully before another payment was \
        // requested: preventive measures failed.\n".to_string())
    }

    #[test]
    fn mark_pending_payables_rowids_handles_general_sql_error() {
        // TODO Will be an object of removal in GH-662
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "mark_pending_payables_rowids_handles_general_sql_error",
        // );
        // let wallet = make_wallet("booga");
        // let rowid = 656;
        // let single_mark_instruction = MarkPendingPayableID::new(wallet.address(), rowid);
        // let conn = payable_read_only_conn(&home_dir);
        // let conn_wrapped = ConnectionWrapperReal::new(conn);
        // let subject = PayableDaoReal::new(Box::new(conn_wrapped));
        //
        // let result = subject.mark_pending_payables_rowids(&[single_mark_instruction]);
        //
        // assert_eq!(
        //     result,
        //     Err(PayableDaoError::RusqliteError(
        //         "Multi-row update to mark pending payable hit these errors: [SqliteFailure(\
        //         Error { code: ReadOnly, extended_code: 8 }, Some(\"attempt to write a readonly \
        //         database\"))]"
        //             .to_string()
        //     ))
        // )
    }

    #[test]
    //#[should_panic(expected = "broken code: empty input is not permit to enter this method")]
    fn mark_pending_payables_rowids_is_strict_about_empty_input() {
        // TODO Will be an object of removal in GH-662
        // let wrapped_conn = ConnectionWrapperMock::default();
        // let subject = PayableDaoReal::new(Box::new(wrapped_conn));
        //
        // let _ = subject.mark_pending_payables_rowids(&[]);
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
        wallet: Address,
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
                wallet: make_wallet("bobbles").address(),
                initial_amount_wei: initial_amount_1,
                balance_change: balance_change_1,
            },
            TestInputs {
                hash: make_tx_hash(54321),
                previous_timestamp: now.checked_sub(Duration::from_secs(22_000)).unwrap(),
                new_payable_timestamp: now.checked_sub(Duration::from_secs(2)).unwrap(),
                wallet: make_wallet("yet more bobbles").address(),
                initial_amount_wei: initial_amount_2,
                balance_change: balance_change_2,
            },
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, test_inputs)| {
            insert_payable_record_fn(
                conn,
                &format!("{:?}", test_inputs.wallet),
                i128::try_from(test_inputs.initial_amount_wei).unwrap(),
                to_unix_timestamp(test_inputs.previous_timestamp),
                // TODO argument will be eliminated in GH-662
                None,
            );
            let mut sent_tx = make_sent_tx((idx as u64 + 1) * 1234);
            sent_tx.hash = test_inputs.hash;
            sent_tx.amount_minor = test_inputs.balance_change;
            sent_tx.receiver_address = test_inputs.wallet;
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
        // TODO yes these pending_payable_opt values are unsensible now but it will eventually be all cleaned up with GH-662
        let expected_status_before_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: initial_amount_1,
            last_paid_timestamp: expected_last_paid_timestamp_1,
            pending_payable_opt: None,
        };
        let expected_status_before_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: initial_amount_2,
            last_paid_timestamp: expected_last_paid_timestamp_2,
            pending_payable_opt: None,
        };
        let expected_resulting_status_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: expected_balance_after_1,
            last_paid_timestamp: from_unix_timestamp(
                setup_holder.account_1.pending_payable.timestamp,
            ),
            pending_payable_opt: None,
        };
        let expected_resulting_status_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: expected_balance_after_2,
            last_paid_timestamp: from_unix_timestamp(
                setup_holder.account_2.pending_payable.timestamp,
            ),
            pending_payable_opt: None,
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
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_payables_with_no_pending_transaction",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap(),
        );
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn = Connection::open_with_flags(&home_dir.join(DATABASE_FILE), flags).unwrap();
        let conn = ConnectionWrapperReal::new(conn);
        let insert = |wallet: &str, pending_payable_rowid: Option<i64>| {
            insert_payable_record_fn(
                &conn,
                wallet,
                1234567890123456,
                111_111_111,
                pending_payable_rowid,
            );
        };
        insert("0x0000000000000000000000000000000000666f6f", Some(15));
        insert(&make_wallet("foobar").to_string(), None);
        insert("0x0000000000000000000000000000000000626172", Some(16));
        insert(&make_wallet("barfoo").to_string(), None);

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance_wei: 1234567890123456 as u128,
                    last_paid_timestamp: from_unix_timestamp(111_111_111),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance_wei: 1234567890123456 as u128,
                    last_paid_timestamp: from_unix_timestamp(111_111_111),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_handles_empty_table_in_top_records_mode() {
        let main_test_setup = |_conn: &dyn ConnectionWrapper, _insert: InsertPayableHelperFn| {};
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

    type InsertPayableHelperFn<'b> =
        &'b dyn for<'a> Fn(&'a dyn ConnectionWrapper, &'a str, i128, i64, Option<i64>);

    fn insert_payable_record_fn(
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

    fn accounts_for_tests_of_top_records(
        now: i64,
    ) -> Box<dyn Fn(&dyn ConnectionWrapper, InsertPayableHelperFn)> {
        Box::new(move |conn, insert: InsertPayableHelperFn| {
            insert(
                conn,
                "0x1111111111111111111111111111111111111111",
                1_000_000_002,
                now - 86_401,
                None,
            );
            insert(
                conn,
                "0x2222222222222222222222222222222222222222",
                7_562_000_300_000,
                now - 86_001,
                None,
            );
            insert(
                conn,
                "0x3333333333333333333333333333333333333333",
                999_999_999, //balance smaller than 1 gwei
                now - 86_000,
                None,
            );
            insert(
                conn,
                "0x4444444444444444444444444444444444444444",
                10_000_000_100,
                now - 86_300,
                None,
            );
            insert(
                conn,
                "0x5555555555555555555555555555555555555555",
                10_000_000_100,
                now - 86_401,
                Some(1),
            );
        })
    }

    #[test]
    fn custom_query_in_top_records_mode_with_default_ordering() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in debt's age but not balance which allows to check doubled ordering,
        //here by balance and then by age.
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
                PayableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: 7_562_000_300_000,
                    last_paid_timestamp: from_unix_timestamp(now - 86_001),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    pending_payable_opt: Some(PendingPayableId::new(
                        1,
                        H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    ))
                },
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_unix_timestamp(now - 86_300),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_in_top_records_mode_ordered_by_age() {
        //Accounts of balances smaller than one gwei don't qualify.
        //Two accounts differ only in balance but not in the debt's age which allows to check doubled ordering,
        //here by age and then by balance.
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
                PayableAccount {
                    wallet: Wallet::new("0x5555555555555555555555555555555555555555"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    pending_payable_opt: Some(PendingPayableId::new(
                        1,
                        H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    ))
                },
                PayableAccount {
                    wallet: Wallet::new("0x1111111111111111111111111111111111111111"),
                    balance_wei: 1_000_000_002,
                    last_paid_timestamp: from_unix_timestamp(now - 86_401),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance_wei: 10_000_000_100,
                    last_paid_timestamp: from_unix_timestamp(now - 86_300),
                    pending_payable_opt: None
                },
            ]
        );
    }

    #[test]
    fn custom_query_handles_empty_table_in_range_mode() {
        let main_test_setup = |_conn: &dyn ConnectionWrapper, _insert: InsertPayableHelperFn| {};
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
        let now = current_unix_timestamp();
        let main_setup = |conn: &dyn ConnectionWrapper, insert: InsertPayableHelperFn| {
            insert(
                conn,
                "0x1111111111111111111111111111111111111111",
                gwei_to_wei::<_, u64>(499_999_999), //too small
                now - 70_000,
                None,
            );
            insert(
                conn,
                "0x2222222222222222222222222222222222222222",
                gwei_to_wei::<_, u64>(1_800_456_000),
                now - 55_120,
                Some(1),
            );
            insert(
                conn,
                "0x3333333333333333333333333333333333333333",
                gwei_to_wei::<_, u64>(600_123_456),
                now - 200_001, //too old
                None,
            );
            insert(
                conn,
                "0x4444444444444444444444444444444444444444",
                gwei_to_wei::<_, u64>(1_033_456_000_u64),
                now - 19_999, //too young
                None,
            );
            insert(
                conn,
                "0x5555555555555555555555555555555555555555",
                gwei_to_wei::<_, u64>(35_000_000_001), //too big
                now - 30_786,
                None,
            );
            insert(
                conn,
                "0x6666666666666666666666666666666666666666",
                gwei_to_wei::<_, u64>(1_800_456_000u64),
                now - 100_401,
                None,
            );
            insert(
                conn,
                "0x7777777777777777777777777777777777777777",
                gwei_to_wei::<_, u64>(2_500_647_000u64),
                now - 80_333,
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
                timestamp: from_unix_timestamp(now),
            })
            .unwrap();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: Wallet::new("0x7777777777777777777777777777777777777777"),
                    balance_wei: gwei_to_wei(2_500_647_000_u32),
                    last_paid_timestamp: from_unix_timestamp(now - 80_333),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x6666666666666666666666666666666666666666"),
                    balance_wei: gwei_to_wei(1_800_456_000_u32),
                    last_paid_timestamp: from_unix_timestamp(now - 100_401),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: Wallet::new("0x2222222222222222222222222222222222222222"),
                    balance_wei: gwei_to_wei(1_800_456_000_u32),
                    last_paid_timestamp: from_unix_timestamp(now - 55_120),
                    pending_payable_opt: Some(PendingPayableId::new(
                        1,
                        H256::from_str(
                            "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
                        )
                        .unwrap()
                    ))
                }
            ]
        );
    }

    #[test]
    fn range_query_does_not_display_values_from_below_1_gwei() {
        let now = current_unix_timestamp();
        let timestamp_1 = now - 11_001;
        let timestamp_2 = now - 5000;
        let main_setup = |conn: &dyn ConnectionWrapper, insert: InsertPayableHelperFn| {
            insert(
                conn,
                "0x1111111111111111111111111111111111111111",
                400_005_601,
                timestamp_1,
                None,
            );
            insert(
                conn,
                "0x2222222222222222222222222222222222222222",
                30_000_300_000,
                timestamp_2,
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
                last_paid_timestamp: from_unix_timestamp(timestamp_2),
                pending_payable_opt: None
            },]
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
            None,
        );
        insert_payable_record_fn(
            &*conn,
            "0x2222222222222222222222222222222222222222",
            1_000_123_123,
            timestamp - 2000,
            None,
        );
        insert_payable_record_fn(
            &*conn,
            "0x3333333333333333333333333333333333333333",
            1_000_000_000,
            timestamp - 3000,
            None,
        );
        insert_payable_record_fn(
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
            None,
        );
        insert_payable_record_fn(
            &*conn,
            "0x2222222222222222222222222222222222222222",
            -999_999,
            222_222_222,
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
            PayableDaoReal::create_payable_account,
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
        F: Fn(&dyn ConnectionWrapper, InsertPayableHelperFn),
    {
        let home_dir = ensure_node_home_directory_exists("payable_dao", test_name);
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        main_setup_fn(conn.as_ref(), &insert_payable_record_fn);

        let pending_payable_account: &[&dyn ToSql] = &[
            &String::from("0xabc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"),
            &40,
            &478945,
            &177777777,
            &1,
        ];
        conn
            .prepare("insert into pending_payable (transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt) values (?,?,?,?,?)")
            .unwrap()
            .execute(pending_payable_account)
            .unwrap();
        PayableDaoReal::new(conn)
    }
}
