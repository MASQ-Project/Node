// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::blob_utils::{
    collect_and_sum_i128_values_from_table, get_unsized_128, BalanceChange, InsertUpdateConfig,
    InsertUpdateCore, InsertUpdateCoreReal, ParamKeyHolder, SQLExtendedParams, Table, UpdateConfig,
};
use crate::accountant::dao_utils;
use crate::accountant::dao_utils::{to_time_t, DaoFactoryReal};
use crate::accountant::{checked_conversion, sign_conversion, PendingPayableId};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::{BigEndianHash, U256};
use itertools::Either;
use masq_lib::utils::ExpectValue;
use rusqlite::types::ToSql;
use rusqlite::{Error, OptionalExtension};
use std::fmt::Debug;
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
    pub balance: u128,
    pub last_paid_timestamp: SystemTime,
    pub pending_payable_opt: Option<PendingPayableId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payable {
    pub to: Wallet,
    pub amount: u64,
    pub timestamp: SystemTime,
    pub tx_hash: H256,
}

impl Payable {
    pub fn new(to: Wallet, amount: u64, txn: H256, timestamp: SystemTime) -> Self {
        Self {
            to,
            amount,
            timestamp,
            tx_hash: txn,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(&self, wallet: &Wallet, amount: u128) -> Result<(), PayableDaoError>;

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

    //fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount>;

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
    insert_update_core: Box<dyn InsertUpdateCore>,
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(&self, wallet: &Wallet, amount: u128) -> Result<(), PayableDaoError> {
        Ok(self.insert_update_core.upsert(self.conn.as_ref(), InsertUpdateConfig{
            insert_sql: "insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (:wallet,:balance,strftime('%s','now'),null)",
            update_sql: "update payable set balance = :updated_balance where wallet_address = :wallet",
            params: SQLExtendedParams::new(
                vec![
                    (":wallet", &ParamKeyHolder::new(wallet,"wallet_address")),
                    (":balance", &BalanceChange::new_addition(amount))
                ]),
            table: Table::Payable,
        })?)
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
        Ok(self.insert_update_core.update(Either::Left(self.conn.as_ref()), &UpdateConfig{
            update_sql: "update payable set balance = :updated_balance, last_paid_timestamp = :last_paid, pending_payable_rowid = null where pending_payable_rowid = :rowid",
            params: SQLExtendedParams::new(
                vec![
                    (":balance", &BalanceChange::new_subtraction(fingerprint.amount)),
                    (":last_paid", &to_time_t(fingerprint.timestamp)),
                    (":rowid", &ParamKeyHolder::new(&checked_conversion::<u64, i64>(fingerprint.rowid_opt.expectv("initialized rowid")),"pending_payable_rowid")),
                ]),
            table: Table::Payable,
        })?)
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select wallet_address, balance, last_paid_timestamp from payable where pending_payable_rowid is null")
            .expect("Internal error");

        stmt.query_map([], |row| {
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(0);
            let balance_result = get_unsized_128(row, 1);
            let last_paid_timestamp_result = row.get(2);
            match (wallet_result, balance_result, last_paid_timestamp_result) {
                (Ok(wallet), Ok(balance), Ok(last_paid_timestamp)) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payable_opt: None,
                }),
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    //TODO: never used!!
    //fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
    //     let min_amt =
    //         unsigned_to_signed::<u64, i64>(minimum_amount).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
    //     let max_age = unsigned_to_signed::<u64, i64>(maximum_age).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
    //     let min_timestamp = dao_utils::now_time_t() - max_age;
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             r#"
    //             select
    //                 balance,
    //                 last_paid_timestamp,
    //                 wallet_address,
    //                 pending_payable_rowid,
    //                 pending_payable.transaction_hash
    //             from
    //                 payable
    //             left join pending_payable on
    //                 pending_payable.rowid = payable.pending_payable_rowid
    //             where
    //                 balance >= ? and
    //                 last_paid_timestamp >= ?
    //             order by
    //                 balance desc,
    //                 last_paid_timestamp desc
    //         "#,
    //         )
    //         .expect("Internal error");
    //     let params: &[&dyn ToSql] = &[&min_amt, &min_timestamp];
    //     stmt.query_map(params, |row| {
    //         let balance_result = get_unsized_128(row, 0);
    //         let last_paid_timestamp_result = row.get(1);
    //         let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
    //         let pending_payable_rowid_result_opt: Result<Option<u64>, Error> = row.get(3);
    //         let pending_payable_hash_result_opt: Result<Option<String>, Error> = row.get(4);
    //         match (
    //             wallet_result,
    //             balance_result,
    //             last_paid_timestamp_result,
    //             pending_payable_rowid_result_opt,
    //             pending_payable_hash_result_opt,
    //         ) {
    //             (
    //                 Ok(wallet),
    //                 Ok(balance),
    //                 Ok(last_paid_timestamp),
    //                 Ok(pending_payable_rowid_opt),
    //                 Ok(pending_payable_hash_opt),
    //             ) => Ok(PayableAccount {
    //                 wallet,
    //                 balance,
    //                 last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
    //                 pending_payable_opt: pending_payable_rowid_opt.map(|rowid| PendingPayableId {
    //                     rowid,
    //                     hash: pending_payable_hash_opt
    //                         .map(|s| H256::from_str(&s[2..]).expectv("string tx hash"))
    //                         .expectv("tx hash"),
    //                 }),
    //             }),
    //             x => panic!(
    //                 "Database is corrupt: PAYABLE table columns and/or types {:?}",
    //                 x
    //             ),
    //         }
    //     })
    //     .expect("Database is corrupt")
    //     .flatten()
    //     .collect()
    // }

    fn total(&self) -> u128 {
        sign_conversion::<i128, u128>(collect_and_sum_i128_values_from_table(
            self.conn.as_ref(),
            Table::Payable,
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
            .prepare("select balance, last_paid_timestamp, pending_payable_rowid from payable where wallet_address = ?")
            .unwrap();
        stmt.query_row(&[&wallet], |row| {
            let balance_result = get_unsized_128(row, 0);
            let last_paid_timestamp_result = row.get(1);
            let pending_payable_rowid_result: Result<Option<i64>, Error> = row.get(2);
            match (
                balance_result,
                last_paid_timestamp_result,
                pending_payable_rowid_result,
            ) {
                (Ok(balance), Ok(last_paid_timestamp), Ok(rowid)) => Ok(PayableAccount {
                    wallet: wallet.clone(),
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payable_opt: match rowid {
                        Some(rowid) => Some(PendingPayableId {
                            rowid: u64::try_from(rowid).unwrap(),
                            hash: H256::from_uint(&U256::from(0)), //garbage
                        }),
                        None => None,
                    },
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
            insert_update_core: Box::new(InsertUpdateCoreReal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::blob_utils::{InsertUpdateError, Table};
    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::accountant::test_utils::{
        convert_to_all_string_values, make_pending_payable_fingerprint, InsertUpdateCoreMock,
    };
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::db_initializer;
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::make_wallet;
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection as RusqliteConnection;
    use rusqlite::{Connection, OpenFlags};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use web3::types::U256;

    #[test]
    fn more_money_payable_works_for_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_new_address",
        );
        let before = dao_utils::to_time_t(SystemTime::now());
        let wallet = make_wallet("booga");
        let status = {
            let boxed_conn = DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
            let subject = PayableDaoReal::new(boxed_conn);

            subject.more_money_payable(&wallet, 1234).unwrap();

            subject.account_status(&wallet).unwrap()
        };
        let after = dao_utils::to_time_t(SystemTime::now());
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 1234);
        let timestamp = dao_utils::to_time_t(status.last_paid_timestamp);
        assert!(
            timestamp >= before,
            "{:?} should be on or after {:?}",
            timestamp,
            before
        );
        assert!(
            timestamp <= after,
            "{:?} should be on or before {:?}",
            timestamp,
            after
        );
    }

    #[test]
    fn more_money_payable_works_for_existing_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "more_money_payable_works_for_existing_address",
        );
        let wallet = make_wallet("booga");
        let boxed_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = {
            let subject = PayableDaoReal::new(boxed_conn);
            subject.more_money_payable(&wallet, 1234).unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update payable set last_paid_timestamp = 0 where wallet_address = '0x000000000000000000000000000000626f6f6761'",
                [],
            )
            .unwrap();
            subject
        };

        subject.more_money_payable(&wallet, 2345).unwrap();

        let status = subject.account_status(&wallet).unwrap();
        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_paid_timestamp, SystemTime::UNIX_EPOCH);
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
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_payable(&wallet, u128::MAX);
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
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stm = boxed_conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp) values (?,?,?)").unwrap();
            let params: &[&dyn ToSql] = &[&wallet, &5000_i128, &150_000_000];
            stm.execute(params).unwrap();
        }
        let subject = PayableDaoReal::new(boxed_conn);
        let before_account_status = subject.account_status(&wallet).unwrap();
        let before_expected_status = PayableAccount {
            wallet: wallet.clone(),
            balance: 5000,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        };
        assert_eq!(before_account_status, before_expected_status.clone());

        subject
            .mark_pending_payable_rowid(&wallet, pending_payable_rowid)
            .unwrap();

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
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;
        let previous_timestamp = from_time_t(190_000_000);
        let payable_timestamp = from_time_t(199_000_000);
        let attempt = 5;
        let starting_amount = 10000;
        let payment = 6666;
        let wallet = make_wallet("bobble");
        {
            let params: &[&dyn ToSql] = &[
                &wallet,
                &(starting_amount as i128),
                &to_time_t(previous_timestamp),
                &sign_conversion::<u64, i64>(rowid).unwrap(),
            ];
            boxed_conn.prepare(
                "insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) \
                 values (?,?,?,?)",
            )
            .unwrap()
            .execute(params)
            .unwrap();
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
                balance: starting_amount,
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
                balance: starting_amount - payment,
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
                "Updating balance for payable of -12345 Wei to 789 with error 'Query returned no rows'".to_string()
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
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;
        pending_payable_fingerprint.hash = hash;
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.amount = u128::MAX;
        //The overflow occurs before we start modifying the payable account so I decided not to create an example in the database

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
                    balance integer not null,
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
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        assert_eq!(subject.non_pending_payables(), vec![]);
    }

    #[test]
    fn non_pending_payables_should_return_payables_with_no_pending_transaction() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "non_pending_payables_should_return_payables_with_no_pending_transaction",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let mut flags = OpenFlags::empty();
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
        let conn =
            Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                .unwrap();
        let insert = |wallet: &str, balance: i128, pending_payable_rowid: Option<i64>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &0i64, &pending_payable_rowid];

            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        insert("0x0000000000000000000000000000000000666f6f", 42, Some(15));
        insert("0x0000000000000000000000000000000000626172", 24, Some(16));
        insert(&make_wallet("foobar").to_string(), 44, None);
        insert(&make_wallet("barfoo").to_string(), 22, None);

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance: 44,
                    last_paid_timestamp: from_time_t(0),
                    pending_payable_opt: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance: 22,
                    last_paid_timestamp: from_time_t(0),
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
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let _ = subject.more_money_payable(&make_wallet("foobar"), u128::MAX);
    }

    #[test]
    fn top_records_and_total() {
        todo!("decide how to see to the top records query")
        // let home_dir = ensure_node_home_directory_exists("payable_dao", "top_records_and_total");
        // let conn = DbInitializerReal::default()
        //     .initialize(&home_dir, true, MigratorConfig::test_default())
        //     .unwrap();
        // let insert = |wallet: &str,
        //               balance: i64,
        //               timestamp: i64,
        //               pending_payable_rowid: Option<i64>| {
        //     let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp, &pending_payable_rowid];
        //     conn
        //         .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?)")
        //         .unwrap()
        //         .execute(params)
        //         .unwrap();
        // };
        // let timestamp1 = dao_utils::now_time_t() - 80_000;
        // let timestamp2 = dao_utils::now_time_t() - 86_401;
        // let timestamp3 = dao_utils::now_time_t() - 86_000;
        // let timestamp4 = dao_utils::now_time_t() - 86_001;
        // insert(
        //     "0x1111111111111111111111111111111111111111",
        //     999_999_999, // below minimum amount - reject
        //     timestamp1,  // below maximum age
        //     None,
        // );
        // insert(
        //     "0x2222222222222222222222222222222222222222",
        //     1_000_000_000, // minimum amount
        //     timestamp2,    // above maximum age - reject
        //     None,
        // );
        // insert(
        //     "0x3333333333333333333333333333333333333333",
        //     1_000_000_000, // minimum amount
        //     timestamp3,    // below maximum age
        //     None,
        // );
        // insert(
        //     "0x4444444444444444444444444444444444444444",
        //     1_000_000_001, // above minimum amount
        //     timestamp4,    // below maximum age
        //     Some(1),
        // );
        // let params: &[&dyn ToSql] = &[
        //     &String::from("0xabc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"),
        //     &40,
        //     &177777777,
        //     &1,
        // ];
        // conn
        //     .prepare("insert into pending_payable (transaction_hash,amount,payable_timestamp,attempt) values (?,?,?,?)")
        //     .unwrap()
        //     .execute(params)
        //     .unwrap();
        //
        // let subject = PayableDaoReal::new(conn);
        //
        // let top_records = subject.top_records(1_000_000_000, 86400);
        // let total = subject.total();
        // assert_eq!(
        //     top_records,
        //     vec![
        //         PayableAccount {
        //             wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
        //             balance: 1_000_000_001,
        //             last_paid_timestamp: dao_utils::from_time_t(timestamp4),
        //             pending_payable_opt: Some(PendingPayableId {
        //                 rowid: 1,
        //                 hash: H256::from_str(
        //                     "abc4546cce78230a2312e12f3acb78747340456fe5237896666100143abcd223"
        //                 )
        //                 .unwrap()
        //             })
        //         },
        //         PayableAccount {
        //             wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
        //             balance: 1_000_000_000,
        //             last_paid_timestamp: dao_utils::from_time_t(timestamp3),
        //             pending_payable_opt: None
        //         },
        //     ]
        // );
        // assert_eq!(total, 4_000_000_000)
    }

    fn insert_record(
        conn: &dyn ConnectionWrapper,
        wallet: &str,
        balance: i128,
        timestamp: i64,
        pending_payable_rowid: Option<i64>,
    ) {
        let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp, &pending_payable_rowid];
        conn
        .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) values (?, ?, ?, ?)")
        .unwrap()
        .execute(params)
        .unwrap();
    }

    #[test]
    fn total_works() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "total_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
            .initialize(&home_dir, true, MigratorConfig::test_default())
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
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PayableDaoReal::new(conn);

        let result = subject.total();

        assert_eq!(result, 0)
    }

    #[test]
    fn more_money_payable_error_handling_and_core_params_assertion() {
        let insert_or_update_params_arc = Arc::new(Mutex::new(vec![]));
        let wallet = make_wallet("xyz123");
        let amount = 100;
        let insert_update_core = InsertUpdateCoreMock::default()
            .upsert_params(&insert_or_update_params_arc)
            .upsert_results(Err(InsertUpdateError("SomethingWrong".to_string())));
        let conn = ConnectionWrapperMock::new();
        let conn_id_stamp = conn.set_arbitrary_id_stamp();
        let mut subject = PayableDaoReal::new(Box::new(conn));
        subject.insert_update_core = Box::new(insert_update_core);

        let result = subject.more_money_payable(&wallet, amount);

        assert_eq!(
            result,
            Err(PayableDaoError::RusqliteError("SomethingWrong".to_string()))
        );
        let mut insert_or_update_params = insert_or_update_params_arc.lock().unwrap();
        let (captured_conn_id_stamp, update_sql, insert_sql, table, sql_param_names) =
            insert_or_update_params.remove(0);
        assert_eq!(captured_conn_id_stamp, conn_id_stamp);
        assert!(insert_or_update_params.is_empty());
        assert_eq!(
            update_sql,
            "update payable set balance = :updated_balance where wallet_address = :wallet"
        );
        assert_eq!(insert_sql,"insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) \
         values (:wallet,:balance,strftime('%s','now'),null)"
        );
        assert_eq!(table, Table::Payable);
        assert_eq!(
            sql_param_names,
            convert_to_all_string_values(vec![
                (":wallet", &wallet.to_string()),
                (":balance", &amount.to_string())
            ])
        )
    }

    #[test]
    fn transaction_confirmed_and_core_params_assertion() {
        let update_params_arc = Arc::new(Mutex::new(vec![]));
        let wrapped_conn = ConnectionWrapperMock::new();
        let conn_id_stamp = wrapped_conn.set_arbitrary_id_stamp();
        let fingerprint = make_pending_payable_fingerprint();
        let insert_update_core = InsertUpdateCoreMock::default()
            .update_params(&update_params_arc)
            .update_result(Ok(()));
        let mut subject = PayableDaoReal::new(Box::new(wrapped_conn));
        subject.insert_update_core = Box::new(insert_update_core);

        let result = subject.transaction_confirmed(&fingerprint);

        assert_eq!(result, Ok(()));
        let mut update_params = update_params_arc.lock().unwrap();
        let (captured_conn_id_stamp_opt, select_sql, update_sql, table, sql_param_names) =
            update_params.remove(0);
        assert_eq!(captured_conn_id_stamp_opt.unwrap(), conn_id_stamp);
        assert!(update_params.is_empty());
        assert_eq!(
            select_sql,
            "select balance from payable where pending_payable_rowid = :rowid"
        );
        assert_eq!(
            update_sql,
            "update payable set balance = :updated_balance, last_paid_timestamp = :last_paid, \
         pending_payable_rowid = null where pending_payable_rowid = :rowid"
        );
        assert_eq!(table, Table::Payable.to_string());
        assert_eq!(
            sql_param_names,
            convert_to_all_string_values(vec![
                (":balance", &(-12345_i128).to_string()),
                (
                    ":last_paid",
                    &to_time_t(from_time_t(222_222_222)).to_string()
                ),
                (":rowid", &33_i64.to_string())
            ])
        )
    }
}
