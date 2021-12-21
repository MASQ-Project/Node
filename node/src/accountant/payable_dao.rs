// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::{
    jackass_unsigned_to_signed, DebtRecordingError, PaymentError, PaymentErrorKind, TransactionId,
};
use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils;
use crate::database::dao_utils::DaoFactoryReal;
use crate::sub_lib::wallet::Wallet;
use rusqlite::types::{Null, ToSql, Type};
use rusqlite::{Error, OptionalExtension, NO_PARAMS};
use std::fmt::Debug;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Clone, Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_rowid_opt: Option<u64>,
}

//TODO we probably can cut back this struct below as we need very little from it

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub to: Wallet,
    pub amount: u64,
    pub timestamp: SystemTime,
    pub transaction: H256,
    //rowid from pending_payments corresponding to this wallet account in payables
    pub rowid: u64,
}

impl Payment {
    pub fn new(to: Wallet, amount: u64, txn: H256, timestamp: SystemTime, rowid: u64) -> Self {
        Self {
            to,
            amount,
            timestamp,
            transaction: txn,
            rowid,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) -> Result<(), DebtRecordingError>;

    fn mark_pending_payment_rowid(&self, wallet: &Wallet, rowid: u64) -> Result<(), PaymentError>;

    fn transaction_confirmed(&self, payment: &PaymentBackupRecord) -> Result<(), PaymentError>;

    fn transaction_canceled(&self, transaction_id: TransactionId) -> Result<(), PaymentError>;

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount>;

    fn non_pending_payables(&self) -> Vec<PayableAccount>;

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount>;

    fn total(&self) -> u64;
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
}

impl PayableDao for PayableDaoReal {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) -> Result<(), DebtRecordingError> {
        let signed_amount = jackass_unsigned_to_signed(amount)
            .map_err(|err_num| DebtRecordingError::SignConversion(err_num))?;
        match self.try_increase_balance(wallet, signed_amount) {
            Ok(_) => Ok(()),
            Err(e) => panic!("Database is corrupt: {}", e),
        }
    }

    fn mark_pending_payment_rowid(&self, wallet: &Wallet, rowid: u64) -> Result<(), PaymentError> {
        let mut stm = self
            .conn
            .prepare("update payable set pending_payment_rowid=? where wallet_address=?")
            .expect("Internal Error");
        let params: &[&dyn ToSql] = &[
            &jackass_unsigned_to_signed(rowid)
                .expect("SQLite counts up to i64::MAX; should never happen"),
            wallet,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(num) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn transaction_confirmed(&self, payment: &PaymentBackupRecord) -> Result<(), PaymentError> {
        let signed_amount = jackass_unsigned_to_signed(payment.amount).map_err(|err_num| {
            PaymentError(PaymentErrorKind::SignConversion(err_num), payment.into())
        })?;
        if let Err(e) = self
            .try_decrease_balance(payment.rowid, signed_amount, payment.timestamp)
            .map_err(|e| PaymentError(PaymentErrorKind::RusqliteError(e), payment.into()))
        {
            unimplemented!()
        }
        let formally_signed_rowid = jackass_unsigned_to_signed(payment.rowid)
            .expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("update payable set pending_payment_rowid=? where pending_payment_rowid=?")
            .expect("Internal Error");
        let params: &[&dyn ToSql] = &[&Null, &formally_signed_rowid];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(num) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn transaction_canceled(&self, transaction_id: TransactionId) -> Result<(), PaymentError> {
        let formally_signed_rowid =
            jackass_unsigned_to_signed(transaction_id.rowid).map_err(|e| {
                unimplemented!();
                PaymentError(PaymentErrorKind::SignConversion(e), transaction_id)
            })?;
        let mut stm = self
            .conn
            .prepare("update payable set pending_payment_rowid = ? where pending_payment_rowid = ?")
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&Null, &formally_signed_rowid];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!("{}", x),
            Err(e) => unimplemented!(),
        }
    }

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select rowid, balance, last_paid_timestamp, pending_payment_rowid from payable where wallet_address = ?")
            .expect("Internal error");
        match stmt
            .query_row(&[&wallet], |row| {
                let balance_result = row.get(1);
                let last_paid_timestamp_result = row.get(2);
                let pending_payment_rowid_result: Result<Option<i64>, Error> = row.get(3);
                match (
                    balance_result,
                    last_paid_timestamp_result,
                    pending_payment_rowid_result,
                ) {
                    (Ok(balance), Ok(last_paid_timestamp), Ok(rowid)) => Ok(PayableAccount {
                        wallet: wallet.clone(),
                        balance,
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payment_rowid_opt: rowid.map(|num| {
                            u64::try_from(num).expect("SQLite counts this just in positive numbers")
                        }),
                    }),
                    _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
                }
            })
            .optional()
        {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select wallet_address, balance, last_paid_timestamp from payable where pending_payments_rowid is null")
            .expect("Internal error");

        stmt.query_map(NO_PARAMS, |row| {
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(0);
            let balance_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            let rowid: rusqlite::Result<Option<i64>> = row.get(3);
            match (
                wallet_result,
                balance_result,
                last_paid_timestamp_result,
                rowid,
            ) {
                (Ok(wallet), Ok(balance), Ok(last_paid_timestamp), Ok(rowid_opt)) => {
                    Ok(PayableAccount {
                        wallet,
                        balance,
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payment_rowid_opt: rowid_opt.map(|num| {
                            u64::try_from(num).expect(
                                "SQLite counts this in only positive numbers; should never happen",
                            )
                        }),
                    })
                }
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
        let min_amt = jackass_unsigned_to_signed(minimum_amount).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let max_age = jackass_unsigned_to_signed(maximum_age).unwrap_or(0x7FFF_FFFF_FFFF_FFFF);
        let min_timestamp = dao_utils::now_time_t() - max_age;
        let mut stmt = self
            .conn
            .prepare(
                r#"
                select
                    balance,
                    last_paid_timestamp,
                    wallet_address,
                    pending_payment_rowid
                from
                    payable
                where
                    balance >= ? and
                    last_paid_timestamp >= ?
                order by
                    balance desc,
                    last_paid_timestamp desc
            "#,
            )
            .expect("Internal error");
        let params: &[&dyn ToSql] = &[&min_amt, &min_timestamp];
        stmt.query_map(params, |row| {
            let balance_result = row.get(0);
            let last_paid_timestamp_result = row.get(1);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(2);
            let pending_payments_rowid_result_opt: Result<Option<i64>, Error> = row.get(3);
            match (
                wallet_result,
                balance_result,
                last_paid_timestamp_result,
                pending_payments_rowid_result_opt,
            ) {
                (
                    Ok(wallet),
                    Ok(balance),
                    Ok(last_paid_timestamp),
                    Ok(pending_payment_rowid_opt),
                ) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payment_rowid_opt: pending_payment_rowid_opt.map(|num| {
                        u64::try_from(num).expect(
                            "SQLite counts this just in positive numbers; should never happened",
                        )
                    }),
                }),
                _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
            }
        })
        .expect("Database is corrupt")
        .flatten()
        .collect()
    }

    fn total(&self) -> u64 {
        let mut stmt = self
            .conn
            .prepare("select sum(balance) from payable")
            .expect("Internal error");
        match stmt.query_row(NO_PARAMS, |row| {
            let total_balance_result: Result<i64, rusqlite::Error> = row.get(0);
            match total_balance_result {
                Ok(total_balance) => Ok(total_balance as u64),
                Err(e)
                    if e == rusqlite::Error::InvalidColumnType(
                        0,
                        "sum(balance)".to_string(),
                        Type::Null,
                    ) =>
                {
                    Ok(0u64)
                }
                Err(e) => panic!(
                    "Database is corrupt: PAYABLE table columns and/or types: {:?}",
                    e
                ),
            }
        }) {
            Ok(value) => value,
            Err(e) => panic!("Database is corrupt: {:?}", e),
        }
    }
}

impl PayableDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> PayableDaoReal {
        PayableDaoReal { conn }
    }

    fn try_increase_balance(&self, wallet: &Wallet, amount: i64) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (:address, :balance, strftime('%s','now'), null) on conflict (wallet_address) do update set balance = balance + :balance where wallet_address = :address")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[(":address", &wallet), (":balance", &amount)];
        match stmt.execute_named(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }

    fn try_decrease_balance(
        &self,
        rowid: u64,
        amount: i64,
        last_paid_timestamp: SystemTime,
    ) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare("update payable set balance = balance - :balance, last_paid_timestamp = :last_paid where pending_payment_rowid = :referential_rowid")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (":balance", &amount),
            (":last_paid", &dao_utils::to_time_t(last_paid_timestamp)),
            (
                ":referential_rowid",
                &i64::try_from(rowid).expect("SQLite was wrong when choosing the rowid"),
            ),
        ];
        match stmt.execute_named(params) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!("{}", x),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::make_payment_backup;
    use crate::accountant::TransactionId;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::make_wallet;
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection as RusqliteConnection;
    use rusqlite::{Connection, OpenFlags, NO_PARAMS};
    use std::path::Path;
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
            let subject = PayableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, MigratorConfig::test_default())
                    .unwrap(),
            );

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
        let subject = {
            let subject = PayableDaoReal::new(
                DbInitializerReal::default()
                    .initialize(&home_dir, true, MigratorConfig::test_default())
                    .unwrap(),
            );
            subject.more_money_payable(&wallet, 1234).unwrap();
            let mut flags = OpenFlags::empty();
            flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
            let conn =
                Connection::open_with_flags(&home_dir.join(db_initializer::DATABASE_FILE), flags)
                    .unwrap();
            conn.execute(
                "update payable set last_paid_timestamp = 0 where wallet_address = '0x000000000000000000000000000000626f6f6761'",
                NO_PARAMS,
            )
            .unwrap();
            subject
        };

        let status = {
            subject.more_money_payable(&wallet, 2345).unwrap();
            subject.account_status(&wallet).unwrap()
        };

        assert_eq!(status.wallet, wallet);
        assert_eq!(status.balance, 3579);
        assert_eq!(status.last_paid_timestamp, SystemTime::UNIX_EPOCH);
    }

    #[test]
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

        let result = subject.more_money_payable(&wallet, std::u64::MAX);

        assert_eq!(result, Err(DebtRecordingError::SignConversion(u64::MAX)));
    }

    #[test]
    fn mark_pending_payment_marks_a_pending_transaction_for_a_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payment_marks_a_pending_transaction_for_a_new_address",
        );
        let wallet = make_wallet("booga");
        let pending_payments_rowid = 656;
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp) values (?,?,?)").unwrap();
            let params: &[&dyn ToSql] = &[&wallet, &5000, &150_000_000];
            stm.execute(params).unwrap();
        }
        let subject = PayableDaoReal::new(conn);
        let before_account_status = subject.account_status(&wallet).unwrap();
        let before_expected_status = PayableAccount {
            wallet: wallet.clone(),
            balance: 5000,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payment_rowid_opt: None,
        };
        assert_eq!(before_account_status, before_expected_status.clone());

        subject
            .mark_pending_payment_rowid(&wallet, pending_payments_rowid)
            .unwrap();

        let after_account_status = subject.account_status(&wallet).unwrap();
        let mut after_expected_status = before_expected_status;
        after_expected_status.pending_payment_rowid_opt = Some(pending_payments_rowid);
        assert_eq!(after_account_status, after_expected_status)
    }

    #[test]
    fn payment_sent_records_a_pending_transaction_for_an_existing_address() {
        todo!("convert this into transaction_confirmed()")
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "payment_sent_records_a_pending_transaction_for_an_existing_address",
        // );
        // let wallet = make_wallet("booga");
        // let subject = PayableDaoReal::new(
        //     DbInitializerReal::default()
        //         .initialize(&home_dir, true, MigratorConfig::test_default())
        //         .unwrap(),
        // );
        // let payment = Payment::new(wallet.clone(), 1, H256::from_uint(&U256::from(1)));
        //
        // let before_account_status = subject.account_status(&payment.to);
        // assert!(before_account_status.is_none());
        // subject.more_money_payable(&wallet, 1).unwrap();
        // subject.mark_pending_payment(&payment).unwrap();
        //
        // let after_account_status = subject.account_status(&payment.to).unwrap();
        //
        // assert_eq!(
        //     after_account_status.clone(),
        //     PayableAccount {
        //         wallet,
        //         balance: 0,
        //         last_paid_timestamp: after_account_status.last_paid_timestamp,
        //         pending_payment_transaction: Some(H256::from_uint(&U256::from(1))),
        //     }
        // )
    }

    #[test]
    fn payment_sent_works_for_overflow() {
        todo!("maybe convert this into transaction_confirmed()")
        // let home_dir =
        //     ensure_node_home_directory_exists("payable_dao", "payment_sent_works_for_overflow");
        // let wallet = make_wallet("booga");
        // let subject = PayableDaoReal::new(
        //     DbInitializerReal::default()
        //         .initialize(&home_dir, true, MigratorConfig::test_default())
        //         .unwrap(),
        // );
        // let payment = Payment::new(wallet, u64::MAX, H256::from_uint(&U256::from(1)));
        //
        // let result = subject.mark_pending_payment(&payment);
        //
        // assert_eq!(
        //     result,
        //     Err(PaymentError::PostTransaction(
        //         PaymentErrorKind::SignConversion(u64::MAX),
        //         payment.transaction
        //     ))
        // )
    }

    #[test]
    fn transaction_canceled_works_for_overflow() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_canceled_works_for_overflow",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;

        let result = subject.transaction_canceled(TransactionId { hash, rowid });

        assert_eq!(
            result,
            Err(PaymentError(
                PaymentErrorKind::SignConversion(u64::MAX),
                TransactionId { hash, rowid }
            ))
        )
    }

    #[test]
    fn transaction_canceled_works_for_generic_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_canceled_works_for_generic_sql_error",
        );
        let conn = how_to_trick_rusqlite_to_throw_an_error(&home_dir);
        let conn_wrapped = ConnectionWrapperReal::new(conn);
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));
        let hash = H256::from_uint(&U256::from(12345));
        let rowid = 789;

        let result = subject.transaction_canceled(TransactionId { hash, rowid });

        assert_eq!(
            result,
            Err(PaymentError(
                PaymentErrorKind::RusqliteError("attempt to write a readonly database".to_string()),
                TransactionId { hash, rowid }
            ))
        )
    }

    #[test]
    fn transaction_confirmed_works_for_generic_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "transaction_confirmed_works_for_generic_sql_error",
        );
        let conn = how_to_trick_rusqlite_to_throw_an_error(&home_dir);
        let conn_wrapped = ConnectionWrapperReal::new(conn);
        let payment_backup = make_payment_backup();
        let hash = H256::from_uint(&U256::from(12345));
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));

        let result = subject.transaction_confirmed(&payment_backup);

        assert_eq!(
            result,
            Err(PaymentError(
                PaymentErrorKind::RusqliteError("attempt to write a readonly database".to_string()),
                TransactionId {
                    hash,
                    rowid: unimplemented!()
                }
            ))
        )
    }

    fn how_to_trick_rusqlite_to_throw_an_error(path: &Path) -> Connection {
        let db_path = path.join("experiment.db");
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::default()).unwrap();
        {
            let mut stm = conn
                .prepare(
                    "\
                    create table payable (\
                    wallet_address real primary key,
                    balance text not null,
                    last_paid_timestamp real not null,
                    pending_payment_transaction real not null)\
                    ",
                )
                .unwrap();
            stm.execute(NO_PARAMS).unwrap();
        }
        conn.close().unwrap();
        let conn = RusqliteConnection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
        conn
    }

    #[test]
    fn payable_account_status_works_when_account_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_account_status_works_when_account_doesnt_exist",
        );
        let wallet = make_wallet("booga");
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.account_status(&wallet);

        assert_eq!(result, None);
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
        let insert = |wallet: &str, balance: i64, pending_payment_transaction: Option<&str>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &0i64, &pending_payment_transaction];

            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };

        insert(
            "0x0000000000000000000000000000000000666f6f",
            42,
            Some("0x155553215215"),
        );
        insert(
            "0x0000000000000000000000000000000000626172",
            24,
            Some("0x689477777623"),
        );
        insert("0x0000000000000000000000000000666f6f626172", 44, None);
        insert("0x0000000000000000000000000000626172666f6f", 22, None);

        let result = subject.non_pending_payables();

        assert_eq!(
            result,
            vec![
                PayableAccount {
                    wallet: make_wallet("foobar"),
                    balance: 44,
                    last_paid_timestamp: from_time_t(0),
                    pending_payment_rowid_opt: None
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance: 22,
                    last_paid_timestamp: from_time_t(0),
                    pending_payment_rowid_opt: None
                },
            ]
        );
    }

    #[test]
    fn payable_amount_errors_on_insert_when_out_of_range() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "payable_amount_precision_loss_panics_on_insert",
        );
        let subject = PayableDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.more_money_payable(&make_wallet("foobar"), u64::MAX);

        assert_eq!(result, Err(DebtRecordingError::SignConversion(u64::MAX)))
    }

    #[test]
    fn payable_amount_errors_on_update_balance_when_out_of_range() {
        todo!("maybe convert this into transaction_confirmed()")
        // let home_dir = ensure_node_home_directory_exists(
        //     "payable_dao",
        //     "payable_amount_precision_loss_panics_on_update_balance",
        // );
        // let payment = Payment::new(
        //     make_wallet("foobar"),
        //     u64::MAX,
        //     H256::from_uint(&U256::from(123)),
        // );
        // let subject = PayableDaoReal::new(
        //     DbInitializerReal::default()
        //         .initialize(&home_dir, true, MigratorConfig::test_default())
        //         .unwrap(),
        // );
        //
        // let result = subject.mark_pending_payment(&payment);
        //
        // assert_eq!(
        //     result,
        //     Err(PaymentError::PostTransaction(
        //         PaymentErrorKind::SignConversion(u64::MAX),
        //         payment.transaction
        //     ))
        // )
    }

    #[test]
    fn top_records_and_total() {
        let home_dir = ensure_node_home_directory_exists("payable_dao", "top_records_and_total");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let insert = |wallet: &str,
                      balance: i64,
                      timestamp: i64,
                      pending_payment_rowid: Option<i64>| {
            let params: &[&dyn ToSql] = &[&wallet, &balance, &timestamp, &pending_payment_rowid];
            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_rowid) values (?, ?, ?, ?)")
                .unwrap()
                .execute(params)
                .unwrap();
        };
        let timestamp1 = dao_utils::now_time_t() - 80_000;
        let timestamp2 = dao_utils::now_time_t() - 86_401;
        let timestamp3 = dao_utils::now_time_t() - 86_000;
        let timestamp4 = dao_utils::now_time_t() - 86_001;
        insert(
            "0x1111111111111111111111111111111111111111",
            999_999_999, // below minimum amount - reject
            timestamp1,  // below maximum age
            None,
        );
        insert(
            "0x2222222222222222222222222222222222222222",
            1_000_000_000, // minimum amount
            timestamp2,    // above maximum age - reject
            None,
        );
        insert(
            "0x3333333333333333333333333333333333333333",
            1_000_000_000, // minimum amount
            timestamp3,    // below maximum age
            None,
        );
        insert(
            "0x4444444444444444444444444444444444444444",
            1_000_000_001, // above minimum amount
            timestamp4,    // below maximum age
            Some(4789),
        );

        let subject = PayableDaoReal::new(conn);

        let top_records = subject.top_records(1_000_000_000, 86400);
        let total = subject.total();

        assert_eq!(
            top_records,
            vec![
                PayableAccount {
                    wallet: Wallet::new("0x4444444444444444444444444444444444444444"),
                    balance: 1_000_000_001,
                    last_paid_timestamp: dao_utils::from_time_t(timestamp4),
                    pending_payment_rowid_opt: Some(4789)
                },
                PayableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance: 1_000_000_000,
                    last_paid_timestamp: dao_utils::from_time_t(timestamp3),
                    pending_payment_rowid_opt: None
                },
            ]
        );
        assert_eq!(total, 4_000_000_000)
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
}
