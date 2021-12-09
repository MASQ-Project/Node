// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::{
    jackass_unsigned_to_signed, DebtRecordingError, PaymentError, PaymentErrorKind,
};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils;
use crate::database::dao_utils::DaoFactoryReal;
use crate::sub_lib::wallet::Wallet;
use rusqlite::types::{ToSql, Type};
use rusqlite::{Error, OptionalExtension, NO_PARAMS};
use serde_json::{self, json};
use std::fmt::Debug;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Clone, Debug, PartialEq)]
pub struct PayableAccount {
    pub wallet: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_transaction: Option<H256>,
    pub rowid: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub to: Wallet,
    pub amount: u64,
    pub timestamp: SystemTime,
    pub previous_timestamp: SystemTime,
    pub transaction: H256,
    pub rowid: u16, // taken from payables which also fills a referential column in pending_payments
}

impl Payment {
    pub fn new(
        to: Wallet,
        amount: u64,
        txn: H256,
        timestamp: SystemTime,
        previous_timestamp: SystemTime,
        rowid: u16,
    ) -> Self {
        Self {
            to,
            amount,
            timestamp,
            previous_timestamp,
            transaction: txn,
            rowid,
        }
    }
}

pub trait PayableDao: Debug + Send {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) -> Result<(), DebtRecordingError>;

    fn mark_pending_payment(&self, wallet: &Wallet, hash: H256) -> Result<(), PaymentError>;

    fn transaction_confirmed(&self, payment: &Payment) -> Result<(), PaymentError>;

    fn transaction_canceled(&self, wallet: &Wallet, hash: H256) -> Result<(), PaymentError>;

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

    fn mark_pending_payment(&self, wallet: &Wallet, hash: H256) -> Result<(), PaymentError> {
        let mut stm = self
            .conn
            .prepare("update payable set pending_payment_transaction=? where wallet_address=?")
            .expect("Internal Error");
        let params: &[&dyn ToSql] = &[&format!("0x{:x}", hash), wallet];
        match stm.execute(params) {
            Ok(0) => unimplemented!(),
            Ok(1) => Ok(()),
            Ok(_) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn transaction_confirmed(&self, payment: &Payment) -> Result<(), PaymentError> {
        unimplemented!()
        // //TODO we will need to make the code below work here as it was moved from the old "sent payments"
        // // let signed_amount = jackass_unsigned_to_signed(payment.amount).map_err(|err_num| {
        // //     PaymentError::PostTransaction(
        // //         PaymentErrorKind::SignConversion(err_num),
        // //         payment.transaction,
        // //     )
        // // })?;
        // // match self.try_decrease_balance(
        // //     &payment.to,
        // //     signed_amount,
        // //     payment.timestamp,
        // //     payment.transaction,
        // // ) {
        // //     Ok(_) => Ok(unimplemented!()),
        // //     Err(e) => panic!("Database is corrupt: {}", e),
        // // }
        // let mut stm = self.conn.prepare("update payable set pending_payment_transaction = ? where pending_payment_transaction = ?").expect("Internal error");
        // let params: &[&dyn ToSql] = &[&Null, &format!("0x{:x}", hash)];
        // match stm.execute(params) {
        //     Ok(1) => Ok(()),
        //     Ok(x) => panic!("unexpected behaviour; expected just one row, got: {}", x), //technically untested
        //     Err(e) => Err(PaymentError::PostTransaction(
        //         PaymentErrorKind::RusqliteError(e.to_string()),
        //         hash,
        //     )),
        // }
    }

    fn transaction_canceled(
        &self,
        invalid_payment: &Wallet,
        hash: H256,
    ) -> Result<(), PaymentError> {
        unimplemented!()
        // let mut stm = self.conn
        //     .prepare("update payable set balance = balance + ?, last_paid_timestamp = ?, pending_payment_transaction = ? where wallet_address = ? and pending_payment_transaction = ?").expect("Internal error");
        // let params: &[&dyn ToSql] = &[
        //     &amount_signed,
        //     &to_time_t(unimplemented!()),
        //     &Null,
        //     &invalid_payment.to,
        //     &format!("0x{:x}", invalid_payment.transaction),
        // ];
        // match stm.execute(params) {
        //     Ok(1) => self
        //         .account_status(&invalid_payment.to)
        //         .expect("the row just modified somehow disappeared now")
        //         .balance
        //         .wrap_to_ok(),
        //     Ok(x) => panic!("unexpected behaviour; expected just one row, got: {}", x), //technically untested
        //     Err(e) => Err(PaymentError::PostTransaction(
        //         PaymentErrorKind::RusqliteError(e.to_string()),
        //         invalid_payment.transaction,
        //     )),
        // }
    }

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        let mut stmt = self.conn
            .prepare("select rowid, balance, last_paid_timestamp, pending_payment_transaction from payable where wallet_address = ?")
            .expect("Internal error");
        match stmt
            .query_row(&[&wallet], |row| {
                let rowid = row.get(0);
                let balance_result = row.get(1);
                let last_paid_timestamp_result = row.get(2);
                let pending_payment_transaction_result: Result<Option<String>, Error> = row.get(3);
                match (
                    rowid,
                    balance_result,
                    last_paid_timestamp_result,
                    pending_payment_transaction_result,
                ) {
                    (
                        Ok(rowid),
                        Ok(balance),
                        Ok(last_paid_timestamp),
                        Ok(pending_payment_transaction),
                    ) => Ok(PayableAccount {
                        wallet: wallet.clone(),
                        balance,
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payment_transaction: match pending_payment_transaction {
                            Some(tx) => match serde_json::from_value(json!(tx)) {
                                Ok(transaction) => Some(transaction),
                                Err(e) => panic!("{:?}", e),
                            },
                            None => None,
                        },
                        rowid,
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
            .prepare("select rowid, balance, last_paid_timestamp, wallet_address from payable where pending_payment_transaction is null")
            .expect("Internal error");

        stmt.query_map(NO_PARAMS, |row| {
            let rowid = row.get(0);
            let balance_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(3);
            match (
                rowid,
                balance_result,
                last_paid_timestamp_result,
                wallet_result,
            ) {
                (Ok(rowid), Ok(balance), Ok(last_paid_timestamp), Ok(wallet)) => {
                    Ok(PayableAccount {
                        wallet,
                        balance,
                        last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                        pending_payment_transaction: None,
                        rowid,
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
                    pending_payment_transaction
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
            let rowid = row.get(0);
            let balance_result = row.get(1);
            let last_paid_timestamp_result = row.get(2);
            let wallet_result: Result<Wallet, rusqlite::Error> = row.get(3);
            let pending_payment_transaction_result: Result<Option<String>, Error> = row.get(4);
            match (
                rowid,
                balance_result,
                last_paid_timestamp_result,
                wallet_result,
                pending_payment_transaction_result,
            ) {
                (
                    Ok(rowid),
                    Ok(balance),
                    Ok(last_paid_timestamp),
                    Ok(wallet),
                    Ok(pending_payment_transaction),
                ) => Ok(PayableAccount {
                    wallet,
                    balance,
                    last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                    pending_payment_transaction: match pending_payment_transaction {
                        Some(tx) => match serde_json::from_value(json!(tx)) {
                            Ok(transaction) => Some(transaction),
                            Err(e) => panic!("{:?}", e),
                        },
                        None => None,
                    },
                    rowid,
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
        wallet: &Wallet,
        amount: i64,
        last_paid_timestamp: SystemTime,
        transaction_hash: H256,
    ) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("insert into payable (balance, last_paid_timestamp, pending_payment_transaction, wallet_address) values (0 - :balance, :last_paid, :transaction, :address) on conflict (wallet_address) do update set balance = balance - :balance, last_paid_timestamp = :last_paid, pending_payment_transaction = :transaction where wallet_address = :address")
            .expect("Internal error");
        let params: &[(&str, &dyn ToSql)] = &[
            (":balance", &amount),
            (":last_paid", &dao_utils::to_time_t(last_paid_timestamp)),
            (":transaction", &format!("{:#x}", &transaction_hash)),
            (":address", &wallet),
        ];
        match stmt.execute_named(params) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    use std::str::FromStr;
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
    fn mark_pending_payment_records_a_pending_transaction_for_a_new_address() {
        let home_dir = ensure_node_home_directory_exists(
            "payable_dao",
            "mark_pending_payment_records_a_pending_transaction_for_a_new_address",
        );
        let wallet = make_wallet("booga");
        let tx_hash = H256::from_uint(&U256::from(123456));
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
            pending_payment_transaction: None,
            rowid: 1,
        };
        assert_eq!(before_account_status, before_expected_status.clone());

        subject.mark_pending_payment(&wallet, tx_hash).unwrap();

        let after_account_status = subject.account_status(&wallet).unwrap();
        let mut after_expected_status = before_expected_status;
        after_expected_status.pending_payment_transaction = Some(tx_hash);
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
        let wallet = make_wallet("blah");
        let hash = H256::from_uint(&U256::from(12345));

        let result = subject.transaction_canceled(&wallet, hash);

        assert_eq!(
            result,
            Err(PaymentError::PostTransaction(
                PaymentErrorKind::SignConversion(u64::MAX),
                hash
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
        let wallet = make_wallet("blah");
        let hash = H256::from_uint(&U256::from(12345));

        let result = subject.transaction_canceled(&wallet, hash);

        assert_eq!(
            result,
            Err(PaymentError::PostTransaction(
                PaymentErrorKind::RusqliteError("attempt to write a readonly database".to_string()),
                hash
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
        let payment = Payment {
            to: make_wallet("boooga"),
            amount: 444555,
            timestamp: from_time_t(200_000_000),
            previous_timestamp: from_time_t(189_000_000),
            transaction: H256::from_uint(&U256::from(16)),
            rowid: 1,
        };
        let hash = H256::from_uint(&U256::from(12345));
        let subject = PayableDaoReal::new(Box::new(conn_wrapped));

        let result = subject.transaction_confirmed(&payment);

        assert_eq!(
            result,
            Err(PaymentError::PostTransaction(
                PaymentErrorKind::RusqliteError("attempt to write a readonly database".to_string()),
                hash
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
                    pending_payment_transaction: None,
                    rowid: 1
                },
                PayableAccount {
                    wallet: make_wallet("barfoo"),
                    balance: 22,
                    last_paid_timestamp: from_time_t(0),
                    pending_payment_transaction: None,
                    rowid: 2
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
                      pending_payment_transaction: Option<&str>| {
            let params: &[&dyn ToSql] =
                &[&wallet, &balance, &timestamp, &pending_payment_transaction];
            conn
                .prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?, ?, ?, ?)")
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
            Some("0x1111111122222222333333334444444455555555666666667777777788888888"),
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
                    pending_payment_transaction: Some(
                        H256::from_str(
                            "1111111122222222333333334444444455555555666666667777777788888888"
                        )
                        .unwrap()
                    ),
                    rowid: 1
                },
                PayableAccount {
                    wallet: Wallet::new("0x3333333333333333333333333333333333333333"),
                    balance: 1_000_000_000,
                    last_paid_timestamp: dao_utils::from_time_t(timestamp3),
                    pending_payment_transaction: None,
                    rowid: 2
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
