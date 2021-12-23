// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::jackass_unsigned_to_signed;
use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::{from_time_t, to_time_t, DaoFactoryReal};
use masq_lib::utils::ExpectValue;
use rusqlite::types::Value::Null;
use rusqlite::{Row, ToSql, NO_PARAMS};
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq)]
pub enum PendingPaymentDaoError {
    InsertionFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    RecordDeletion(String),
}

pub trait PendingPaymentsDao {
    fn payment_backup_exists(&self, transaction_hash: H256) -> Option<u64>;
    fn return_all_payment_backups(&self) -> Vec<PaymentBackupRecord>;
    fn insert_payment_backup(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPaymentDaoError>;
    fn delete_payment_backup(&self, id: u64) -> Result<(), PendingPaymentDaoError>;
    fn update_record_after_cycle(&self, id: u64) -> Result<(), PendingPaymentDaoError>; //TODO implement or discard
    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError>; //TODO implement or discard
}

impl PendingPaymentsDao for PendingPaymentsDaoReal<'_> {
    fn payment_backup_exists(&self, transaction_hash: H256) -> Option<u64> {
        let mut stm = self
            .conn
            .prepare("select rowid from pending_payments where transaction_hash = ?")
            .expect("Internal error");
        stm.exists(&[&format!("{:x}", transaction_hash)])
            .expectv("bool");
        unimplemented!()
    }

    fn return_all_payment_backups(&self) -> Vec<PaymentBackupRecord> {
        let mut stm = self.conn.prepare("select rowid, transaction_hash, amount, payment_timestamp, attempt, process_error from pending_payments").expect("Internal error");
        stm.query_map(NO_PARAMS, |row| {
            let rowid: i64 = Self::get_with_expect(row, 0);
            let transaction_hash: String = Self::get_with_expect(row, 1);
            let amount: i64 = Self::get_with_expect(row, 2);
            let timestamp: i64 = Self::get_with_expect(row, 3);
            let attempt: i64 = Self::get_with_expect(row, 4);
            let process_error: Option<String> = Self::get_with_expect(row, 5);
            Ok(PaymentBackupRecord {
                rowid: u64::try_from(rowid).expectv("positive value"),
                timestamp: from_time_t(timestamp),
                hash: H256::from_str(transaction_hash.as_str()).expectv("string hash"),
                attempt: u16::try_from(attempt).expectv("positive and low value"),
                amount: u64::try_from(amount).expectv("positive value"),
                process_error,
            })
        })
        .expect("behaves quite infallible")
        .flatten()
        .collect()
    }

    fn insert_payment_backup(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPaymentDaoError> {
        let signed_amount = jackass_unsigned_to_signed(amount)
            .map_err(|e| PendingPaymentDaoError::SignConversionError(e))?;
        let mut stm = self.conn.prepare("insert into pending_payments (rowid, transaction_hash, amount, payment_timestamp, attempt, process_error) values (?,?,?,?,?,?)").expect("Internal error");
        let params: &[&dyn ToSql] = &[
            &Null, //to let it increment automatically by SQLite
            &format!("{:x}", transaction_hash),
            &signed_amount,
            &to_time_t(timestamp),
            &1,
            &Null,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(x) => panic!("expected a single row inserted but: {}", x),
            Err(e) => Err(PendingPaymentDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_payment_backup(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        let signed_id = jackass_unsigned_to_signed(id)
            .expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("delete from pending_payments where rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(x) => panic!("one row should've been deleted but the result is {}", x),
            Err(e) => Err(PendingPaymentDaoError::RecordDeletion(e.to_string())),
        }
    }

    fn update_record_after_cycle(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }
}

pub trait PendingPaymentsDaoFactory {
    fn make(&self) -> Box<dyn PendingPaymentsDao>;
}

impl PendingPaymentsDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PendingPaymentsDao> {
        Box::new(PendingPaymentsDaoReal::new(self.make_connection()))
    }
}

#[derive(Debug)]
pub struct PendingPaymentsDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> PendingPaymentsDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        Self { conn }
    }
    fn get_with_expect<T: rusqlite::types::FromSql>(row: &Row, index: usize) -> T {
        row.get(index).expect("database is corrupt")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::pending_payments_dao::{
        PendingPaymentDaoError, PendingPaymentsDao, PendingPaymentsDaoReal,
    };
    use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::db_migrations::MigratorConfig;
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, Error, OpenFlags, NO_PARAMS};
    use std::str::FromStr;
    use web3::types::{H256, U256};

    #[test]
    fn insert_payment_backup_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "insert_payment_backup_happy_path",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(45466));
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPaymentsDaoReal::new(wrapped_conn);

        let _ = subject
            .insert_payment_backup(hash, amount, timestamp)
            .unwrap();

        let assertion_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let mut stm = assertion_conn
            .prepare("select * from pending_payments")
            .unwrap();
        let record = stm
            .query_row(NO_PARAMS, |row| {
                let rowid: i64 = row.get(0).unwrap();
                let hash: String = row.get(1).unwrap();
                let amount: i64 = row.get(2).unwrap();
                let payment_timestamp = row.get(3);
                let attempt: i64 = row.get(4).unwrap();
                let process_error = row.get(5);
                Ok(PaymentBackupRecord {
                    rowid: rowid as u64,
                    timestamp: from_time_t(payment_timestamp.unwrap()),
                    hash: H256::from_str(&hash).unwrap(),
                    attempt: attempt as u16,
                    amount: amount as u64,
                    process_error: process_error.unwrap(),
                })
            })
            .unwrap();
        assert_eq!(
            record,
            PaymentBackupRecord {
                rowid: 1,
                timestamp,
                hash,
                attempt: 1,
                amount,
                process_error: None
            }
        )
    }

    #[test]
    fn insert_payment_sad_path() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payments_dao", "insert_payment_sad_path");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let hash = H256::from_uint(&U256::from(45466));
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPaymentsDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_payment_backup(hash, amount, timestamp);

        assert_eq!(
            result,
            Err(PendingPaymentDaoError::InsertionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn backup_record_exists_when_reachable() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "backup_record_exists_when_reachable",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPaymentsDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(195_000_000);
        let hash = H256::from_uint(&U256::from(11119));
        let amount = 787;
        {
            subject
                .insert_payment_backup(hash, amount, timestamp)
                .unwrap();
        }

        let result = subject.payment_backup_exists(hash);

        assert_eq!(result, Some(1))
    }

    #[test]
    fn backup_record_exists_when_nonexistent() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "backup_record_exists_when_nonexistent",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stm = wrapped_conn
                .prepare("select * from pending_payments")
                .unwrap();
            let res = stm.query_row(NO_PARAMS, |_row| Ok(()));
            let err = res.unwrap_err();
            assert_eq!(err, Error::QueryReturnedNoRows);
        }
        let subject = PendingPaymentsDaoReal::new(wrapped_conn);
        let hash = H256::from_uint(&U256::from(11119));

        let result = subject.payment_backup_exists(hash);

        assert_eq!(result, None)
    }

    #[test]
    fn return_all_payment_backups_works() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "return_all_payment_backups_works",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPaymentsDaoReal::new(wrapped_conn);
        let timestamp_1 = from_time_t(195_000_000);
        let hash_1 = H256::from_uint(&U256::from(11119));
        let amount_1 = 787;
        let timestamp_2 = from_time_t(198_000_000);
        let hash_2 = H256::from_uint(&U256::from(10000));
        let amount_2 = 333;
        {
            subject
                .insert_payment_backup(hash_1, amount_1, timestamp_1)
                .unwrap();
        }
        {
            subject
                .insert_payment_backup(hash_2, amount_2, timestamp_2)
                .unwrap();
        }

        let result = subject.return_all_payment_backups();

        assert_eq!(
            result,
            vec![
                PaymentBackupRecord {
                    rowid: 1,
                    timestamp: timestamp_1,
                    hash: hash_1,
                    attempt: 1,
                    amount: amount_1,
                    process_error: None
                },
                PaymentBackupRecord {
                    rowid: 2,
                    timestamp: timestamp_2,
                    hash: hash_2,
                    attempt: 1,
                    amount: amount_2,
                    process_error: None
                }
            ]
        )
    }

    #[test]
    fn delete_payment_backup_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "delete_payment_backup_sad_path",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let rowid = 45;
        let subject = PendingPaymentsDaoReal::new(Box::new(wrapped_conn));

        let result = subject.delete_payment_backup(rowid);

        assert_eq!(
            result,
            Err(PendingPaymentDaoError::RecordDeletion(
                "attempt to write a readonly database".to_string()
            ))
        )
    }
}
