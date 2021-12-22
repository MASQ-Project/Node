// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::jackass_unsigned_to_signed;
use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::{from_time_t, to_time_t, DaoFactoryReal};
use masq_lib::utils::ExpectValue;
use rusqlite::types::Value::Null;
use rusqlite::{Row, ToSql};
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug)]
pub enum PendingPaymentDaoError {
    InsertionFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    RecordDeletion(String),
}

pub trait PendingPaymentsDao {
    fn payment_backup_exists(&self, transaction_hash: H256) -> bool;
    fn read_payment_backup(
        &self,
        transaction_hash: H256,
    ) -> Result<PaymentBackupRecord, PendingPaymentDaoError>;
    fn return_all_payment_backups(
        &self,
    ) -> Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError>;
    fn insert_payment_backup(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPaymentDaoError>;
    fn delete_payment_backup(&self, id: u64) -> Result<(), PendingPaymentDaoError>;
    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError>;
}

impl PendingPaymentsDao for PendingPaymentsDaoReal {
    fn payment_backup_exists(&self, transaction_hash: H256) -> bool {
        let mut stm = self
            .conn
            .prepare("select rowid from pending_payments where transaction_hash = ?")
            .expect("Internal error");
        stm.exists(&[&format!("{:x}", transaction_hash)])
            .expectv("bool")
    }

    fn read_payment_backup(
        &self,
        transaction_hash: H256,
    ) -> Result<PaymentBackupRecord, PendingPaymentDaoError> {
        let mut stm = self.conn.prepare("select rowid, amount, payment_timestamp, attempt, process_error from pending_payments where transaction_hash = ?").expect("Internal error");
        match stm.query_row(&[&format!("{:x}", transaction_hash)], |row| {
            let rowid: i64 = Self::get_with_expect(row, 0);
            let amount: i64 = Self::get_with_expect(row, 1);
            let timestamp: i64 = Self::get_with_expect(row, 2);
            let attempt: i64 = Self::get_with_expect(row, 3);
            let process_error: Option<String> = Self::get_with_expect(row, 4);
            Ok((rowid, amount, timestamp, attempt, process_error))
        }) {
            Ok((rowid, amount, timestamp, attempt, process_error)) => Ok(PaymentBackupRecord {
                rowid: u64::try_from(rowid).expectv("positive value"),
                timestamp: from_time_t(timestamp),
                hash: transaction_hash,
                attempt: u16::try_from(attempt).expectv("positive and low value"),
                amount: u64::try_from(amount).expectv("positive value"),
                process_error,
            }),
            Err(e) => unimplemented!("{}", e),
        }
    }

    fn return_all_payment_backups(
        &self,
    ) -> Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError> {
        todo!()
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
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn delete_payment_backup(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        let signed_id = jackass_unsigned_to_signed(id)
            .expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("delete from pending_payments where rowid = ?")
            .expect("Internal error");
        eprintln!("{}", signed_id);
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
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
pub struct PendingPaymentsDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl PendingPaymentsDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> Self {
        Self { conn }
    }
    fn get_with_expect<T: rusqlite::types::FromSql>(row: &Row, index: usize) -> T {
        row.get(index).expect("database is corrupt")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::pending_payments_dao::{PendingPaymentsDao, PendingPaymentsDaoReal};
    use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::db_migrations::MigratorConfig;
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, Error, NO_PARAMS};
    use std::str::FromStr;
    use web3::types::{H256, U256};

    #[test]
    fn insert_backup_record_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "insert_backup_record_happy_path",
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
        subject
            .insert_payment_backup(hash, amount, timestamp)
            .unwrap();

        let result = subject.payment_backup_exists(hash);

        assert_eq!(result, true)
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

        assert_eq!(result, false)
    }

    #[test]
    fn read_backup_record_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payments_dao",
            "read_backup_record_happy_path",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPaymentsDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(195_000_000);
        let hash = H256::from_uint(&U256::from(11119));
        let amount = 787;
        subject
            .insert_payment_backup(hash, amount, timestamp)
            .unwrap();

        let result = subject.read_payment_backup(hash).unwrap();

        assert_eq!(
            result,
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
}
