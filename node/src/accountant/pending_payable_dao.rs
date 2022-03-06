// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::unsigned_to_signed;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::{from_time_t, to_time_t, DaoFactoryReal};
use masq_lib::utils::ExpectValue;
use rusqlite::types::Value::Null;
use rusqlite::{Row, ToSql};
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq)]
pub enum PendingPayableDaoError {
    InsertionFailed(String),
    UpdateFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    RecordDeletion(String),
    ErrorMarkFailed(String),
}

pub trait PendingPayableDao {
    fn fingerprint_rowid(&self, transaction_hash: H256) -> Option<u64>;
    fn return_all_fingerprints(&self) -> Vec<PendingPayableFingerprint>;
    fn insert_new_fingerprint(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError>;
    fn delete_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError>;
    fn update_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError>;
    fn mark_failure(&self, id: u64) -> Result<(), PendingPayableDaoError>;
}

impl PendingPayableDao for PendingPayableDaoReal<'_> {
    fn fingerprint_rowid(&self, transaction_hash: H256) -> Option<u64> {
        let mut stm = self
            .conn
            .prepare("select rowid from pending_payable where transaction_hash = ?")
            .expect("Internal error");
        match stm.query_row(&[&format!("{:?}", transaction_hash)], |row| {
            let rowid: i64 = row.get(0).expectv("rowid_opt");
            Ok(rowid)
        }) {
            Err(e) if e == rusqlite::Error::QueryReturnedNoRows => None,
            Err(e) => panic!("Internal error: {}", e),
            Ok(signed) => Some(u64::try_from(signed).expect("SQlite counts up to i64:MAX")),
        }
    }

    fn return_all_fingerprints(&self) -> Vec<PendingPayableFingerprint> {
        let mut stm = self.conn.prepare("select rowid, transaction_hash, amount, payable_timestamp, attempt from pending_payable where process_error is null").expect("Internal error");
        stm.query_map([], |row| {
            let rowid: u64 = Self::get_with_expect(row, 0);
            let transaction_hash: String = Self::get_with_expect(row, 1);
            let amount: u64 = Self::get_with_expect(row, 2);
            let timestamp: i64 = Self::get_with_expect(row, 3);
            let attempt: u16 = Self::get_with_expect(row, 4);
            Ok(PendingPayableFingerprint {
                rowid_opt: Some(rowid),
                timestamp: from_time_t(timestamp),
                hash: H256::from_str(&transaction_hash[2..]).expectv("string hash"),
                attempt_opt: Some(attempt),
                amount,
                process_error: None,
            })
        })
        .expect("rusqlite failure")
        .map(|fingerprint_result| match fingerprint_result {
            Ok(val) => val,
            Err(e) => panic!("hitting an error: {:?}", e),
        })
        .collect()
    }

    fn insert_new_fingerprint(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        let signed_amount =
            unsigned_to_signed(amount).map_err(PendingPayableDaoError::SignConversionError)?;
        let mut stm = self.conn.prepare("insert into pending_payable (transaction_hash, amount, payable_timestamp, attempt, process_error) values (?,?,?,?,?)").expect("Internal error");
        let params: &[&dyn ToSql] = &[
            &format!("{:?}", transaction_hash),
            &signed_amount,
            &to_time_t(timestamp),
            &1,
            &Null,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(x) => panic!("expected a single row inserted but: {}", x),
            Err(e) => Err(PendingPayableDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        let signed_id =
            unsigned_to_signed(id).expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("delete from pending_payable where rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(num) => panic!(
                "payment fingerprint: delete: one row should've been deleted but the result is {}",
                num
            ),
            Err(e) => Err(PendingPayableDaoError::RecordDeletion(e.to_string())),
        }
    }

    fn update_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        let signed_id =
            unsigned_to_signed(id).expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("update pending_payable set attempt = attempt + 1 where rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(num) => panic!(
                "payment fingerprint: update: one row should've been updated but the result is {}",
                num
            ),
            Err(e) => Err(PendingPayableDaoError::UpdateFailed(e.to_string())),
        }
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        let signed_id =
            unsigned_to_signed(id).expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("update pending_payable set process_error = 'ERROR' where rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(num) => panic!(
                "payment fingerprint: mark failure: one row should've been updated but the result is {}",
                num
            ),
            Err(e) => Err(PendingPayableDaoError::ErrorMarkFailed(e.to_string())),
        }
    }
}

pub trait PendingPayableDaoFactory {
    fn make(&self) -> Box<dyn PendingPayableDao>;
}

impl PendingPayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PendingPayableDao> {
        Box::new(PendingPayableDaoReal::new(self.make_connection()))
    }
}

#[derive(Debug)]
pub struct PendingPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> PendingPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        Self { conn }
    }
    fn get_with_expect<T: rusqlite::types::FromSql>(row: &Row, index: usize) -> T {
        row.get(index).expect("database is corrupt")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::pending_payable_dao::{
        PendingPayableDao, PendingPayableDaoError, PendingPayableDaoReal,
    };
    use crate::accountant::unsigned_to_signed;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::db_migrations::MigratorConfig;
    use ethereum_types::BigEndianHash;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, Error, OpenFlags, Row};
    use std::str::FromStr;
    use std::time::SystemTime;
    use web3::types::{H256, U256};

    #[test]
    fn insert_fingerprint_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "insert_fingerprint_happy_path",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(45466));
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(wrapped_conn);

        let _ = subject
            .insert_new_fingerprint(hash, amount, timestamp)
            .unwrap();

        let records = subject.return_all_fingerprints();
        assert_eq!(
            records,
            vec![PendingPayableFingerprint {
                rowid_opt: Some(1),
                timestamp,
                hash,
                attempt_opt: Some(1),
                amount,
                process_error: None
            }]
        )
    }

    #[test]
    fn insert_fingerprint_sad_path() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "insert_fingerprint_sad_path");
        {
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let hash = H256::from_uint(&U256::from(45466));
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_fingerprint(hash, amount, timestamp);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::InsertionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn fingerprint_rowid_when_record_reachable() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprint_rowid_when_record_reachable",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(195_000_000);
        let hash = H256::from_uint(&U256::from(11119));
        let amount = 787;
        {
            subject
                .insert_new_fingerprint(hash, amount, timestamp)
                .unwrap();
        }

        let result = subject.fingerprint_rowid(hash);

        assert_eq!(result, Some(1))
    }

    #[test]
    fn fingerprint_rowid_when_nonexistent_record() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprint_rowid_when_nonexistent_record",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            let mut stm = wrapped_conn
                .prepare("select * from pending_payable")
                .unwrap();
            let res = stm.query_row([], |_row| Ok(()));
            let err = res.unwrap_err();
            assert_eq!(err, Error::QueryReturnedNoRows);
        }
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let hash = H256::from_uint(&U256::from(11119));

        let result = subject.fingerprint_rowid(hash);

        assert_eq!(result, None)
    }

    #[test]
    fn return_all_fingerprints_works_when_no_records_with_errors_marks() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_fingerprints_works_when_no_records_with_errors_marks",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp_1 = from_time_t(195_000_000);
        let hash_1 = H256::from_uint(&U256::from(11119));
        let amount_1 = 787;
        let timestamp_2 = from_time_t(198_000_000);
        let hash_2 = H256::from_uint(&U256::from(10000));
        let amount_2 = 333;
        {
            subject
                .insert_new_fingerprint(hash_1, amount_1, timestamp_1)
                .unwrap();
        }
        {
            subject
                .insert_new_fingerprint(hash_2, amount_2, timestamp_2)
                .unwrap();
        }

        let result = subject.return_all_fingerprints();

        assert_eq!(
            result,
            vec![
                PendingPayableFingerprint {
                    rowid_opt: Some(1),
                    timestamp: timestamp_1,
                    hash: hash_1,
                    attempt_opt: Some(1),
                    amount: amount_1,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid_opt: Some(2),
                    timestamp: timestamp_2,
                    hash: hash_2,
                    attempt_opt: Some(1),
                    amount: amount_2,
                    process_error: None
                }
            ]
        )
    }

    #[test]
    fn return_all_fingerprints_works_when_some_records_with_errors_marks() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_fingerprints_works_when_some_records_with_errors_marks",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(198_000_000);
        let hash = H256::from_uint(&U256::from(10000));
        let amount = 333;
        {
            subject
                .insert_new_fingerprint(
                    H256::from_uint(&U256::from(11119)),
                    2000,
                    SystemTime::now(),
                )
                .unwrap();
            //we know that the previous record has a rowid=1, so we don't need to ask
            subject.mark_failure(1).unwrap();
            subject
                .insert_new_fingerprint(hash, amount, timestamp)
                .unwrap();
        }

        let result = subject.return_all_fingerprints();

        assert_eq!(
            result,
            vec![PendingPayableFingerprint {
                rowid_opt: Some(2),
                timestamp,
                hash,
                attempt_opt: Some(1),
                amount,
                process_error: None
            }]
        )
    }

    #[test]
    fn delete_fingerprint_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprint_happy_path",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(666666));
        let rowid = 1;
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprint(hash, 5555, SystemTime::now())
                .unwrap();
            assert!(subject.fingerprint_rowid(hash).is_some())
        }

        let result = subject.delete_fingerprint(rowid);

        assert_eq!(result, Ok(()));
        let conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let signed_row_id = unsigned_to_signed(rowid).unwrap();
        let mut stm2 = conn
            .prepare("select * from pending_payable where rowid = ?")
            .unwrap();
        let query_result_err = stm2
            .query_row(&[&signed_row_id], |_row: &Row| Ok(()))
            .unwrap_err();
        assert_eq!(query_result_err, Error::QueryReturnedNoRows);
    }

    #[test]
    fn delete_fingerprint_sad_path() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "delete_fingerprint_sad_path");
        {
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let rowid = 45;
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.delete_fingerprint(rowid);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::RecordDeletion(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn update_fingerprint_after_scan_cycle_works() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "update_fingerprint_after_scan_cycle_works",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(666));
        let amount = 1234;
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprint(hash, amount, timestamp)
                .unwrap();
        }
        let mut all_records_before = subject.return_all_fingerprints();
        assert_eq!(all_records_before.len(), 1);
        let mut record_before = all_records_before.remove(0);
        assert_eq!(record_before.hash, hash);
        assert_eq!(record_before.rowid_opt.unwrap(), 1);
        assert_eq!(record_before.attempt_opt.unwrap(), 1);
        assert_eq!(record_before.process_error, None);
        assert_eq!(record_before.timestamp, timestamp);

        let result = subject.update_fingerprint(1);

        assert_eq!(result, Ok(()));
        let mut all_records_after = subject.return_all_fingerprints();
        assert_eq!(all_records_after.len(), 1);
        let backup_after = all_records_after.remove(0);
        record_before.attempt_opt = Some(2);
        assert_eq!(record_before, backup_after)
    }

    #[test]
    fn update_fingerprint_after_scan_cycle_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "update_fingerprint_after_scan_cycle_sad_path",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.update_fingerprint(1);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::UpdateFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn mark_failure_works() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "mark_failure_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = H256::from_uint(&U256::from(666));
        let amount = 1234;
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprint(hash, amount, timestamp)
                .unwrap();
        }
        let assert_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let mut assert_stm = assert_conn
            .prepare("select * from pending_payable")
            .unwrap();
        let mut assert_closure = || {
            assert_stm
                .query_row([], |row| {
                    let rowid: u64 = row.get(0).unwrap();
                    let transaction_hash: String = row.get(1).unwrap();
                    let amount: u64 = row.get(2).unwrap();
                    let timestamp: i64 = row.get(3).unwrap();
                    let attempt: u16 = row.get(4).unwrap();
                    let process_error: Option<String> = row.get(5).unwrap();
                    Ok(PendingPayableFingerprint {
                        rowid_opt: Some(rowid),
                        timestamp: from_time_t(timestamp),
                        hash: H256::from_str(&transaction_hash[2..]).unwrap(),
                        attempt_opt: Some(attempt),
                        amount,
                        process_error,
                    })
                })
                .unwrap()
        };
        let assertion_before = assert_closure();
        assert_eq!(assertion_before.hash, hash);
        assert_eq!(assertion_before.rowid_opt.unwrap(), 1);
        assert_eq!(assertion_before.attempt_opt.unwrap(), 1);
        assert_eq!(assertion_before.process_error, None);
        assert_eq!(assertion_before.timestamp, timestamp);

        let result = subject.mark_failure(1);

        assert_eq!(result, Ok(()));
        let assertion_after = assert_closure();
        assert_eq!(assertion_after.hash, hash);
        assert_eq!(assertion_after.rowid_opt.unwrap(), 1);
        assert_eq!(assertion_after.attempt_opt.unwrap(), 1);
        assert_eq!(assertion_after.process_error, Some("ERROR".to_string()));
        assert_eq!(assertion_after.timestamp, timestamp);
    }

    #[test]
    fn mark_failure_sad_path() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "mark_failure_sad_path");
        {
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap();
        }
        let conn_read_only = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(conn_read_only);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.mark_failure(1);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::ErrorMarkFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }
}
