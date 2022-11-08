// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::{from_time_t, to_time_t, DaoFactoryReal};
use itertools::Itertools;
use masq_lib::utils::ExpectValue;
use rusqlite::Row;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::SystemTime;
use web3::types::H256;

#[derive(Debug, PartialEq, Eq)]
pub enum PendingPayableDaoError {
    InsertionFailed(String),
    UpdateFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    RecordDeletion(String),
    ErrorMarkFailed(String),
}

pub trait PendingPayableDao {
    fn fingerprints_rowids(&self, hashes: &[H256]) -> Vec<(Option<u64>, H256)>;
    fn return_all_fingerprints(&self) -> Vec<PendingPayableFingerprint>;
    fn insert_new_fingerprints(
        &self,
        hashes_and_amounts: &[(H256, u64)],
        batch_wide_timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError>;
    fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
    fn update_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
    fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError>;
}

impl PendingPayableDao for PendingPayableDaoReal<'_> {
    fn fingerprints_rowids(&self, hashes: &[H256]) -> Vec<(Option<u64>, H256)> {
        let sql = format!(
            "select transaction_hash, rowid from pending_payable where transaction_hash = {}",
            hashes.iter().map(|hash| format!("{:?}", hash)).join(" or ")
        );
        let mut all_found_records = self
            .conn
            .prepare(&sql)
            .expect("Internal error")
            .query_map([], |row| {
                let str_hash: String = row.get(0).expectv("hash");
                let hash = H256::from_str(&str_hash[2..]).expect("input hash ensures right result");
                let rowid: i64 = row.get(1).expectv("rowid");
                Ok((hash, rowid))
            })
            .expect("map query failed")
            .flatten()
            .collect::<HashMap<H256, i64>>();
        hashes
            .iter()
            .map(|hash| {
                (
                    all_found_records
                        .remove(hash)
                        .map(|rowid| u64::try_from(rowid).expect("SQlite counts up to i64:MAX")),
                    *hash,
                )
            })
            .collect()
    }

    fn return_all_fingerprints(&self) -> Vec<PendingPayableFingerprint> {
        let mut stm = self
            .conn
            .prepare(
                "select rowid, transaction_hash, amount, \
                 payable_timestamp, attempt from pending_payable where process_error is null",
            )
            .expect("Internal error");
        stm.query_map([], |row| {
            let rowid: u64 = Self::get_with_expect(row, 0);
            let transaction_hash: String = Self::get_with_expect(row, 1);
            let amount: u64 = Self::get_with_expect(row, 2);
            let timestamp: i64 = Self::get_with_expect(row, 3);
            let attempt: u16 = Self::get_with_expect(row, 4);
            Ok(PendingPayableFingerprint {
                rowid,
                timestamp: from_time_t(timestamp),
                hash: H256::from_str(&transaction_hash[2..]).unwrap_or_else(|e| {
                    panic!(
                        "Invalid hash format (\"{}\": {:?}) - database corrupt",
                        transaction_hash, e
                    )
                }),
                attempt,
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

    fn insert_new_fingerprints(
        &self,
        hashes_and_amounts: &[(H256, u64)],
        batch_wide_timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        let timestamp_as_time_t = to_time_t(batch_wide_timestamp);
        let insert_sql =
            format!("insert into pending_payable (transaction_hash, amount, payable_timestamp, attempt, process_error) values {}",
                    hashes_and_amounts
                        .iter()
                        .map(|(hash, amount)|
                                     format!("('{:?}', {}, {}, 1, null)", hash, amount, timestamp_as_time_t)
                         )
                        .join(", ")
        );
        match self
            .conn
            .prepare(&insert_sql)
            .expect("Internal error")
            .execute([])
        {
            Ok(x) if x == hashes_and_amounts.len() => Ok(()),
            //untested panic
            Ok(x) => panic!(
                "expected {} of changed rows but got {}",
                hashes_and_amounts.len(),
                x
            ),
            Err(e) => Err(PendingPayableDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "delete from pending_payable where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self
            .conn
            .prepare(&sql)
            .expect("delete command wrong")
            .execute([])
        {
            Ok(x) if x == ids.len() => Ok(()),
            Ok(num) => panic!(
                "deleting fingerprint, expected {} to be changed, but the actual number is {}",
                ids.len(),
                num
            ),
            Err(e) => Err(PendingPayableDaoError::RecordDeletion(e.to_string())),
        }
    }

    fn update_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "update pending_payable set attempt = attempt + 1 where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(num) if num == ids.len() => Ok(()),
            Ok(num) => panic!(
                "Database corrupt: updating fingerprints: expected to update {} rows but did {}",
                ids.len(),
                num
            ),
            Err(e) => Err(PendingPayableDaoError::UpdateFailed(e.to_string())),
        }
    }

    fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        let sql = format!(
            "update pending_payable set process_error = 'ERROR' where rowid in ({})",
            Self::serialize_ids(ids)
        );
        match self
            .conn
            .prepare(&sql)
            .expect("Internal error")
            .execute([]) {
            Ok(num) if num == ids.len() => Ok(()),
            Ok(num) =>
                panic!(
                    "Database corrupt: marking failure at fingerprints: expected to change {} rows but did {}",
                    ids.len(), num
                )
            ,
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

    fn serialize_ids(ids: &[u64]) -> String {
        ids.iter().map(|id| id.to_string()).join(", ")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::pending_payable_dao::{
        PendingPayableDao, PendingPayableDaoError, PendingPayableDaoReal,
    };
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::connection_wrapper::ConnectionWrapperReal;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal, DATABASE_FILE};
    use crate::database::db_migrations::MigratorConfig;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use std::str::FromStr;
    use std::time::SystemTime;
    use web3::types::H256;

    #[test]
    fn insert_new_fingerprints_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "insert_new_fingerprints_happy_path",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(4546);
        let amount_1 = 55556;
        let hash_2 = make_tx_hash(6789);
        let amount_2 = 44445;
        let batch_wide_timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(wrapped_conn);

        let _ = subject
            .insert_new_fingerprints(
                &[(hash_1, amount_1), (hash_2, amount_2)],
                batch_wide_timestamp,
            )
            .unwrap();

        let records = subject.return_all_fingerprints();
        assert_eq!(
            records,
            vec![
                PendingPayableFingerprint {
                    rowid: 1,
                    timestamp: batch_wide_timestamp,
                    hash: hash_1,
                    attempt: 1,
                    amount: amount_1,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid: 2,
                    timestamp: batch_wide_timestamp,
                    hash: hash_2,
                    attempt: 1,
                    amount: amount_2,
                    process_error: None
                }
            ]
        )
    }

    #[test]
    fn insert_new_fingerprints_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "insert_new_fingerprints_sad_path",
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
        let hash = make_tx_hash(45466);
        let amount = 55556;
        let timestamp = from_time_t(200_000_000);
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_fingerprints(&[(hash, amount)], timestamp);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::InsertionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn fingerprints_rowids_when_records_reachable() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprints_rowids_when_records_reachable",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let timestamp = from_time_t(195_000_000);
        let hash_1 = make_tx_hash(1111);
        let hash_2 = make_tx_hash(3333);
        let fingerprints_init_input = vec![(hash_1, 4567), (hash_2, 6789)];
        {
            subject
                .insert_new_fingerprints(&fingerprints_init_input, timestamp)
                .unwrap();
        }

        let result = subject.fingerprints_rowids(&[hash_1, hash_2]);

        assert_eq!(result, vec![(Some(1), hash_1), (Some(2), hash_2)])
    }

    #[test]
    fn fingerprints_rowids_when_nonexistent_record() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "fingerprints_rowids_when_nonexistent_record",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(wrapped_conn);
        let hash = make_tx_hash(11119);

        let result = subject.fingerprints_rowids(&[hash]);

        assert_eq!(result, vec![(None, hash)])
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
        let batch_wide_timestamp = from_time_t(195_000_000);
        let hash_1 = make_tx_hash(11119);
        let amount_1 = 787;
        let hash_2 = make_tx_hash(10000);
        let amount_2 = 333;
        {
            subject
                .insert_new_fingerprints(
                    &[(hash_1, amount_1), (hash_2, amount_2)],
                    batch_wide_timestamp,
                )
                .unwrap();
        }

        let result = subject.return_all_fingerprints();

        assert_eq!(
            result,
            vec![
                PendingPayableFingerprint {
                    rowid: 1,
                    timestamp: batch_wide_timestamp,
                    hash: hash_1,
                    attempt: 1,
                    amount: amount_1,
                    process_error: None
                },
                PendingPayableFingerprint {
                    rowid: 2,
                    timestamp: batch_wide_timestamp,
                    hash: hash_2,
                    attempt: 1,
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
        let hash = make_tx_hash(10000);
        let amount = 333;
        {
            subject
                .insert_new_fingerprints(&[(make_tx_hash(11119), 2000), (hash, amount)], timestamp)
                .unwrap();
            subject.mark_failures(&[1]).unwrap();
        }

        let result = subject.return_all_fingerprints();

        assert_eq!(
            result,
            vec![PendingPayableFingerprint {
                rowid: 2,
                timestamp,
                hash,
                attempt: 1,
                amount,
                process_error: None
            }]
        )
    }

    #[test]
    #[should_panic(
        expected = "Invalid hash format (\"silly_hash\": Invalid character 'l' at position 0) - database corrupt"
    )]
    fn return_all_fingerprints_panics_on_malformed_hash() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "return_all_fingerprints_panics_on_malformed_hash",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        {
            wrapped_conn
                .prepare("insert into pending_payable (rowid, transaction_hash, amount, payable_timestamp, attempt, process_error) values (1, 'silly_hash', 1234, 10000000000, 1, null)")
                .unwrap()
                .execute([])
                .unwrap();
        }
        let subject = PendingPayableDaoReal::new(wrapped_conn);

        let _ = subject.return_all_fingerprints();
    }

    #[test]
    fn delete_fingerprints_happy_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_happy_path",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(666666);
        let rowid_1 = 1;
        let hash_2 = make_tx_hash(444444);
        let rowid_2 = 2;
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(&[(hash_1, 5555), (hash_2, 2222)], SystemTime::now())
                .unwrap();
        }

        let result = subject.delete_fingerprints(&[rowid_1, rowid_2]);

        assert_eq!(result, Ok(()));
        let records_in_the_db = subject.return_all_fingerprints();
        assert!(records_in_the_db.is_empty())
    }

    #[test]
    fn delete_fingerprints_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_sad_path",
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
        let rowid = 45;
        let subject = PendingPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.delete_fingerprints(&[rowid]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::RecordDeletion(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "deleting fingerprint, expected 2 to be changed, but the actual number is 1"
    )]
    fn delete_fingerprints_changed_different_number_of_rows_than_expected() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "delete_fingerprints_changed_different_number_of_rows_than_expected",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let rowid_1 = 1;
        let rowid_2 = 2;
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(&[(make_tx_hash(666666), 5555)], SystemTime::now())
                .unwrap();
        }

        let _ = subject.delete_fingerprints(&[rowid_1, rowid_2]);
    }

    #[test]
    fn update_fingerprints_after_scan_cycle_works() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "update_fingerprints_after_scan_cycle_works",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash_1 = make_tx_hash(579);
        let amount_1 = 1234;
        let hash_2 = make_tx_hash(456);
        let amount_2 = 6789;
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(&[(hash_1, amount_1), (hash_2, amount_2)], timestamp)
                .unwrap();
        }

        let result = subject.update_fingerprints(&[1, 2]);

        assert_eq!(result, Ok(()));
        let mut all_records = subject.return_all_fingerprints();
        assert_eq!(all_records.len(), 2);
        let record_1 = all_records.remove(0);
        assert_eq!(record_1.hash, hash_1);
        assert_eq!(record_1.attempt, 2);
        let record_2 = all_records.remove(0);
        assert_eq!(record_2.hash, hash_2);
        assert_eq!(record_2.attempt, 2);
    }

    #[test]
    fn update_fingerprints_after_scan_cycle_sad_path() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "update_fingerprints_after_scan_cycle_sad_path",
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

        let result = subject.update_fingerprints(&[1]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::UpdateFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: updating fingerprints: expected to update 2 rows but did 0"
    )]
    fn update_fingerprints_panics_on_unexpected_row_change_count() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "update_fingerprints_panics_on_unexpected_row_change_count",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(conn);

        let _ = subject.update_fingerprints(&[1, 2]);
    }

    #[test]
    fn mark_failure_works() {
        let home_dir =
            ensure_node_home_directory_exists("pending_payable_dao", "mark_failure_works");
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let hash = make_tx_hash(666);
        let amount = 1234;
        let timestamp = from_time_t(190_000_000);
        let subject = PendingPayableDaoReal::new(conn);
        {
            subject
                .insert_new_fingerprints(&[(hash, amount)], timestamp)
                .unwrap();
        }

        let result = subject.mark_failures(&[1]);

        assert_eq!(result, Ok(()));
        let assert_conn = Connection::open(home_dir.join(DATABASE_FILE)).unwrap();
        let mut assert_stm = assert_conn
            .prepare("select rowid, transaction_hash, amount, payable_timestamp, attempt, process_error from pending_payable")
            .unwrap();
        let mut found_fingerprints = assert_stm
            .query_map([], |row| {
                let rowid: u64 = row.get(0).unwrap();
                let transaction_hash: String = row.get(1).unwrap();
                let amount: u64 = row.get(2).unwrap();
                let timestamp: i64 = row.get(3).unwrap();
                let attempt: u16 = row.get(4).unwrap();
                let process_error: Option<String> = row.get(5).unwrap();
                Ok(PendingPayableFingerprint {
                    rowid,
                    timestamp: from_time_t(timestamp),
                    hash: H256::from_str(&transaction_hash[2..]).unwrap(),
                    attempt,
                    amount,
                    process_error,
                })
            })
            .unwrap()
            .flatten()
            .collect::<Vec<PendingPayableFingerprint>>();
        assert_eq!(found_fingerprints.len(), 1);
        let actual_fingerprint = found_fingerprints.remove(0);
        assert_eq!(actual_fingerprint.hash, hash);
        assert_eq!(actual_fingerprint.rowid, 1);
        assert_eq!(actual_fingerprint.attempt, 1);
        assert_eq!(actual_fingerprint.process_error, Some("ERROR".to_string()));
        assert_eq!(actual_fingerprint.timestamp, timestamp);
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

        let result = subject.mark_failures(&[1]);

        assert_eq!(
            result,
            Err(PendingPayableDaoError::ErrorMarkFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: marking failure at fingerprints: expected to change 2 rows but did 0"
    )]
    fn mark_failure_row_change_count_panic() {
        let home_dir = ensure_node_home_directory_exists(
            "pending_payable_dao",
            "mark_failure_row_change_count_panic",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let subject = PendingPayableDaoReal::new(conn);

        let _ = subject.mark_failures(&[10, 20]);
    }
}
