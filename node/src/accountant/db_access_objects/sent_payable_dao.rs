use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use ethereum_types::H256;
use web3::types::Address;
use masq_lib::utils::ExpectValue;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxStatus;
use crate::database::rusqlite_wrappers::ConnectionWrapper;

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    EmptyInput,
    SqlExecutionFailed(String),
    InvalidInput(String),
    PartialExecution(String),
    NoChange(String),
}

type TxHash = H256;
type RowID = u64;

type TxIdentifiers = HashMap<TxHash, RowID>;
type TxUpdates = HashMap<TxHash, TxStatus>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount: u128,
    pub timestamp: i64,
    pub gas_price_wei: u64,
    pub nonce: u32,
    pub status: TxStatus,
}

pub enum RetrieveCondition {
    IsPending,
    ToRetry,
    ByHash(TxHash),
}

impl Display for RetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrieveCondition::IsPending => {
                write!(f, "WHERE status = 'Pending'")
            }
            RetrieveCondition::ToRetry => {
                write!(f, "WHERE status = 'Failed'")
            }
            RetrieveCondition::ByHash(tx_hash) => {
                write!(f, "WHERE tx_hash = '{:?}'", tx_hash)
            }
        }
    }
}

pub trait SentPayableDao {
    // Note that the order of the returned results is not guaranteed
    fn get_tx_identifiers(&self, hashes: &[TxHash]) -> TxIdentifiers;
    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> Vec<Tx>;
    fn change_statuses(&self, hash_map: &TxUpdates) -> Result<(), SentPayableDaoError>;
    fn delete_records(&self, hashes: HashSet<TxHash>) -> Result<(), SentPayableDaoError>;
}

#[derive(Debug)]
pub struct SentPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> SentPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        // TODO: GH-608: You'll need to write a mock to test this, do that wisely
        Self { conn }
    }

    // TODO: GH-608: There should be a function for executing SQL
    // TODO: GH-608: There should be a function for handling database errors
}

impl SentPayableDao for SentPayableDaoReal<'_> {
    fn get_tx_identifiers(&self, hashes: &[TxHash]) -> TxIdentifiers {
        let sql = format!(
            "SELECT tx_hash, rowid FROM sent_payable WHERE tx_hash IN ({})",
            comma_joined_stringifiable(hashes, |hash| format!("'{:?}'", hash))
        );

        let mut stmt = self
            .conn
            .prepare(&sql)
            .expect("Failed to prepare SQL statement");

        stmt.query_map([], |row| {
            let tx_hash_str: String = row.get(0).expectv("tx_hash");
            let tx_hash = H256::from_str(&tx_hash_str[2..]).expect("Failed to parse H256");
            let row_id: u64 = row.get(1).expectv("rowid");

            Ok((tx_hash, row_id))
        })
        .expect("Failed to execute query")
        .filter_map(Result::ok)
        .collect()
    }

    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError> {
        let sql = format!(
            "INSERT INTO sent_payable (\
            tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status
            ) VALUES {}",
            comma_joined_stringifiable(&txs, |tx| {
                let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                let (high_bytes, low_bytes) = BigIntDivider::deconstruct(amount_checked);
                format!(
                    "('{:?}', '{:?}', {}, {}, {}, {}, {}, '{}')",
                    tx.hash,
                    tx.receiver_address,
                    high_bytes,
                    low_bytes,
                    tx.timestamp,
                    tx.gas_price_wei,
                    tx.nonce,
                    tx.status
                )
            })
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(inserted_rows) => {
                if inserted_rows == txs.len() {
                    Ok(())
                } else {
                    Err(SentPayableDaoError::PartialExecution(format!(
                        "Only {} out of {} records inserted",
                        inserted_rows,
                        txs.len()
                    )))
                }
            }
            Err(e) => Err(SentPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }

    fn retrieve_txs(&self, condition_opt: Option<RetrieveCondition>) -> Vec<Tx> {
        let raw_sql = "SELECT tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status FROM sent_payable"
            .to_string();
        let sql = match condition_opt {
            None => raw_sql,
            Some(condition) => format!("{} {}", raw_sql, condition),
        };

        let mut stmt = self
            .conn
            .prepare(&sql)
            .expect("Failed to prepare SQL statement");

        stmt.query_map([], |row| {
            let tx_hash_str: String = row.get(0).expectv("tx_hash");
            let hash = H256::from_str(&tx_hash_str[2..]).expect("Failed to parse H256");
            let receiver_address_str: String = row.get(1).expectv("row_id");
            let receiver_address =
                Address::from_str(&receiver_address_str[2..]).expect("Failed to parse H160");
            let amount_high_b = row.get(2).expectv("amount_high_b");
            let amount_low_b = row.get(3).expectv("amount_low_b");
            let amount = BigIntDivider::reconstitute(amount_high_b, amount_low_b) as u128;
            let timestamp = row.get(4).expectv("timestamp");
            let gas_price_wei = row.get(5).expectv("gas_price_wei");
            let nonce = row.get(6).expectv("nonce");
            let status_str: String = row.get(7).expectv("status");
            let status = TxStatus::from_str(&status_str).expect("Failed to parse TxStatus");

            Ok(Tx {
                hash,
                receiver_address,
                amount,
                timestamp,
                gas_price_wei,
                nonce,
                status,
            })
        })
        .expect("Failed to execute query")
        .filter_map(Result::ok)
        .collect()
    }

    fn change_statuses(&self, hash_map: &TxUpdates) -> Result<(), SentPayableDaoError> {
        if hash_map.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        for (hash, status) in hash_map {
            let sql = format!(
                "UPDATE sent_payable SET status = '{}' WHERE tx_hash = '{:?}'",
                status, hash
            );

            match self.conn.prepare(&sql).expect("Internal error").execute([]) {
                Ok(updated_rows) => {
                    if updated_rows == 1 {
                        continue;
                    } else {
                        return Err(SentPayableDaoError::PartialExecution(format!(
                            "Failed to update status for hash {:?}",
                            hash
                        )));
                    }
                }
                Err(e) => {
                    return Err(SentPayableDaoError::SqlExecutionFailed(e.to_string()));
                }
            }
        }

        Ok(())
    }

    fn delete_records(&self, hashes: HashSet<TxHash>) -> Result<(), SentPayableDaoError> {
        if hashes.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let hash_strings: Vec<String> = hashes.iter().map(|h| format!("'{:?}'", h)).collect();
        let hash_list = hash_strings.join(", ");

        let sql = format!("DELETE FROM sent_payable WHERE tx_hash IN ({})", hash_list);

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(deleted_rows) => {
                if deleted_rows == hashes.len() {
                    Ok(())
                } else if deleted_rows == 0 {
                    Err(SentPayableDaoError::NoChange(
                        "No records were deleted for the specified hashes.".to_string(),
                    ))
                } else {
                    Err(SentPayableDaoError::PartialExecution(format!(
                        "Only {} of the {} hashes has been deleted.",
                        deleted_rows,
                        hashes.len(),
                    )))
                }
            }
            Err(e) => Err(SentPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use crate::accountant::db_access_objects::sent_payable_dao::{RetrieveCondition, SentPayableDao, SentPayableDaoError, SentPayableDaoReal};
    use crate::accountant::db_access_objects::utils::current_unix_timestamp;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::database::test_utils::ConnectionWrapperMock;
    use ethereum_types::{ H256, U64};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::{ByHash, IsPending, ToRetry};
    use crate::accountant::db_access_objects::test_utils::TxBuilder;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock, TxStatus};

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(1))
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(2))
            .status(TxStatus::Failed)
            .build();
        let tx3 = TxBuilder::default()
            .hash(H256::from_low_u64_le(3))
            .status(TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: Default::default(),
            }))
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let txs = vec![tx1, tx2, tx3];

        let result = subject.insert_new_records(txs.clone());

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs.len(), 3);
        assert_eq!(retrieved_txs, txs);
    }

    #[test]
    fn insert_new_records_throws_error_when_two_txs_with_same_hash_are_inserted() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_throws_error_when_two_txs_with_same_hash_are_inserted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = H256::from_low_u64_be(1234567890);
        let tx1 = TxBuilder::default()
            .hash(hash)
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(hash)
            .status(TxStatus::Failed)
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(vec![tx1, tx2]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "UNIQUE constraint failed: sent_payable.tx_hash".to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_throws_error_when_txs_with_an_already_present_hash_is_inserted() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_throws_error_when_txs_with_an_already_present_hash_is_inserted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = H256::from_low_u64_be(1234567890);
        let tx1 = TxBuilder::default()
            .hash(hash)
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(hash)
            .status(TxStatus::Failed)
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let initial_insertion_result = subject.insert_new_records(vec![tx1]);

        let result = subject.insert_new_records(vec![tx2]);

        assert_eq!(initial_insertion_result, Ok(()));
        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "UNIQUE constraint failed: sent_payable.tx_hash".to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_returns_err_if_partially_executed() {
        let setup_conn = Connection::open_in_memory().unwrap();
        // Inject a deliberately failing statement into the mocked connection.
        let failing_stmt = {
            setup_conn
                .execute("CREATE TABLE example (id integer)", [])
                .unwrap();
            setup_conn.prepare("SELECT id FROM example").unwrap()
        };
        let wrapped_conn = ConnectionWrapperMock::default().prepare_result(Ok(failing_stmt));
        let tx = TxBuilder::default().build();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(vec![tx]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(
                "Only 0 out of 1 records inserted".to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_can_throw_error() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_can_throw_error",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let read_only_conn = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(read_only_conn);
        let tx = TxBuilder::default().build();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(vec![tx]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn get_tx_identifiers_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "get_tx_identifiers_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let hash1 = H256::from_low_u64_le(1);
        let hash2 = H256::from_low_u64_le(2);
        let hash3 = H256::from_low_u64_le(3); // not present in the database
        let tx1 = TxBuilder::default().hash(hash1).build();
        let tx2 = TxBuilder::default().hash(hash2).build();
        subject.insert_new_records(vec![tx1, tx2]).unwrap();

        let result = subject.get_tx_identifiers(&vec![hash1, hash2, hash3]);

        assert_eq!(result.get(&hash1), Some(&1u64));
        assert_eq!(result.get(&hash2), Some(&2u64));
        assert_eq!(result.get(&hash3), None);
    }

    #[test]
    fn can_retrieve_pending_txs() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "can_retrieve_pending_txs");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(1))
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(2))
            .status(TxStatus::Pending)
            .build();
        let tx3 = TxBuilder::default()
            .hash(H256::from_low_u64_le(3))
            .status(TxStatus::Failed)
            .build();
        let tx4 = TxBuilder::default()
            .hash(H256::from_low_u64_le(4))
            .status(TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: Default::default(),
            }))
            .build();
        subject
            .insert_new_records(vec![tx1.clone(), tx2.clone(), tx3, tx4])
            .unwrap();

        let result = subject.retrieve_txs(Some(RetrieveCondition::IsPending));

        assert_eq!(result, vec![tx1, tx2]);
    }

    #[test]
    fn can_retrieve_txs_to_retry() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "can_retrieve_txs_to_retry");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let old_timestamp = current_unix_timestamp() - 60; // 1 minute old
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(3))
            .timestamp(old_timestamp)
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(4))
            .timestamp(old_timestamp)
            .status(TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: Default::default(),
            }))
            .build();
        let tx3 = TxBuilder::default() // this should be picked for retry
            .hash(H256::from_low_u64_le(5))
            .timestamp(old_timestamp)
            .status(TxStatus::Failed)
            .build();
        subject
            .insert_new_records(vec![tx1, tx2, tx3.clone()])
            .unwrap();

        let result = subject.retrieve_txs(Some(RetrieveCondition::ToRetry));

        assert_eq!(result, vec![tx3]);
    }

    #[test]
    fn retrieve_condition_display_works() {
        assert_eq!(IsPending.to_string(), "WHERE status = 'Pending'");
        assert_eq!(ToRetry.to_string(), "WHERE status = 'Failed'");
        assert_eq!(
            ByHash(H256::default()).to_string(),
            format!("WHERE tx_hash = '{:?}'", H256::default())
        );
    }

    #[test]
    fn tx_can_be_retrieved_by_hash() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "tx_can_be_retrieved_by_hash");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(1))
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(2))
            .status(TxStatus::Failed)
            .build();
        subject
            .insert_new_records(vec![tx1.clone(), tx2.clone()])
            .unwrap();

        let result = subject.retrieve_txs(Some(ByHash(tx1.hash)));

        assert_eq!(result, vec![tx1]);
    }

    #[test]
    fn change_statuses_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "change_statuses_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(1))
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(2))
            .status(TxStatus::Pending)
            .build();
        subject
            .insert_new_records(vec![tx1.clone(), tx2.clone()])
            .unwrap();
        let hash_map = HashMap::from([
            (tx1.hash, TxStatus::Failed),
            (
                tx2.hash,
                TxStatus::Succeeded(TransactionBlock {
                    block_hash: H256::from_low_u64_le(3),
                    block_number: U64::from(1),
                }),
            ),
        ]);

        let result = subject.change_statuses(&hash_map);

        let tx1_updated = subject.retrieve_txs(Some(ByHash(tx1.hash))).pop().unwrap();
        let tx2_updated = subject.retrieve_txs(Some(ByHash(tx2.hash))).pop().unwrap();
        assert_eq!(tx1_updated.status, TxStatus::Failed);
        assert_eq!(
            tx2_updated.status,
            TxStatus::Succeeded(TransactionBlock {
                block_hash: H256::from_low_u64_le(3),
                block_number: U64::from(1),
            })
        )
    }

    #[test]
    fn change_statuses_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "change_statuses_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = H256::from_low_u64_le(1);
        let tx = TxBuilder::default()
            .hash(existent_hash)
            .status(TxStatus::Pending)
            .build();
        subject.insert_new_records(vec![tx.clone()]).unwrap();
        let hash_map = HashMap::new();

        let result = subject.change_statuses(&hash_map);

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn change_statuses_returns_error_during_partial_execution() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "change_statuses_returns_error_during_partial_execution",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = H256::from_low_u64_le(1);
        let non_existent_hash = H256::from_low_u64_le(999);
        let tx = TxBuilder::default()
            .hash(existent_hash)
            .status(TxStatus::Pending)
            .build();
        subject.insert_new_records(vec![tx.clone()]).unwrap();
        let hash_map = HashMap::from([
            (existent_hash, TxStatus::Failed),
            (non_existent_hash, TxStatus::Failed),
        ]);

        let result = subject.change_statuses(&hash_map);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(format!(
                "Failed to update status for hash {:?}",
                non_existent_hash
            )))
        );
    }

    #[test]
    fn change_statuses_returns_error_when_an_error_occurs_while_executing_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "change_statuses_returns_error_when_an_error_occurs_while_executing_sql",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let read_only_conn = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(read_only_conn);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let hash = H256::from_low_u64_le(1);
        let hash_map = HashMap::from([(hash, TxStatus::Failed)]);

        let result = subject.change_statuses(&hash_map);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn txs_can_be_deleted() {
        let home_dir = ensure_node_home_directory_exists("sent_payable_dao", "txs_can_be_deleted");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default()
            .hash(H256::from_low_u64_le(1))
            .status(TxStatus::Pending)
            .build();
        let tx2 = TxBuilder::default()
            .hash(H256::from_low_u64_le(2))
            .status(TxStatus::Failed)
            .build();
        let tx3 = TxBuilder::default()
            .hash(H256::from_low_u64_le(3))
            .status(TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: Default::default(),
            }))
            .build();
        subject
            .insert_new_records(vec![tx1.clone(), tx2.clone(), tx3.clone()])
            .unwrap();
        let hashset = HashSet::from([tx1.hash, tx2.hash]);

        let result = subject.delete_records(hashset);

        let remaining_records = subject.retrieve_txs(None);
        assert_eq!(remaining_records, vec![tx3]);
    }

    #[test]
    fn delete_records_returns_error_when_input_records_are_invalid() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "delete_records_returns_error_when_input_records_are_invalid",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.delete_records(HashSet::new());

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn delete_records_returns_error_when_no_records_are_deleted() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "delete_records_returns_error_when_no_records_are_deleted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let non_existent_hash = H256::from_low_u64_le(999);
        let hashset = HashSet::from([non_existent_hash]);

        let result = subject.delete_records(hashset);

        assert_eq!(
            result,
            Err(SentPayableDaoError::NoChange(
                "No records were deleted for the specified hashes.".to_string()
            ))
        );
    }

    #[test]
    fn delete_records_returns_error_when_not_all_input_records_were_deleted() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "delete_records_returns_error_when_not_all_input_records_were_deleted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let present_hash = H256::from_low_u64_le(1);
        let absent_hash = H256::from_low_u64_le(2);
        let tx = TxBuilder::default()
            .hash(present_hash)
            .status(TxStatus::Failed)
            .build();
        subject.insert_new_records(vec![tx]);
        let hashset = HashSet::from([present_hash, absent_hash]);

        let result = subject.delete_records(hashset);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(format!(
                "Only 1 of the 2 hashes has been deleted."
            )))
        );
    }

    #[test]
    fn delete_records_returns_deletion_failed_error_when_an_error_occurs_in_sql() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "delete_records_can_throw_error");
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let read_only_conn = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(read_only_conn);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let hashes = HashSet::from([H256::from_low_u64_le(1)]);

        let result = subject.delete_records(hashes);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }
}
