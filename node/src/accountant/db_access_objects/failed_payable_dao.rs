// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::utils::{
    current_unix_timestamp, TxHash, TxIdentifiers, VigilantRusqliteFlatten,
};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use masq_lib::utils::ExpectValue;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use web3::types::Address;

#[derive(Debug, PartialEq, Eq)]
pub enum FailedPayableDaoError {
    EmptyInput,
    NoChange,
    InvalidInput(String),
    PartialExecution(String),
    SqlExecutionFailed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureReason {
    PendingTooLong,
    NonceIssue,
}

impl FromStr for FailureReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PendingTooLong" => Ok(FailureReason::PendingTooLong),
            "NonceIssue" => Ok(FailureReason::NonceIssue),
            _ => Err(format!("Invalid FailureReason: {}", s)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedTx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount: u128,
    pub timestamp: i64,
    pub gas_price_wei: u128,
    pub nonce: u64,
    pub reason: FailureReason,
    pub checked: bool,
}

pub enum FailureRetrieveCondition {
    UncheckedPendingTooLong(u32), // u32 represents seconds ago
}

impl Display for FailureRetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureRetrieveCondition::UncheckedPendingTooLong(seconds_ago) => {
                let timestamp_threshold = current_unix_timestamp() - *seconds_ago as i64;
                write!(
                    f,
                    "WHERE reason = 'PendingTooLong' AND checked = 0 \
                     AND timestamp >= {} \
                     ORDER BY timestamp DESC",
                    timestamp_threshold
                )
            }
        }
    }
}

pub trait FailedPayableDao {
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers;
    fn insert_new_records(&self, txs: &[FailedTx]) -> Result<(), FailedPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<FailureRetrieveCondition>) -> Vec<FailedTx>;
    fn update_recheck_status(
        &self,
        hash_map: &HashSet<TxHash>,
    ) -> Result<(), FailedPayableDaoError>;
    fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), FailedPayableDaoError>;
}

#[derive(Debug)]
pub struct FailedPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> FailedPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        Self { conn }
    }
}

impl FailedPayableDao for FailedPayableDaoReal<'_> {
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers {
        let hashes_vec: Vec<TxHash> = hashes.iter().copied().collect();
        let sql = format!(
            "SELECT tx_hash, rowid FROM failed_payable WHERE tx_hash IN ({})",
            comma_joined_stringifiable(&hashes_vec, |hash| format!("'{:?}'", hash))
        );

        let mut stmt = self
            .conn
            .prepare(&sql)
            .unwrap_or_else(|_| panic!("Failed to prepare SQL statement"));

        stmt.query_map([], |row| {
            let tx_hash_str: String = row.get(0).expectv("tx_hash");
            let tx_hash = TxHash::from_str(&tx_hash_str[2..]).expect("Failed to parse TxHash");
            let row_id: u64 = row.get(1).expectv("row_id");

            Ok((tx_hash, row_id))
        })
        .unwrap_or_else(|_| panic!("Failed to execute query"))
        .vigilant_flatten()
        .collect()
    }

    fn insert_new_records(&self, txs: &[FailedTx]) -> Result<(), FailedPayableDaoError> {
        if txs.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let unique_hashes: HashSet<TxHash> = txs.iter().map(|tx| tx.hash).collect();
        if unique_hashes.len() != txs.len() {
            return Err(FailedPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input".to_string(),
            ));
        }

        let duplicates = self.get_tx_identifiers(&unique_hashes);
        if !duplicates.is_empty() {
            return Err(FailedPayableDaoError::InvalidInput(format!(
                "Duplicates detected in the database: {:?}",
                duplicates,
            )));
        }

        let sql = format!(
            "INSERT INTO failed_payable (\
             tx_hash, \
             receiver_address, \
             amount_high_b, \
             amount_low_b, \
             timestamp, \
             gas_price_wei_high_b, \
             gas_price_wei_low_b, \
             nonce, \
             reason, \
             checked
             ) VALUES {}",
            comma_joined_stringifiable(txs, |tx| {
                let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_wei);
                let (amount_high_b, amount_low_b) = BigIntDivider::deconstruct(amount_checked);
                let (gas_price_wei_high_b, gas_price_wei_low_b) =
                    BigIntDivider::deconstruct(gas_price_wei_checked);
                format!(
                    "('{:?}', '{:?}', {}, {}, {}, {}, {}, {}, '{:?}', {})",
                    tx.hash,
                    tx.receiver_address,
                    amount_high_b,
                    amount_low_b,
                    tx.timestamp,
                    gas_price_wei_high_b,
                    gas_price_wei_low_b,
                    tx.nonce,
                    tx.reason,
                    tx.checked
                )
            })
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(inserted_rows) => {
                if inserted_rows == txs.len() {
                    Ok(())
                } else {
                    Err(FailedPayableDaoError::PartialExecution(format!(
                        "Only {} out of {} records inserted",
                        inserted_rows,
                        txs.len()
                    )))
                }
            }
            Err(e) => Err(FailedPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }

    fn retrieve_txs(&self, condition: Option<FailureRetrieveCondition>) -> Vec<FailedTx> {
        let raw_sql = "SELECT tx_hash, \
                              receiver_address, \
                              amount_high_b, \
                              amount_low_b, \
                              timestamp, \
                              gas_price_wei_high_b, \
                              gas_price_wei_low_b, \
                              nonce, \
                              reason, \
                              checked \
                       FROM failed_payable"
            .to_string();
        let sql = match condition {
            None => raw_sql,
            Some(condition) => format!("{} {}", raw_sql, condition),
        };

        let mut stmt = self
            .conn
            .prepare(&sql)
            .expect("Failed to prepare SQL statement");

        stmt.query_map([], |row| {
            let tx_hash_str: String = row.get(0).expectv("tx_hash");
            let hash = TxHash::from_str(&tx_hash_str[2..]).expect("Failed to parse TxHash");
            let receiver_address_str: String = row.get(1).expectv("receiver_address");
            let receiver_address =
                Address::from_str(&receiver_address_str[2..]).expect("Failed to parse Address");
            let amount_high_b = row.get(2).expectv("amount_high_b");
            let amount_low_b = row.get(3).expectv("amount_low_b");
            let amount = BigIntDivider::reconstitute(amount_high_b, amount_low_b) as u128;
            let timestamp = row.get(4).expectv("timestamp");
            let gas_price_wei_high_b = row.get(5).expectv("gas_price_wei_high_b");
            let gas_price_wei_low_b = row.get(6).expectv("gas_price_wei_low_b");
            let gas_price_wei =
                BigIntDivider::reconstitute(gas_price_wei_high_b, gas_price_wei_low_b) as u128;
            let nonce = row.get(7).expectv("nonce");
            let reason_str: String = row.get(8).expectv("reason");
            let reason =
                FailureReason::from_str(&reason_str).expect("Failed to parse FailureReason");
            let checked_integer: u8 = row.get(9).expectv("checked");
            let checked = checked_integer == 1;

            Ok(FailedTx {
                hash,
                receiver_address,
                amount,
                timestamp,
                gas_price_wei,
                nonce,
                reason,
                checked,
            })
        })
        .expect("Failed to execute query")
        .vigilant_flatten()
        .collect()
    }

    fn update_recheck_status(
        &self,
        hash_set: &HashSet<TxHash>,
    ) -> Result<(), FailedPayableDaoError> {
        if hash_set.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let vec: Vec<TxHash> = hash_set.iter().cloned().collect();
        let sql = format!(
            "UPDATE failed_payable SET checked = 1 WHERE tx_hash IN ({})",
            comma_joined_stringifiable(&vec, |hash| format!("'{:?}'", hash))
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(updated_rows) => {
                if updated_rows == hash_set.len() {
                    Ok(())
                } else {
                    Err(FailedPayableDaoError::PartialExecution(format!(
                        "Only {} out of {} records updated",
                        updated_rows,
                        hash_set.len()
                    )))
                }
            }
            Err(e) => Err(FailedPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }

    fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), FailedPayableDaoError> {
        if hashes.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let hashes_vec: Vec<TxHash> = hashes.iter().cloned().collect();
        let sql = format!(
            "DELETE FROM failed_payable WHERE tx_hash IN ({})",
            comma_joined_stringifiable(&hashes_vec, |hash| { format!("'{:?}'", hash) })
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(deleted_rows) => {
                if deleted_rows == hashes.len() {
                    Ok(())
                } else if deleted_rows == 0 {
                    Err(FailedPayableDaoError::NoChange)
                } else {
                    Err(FailedPayableDaoError::PartialExecution(format!(
                        "Only {} of {} hashes has been deleted.",
                        deleted_rows,
                        hashes.len(),
                    )))
                }
            }
            Err(e) => Err(FailedPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::{
        NonceIssue, PendingTooLong,
    };
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDao, FailedPayableDaoError, FailedPayableDaoReal, FailureReason,
        FailureRetrieveCondition,
    };
    use crate::accountant::db_access_objects::test_utils::{
        make_read_only_db_connection, FailedTxBuilder,
    };
    use crate::accountant::db_access_objects::utils::current_unix_timestamp;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::test_utils::ConnectionWrapperMock;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(PendingTooLong)
            .checked(true)
            .build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let txs = vec![tx1, tx2];

        let result = subject.insert_new_records(&txs);

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs.len(), 2);
        assert_eq!(retrieved_txs, txs);
    }

    #[test]
    fn insert_new_records_throws_err_for_empty_input() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "insert_new_records_throws_err_for_empty_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let empty_input = vec![];

        let result = subject.insert_new_records(&empty_input);

        assert_eq!(result, Err(FailedPayableDaoError::EmptyInput));
    }

    #[test]
    fn insert_new_records_throws_error_when_two_txs_with_same_hash_are_present_in_the_input() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "insert_new_records_throws_error_when_two_txs_with_same_hash_are_present_in_the_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = make_tx_hash(123);
        let tx1 = FailedTxBuilder::default().hash(hash).build();
        let tx2 = FailedTxBuilder::default().hash(hash).checked(true).build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(&vec![tx1, tx2]);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input".to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_throws_error_when_input_tx_hash_is_already_present_in_the_db() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "insert_new_records_throws_error_when_input_tx_hash_is_already_present_in_the_db",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = make_tx_hash(123);
        let tx1 = FailedTxBuilder::default().hash(hash).build();
        let tx2 = FailedTxBuilder::default().hash(hash).checked(true).build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let initial_insertion_result = subject.insert_new_records(&vec![tx1]);

        let result = subject.insert_new_records(&vec![tx2]);

        assert_eq!(initial_insertion_result, Ok(()));
        assert_eq!(
            result,
            Err(FailedPayableDaoError::InvalidInput(
                "Duplicates detected in the database: \
                {0x000000000000000000000000000000000000000000000000000000000000007b: 1}"
                    .to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_returns_err_if_partially_executed() {
        let setup_conn = Connection::open_in_memory().unwrap();
        setup_conn
            .execute("CREATE TABLE example (id integer)", [])
            .unwrap();
        let get_tx_identifiers_stmt = setup_conn.prepare("SELECT id FROM example").unwrap();
        let faulty_insert_stmt = { setup_conn.prepare("SELECT id FROM example").unwrap() };
        let wrapped_conn = ConnectionWrapperMock::default()
            .prepare_result(Ok(get_tx_identifiers_stmt))
            .prepare_result(Ok(faulty_insert_stmt));
        let tx = FailedTxBuilder::default().build();
        let subject = FailedPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(&vec![tx]);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::PartialExecution(
                "Only 0 out of 1 records inserted".to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_can_throw_error() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "insert_new_records_can_throw_error",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let tx = FailedTxBuilder::default().build();
        let subject = FailedPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(&vec![tx]);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn get_tx_identifiers_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "get_tx_identifiers_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let present_hash = make_tx_hash(1);
        let absent_hash = make_tx_hash(2);
        let another_present_hash = make_tx_hash(3);
        let hashset = HashSet::from([present_hash, absent_hash, another_present_hash]);
        let present_tx = FailedTxBuilder::default().hash(present_hash).build();
        let another_present_tx = FailedTxBuilder::default()
            .hash(another_present_hash)
            .build();
        subject
            .insert_new_records(&vec![present_tx, another_present_tx])
            .unwrap();

        let result = subject.get_tx_identifiers(&hashset);

        assert_eq!(result.get(&present_hash), Some(&1u64));
        assert_eq!(result.get(&absent_hash), None);
        assert_eq!(result.get(&another_present_hash), Some(&2u64));
    }

    #[test]
    fn failure_reason_from_str_works() {
        assert_eq!(
            FailureReason::from_str("PendingTooLong"),
            Ok(PendingTooLong)
        );
        assert_eq!(FailureReason::from_str("NonceIssue"), Ok(NonceIssue));
        assert_eq!(
            FailureReason::from_str("InvalidReason"),
            Err("Invalid FailureReason: InvalidReason".to_string())
        );
    }

    #[test]
    fn retrieve_condition_display_works() {
        let expected_condition = format!(
            "WHERE reason = 'PendingTooLong' AND checked = 0 \
             AND timestamp >= {} ORDER BY timestamp DESC",
            current_unix_timestamp() - 30
        );
        assert_eq!(
            FailureRetrieveCondition::UncheckedPendingTooLong(30).to_string(),
            expected_condition
        );
    }

    #[test]
    fn can_retrieve_all_txs() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "can_retrieve_all_txs");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .nonce(1)
            .build();
        let tx3 = FailedTxBuilder::default().hash(make_tx_hash(3)).build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone()])
            .unwrap();
        subject.insert_new_records(&vec![tx3.clone()]).unwrap();

        let result = subject.retrieve_txs(None);

        assert_eq!(result, vec![tx1, tx2, tx3]);
    }

    #[test]
    fn can_retrieve_unchecked_pending_too_long_txs() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "can_retrieve_unchecked_pending_too_long_txs",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let now = current_unix_timestamp();
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .reason(FailureReason::PendingTooLong)
            .checked(false)
            .timestamp(now - 3600) // 1 hour ago
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(FailureReason::PendingTooLong)
            .checked(true) // This one is checked
            .timestamp(now - 7200) // 2 hours ago
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .reason(FailureReason::PendingTooLong)
            .checked(false)
            .timestamp(now - 1800) // 30 minutes ago
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .reason(FailureReason::NonceIssue)
            .checked(false)
            .timestamp(now - 3600) // 1 hour ago
            .build();
        let tx5 = FailedTxBuilder::default()
            .hash(make_tx_hash(5))
            .reason(FailureReason::PendingTooLong)
            .checked(false) // This one is checked
            .timestamp(now - 7200) // 2 hours ago
            .build();

        subject
            .insert_new_records(&vec![tx1.clone(), tx2, tx3.clone(), tx4, tx5])
            .unwrap();

        // Retrieve unchecked PendingTooLong transactions from the last hour
        let result = subject.retrieve_txs(Some(FailureRetrieveCondition::UncheckedPendingTooLong(
            3600,
        )));
        assert_eq!(result, vec![tx3, tx1]);
    }

    #[test]
    fn update_recheck_status_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "update_recheck_status_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .reason(NonceIssue)
            .checked(false)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(PendingTooLong)
            .checked(false)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .reason(PendingTooLong)
            .checked(true) // already checked
            .build();
        let tx1_pre_checked_state = tx1.checked;
        let tx2_pre_checked_state = tx2.checked;
        let tx3_pre_checked_state = tx3.checked;
        subject
            .insert_new_records(&vec![tx1, tx2.clone(), tx3.clone()])
            .unwrap();
        let hash_set = HashSet::from([tx2.hash, tx3.hash]);

        let result = subject.update_recheck_status(&hash_set);

        let updated_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(tx1_pre_checked_state, false);
        assert_eq!(tx2_pre_checked_state, false);
        assert_eq!(tx3_pre_checked_state, true);
        assert_eq!(updated_txs[0].checked, false);
        assert_eq!(updated_txs[1].checked, true);
        assert_eq!(updated_txs[2].checked, true);
    }

    #[test]
    fn update_recheck_status_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "update_recheck_status_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let tx = FailedTxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&vec![tx]).unwrap();
        let hash_map = HashSet::new();

        let result = subject.update_recheck_status(&hash_map);

        assert_eq!(result, Err(FailedPayableDaoError::EmptyInput));
    }

    #[test]
    fn update_recheck_status_returns_error_during_partial_execution() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "update_recheck_status_returns_error_during_partial_execution",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let non_existent_hash = make_tx_hash(999);
        let tx = FailedTxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&vec![tx]).unwrap();
        let hash_map = HashSet::from([existent_hash, non_existent_hash]);

        let result = subject.update_recheck_status(&hash_map);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::PartialExecution(
                "Only 1 out of 2 records updated".to_string()
            ))
        );
    }

    #[test]
    fn update_recheck_status_returns_error_when_an_error_occurs_while_executing_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "update_recheck_status_returns_error_when_an_error_occurs_while_executing_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = FailedPayableDaoReal::new(Box::new(wrapped_conn));
        let hash = make_tx_hash(1);
        let hash_set = HashSet::from([hash]);

        let result = subject.update_recheck_status(&hash_set);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn txs_can_be_deleted() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "txs_can_be_deleted");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = FailedTxBuilder::default().hash(make_tx_hash(2)).build();
        let tx3 = FailedTxBuilder::default().hash(make_tx_hash(3)).build();
        let tx4 = FailedTxBuilder::default().hash(make_tx_hash(4)).build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone(), tx3.clone(), tx4.clone()])
            .unwrap();
        let hashset = HashSet::from([tx1.hash, tx3.hash]);

        let result = subject.delete_records(&hashset);

        let remaining_records = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(remaining_records, vec![tx2, tx4]);
    }

    #[test]
    fn delete_records_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "delete_records_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);

        let result = subject.delete_records(&HashSet::new());

        assert_eq!(result, Err(FailedPayableDaoError::EmptyInput));
    }

    #[test]
    fn delete_records_returns_error_when_no_records_are_deleted() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "delete_records_returns_error_when_no_records_are_deleted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let non_existent_hash = make_tx_hash(999);
        let hashset = HashSet::from([non_existent_hash]);

        let result = subject.delete_records(&hashset);

        assert_eq!(result, Err(FailedPayableDaoError::NoChange));
    }

    #[test]
    fn delete_records_returns_error_when_not_all_input_records_were_deleted() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "delete_records_returns_error_when_not_all_input_records_were_deleted",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let present_hash = make_tx_hash(1);
        let absent_hash = make_tx_hash(2);
        let tx = FailedTxBuilder::default().hash(present_hash).build();
        subject.insert_new_records(&vec![tx]).unwrap();
        let hashset = HashSet::from([present_hash, absent_hash]);

        let result = subject.delete_records(&hashset);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::PartialExecution(
                "Only 1 of 2 hashes has been deleted.".to_string()
            ))
        );
    }

    #[test]
    fn delete_records_returns_a_general_error_from_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "delete_records_returns_a_general_error_from_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = FailedPayableDaoReal::new(Box::new(wrapped_conn));
        let hashes = HashSet::from([make_tx_hash(1)]);

        let result = subject.delete_records(&hashes);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }
}
