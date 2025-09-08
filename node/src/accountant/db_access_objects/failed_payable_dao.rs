// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::utils::{
    DaoFactoryReal, TxHash, TxIdentifiers, TxRecordWithHash, VigilantRusqliteFlatten,
};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::blockchain::errors::rpc_errors::AppRpcErrorKind;
use crate::blockchain::errors::validation_status::ValidationStatus;
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use itertools::Itertools;
use masq_lib::utils::ExpectValue;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    Submission(AppRpcErrorKind),
    Reverted,
    Unrecognized,
    PendingTooLong,
}

impl Display for FailureReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            // Untestable
            Err(_) => write!(f, "<invalid FailureReason>"),
        }
    }
}

impl FromStr for FailureReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("{} in '{}'", e, s))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureStatus {
    RetryRequired,
    RecheckRequired(ValidationStatus),
    Concluded,
}

impl Display for FailureStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            // Untestable
            Err(e) => panic!(
                "cat: {:?}, line: {}, column: {}",
                e.classify(),
                e.line(),
                e.column()
            ), //write!(f, "<invalid FailureStatus>"),
        }
    }
}

impl FromStr for FailureStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("{} in '{}'", e, s))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedTx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount_minor: u128,
    pub timestamp: i64,
    pub gas_price_minor: u128,
    pub nonce: u64,
    pub reason: FailureReason,
    pub status: FailureStatus,
}

impl TxRecordWithHash for FailedTx {
    fn hash(&self) -> TxHash {
        self.hash
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FailureRetrieveCondition {
    ByTxHash(Vec<TxHash>),
    ByStatus(FailureStatus),
    EveryRecheckRequiredRecord,
}

impl Display for FailureRetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureRetrieveCondition::ByTxHash(hashes) => {
                write!(
                    f,
                    "WHERE tx_hash IN ({})",
                    comma_joined_stringifiable(hashes, |hash| format!("'{:?}'", hash))
                )
            }
            FailureRetrieveCondition::ByStatus(status) => {
                write!(f, "WHERE status = '{}'", status)
            }
            FailureRetrieveCondition::EveryRecheckRequiredRecord => {
                write!(f, "WHERE status LIKE 'RecheckRequired%'")
            }
        }
    }
}

pub trait FailedPayableDao {
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers;
    //TODO potentially atomically
    fn insert_new_records(&self, txs: &[FailedTx]) -> Result<(), FailedPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<FailureRetrieveCondition>) -> Vec<FailedTx>;
    fn update_statuses(
        &self,
        status_updates: &HashMap<TxHash, FailureStatus>,
    ) -> Result<(), FailedPayableDaoError>;
    //TODO potentially atomically
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
            return Err(FailedPayableDaoError::InvalidInput(format!(
                "Duplicate hashes found in the input. Input Transactions: {:?}",
                txs
            )));
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
             status
             ) VALUES {}",
            comma_joined_stringifiable(txs, |tx| {
                let amount_checked = checked_conversion::<u128, i128>(tx.amount_minor);
                let gas_price_minor_checked = checked_conversion::<u128, i128>(tx.gas_price_minor);
                let (amount_high_b, amount_low_b) = BigIntDivider::deconstruct(amount_checked);
                let (gas_price_wei_high_b, gas_price_wei_low_b) =
                    BigIntDivider::deconstruct(gas_price_minor_checked);
                format!(
                    "('{:?}', '{:?}', {}, {}, {}, {}, {}, {}, '{}', '{}')",
                    tx.hash,
                    tx.receiver_address,
                    amount_high_b,
                    amount_low_b,
                    tx.timestamp,
                    gas_price_wei_high_b,
                    gas_price_wei_low_b,
                    tx.nonce,
                    tx.reason,
                    tx.status
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
                              status \
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
            let amount_minor = BigIntDivider::reconstitute(amount_high_b, amount_low_b) as u128;
            let timestamp = row.get(4).expectv("timestamp");
            let gas_price_wei_high_b = row.get(5).expectv("gas_price_wei_high_b");
            let gas_price_wei_low_b = row.get(6).expectv("gas_price_wei_low_b");
            let gas_price_minor =
                BigIntDivider::reconstitute(gas_price_wei_high_b, gas_price_wei_low_b) as u128;
            let nonce = row.get(7).expectv("nonce");
            let reason_str: String = row.get(8).expectv("reason");
            let reason =
                FailureReason::from_str(&reason_str).expect("Failed to parse FailureReason");
            let status_str: String = row.get(9).expectv("status");
            let status =
                FailureStatus::from_str(&status_str).expect("Failed to parse FailureStatus");

            Ok(FailedTx {
                hash,
                receiver_address,
                amount_minor,
                timestamp,
                gas_price_minor,
                nonce,
                reason,
                status,
            })
        })
        .expect("Failed to execute query")
        .vigilant_flatten()
        .collect()
    }

    fn update_statuses(
        &self,
        status_updates: &HashMap<TxHash, FailureStatus>,
    ) -> Result<(), FailedPayableDaoError> {
        if status_updates.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let case_statements = status_updates
            .iter()
            .map(|(hash, status)| format!("WHEN tx_hash = '{:?}' THEN '{}'", hash, status))
            .join(" ");
        let tx_hashes = comma_joined_stringifiable(&status_updates.keys().collect_vec(), |hash| {
            format!("'{:?}'", hash)
        });

        let sql = format!(
            "UPDATE failed_payable \
                SET \
                    status = CASE \
                    {case_statements} \
                END \
            WHERE tx_hash IN ({tx_hashes})"
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(rows_changed) => {
                if rows_changed == status_updates.len() {
                    Ok(())
                } else {
                    Err(FailedPayableDaoError::PartialExecution(format!(
                        "Only {} of {} records had their status updated.",
                        rows_changed,
                        status_updates.len(),
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

pub trait FailedPayableDaoFactory {
    fn make(&self) -> Box<dyn FailedPayableDao>;
}

impl FailedPayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn FailedPayableDao> {
        Box::new(FailedPayableDaoReal::new(self.make_connection()))
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::{
        PendingTooLong, Reverted,
    };
    use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::{
        Concluded, RecheckRequired, RetryRequired,
    };
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDao, FailedPayableDaoError, FailedPayableDaoReal, FailureReason,
        FailureRetrieveCondition, FailureStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{
        make_read_only_db_connection, FailedTxBuilder,
    };
    use crate::accountant::db_access_objects::utils::{current_unix_timestamp, TxRecordWithHash};
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::accountant::test_utils::make_failed_tx;
    use crate::blockchain::errors::rpc_errors::AppRpcErrorKind;
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal, ValidationStatus,
    };
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::test_utils::ConnectionWrapperMock;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use std::collections::{HashMap, HashSet};
    use std::ops::Add;
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .reason(Reverted)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(PendingTooLong)
            .build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let txs = vec![tx1, tx2];

        let result = subject.insert_new_records(&txs);

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
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
        let tx1 = FailedTxBuilder::default()
            .hash(hash)
            .status(RetryRequired)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(hash)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(&vec![tx1, tx2]);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input. Input Transactions: \
                [FailedTx { \
                hash: 0x000000000000000000000000000000000000000000000000000000000000007b, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount_minor: 0, timestamp: 0, gas_price_minor: 0, \
                nonce: 0, reason: PendingTooLong, status: RetryRequired }, \
                FailedTx { \
                hash: 0x000000000000000000000000000000000000000000000000000000000000007b, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount_minor: 0, timestamp: 0, gas_price_minor: 0, \
                nonce: 0, reason: PendingTooLong, status: RecheckRequired(Waiting) }]"
                    .to_string()
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
        let tx1 = FailedTxBuilder::default()
            .hash(hash)
            .status(RetryRequired)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(hash)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .build();
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
    fn display_for_failure_retrieve_condition_works() {
        let tx_hash_1 = make_tx_hash(123);
        let tx_hash_2 = make_tx_hash(456);
        assert_eq!(FailureRetrieveCondition::ByTxHash(vec![tx_hash_1, tx_hash_2]).to_string(),
                   "WHERE tx_hash IN ('0x000000000000000000000000000000000000000000000000000000000000007b', \
                   '0x00000000000000000000000000000000000000000000000000000000000001c8')"
        );
        assert_eq!(
            FailureRetrieveCondition::ByStatus(RetryRequired).to_string(),
            "WHERE status = '\"RetryRequired\"'"
        );
        assert_eq!(
            FailureRetrieveCondition::ByStatus(RecheckRequired(ValidationStatus::Waiting))
                .to_string(),
            "WHERE status = '{\"RecheckRequired\":\"Waiting\"}'"
        );
        assert_eq!(
            FailureRetrieveCondition::EveryRecheckRequiredRecord.to_string(),
            "WHERE status LIKE 'RecheckRequired%'"
        );
    }

    #[test]
    fn failure_reason_from_str_works() {
        // Submission error
        assert_eq!(
            FailureReason::from_str(r#"{"Submission":{"Decoder":{"firstSeen":{"secs_since_epoch":1755080031,"nanos_since_epoch":0},"attempts":1}}}"#).unwrap(),
            FailureReason::Submission(AppRpcErrorKind::Decoder)
        );

        // Reverted
        assert_eq!(
            FailureReason::from_str("\"Reverted\"").unwrap(),
            FailureReason::Reverted
        );

        // PendingTooLong
        assert_eq!(
            FailureReason::from_str("\"PendingTooLong\"").unwrap(),
            FailureReason::PendingTooLong
        );

        // Invalid Variant
        assert_eq!(
            FailureReason::from_str("\"UnknownReason\"").unwrap_err(),
            "unknown variant `UnknownReason`, \
            expected one of `Submission`, `Reverted`, `Unrecognized`, `PendingTooLong` \
            at line 1 column 15 in '\"UnknownReason\"'"
        );

        // Invalid Input
        assert_eq!(
            FailureReason::from_str("not a failure reason").unwrap_err(),
            "expected value at line 1 column 1 in 'not a failure reason'"
        );
    }

    #[test]
    fn failure_status_from_str_works() {
        let validation_failure_clock = ValidationFailureClockMock::default().now_result(
            SystemTime::UNIX_EPOCH
                .add(Duration::from_secs(1755080031))
                .add(Duration::from_nanos(612180914)),
        );
        assert_eq!(
            FailureStatus::from_str("\"RetryRequired\"").unwrap(),
            FailureStatus::RetryRequired
        );

        assert_eq!(
            FailureStatus::from_str(r#"{"RecheckRequired":"Waiting"}"#).unwrap(),
            FailureStatus::RecheckRequired(ValidationStatus::Waiting)
        );

        assert_eq!(
            FailureStatus::from_str(r#"{"RecheckRequired":{"Reattempting":{"ServerUnreachable":{"firstSeen":{"secs_since_epoch":1755080031,"nanos_since_epoch":612180914},"attempts":1}}}}"#).unwrap(),
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting( PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::ServerUnreachable), &validation_failure_clock)))
        );

        assert_eq!(
            FailureStatus::from_str("\"Concluded\"").unwrap(),
            FailureStatus::Concluded
        );

        // Invalid Variant
        assert_eq!(
            FailureStatus::from_str("\"UnknownStatus\"").unwrap_err(),
            "unknown variant `UnknownStatus`, \
            expected one of `RetryRequired`, `RecheckRequired`, `Concluded` \
            at line 1 column 15 in '\"UnknownStatus\"'"
        );

        // Invalid Input
        assert_eq!(
            FailureStatus::from_str("not a failure status").unwrap_err(),
            "expected value at line 1 column 1 in 'not a failure status'"
        );
    }

    #[test]
    fn retrieve_condition_display_works() {
        assert_eq!(
            FailureRetrieveCondition::ByStatus(RetryRequired).to_string(),
            "WHERE status = '\"RetryRequired\"'"
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
            .reason(PendingTooLong)
            .timestamp(now - 3600)
            .status(RetryRequired)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(Reverted)
            .timestamp(now - 3600)
            .status(RetryRequired)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Reattempting(
                PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::ServerUnreachable),
                    &ValidationFailureClockReal::default(),
                ),
            )))
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .reason(PendingTooLong)
            .status(Concluded)
            .timestamp(now - 3000)
            .build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone(), tx3, tx4])
            .unwrap();

        let result = subject.retrieve_txs(Some(FailureRetrieveCondition::ByStatus(RetryRequired)));

        assert_eq!(result, vec![tx1, tx2]);
    }

    #[test]
    fn update_statuses_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "update_statuses_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .reason(Reverted)
            .status(RetryRequired)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone(), tx3.clone(), tx4.clone()])
            .unwrap();
        let now = SystemTime::now();
        let hashmap = HashMap::from([
            (tx1.hash, Concluded),
            (
                tx2.hash,
                RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::ServerUnreachable),
                    &ValidationFailureClockMock::default().now_result(now),
                ))),
            ),
            (tx3.hash, Concluded),
        ]);

        let result = subject.update_statuses(&hashmap);

        let updated_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(tx1.status, RetryRequired);
        assert_eq!(updated_txs[0].status, Concluded);
        assert_eq!(tx2.status, RecheckRequired(ValidationStatus::Waiting));
        assert_eq!(
            updated_txs[1].status,
            RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::ServerUnreachable),
                &ValidationFailureClockMock::default().now_result(now),
            )))
        );
        assert_eq!(tx3.status, RetryRequired);
        assert_eq!(updated_txs[2].status, Concluded);
        assert_eq!(tx4.status, RecheckRequired(ValidationStatus::Waiting));
        assert_eq!(
            updated_txs[3].status,
            RecheckRequired(ValidationStatus::Waiting)
        );
        assert_eq!(updated_txs.len(), 4);
    }

    #[test]
    fn update_statuses_handles_empty_input_error() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "update_statuses_handles_empty_input_error",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);

        let result = subject.update_statuses(&HashMap::new());

        assert_eq!(result, Err(FailedPayableDaoError::EmptyInput));
    }

    #[test]
    fn update_statuses_handles_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "update_statuses_handles_sql_error",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = FailedPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.update_statuses(&HashMap::from([(make_tx_hash(1), Concluded)]));

        assert_eq!(
            result,
            Err(FailedPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        );
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

    #[test]
    fn tx_record_with_hash_is_implemented_for_failed_tx() {
        let failed_tx = make_failed_tx(1234);
        let hash = failed_tx.hash;

        let hash_from_trait = failed_tx.hash();

        assert_eq!(hash_from_trait, hash);
    }
}
