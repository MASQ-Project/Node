// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::sent_payable_dao::Tx;
use crate::accountant::db_access_objects::utils::{
    DaoFactoryReal, TxHash, TxIdentifiers, VigilantRusqliteFlatten,
};
use crate::accountant::db_access_objects::Transaction;
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, join_with_separator};
use crate::blockchain::errors::rpc_errors::{AppRpcError, AppRpcErrorKind};
use crate::blockchain::errors::validation_status::PreviousAttempts;
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use masq_lib::utils::ExpectValue;
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use web3::types::Address;
use web3::Error as Web3Error;

#[derive(Debug, PartialEq, Eq)]
pub enum FailedPayableDaoError {
    EmptyInput,
    NoChange,
    InvalidInput(String),
    PartialExecution(String),
    SqlExecutionFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum FailureReason {
    Submission(AppRpcError),
    Reverted,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
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
            Err(_) => write!(f, "<invalid FailureStatus>"),
        }
    }
}

impl FromStr for FailureStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("{} in '{}'", e, s))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum ValidationStatus {
    Waiting,
    Reattempting(PreviousAttempts),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FailedTx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount: u128,
    pub timestamp: i64,
    pub gas_price_wei: u128,
    pub nonce: u64,
    pub reason: FailureReason,
    pub status: FailureStatus,
}

impl Transaction for FailedTx {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn receiver_address(&self) -> Address {
        self.receiver_address
    }

    fn amount(&self) -> u128 {
        self.amount
    }

    fn timestamp(&self) -> i64 {
        self.timestamp
    }

    fn gas_price_wei(&self) -> u128 {
        self.gas_price_wei
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn is_failed(&self) -> bool {
        true
    }
}

// PartialOrd and Ord are used to create BTreeSet
impl PartialOrd for FailedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FailedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Descending Order
        other
            .timestamp
            .cmp(&self.timestamp)
            .then_with(|| other.nonce.cmp(&self.nonce))
            .then_with(|| other.amount.cmp(&self.amount))
    }
}

impl From<(&Tx, &Web3Error)> for FailedTx {
    fn from((sent_tx, error): (&Tx, &Web3Error)) -> Self {
        Self {
            hash: sent_tx.hash,
            receiver_address: sent_tx.receiver_address,
            amount: sent_tx.amount,
            timestamp: sent_tx.timestamp,
            gas_price_wei: sent_tx.gas_price_wei,
            nonce: sent_tx.nonce,
            reason: FailureReason::Submission(error.clone().into()),
            status: FailureStatus::RetryRequired,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureRetrieveCondition {
    ByStatus(FailureStatus),
    ByReceiverAddresses(BTreeSet<Address>),
}

impl Display for FailureRetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureRetrieveCondition::ByStatus(status) => {
                write!(f, "WHERE status = '{}'", status)
            }
            FailureRetrieveCondition::ByReceiverAddresses(addresses) => {
                write!(
                    f,
                    "WHERE receiver_address IN ({})",
                    join_with_separator(addresses, |address| format!("'{:?}'", address), ", ")
                )
            }
        }
    }
}

pub trait FailedPayableDao {
    fn get_tx_identifiers(&self, hashes: &BTreeSet<TxHash>) -> TxIdentifiers;
    fn insert_new_records(&self, txs: &BTreeSet<FailedTx>) -> Result<(), FailedPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<FailureRetrieveCondition>) -> BTreeSet<FailedTx>;
    fn update_statuses(
        &self,
        status_updates: HashMap<TxHash, FailureStatus>,
    ) -> Result<(), FailedPayableDaoError>;
    fn delete_records(&self, hashes: &BTreeSet<TxHash>) -> Result<(), FailedPayableDaoError>;
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
    fn get_tx_identifiers(&self, hashes: &BTreeSet<TxHash>) -> TxIdentifiers {
        let sql = format!(
            "SELECT tx_hash, rowid FROM failed_payable WHERE tx_hash IN ({})",
            join_with_separator(hashes, |hash| format!("'{:?}'", hash), ", ")
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

    fn insert_new_records(&self, txs: &BTreeSet<FailedTx>) -> Result<(), FailedPayableDaoError> {
        if txs.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let unique_hashes: BTreeSet<TxHash> = txs.iter().map(|tx| tx.hash).collect();
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
            join_with_separator(
                txs,
                |tx| {
                    let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                    let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_wei);
                    let (amount_high_b, amount_low_b) = BigIntDivider::deconstruct(amount_checked);
                    let (gas_price_wei_high_b, gas_price_wei_low_b) =
                        BigIntDivider::deconstruct(gas_price_wei_checked);
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
                },
                ", "
            )
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

    fn retrieve_txs(&self, condition: Option<FailureRetrieveCondition>) -> BTreeSet<FailedTx> {
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
            let status_str: String = row.get(9).expectv("status");
            let status =
                FailureStatus::from_str(&status_str).expect("Failed to parse FailureStatus");

            Ok(FailedTx {
                hash,
                receiver_address,
                amount,
                timestamp,
                gas_price_wei,
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
        status_updates: HashMap<TxHash, FailureStatus>,
    ) -> Result<(), FailedPayableDaoError> {
        if status_updates.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let case_statements = join_with_separator(
            &status_updates,
            |(hash, status)| format!("WHEN tx_hash = '{:?}' THEN '{}'", hash, status),
            " ",
        );
        let tx_hashes =
            join_with_separator(status_updates.keys(), |hash| format!("'{:?}'", hash), ", ");

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

    fn delete_records(&self, hashes: &BTreeSet<TxHash>) -> Result<(), FailedPayableDaoError> {
        if hashes.is_empty() {
            return Err(FailedPayableDaoError::EmptyInput);
        }

        let sql = format!(
            "DELETE FROM failed_payable WHERE tx_hash IN ({})",
            join_with_separator(hashes, |hash| { format!("'{:?}'", hash) }, ", ")
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
        FailedPayableDao, FailedPayableDaoError, FailedPayableDaoReal, FailedTx, FailureReason,
        FailureRetrieveCondition, FailureStatus, ValidationStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{
        make_read_only_db_connection, FailedTxBuilder,
    };
    use crate::accountant::db_access_objects::utils::current_unix_timestamp;
    use crate::accountant::db_access_objects::Transaction;
    use crate::blockchain::errors::rpc_errors::LocalError::Decoder;
    use crate::blockchain::errors::rpc_errors::{AppRpcError, AppRpcErrorKind};
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal,
    };
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::{make_address, make_tx_hash, ValidationFailureClockMock};
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::test_utils::ConnectionWrapperMock;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use std::collections::{BTreeSet, HashMap};
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
            .nonce(1)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .nonce(2)
            .reason(PendingTooLong)
            .build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let hashset = BTreeSet::from([tx1.clone(), tx2.clone()]);

        let result = subject.insert_new_records(&hashset);

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs, BTreeSet::from([tx2, tx1]));
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
        let empty_input = BTreeSet::new();

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
            .nonce(1)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(hash)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .nonce(2)
            .build();
        let subject = FailedPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(&BTreeSet::from([tx1, tx2]));

        assert_eq!(
            result,
            Err(FailedPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input. Input Transactions: \
                {FailedTx { \
                hash: 0x000000000000000000000000000000000000000000000000000000000000007b, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount: 0, timestamp: 1719990000, gas_price_wei: 0, \
                nonce: 2, reason: PendingTooLong, status: RecheckRequired(Waiting) }, \
                FailedTx { \
                hash: 0x000000000000000000000000000000000000000000000000000000000000007b, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount: 0, timestamp: 1719990000, gas_price_wei: 0, \
                nonce: 1, reason: PendingTooLong, status: RetryRequired }}"
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
        let initial_insertion_result = subject.insert_new_records(&BTreeSet::from([tx1]));

        let result = subject.insert_new_records(&BTreeSet::from([tx2]));

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

        let result = subject.insert_new_records(&BTreeSet::from([tx]));

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

        let result = subject.insert_new_records(&BTreeSet::from([tx]));

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
        let hashset = BTreeSet::from([present_hash, absent_hash, another_present_hash]);
        let present_tx = FailedTxBuilder::default()
            .hash(present_hash)
            .nonce(1)
            .build();
        let another_present_tx = FailedTxBuilder::default()
            .hash(another_present_hash)
            .nonce(2)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([present_tx, another_present_tx]))
            .unwrap();

        let result = subject.get_tx_identifiers(&hashset);

        assert_eq!(result.get(&present_hash), Some(&2u64));
        assert_eq!(result.get(&absent_hash), None);
        assert_eq!(result.get(&another_present_hash), Some(&1u64));
    }

    #[test]
    fn failure_reason_from_str_works() {
        // Submission error
        assert_eq!(
            FailureReason::from_str(r#"{"Submission":{"Local":{"Decoder":"am i alive?"}}}"#)
                .unwrap(),
            FailureReason::Submission(AppRpcError::Local(Decoder("am i alive?".to_string())))
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
            expected one of `Submission`, `Reverted`, `PendingTooLong` \
            at line 1 column 15 in '\"UnknownReason\"'"
        );

        // Invalid Input
        assert_eq!(
            FailureReason::from_str("not a failure reason").unwrap_err(),
            "expected value at line 1 column 1 in 'not a failure reason'"
        );
    }

    #[test]
    fn show_str() {
        let validation_failure_clock = ValidationFailureClockMock::default().now_result(
            SystemTime::UNIX_EPOCH
                .add(Duration::from_secs(1755080031))
                .add(Duration::from_nanos(612180914)),
        );
        let a =
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Unreachable),
                &validation_failure_clock,
            )))
            .to_string();

        eprintln!("a: {}", a);
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
            FailureStatus::from_str(r#"{"RecheckRequired":{"Reattempting":{"AppRpc":{"Unreachable":{"firstSeen":{"secs_since_epoch":1755080031,"nanos_since_epoch":612180914},"attempts":1}}}}}"#).unwrap(),
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting( PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Unreachable), &validation_failure_clock)))
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
        assert_eq!(
            FailureRetrieveCondition::ByReceiverAddresses(BTreeSet::from([make_address(1), make_address(2)]))
                .to_string(),
            "WHERE receiver_address IN ('0x0000000000000000000000000000000000000001', '0x0000000000000000000000000000000000000002')"
        )
    }

    #[test]
    fn can_retrieve_all_txs_ordered_by_timestamp_and_nonce() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "can_retrieve_all_txs_ordered_by_timestamp_and_nonce",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .timestamp(1000)
            .nonce(1)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .timestamp(1000)
            .nonce(2)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .timestamp(1001)
            .nonce(1)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .timestamp(1001)
            .nonce(2)
            .build();

        subject
            .insert_new_records(&BTreeSet::from([tx2.clone(), tx4.clone()]))
            .unwrap();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx3.clone()]))
            .unwrap();

        let result = subject.retrieve_txs(None);

        assert_eq!(result, BTreeSet::from([tx4, tx3, tx2, tx1]));
    }

    #[test]
    fn can_retrieve_txs_to_retry() {
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
            .nonce(1)
            .timestamp(now - 3600)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .nonce(2)
            .timestamp(now - 3600)
            .reason(Reverted)
            .status(RetryRequired)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .nonce(3)
            .timestamp(now - 3000)
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Reattempting(
                PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Unreachable),
                    &ValidationFailureClockReal::default(),
                ),
            )))
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .nonce(4)
            .reason(PendingTooLong)
            .status(Concluded)
            .timestamp(now - 3000)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone(), tx3, tx4]))
            .unwrap();

        let result = subject.retrieve_txs(Some(FailureRetrieveCondition::ByStatus(RetryRequired)));

        assert_eq!(result, BTreeSet::from([tx2, tx1]));
    }

    #[test]
    fn can_retrieve_txs_by_receiver_addresses() {
        let home_dir = ensure_node_home_directory_exists(
            "failed_payable_dao",
            "can_retrieve_txs_by_receiver_addresses",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let address1 = make_address(1);
        let address2 = make_address(2);
        let address3 = make_address(3);
        let address4 = make_address(4);
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .receiver_address(address1)
            .nonce(1)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .receiver_address(address2)
            .nonce(2)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .receiver_address(address3)
            .nonce(3)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .receiver_address(address4)
            .nonce(4)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([
                tx1.clone(),
                tx2.clone(),
                tx3.clone(),
                tx4.clone(),
            ]))
            .unwrap();

        let result = subject.retrieve_txs(Some(FailureRetrieveCondition::ByReceiverAddresses(
            BTreeSet::from([address1, address2, address3]),
        )));

        assert_eq!(result.len(), 3);
        assert!(result.contains(&tx1));
        assert!(result.contains(&tx2));
        assert!(result.contains(&tx3));
        assert!(!result.contains(&tx4));
    }

    #[test]
    fn update_statuses_works() {
        let home_dir =
            ensure_node_home_directory_exists("failed_payable_dao", "update_statuses_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = FailedPayableDaoReal::new(wrapped_conn);
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hash3 = make_tx_hash(3);
        let hash4 = make_tx_hash(4);
        let tx1 = FailedTxBuilder::default()
            .hash(hash1)
            .reason(Reverted)
            .status(RetryRequired)
            .nonce(4)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(hash2)
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .nonce(3)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(hash3)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .nonce(2)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(hash4)
            .reason(PendingTooLong)
            .status(RecheckRequired(ValidationStatus::Waiting))
            .nonce(1)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([
                tx1.clone(),
                tx2.clone(),
                tx3.clone(),
                tx4.clone(),
            ]))
            .unwrap();
        let hashmap = HashMap::from([
            (tx1.hash, Concluded),
            (
                tx2.hash,
                RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Unreachable),
                    &ValidationFailureClockReal::default(),
                ))),
            ),
            (tx3.hash, Concluded),
        ]);

        let result = subject.update_statuses(hashmap);

        let updated_txs = subject.retrieve_txs(None);
        let updated_tx1 = updated_txs.iter().find(|tx| tx.hash == hash1).unwrap();
        let updated_tx2 = updated_txs.iter().find(|tx| tx.hash == hash2).unwrap();
        let updated_tx3 = updated_txs.iter().find(|tx| tx.hash == hash3).unwrap();
        let updated_tx4 = updated_txs.iter().find(|tx| tx.hash == hash4).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(tx1.status, RetryRequired);
        assert_eq!(updated_tx1.status, Concluded);
        assert_eq!(tx2.status, RecheckRequired(ValidationStatus::Waiting));
        assert_eq!(
            updated_tx2.status,
            RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Unreachable),
                &ValidationFailureClockReal::default()
            )))
        );
        assert_eq!(tx3.status, RetryRequired);
        assert_eq!(updated_tx3.status, Concluded);
        assert_eq!(tx4.status, RecheckRequired(ValidationStatus::Waiting));
        assert_eq!(
            updated_tx4.status,
            RecheckRequired(ValidationStatus::Waiting)
        );
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

        let result = subject.update_statuses(HashMap::new());

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

        let result = subject.update_statuses(HashMap::from([(make_tx_hash(1), Concluded)]));

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
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .nonce(1)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .nonce(2)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .nonce(3)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .nonce(4)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([
                tx1.clone(),
                tx2.clone(),
                tx3.clone(),
                tx4.clone(),
            ]))
            .unwrap();
        let hashset = BTreeSet::from([tx1.hash, tx3.hash]);

        let result = subject.delete_records(&hashset);

        let remaining_records = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(remaining_records, BTreeSet::from([tx4, tx2]));
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

        let result = subject.delete_records(&BTreeSet::new());

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
        let hashset = BTreeSet::from([non_existent_hash]);

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
        subject.insert_new_records(&BTreeSet::from([tx])).unwrap();
        let set = BTreeSet::from([present_hash, absent_hash]);

        let result = subject.delete_records(&set);

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
        let hashes = BTreeSet::from([make_tx_hash(1)]);

        let result = subject.delete_records(&hashes);

        assert_eq!(
            result,
            Err(FailedPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn failed_tx_ordering_in_btree_set_works() {
        let tx1 = FailedTxBuilder::default()
            .hash(make_tx_hash(1))
            .timestamp(1000)
            .nonce(1)
            .amount(100)
            .build();
        let tx2 = FailedTxBuilder::default()
            .hash(make_tx_hash(2))
            .timestamp(1000)
            .nonce(1)
            .amount(200)
            .build();
        let tx3 = FailedTxBuilder::default()
            .hash(make_tx_hash(3))
            .timestamp(1000)
            .nonce(2)
            .amount(100)
            .build();
        let tx4 = FailedTxBuilder::default()
            .hash(make_tx_hash(4))
            .timestamp(2000)
            .nonce(3)
            .amount(100)
            .build();

        let mut set = BTreeSet::new();
        set.insert(tx1.clone());
        set.insert(tx2.clone());
        set.insert(tx3.clone());
        set.insert(tx4.clone());

        let expected_order = vec![tx4, tx3, tx2, tx1];
        assert_eq!(set.into_iter().collect::<Vec<_>>(), expected_order);
    }

    #[test]
    fn transaction_trait_methods_for_failed_tx() {
        let hash = make_tx_hash(1);
        let receiver_address = make_address(1);
        let amount = 1000;
        let timestamp = 1625247600;
        let gas_price_wei = 2000;
        let nonce = 42;
        let reason = FailureReason::Reverted;
        let status = FailureStatus::RetryRequired;

        let failed_tx = FailedTx {
            hash,
            receiver_address,
            amount,
            timestamp,
            gas_price_wei,
            nonce,
            reason,
            status,
        };

        assert_eq!(failed_tx.receiver_address(), receiver_address);
        assert_eq!(failed_tx.hash(), hash);
        assert_eq!(failed_tx.amount(), amount);
        assert_eq!(failed_tx.timestamp(), timestamp);
        assert_eq!(failed_tx.gas_price_wei(), gas_price_wei);
        assert_eq!(failed_tx.nonce(), nonce);
        assert_eq!(failed_tx.is_failed(), true);
    }
}
