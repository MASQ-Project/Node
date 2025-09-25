// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::{
    sql_values_of_sent_tx, DaoFactoryReal, TxHash, TxIdentifiers,
};
use crate::accountant::db_access_objects::Transaction;
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::{checked_conversion, comma_joined_stringifiable, join_with_separator};
use crate::blockchain::blockchain_interface::data_structures::TxBlock;
use crate::blockchain::errors::validation_status::ValidationStatus;
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use ethereum_types::H256;
use itertools::Itertools;
use masq_lib::utils::ExpectValue;
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use web3::types::Address;

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    EmptyInput,
    NoChange,
    InvalidInput(String),
    PartialExecution(String),
    SqlExecutionFailed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentTx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount_minor: u128,
    pub timestamp: i64,
    pub gas_price_minor: u128,
    pub nonce: u64,
    pub status: TxStatus,
}

impl Transaction for SentTx {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn receiver_address(&self) -> Address {
        self.receiver_address
    }

    fn amount(&self) -> u128 {
        self.amount_minor
    }

    fn timestamp(&self) -> i64 {
        self.timestamp
    }

    fn gas_price_wei(&self) -> u128 {
        self.gas_price_minor
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn is_failed(&self) -> bool {
        false
    }
}

impl PartialOrd for SentTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SentTx {
    fn cmp(&self, other: &Self) -> Ordering {
        // Descending Order
        other
            .timestamp
            .cmp(&self.timestamp)
            .then_with(|| other.nonce.cmp(&self.nonce))
            .then_with(|| other.amount_minor.cmp(&self.amount_minor))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending(ValidationStatus),
    Confirmed {
        block_hash: String,
        block_number: u64,
        detection: Detection,
    },
}

impl PartialOrd for TxStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        todo!()
    }
}

impl Ord for TxStatus {
    fn cmp(&self, other: &Self) -> Ordering {
        todo!()
    }
}

impl FromStr for TxStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("{} in '{}'", e, s))
    }
}

impl Display for TxStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            // Untestable
            Err(_) => write!(f, "<invalid TxStatus>"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Detection {
    Normal,
    Reclaim,
}

impl From<TxBlock> for TxStatus {
    fn from(tx_block: TxBlock) -> Self {
        TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block.block_hash),
            block_number: u64::try_from(tx_block.block_number).expect("block number too big"),
            detection: Detection::Normal,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetrieveCondition {
    IsPending,
    ByHash(BTreeSet<TxHash>),
    ByNonce(Vec<u64>),
}

impl Display for RetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrieveCondition::IsPending => {
                write!(f, r#"WHERE status LIKE '%"Pending":%'"#)
            }
            RetrieveCondition::ByHash(tx_hashes) => {
                write!(
                    f,
                    "WHERE tx_hash IN ({})",
                    join_with_separator(tx_hashes, |hash| format!("'{:?}'", hash), ", ")
                )
            }
            RetrieveCondition::ByNonce(nonces) => {
                write!(
                    f,
                    "WHERE nonce IN ({})",
                    comma_joined_stringifiable(nonces, |nonce| nonce.to_string())
                )
            }
        }
    }
}

pub trait SentPayableDao {
    fn get_tx_identifiers(&self, hashes: &BTreeSet<TxHash>) -> TxIdentifiers;
    fn insert_new_records(&self, txs: &BTreeSet<SentTx>) -> Result<(), SentPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> BTreeSet<SentTx>;
    //TODO potentially atomically
    fn confirm_txs(&self, hash_map: &HashMap<TxHash, TxBlock>) -> Result<(), SentPayableDaoError>;
    fn replace_records(&self, new_txs: &BTreeSet<SentTx>) -> Result<(), SentPayableDaoError>;
    fn update_statuses(
        &self,
        hash_map: &HashMap<TxHash, TxStatus>,
    ) -> Result<(), SentPayableDaoError>;
    //TODO potentially atomically
    fn delete_records(&self, hashes: &BTreeSet<TxHash>) -> Result<(), SentPayableDaoError>;
}

// TODO: GH-605: Coming from GH-598
// pub trait SentPayableDao {
//     fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers;
//     fn insert_new_records(&self, txs: &[SentTx]) -> Result<(), SentPayableDaoError>;
//     fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> Vec<SentTx>;
//     //TODO potentially atomically
//     fn confirm_txs(&self, hash_map: &HashMap<TxHash, TxBlock>) -> Result<(), SentPayableDaoError>;
//     fn replace_records(&self, new_txs: &[SentTx]) -> Result<(), SentPayableDaoError>;
//     fn update_statuses(
//         &self,
//         hash_map: &HashMap<TxHash, TxStatus>,
//     ) -> Result<(), SentPayableDaoError>;
//     //TODO potentially atomically
//     fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), SentPayableDaoError>;
// }

#[derive(Debug)]
pub struct SentPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> SentPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        Self { conn }
    }
}

impl SentPayableDao for SentPayableDaoReal<'_> {
    fn get_tx_identifiers(&self, hashes: &BTreeSet<TxHash>) -> TxIdentifiers {
        let sql = format!(
            "SELECT tx_hash, rowid FROM sent_payable WHERE tx_hash IN ({})",
            join_with_separator(hashes, |hash| format!("'{:?}'", hash), ", ")
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

    fn insert_new_records(&self, txs: &BTreeSet<SentTx>) -> Result<(), SentPayableDaoError> {
        if txs.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let unique_hashes: BTreeSet<TxHash> = txs.iter().map(|tx| tx.hash).collect();
        if unique_hashes.len() != txs.len() {
            return Err(SentPayableDaoError::InvalidInput(format!(
                "Duplicate hashes found in the input. Input Transactions: {:?}",
                txs
            )));
        }

        let duplicates = self.get_tx_identifiers(&unique_hashes);
        if !duplicates.is_empty() {
            return Err(SentPayableDaoError::InvalidInput(format!(
                "Duplicates detected in the database: {:?}",
                duplicates,
            )));
        }

        let sql = format!(
            "INSERT INTO sent_payable (\
             tx_hash, \
             receiver_address, \
             amount_high_b, \
             amount_low_b, \
             timestamp, \
             gas_price_wei_high_b, \
             gas_price_wei_low_b, \
             nonce, \
             status \
             ) VALUES {}",
            join_with_separator(txs, |tx| sql_values_of_sent_tx(tx), ", ")
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

    fn retrieve_txs(&self, condition_opt: Option<RetrieveCondition>) -> BTreeSet<SentTx> {
        let raw_sql = "SELECT tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei_high_b, gas_price_wei_low_b, nonce, status FROM sent_payable"
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
            let receiver_address_str: String = row.get(1).expectv("receivable_address");
            let receiver_address =
                Address::from_str(&receiver_address_str[2..]).expect("Failed to parse H160");
            let amount_high_b = row.get(2).expectv("amount_high_b");
            let amount_low_b = row.get(3).expectv("amount_low_b");
            let amount_minor = BigIntDivider::reconstitute(amount_high_b, amount_low_b) as u128;
            let timestamp = row.get(4).expectv("timestamp");
            let gas_price_wei_high_b = row.get(5).expectv("gas_price_wei_high_b");
            let gas_price_wei_low_b = row.get(6).expectv("gas_price_wei_low_b");
            let gas_price_minor =
                BigIntDivider::reconstitute(gas_price_wei_high_b, gas_price_wei_low_b) as u128;
            let nonce = row.get(7).expectv("nonce");
            let status_str: String = row.get(8).expectv("status");
            let status = TxStatus::from_str(&status_str).expect("Failed to parse TxStatus");

            Ok(SentTx {
                hash,
                receiver_address,
                amount_minor,
                timestamp,
                gas_price_minor,
                nonce,
                status,
            })
        })
        .expect("Failed to execute query")
        .filter_map(Result::ok)
        .collect()
    }

    fn confirm_txs(&self, hash_map: &HashMap<TxHash, TxBlock>) -> Result<(), SentPayableDaoError> {
        if hash_map.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        for (hash, tx_block) in hash_map {
            let sql = format!(
                "UPDATE sent_payable SET status = '{}' WHERE tx_hash = '{:?}'",
                TxStatus::from(*tx_block),
                hash
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

    fn replace_records(&self, new_txs: &BTreeSet<SentTx>) -> Result<(), SentPayableDaoError> {
        if new_txs.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let build_case = |value_fn: fn(&SentTx) -> String| {
            join_with_separator(
                new_txs,
                |tx| format!("WHEN nonce = {} THEN {}", tx.nonce, value_fn(tx)),
                " ",
            )
        };

        let tx_hash_cases = build_case(|tx| format!("'{:?}'", tx.hash));
        let receiver_address_cases = build_case(|tx| format!("'{:?}'", tx.receiver_address));
        let amount_high_b_cases = build_case(|tx| {
            let amount_checked = checked_conversion::<u128, i128>(tx.amount_minor);
            let (high, _) = BigIntDivider::deconstruct(amount_checked);
            high.to_string()
        });
        let amount_low_b_cases = build_case(|tx| {
            let amount_checked = checked_conversion::<u128, i128>(tx.amount_minor);
            let (_, low) = BigIntDivider::deconstruct(amount_checked);
            low.to_string()
        });
        let timestamp_cases = build_case(|tx| tx.timestamp.to_string());
        let gas_price_wei_high_b_cases = build_case(|tx| {
            let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_minor);
            let (high, _) = BigIntDivider::deconstruct(gas_price_wei_checked);
            high.to_string()
        });
        let gas_price_wei_low_b_cases = build_case(|tx| {
            let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_minor);
            let (_, low) = BigIntDivider::deconstruct(gas_price_wei_checked);
            low.to_string()
        });
        let status_cases = build_case(|tx| format!("'{}'", tx.status));

        let nonces = join_with_separator(new_txs, |tx| tx.nonce.to_string(), ", ");

        let sql = format!(
            "UPDATE sent_payable \
             SET \
                tx_hash = CASE \
                    {tx_hash_cases} \
                END, \
                receiver_address = CASE \
                    {receiver_address_cases} \
                END, \
                amount_high_b = CASE \
                    {amount_high_b_cases} \
                END, \
                amount_low_b = CASE \
                    {amount_low_b_cases} \
                END, \
                timestamp = CASE \
                    {timestamp_cases} \
                END, \
                gas_price_wei_high_b = CASE \
                    {gas_price_wei_high_b_cases} \
                END, \
                gas_price_wei_low_b = CASE \
                    {gas_price_wei_low_b_cases} \
                END, \
                status = CASE \
                    {status_cases} \
                END \
            WHERE nonce IN ({nonces})",
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(updated_rows) => match updated_rows {
                0 => Err(SentPayableDaoError::NoChange),
                count if count == new_txs.len() => Ok(()),
                _ => Err(SentPayableDaoError::PartialExecution(format!(
                    "Only {} out of {} records updated",
                    updated_rows,
                    new_txs.len()
                ))),
            },
            Err(e) => Err(SentPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }

    fn update_statuses(
        &self,
        status_updates: &HashMap<TxHash, TxStatus>,
    ) -> Result<(), SentPayableDaoError> {
        if status_updates.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let case_statements = status_updates
            .iter()
            .map(|(hash, status)| format!("WHEN tx_hash = '{:?}' THEN '{}'", hash, status))
            .join(" ");
        let tx_hashes = comma_joined_stringifiable(&status_updates.keys().collect_vec(), |hash| {
            format!("'{:?}'", hash)
        });

        let sql = format!(
            "UPDATE sent_payable \
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
                    Err(SentPayableDaoError::PartialExecution(format!(
                        "Only {} of {} records had their status updated.",
                        rows_changed,
                        status_updates.len(),
                    )))
                }
            }
            Err(e) => Err(SentPayableDaoError::SqlExecutionFailed(e.to_string())),
        }
    }

    fn delete_records(&self, hashes: &BTreeSet<TxHash>) -> Result<(), SentPayableDaoError> {
        if hashes.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let sql = format!(
            "DELETE FROM sent_payable WHERE tx_hash IN ({})",
            join_with_separator(hashes, |hash| { format!("'{:?}'", hash) }, ", ")
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(deleted_rows) => {
                if deleted_rows == hashes.len() {
                    Ok(())
                } else if deleted_rows == 0 {
                    Err(SentPayableDaoError::NoChange)
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

pub trait SentPayableDaoFactory {
    fn make(&self) -> Box<dyn SentPayableDao>;
}

impl SentPayableDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn SentPayableDao> {
        Box::new(SentPayableDaoReal::new(self.make_connection()))
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::{
        ByHash, ByNonce, IsPending,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoError::{
        EmptyInput, PartialExecution,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{
        Detection, RetrieveCondition, SentPayableDao, SentPayableDaoError, SentPayableDaoReal,
        SentTx, TxStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{
        make_read_only_db_connection, make_sent_tx, TxBuilder,
    };
    use crate::accountant::db_access_objects::Transaction;
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::blockchain::blockchain_interface::data_structures::TxBlock;
    use crate::blockchain::errors::rpc_errors::{AppRpcErrorKind, LocalErrorKind, RemoteErrorKind};
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal, ValidationStatus,
    };
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::{make_address, make_block_hash, make_tx_hash};
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::test_utils::ConnectionWrapperMock;
    use ethereum_types::{H256, U64};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Connection;
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::ops::{Add, Sub};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default()
            .hash(make_tx_hash(2))
            .status(TxStatus::Pending(ValidationStatus::Reattempting(
                PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    &ValidationFailureClockReal::default(),
                )
                .add_attempt(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    &ValidationFailureClockReal::default(),
                ),
            )))
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let txs = BTreeSet::from([tx1, tx2]);

        let result = subject.insert_new_records(&txs);

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs, txs);
    }

    #[test]
    fn insert_new_records_throws_err_for_empty_input() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_throws_err_for_empty_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let empty_input = BTreeSet::new();

        let result = subject.insert_new_records(&empty_input);

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn insert_new_records_throws_error_when_two_txs_with_same_hash_are_present_in_the_input() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_throws_error_when_two_txs_with_same_hash_are_present_in_the_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = make_tx_hash(1234);
        let tx1 = TxBuilder::default()
            .hash(hash)
            .timestamp(1749204017)
            .status(TxStatus::Pending(ValidationStatus::Waiting))
            .build();
        let tx2 = TxBuilder::default()
            .hash(hash)
            .timestamp(1749204020)
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(456)),
                block_number: 7890123,
                detection: Detection::Reclaim,
            })
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(&BTreeSet::from([tx1, tx2]));

        assert_eq!(
            result,
            Err(SentPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input. Input Transactions: \
                {\
                SentTx { \
                hash: 0x00000000000000000000000000000000000000000000000000000000000004d2, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount_minor: 0, timestamp: 1749204020, gas_price_minor: 0, \
                nonce: 0, status: Confirmed { block_hash: \
                \"0x000000000000000000000000000000000000000000000000000000003b9acbc8\", \
                block_number: 7890123, detection: Reclaim } }, \
                SentTx { \
                hash: 0x00000000000000000000000000000000000000000000000000000000000004d2, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount_minor: 0, timestamp: 1749204017, gas_price_minor: 0, \
                nonce: 0, status: Pending(Waiting) }\
                }"
                .to_string()
            ))
        );
    }

    #[test]
    fn insert_new_records_throws_error_when_input_tx_hash_is_already_present_in_the_db() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_throws_error_when_input_tx_hash_is_already_present_in_the_db",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let hash = make_tx_hash(1234);
        let tx1 = TxBuilder::default().hash(hash).build();
        let tx2 = TxBuilder::default().hash(hash).build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let initial_insertion_result = subject.insert_new_records(&BTreeSet::from([tx1]));

        let result = subject.insert_new_records(&BTreeSet::from([tx2]));

        assert_eq!(initial_insertion_result, Ok(()));
        assert_eq!(
            result,
            Err(SentPayableDaoError::InvalidInput(
                "Duplicates detected in the database: \
                {0x00000000000000000000000000000000000000000000000000000000000004d2: 1}"
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
        let tx = TxBuilder::default().build();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(&BTreeSet::from([tx]));

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
        let tx = TxBuilder::default().build();
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(&BTreeSet::from([tx]));

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
        let present_hash = make_tx_hash(1);
        let absent_hash = make_tx_hash(2);
        let another_present_hash = make_tx_hash(3);
        let hashset = BTreeSet::from([present_hash, absent_hash, another_present_hash]);
        let present_tx = TxBuilder::default().hash(present_hash).build();
        let another_present_tx = TxBuilder::default().hash(another_present_hash).build();
        subject
            .insert_new_records(&BTreeSet::from([present_tx, another_present_tx]))
            .unwrap();

        let result = subject.get_tx_identifiers(&hashset);

        assert_eq!(result.get(&present_hash), Some(&1u64));
        assert_eq!(result.get(&absent_hash), None);
        assert_eq!(result.get(&another_present_hash), Some(&2u64));
    }

    #[test]
    fn retrieve_condition_display_works() {
        assert_eq!(IsPending.to_string(), "WHERE status LIKE '%\"Pending\":%'");
        // 0x0000000000000000000000000000000000000000000000000000000123456789
        assert_eq!(
            ByHash(BTreeSet::from([
                H256::from_low_u64_be(0x123456789),
                H256::from_low_u64_be(0x987654321),
            ]))
            .to_string(),
            "WHERE tx_hash IN (\
            '0x0000000000000000000000000000000000000000000000000000000123456789', \
            '0x0000000000000000000000000000000000000000000000000000000987654321'\
            )"
        );
        assert_eq!(ByNonce(vec![45, 47]).to_string(), "WHERE nonce IN (45, 47)")
    }

    #[test]
    fn can_retrieve_all_txs() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "can_retrieve_all_txs");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone()]))
            .unwrap();
        subject
            .insert_new_records(&BTreeSet::from([tx3.clone()]))
            .unwrap();

        let result = subject.retrieve_txs(None);

        assert_eq!(result, BTreeSet::from([tx1, tx2, tx3]));
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
            .hash(make_tx_hash(1))
            .status(TxStatus::Pending(ValidationStatus::Waiting))
            .build();
        let tx2 = TxBuilder::default()
            .hash(make_tx_hash(2))
            .status(TxStatus::Pending(ValidationStatus::Reattempting(
                PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    &ValidationFailureClockReal::default(),
                ),
            )))
            .build();
        let tx3 = TxBuilder::default()
            .hash(make_tx_hash(3))
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(456)),
                block_number: 456789,
                detection: Detection::Normal,
            })
            .build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone(), tx3]))
            .unwrap();

        let result = subject.retrieve_txs(Some(RetrieveCondition::IsPending));

        assert_eq!(result, BTreeSet::from([tx1, tx2]));
    }

    #[test]
    fn tx_can_be_retrieved_by_hash() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "tx_can_be_retrieved_by_hash");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2, tx3.clone()]))
            .unwrap();

        let result = subject.retrieve_txs(Some(ByHash(BTreeSet::from([tx1.hash, tx3.hash]))));

        assert_eq!(result, BTreeSet::from([tx1, tx3]));
    }

    #[test]
    fn retrieve_txs_by_hash_returns_only_existing_transactions() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "retrieve_txs_by_hash_returns_only_existing_transactions",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).nonce(2).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).nonce(3).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone(), tx3.clone()]))
            .unwrap();
        let mut query_hashes = BTreeSet::new();
        query_hashes.insert(make_tx_hash(1)); // Exists
        query_hashes.insert(make_tx_hash(2)); // Exists
        query_hashes.insert(make_tx_hash(4)); // Does not exist
        query_hashes.insert(make_tx_hash(5)); // Does not exist

        let result = subject.retrieve_txs(Some(RetrieveCondition::ByHash(query_hashes)));

        assert_eq!(result.len(), 2, "Should only return 2 transactions");
        assert!(result.contains(&tx1), "Should contain tx1");
        assert!(result.contains(&tx2), "Should contain tx2");
        assert!(!result.contains(&tx3), "Should not contain tx3");
        assert!(
            result.iter().all(|tx| tx.hash != make_tx_hash(4)),
            "Should not contain hash 4"
        );
        assert!(
            result.iter().all(|tx| tx.hash != make_tx_hash(5)),
            "Should not contain hash 5"
        );
    }

    #[test]
    fn tx_can_be_retrieved_by_nonce() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "tx_can_be_retrieved_by_nonce");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default()
            .hash(make_tx_hash(123))
            .nonce(33)
            .build();
        let tx2 = TxBuilder::default()
            .hash(make_tx_hash(456))
            .nonce(34)
            .build();
        let tx3 = TxBuilder::default()
            .hash(make_tx_hash(789))
            .nonce(35)
            .build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2, tx3.clone()]))
            .unwrap();

        let result = subject.retrieve_txs(Some(ByNonce(vec![33, 35])));

        assert_eq!(result, BTreeSet::from([tx1, tx3]));
    }

    #[test]
    fn confirm_tx_works() {
        let home_dir = ensure_node_home_directory_exists("sent_payable_dao", "confirm_tx_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let tx1 = TxBuilder::default().hash(hash1).build();
        let tx2 = TxBuilder::default().hash(hash2).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone()]))
            .unwrap();
        let updated_pre_assert_txs =
            subject.retrieve_txs(Some(ByHash(BTreeSet::from([hash1, hash2]))));
        let pre_assert_status_tx1 = updated_pre_assert_txs.get(&tx1).unwrap().status.clone();
        let pre_assert_status_tx2 = updated_pre_assert_txs.get(&tx2).unwrap().status.clone();
        let confirmed_tx_block_1 = TxBlock {
            block_hash: make_block_hash(3),
            block_number: U64::from(1),
        };
        let confirmed_tx_block_2 = TxBlock {
            block_hash: make_block_hash(4),
            block_number: U64::from(2),
        };
        let hash_map = HashMap::from([
            (tx1.hash, confirmed_tx_block_1.clone()),
            (tx2.hash, confirmed_tx_block_2.clone()),
        ]);

        let result = subject.confirm_txs(&hash_map);

        let updated_txs = subject.retrieve_txs(Some(ByHash(BTreeSet::from([tx1.hash, tx2.hash]))));
        let updated_tx1 = updated_txs.iter().find(|tx| tx.hash == hash1).unwrap();
        let updated_tx2 = updated_txs.iter().find(|tx| tx.hash == hash2).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(
            pre_assert_status_tx1,
            TxStatus::Pending(ValidationStatus::Waiting)
        );
        assert_eq!(
            updated_tx1.status,
            TxStatus::Confirmed {
                block_hash: format!("{:?}", confirmed_tx_block_1.block_hash),
                block_number: confirmed_tx_block_1.block_number.as_u64(),
                detection: Detection::Normal
            }
        );
        assert_eq!(
            pre_assert_status_tx2,
            TxStatus::Pending(ValidationStatus::Waiting)
        );
        assert_eq!(
            updated_tx2.status,
            TxStatus::Confirmed {
                block_hash: format!("{:?}", confirmed_tx_block_2.block_hash),
                block_number: confirmed_tx_block_2.block_number.as_u64(),
                detection: Detection::Normal
            }
        );
    }

    #[test]
    fn confirm_tx_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "confirm_tx_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let tx = TxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&BTreeSet::from([tx])).unwrap();
        let hash_map = HashMap::new();

        let result = subject.confirm_txs(&hash_map);

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn confirm_tx_returns_error_during_partial_execution() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "confirm_tx_returns_error_during_partial_execution",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let non_existent_hash = make_tx_hash(999);
        let tx = TxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&BTreeSet::from([tx])).unwrap();
        let hash_map = HashMap::from([
            (
                existent_hash,
                TxBlock {
                    block_hash: make_block_hash(1),
                    block_number: U64::from(1),
                },
            ),
            (
                non_existent_hash,
                TxBlock {
                    block_hash: make_block_hash(2),
                    block_number: U64::from(2),
                },
            ),
        ]);

        let result = subject.confirm_txs(&hash_map);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(format!(
                "Failed to update status for hash {:?}",
                non_existent_hash
            )))
        );
    }

    #[test]
    fn confirm_tx_returns_error_when_an_error_occurs_while_executing_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "confirm_tx_returns_error_when_an_error_occurs_while_executing_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let hash = make_tx_hash(1);
        let hash_map = HashMap::from([(
            hash,
            TxBlock {
                block_hash: make_block_hash(1),
                block_number: U64::default(),
            },
        )]);

        let result = subject.confirm_txs(&hash_map);

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
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).build();
        let tx4 = TxBuilder::default().hash(make_tx_hash(4)).build();
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
        assert_eq!(remaining_records, BTreeSet::from([tx2, tx4]));
    }

    #[test]
    fn delete_records_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "delete_records_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.delete_records(&BTreeSet::new());

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
        let non_existent_hash = make_tx_hash(999);
        let hashset = BTreeSet::from([non_existent_hash]);

        let result = subject.delete_records(&hashset);

        assert_eq!(result, Err(SentPayableDaoError::NoChange));
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
        let present_hash = make_tx_hash(1);
        let absent_hash = make_tx_hash(2);
        let tx = TxBuilder::default().hash(present_hash).build();
        subject.insert_new_records(&BTreeSet::from([tx])).unwrap();
        let hashset = BTreeSet::from([present_hash, absent_hash]);

        let result = subject.delete_records(&hashset);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(
                "Only 1 of the 2 hashes has been deleted.".to_string()
            ))
        );
    }

    #[test]
    fn delete_records_returns_a_general_error_from_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "delete_records_returns_a_general_error_from_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let hashes = BTreeSet::from([make_tx_hash(1)]);

        let result = subject.delete_records(&hashes);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn update_statuses_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "update_statuses_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let timestamp_a = SystemTime::now().sub(Duration::from_millis(11));
        let timestamp_b = SystemTime::now().sub(Duration::from_millis(1234));
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let mut tx1 = make_sent_tx(456);
        tx1.status = TxStatus::Pending(ValidationStatus::Waiting);
        let mut tx2 = make_sent_tx(789);
        tx2.status = TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)),
            &ValidationFailureClockMock::default().now_result(timestamp_b),
        )));
        let mut tx3 = make_sent_tx(123);
        tx3.status = TxStatus::Pending(ValidationStatus::Waiting);
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone(), tx3.clone()]))
            .unwrap();
        let hashmap = HashMap::from([
            (
                tx1.hash,
                TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    &ValidationFailureClockMock::default().now_result(timestamp_a),
                ))),
            ),
            (
                tx2.hash,
                TxStatus::Pending(ValidationStatus::Reattempting(
                    PreviousAttempts::new(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                            RemoteErrorKind::Unreachable,
                        )),
                        &ValidationFailureClockMock::default().now_result(timestamp_b),
                    )
                    .add_attempt(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                            RemoteErrorKind::Unreachable,
                        )),
                        &ValidationFailureClockReal::default(),
                    ),
                )),
            ),
            (
                tx3.hash,
                TxStatus::Confirmed {
                    block_hash:
                        "0x0000000000000000000000000000000000000000000000000000000000000002"
                            .to_string(),
                    block_number: 123,
                    detection: Detection::Normal,
                },
            ),
        ]);

        let result = subject.update_statuses(&hashmap);

        let updated_txs: Vec<_> = subject.retrieve_txs(None).into_iter().collect();
        assert_eq!(result, Ok(()));
        assert_eq!(
            updated_txs[0].status,
            TxStatus::Pending(ValidationStatus::Reattempting(
                PreviousAttempts::new(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable
                    )),
                    &ValidationFailureClockMock::default().now_result(timestamp_b)
                )
                .add_attempt(
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable
                    )),
                    &ValidationFailureClockReal::default()
                )
            ))
        );
        assert_eq!(
            updated_txs[1].status,
            TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                &ValidationFailureClockMock::default().now_result(timestamp_a)
            )))
        );
        assert_eq!(
            updated_txs[2].status,
            TxStatus::Confirmed {
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000002"
                    .to_string(),
                block_number: 123,
                detection: Detection::Normal,
            }
        );
        assert_eq!(updated_txs.len(), 3)
    }

    #[test]
    fn update_statuses_handles_empty_input_error() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "update_statuses_handles_empty_input_error",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.update_statuses(&HashMap::new());

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn update_statuses_handles_sql_error() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "update_statuses_handles_sql_error",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.update_statuses(&HashMap::from([(
            make_tx_hash(1),
            TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)),
                &ValidationFailureClockReal::default(),
            ))),
        )]));

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        );
    }

    #[test]
    fn replace_records_works_as_expected() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "replace_records_works_as_expected",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).nonce(2).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).nonce(3).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2, tx3]))
            .unwrap();
        let new_tx2 = TxBuilder::default()
            .hash(make_tx_hash(22))
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(123)),
                block_number: 45454545,
                detection: Detection::Normal,
            })
            .nonce(2)
            .build();
        let new_tx3 = TxBuilder::default()
            .hash(make_tx_hash(33))
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(789)),
                block_number: 45454566,
                detection: Detection::Reclaim,
            })
            .nonce(3)
            .build();

        let result = subject.replace_records(&BTreeSet::from([new_tx2.clone(), new_tx3.clone()]));

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs, BTreeSet::from([tx1, new_tx2, new_tx3]));
    }

    #[test]
    fn replace_records_uses_single_sql_statement() {
        let prepare_params = Arc::new(Mutex::new(vec![]));
        let setup_conn = Connection::open_in_memory().unwrap();
        setup_conn
            .execute("CREATE TABLE example (id integer)", [])
            .unwrap();
        let stmt = setup_conn.prepare("SELECT id FROM example").unwrap();
        let wrapped_conn = ConnectionWrapperMock::default()
            .prepare_params(&prepare_params)
            .prepare_result(Ok(stmt));
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).nonce(2).build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).nonce(3).build();

        let _ = subject.replace_records(&BTreeSet::from([tx1, tx2, tx3]));

        let captured_params = prepare_params.lock().unwrap();
        let sql = &captured_params[0];
        assert!(sql.starts_with("UPDATE sent_payable SET"));
        assert!(sql.contains("tx_hash = CASE"));
        assert!(sql.contains("receiver_address = CASE"));
        assert!(sql.contains("amount_high_b = CASE"));
        assert!(sql.contains("amount_low_b = CASE"));
        assert!(sql.contains("timestamp = CASE"));
        assert!(sql.contains("gas_price_wei_high_b = CASE"));
        assert!(sql.contains("gas_price_wei_low_b = CASE"));
        assert!(sql.contains("status = CASE"));
        assert!(sql.contains("WHERE nonce IN (3, 2, 1)"));
        assert!(sql.contains("WHEN nonce = 1 THEN '0x0000000000000000000000000000000000000000000000000000000000000001'"));
        assert!(sql.contains("WHEN nonce = 2 THEN '0x0000000000000000000000000000000000000000000000000000000000000002'"));
        assert!(sql.contains("WHEN nonce = 3 THEN '0x0000000000000000000000000000000000000000000000000000000000000003'"));
        assert_eq!(captured_params.len(), 1);
    }

    #[test]
    fn replace_records_throws_error_for_empty_input() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "replace_records_throws_error_for_empty_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).nonce(2).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1, tx2]))
            .unwrap();

        let result = subject.replace_records(&BTreeSet::new());

        assert_eq!(result, Err(EmptyInput));
    }

    #[test]
    fn replace_records_throws_partial_execution_error() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "replace_records_throws_partial_execution_error",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).nonce(2).build();
        subject
            .insert_new_records(&BTreeSet::from([tx1.clone(), tx2.clone()]))
            .unwrap();
        let new_tx2 = TxBuilder::default()
            .hash(make_tx_hash(22))
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(77777)),
                block_number: 357913,
                detection: Detection::Normal,
            })
            .nonce(2)
            .build();
        let new_tx3 = TxBuilder::default()
            .hash(make_tx_hash(33))
            .status(TxStatus::Confirmed {
                block_hash: format!("{:?}", make_block_hash(66666)),
                block_number: 353535,
                detection: Detection::Reclaim,
            })
            .nonce(3)
            .build();

        let result = subject.replace_records(&BTreeSet::from([new_tx2, new_tx3]));

        assert_eq!(
            result,
            Err(PartialExecution(
                "Only 1 out of 2 records updated".to_string()
            ))
        );
    }

    #[test]
    fn replace_records_returns_no_change_error_when_no_rows_updated() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "replace_records_returns_no_change_error_when_no_rows_updated",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx = TxBuilder::default().hash(make_tx_hash(1)).nonce(42).build();

        let result = subject.replace_records(&BTreeSet::from([tx]));

        assert_eq!(result, Err(SentPayableDaoError::NoChange));
    }

    #[test]
    fn replace_records_returns_a_general_error_from_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "replace_records_returns_a_general_error_from_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let tx = TxBuilder::default().hash(make_tx_hash(1)).nonce(1).build();

        let result = subject.replace_records(&BTreeSet::from([tx]));

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn tx_status_from_str_works() {
        let validation_failure_clock = ValidationFailureClockMock::default()
            .now_result(UNIX_EPOCH.add(Duration::from_secs(12456)));

        assert_eq!(
            TxStatus::from_str(r#"{"Pending":"Waiting"}"#).unwrap(),
            TxStatus::Pending(ValidationStatus::Waiting)
        );

        assert_eq!(
            TxStatus::from_str(r#"{"Pending":{"Reattempting":[{"error":{"AppRpc":{"Remote":"InvalidResponse"}},"firstSeen":{"secs_since_epoch":12456,"nanos_since_epoch":0},"attempts":1}]}}"#).unwrap(),
            TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::InvalidResponse)), &validation_failure_clock)))
        );

        assert_eq!(
            TxStatus::from_str(r#"{"Confirmed":{"block_hash":"0xb4bc263299d3a82a652a8d73a6bfd8ec0ba1a63923bbb4f38147fb8a943da26a","block_number":456789,"detection":"Normal"}}"#).unwrap(),
            TxStatus::Confirmed{
                block_hash: "0xb4bc263299d3a82a652a8d73a6bfd8ec0ba1a63923bbb4f38147fb8a943da26a".to_string(),
                block_number: 456789,
                detection: Detection::Normal,
            }
        );

        assert_eq!(
            TxStatus::from_str(r#"{"Confirmed":{"block_hash":"0x6d0abc11e617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18","block_number":567890,"detection":"Reclaim"}}"#).unwrap(),
            TxStatus::Confirmed{
                    block_hash: "0x6d0abc11e617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18".to_string(),
                    block_number: 567890,
                    detection: Detection::Reclaim,
            }
        );

        // Invalid Variant
        assert_eq!(
            TxStatus::from_str("\"UnknownStatus\"").unwrap_err(),
            "unknown variant `UnknownStatus`, \
            expected `Pending` or `Confirmed` at line 1 column 15 in '\"UnknownStatus\"'"
        );

        // Invalid Input
        assert_eq!(
            TxStatus::from_str("not a failure status").unwrap_err(),
            "expected value at line 1 column 1 in 'not a failure status'"
        );
    }

    #[test]
    fn tx_status_can_be_made_from_transaction_block() {
        let tx_block = TxBlock {
            block_hash: make_block_hash(6),
            block_number: 456789_u64.into(),
        };

        assert_eq!(
            TxStatus::from(tx_block),
            TxStatus::Confirmed {
                block_hash: format!("{:?}", tx_block.block_hash),
                block_number: u64::try_from(tx_block.block_number).unwrap(),
                detection: Detection::Normal,
            }
        )
    }

    #[test]
    fn tx_ordering_works() {
        let tx1 = SentTx {
            hash: make_tx_hash(1),
            receiver_address: make_address(1),
            amount_minor: 100,
            timestamp: 1000,
            gas_price_minor: 10,
            nonce: 1,
            status: TxStatus::Pending(ValidationStatus::Waiting),
        };
        let tx2 = SentTx {
            hash: make_tx_hash(2),
            receiver_address: make_address(2),
            amount_minor: 200,
            timestamp: 1000,
            gas_price_minor: 20,
            nonce: 1,
            status: TxStatus::Pending(ValidationStatus::Waiting),
        };
        let tx3 = SentTx {
            hash: make_tx_hash(3),
            receiver_address: make_address(3),
            amount_minor: 100,
            timestamp: 2000,
            gas_price_minor: 30,
            nonce: 2,
            status: TxStatus::Pending(ValidationStatus::Waiting),
        };

        let mut set = BTreeSet::new();
        set.insert(tx1.clone());
        set.insert(tx2.clone());
        set.insert(tx3.clone());

        let expected_order = vec![tx3, tx2, tx1];
        assert_eq!(set.into_iter().collect::<Vec<_>>(), expected_order);
    }

    #[test]
    fn transaction_trait_methods_for_tx() {
        let hash = make_tx_hash(1);
        let receiver_address = make_address(1);
        let amount_minor = 1000;
        let timestamp = 1625247600;
        let gas_price_minor = 2000;
        let nonce = 42;
        let status = TxStatus::Pending(ValidationStatus::Waiting);

        let tx = SentTx {
            hash,
            receiver_address,
            amount_minor,
            timestamp,
            gas_price_minor,
            nonce,
            status,
        };

        assert_eq!(tx.receiver_address(), receiver_address);
        assert_eq!(tx.hash(), hash);
        assert_eq!(tx.amount(), amount_minor);
        assert_eq!(tx.timestamp(), timestamp);
        assert_eq!(tx.gas_price_wei(), gas_price_minor);
        assert_eq!(tx.nonce(), nonce);
        assert_eq!(tx.is_failed(), false);
    }
}
