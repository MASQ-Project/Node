// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use ethereum_types::{H256, U64};
use web3::types::Address;
use masq_lib::utils::ExpectValue;
use crate::accountant::{checked_conversion, join_with_separator};
use crate::accountant::db_access_objects::utils::{DaoFactoryReal, TxHash, TxIdentifiers};
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock};
use crate::database::rusqlite_wrappers::ConnectionWrapper;
use itertools::Itertools;
use crate::accountant::db_access_objects::failed_payable_dao::{FailedPayableDao, FailedPayableDaoReal};

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    EmptyInput,
    NoChange,
    InvalidInput(String),
    PartialExecution(String),
    SqlExecutionFailed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub hash: TxHash,
    pub receiver_address: Address,
    pub amount: u128,
    pub timestamp: i64,
    pub gas_price_wei: u128,
    pub nonce: u64,
    pub block_opt: Option<TransactionBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetrieveCondition {
    IsPending,
    ByHash(HashSet<TxHash>), // TODO: GH-605: Want to implement lifetime here?
}

impl Display for RetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RetrieveCondition::IsPending => {
                write!(f, "WHERE block_hash IS NULL")
            }
            RetrieveCondition::ByHash(tx_hashes) => {
                write!(
                    f,
                    "WHERE tx_hash IN ({})",
                    join_with_separator(tx_hashes, |hash| format!("'{:?}'", hash), ", ")
                )
            }
        }
    }
}

pub trait SentPayableDao {
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers;
    fn insert_new_records(&self, txs: &[Tx]) -> Result<(), SentPayableDaoError>;
    fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> Vec<Tx>; // TODO: GH-605: Turn it into HashSet
    fn update_tx_blocks(
        &self,
        hash_map: &HashMap<TxHash, TransactionBlock>,
    ) -> Result<(), SentPayableDaoError>;
    fn replace_records(&self, new_txs: &[Tx]) -> Result<(), SentPayableDaoError>;
    fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), SentPayableDaoError>;
}

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
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers {
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

    fn insert_new_records(&self, txs: &[Tx]) -> Result<(), SentPayableDaoError> {
        if txs.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let unique_hashes: HashSet<TxHash> = txs.iter().map(|tx| tx.hash).collect();
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
             block_hash, \
             block_number
             ) VALUES {}",
            join_with_separator(
                txs,
                |tx| {
                    let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                    let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_wei);
                    let (amount_high_b, amount_low_b) = BigIntDivider::deconstruct(amount_checked);
                    let (gas_price_wei_high_b, gas_price_wei_low_b) =
                        BigIntDivider::deconstruct(gas_price_wei_checked);
                    let block_details = match &tx.block_opt {
                        Some(block) => format!("'{:?}', {}", block.block_hash, block.block_number),
                        None => "null, null".to_string(),
                    };
                    format!(
                        "('{:?}', '{:?}', {}, {}, {}, {}, {}, {}, {})",
                        tx.hash,
                        tx.receiver_address,
                        amount_high_b,
                        amount_low_b,
                        tx.timestamp,
                        gas_price_wei_high_b,
                        gas_price_wei_low_b,
                        tx.nonce,
                        block_details
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
            timestamp, gas_price_wei_high_b, gas_price_wei_low_b, nonce, block_hash, block_number FROM sent_payable"
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
            let amount = BigIntDivider::reconstitute(amount_high_b, amount_low_b) as u128;
            let timestamp = row.get(4).expectv("timestamp");
            let gas_price_wei_high_b = row.get(5).expectv("gas_price_wei_high_b");
            let gas_price_wei_low_b = row.get(6).expectv("gas_price_wei_low_b");
            let gas_price_wei =
                BigIntDivider::reconstitute(gas_price_wei_high_b, gas_price_wei_low_b) as u128;
            let nonce = row.get(7).expectv("nonce");
            let block_hash_opt: Option<H256> = {
                let block_hash_str_opt: Option<String> = row.get(8).expectv("block_hash");
                block_hash_str_opt
                    .map(|string| H256::from_str(&string[2..]).expect("Failed to parse H256"))
            };
            let block_number_opt: Option<u64> = {
                let block_number_i64_opt: Option<i64> = row.get(9).expectv("block_number");
                block_number_i64_opt.map(|v| u64::try_from(v).expect("Failed to parse u64"))
            };

            let block_opt = match (block_hash_opt, block_number_opt) {
                (Some(block_hash), Some(block_number)) => Some(TransactionBlock {
                    block_hash,
                    block_number: U64::from(block_number),
                }),
                (None, None) => None,
                _ => panic!("Invalid block details"),
            };

            Ok(Tx {
                hash,
                receiver_address,
                amount,
                timestamp,
                gas_price_wei,
                nonce,
                block_opt,
            })
        })
        .expect("Failed to execute query")
        .filter_map(Result::ok)
        .collect()
    }

    fn update_tx_blocks(
        &self,
        hash_map: &HashMap<TxHash, TransactionBlock>,
    ) -> Result<(), SentPayableDaoError> {
        if hash_map.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        for (hash, transaction_block) in hash_map {
            let sql = format!(
                "UPDATE sent_payable SET block_hash = '{:?}', block_number = {} WHERE tx_hash = '{:?}'",
                transaction_block.block_hash, transaction_block.block_number, hash
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

    fn replace_records(&self, new_txs: &[Tx]) -> Result<(), SentPayableDaoError> {
        if new_txs.is_empty() {
            return Err(SentPayableDaoError::EmptyInput);
        }

        let build_case = |value_fn: fn(&Tx) -> String| {
            join_with_separator(
                new_txs,
                |tx| format!("WHEN nonce = {} THEN {}", tx.nonce, value_fn(tx)),
                " ",
            )
        };

        let tx_hash_cases = build_case(|tx| format!("'{:?}'", tx.hash));
        let receiver_address_cases = build_case(|tx| format!("'{:?}'", tx.receiver_address));
        let amount_high_b_cases = build_case(|tx| {
            let amount_checked = checked_conversion::<u128, i128>(tx.amount);
            let (high, _) = BigIntDivider::deconstruct(amount_checked);
            high.to_string()
        });
        let amount_low_b_cases = build_case(|tx| {
            let amount_checked = checked_conversion::<u128, i128>(tx.amount);
            let (_, low) = BigIntDivider::deconstruct(amount_checked);
            low.to_string()
        });
        let timestamp_cases = build_case(|tx| tx.timestamp.to_string());
        let gas_price_wei_high_b_cases = build_case(|tx| {
            let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_wei);
            let (high, _) = BigIntDivider::deconstruct(gas_price_wei_checked);
            high.to_string()
        });
        let gas_price_wei_low_b_cases = build_case(|tx| {
            let gas_price_wei_checked = checked_conversion::<u128, i128>(tx.gas_price_wei);
            let (_, low) = BigIntDivider::deconstruct(gas_price_wei_checked);
            low.to_string()
        });
        let block_hash_cases = build_case(|tx| match &tx.block_opt {
            Some(block) => format!("'{:?}'", block.block_hash),
            None => "NULL".to_string(),
        });
        let block_number_cases = build_case(|tx| match &tx.block_opt {
            Some(block) => block.block_number.as_u64().to_string(),
            None => "NULL".to_string(),
        });

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
                block_hash = CASE \
                    {block_hash_cases} \
                END, \
                block_number = CASE \
                    {block_number_cases} \
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

    fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), SentPayableDaoError> {
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
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use crate::accountant::db_access_objects::sent_payable_dao::{RetrieveCondition, SentPayableDao, SentPayableDaoError, SentPayableDaoReal};
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use crate::database::test_utils::ConnectionWrapperMock;
    use ethereum_types::{ H256, U64};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection};
    use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::{ByHash, IsPending};
    use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoError::{EmptyInput, PartialExecution};
    use crate::accountant::db_access_objects::test_utils::{make_read_only_db_connection, TxBuilder};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock};
    use crate::blockchain::test_utils::{make_block_hash, make_tx_hash};

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
            .block(Default::default())
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
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
            "sent_payable_dao",
            "insert_new_records_throws_err_for_empty_input",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let empty_input = vec![];

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
            .build();
        let tx2 = TxBuilder::default()
            .hash(hash)
            .timestamp(1749204020)
            .block(Default::default())
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(&vec![tx1, tx2]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::InvalidInput(
                "Duplicate hashes found in the input. Input Transactions: \
                [Tx { \
                hash: 0x00000000000000000000000000000000000000000000000000000000000004d2, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount: 0, timestamp: 1749204017, gas_price_wei: 0, \
                nonce: 0, block_opt: None }, \
                Tx { \
                hash: 0x00000000000000000000000000000000000000000000000000000000000004d2, \
                receiver_address: 0x0000000000000000000000000000000000000000, \
                amount: 0, timestamp: 1749204020, gas_price_wei: 0, \
                nonce: 0, block_opt: Some(TransactionBlock { \
                block_hash: 0x0000000000000000000000000000000000000000000000000000000000000000, \
                block_number: 0 }) }]"
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
        let tx2 = TxBuilder::default()
            .hash(hash)
            .block(Default::default())
            .build();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let initial_insertion_result = subject.insert_new_records(&vec![tx1]);

        let result = subject.insert_new_records(&vec![tx2]);

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

        let result = subject.insert_new_records(&vec![tx]);

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

        let result = subject.insert_new_records(&vec![tx]);

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
        let hashset = HashSet::from([present_hash, absent_hash, another_present_hash]);
        let present_tx = TxBuilder::default().hash(present_hash).build();
        let another_present_tx = TxBuilder::default().hash(another_present_hash).build();
        subject
            .insert_new_records(&vec![present_tx, another_present_tx])
            .unwrap();

        let result = subject.get_tx_identifiers(&hashset);

        assert_eq!(result.get(&present_hash), Some(&1u64));
        assert_eq!(result.get(&absent_hash), None);
        assert_eq!(result.get(&another_present_hash), Some(&2u64));
    }

    #[test]
    fn retrieve_condition_display_works() {
        assert_eq!(IsPending.to_string(), "WHERE block_hash IS NULL");
        assert_eq!(
            ByHash(HashSet::from([
                H256::from_low_u64_be(0x123456789),
                H256::from_low_u64_be(0x987654321),
            ]))
            .to_string(),
            "WHERE tx_hash IN (\
            '0x0000000000000000000000000000000000000000000000000000000123456789', \
            '0x0000000000000000000000000000000000000000000000000000000987654321'\
            )"
            .to_string()
        );
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
        let tx2 = TxBuilder::default()
            .hash(make_tx_hash(2))
            .block(Default::default())
            .build();
        let tx3 = TxBuilder::default().hash(make_tx_hash(3)).build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone()])
            .unwrap();
        subject.insert_new_records(&vec![tx3.clone()]).unwrap();

        let result = subject.retrieve_txs(None);

        assert_eq!(result, vec![tx1, tx2, tx3]);
    }

    #[test]
    fn can_retrieve_pending_txs() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "can_retrieve_pending_txs");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let tx3 = TxBuilder::default()
            .hash(make_tx_hash(3))
            .block(Default::default())
            .build();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone(), tx3])
            .unwrap();

        let result = subject.retrieve_txs(Some(RetrieveCondition::IsPending));

        assert_eq!(result, vec![tx1, tx2]);
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
            .insert_new_records(&vec![tx1.clone(), tx2, tx3.clone()])
            .unwrap();

        let result = subject.retrieve_txs(Some(ByHash(HashSet::from([tx1.hash, tx3.hash]))));

        assert_eq!(result, vec![tx1, tx3]);
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
            .insert_new_records(&[tx1.clone(), tx2.clone(), tx3.clone()])
            .unwrap();
        let mut query_hashes = HashSet::new();
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
    #[should_panic(expected = "Invalid block details")]
    fn retrieve_txs_enforces_complete_block_details() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "retrieve_txs_enforces_complete_block_details",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        // Insert a record with block_hash but no block_number
        {
            let sql = "INSERT INTO sent_payable (\
            tx_hash, \
            receiver_address, \
            amount_high_b, \
            amount_low_b, \
            timestamp, \
            gas_price_wei_high_b, \
            gas_price_wei_low_b, \
            nonce, \
            block_hash, \
            block_number\
            )
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
            let mut stmt = wrapped_conn.prepare(sql).unwrap();
            stmt.execute(rusqlite::params![
                "0x1234567890123456789012345678901234567890123456789012345678901234",
                "0x1234567890123456789012345678901234567890",
                0,
                100,
                1234567890,
                0,
                1000000000,
                1,
                "0x2345678901234567890123456789012345678901234567890123456789012345",
                rusqlite::types::Null,
            ])
            .unwrap();
        }
        let subject = SentPayableDaoReal::new(wrapped_conn);

        // This should panic due to invalid block details
        let _ = subject.retrieve_txs(None);
    }

    #[test]
    fn update_tx_blocks_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "update_tx_blocks_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let pre_assert_is_block_details_present_tx1 = tx1.block_opt.is_some();
        let pre_assert_is_block_details_present_tx2 = tx2.block_opt.is_some();
        subject
            .insert_new_records(&vec![tx1.clone(), tx2.clone()])
            .unwrap();
        let tx_block_1 = TransactionBlock {
            block_hash: make_block_hash(3),
            block_number: U64::from(1),
        };
        let tx_block_2 = TransactionBlock {
            block_hash: make_block_hash(4),
            block_number: U64::from(2),
        };
        let hash_map = HashMap::from([
            (tx1.hash, tx_block_1.clone()),
            (tx2.hash, tx_block_2.clone()),
        ]);

        let result = subject.update_tx_blocks(&hash_map);

        let updated_txs = subject.retrieve_txs(Some(ByHash(HashSet::from([tx1.hash, tx2.hash]))));
        assert_eq!(result, Ok(()));
        assert_eq!(pre_assert_is_block_details_present_tx1, false);
        assert_eq!(updated_txs[0].block_opt, Some(tx_block_1));
        assert_eq!(pre_assert_is_block_details_present_tx2, false);
        assert_eq!(updated_txs[1].block_opt, Some(tx_block_2));
    }

    #[test]
    fn update_tx_blocks_returns_error_when_input_is_empty() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "update_tx_blocks_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let tx = TxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&vec![tx]).unwrap();
        let hash_map = HashMap::new();

        let result = subject.update_tx_blocks(&hash_map);

        assert_eq!(result, Err(SentPayableDaoError::EmptyInput));
    }

    #[test]
    fn update_tx_blocks_returns_error_during_partial_execution() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "update_tx_blocks_returns_error_during_partial_execution",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);
        let existent_hash = make_tx_hash(1);
        let non_existent_hash = make_tx_hash(999);
        let tx = TxBuilder::default().hash(existent_hash).build();
        subject.insert_new_records(&vec![tx]).unwrap();
        let hash_map = HashMap::from([
            (
                existent_hash,
                TransactionBlock {
                    block_hash: make_block_hash(1),
                    block_number: U64::from(1),
                },
            ),
            (
                non_existent_hash,
                TransactionBlock {
                    block_hash: make_block_hash(2),
                    block_number: U64::from(2),
                },
            ),
        ]);

        let result = subject.update_tx_blocks(&hash_map);

        assert_eq!(
            result,
            Err(SentPayableDaoError::PartialExecution(format!(
                "Failed to update status for hash {:?}",
                non_existent_hash
            )))
        );
    }

    #[test]
    fn update_tx_blocks_returns_error_when_an_error_occurs_while_executing_sql() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "update_tx_blocks_returns_error_when_an_error_occurs_while_executing_sql",
        );
        let wrapped_conn = make_read_only_db_connection(home_dir);
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));
        let hash = make_tx_hash(1);
        let hash_map = HashMap::from([(
            hash,
            TransactionBlock {
                block_hash: make_block_hash(1),
                block_number: U64::default(),
            },
        )]);

        let result = subject.update_tx_blocks(&hash_map);

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
        let tx4 = TxBuilder::default()
            .hash(make_tx_hash(4))
            .block(Default::default())
            .build();
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
            "sent_payable_dao",
            "delete_records_returns_error_when_input_is_empty",
        );
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.delete_records(&HashSet::new());

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
        let hashset = HashSet::from([non_existent_hash]);

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
        subject.insert_new_records(&vec![tx]).unwrap();
        let hashset = HashSet::from([present_hash, absent_hash]);

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
        let hashes = HashSet::from([make_tx_hash(1)]);

        let result = subject.delete_records(&hashes);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
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
            .insert_new_records(&vec![tx1.clone(), tx2, tx3])
            .unwrap();
        let new_tx2 = TxBuilder::default()
            .hash(make_tx_hash(22))
            .block(TransactionBlock {
                block_hash: make_block_hash(1),
                block_number: U64::from(1),
            })
            .nonce(2)
            .build();
        let new_tx3 = TxBuilder::default()
            .hash(make_tx_hash(33))
            .block(TransactionBlock {
                block_hash: make_block_hash(1),
                block_number: U64::from(1),
            })
            .nonce(3)
            .build();

        let result = subject.replace_records(&[new_tx2.clone(), new_tx3.clone()]);

        let retrieved_txs = subject.retrieve_txs(None);
        assert_eq!(result, Ok(()));
        assert_eq!(retrieved_txs, vec![tx1, new_tx2, new_tx3]);
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

        let _ = subject.replace_records(&[tx1, tx2, tx3]);

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
        assert!(sql.contains("block_hash = CASE"));
        assert!(sql.contains("block_number = CASE"));
        assert!(sql.contains("WHERE nonce IN (1, 2, 3)"));
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
        subject.insert_new_records(&vec![tx1, tx2]).unwrap();

        let result = subject.replace_records(&[]);

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
            .insert_new_records(&vec![tx1.clone(), tx2.clone()])
            .unwrap();
        let new_tx2 = TxBuilder::default()
            .hash(make_tx_hash(22))
            .block(TransactionBlock {
                block_hash: make_block_hash(1),
                block_number: U64::from(1),
            })
            .nonce(2)
            .build();
        let new_tx3 = TxBuilder::default()
            .hash(make_tx_hash(33))
            .block(TransactionBlock {
                block_hash: make_block_hash(1),
                block_number: U64::from(1),
            })
            .nonce(3)
            .build();

        let result = subject.replace_records(&[new_tx2, new_tx3]);

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

        let result = subject.replace_records(&[tx]);

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

        let result = subject.replace_records(&[tx]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::SqlExecutionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }
}
