use std::collections::HashMap;
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
    InsertionFailed(String),
    // UpdateFailed(String),
    // SignConversionError(u64),
    // RecordCannotBeRead,
    // RecordDeletion(String),
    // ErrorMarkFailed(String),
}

type TxIdentifiers = HashMap<H256, u64>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    hash: H256,
    receiver_address: Address,
    amount: u128,
    timestamp: i64,
    gas_price_wei: u64,
    nonce: u32,
    status: TxStatus,
}

pub struct StatusChange {
    new_status: TxStatus,
}

pub enum RetrieveCondition {
    IsPending,
}

impl Display for RetrieveCondition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: GH-608: Test me separately
        match self {
            RetrieveCondition::IsPending => {
                write!(f, "where status in ('Pending')")
            }
        }
    }
}

pub trait SentPayableDao {
    // Note that the order of the returned results is not guaranteed
    fn get_tx_identifiers(&self, hashes: &[H256]) -> TxIdentifiers;
    fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> Vec<Tx>;
    fn retrieve_txs_to_retry(&self) -> Vec<Tx>;
    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError>;
    // TODO: GH-608: We might not need this
    fn delete_records(&self, ids: &[u64]) -> Result<(), SentPayableDaoError>;
    fn change_statuses(&self, ids: &[StatusChange]) -> Result<(), SentPayableDaoError>;
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
}

impl SentPayableDao for SentPayableDaoReal<'_> {
    fn get_tx_identifiers(&self, hashes: &[H256]) -> TxIdentifiers {
        let sql = format!(
            "select tx_hash, rowid from sent_payable where tx_hash in ({})",
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

    fn retrieve_txs(&self, condition_opt: Option<RetrieveCondition>) -> Vec<Tx> {
        let raw_sql = "select tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status from sent_payable"
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

    fn retrieve_txs_to_retry(&self) -> Vec<Tx> {
        todo!()
    }

    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError> {
        let sql = format!(
            "insert into sent_payable (\
            tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status, retried\
            ) values {}",
            comma_joined_stringifiable(&txs, |tx| {
                let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                let (high_bytes, low_bytes) = BigIntDivider::deconstruct(amount_checked);
                format!(
                    "('{:?}', '{:?}', {}, {}, {}, {}, {}, '{}', 0)",
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
            Ok(x) if x == txs.len() => Ok(()),
            Ok(x) => panic!("expected {} changed rows but got {}", txs.len(), x),
            Err(e) => Err(SentPayableDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_records(&self, ids: &[u64]) -> Result<(), SentPayableDaoError> {
        todo!()
    }

    fn change_statuses(&self, ids: &[StatusChange]) -> Result<(), SentPayableDaoError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::sent_payable_dao::{RetrieveCondition, SentPayableDao, SentPayableDaoError, SentPayableDaoReal, Tx};
    use crate::accountant::db_access_objects::utils::current_unix_timestamp;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::database::test_utils::ConnectionWrapperMock;
    use ethereum_types::{Address, H256};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock, TxStatus};

    #[derive(Default)]
    pub struct TxBuilder {
        hash_opt: Option<H256>,
        receiver_address_opt: Option<Address>,
        amount_opt: Option<u128>,
        timestamp_opt: Option<i64>,
        gas_price_wei_opt: Option<u64>,
        nonce_opt: Option<u32>,
        status_opt: Option<TxStatus>,
    }

    impl TxBuilder {
        pub fn default() -> Self {
            Default::default()
        }

        pub fn hash(mut self, hash: H256) -> Self {
            self.hash_opt = Some(hash);
            self
        }

        pub fn receiver_address(mut self, receiver_address: Address) -> Self {
            self.receiver_address_opt = Some(receiver_address);
            self
        }

        pub fn amount(mut self, amount: u128) -> Self {
            self.amount_opt = Some(amount);
            self
        }

        pub fn timestamp(mut self, timestamp: i64) -> Self {
            self.timestamp_opt = Some(timestamp);
            self
        }

        pub fn gas_price_wei(mut self, gas_price_wei: u64) -> Self {
            self.gas_price_wei_opt = Some(gas_price_wei);
            self
        }

        pub fn nonce(mut self, nonce: u32) -> Self {
            self.nonce_opt = Some(nonce);
            self
        }

        pub fn status(mut self, status: TxStatus) -> Self {
            self.status_opt = Some(status);
            self
        }

        pub fn build(self) -> Tx {
            Tx {
                hash: self.hash_opt.unwrap_or_default(),
                receiver_address: self.receiver_address_opt.unwrap_or_default(),
                amount: self.amount_opt.unwrap_or_default(),
                timestamp: self.timestamp_opt.unwrap_or_else(current_unix_timestamp),
                gas_price_wei: self.gas_price_wei_opt.unwrap_or_default(),
                nonce: self.nonce_opt.unwrap_or_default(),
                status: self.status_opt.unwrap_or(TxStatus::Pending),
            }
        }
    }

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
            Err(SentPayableDaoError::InsertionFailed(
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
            Err(SentPayableDaoError::InsertionFailed(
                "UNIQUE constraint failed: sent_payable.tx_hash".to_string()
            ))
        );
    }

    #[test]
    #[should_panic(expected = "expected 1 changed rows but got 0")]
    fn insert_new_records_can_panic() {
        let setup_conn = Connection::open_in_memory().unwrap();
        // Inject a deliberately failing statement into the mocked connection.
        let failing_stmt = {
            setup_conn
                .execute("create table example (id integer)", [])
                .unwrap();
            setup_conn.prepare("select id from example").unwrap()
        };
        let wrapped_conn = ConnectionWrapperMock::default().prepare_result(Ok(failing_stmt));
        let tx = TxBuilder::default().build();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let _ = subject.insert_new_records(vec![tx]);
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
            Err(SentPayableDaoError::InsertionFailed(
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
    fn retrieve_pending_txs_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "retrieve_pending_txs_works");
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
}
