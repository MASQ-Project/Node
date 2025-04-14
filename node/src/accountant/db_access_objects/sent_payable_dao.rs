use std::collections::HashMap;
use std::time::SystemTime;
use ethereum_types::H256;
use web3::types::Address;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDaoError;
use crate::accountant::db_access_objects::utils::to_time_t;
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

type TxIdentifiers = HashMap<H256, Option<u64>>;

pub struct Tx {
    // GH-608: Perhaps TxReceipt could be a similar structure to be used
    hash: H256,
    receiver_address: Address,
    amount: u128,
    timestamp: SystemTime,
    gas_price_wei: u64,
    nonce: u32,
}

pub struct StatusChange {
    new_status: TxStatus,
}

pub trait SentPayableDao {
    // Note that the order of the returned results is not guaranteed
    fn get_tx_identifiers(&self, hashes: &[H256]) -> TxIdentifiers;
    fn retrieve_pending_txs(&self) -> Vec<Tx>;
    fn retrieve_txs_to_retry(&self) -> Vec<Tx>;
    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError>;
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
        todo!()
    }

    fn retrieve_pending_txs(&self) -> Vec<Tx> {
        todo!()
    }

    fn retrieve_txs_to_retry(&self) -> Vec<Tx> {
        todo!()
    }

    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError> {
        fn generate_values(txs: &[Tx]) -> String {
            comma_joined_stringifiable(txs, |tx| {
                let amount_checked = checked_conversion::<u128, i128>(tx.amount);
                let (high_bytes, low_bytes) = BigIntDivider::deconstruct(amount_checked);
                format!(
                    "('{:?}', '{:?}', {}, {}, {}, {}, {}, 'Pending', 0)",
                    tx.hash,
                    tx.receiver_address,
                    high_bytes,
                    low_bytes,
                    to_time_t(tx.timestamp),
                    tx.gas_price_wei,
                    tx.nonce,
                )
            })
        }

        let sql = format!(
            "insert into sent_payable (\
            tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status, retried\
            ) values {}",
            generate_values(&txs)
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
    use crate::accountant::db_access_objects::sent_payable_dao::{
        SentPayableDao, SentPayableDaoReal, Tx,
    };
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use std::time::SystemTime;

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx = Tx {
            hash: Default::default(),
            receiver_address: Default::default(),
            amount: 0,
            timestamp: SystemTime::now(),
            gas_price_wei: 0,
            nonce: 0,
        };
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(vec![tx]);

        let row_count: i64 = {
            let mut stmt = subject
                .conn
                .prepare("SELECT COUNT(*) FROM sent_payable")
                .unwrap();
            stmt.query_row([], |row| row.get(0)).unwrap()
        };
        assert_eq!(result, Ok(()));
        assert_eq!(row_count, 1);
    }

    #[test]
    fn get_tx_identifiers_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "get_tx_identifiers_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        todo!("first you'll have to write tests for the insertion method");
    }
}
