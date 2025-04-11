use std::collections::HashMap;
use std::time::SystemTime;
use ethereum_types::H256;
use web3::types::Address;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxStatus;
use crate::database::rusqlite_wrappers::ConnectionWrapper;

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    // InsertionFailed(String),
    // UpdateFailed(String),
    // SignConversionError(u64),
    // RecordCannotBeRead,
    // RecordDeletion(String),
    // ErrorMarkFailed(String),
}

type TxIdentifiers = HashMap<H256, Option<u64>>;

pub struct Tx {
    // GH-608: Perhaps TxReceipt could be a similar structure to be used
    tx_hash: String,
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
        // TODO: GH-608: Figure out how to test this guy
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
        todo!()
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
    use crate::accountant::db_access_objects::pending_payable_dao::{
        PendingPayableDao, PendingPayableDaoReal,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{
        SentPayableDao, SentPayableDaoReal, Tx,
    };
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        // let tx = Tx {
        //     tx_hash: "".to_string(),
        //     receiver_address: Default::default(),
        //     amount: 0,
        //     timestamp: (),
        //     gas_price_wei: 0,
        //     nonce: 0,
        // };
        let subject = SentPayableDaoReal::new(wrapped_conn);

        // let _ = subject.insert_new_records()
        todo!("finish me first");
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
