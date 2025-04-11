use std::time::SystemTime;
use ethereum_types::H256;
use web3::types::Address;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxStatus;

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    // InsertionFailed(String),
    // UpdateFailed(String),
    // SignConversionError(u64),
    // RecordCannotBeRead,
    // RecordDeletion(String),
    // ErrorMarkFailed(String),
}

#[derive(Debug)]
pub struct TxIdentifiers {
    // pub rowid_results: Vec<(u64, H256)>,
    // pub no_rowid_results: Vec<H256>,
}

pub struct Tx {
    // GH-608: Perhaps TxReceipt could be a similar structure to be used
    receiver_address: Address,
    amount: u128,
    tx_hash: String,
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
