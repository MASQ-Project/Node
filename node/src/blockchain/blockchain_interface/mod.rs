// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_null;
pub mod blockchain_interface_web3;
pub mod data_structures;
pub mod lower_level_interface;
pub mod test_utils;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainAgentBuildError, BlockchainError, PayableTransactionError, ResultForReceipt,
};
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, RetrievedBlockchainTransactions,
};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use web3::types::{Address, BlockNumber, H256};

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError>;

    fn build_blockchain_agent(
        &self,
        consuming_wallet: &Wallet,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError>;

    fn send_batch_of_payables(
        &self,
        agent: Box<dyn BlockchainAgent>,
        new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError>;

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt;

    fn lower_interface(&self) -> &dyn LowBlockchainInt;

    as_any_ref_in_trait!();
}
