// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_web3;
pub mod data_structures;
pub mod lower_level_interface;

use actix::Recipient;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainAgentBuildError, BlockchainError, PayableTransactionError};
use crate::blockchain::blockchain_interface::data_structures::{ProcessedPayableFallible, RetrievedBlockchainTransactions};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::sub_lib::wallet::Wallet;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use web3::types::Address;
use masq_lib::logger::Logger;
use crate::accountant::scanners::payable_scanner_extension::msgs::{PricedQualifiedPayables};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
use crate::accountant::scanners::scanners_utils::pending_payable_scanner_utils::TxHashByTable;
use crate::blockchain::blockchain_bridge::{BlockMarker, BlockScanRange, RegisterNewPendingPayables};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxReceiptResult;

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn get_chain(&self) -> Chain;

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt>;

    fn retrieve_transactions(
        &self,
        start_block: BlockMarker,
        scan_range: BlockScanRange,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>>;

    fn introduce_blockchain_agent(
        &self,
        consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>>;

    fn process_transaction_receipts(
        &self,
        tx_hashes: Vec<TxHashByTable>,
    ) -> Box<dyn Future<Item = Vec<TxReceiptResult>, Error = BlockchainError>>;

    fn submit_payables_in_batch(
        &self,
        logger: Logger,
        agent: Box<dyn BlockchainAgent>,
        new_pending_payables_recipient: Recipient<RegisterNewPendingPayables>,
        affordable_accounts: PricedQualifiedPayables,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>;

    as_any_ref_in_trait!();
}
