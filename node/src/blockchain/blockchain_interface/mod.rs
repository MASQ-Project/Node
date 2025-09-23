// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_web3;
pub mod data_structures;
pub mod lower_level_interface;

use actix::Recipient;
use ethereum_types::H256;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainAgentBuildError, BlockchainInterfaceError, PayableTransactionError};
use crate::blockchain::blockchain_interface::data_structures::{ProcessedPayableFallible, RetrievedBlockchainTransactions};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::Future;
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use crate::accountant::scanners::payable_scanner_extension::msgs::{PricedQualifiedPayables};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::{BlockMarker, BlockScanRange, PendingPayableFingerprintSeeds};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn get_chain(&self) -> Chain;

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt>;

    fn retrieve_transactions(
        &self,
        start_block: BlockMarker,
        scan_range: BlockScanRange,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainInterfaceError>>;

    fn introduce_blockchain_agent(
        &self,
        consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>>;

    fn process_transaction_receipts(
        &self,
        tx_hashes: Vec<TxHashByTable>,
    ) -> Box<
        dyn Future<
            Item = HashMap<TxHashByTable, TxReceiptResult>,
            Error = BlockchainInterfaceError,
        >,
    >;

    fn submit_payables_in_batch(
        &self,
        logger: Logger,
        agent: Box<dyn BlockchainAgent>,
        priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    ) -> Box<dyn Future<Item = BatchResults, Error = LocalPayableError>>;

    as_any_ref_in_trait!();
}
