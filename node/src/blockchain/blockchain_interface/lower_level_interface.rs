// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainError, BlockchainResult};
use crate::sub_lib::wallet::Wallet;
use ethereum_types::{H256, U64};
use futures::Future;
use web3::types::{Address, TransactionReceipt, U256};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;

pub trait LowBlockchainInt {
    fn get_transaction_fee_balance(&self, address: Address) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_service_fee_balance(&self, address: Address) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>>;

    fn get_transaction_id(&self, address: Address) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_transaction_receipt(&self, hash: H256) -> Box<dyn Future<Item = Option<TransactionReceipt>, Error = BlockchainError>>;

    fn get_transaction_receipt_batch(&self, hash_vec: Vec<H256>) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>>;

    // fn dup(&self) -> Box<dyn LowBlockchainInt>;
}

pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<U256>;
pub type LatestBlockNumber = BlockchainResult<U64>;
