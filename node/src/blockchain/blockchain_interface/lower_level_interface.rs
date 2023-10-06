// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainResult;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::U64;
use web3::types::U256;

pub trait LowerBCI {
    fn get_transaction_fee_balance(&self, wallet: &Wallet) -> ResultForBalance;

    // This is currently exclusive to the MASQ token but a more general naming might
    // be needed for an architecture including also widely established public chains
    // without a project-specific application layer on top of it
    fn get_service_fee_balance(&self, wallet: &Wallet) -> ResultForBalance;

    fn get_block_number(&self) -> LatestBlockNumber;

    fn get_transaction_id(&self, wallet: &Wallet) -> ResultForNonce;
}

pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<U256>;
pub type LatestBlockNumber = BlockchainResult<U64>;
