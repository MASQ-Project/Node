// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::BlockchainResult;
use crate::sub_lib::wallet::Wallet;
use web3::types::U256;

pub trait RPCHelpers {
    fn get_transaction_fee_balance(&self, wallet: &Wallet) -> ResultForBalance;

    fn get_masq_balance(&self, wallet: &Wallet) -> ResultForBalance;

    fn get_transaction_id(&self, wallet: &Wallet) -> ResultForNonce;
}

pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<U256>;
