// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;

use crate::accountant::db_access_objects::payable_dao::PendingPayable;
use crate::sub_lib::wallet::Wallet;
use std::fmt;
use std::fmt::Formatter;
use web3::types::H256;
use web3::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockchainTransaction {
    pub block_number: u64,
    pub from: Wallet,
    pub wei_amount: u128,
}

impl fmt::Display for BlockchainTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}gw from {} ({})",
            self.wei_amount, self.from, self.block_number
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievedBlockchainTransactions {
    pub new_start_block: u64,
    pub transactions: Vec<BlockchainTransaction>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProcessedPayableFallible {
    Correct(PendingPayable),
    Failed(RpcPayablesFailure),
}

#[derive(Debug, PartialEq, Clone)]
pub struct RpcPayablesFailure {
    pub rpc_error: Error,
    pub recipient_wallet: Wallet,
    pub hash: H256,
}
