// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;

use crate::blockchain::blockchain_bridge::BlockMarker;
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
            "{}wei from {} ({})",
            self.wei_amount, self.from, self.block_number
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievedBlockchainTransactions {
    pub new_start_block: BlockMarker,
    pub transactions: Vec<BlockchainTransaction>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RpcPayableFailure {
    pub rpc_error: Error,
    pub recipient_wallet: Wallet,
    pub hash: H256,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProcessedPayableFallible {
    Correct(PendingPayable),
    Failed(RpcPayableFailure),
}
