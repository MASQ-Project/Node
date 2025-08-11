// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;

use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::sent_payable_dao::Tx;
use crate::blockchain::blockchain_bridge::BlockMarker;
use crate::sub_lib::wallet::Wallet;
use std::fmt;
use std::fmt::Formatter;

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

#[derive(Default, Debug, PartialEq, Clone)]
pub struct BatchResults {
    pub sent_txs: Vec<Tx>,
    pub failed_txs: Vec<FailedTx>,
}
