// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;

use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::pending_payable_scanner::utils::TxHashByTable;
use crate::accountant::PendingPayable;
use crate::blockchain::blockchain_bridge::BlockMarker;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::U64;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
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
    pub hash: TxHash,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProcessedPayableFallible {
    Correct(PendingPayable),
    Failed(RpcPayableFailure),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RetrievedTxStatus {
    pub tx_hash: TxHashByTable,
    pub status: StatusReadFromReceiptCheck,
}

impl RetrievedTxStatus {
    pub fn new(tx_hash: TxHashByTable, status: StatusReadFromReceiptCheck) -> Self {
        Self { tx_hash, status }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StatusReadFromReceiptCheck {
    Reverted,
    Succeeded(TxBlock),
    Pending,
}

impl Display for StatusReadFromReceiptCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusReadFromReceiptCheck::Reverted => {
                write!(f, "Reverted")
            }
            StatusReadFromReceiptCheck::Succeeded(block) => {
                write!(
                    f,
                    "Succeeded({},{:?})",
                    block.block_number, block.block_hash
                )
            }
            StatusReadFromReceiptCheck::Pending => write!(f, "Pending"),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TxBlock {
    pub block_hash: H256,
    pub block_number: U64,
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::data_structures::{
        StatusReadFromReceiptCheck, TxBlock,
    };
    use ethereum_types::{H256, U64};

    #[test]
    fn tx_status_display_works() {
        // Test Failed
        assert_eq!(StatusReadFromReceiptCheck::Reverted.to_string(), "Reverted");

        // Test Pending
        assert_eq!(StatusReadFromReceiptCheck::Pending.to_string(), "Pending");

        // Test Succeeded
        let block_number = U64::from(12345);
        let block_hash = H256::from_low_u64_be(0xabcdef);
        let succeeded = StatusReadFromReceiptCheck::Succeeded(TxBlock {
            block_hash,
            block_number,
        });
        assert_eq!(
            succeeded.to_string(),
            format!("Succeeded({},0x{:x})", block_number, block_hash)
        );
    }
}
