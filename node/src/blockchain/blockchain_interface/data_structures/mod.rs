// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod errors;

use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::pending_payable_scanner::utils::TxHashByTable;
use crate::accountant::PendingPayable;
use crate::blockchain::blockchain_bridge::BlockMarker;
use crate::blockchain::errors::rpc_errors::AppRpcError;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use ethereum_types::U64;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use variant_count::VariantCount;
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

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct TxReceiptResult(pub Result<RetrievedTxStatus, TxReceiptError>);

impl TxReceiptResult {
    pub fn hash(&self) -> TxHashByTable {
        match &self.0 {
            Ok(retrieved_tx_status) => retrieved_tx_status.tx_hash,
            Err(tx_receipt_error) => tx_receipt_error.tx_hash,
        }
    }
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
    Failed(BlockchainTxFailure),
    Succeeded(TxBlock),
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantCount)]
pub enum BlockchainTxFailure {
    Unrecognized,
}

impl Display for BlockchainTxFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockchainTxFailure::Unrecognized => write!(f, "Unrecognized failure"),
        }
    }
}

impl Display for StatusReadFromReceiptCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusReadFromReceiptCheck::Failed(reason) => {
                write!(f, "Failed(Reason: {})", reason)
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxReceiptError {
    pub tx_hash: TxHashByTable,
    pub err: AppRpcError,
}

impl TxReceiptError {
    pub fn new(tx_hash: TxHashByTable, err: AppRpcError) -> Self {
        Self { tx_hash, err }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TxBlock {
    pub block_hash: H256,
    pub block_number: U64,
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::pending_payable_scanner::utils::TxHashByTable;
    use crate::accountant::test_utils::make_transaction_block;
    use crate::assert_on_testing_enum_with_all_its_variants;
    use crate::blockchain::blockchain_interface::data_structures::{
        BlockchainTxFailure, RetrievedTxStatus, StatusReadFromReceiptCheck, TxBlock,
        TxReceiptError, TxReceiptResult,
    };
    use crate::blockchain::errors::rpc_errors::{AppRpcError, LocalError, RemoteError};
    use crate::blockchain::test_utils::make_tx_hash;
    use ethereum_types::{H256, U64};
    use itertools::Itertools;

    #[test]
    fn tx_status_display_works() {
        // Test Failed
        assert_eq!(
            StatusReadFromReceiptCheck::Failed(BlockchainTxFailure::Unrecognized).to_string(),
            "Failed(Reason: Unrecognized failure)"
        );

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

    #[test]
    fn display_for_blockchain_tx_failure_works() {
        let input_and_expected_results =
            vec![(BlockchainTxFailure::Unrecognized, "Unrecognized failure")];
        let inputs_len = input_and_expected_results.len();

        let check_nums = input_and_expected_results
            .into_iter()
            .map(|(input, failure_reason)| match input {
                BlockchainTxFailure::Unrecognized => {
                    let result = input.to_string();
                    assert_eq!(result, failure_reason);
                    1
                }
            })
            .collect_vec();

        assert_on_testing_enum_with_all_its_variants!(BlockchainTxFailure, check_nums, inputs_len)
    }

    #[test]
    fn hash_can_be_fetched_from_tx_receipt_result() {
        let hash_1 = TxHashByTable::SentPayable(make_tx_hash(123));
        let hash_2 = TxHashByTable::SentPayable(make_tx_hash(111));
        let hash_3 = TxHashByTable::FailedPayable(make_tx_hash(222));
        let hash_4 = TxHashByTable::FailedPayable(make_tx_hash(321));
        let positive_with_sent_payable = TxReceiptResult(Ok(RetrievedTxStatus::new(
            hash_1,
            StatusReadFromReceiptCheck::Pending,
        )));
        let negative_with_sent_payable = TxReceiptResult(Err(TxReceiptError::new(
            hash_2,
            AppRpcError::Local(LocalError::Internal),
        )));
        let positive_with_failed_payable = TxReceiptResult(Ok(RetrievedTxStatus::new(
            hash_3,
            StatusReadFromReceiptCheck::Succeeded(make_transaction_block(789)),
        )));
        let negative_with_failed_payable = TxReceiptResult(Err(TxReceiptError::new(
            hash_4,
            AppRpcError::Remote(RemoteError::Unreachable),
        )));

        let result_1 = positive_with_sent_payable.hash();
        let result_2 = negative_with_sent_payable.hash();
        let result_3 = positive_with_failed_payable.hash();
        let result_4 = negative_with_failed_payable.hash();

        assert_eq!(result_1, hash_1);
        assert_eq!(result_2, hash_2);
        assert_eq!(result_3, hash_3);
        assert_eq!(result_4, hash_4);
    }
}
