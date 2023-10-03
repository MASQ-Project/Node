// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_null;
pub mod blockchain_interface_web3;
pub mod rpc_helpers;
pub mod test_utils;

use crate::accountant::comma_joined_stringifiable;
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PendingPayable};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::rpc_helpers::RPCHelpers;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use itertools::Either;
use std::fmt;
use std::fmt::{Display, Formatter};
use variant_count::VariantCount;
use web3::types::{Address, BlockNumber, TransactionReceipt, H256};
use web3::Error;

const BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED: &str = "To avoid being delinquency-banned, you should \
restart the Node with a value for blockchain-service-url";

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError>;

    // TODO change the string to a real err type and then make changes in the BINull
    fn build_blockchain_agent(
        &self,
        consuming_wallet: &Wallet,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, String>;

    fn send_batch_of_payables(
        &self,
        agent: Box<dyn BlockchainAgent>,
        new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError>;

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt;

    fn helpers(&self) -> &dyn RPCHelpers;

    as_any_in_trait!();
}

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

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed(String),
    UninitializedBlockchainInterface,
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let err_spec = match self {
            Self::InvalidUrl => Either::Left("Invalid url"),
            Self::InvalidAddress => Either::Left("Invalid address"),
            Self::InvalidResponse => Either::Left("Invalid response"),
            Self::QueryFailed(msg) => Either::Right(format!("Query failed: {}", msg)),
            Self::UninitializedBlockchainInterface => {
                Either::Left(BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            }
        };
        write!(f, "Blockchain error: {}", err_spec)
    }
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;
pub type ResultForReceipt = BlockchainResult<Option<TransactionReceipt>>;

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum PayableTransactionError {
    MissingConsumingWallet,
    GasPriceQueryFailed(String),
    TransactionCount(BlockchainError),
    UnusableWallet(String),
    Signing(String),
    Sending { msg: String, hashes: Vec<H256> },
    UninitializedBlockchainInterface,
}

impl Display for PayableTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConsumingWallet => {
                write!(f, "Missing consuming wallet to pay payable from")
            }
            Self::GasPriceQueryFailed(msg) => {
                write!(f, "Unsuccessful gas price query: \"{}\"", msg)
            }
            Self::TransactionCount(blockchain_err) => {
                write!(f, "Transaction count fetching failed: {}", blockchain_err)
            }
            Self::UnusableWallet(msg) => write!(
                f,
                "Unusable wallet for signing payable transactions: \"{}\"",
                msg
            ),
            Self::Signing(msg) => write!(f, "Signing phase: \"{}\"", msg),
            Self::Sending { msg, hashes } => write!(
                f,
                "Sending phase: \"{}\". Signed and hashed transactions: {}",
                msg,
                comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
            ),
            Self::UninitializedBlockchainInterface => {
                write!(f, "{}", BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            }
        }
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

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::{
        BlockchainError, PayableTransactionError, BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED,
            "To avoid being delinquency-banned, you should restart the Node with a value for \
            blockchain-service-url"
        )
    }

    #[test]
    fn blockchain_error_implements_display() {
        let original_errors = [
            BlockchainError::InvalidUrl,
            BlockchainError::InvalidAddress,
            BlockchainError::InvalidResponse,
            BlockchainError::QueryFailed(
                "Don't query so often, it gives me a headache".to_string(),
            ),
            BlockchainError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors
            .iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            BlockchainError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Blockchain error: Invalid url",
                "Blockchain error: Invalid address",
                "Blockchain error: Invalid response",
                "Blockchain error: Query failed: Don't query so often, it gives me a headache",
                &format!("Blockchain error: {}", BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            ])
        );
    }

    #[test]
    fn payable_payment_error_implements_display() {
        let original_errors = [
            PayableTransactionError::MissingConsumingWallet,
            PayableTransactionError::GasPriceQueryFailed(
                "Gas halves shut, no drop left".to_string(),
            ),
            PayableTransactionError::TransactionCount(BlockchainError::InvalidResponse),
            PayableTransactionError::UnusableWallet(
                "This is a LEATHER wallet, not LEDGER wallet, stupid.".to_string(),
            ),
            PayableTransactionError::Signing(
                "You cannot sign with just three crosses here, clever boy".to_string(),
            ),
            PayableTransactionError::Sending {
                msg: "Sending to cosmos belongs elsewhere".to_string(),
                hashes: vec![make_tx_hash(0x6f), make_tx_hash(0xde)],
            },
            PayableTransactionError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors
            .iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            PayableTransactionError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Missing consuming wallet to pay payable from",
                "Unsuccessful gas price query: \"Gas halves shut, no drop left\"",
                "Transaction count fetching failed: Blockchain error: Invalid response",
                "Unusable wallet for signing payable transactions: \"This is a LEATHER wallet, not \
                LEDGER wallet, stupid.\"",
                "Signing phase: \"You cannot sign with just three crosses here, clever boy\"",
                "Sending phase: \"Sending to cosmos belongs elsewhere\". Signed and hashed \
                transactions: 0x000000000000000000000000000000000000000000000000000000000000006f, \
                0x00000000000000000000000000000000000000000000000000000000000000de",
                BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED
            ])
        )
    }
}
