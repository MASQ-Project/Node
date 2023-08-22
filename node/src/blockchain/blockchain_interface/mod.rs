// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_null;
pub mod blockchain_interface_web3;
pub mod rpc_helpers;
pub mod test_utils;

use crate::accountant::comma_joined_stringifiable;
use crate::accountant::database_access_objects::payable_dao::{PayableAccount, PendingPayable};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::rpc_helpers::RPCHelpers;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use itertools::Either;
use std::fmt;
use std::fmt::{Display, Formatter};
use web3::types::{Address, TransactionReceipt, H256};
use web3::Error;

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError>;

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
}

#[derive(Clone, Debug, Eq, Message, PartialEq)]
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
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed(String),
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let err_spec = match self {
            Self::InvalidUrl => Either::Left("Invalid url"),
            Self::InvalidAddress => Either::Left("Invalid address"),
            Self::InvalidResponse => Either::Left("Invalid response"),
            Self::QueryFailed(msg) => Either::Right(format!("Query failed: {}", msg)),
        };
        write!(f, "Blockchain error: {}", err_spec)
    }
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;
pub type ResultForReceipt = BlockchainResult<Option<TransactionReceipt>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayableTransactionError {
    MissingConsumingWallet,
    GasPriceQueryFailed(String),
    TransactionCount(BlockchainError),
    UnusableWallet(String),
    Signing(String),
    Sending { msg: String, hashes: Vec<H256> },
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
            Self::TransactionCount(blockchain_err) => write!(
                f,
                "Transaction count fetching failed for: {}",
                blockchain_err
            ),
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
    Failed(RpcFailurePayables),
}

#[derive(Debug, PartialEq, Clone)]
pub struct RpcFailurePayables {
    pub rpc_error: Error,
    pub recipient_wallet: Wallet,
    pub hash: H256,
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::{BlockchainError, PayableTransactionError};
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;
    use std::fmt::Display;

    fn collect_match_displayable_error_variants_in_exhaustive_mode<E, C>(
        errors_to_assert: &[E],
        exhaustive_error_matching: C,
        expected_check_nums: Vec<u8>,
    ) -> Vec<String>
    where
        E: Display,
        C: Fn(&E) -> (String, u8),
    {
        let displayed_errors_with_check_nums = errors_to_assert
            .iter()
            .map(exhaustive_error_matching)
            .collect::<Vec<(String, u8)>>();
        let check_nums_alone = displayed_errors_with_check_nums
            .iter()
            .map(|(_, num_check)| *num_check)
            .collect::<Vec<u8>>();
        assert_eq!(check_nums_alone, expected_check_nums);
        displayed_errors_with_check_nums
            .into_iter()
            .map(|(msg, _)| msg)
            .collect()
    }

    #[test]
    fn blockchain_error_implements_display() {
        //TODO at the time of writing this test 'core::mem::variant_count' was only in nightly,
        // consider its implementation instead of these match statements here and in the test below
        let original_errors = [
            BlockchainError::InvalidUrl,
            BlockchainError::InvalidAddress,
            BlockchainError::InvalidResponse,
            BlockchainError::QueryFailed(
                "Don't query so often, it gives me a headache".to_string(),
            ),
        ];
        let pretty_print_closure = |err_to_resolve: &BlockchainError| match err_to_resolve {
            BlockchainError::InvalidUrl => (err_to_resolve.to_string(), 11),
            BlockchainError::InvalidAddress => (err_to_resolve.to_string(), 22),
            BlockchainError::InvalidResponse => (err_to_resolve.to_string(), 33),
            BlockchainError::QueryFailed(..) => (err_to_resolve.to_string(), 44),
        };

        let actual_error_msgs = collect_match_displayable_error_variants_in_exhaustive_mode(
            original_errors.as_slice(),
            pretty_print_closure,
            vec![11, 22, 33, 44],
        );

        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Blockchain error: Invalid url",
                "Blockchain error: Invalid address",
                "Blockchain error: Invalid response",
                "Blockchain error: Query failed: Don't query so often, it gives me a headache",
            ])
        )
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
        ];
        let pretty_print_closure = |err_to_resolve: &PayableTransactionError| match err_to_resolve {
            PayableTransactionError::MissingConsumingWallet => (err_to_resolve.to_string(), 11),
            PayableTransactionError::GasPriceQueryFailed(_) => (err_to_resolve.to_string(), 22),
            PayableTransactionError::TransactionCount(_) => (err_to_resolve.to_string(), 33),
            PayableTransactionError::UnusableWallet(_) => (err_to_resolve.to_string(), 44),
            PayableTransactionError::Signing(_) => (err_to_resolve.to_string(), 55),
            PayableTransactionError::Sending { .. } => (err_to_resolve.to_string(), 66),
        };

        let actual_error_msgs = collect_match_displayable_error_variants_in_exhaustive_mode(
            original_errors.as_slice(),
            pretty_print_closure,
            vec![11, 22, 33, 44, 55, 66],
        );

        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Missing consuming wallet to pay payable from",
                "Unsuccessful gas price query: \"Gas halves shut, no drop left\"",
                "Transaction count fetching failed for: Blockchain error: Invalid response",
                "Unusable wallet for signing payable transactions: \"This is a LEATHER wallet, not \
                LEDGER wallet, stupid.\"",
                "Signing phase: \"You cannot sign with just three crosses here, clever boy\"",
                "Sending phase: \"Sending to cosmos belongs elsewhere\". Signed and hashed \
                transactions: 0x000000000000000000000000000000000000000000000000000000000000006f, \
                0x00000000000000000000000000000000000000000000000000000000000000de"
            ])
        )
    }
}
