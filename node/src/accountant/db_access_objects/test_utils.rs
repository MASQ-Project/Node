// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::accountant::db_access_objects::sent_payable_dao::{TxHash, Tx};
use crate::accountant::db_access_objects::utils::current_unix_timestamp;
use web3::types::{Address};
use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionBlock;

#[derive(Default)]
pub struct TxBuilder {
    hash_opt: Option<TxHash>,
    receiver_address_opt: Option<Address>,
    amount_opt: Option<u128>,
    timestamp_opt: Option<i64>,
    gas_price_wei_opt: Option<u128>,
    nonce_opt: Option<u64>,
    block_opt: Option<TransactionBlock>,
}

impl TxBuilder {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn hash(mut self, hash: TxHash) -> Self {
        self.hash_opt = Some(hash);
        self
    }

    pub fn block(mut self, block: TransactionBlock) -> Self {
        self.block_opt = Some(block);
        self
    }

    pub fn build(self) -> Tx {
        Tx {
            hash: self.hash_opt.unwrap_or_default(),
            receiver_address: self.receiver_address_opt.unwrap_or_default(),
            amount: self.amount_opt.unwrap_or_default(),
            timestamp: self.timestamp_opt.unwrap_or_else(current_unix_timestamp),
            gas_price_wei: self.gas_price_wei_opt.unwrap_or_default(),
            nonce: self.nonce_opt.unwrap_or_default(),
            block_opt: self.block_opt,
        }
    }
}

#[derive(Default)]
pub struct FailedTxBuilder {
    hash_opt: Option<TxHash>,
    receiver_address_opt: Option<Address>,
    amount_opt: Option<u128>,
    timestamp_opt: Option<i64>,
    gas_price_wei_opt: Option<u128>,
    nonce_opt: Option<u64>,
    reason_opt: Option<FailureReason>,
    checked_opt: Option<u8>,
}

impl FailedTxBuilder {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn hash(mut self, hash: TxHash) -> Self {
        self.hash_opt = Some(hash);
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce_opt = Some(nonce);
        self
    }

    pub fn reason(mut self, reason: FailureReason) -> Self {
        self.reason_opt = Some(reason);
        self
    }

    pub fn checked(mut self, checked: u8) -> Self {
        self.checked_opt = Some(checked);
        self
    }

    pub fn build(self) -> FailedTx {
        FailedTx {
            hash: self.hash_opt.unwrap_or_default(),
            receiver_address: self.receiver_address_opt.unwrap_or_default(),
            amount: self.amount_opt.unwrap_or_default(),
            timestamp: self.timestamp_opt.unwrap_or_default(),
            gas_price_wei: self.gas_price_wei_opt.unwrap_or_default(),
            nonce: self.nonce_opt.unwrap_or_default(),
            reason: self
                .reason_opt
                .unwrap_or_else(|| FailureReason::PendingTooLong),
            checked: self.checked_opt.unwrap_or_default(),
        }
    }
}
