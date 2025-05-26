// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use web3::types::{Address, H256};
use crate::accountant::db_access_objects::sent_payable_dao::Tx;
use crate::accountant::db_access_objects::utils::current_unix_timestamp;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxStatus;

#[derive(Default)]
pub struct TxBuilder {
    hash_opt: Option<H256>,
    receiver_address_opt: Option<Address>,
    amount_opt: Option<u128>,
    timestamp_opt: Option<i64>,
    gas_price_wei_opt: Option<u64>,
    nonce_opt: Option<u32>,
    status_opt: Option<TxStatus>,
}

impl TxBuilder {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn hash(mut self, hash: H256) -> Self {
        self.hash_opt = Some(hash);
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp_opt = Some(timestamp);
        self
    }

    pub fn status(mut self, status: TxStatus) -> Self {
        self.status_opt = Some(status);
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
            status: self.status_opt.unwrap_or(TxStatus::Pending),
        }
    }
}
