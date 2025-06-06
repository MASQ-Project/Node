// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use std::path::PathBuf;
use rusqlite::{Connection, OpenFlags};
use crate::accountant::db_access_objects::sent_payable_dao::{ Tx};
use crate::accountant::db_access_objects::utils::{current_unix_timestamp, TxHash};
use web3::types::{Address};
use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionBlock;
use crate::database::db_initializer::{DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE};
use crate::database::rusqlite_wrappers::ConnectionWrapperReal;

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

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp_opt = Some(timestamp);
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
    checked_opt: Option<bool>,
}

impl FailedTxBuilder {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn hash(mut self, hash: TxHash) -> Self {
        self.hash_opt = Some(hash);
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp_opt = Some(timestamp);
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

    pub fn checked(mut self, checked: bool) -> Self {
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
            checked: self.checked_opt.unwrap_or_else(|| false),
        }
    }
}

pub fn make_read_only_db_connection(home_dir: PathBuf) -> ConnectionWrapperReal {
    {
        DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
    }
    let read_only_conn = Connection::open_with_flags(
        home_dir.join(DATABASE_FILE),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();

    ConnectionWrapperReal::new(read_only_conn)
}
