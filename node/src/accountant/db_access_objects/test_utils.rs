// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedTx, FailureReason, FailureStatus, ValidationStatus,
};
use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
use crate::accountant::db_access_objects::utils::{current_unix_timestamp, TxHash};
use crate::database::db_initializer::{
    DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
};
use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;
use web3::types::Address;

#[derive(Default)]
pub struct TxBuilder {
    hash_opt: Option<TxHash>,
    receiver_address_opt: Option<Address>,
    amount_opt: Option<u128>,
    timestamp_opt: Option<i64>,
    gas_price_wei_opt: Option<u128>,
    nonce_opt: Option<u64>,
    status_opt: Option<TxStatus>,
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

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce_opt = Some(nonce);
        self
    }

    pub fn status(mut self, status: TxStatus) -> Self {
        self.status_opt = Some(status);
        self
    }

    pub fn build(self) -> SentTx {
        SentTx {
            hash: self.hash_opt.unwrap_or_default(),
            receiver_address: self.receiver_address_opt.unwrap_or_default(),
            amount_minor: self.amount_opt.unwrap_or_default(),
            timestamp: self.timestamp_opt.unwrap_or_else(current_unix_timestamp),
            gas_price_minor: self.gas_price_wei_opt.unwrap_or_default(),
            nonce: self.nonce_opt.unwrap_or_default(),
            status: self
                .status_opt
                .unwrap_or(TxStatus::Pending(ValidationStatus::Waiting)),
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
    status_opt: Option<FailureStatus>,
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

    pub fn status(mut self, failure_status: FailureStatus) -> Self {
        self.status_opt = Some(failure_status);
        self
    }

    pub fn build(self) -> FailedTx {
        FailedTx {
            hash: self.hash_opt.unwrap_or_default(),
            receiver_address: self.receiver_address_opt.unwrap_or_default(),
            amount_minor: self.amount_opt.unwrap_or_default(),
            timestamp: self.timestamp_opt.unwrap_or_default(),
            gas_price_minor: self.gas_price_wei_opt.unwrap_or_default(),
            nonce: self.nonce_opt.unwrap_or_default(),
            reason: self
                .reason_opt
                .unwrap_or_else(|| FailureReason::PendingTooLong),
            status: self
                .status_opt
                .unwrap_or_else(|| FailureStatus::RetryRequired),
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
