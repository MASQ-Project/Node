// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedTx, FailureReason, FailureStatus,
};
use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
use crate::accountant::db_access_objects::utils::{current_unix_timestamp, TxHash};
use crate::accountant::scanners::payable_scanner::tx_templates::signable::SignableTxTemplate;
use crate::blockchain::errors::validation_status::ValidationStatus;
use crate::blockchain::test_utils::{make_address, make_tx_hash};
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

    pub fn receiver_address(mut self, receiver_address: Address) -> Self {
        self.receiver_address_opt = Some(receiver_address);
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

    pub fn template(mut self, signable_tx_template: SignableTxTemplate) -> Self {
        self.receiver_address_opt = Some(signable_tx_template.receiver_address);
        self.amount_opt = Some(signable_tx_template.amount_in_wei);
        self.gas_price_wei_opt = Some(signable_tx_template.gas_price_wei);
        self.nonce_opt = Some(signable_tx_template.nonce);
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

    pub fn receiver_address(mut self, receiver_address: Address) -> Self {
        self.receiver_address_opt = Some(receiver_address);
        self
    }

    pub fn amount(mut self, amount: u128) -> Self {
        self.amount_opt = Some(amount);
        self
    }

    pub fn timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp_opt = Some(timestamp);
        self
    }

    pub fn gas_price_wei(mut self, gas_price_wei: u128) -> Self {
        self.gas_price_wei_opt = Some(gas_price_wei);
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

    pub fn template(mut self, signable_tx_template: SignableTxTemplate) -> Self {
        self.receiver_address_opt = Some(signable_tx_template.receiver_address);
        self.amount_opt = Some(signable_tx_template.amount_in_wei);
        self.gas_price_wei_opt = Some(signable_tx_template.gas_price_wei);
        self.nonce_opt = Some(signable_tx_template.nonce);
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
            timestamp: self.timestamp_opt.unwrap_or_else(|| 1719990000),
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

pub fn make_failed_tx(n: u32) -> FailedTx {
    let n = n % 0xfff;
    FailedTxBuilder::default()
        .hash(make_tx_hash(n))
        .timestamp(((n * 12) as i64).pow(2))
        .receiver_address(make_address(n.pow(2)))
        .gas_price_wei((n as u128).pow(3))
        .amount((n as u128).pow(4))
        .nonce(n as u64)
        .build()
}

pub fn make_sent_tx(n: u32) -> SentTx {
    let n = n % 0xfff;
    TxBuilder::default()
        .hash(make_tx_hash(n))
        .timestamp(((n * 12) as i64).pow(2))
        .template(SignableTxTemplate {
            receiver_address: make_address(n),
            amount_in_wei: (n as u128).pow(4),
            gas_price_wei: (n as u128).pow(3),
            nonce: n as u64,
        })
        .build()
}

pub fn assert_on_sent_txs(actual: Vec<SentTx>, expected: Vec<SentTx>) {
    assert_eq!(actual.len(), expected.len());

    actual.iter().zip(expected).for_each(|(st1, st2)| {
        assert_eq!(st1.hash, st2.hash);
        assert_eq!(st1.receiver_address, st2.receiver_address);
        assert_eq!(st1.amount_minor, st2.amount_minor);
        assert_eq!(st1.gas_price_minor, st2.gas_price_minor);
        assert_eq!(st1.nonce, st2.nonce);
        assert_eq!(st1.status, st2.status);
        assert!((st1.timestamp - st2.timestamp).abs() < 10);
    })
}

pub fn assert_on_failed_txs(actual: Vec<FailedTx>, expected: Vec<FailedTx>) {
    assert_eq!(actual.len(), expected.len());

    actual.iter().zip(expected).for_each(|(f1, f2)| {
        assert_eq!(f1.hash, f2.hash);
        assert_eq!(f1.receiver_address, f2.receiver_address);
        assert_eq!(f1.amount_minor, f2.amount_minor);
        assert_eq!(f1.gas_price_minor, f2.gas_price_minor);
        assert_eq!(f1.nonce, f2.nonce);
        assert_eq!(f1.reason, f2.reason);
        assert_eq!(f1.status, f2.status);
        assert!((f1.timestamp - f2.timestamp).abs() < 10);
    })
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
