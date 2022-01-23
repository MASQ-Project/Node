// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PaymentFingerprint;
use actix::prelude::SendError;
use actix::Recipient;
use ethereum_types::H256;
use std::fmt::Debug;
use std::time::SystemTime;
use web3::futures::Future;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Error as Web3Error;
use web3::{Transport, Web3};

pub trait SendTransactionToolWrapper {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn request_new_payment_fingerprint(&self, transaction_hash: H256, amount: u64) -> SystemTime;
    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error>;
}

pub struct SendTransactionToolWrapperReal<'a, T: Transport + Debug> {
    web3: &'a Web3<T>,
    payment_fingerprint_sub: &'a dyn PaymentBackupRecipientWrapper,
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapperReal<'a, T> {
    pub fn new(
        web3: &'a Web3<T>,
        payment_fingerprint_sub: &'a dyn PaymentBackupRecipientWrapper,
    ) -> Self {
        Self {
            web3,
            payment_fingerprint_sub,
        }
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapper
    for SendTransactionToolWrapperReal<'a, T>
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.web3
            .accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn request_new_payment_fingerprint(&self, hash: H256, amount: u64) -> SystemTime {
        let now = SystemTime::now();
        self.payment_fingerprint_sub
            .try_send(PaymentFingerprint {
                amount,
                rowid: 0, //disregarded in this context
                timestamp: now,
                hash,
                attempt: 0, //DB will know where to start: 1
                process_error: None,
            })
            .expect("Accountant is dead");
        now
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
        self.web3.eth().send_raw_transaction(rlp).wait()
    }
}

pub struct SendTransactionToolWrapperNull;

impl SendTransactionToolWrapper for SendTransactionToolWrapperNull {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sing_transaction() should never be called on the null object")
    }

    fn request_new_payment_fingerprint(&self, _transaction_hash: H256, _amount: u64) -> SystemTime {
        panic!("request_new_payment_fingerprint() should never be called on the null object")
    }

    fn send_raw_transaction(&self, _rlp: Bytes) -> Result<H256, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

pub trait PaymentBackupRecipientWrapper {
    fn try_send(&self, msg: PaymentFingerprint) -> Result<(), SendError<PaymentFingerprint>>;
}

pub struct PaymentBackupRecipientWrapperReal<'a> {
    recipient: &'a Recipient<PaymentFingerprint>,
}

impl<'a> PaymentBackupRecipientWrapperReal<'a> {
    pub fn new(recipient: &'a Recipient<PaymentFingerprint>) -> Self {
        Self { recipient }
    }
}

impl PaymentBackupRecipientWrapper for PaymentBackupRecipientWrapperReal<'_> {
    fn try_send(&self, msg: PaymentFingerprint) -> Result<(), SendError<PaymentFingerprint>> {
        self.recipient.try_send(msg)
    }
}

pub struct PaymentBackupRecipientWrapperNull;

impl PaymentBackupRecipientWrapper for PaymentBackupRecipientWrapperNull {
    fn try_send(&self, _msg: PaymentFingerprint) -> Result<(), SendError<PaymentFingerprint>> {
        panic!("try_send() for PaymentBackupRecipientWrapper should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::PaymentFingerprint;
    use crate::blockchain::tool_wrappers::{
        PaymentBackupRecipientWrapper, PaymentBackupRecipientWrapperNull,
        SendTransactionToolWrapper, SendTransactionToolWrapperNull,
    };
    use std::time::SystemTime;
    use web3::types::{Bytes, TransactionParameters};

    #[test]
    #[should_panic(expected = "sing_transaction() should never be called on the null object")]
    fn null_sign_transaction_stops_the_run() {
        let transaction_parameters = TransactionParameters {
            nonce: None,
            to: None,
            gas: Default::default(),
            gas_price: None,
            value: Default::default(),
            data: Default::default(),
            chain_id: None,
        };
        let secret_key =
            secp256k1secrets::key::SecretKey::from_slice(b"000000000000000000000000000000aa")
                .unwrap();

        let _ =
            SendTransactionToolWrapperNull.sign_transaction(transaction_parameters, &secret_key);
    }

    #[test]
    #[should_panic(expected = "send_raw_transaction() should never be called on the null object")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolWrapperNull.send_raw_transaction(rlp);
    }

    #[test]
    #[should_panic(
        expected = "request_new_payment_fingerprint() should never be called on the null object"
    )]
    fn null_request_new_payment_fingerprint_stops_the_run() {
        let _ = SendTransactionToolWrapperNull.request_new_payment_fingerprint(Default::default(), 5);
    }

    #[test]
    #[should_panic(
        expected = "try_send() for PaymentBackupRecipientWrapper should never be called on the null object"
    )]
    fn null_try_send_stops_the_run() {
        let msg = PaymentFingerprint {
            rowid: 1,
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt: 0,
            amount: 44,
            process_error: None,
        };

        let _ = PaymentBackupRecipientWrapperNull.try_send(msg);
    }
}
