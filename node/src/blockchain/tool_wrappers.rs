// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::{InitiatePPFingerprints, PendingPayableFingerprint};
use actix::Recipient;
use ethereum_types::H256;
use jsonrpc_core as rpc;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};
use web3::futures::Future;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::{BatchTransport, Error as Web3Error};
use web3::{Error, Web3};

pub trait BatchedPayableTools<T>
where
    T: BatchTransport,
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn batch_wide_timestamp(&self) -> SystemTime;
    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        payable_attributes: &[(H256, u64)],
    );
    fn send_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>;
}

#[derive(Debug)]
pub struct BatchedPayablesToolsReal<T> {
    phantom: PhantomData<T>,
}

impl<T: BatchTransport> Default for BatchedPayablesToolsReal<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport + Debug> BatchedPayableTools<T> for BatchedPayablesToolsReal<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        web3.accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        SystemTime::now()
    }

    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        chief_payable_attributes: &[(H256, u64)],
    ) {
        pp_fingerprint_sub
            .try_send(InitiatePPFingerprints {
                batch_wide_timestamp,
                init_params: chief_payable_attributes.to_vec(),
            })
            .expect("Accountant is dead");
    }

    fn send_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
        web3.transport().submit_batch().wait()
    }
}

#[derive(Debug)]
pub struct BatchedPayableToolsNull<T> {
    phantom: PhantomData<T>,
}

impl<T> Default for BatchedPayableToolsNull<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport> BatchedPayableTools<T> for BatchedPayableToolsNull<T> {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _web3: &Web3<Batch<T>>,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sign_transaction() should never be called on the null object")
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        todo!()
    }

    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        payable_attributes: &[(H256, u64)],
    ) {
        panic!(
            "request_new_pending_payable_fingerprint() should never be called on the null object"
        )
    }

    fn send_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::{InitiatePPFingerprints, PendingPayableFingerprint};
    use crate::blockchain::test_utils::{make_tx_hash, TestTransport};
    use crate::blockchain::tool_wrappers::{
        BatchedPayableTools, BatchedPayableToolsNull, BatchedPayablesToolsReal,
    };
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::{Actor, Recipient, System};
    use primitive_types::H256;
    use std::time::SystemTime;
    use web3::transports::{Batch, Http};
    use web3::types::{Bytes, TransactionParameters, U256};
    use web3::Web3;

    #[test]
    #[should_panic(expected = "sign_transaction() should never be called on the null object")]
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
        let web3 = Web3::new(Batch::new(TestTransport::default()));
        let secret_key =
            secp256k1secrets::key::SecretKey::from_slice(b"000000000000000000000000000000aa")
                .unwrap();

        let _ = BatchedPayableToolsNull::<TestTransport>::default().sign_transaction(
            transaction_parameters,
            &web3,
            &secret_key,
        );
    }

    #[test]
    #[should_panic(expected = "send_batch() should never be called on the null object")]
    fn null_send_batch_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());
        let web3 = Web3::new(Batch::new(TestTransport::default()));

        let _ = BatchedPayableToolsNull::<TestTransport>::default().send_batch(&web3);
    }

    #[test]
    #[should_panic(
        expected = "request_new_pending_payable_fingerprint() should never be called on the null object"
    )]
    fn null_request_new_pending_payable_fingerprint_stops_the_run() {
        let recipient = Recorder::new().start().recipient();
        let _ = BatchedPayableToolsNull::<TestTransport>::default().new_payable_fingerprints(
            SystemTime::now(),
            &recipient,
            &[(Default::default(), 5)],
        );
    }

    #[test]
    fn request_new_payable_fingerprints_works() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let timestamp = SystemTime::now();
        let chief_attributes_of_payables =
            vec![(Default::default(), 5), (make_tx_hash(45466), 444444)];

        let _ = BatchedPayablesToolsReal::<TestTransport>::default().new_payable_fingerprints(
            timestamp,
            &recipient,
            &chief_attributes_of_payables,
        );

        let system = System::new("new fingerprints");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<InitiatePPFingerprints>(0);
        assert_eq!(
            message,
            &InitiatePPFingerprints {
                batch_wide_timestamp: timestamp,
                init_params: chief_attributes_of_payables
            }
        )
    }

    #[test]
    fn batch_wide_timestamp_returns_current_now() {
        let subject = BatchedPayablesToolsReal::<TestTransport>::default();
        let before = SystemTime::now();

        let result = subject.batch_wide_timestamp();

        let after = SystemTime::now();
        assert!(before <= result && result <= after)
    }
}
