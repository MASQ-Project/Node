// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use actix::Recipient;
use ethereum_types::H256;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};
use web3::futures::Future;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Web3;
use web3::{BatchTransport, Error as Web3Error};

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
    //TODO write that so that all fingerprints are requested by a single message
    fn request_new_payable_fingerprint(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprint>,
        payable_attributes: Vec<(H256, u64)>,
    );
    fn send_batch(&self, rlp: Bytes, web3: Web3<Batch<T>>) -> Result<H256, Web3Error>;
}

#[derive(Debug, Default)]
pub struct BatchedPayableToolsReal {}

impl<T: BatchTransport + Debug> BatchedPayableTools<T> for BatchedPayableToolsReal {
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
        UNIX_EPOCH //TODO test drive this out
    }

    fn request_new_payable_fingerprint(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprint>,
        payable_attributes: Vec<(H256, u64)>,
    ) {
        payable_attributes.into_iter().for_each(|payable| {
            todo!("make sure it is tested");
            let (hash, amount) = payable;
            pp_fingerprint_sub
                .try_send(PendingPayableFingerprint {
                    amount,
                    rowid_opt: None,
                    timestamp: batch_wide_timestamp,
                    hash,
                    attempt_opt: None,
                    process_error: None,
                })
                .expect("Accountant is dead");
        })
    }

    fn send_batch(&self, rlp: Bytes, web3: Web3<Batch<T>>) -> Result<H256, Web3Error> {
        web3.eth().send_raw_transaction(rlp).wait()
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

    fn request_new_payable_fingerprint(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprint>,
        payable_attributes: Vec<(H256, u64)>,
    ) {
        panic!(
            "request_new_pending_payable_fingerprint() should never be called on the null object"
        )
    }

    fn send_batch(&self, rlp: Bytes, web3: Web3<Batch<T>>) -> Result<H256, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::TestTransport;
    use crate::blockchain::tool_wrappers::{
        BatchedPayableTools, BatchedPayableToolsNull, BatchedPayableToolsReal,
    };
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use actix::{Actor, Recipient};
    use std::time::SystemTime;
    use web3::transports::Batch;
    use web3::types::{Bytes, TransactionParameters};
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
    #[should_panic(expected = "send_raw_transaction() should never be called on the null object")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());
        let web3 = Web3::new(Batch::new(TestTransport::default()));

        let _ = BatchedPayableToolsNull::<TestTransport>::default().send_batch(rlp, web3);
    }

    #[test]
    #[should_panic(
        expected = "request_new_pending_payable_fingerprint() should never be called on the null object"
    )]
    fn null_request_new_pending_payable_fingerprint_stops_the_run() {
        let recipient = Recorder::new().start().recipient();
        let _ = BatchedPayableToolsNull::<TestTransport>::default()
            .request_new_payable_fingerprint(
                SystemTime::now(),
                &recipient,
                vec![(Default::default(), 5)],
            );
    }

    #[test]
    fn custom_debug_for_send_transaction_tool_wrapper_real() {
        let transport = TestTransport::default();
        let web3 = Web3::new(transport);
        let (random_actor, _, _) = make_recorder();
        let recipient: Recipient<PendingPayableFingerprint> = random_actor.start().recipient();

        let result = format!("{:?}", BatchedPayableToolsReal::default());

        assert_eq!(result,"SendTransactionToolWrapperReal { web3: Web3 { transport: TestTransport { asserted: 0, \
         requests: RefCell { value: [] }, responses: RefCell { value: [] } } }, pending_payable_fingerprint_sub: _OMITTED_ }")
    }
}
