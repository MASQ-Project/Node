// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use actix::{Recipient};
use serde_json::Value;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::SystemTime;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters, H256};
use web3::{BatchTransport, Error as Web3Error, Web3};

pub enum Web3TransportsResult<O> {
    Ok(O)
}

#[derive(Clone)]
pub struct SecP256K1SecretsKeySecretKey;

pub trait BatchPayableTools<T>
where
    T: BatchTransport,
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &SecP256K1SecretsKeySecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>);
    fn batch_wide_timestamp(&self) -> SystemTime;
    fn send_new_payable_fingerprints_seeds(
        &self,
        batch_wide_timestamp: SystemTime,
        new_pp_fingerprints_sub: &Recipient<PendingPayableFingerprintSeeds>,
        hashes_and_balances: &[(H256, u128)],
    );
    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<Web3TransportsResult<Value>>, Web3Error>;
}

#[derive(Debug)]
pub struct BatchPayableToolsReal<T> {
    phantom: PhantomData<T>,
}

impl<T: BatchTransport> Default for BatchPayableToolsReal<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport + Debug> BatchPayableTools<T> for BatchPayableToolsReal<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &SecP256K1SecretsKeySecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        todo!()
        // web3.accounts()
        //     .sign_transaction(transaction_params, key)
        //     .wait()
    }

    fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>) {
        let _ = web3.eth().send_raw_transaction(signed_transaction);
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        SystemTime::now()
    }

    fn send_new_payable_fingerprints_seeds(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprintSeeds>,
        hashes_and_balances: &[(H256, u128)],
    ) {
        pp_fingerprint_sub
            .try_send(PendingPayableFingerprintSeeds {
                batch_wide_timestamp,
                hashes_and_balances: hashes_and_balances.to_vec(),
            })
            .expect("Accountant is dead");
    }

    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<Web3TransportsResult<Value>>, Web3Error> {
        todo!()
        // web3.transport().submit_batch().wait()
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::batch_payable_tools::{BatchPayableTools, BatchPayableToolsReal};
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
    use crate::blockchain::test_utils::{make_tx_hash, TestTransport};
    use crate::test_utils::recorder::make_recorder;
    use actix::{Actor, System};
    use std::time::SystemTime;

    #[test]
    fn request_new_payable_fingerprints_works() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let timestamp = SystemTime::now();
        let hashes_and_balances = vec![(make_tx_hash(123), 5), (make_tx_hash(45466), 444444)];

        let _ = BatchPayableToolsReal::<TestTransport>::default()
            .send_new_payable_fingerprints_seeds(timestamp, &recipient, &hashes_and_balances);

        let system = System::new();
        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(
            message,
            &PendingPayableFingerprintSeeds {
                batch_wide_timestamp: timestamp,
                hashes_and_balances
            }
        )
    }

    #[test]
    fn batch_wide_timestamp_returns_current_now() {
        let subject = BatchPayableToolsReal::<TestTransport>::default();
        let before = SystemTime::now();

        let result = subject.batch_wide_timestamp();

        let after = SystemTime::now();
        assert!(
            before <= result && result <= after,
            "Actual timestamp {:?} didn't fit between before {:?} and after {:?}",
            result,
            before,
            after
        )
    }
}
