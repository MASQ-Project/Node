// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use actix::Recipient;
use futures::Future;
use serde_json::Value;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::SystemTime;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters, H256};
use web3::{BatchTransport, Error as Web3Error, Web3};

pub trait BatchPayableTools<T>
where
    T: BatchTransport,
{
    // fn sign_transaction(
    //     &self,
    //     transaction_params: TransactionParameters,
    //     web3: &Web3<Batch<T>>,
    //     key: &secp256k1secrets::key::SecretKey,
    // ) -> Result<SignedTransaction, Web3Error>;
    // fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>);
    // fn batch_wide_timestamp(&self) -> SystemTime;
    // fn send_new_payable_fingerprints_seeds(
    //     &self,
    //     batch_wide_timestamp: SystemTime,
    //     new_pp_fingerprints_sub: &Recipient<PendingPayableFingerprintSeeds>,
    //     hashes_and_balances: &[(H256, u128)],
    // );
    // fn submit_batch(
    //     &self,
    //     web3: &Web3<Batch<T>>,
    // ) -> Box<dyn Future<Item = Vec<web3::transports::Result<Value>>, Error = Web3Error>>;
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

impl<T: BatchTransport + Debug + 'static> BatchPayableTools<T> for BatchPayableToolsReal<T> {
    // fn sign_transaction(
    //     &self,
    //     transaction_params: TransactionParameters,
    //     web3: &Web3<Batch<T>>,
    //     key: &secp256k1secrets::key::SecretKey,
    // ) -> Result<SignedTransaction, Web3Error> {
    //     web3.accounts()
    //         .sign_transaction(transaction_params, key)
    //         .wait()
    // }

    // fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>) {
    //     let _ = web3.eth().send_raw_transaction(signed_transaction);
    // }

    // fn batch_wide_timestamp(&self) -> SystemTime {
    //     SystemTime::now()
    // }

    // fn send_new_payable_fingerprints_seeds(
    //     &self,
    //     batch_wide_timestamp: SystemTime,
    //     pp_fingerprint_sub: &Recipient<PendingPayableFingerprintSeeds>,
    //     hashes_and_balances: &[(H256, u128)],
    // ) {
    //     pp_fingerprint_sub
    //         .try_send(PendingPayableFingerprintSeeds {
    //             batch_wide_timestamp,
    //             hashes_and_balances: hashes_and_balances.to_vec(),
    //         })
    //         .expect("Accountant is dead");
    // }

    //Result<Vec<web3::transports::Result<Value>>, Web3Error>
    // fn submit_batch(
    //     &self,
    //     web3: &Web3<Batch<T>>,
    // ) -> Box<dyn Future<Item = Vec<web3::transports::Result<Value>>, Error = Web3Error>> {
    //     Box::new(web3.transport().submit_batch())
    // }
}
