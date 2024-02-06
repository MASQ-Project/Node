// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// TODO: GH-744: Delete me later

// #![cfg(test)]
// use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
// use actix::Recipient;
// use jsonrpc_core as rpc;
// use std::cell::RefCell;
// use std::sync::{Arc, Mutex};
// use std::time::SystemTime;
// use web3::transports::Batch;
// use web3::types::{Bytes, SignedTransaction, TransactionParameters, H256};
// use web3::{BatchTransport, Error as Web3Error, Web3};

// #[derive(Default)]
// pub struct BatchPayableToolsMock<T: BatchTransport> {
//     sign_transaction_params: Arc<
//         Mutex<
//             Vec<(
//                 TransactionParameters,
//                 Web3<Batch<T>>,
//                 secp256k1secrets::key::SecretKey,
//             )>,
//         >,
//     >,
//     sign_transaction_results: RefCell<Vec<Result<SignedTransaction, Web3Error>>>,
//     append_transaction_to_batch_params: Arc<Mutex<Vec<(Bytes, Web3<Batch<T>>)>>>,
//     //append_transaction_to_batch returns just the unit type
//     //batch_wide_timestamp doesn't have params
//     batch_wide_timestamp_results: RefCell<Vec<SystemTime>>,
//     send_new_payable_fingerprints_seeds_params: Arc<
//         Mutex<
//             Vec<(
//                 SystemTime,
//                 Recipient<PendingPayableFingerprintSeeds>,
//                 Vec<(H256, u128)>,
//             )>,
//         >,
//     >,
//     //new_payable_fingerprints returns just the unit type
//     submit_batch_params: Arc<Mutex<Vec<Web3<Batch<T>>>>>,
//     submit_batch_results:
//         RefCell<Vec<Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>>>,
// }

// impl<T: BatchTransport> BatchPayableTools<T> for BatchPayableToolsMock<T> {
//     fn sign_transaction(
//         &self,
//         transaction_params: TransactionParameters,
//         web3: &Web3<Batch<T>>,
//         key: &secp256k1secrets::key::SecretKey,
//     ) -> Result<SignedTransaction, Web3Error> {
//         self.sign_transaction_params.lock().unwrap().push((
//             transaction_params.clone(),
//             web3.clone(),
//             key.clone(),
//         ));
//         self.sign_transaction_results.borrow_mut().remove(0)
//     }
//
//     fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>) {
//         self.append_transaction_to_batch_params
//             .lock()
//             .unwrap()
//             .push((signed_transaction, web3.clone()));
//     }
//
//     fn batch_wide_timestamp(&self) -> SystemTime {
//         self.batch_wide_timestamp_results.borrow_mut().remove(0)
//     }
//
//     fn send_new_payable_fingerprints_seeds(
//         &self,
//         batch_wide_timestamp: SystemTime,
//         pp_fingerprint_sub: &Recipient<PendingPayableFingerprintSeeds>,
//         hashes_and_balances: &[(H256, u128)],
//     ) {
//         self.send_new_payable_fingerprints_seeds_params
//             .lock()
//             .unwrap()
//             .push((
//                 batch_wide_timestamp,
//                 (*pp_fingerprint_sub).clone(),
//                 hashes_and_balances.to_vec(),
//             ));
//     }
//
//     fn submit_batch(
//         &self,
//         web3: &Web3<Batch<T>>,
//     ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
//         self.submit_batch_params.lock().unwrap().push(web3.clone());
//         self.submit_batch_results.borrow_mut().remove(0)
//     }
// }

// impl<T: BatchTransport> BatchPayableToolsMock<T> {
//     pub fn sign_transaction_params(
//         mut self,
//         params: &Arc<
//             Mutex<
//                 Vec<(
//                     TransactionParameters,
//                     Web3<Batch<T>>,
//                     secp256k1secrets::key::SecretKey,
//                 )>,
//             >,
//         >,
//     ) -> Self {
//         self.sign_transaction_params = params.clone();
//         self
//     }
//
//     pub fn sign_transaction_result(self, result: Result<SignedTransaction, Web3Error>) -> Self {
//         self.sign_transaction_results.borrow_mut().push(result);
//         self
//     }
//
//     pub fn batch_wide_timestamp_result(self, result: SystemTime) -> Self {
//         self.batch_wide_timestamp_results.borrow_mut().push(result);
//         self
//     }
//
//     pub fn send_new_payable_fingerprint_credentials_params(
//         mut self,
//         params: &Arc<
//             Mutex<
//                 Vec<(
//                     SystemTime,
//                     Recipient<PendingPayableFingerprintSeeds>,
//                     Vec<(H256, u128)>,
//                 )>,
//             >,
//         >,
//     ) -> Self {
//         self.send_new_payable_fingerprints_seeds_params = params.clone();
//         self
//     }
//
//     pub fn append_transaction_to_batch_params(
//         mut self,
//         params: &Arc<Mutex<Vec<(Bytes, Web3<Batch<T>>)>>>,
//     ) -> Self {
//         self.append_transaction_to_batch_params = params.clone();
//         self
//     }
//
//     pub fn submit_batch_params(mut self, params: &Arc<Mutex<Vec<Web3<Batch<T>>>>>) -> Self {
//         self.submit_batch_params = params.clone();
//         self
//     }
//
//     pub fn submit_batch_result(
//         self,
//         result: Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>,
//     ) -> Self {
//         self.submit_batch_results.borrow_mut().push(result);
//         self
//     }
// }

// pub fn make_default_signed_transaction() -> SignedTransaction {
//     SignedTransaction {
//         message_hash: Default::default(),
//         v: 0,
//         r: Default::default(),
//         s: Default::default(),
//         raw_transaction: Default::default(),
//         transaction_hash: Default::default(),
//     }
// }
