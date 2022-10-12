// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_bridge::{InitiatePPFingerprints, PendingPayableFingerprint};
use crate::blockchain::blockchain_interface::{
    Balance, BlockchainError, BlockchainInterface, BlockchainResult, Nonce,
    PayableTransactionError, PendingPayableFallible, Receipt, REQUESTS_IN_PARALLEL,
};
use crate::blockchain::tool_wrappers::BatchedPayableTools;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::{BigEndianHash, H256};
use jsonrpc_core as rpc;
use jsonrpc_core::Call;
use lazy_static::lazy_static;
use rusqlite::params;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::accountant::payable_dao::PayableAccount;
use web3::transports::{Batch, EventLoopHandle, Http};
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, U256};
use web3::{BatchTransport, Error as Web3Error, Web3};
use web3::{RequestId, Transport};

use crate::blockchain::blockchain_interface::RetrievedBlockchainTransactions;

lazy_static! {
    static ref BIG_MEANINGLESS_PHRASE: Vec<&'static str> = vec![
        "parent", "prevent", "vehicle", "tooth", "crazy", "cruel", "update", "mango", "female",
        "mad", "spread", "plunge", "tiny", "inch", "under", "engine", "enforce", "film", "awesome",
        "plunge", "cloud", "spell", "empower", "pipe",
    ];
}

pub fn make_meaningless_phrase_words() -> Vec<String> {
    BIG_MEANINGLESS_PHRASE
        .iter()
        .map(|word| word.to_string())
        .collect()
}

pub fn make_meaningless_phrase() -> String {
    make_meaningless_phrase_words().join(" ").to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}

#[derive(Default)]
pub struct BlockchainInterfaceMock {
    retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
    retrieve_transactions_results:
        RefCell<Vec<Result<RetrievedBlockchainTransactions, BlockchainError>>>,
    send_payables_within_batch_params: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    send_payables_within_batch_results:
        RefCell<Vec<Result<(H256, SystemTime), PayableTransactionError>>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results: RefCell<Vec<Receipt>>,
    contract_address_results: RefCell<Vec<Address>>,
    get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(mut self, params: &Arc<Mutex<Vec<(u64, Wallet)>>>) -> Self {
        self.retrieve_transactions_parameters = params.clone();
        self
    }

    pub fn retrieve_transactions_result(
        self,
        result: Result<RetrievedBlockchainTransactions, BlockchainError>,
    ) -> Self {
        self.retrieve_transactions_results.borrow_mut().push(result);
        self
    }

    pub fn send_payables_within_batch_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    ) -> Self {
        self.send_payables_within_batch_params = params.clone();
        self
    }

    pub fn send_payables_within_batch_result(
        self,
        result: Result<(H256, SystemTime), PayableTransactionError>,
    ) -> Self {
        self.send_payables_within_batch_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn contract_address_result(self, address: Address) -> Self {
        self.contract_address_results.borrow_mut().push(address);
        self
    }

    pub fn get_transaction_count_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_count_parameters = params.clone();
        self
    }

    pub fn get_transaction_count_result(self, result: BlockchainResult<U256>) -> Self {
        self.get_transaction_count_results.borrow_mut().push(result);
        self
    }

    pub fn get_transaction_receipt_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
        self.get_transaction_receipt_params = params.clone();
        self
    }

    pub fn get_transaction_receipt_result(self, result: Receipt) -> Self {
        self.get_transaction_receipt_results
            .borrow_mut()
            .push(result);
        self
    }
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        self.contract_address_results.borrow_mut().remove(0)
    }

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        self.retrieve_transactions_parameters
            .lock()
            .unwrap()
            .push((start_block, recipient.clone()));
        self.retrieve_transactions_results.borrow_mut().remove(0)
    }

    fn send_payables_within_batch(
        &self,
        consuming_wallet: &Wallet,
        gas_price: u64,
        last_nonce: U256,
        fingerprint_recipient: &Recipient<InitiatePPFingerprints>,
        accounts: Vec<PayableAccount>,
    ) -> Result<(SystemTime, Vec<PendingPayableFallible>), PayableTransactionError> {
        todo!()
    }

    // fn send_transaction<'b>(
    //     &self,
    //     inputs: SendTransactionInputs,
    // ) -> Result<(H256, SystemTime), BlockchainTransactionError> {
    //     self.send_transaction_parameters
    //         .lock()
    //         .unwrap()
    //         .push(inputs.abstract_for_assertions());
    //     self.send_transaction_results.borrow_mut().remove(0)
    // }

    fn get_eth_balance(&self, _address: &Wallet) -> Balance {
        unimplemented!()
    }

    fn get_token_balance(&self, _address: &Wallet) -> Balance {
        unimplemented!()
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
        self.get_transaction_count_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());
        self.get_transaction_count_results.borrow_mut().remove(0)
    }

    fn get_transaction_receipt(&self, hash: H256) -> Receipt {
        self.get_transaction_receipt_params
            .lock()
            .unwrap()
            .push(hash);
        self.get_transaction_receipt_results.borrow_mut().remove(0)
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestTransport {
    asserted: usize,
    prepare_params: Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>,
    send_params: Arc<Mutex<Vec<(RequestId, Call)>>>,
    send_results: RefCell<Vec<rpc::Value>>,
    send_batch_params: Arc<Mutex<Vec<Vec<(RequestId, Call)>>>>,
    send_batch_results: RefCell<Vec<Vec<Result<rpc::Value, web3::Error>>>>,
}

impl Transport for TestTransport {
    type Out = web3::Result<rpc::Value>;

    fn prepare(&self, method: &str, params: Vec<rpc::Value>) -> (RequestId, rpc::Call) {
        let request = web3::helpers::build_request(1, method, params.clone());
        let mut prepare_params = self.prepare_params.lock().unwrap();
        prepare_params.push((method.to_string(), params));
        (prepare_params.len(), request)
    }

    fn send(&self, id: RequestId, request: rpc::Call) -> Self::Out {
        todo!("drive me in again")
        // match self.responses.borrow_mut().pop_front() {
        //     Some(response) => Box::new(futures::finished(response)),
        //     None => {
        //         println!("Unexpected request (id: {:?}): {:?}", id, request);
        //         Box::new(futures::failed(Web3Error::Unreachable))
        //     }
        // }
    }
}

impl BatchTransport for TestTransport {
    type Batch = web3::Result<Vec<Result<rpc::Value, web3::Error>>>;

    fn send_batch<T>(&self, requests: T) -> Self::Batch
    where
        T: IntoIterator<Item = (RequestId, Call)>,
    {
        self.send_batch_params
            .lock()
            .unwrap()
            .push(requests.into_iter().collect());
        let response = self.send_batch_results.borrow_mut().remove(0);
        Box::new(futures::finished(response))
    }
}

impl TestTransport {
    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn send_result(self, rpc_call_response: rpc::Value) -> Self {
        self.send_results.borrow_mut().push(rpc_call_response);
        self
    }

    pub fn send_batch_params(mut self, params: &Arc<Mutex<Vec<Vec<(RequestId, Call)>>>>) -> Self {
        self.send_batch_params = params.clone();
        self
    }

    pub fn send_batch_result(
        self,
        batched_responses: Vec<Result<rpc::Value, web3::Error>>,
    ) -> Self {
        self.send_batch_results.borrow_mut().push(batched_responses);
        self
    }
}

pub fn make_fake_event_loop_handle() -> EventLoopHandle {
    Http::with_max_parallel("http://86.75.30.9", REQUESTS_IN_PARALLEL)
        .unwrap()
        .0
}

#[derive(Default)]
pub struct SendTransactionToolWrapperFactoryMock<T> {
    make_results: RefCell<Vec<Box<dyn BatchedPayableTools<T>>>>,
}

impl<T> SendTransactionToolWrapperFactoryMock<T> {
    pub fn make_result(self, result: Box<dyn BatchedPayableTools<T>>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct BatchedPayableToolsMock<T: BatchTransport> {
    sign_transaction_params:
        Arc<Mutex<Vec<(TransactionParameters, secp256k1secrets::key::SecretKey)>>>,
    sign_transaction_results: RefCell<Vec<Result<SignedTransaction, Web3Error>>>,
    system_wide_timestamp_results: RefCell<Vec<SystemTime>>,
    request_new_pending_payable_fingerprint_params: Arc<
        Mutex<
            Vec<(
                SystemTime,
                Recipient<InitiatePPFingerprints>,
                Vec<(H256, u64)>,
            )>,
        >,
    >,
    request_new_pending_payable_fingerprint_results: RefCell<Vec<SystemTime>>,
    send_batch_params: Arc<Mutex<Vec<Web3<Batch<T>>>>>,
    send_batch_results: RefCell<Vec<Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>>>,
}

impl<T: BatchTransport> BatchedPayableTools<T> for BatchedPayableToolsMock<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.sign_transaction_params
            .lock()
            .unwrap()
            .push((transaction_params.clone(), key.clone()));
        self.sign_transaction_results.borrow_mut().remove(0)
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        self.system_wide_timestamp_results.borrow_mut().remove(0)
    }

    fn new_payable_fingerprints(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<InitiatePPFingerprints>,
        payable_attributes: &[(H256, u64)],
    ) {
        self.request_new_pending_payable_fingerprint_params
            .lock()
            .unwrap()
            .push((
                batch_wide_timestamp,
                (*pp_fingerprint_sub).clone(),
                payable_attributes.to_vec(),
            ));
    }

    fn send_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
        self.send_batch_params.lock().unwrap().push(web3.clone());
        self.send_batch_results.borrow_mut().remove(0)
    }
}

impl<T: BatchTransport> BatchedPayableToolsMock<T> {
    pub fn sign_transaction_params(
        mut self,
        params: &Arc<Mutex<Vec<(TransactionParameters, secp256k1secrets::key::SecretKey)>>>,
    ) -> Self {
        self.sign_transaction_params = params.clone();
        self
    }
    pub fn sign_transaction_result(self, result: Result<SignedTransaction, Web3Error>) -> Self {
        self.sign_transaction_results.borrow_mut().push(result);
        self
    }

    pub fn batch_wide_timestamp_result(self, result: SystemTime) -> Self {
        self.system_wide_timestamp_results.borrow_mut().push(result);
        self
    }

    pub fn request_new_pending_payable_fingerprint_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    SystemTime,
                    Recipient<InitiatePPFingerprints>,
                    Vec<(H256, u64)>,
                )>,
            >,
        >,
    ) -> Self {
        self.request_new_pending_payable_fingerprint_params = params.clone();
        self
    }

    pub fn send_batch_params(mut self, params: &Arc<Mutex<Vec<Web3<Batch<T>>>>>) -> Self {
        self.send_batch_params = params.clone();
        self
    }
    pub fn send_batch_result(
        self,
        result: Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>,
    ) -> Self {
        self.send_batch_results.borrow_mut().push(result);
        self
    }
}

pub fn make_default_signed_transaction() -> SignedTransaction {
    SignedTransaction {
        message_hash: Default::default(),
        v: 0,
        r: Default::default(),
        s: Default::default(),
        raw_transaction: Default::default(),
        transaction_hash: Default::default(),
    }
}

pub fn make_tx_hash(base: u32) -> H256 {
    H256::from_uint(&U256::from(base))
}
