// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainResult, PayableTransactionError,
    ProcessedPayableFallible, ResultForBalance, ResultForNonce, ResultForReceipt,
    REQUESTS_IN_PARALLEL,
};
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::{BigEndianHash, H256};
use futures::future::{err, result};
use futures::Future;
use jsonrpc_core as rpc;
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use masq_lib::blockchains::chains::Chain;
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
    send_payables_within_batch_params: Arc<
        Mutex<
            Vec<(
                Wallet,
                u64,
                U256,
                Recipient<PendingPayableFingerprintSeeds>,
                Vec<PayableAccount>,
            )>,
        >,
    >,
    send_payables_within_batch_results:
        RefCell<Vec<Result<Vec<ProcessedPayableFallible>, PayableTransactionError>>>,
    get_transaction_fee_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_fee_balance_results: RefCell<Vec<ResultForBalance>>,
    get_token_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_token_balance_results: RefCell<Vec<ResultForBalance>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results: RefCell<Vec<ResultForReceipt>>,
    contract_address_results: RefCell<Vec<Address>>,
    get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
    get_chain_results: RefCell<Vec<Chain>>,
    get_batch_web3_results: RefCell<Vec<Web3<Batch<TestTransport>>>>,
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        self.contract_address_results.borrow_mut().remove(0)
    }

    fn get_chain(&self) -> Chain {
        self.get_chain_results.borrow_mut().remove(0)
    }

    fn get_batch_web3(&self) -> Web3<Batch<TestTransport>> {
        self.get_batch_web3_results.borrow_mut().remove(0)
    }

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        self.retrieve_transactions_parameters
            .lock()
            .unwrap()
            .push((start_block, recipient.clone()));
        Box::new(result(
            self.retrieve_transactions_results.borrow_mut().remove(0),
        ))
    }

    fn get_transaction_fee_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        self.get_transaction_fee_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        Box::new(result(
            self.get_transaction_fee_balance_results
                .borrow_mut()
                .remove(0),
        ))
    }

    fn get_token_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        self.get_token_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        Box::new(result(
            self.get_token_balance_results.borrow_mut().remove(0),
        ))
    }

    fn get_transaction_count(
        &self,
        wallet: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        self.get_transaction_count_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());
        Box::new(result(
            self.get_transaction_count_results.borrow_mut().remove(0),
        ))
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.get_transaction_receipt_params
            .lock()
            .unwrap()
            .push(hash);
        self.get_transaction_receipt_results.borrow_mut().remove(0)
    }
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
        params: &Arc<
            Mutex<
                Vec<(
                    Wallet,
                    u64,
                    U256,
                    Recipient<PendingPayableFingerprintSeeds>,
                    Vec<PayableAccount>,
                )>,
            >,
        >,
    ) -> Self {
        self.send_payables_within_batch_params = params.clone();
        self
    }

    pub fn send_payables_within_batch_result(
        self,
        result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
    ) -> Self {
        self.send_payables_within_batch_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_transaction_fee_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_fee_balance_params = params.clone();
        self
    }

    pub fn get_chain_result(self, result: Chain) -> Self {
        self.get_chain_results.borrow_mut().push(result);
        self
    }

    pub fn get_batch_web3_result(self, result: Web3<Batch<TestTransport>>) -> Self {
        self.get_batch_web3_results.borrow_mut().push(result);
        self
    }

    pub fn get_transaction_fee_balance_result(self, result: ResultForBalance) -> Self {
        self.get_transaction_fee_balance_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_token_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_token_balance_params = params.clone();
        self
    }

    pub fn get_token_balance_result(self, result: ResultForBalance) -> Self {
        self.get_token_balance_results.borrow_mut().push(result);
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

    pub fn get_transaction_receipt_result(self, result: ResultForReceipt) -> Self {
        self.get_transaction_receipt_results
            .borrow_mut()
            .push(result);
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestTransport {
    // neither prepare_results or send_results can be effectively implemented the traditional way,
    // their queue would never progress and would return always the first prepared result despite
    // taking multiple calls; the reason is that the Web3 library tends to clone (!!) the transport
    // and by doing that, removing one element affects just the current clone, and next time an intact
    // version of the same full queue will come in again as another individualistic clone
    prepare_params: Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>,
    send_params: Arc<Mutex<Vec<(RequestId, rpc::Call)>>>,
    send_results: RefCell<VecDeque<rpc::Value>>,
    send_batch_params: Arc<Mutex<Vec<Vec<(RequestId, rpc::Call)>>>>,
    send_batch_results: RefCell<Vec<Vec<Result<rpc::Value, web3::Error>>>>,
    //to check inheritance from a certain descendant, be proving a relation with reference counting
    reference_counter_opt: Option<Arc<()>>,
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
        self.send_params.lock().unwrap().push((id, request.clone()));
        match self.send_results.borrow_mut().pop_front() {
            Some(response) => Box::new(futures::finished(response)),
            None => {
                println!("Unexpected request (id: {:?}): {:?}", id, request);
                Box::new(futures::failed(Web3Error::Unreachable))
            }
        }
    }
}

impl BatchTransport for TestTransport {
    type Batch = web3::Result<Vec<Result<rpc::Value, web3::Error>>>;

    fn send_batch<T>(&self, requests: T) -> Self::Batch
    where
        T: IntoIterator<Item = (RequestId, rpc::Call)>,
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

    //why prepare_result missing? Look up for a comment at the struct

    pub fn send_params(mut self, params: &Arc<Mutex<Vec<(RequestId, rpc::Call)>>>) -> Self {
        self.send_params = params.clone();
        self
    }

    pub fn send_result(self, rpc_call_response: rpc::Value) -> Self {
        self.send_results.borrow_mut().push_back(rpc_call_response);
        self
    }

    pub fn send_batch_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<(RequestId, rpc::Call)>>>>,
    ) -> Self {
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

    pub fn initiate_reference_counter(mut self, reference_arc: &Arc<()>) -> Self {
        self.reference_counter_opt = Some(reference_arc.clone());
        self
    }
}

pub fn make_fake_event_loop_handle() -> EventLoopHandle {
    Http::with_max_parallel("http://86.75.30.9", REQUESTS_IN_PARALLEL)
        .unwrap()
        .0
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
