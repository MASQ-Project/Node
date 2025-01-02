// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::REQUESTS_IN_PARALLEL;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainAgentBuildError, BlockchainError, PayableTransactionError, ResultForReceipt,
};
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, RetrievedBlockchainTransactions,
};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::blockchain::blockchain_interface::test_utils::LowBlockchainIntMock;
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::set_arbitrary_id_stamp_in_mock_impl;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use actix::Recipient;
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::{BigEndianHash, H256};
use jsonrpc_core as rpc;
use lazy_static::lazy_static;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::to_string;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, BlockNumber, U256};
use web3::{BatchTransport, Error as Web3Error};
use web3::{RequestId, Transport};

lazy_static! {
    static ref BIG_MEANINGLESS_PHRASE: Vec<&'static str> = vec![
        "parent", "prevent", "vehicle", "tooth", "crazy", "cruel", "update", "mango", "female",
        "mad", "spread", "plunge", "tiny", "inch", "under", "engine", "enforce", "film", "awesome",
        "plunge", "cloud", "spell", "empower", "pipe",
    ];
}

pub fn make_meaningless_phrase_words() -> Vec<String> {
    BIG_MEANINGLESS_PHRASE.iter().map(to_string).collect()
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
    retrieve_transactions_parameters: Arc<Mutex<Vec<(BlockNumber, BlockNumber, Wallet)>>>,
    retrieve_transactions_results:
        RefCell<Vec<Result<RetrievedBlockchainTransactions, BlockchainError>>>,
    build_blockchain_agent_params: Arc<Mutex<Vec<(Wallet, ArbitraryIdStamp)>>>,
    build_blockchain_agent_results:
        RefCell<Vec<Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError>>>,
    send_batch_of_payables_params: Arc<
        Mutex<
            Vec<(
                ArbitraryIdStamp,
                Recipient<PendingPayableFingerprintSeeds>,
                Vec<PayableAccount>,
            )>,
        >,
    >,
    send_batch_of_payables_results:
        RefCell<Vec<Result<Vec<ProcessedPayableFallible>, PayableTransactionError>>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results: RefCell<Vec<ResultForReceipt>>,
    lower_interface_result: Option<Box<LowBlockchainIntMock>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        unimplemented!("not needed so far")
    }

    fn retrieve_transactions(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        self.retrieve_transactions_parameters.lock().unwrap().push((
            start_block,
            end_block,
            recipient.clone(),
        ));
        self.retrieve_transactions_results.borrow_mut().remove(0)
    }

    fn build_blockchain_agent(
        &self,
        consuming_wallet: &Wallet,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError> {
        self.build_blockchain_agent_params.lock().unwrap().push((
            consuming_wallet.clone(),
            persistent_config.arbitrary_id_stamp(),
        ));
        self.build_blockchain_agent_results.borrow_mut().remove(0)
    }

    fn send_batch_of_payables(
        &self,
        agent: Box<dyn BlockchainAgent>,
        new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
        self.send_batch_of_payables_params.lock().unwrap().push((
            agent.arbitrary_id_stamp(),
            new_fingerprints_recipient.clone(),
            accounts.to_vec(),
        ));
        self.send_batch_of_payables_results.borrow_mut().remove(0)
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.get_transaction_receipt_params
            .lock()
            .unwrap()
            .push(hash);
        self.get_transaction_receipt_results.borrow_mut().remove(0)
    }

    fn lower_interface(&self) -> &dyn LowBlockchainInt {
        self.lower_interface_result.as_ref().unwrap().as_ref()
    }
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(
        mut self,
        params: &Arc<Mutex<Vec<(BlockNumber, BlockNumber, Wallet)>>>,
    ) -> Self {
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

    pub fn build_blockchain_agent_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, ArbitraryIdStamp)>>>,
    ) -> Self {
        self.build_blockchain_agent_params = params.clone();
        self
    }

    pub fn build_blockchain_agent_result(
        self,
        result: Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError>,
    ) -> Self {
        self.build_blockchain_agent_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn send_batch_of_payables_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    ArbitraryIdStamp,
                    Recipient<PendingPayableFingerprintSeeds>,
                    Vec<PayableAccount>,
                )>,
            >,
        >,
    ) -> Self {
        self.send_batch_of_payables_params = params.clone();
        self
    }

    pub fn send_batch_of_payables_result(
        self,
        result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
    ) -> Self {
        self.send_batch_of_payables_results
            .borrow_mut()
            .push(result);
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

    pub fn lower_interface_results(
        mut self,
        aggregated_results: Box<LowBlockchainIntMock>,
    ) -> Self {
        self.lower_interface_result = Some(aggregated_results);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
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

pub fn make_tx_hash(base: u32) -> H256 {
    H256::from_uint(&U256::from(base))
}

pub fn all_chains() -> [Chain; 4] {
    [
        Chain::EthMainnet,
        Chain::PolyMainnet,
        Chain::PolyAmoy,
        Chain::Dev,
    ]
}
