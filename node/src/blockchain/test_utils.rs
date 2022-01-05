// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_interface::{
    Balance, BlockchainError, BlockchainInterface, BlockchainResult, Nonce, Transaction,
    Transactions,
};
use crate::blockchain::tool_wrappers::{
    SendTransactionToolsWrapper, SendTransactionToolsWrapperNull,
};
use crate::sub_lib::wallet::Wallet;
use bip39::{Language, Mnemonic, Seed};
use jsonrpc_core as rpc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use web3::types::{Address, H256, U256};
use web3::{Error, RequestId, Transport};

pub fn make_meaningless_phrase() -> String {
    "phrase donate agent satoshi burst end company pear obvious achieve depth advice".to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}

#[derive(Debug, Default)]
pub struct BlockchainInterfaceMock {
    pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
    pub retrieve_transactions_results: RefCell<Vec<BlockchainResult<Vec<Transaction>>>>,
    pub send_transaction_parameters: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    pub send_transaction_results: RefCell<Vec<BlockchainResult<H256>>>,
    pub contract_address_results: RefCell<Vec<Address>>,
    pub get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
    pub get_transaction_count_results: RefCell<Vec<Nonce>>,
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(mut self, params: &Arc<Mutex<Vec<(u64, Wallet)>>>) -> Self {
        self.retrieve_transactions_parameters = params.clone();
        self
    }

    pub fn retrieve_transactions_result(
        self,
        result: Result<Vec<Transaction>, BlockchainError>,
    ) -> Self {
        self.retrieve_transactions_results.borrow_mut().push(result);
        self
    }

    pub fn send_transaction_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    ) -> Self {
        self.send_transaction_parameters = params.clone();
        self
    }

    pub fn send_transaction_result(self, result: BlockchainResult<H256>) -> Self {
        self.send_transaction_results.borrow_mut().push(result);
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

    pub fn get_transaction_count_result(self, result: Nonce) -> Self {
        self.get_transaction_count_results.borrow_mut().push(result);
        self
    }
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        self.contract_address_results.borrow_mut().remove(0)
    }

    fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
        self.retrieve_transactions_parameters
            .lock()
            .unwrap()
            .push((start_block, recipient.clone()));
        self.retrieve_transactions_results.borrow_mut().remove(0)
    }

    fn send_transaction<'a>(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
        _send_transaction_tools: &'a dyn SendTransactionToolsWrapper,
    ) -> BlockchainResult<H256> {
        self.send_transaction_parameters.lock().unwrap().push((
            consuming_wallet.clone(),
            recipient.clone(),
            amount,
            nonce,
            gas_price,
        ));
        self.send_transaction_results.borrow_mut().remove(0)
    }

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

    fn send_transaction_tools<'a>(&'a self) -> Box<dyn SendTransactionToolsWrapper + 'a> {
        Box::new(SendTransactionToolsWrapperNull)
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestTransport {
    asserted: usize,
    requests: Rc<RefCell<Vec<(String, Vec<rpc::Value>)>>>,
    responses: Rc<RefCell<VecDeque<rpc::Value>>>,
}

impl Transport for TestTransport {
    type Out = web3::Result<rpc::Value>;

    fn prepare(&self, method: &str, params: Vec<rpc::Value>) -> (RequestId, rpc::Call) {
        let request = web3::helpers::build_request(1, method, params.clone());
        self.requests.borrow_mut().push((method.into(), params));
        (self.requests.borrow().len(), request)
    }

    fn send(&self, id: RequestId, request: rpc::Call) -> Self::Out {
        match self.responses.borrow_mut().pop_front() {
            Some(response) => Box::new(futures::finished(response)),
            None => {
                println!("Unexpected request (id: {:?}): {:?}", id, request);
                Box::new(futures::failed(Error::Unreachable))
            }
        }
    }
}

impl TestTransport {
    pub fn add_response(&mut self, value: rpc::Value) {
        self.responses.borrow_mut().push_back(value);
    }

    pub fn assert_request(&mut self, method: &str, params: &[String]) {
        let idx = self.asserted;
        self.asserted += 1;

        let (m, p) = self
            .requests
            .borrow()
            .get(idx)
            .expect("Expected result.")
            .clone();
        assert_eq!(&m, method);
        let p: Vec<String> = p
            .into_iter()
            .map(|p| serde_json::to_string(&p).unwrap())
            .collect();
        assert_eq!(p, params);
    }

    pub fn assert_no_more_requests(&mut self) {
        let requests = self.requests.borrow();
        assert_eq!(
            self.asserted,
            requests.len(),
            "Expected no more requests, got: {:?}",
            &requests[self.asserted..]
        );
    }
}
