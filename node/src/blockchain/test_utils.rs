// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_interface::{BlockchainResult, REQUESTS_IN_PARALLEL};
use crate::blockchain::tool_wrappers::{
    NotifyHandle, NotifyLaterHandle, SendTransactionToolWrapper,
};
use actix::{Message, SpawnHandle};
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::H256;
use jsonrpc_core as rpc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Error as Web3Error;
use web3::{RequestId, Transport};

pub fn make_meaningless_phrase() -> String {
    "phrase donate agent satoshi burst end company pear obvious achieve depth advice".to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
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
                Box::new(futures::failed(Web3Error::Unreachable))
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

pub fn make_fake_event_loop_handle() -> EventLoopHandle {
    Http::with_max_parallel("http://86.75.30.9", REQUESTS_IN_PARALLEL)
        .unwrap()
        .0
}

#[derive(Default)]
pub struct SendTransactionToolWrapperFactoryMock {
    make_results: RefCell<Vec<Box<dyn SendTransactionToolWrapper>>>,
}

impl SendTransactionToolWrapperFactoryMock {
    pub fn make_result(self, result: Box<dyn SendTransactionToolWrapper>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default, Debug)]
pub struct SendTransactionToolWrapperMock {
    sign_transaction_params:
        Arc<Mutex<Vec<(TransactionParameters, secp256k1secrets::key::SecretKey)>>>,
    sign_transaction_results: RefCell<Vec<Result<SignedTransaction, Web3Error>>>,
    order_payment_backup_params: Arc<Mutex<Vec<(u16, u64)>>>,
    order_payment_backup_results: RefCell<Vec<SystemTime>>,
    send_raw_transaction_params: Arc<Mutex<Vec<Bytes>>>,
    send_raw_transaction_results: RefCell<Vec<Result<H256, Web3Error>>>,
}

impl SendTransactionToolWrapper for SendTransactionToolWrapperMock {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.sign_transaction_params
            .lock()
            .unwrap()
            .push((transaction_params.clone(), key.clone()));
        self.sign_transaction_results.borrow_mut().remove(0)
    }

    fn order_payment_backup(&self, rowid: u16, amount: u64) -> SystemTime {
        self.order_payment_backup_params
            .lock()
            .unwrap()
            .push((rowid, amount));
        self.order_payment_backup_results.borrow_mut().remove(0)
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
        self.send_raw_transaction_params.lock().unwrap().push(rlp);
        self.send_raw_transaction_results.borrow_mut().remove(0)
    }
}

impl SendTransactionToolWrapperMock {
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

    pub fn order_payment_backup_params(mut self, params: &Arc<Mutex<Vec<(u16, u64)>>>) -> Self {
        self.order_payment_backup_params = params.clone();
        self
    }

    pub fn order_payment_backup_result(self, result: SystemTime) -> Self {
        self.order_payment_backup_results.borrow_mut().push(result);
        self
    }

    pub fn send_raw_transaction_params(mut self, params: &Arc<Mutex<Vec<Bytes>>>) -> Self {
        self.send_raw_transaction_params = params.clone();
        self
    }
    pub fn send_raw_transaction_result(self, result: Result<H256, Web3Error>) -> Self {
        self.send_raw_transaction_results.borrow_mut().push(result);
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

pub struct NotifyLaterHandleMock<T> {
    notify_later_params: Arc<Mutex<Vec<(T, Duration)>>>, //I care only about the params; realize that it's hard to test self addressed messages if you cannot mock yourself
}

impl<T: Message> Default for NotifyLaterHandleMock<T> {
    fn default() -> Self {
        Self {
            notify_later_params: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl<T: Message> NotifyLaterHandleMock<T> {
    pub fn notify_later_params(mut self, params: &Arc<Mutex<Vec<(T, Duration)>>>) -> Self {
        self.notify_later_params = params.clone();
        self
    }
}

impl<T: Message + Clone> NotifyLaterHandle<T> for NotifyLaterHandleMock<T> {
    fn notify_later<'a>(
        &'a self,
        msg: T,
        interval: Duration,
        mut closure: Box<dyn FnMut(T, Duration) -> SpawnHandle + 'a>,
    ) -> SpawnHandle {
        self.notify_later_params
            .lock()
            .unwrap()
            .push((msg.clone(), interval.clone()));
        if !cfg!(test) {
            panic!("this shouldn't run outside a test")
        }
        closure(msg, interval)
    }
}

pub struct NotifyHandleMock<T> {
    notify_params: Arc<Mutex<Vec<T>>>, //I care only about the params; realize that it's hard to test self addressed messages if you cannot mock yourself
}

impl<T: Message> Default for NotifyHandleMock<T> {
    fn default() -> Self {
        Self {
            notify_params: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl<T: Message> NotifyHandleMock<T> {
    pub fn notify_params(mut self, params: &Arc<Mutex<Vec<T>>>) -> Self {
        self.notify_params = params.clone();
        self
    }
}

impl<T: Message + Clone> NotifyHandle<T> for NotifyHandleMock<T> {
    fn notify<'a>(&'a self, msg: T, mut closure: Box<dyn FnMut(T) + 'a>) {
        self.notify_params.lock().unwrap().push(msg.clone());
        if !cfg!(test) {
            panic!("this shouldn't run outside a test")
        }
        closure(msg)
    }
}
