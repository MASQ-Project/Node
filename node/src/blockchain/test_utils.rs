// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use bip39::{Language, Mnemonic, Seed};
use jsonrpc_core as rpc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use web3::{Error, RequestId, Transport};

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
