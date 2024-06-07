// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_interface::lower_level_interface::{
    LatestBlockNumber, LowBlockchainInt, ResultForBalance, ResultForNonce,
};
use crate::sub_lib::wallet::Wallet;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct LowBlockchainIntMock {
    get_transaction_fee_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_fee_balance_results: RefCell<Vec<ResultForBalance>>,
    get_masq_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_masq_balance_results: RefCell<Vec<ResultForBalance>>,
    get_block_number_results: RefCell<Vec<LatestBlockNumber>>,
    get_transaction_id_params: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_id_results: RefCell<Vec<ResultForNonce>>,
}

impl LowBlockchainInt for LowBlockchainIntMock {
    fn get_transaction_fee_balance(&self, address: &Wallet) -> ResultForBalance {
        self.get_transaction_fee_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        self.get_transaction_fee_balance_results
            .borrow_mut()
            .remove(0)
    }

    fn get_service_fee_balance(&self, address: &Wallet) -> ResultForBalance {
        self.get_masq_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        self.get_masq_balance_results.borrow_mut().remove(0)
    }

    fn get_block_number(&self) -> LatestBlockNumber {
        self.get_block_number_results.borrow_mut().remove(0)
    }

    fn get_transaction_id(&self, address: &Wallet) -> ResultForNonce {
        self.get_transaction_id_params
            .lock()
            .unwrap()
            .push(address.clone());
        self.get_transaction_id_results.borrow_mut().remove(0)
    }

    fn dup(&self) -> Box<dyn LowBlockchainInt> {
        todo!()
    }
}

impl LowBlockchainIntMock {
    pub fn get_transaction_fee_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_fee_balance_params = params.clone();
        self
    }

    pub fn get_transaction_fee_balance_result(self, result: ResultForBalance) -> Self {
        self.get_transaction_fee_balance_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_masq_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_masq_balance_params = params.clone();
        self
    }

    pub fn get_masq_balance_result(self, result: ResultForBalance) -> Self {
        self.get_masq_balance_results.borrow_mut().push(result);
        self
    }

    pub fn get_block_number_result(self, result: LatestBlockNumber) -> Self {
        self.get_block_number_results.borrow_mut().push(result);
        self
    }

    pub fn get_transaction_id_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_id_params = params.clone();
        self
    }

    pub fn get_transaction_id_result(self, result: ResultForNonce) -> Self {
        self.get_transaction_id_results.borrow_mut().push(result);
        self
    }
}

// pub fn test_blockchain_interface_is_connected_and_functioning(port: u16, chain: Chain) {
//     // let port = find_free_port();
//     let test_server = TestServer::start(
//         port,
//         vec![br#"{"jsonrpc":"2.0","id":0,"result":someGarbage}"#.to_vec()],
//     );
//     let wallet = make_wallet("123");
//     // let chain = Chain::PolyMainnet;
//     let subject = make_subject() subject_factory(port, chain);
//
//     // no assertion for the result, we anticipate an error from a badly formatted response from the server;
//     // yet enough to prove we have a proper connection
//     let _ = subject.lower_interface().get_service_fee_balance(&wallet);
//
//     let requests = test_server.requests_so_far();
//     let bodies: Vec<Value> = requests
//         .into_iter()
//         .map(|request| serde_json::from_slice(&request.body()).unwrap())
//         .collect();
//     assert_eq!(
//         bodies[0]["params"][0]["data"].to_string()[35..75],
//         wallet.to_string()[2..]
//     );
//     assert_eq!(
//         bodies[0]["params"][0]["to"],
//         format!("{:?}", chain.rec().contract)
//     );
// }
