// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_interface::{
    Balance, BlockchainError, BlockchainInterface, BlockchainResult, Nonce, Transaction,
    Transactions,
};
use crate::sub_lib::wallet::Wallet;
use bip39::{Language, Mnemonic, Seed};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use web3::types::{Address, H256, U256};

pub fn make_meaningless_phrase() -> String {
    "phrase donate agent satoshi burst end company pear obvious achieve depth advice".to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(make_meaningless_phrase(), Language::English).unwrap();
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

    fn send_transaction(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
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
}
