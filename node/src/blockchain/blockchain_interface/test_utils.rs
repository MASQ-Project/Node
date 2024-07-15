// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]
use crate::blockchain::blockchain_interface::lower_level_interface::{
    LatestBlockNumber, LowBlockchainInt, ResultForBalance, ResultForNonce,
};
use crate::sub_lib::wallet::Wallet;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use actix::Recipient;
use ethereum_types::{H256, U256, U64};
use futures::Future;
use web3::contract::Contract;
use web3::transports::Http;
use web3::types::{Address, Filter, Log, TransactionReceipt};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainError, PayableTransactionError};
use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible;

#[derive(Default)]
pub struct LowBlockchainIntMock {
    get_transaction_fee_balance_params: Arc<Mutex<Vec<Address>>>,
    get_transaction_fee_balance_results: RefCell<Vec<ResultForBalance>>,
    get_masq_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_masq_balance_results: RefCell<Vec<ResultForBalance>>,
    get_block_number_results: RefCell<Vec<LatestBlockNumber>>,
    get_transaction_id_params: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_id_results: RefCell<Vec<ResultForNonce>>,
}

impl LowBlockchainInt for LowBlockchainIntMock {
    fn get_transaction_fee_balance(&self, address: Address) -> Box<dyn Future<Item=U256, Error=BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_service_fee_balance(&self, address: Address) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_gas_price(&self) -> Box<dyn Future<Item=U256, Error=BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_transaction_id(&self, address: Address) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_transaction_receipt(&self, hash: H256) -> Box<dyn Future<Item = Option<TransactionReceipt>, Error = BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_transaction_receipt_batch(&self, hash_vec: Vec<H256>) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn get_contract(&self) -> Contract<Http> {
        unimplemented!("not needed so far")
    }

    fn get_transaction_logs(&self, filter: Filter) -> Box<dyn Future<Item=Vec<Log>, Error=BlockchainError>> {
        unimplemented!("not needed so far")
    }

    fn submit_payables_in_batch(&self, logger: Logger, chain: Chain, consuming_wallet: Wallet, fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>, affordable_accounts: Vec<PayableAccount>) -> Box<dyn Future<Item=Vec<ProcessedPayableFallible>, Error=PayableTransactionError>> {
        unimplemented!("not needed so far")
    }

}

impl LowBlockchainIntMock {
    pub fn get_transaction_fee_balance_params(mut self, params: &Arc<Mutex<Vec<Address>>>) -> Self {
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