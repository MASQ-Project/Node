// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use ethereum_types::U256;
use masq_lib::percentage::Percentage;
use std::cell::RefCell;

#[derive(Default)]
pub struct BlockchainAgentMock {
    estimated_transaction_fee_per_transaction_minor_results: RefCell<Vec<u128>>,
    transaction_fee_balance_minor_results: RefCell<Vec<U256>>,
    service_fee_balance_minor_results: RefCell<Vec<u128>>,
    agreed_fee_per_computation_unit_results: RefCell<Vec<u64>>,
    agreed_transaction_fee_margin: RefCell<Vec<Percentage>>,
    consuming_wallet_result_opt: Option<Wallet>,
    pending_transaction_id_results: RefCell<Vec<U256>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl BlockchainAgent for BlockchainAgentMock {
    fn estimated_transaction_fee_per_transaction_minor(&self) -> u128 {
        self.estimated_transaction_fee_per_transaction_minor_results
            .borrow_mut()
            .remove(0)
    }

    fn transaction_fee_balance_minor(&self) -> U256 {
        self.transaction_fee_balance_minor_results
            .borrow_mut()
            .remove(0)
    }

    fn service_fee_balance_minor(&self) -> u128 {
        self.service_fee_balance_minor_results
            .borrow_mut()
            .remove(0)
    }

    fn agreed_fee_per_computation_unit(&self) -> u64 {
        self.agreed_fee_per_computation_unit_results
            .borrow_mut()
            .remove(0)
    }

    fn agreed_transaction_fee_margin(&self) -> Percentage {
        self.agreed_transaction_fee_margin.borrow_mut().remove(0)
    }

    fn consuming_wallet(&self) -> &Wallet {
        self.consuming_wallet_result_opt.as_ref().unwrap()
    }

    fn pending_transaction_id(&self) -> U256 {
        self.pending_transaction_id_results.borrow_mut().remove(0)
    }

    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl BlockchainAgentMock {
    pub fn estimated_transaction_fee_per_transaction_minor_result(self, result: u128) -> Self {
        self.estimated_transaction_fee_per_transaction_minor_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn transaction_fee_balance_minor_result(self, result: U256) -> Self {
        self.transaction_fee_balance_minor_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn service_fee_balance_minor_result(self, result: u128) -> Self {
        self.service_fee_balance_minor_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn agreed_fee_per_computation_unit_result(self, result: u64) -> Self {
        self.agreed_fee_per_computation_unit_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn agreed_transaction_fee_margin_result(self, result: Percentage) -> Self {
        self.agreed_transaction_fee_margin.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_result(mut self, consuming_wallet_result: Wallet) -> Self {
        self.consuming_wallet_result_opt = Some(consuming_wallet_result);
        self
    }

    pub fn pending_transaction_id_result(self, result: U256) -> Self {
        self.pending_transaction_id_results
            .borrow_mut()
            .push(result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}
