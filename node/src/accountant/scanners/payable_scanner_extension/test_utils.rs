// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use std::cell::RefCell;

pub struct BlockchainAgentMock {
    consuming_wallet_balances_results: RefCell<Vec<ConsumingWalletBalances>>,
    gas_price_results: RefCell<Vec<u128>>,
    consuming_wallet_result_opt: Option<Wallet>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
    get_chain_result_opt: Option<Chain>,
}

impl Default for BlockchainAgentMock {
    fn default() -> Self {
        BlockchainAgentMock {
            consuming_wallet_balances_results: RefCell::new(vec![]),
            gas_price_results: RefCell::new(vec![]),
            consuming_wallet_result_opt: None,
            arbitrary_id_stamp_opt: None,
            get_chain_result_opt: None,
        }
    }
}

impl BlockchainAgent for BlockchainAgentMock {
    fn price_qualified_payables(
        &self,
        _tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    ) -> Either<NewTxTemplates, RetryTxTemplates> {
        unimplemented!("not needed yet")
    }

    fn estimate_transaction_fee_total(
        &self,
        _tx_templates_with_gas_price: &Either<NewTxTemplates, RetryTxTemplates>,
    ) -> u128 {
        todo!("to be implemented by GH-711")
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        todo!("to be implemented by GH-711")
    }

    fn consuming_wallet(&self) -> &Wallet {
        self.consuming_wallet_result_opt.as_ref().unwrap()
    }

    fn get_chain(&self) -> Chain {
        self.get_chain_result_opt.unwrap()
    }

    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl BlockchainAgentMock {
    pub fn consuming_wallet_balances_result(self, result: ConsumingWalletBalances) -> Self {
        self.consuming_wallet_balances_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn gas_price_result(self, result: u128) -> Self {
        self.gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_result(mut self, consuming_wallet_result: Wallet) -> Self {
        self.consuming_wallet_result_opt = Some(consuming_wallet_result);
        self
    }

    pub fn get_chain_result(mut self, get_chain_result: Chain) -> Self {
        self.get_chain_result_opt = Some(get_chain_result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}
