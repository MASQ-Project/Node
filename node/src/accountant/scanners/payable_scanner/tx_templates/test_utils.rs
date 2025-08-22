// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplate;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::{
    PricedNewTxTemplate, PricedNewTxTemplates,
};
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplate;
use crate::accountant::scanners::payable_scanner::tx_templates::signable::SignableTxTemplate;
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use crate::accountant::test_utils::make_payable_account;
use crate::blockchain::test_utils::make_address;
use masq_lib::constants::DEFAULT_GAS_PRICE;
use web3::types::Address;

pub fn make_priced_new_tx_templates(vec: Vec<(PayableAccount, u128)>) -> PricedNewTxTemplates {
    vec.iter()
        .map(|(payable_account, gas_price_wei)| PricedNewTxTemplate {
            base: BaseTxTemplate::from(payable_account),
            computed_gas_price_wei: *gas_price_wei,
        })
        .collect()
}

pub fn make_priced_new_tx_template(n: u64) -> PricedNewTxTemplate {
    PricedNewTxTemplate {
        base: BaseTxTemplate::from(&make_payable_account(n)),
        computed_gas_price_wei: DEFAULT_GAS_PRICE as u128,
    }
}

pub fn make_priced_retry_tx_template(n: u64) -> PricedRetryTxTemplate {
    PricedRetryTxTemplate {
        base: BaseTxTemplate::from(&make_payable_account(n)),
        prev_nonce: n,
        computed_gas_price_wei: DEFAULT_GAS_PRICE as u128,
    }
}

pub fn make_signable_tx_template(n: u64) -> SignableTxTemplate {
    SignableTxTemplate {
        receiver_address: make_address(1),
        amount_in_wei: n as u128 * 1000,
        gas_price_wei: n as u128 * 100,
        nonce: n,
    }
}

pub fn make_retry_tx_template(n: u32) -> RetryTxTemplate {
    RetryTxTemplateBuilder::new()
        .receiver_address(make_address(n))
        .amount_in_wei(n as u128 * 1000)
        .prev_gas_price_wei(n as u128 * 100)
        .prev_nonce(n as u64)
        .build()
}

#[derive(Default)]
pub struct RetryTxTemplateBuilder {
    receiver_address_opt: Option<Address>,
    amount_in_wei_opt: Option<u128>,
    prev_gas_price_wei_opt: Option<u128>,
    prev_nonce_opt: Option<u64>,
}

impl RetryTxTemplateBuilder {
    pub fn new() -> Self {
        RetryTxTemplateBuilder::default()
    }

    pub fn receiver_address(mut self, address: Address) -> Self {
        self.receiver_address_opt = Some(address);
        self
    }

    pub fn amount_in_wei(mut self, amount: u128) -> Self {
        self.amount_in_wei_opt = Some(amount);
        self
    }

    pub fn prev_gas_price_wei(mut self, gas_price: u128) -> Self {
        self.prev_gas_price_wei_opt = Some(gas_price);
        self
    }

    pub fn prev_nonce(mut self, nonce: u64) -> Self {
        self.prev_nonce_opt = Some(nonce);
        self
    }

    pub fn payable_account(mut self, payable_account: &PayableAccount) -> Self {
        self.receiver_address_opt = Some(payable_account.wallet.address());
        self.amount_in_wei_opt = Some(payable_account.balance_wei);
        self
    }

    pub fn build(self) -> RetryTxTemplate {
        RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: self.receiver_address_opt.unwrap_or_else(|| make_address(0)),
                amount_in_wei: self.amount_in_wei_opt.unwrap_or(0),
            },
            prev_gas_price_wei: self.prev_gas_price_wei_opt.unwrap_or(0),
            prev_nonce: self.prev_nonce_opt.unwrap_or(0),
        }
    }
}
