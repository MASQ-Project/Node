// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::join_with_separator;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::{
    RetryTxTemplate, RetryTxTemplates,
};
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
use masq_lib::logger::Logger;
use std::ops::{Deref, DerefMut};
use thousands::Separable;
use web3::types::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedRetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_nonce: u64,
    pub computed_gas_price_wei: u128,
}

impl PricedRetryTxTemplate {
    pub fn new(initial: RetryTxTemplate, computed_gas_price_wei: u128) -> Self {
        Self {
            base: initial.base,
            prev_nonce: initial.prev_nonce,
            computed_gas_price_wei,
        }
    }

    fn create_and_update_log_data(
        retry_tx_template: RetryTxTemplate,
        latest_gas_price_wei: u128,
        ceil: u128,
        log_builder: &mut RetryLogBuilder,
    ) -> PricedRetryTxTemplate {
        let receiver = retry_tx_template.base.receiver_address;
        let computed_gas_price_wei =
            Self::compute_gas_price(retry_tx_template.prev_gas_price_wei, latest_gas_price_wei);

        let safe_gas_price_wei = if computed_gas_price_wei > ceil {
            log_builder.push(receiver, computed_gas_price_wei);
            ceil
        } else {
            computed_gas_price_wei
        };

        PricedRetryTxTemplate::new(retry_tx_template, safe_gas_price_wei)
    }

    fn compute_gas_price(latest_gas_price_wei: u128, prev_gas_price_wei: u128) -> u128 {
        let gas_price_wei = latest_gas_price_wei.max(prev_gas_price_wei);

        increase_gas_price_by_margin(gas_price_wei)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PricedRetryTxTemplates(pub Vec<PricedRetryTxTemplate>);

impl Deref for PricedRetryTxTemplates {
    type Target = Vec<PricedRetryTxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PricedRetryTxTemplates {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<PricedRetryTxTemplate> for PricedRetryTxTemplates {
    fn from_iter<I: IntoIterator<Item = PricedRetryTxTemplate>>(iter: I) -> Self {
        PricedRetryTxTemplates(iter.into_iter().collect())
    }
}

impl PricedRetryTxTemplates {
    pub fn from_initial_with_logging(
        initial_templates: RetryTxTemplates,
        latest_gas_price_wei: u128,
        ceil: u128,
        logger: &Logger,
    ) -> Self {
        let mut log_builder = RetryLogBuilder::new(initial_templates.len(), ceil);

        let templates = initial_templates
            .into_iter()
            .map(|retry_tx_template| {
                PricedRetryTxTemplate::create_and_update_log_data(
                    retry_tx_template,
                    latest_gas_price_wei,
                    ceil,
                    &mut log_builder,
                )
            })
            .collect();

        log_builder.build().map(|log_msg| {
            warning!(logger, "{}", log_msg);
        });

        templates
    }

    pub fn total_gas_price(&self) -> u128 {
        self.iter()
            .map(|retry_tx_template| retry_tx_template.computed_gas_price_wei)
            .sum()
    }

    pub fn reorder_by_nonces(mut self, latest_nonce: u64) -> Self {
        // TODO: This algorithm could be made more robust by including un-realistic permutations of tx nonces
        self.sort_by_key(|template| template.prev_nonce);

        let split_index = self
            .iter()
            .position(|template| template.prev_nonce == latest_nonce)
            .unwrap_or(0);

        let (left, right) = self.split_at(split_index);

        Self([right, left].concat())
    }
}

pub struct RetryLogBuilder {
    log_data: Vec<(Address, u128)>,
    ceil: u128,
}

impl RetryLogBuilder {
    fn new(capacity: usize, ceil: u128) -> Self {
        Self {
            log_data: Vec::with_capacity(capacity),
            ceil,
        }
    }

    fn push(&mut self, address: Address, gas_price: u128) {
        self.log_data.push((address, gas_price));
    }

    fn build(&self) -> Option<String> {
        if self.log_data.is_empty() {
            None
        } else {
            Some(format!(
                "The computed gas price(s) in wei is \
                 above the ceil value of {} wei set by the Node.\n\
                 Transaction(s) to following receivers are affected:\n\
                 {}",
                self.ceil.separate_with_commas(),
                join_with_separator(
                    &self.log_data,
                    |(address, gas_price)| format!(
                        "{:?} with gas price {}",
                        address,
                        gas_price.separate_with_commas()
                    ),
                    "\n"
                )
            ))
        }
    }
}
