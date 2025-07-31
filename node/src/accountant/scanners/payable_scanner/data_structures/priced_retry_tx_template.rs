use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::{
    RetryTxTemplate, RetryTxTemplates,
};
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedRetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_nonce: u64,
    pub computed_gas_price_wei: u128,
}

impl PricedRetryTxTemplate {
    pub fn new(unpriced_retry_template: RetryTxTemplate, computed_gas_price_wei: u128) -> Self {
        Self {
            base: unpriced_retry_template.base,
            prev_nonce: unpriced_retry_template.prev_nonce,
            computed_gas_price_wei,
        }
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

impl PricedRetryTxTemplates {
    pub fn total_gas_price(&self) -> u128 {
        self.iter()
            .map(|retry_tx_template| retry_tx_template.computed_gas_price_wei)
            .sum()
    }
}
