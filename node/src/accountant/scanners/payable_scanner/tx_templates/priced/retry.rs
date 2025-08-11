use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplate;
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use std::ops::{Deref, DerefMut};

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

impl DerefMut for PricedRetryTxTemplates {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PricedRetryTxTemplates {
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
