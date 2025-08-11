use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::{
    NewTxTemplate, NewTxTemplates,
};
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedNewTxTemplate {
    pub base: BaseTxTemplate,
    pub computed_gas_price_wei: u128,
}

impl PricedNewTxTemplate {
    pub fn new(unpriced_tx_template: NewTxTemplate, computed_gas_price_wei: u128) -> Self {
        Self {
            base: unpriced_tx_template.base,
            computed_gas_price_wei,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PricedNewTxTemplates(pub Vec<PricedNewTxTemplate>);

impl Deref for PricedNewTxTemplates {
    type Target = Vec<PricedNewTxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromIterator<PricedNewTxTemplate> for PricedNewTxTemplates {
    fn from_iter<I: IntoIterator<Item = PricedNewTxTemplate>>(iter: I) -> Self {
        PricedNewTxTemplates(iter.into_iter().collect())
    }
}

impl PricedNewTxTemplates {
    pub fn new(
        unpriced_new_tx_templates: NewTxTemplates,
        computed_gas_price_wei: u128,
    ) -> PricedNewTxTemplates {
        // TODO: GH-605: Test me
        let updated_tx_templates = unpriced_new_tx_templates
            .into_iter()
            .map(|new_tx_template| {
                PricedNewTxTemplate::new(new_tx_template, computed_gas_price_wei)
            })
            .collect();

        PricedNewTxTemplates(updated_tx_templates)
    }

    pub fn total_gas_price(&self) -> u128 {
        self.iter()
            .map(|new_tx_template| new_tx_template.computed_gas_price_wei)
            .sum()
    }
}
