// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::join_with_separator;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::{
    NewTxTemplate, NewTxTemplates,
};
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
use masq_lib::logger::Logger;
use std::ops::Deref;
use thousands::Separable;

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

// TODO: GH-703: Consider design changes here
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
        let updated_tx_templates = unpriced_new_tx_templates
            .into_iter()
            .map(|new_tx_template| {
                PricedNewTxTemplate::new(new_tx_template, computed_gas_price_wei)
            })
            .collect();

        PricedNewTxTemplates(updated_tx_templates)
    }

    pub fn from_initial_with_logging(
        initial_templates: NewTxTemplates,
        latest_gas_price_wei: u128,
        ceil: u128,
        logger: &Logger,
    ) -> Self {
        let computed_gas_price_wei = increase_gas_price_by_margin(latest_gas_price_wei);

        let safe_gas_price_wei = if computed_gas_price_wei > ceil {
            warning!(
                logger,
                "{}",
                Self::log_ceiling_crossed(&initial_templates, computed_gas_price_wei, ceil)
            );

            ceil
        } else {
            computed_gas_price_wei
        };

        Self::new(initial_templates, safe_gas_price_wei)
    }

    fn log_ceiling_crossed(
        templates: &NewTxTemplates,
        computed_gas_price_wei: u128,
        ceil: u128,
    ) -> String {
        format!(
            "The computed gas price {} wei is above the ceil value of {} wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             {}",
            computed_gas_price_wei.separate_with_commas(),
            ceil.separate_with_commas(),
            join_with_separator(
                templates.iter(),
                |tx_template| format!("{:?}", tx_template.base.receiver_address),
                "\n"
            )
        )
    }

    pub fn total_gas_price(&self) -> u128 {
        self.iter()
            .map(|new_tx_template| new_tx_template.computed_gas_price_wei)
            .sum()
    }
}
