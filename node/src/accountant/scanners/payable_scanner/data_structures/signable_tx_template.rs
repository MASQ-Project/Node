use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use itertools::Either;
use std::ops::Deref;
use web3::types::Address;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignableTxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
    pub gas_price_wei: u128,
    pub nonce: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignableTxTemplates(pub Vec<SignableTxTemplate>);

impl SignableTxTemplates {
    pub fn new(
        priced_tx_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
        latest_nonce: u64,
    ) -> Self {
        todo!()
    }

    pub fn first_nonce(&self) -> u64 {
        todo!()
    }

    pub fn last_nonce(&self) -> u64 {
        todo!()
    }

    pub fn largest_amount(&self) -> u128 {
        todo!()

        // let largest_amount = signable_tx_templates
        //     .iter()
        //     .map(|signable_tx_template| signable_tx_template.amount_in_wei)
        //     .max()
        //     .unwrap();
    }
}

impl Deref for SignableTxTemplates {
    type Target = Vec<SignableTxTemplate>;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}
