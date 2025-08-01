use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::{
    PricedNewTxTemplate, PricedNewTxTemplates,
};
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

impl FromIterator<SignableTxTemplate> for SignableTxTemplates {
    fn from_iter<I: IntoIterator<Item = SignableTxTemplate>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

// impl From<PricedNewTxTemplates> for SignableTxTemplates {
//     fn from(priced_new_tx_templates: PricedNewTxTemplates) -> Self {
//         todo!()
//     }
// }

impl SignableTxTemplates {
    pub fn new(
        priced_tx_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
        latest_nonce: u64,
    ) -> Self {
        match priced_tx_templates {
            Either::Left(priced_new_tx_templates) => {
                Self::from_priced_new_tx_templates(priced_new_tx_templates, latest_nonce)
            }
            Either::Right(priced_retry_tx_templates) => {
                todo!()
            }
        }
    }

    fn from_priced_new_tx_templates(
        priced_new_tx_templates: PricedNewTxTemplates,
        latest_nonce: u64,
    ) -> Self {
        priced_new_tx_templates
            .iter()
            .enumerate()
            .map(|(i, priced_new_tx_template)| SignableTxTemplate {
                receiver_address: priced_new_tx_template.base.receiver_address,
                amount_in_wei: priced_new_tx_template.base.amount_in_wei,
                gas_price_wei: priced_new_tx_template.computed_gas_price_wei,
                nonce: latest_nonce + i as u64,
            })
            .collect()
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
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::{
        PricedNewTxTemplate, PricedNewTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::data_structures::signable_tx_template::SignableTxTemplates;
    use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
    use crate::accountant::test_utils::make_payable_account;
    use itertools::Either;
    use masq_lib::constants::DEFAULT_GAS_PRICE;

    fn make_priced_tx_template(n: u64) -> PricedNewTxTemplate {
        PricedNewTxTemplate {
            base: BaseTxTemplate::from(&make_payable_account(n)),
            computed_gas_price_wei: DEFAULT_GAS_PRICE as u128,
        }
    }

    #[test]
    fn signable_tx_templates_can_be_created_from_priced_new_tx_templates() {
        let nonce = 10;
        let priced_new_tx_templates = PricedNewTxTemplates(vec![
            make_priced_tx_template(1),
            make_priced_tx_template(2),
            make_priced_tx_template(3),
            make_priced_tx_template(4),
            make_priced_tx_template(5),
        ]);

        let result = SignableTxTemplates::new(Either::Left(priced_new_tx_templates.clone()), nonce);

        priced_new_tx_templates
            .iter()
            .zip(result.iter())
            .enumerate()
            .for_each(|(index, (priced, signable))| {
                assert_eq!(signable.receiver_address, priced.base.receiver_address);
                assert_eq!(signable.amount_in_wei, priced.base.amount_in_wei);
                assert_eq!(signable.gas_price_wei, priced.computed_gas_price_wei);
                assert_eq!(signable.nonce, nonce + index as u64);
            });
    }
}
