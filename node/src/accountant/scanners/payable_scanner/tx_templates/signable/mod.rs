// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
use bytes::Buf;
use itertools::{Either, Itertools};
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

impl SignableTxTemplates {
    pub fn new(
        priced_tx_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
        latest_nonce: u64,
    ) -> Self {
        match priced_tx_templates {
            Either::Left(priced_new_tx_templates) => {
                Self::from_new_txs(priced_new_tx_templates, latest_nonce)
            }
            Either::Right(priced_retry_tx_templates) => {
                Self::from_retry_txs(priced_retry_tx_templates, latest_nonce)
            }
        }
    }

    fn from_new_txs(templates: PricedNewTxTemplates, latest_nonce: u64) -> Self {
        templates
            .iter()
            .enumerate()
            .map(|(i, template)| SignableTxTemplate {
                receiver_address: template.base.receiver_address,
                amount_in_wei: template.base.amount_in_wei,
                gas_price_wei: template.computed_gas_price_wei,
                nonce: latest_nonce + i as u64,
            })
            .collect()
    }

    fn from_retry_txs(templates: PricedRetryTxTemplates, latest_nonce: u64) -> Self {
        templates
            .reorder_by_nonces(latest_nonce)
            .iter()
            .enumerate()
            .map(|(i, template)| SignableTxTemplate {
                receiver_address: template.base.receiver_address,
                amount_in_wei: template.base.amount_in_wei,
                gas_price_wei: template.computed_gas_price_wei,
                nonce: latest_nonce + i as u64,
            })
            .collect()
    }

    pub fn nonce_range(&self) -> (u64, u64) {
        let sorted: Vec<&SignableTxTemplate> = self
            .iter()
            .sorted_by_key(|template| template.nonce)
            .collect();
        let first = sorted.first().map_or(0, |template| template.nonce);
        let last = sorted.last().map_or(0, |template| template.nonce);

        (first, last)
    }

    pub fn largest_amount(&self) -> u128 {
        self.iter()
            .map(|signable_tx_template| signable_tx_template.amount_in_wei)
            .max()
            .unwrap_or(0)
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

    use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::signable::SignableTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::test_utils::{
        make_priced_new_tx_template, make_priced_retry_tx_template, make_signable_tx_template,
    };
    use itertools::Either;

    #[test]
    fn signable_tx_templates_can_be_created_from_priced_new_tx_templates() {
        let nonce = 10;
        let priced_new_tx_templates = PricedNewTxTemplates(vec![
            make_priced_new_tx_template(1),
            make_priced_new_tx_template(2),
            make_priced_new_tx_template(3),
            make_priced_new_tx_template(4),
            make_priced_new_tx_template(5),
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

    #[test]
    fn signable_tx_templates_can_be_created_from_priced_retry_tx_templates() {
        let nonce = 10;
        // n is same as prev_nonce here
        let retries = PricedRetryTxTemplates(vec![
            make_priced_retry_tx_template(12),
            make_priced_retry_tx_template(6),
            make_priced_retry_tx_template(10),
            make_priced_retry_tx_template(8),
            make_priced_retry_tx_template(11),
        ]);

        let result = SignableTxTemplates::new(Either::Right(retries.clone()), nonce);

        let expected_order = vec![2, 4, 0, 1, 3];
        result
            .iter()
            .enumerate()
            .zip(expected_order.into_iter())
            .for_each(|((i, signable), index)| {
                assert_eq!(
                    signable.receiver_address,
                    retries[index].base.receiver_address
                );
                assert_eq!(signable.nonce, nonce + i as u64);
                assert_eq!(signable.amount_in_wei, retries[index].base.amount_in_wei);
                assert_eq!(
                    signable.gas_price_wei,
                    retries[index].computed_gas_price_wei
                );
            });
    }

    #[test]
    fn test_largest_amount() {
        let empty_templates = SignableTxTemplates(vec![]);
        let templates = SignableTxTemplates(vec![
            make_signable_tx_template(1),
            make_signable_tx_template(2),
            make_signable_tx_template(3),
        ]);

        assert_eq!(empty_templates.largest_amount(), 0);
        assert_eq!(templates.largest_amount(), 3000);
    }

    #[test]
    fn test_nonce_range() {
        // Test case 1: Empty templates
        let empty_templates = SignableTxTemplates(vec![]);
        assert_eq!(empty_templates.nonce_range(), (0, 0));

        // Test case 2: Single template
        let single_template = SignableTxTemplates(vec![make_signable_tx_template(5)]);
        assert_eq!(single_template.nonce_range(), (5, 5));

        // Test case 3: Multiple templates in order
        let ordered_templates = SignableTxTemplates(vec![
            make_signable_tx_template(1),
            make_signable_tx_template(2),
            make_signable_tx_template(3),
        ]);
        assert_eq!(ordered_templates.nonce_range(), (1, 3));

        // Test case 4: Multiple templates out of order
        let unordered_templates = SignableTxTemplates(vec![
            make_signable_tx_template(3),
            make_signable_tx_template(1),
            make_signable_tx_template(2),
        ]);
        assert_eq!(unordered_templates.nonce_range(), (1, 3));
    }
}
