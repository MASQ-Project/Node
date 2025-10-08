// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
use std::collections::{BTreeSet, HashMap};
use std::ops::{Deref, DerefMut};
use web3::types::Address;
use masq_lib::logger::Logger;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_gas_price_wei: u128,
    pub prev_nonce: u64,
}

impl RetryTxTemplate {
    pub fn new(failed_tx: &FailedTx, updated_payable_balance_opt: Option<u128>, logger: &Logger) -> Self {
        let mut retry_template = RetryTxTemplate::from(failed_tx);

        debug!(logger, "Tx to retry {:?}", failed_tx);

        if let Some(updated_payable_balance) = updated_payable_balance_opt {
            debug!(logger, "Updating the pay for {:?} from former {} to latest accounted balance {} of minor", failed_tx.receiver_address, failed_tx.amount_minor, updated_payable_balance);

            retry_template.base.amount_in_wei = updated_payable_balance;
        }

        retry_template
    }
}

impl From<&FailedTx> for RetryTxTemplate {
    fn from(failed_tx: &FailedTx) -> Self {
        RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: failed_tx.receiver_address,
                amount_in_wei: failed_tx.amount_minor,
            },
            prev_gas_price_wei: failed_tx.gas_price_minor,
            prev_nonce: failed_tx.nonce,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RetryTxTemplates(pub Vec<RetryTxTemplate>);

impl RetryTxTemplates {
    pub fn new(
        txs_to_retry: &BTreeSet<FailedTx>,
        amounts_from_payables: &HashMap<Address, u128>,
        logger: &Logger,
    ) -> Self {
        Self(
            txs_to_retry
                .iter()
                .map(|tx_to_retry| {
                    let payable_scan_amount_opt = amounts_from_payables
                        .get(&tx_to_retry.receiver_address)
                        .copied();
                    RetryTxTemplate::new(tx_to_retry, payable_scan_amount_opt, logger)
                })
                .collect(),
        )
    }
}

impl From<Vec<RetryTxTemplate>> for RetryTxTemplates {
    fn from(retry_tx_templates: Vec<RetryTxTemplate>) -> Self {
        Self(retry_tx_templates)
    }
}

impl Deref for RetryTxTemplates {
    type Target = Vec<RetryTxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RetryTxTemplates {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for RetryTxTemplates {
    type Item = RetryTxTemplate;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use masq_lib::logger::Logger;
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::{
        RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
    use crate::blockchain::test_utils::{make_address, make_tx_hash};

    #[test]
    fn retry_tx_template_constructor_works() {
        let receiver_address = make_address(42);
        let amount_in_wei = 1_000_000;
        let gas_price = 20_000_000_000;
        let nonce = 123;
        let tx_hash = make_tx_hash(789);
        let failed_tx = FailedTx {
            hash: tx_hash,
            receiver_address,
            amount_minor: amount_in_wei,
            gas_price_minor: gas_price,
            nonce,
            timestamp: 1234567,
            reason: FailureReason::PendingTooLong,
            status: FailureStatus::RetryRequired,
        };
        let logger = Logger::new("test");
        let fetched_balance_from_payable_table_opt_1 = None;
        let fetched_balance_from_payable_table_opt_2 = Some(1_234_567);

        let result_1 = RetryTxTemplate::new(&failed_tx, fetched_balance_from_payable_table_opt_1, &logger);
        let result_2  = RetryTxTemplate::new(&failed_tx, fetched_balance_from_payable_table_opt_2, &logger);

        let assert = |result: RetryTxTemplate, expected_amount_in_wei: u128| {
            assert_eq!(result.base.receiver_address, receiver_address);
            assert_eq!(result.base.amount_in_wei, expected_amount_in_wei);
            assert_eq!(result.prev_gas_price_wei, gas_price);
            assert_eq!(result.prev_nonce, nonce);
        };
        assert(result_1, amount_in_wei);
        assert(result_2, fetched_balance_from_payable_table_opt_2.unwrap());
    }

    #[test]
    fn retry_tx_template_can_be_created_from_failed_tx() {
        let receiver_address = make_address(42);
        let amount_in_wei = 1_000_000;
        let gas_price = 20_000_000_000;
        let nonce = 123;
        let tx_hash = make_tx_hash(789);
        let failed_tx = FailedTx {
            hash: tx_hash,
            receiver_address,
            amount_minor: amount_in_wei,
            gas_price_minor: gas_price,
            nonce,
            timestamp: 1234567,
            reason: FailureReason::PendingTooLong,
            status: FailureStatus::RetryRequired,
        };

        let retry_tx_template = RetryTxTemplate::from(&failed_tx);

        assert_eq!(retry_tx_template.base.receiver_address, receiver_address);
        assert_eq!(retry_tx_template.base.amount_in_wei, amount_in_wei);
        assert_eq!(retry_tx_template.prev_gas_price_wei, gas_price);
        assert_eq!(retry_tx_template.prev_nonce, nonce);
    }

    #[test]
    fn retry_tx_templates_can_be_created_from_vec_using_into() {
        let template1 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            prev_gas_price_wei: 20_000_000_000,
            prev_nonce: 5,
        };
        let template2 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            prev_gas_price_wei: 25_000_000_000,
            prev_nonce: 6,
        };
        let templates_vec = vec![template1.clone(), template2.clone()];

        let templates: RetryTxTemplates = templates_vec.into();

        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0], template1);
        assert_eq!(templates[1], template2);
    }

    #[test]
    fn retry_tx_templates_deref_provides_access_to_inner_vector() {
        let template1 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            prev_gas_price_wei: 20_000_000_000,
            prev_nonce: 5,
        };
        let template2 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            prev_gas_price_wei: 25_000_000_000,
            prev_nonce: 6,
        };

        let templates = RetryTxTemplates(vec![template1.clone(), template2.clone()]);

        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0], template1);
        assert_eq!(templates[1], template2);
        assert!(!templates.is_empty());
        assert!(templates.contains(&template1));
        assert_eq!(
            templates
                .iter()
                .map(|template| template.base.amount_in_wei)
                .sum::<u128>(),
            3000
        );
    }

    #[test]
    fn retry_tx_templates_into_iter_consumes_and_iterates() {
        let template1 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            prev_gas_price_wei: 20_000_000_000,
            prev_nonce: 5,
        };
        let template2 = RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            prev_gas_price_wei: 25_000_000_000,
            prev_nonce: 6,
        };
        let templates = RetryTxTemplates(vec![template1.clone(), template2.clone()]);

        let collected: Vec<RetryTxTemplate> = templates.into_iter().collect();

        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], template1);
        assert_eq!(collected[1], template2);
    }
}
