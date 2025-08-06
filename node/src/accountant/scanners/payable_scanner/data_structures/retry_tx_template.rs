use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_gas_price_wei: u128,
    pub prev_nonce: u64,
}

impl From<&FailedTx> for RetryTxTemplate {
    fn from(failed_tx: &FailedTx) -> Self {
        RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: failed_tx.receiver_address,
                amount_in_wei: failed_tx.amount,
            },
            prev_gas_price_wei: failed_tx.gas_price_wei,
            prev_nonce: failed_tx.nonce,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RetryTxTemplates(pub Vec<RetryTxTemplate>);

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
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::{
        RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
    use crate::blockchain::test_utils::{make_address, make_tx_hash};

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
            amount: amount_in_wei,
            gas_price_wei: gas_price,
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
