use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTxTemplate {
    pub base: BaseTxTemplate,
    pub computed_gas_price_wei: Option<u128>,
}

impl From<&PayableAccount> for NewTxTemplate {
    fn from(payable_account: &PayableAccount) -> Self {
        Self {
            base: BaseTxTemplate::from(payable_account),
            computed_gas_price_wei: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NewTxTemplates(pub Vec<NewTxTemplate>);

impl From<Vec<NewTxTemplate>> for NewTxTemplates {
    fn from(new_tx_template_vec: Vec<NewTxTemplate>) -> Self {
        Self(new_tx_template_vec)
    }
}

impl Deref for NewTxTemplates {
    type Target = Vec<NewTxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NewTxTemplates {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for NewTxTemplates {
    type Item = NewTxTemplate;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// TODO: GH-605: Indirectly tested
impl FromIterator<NewTxTemplate> for NewTxTemplates {
    fn from_iter<I: IntoIterator<Item = NewTxTemplate>>(iter: I) -> Self {
        NewTxTemplates(iter.into_iter().collect())
    }
}

impl From<&Vec<PayableAccount>> for NewTxTemplates {
    fn from(payable_accounts: &Vec<PayableAccount>) -> Self {
        Self(
            payable_accounts
                .iter()
                .map(|payable_account| NewTxTemplate::from(payable_account))
                .collect(),
        )
    }
}

impl NewTxTemplates {
    pub fn total_gas_price(&self) -> u128 {
        self.iter()
            .map(|new_tx_template| {
                new_tx_template
                    .computed_gas_price_wei
                    .expect("gas price should be computed")
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::{
        NewTxTemplate, NewTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
    use crate::blockchain::test_utils::make_address;
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    #[test]
    fn new_tx_template_can_be_created_from_payable_account() {
        let wallet = make_wallet("some wallet");
        let balance_wei = 1_000_000;
        let payable_account = PayableAccount {
            wallet: wallet.clone(),
            balance_wei,
            last_paid_timestamp: SystemTime::now(),
            pending_payable_opt: None,
        };

        let new_tx_template = NewTxTemplate::from(&payable_account);

        assert_eq!(new_tx_template.base.receiver_address, wallet.address());
        assert_eq!(new_tx_template.base.amount_in_wei, balance_wei);
    }

    #[test]
    fn new_tx_templates_can_be_created_from_vec_using_into() {
        let template1 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            computed_gas_price_wei: Some(5000),
        };
        let template2 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            computed_gas_price_wei: Some(6000),
        };
        let templates_vec = vec![template1.clone(), template2.clone()];

        let templates: NewTxTemplates = templates_vec.into();

        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0], template1);
        assert_eq!(templates[1], template2);
        assert_eq!(templates.total_gas_price(), 11000);
    }

    #[test]
    fn new_tx_templates_deref_provides_access_to_inner_vector() {
        let template1 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            computed_gas_price_wei: None,
        };
        let template2 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            computed_gas_price_wei: None,
        };

        let templates = NewTxTemplates(vec![template1.clone(), template2.clone()]);

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
    fn new_tx_templates_into_iter_consumes_and_iterates() {
        let template1 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
            computed_gas_price_wei: Some(5000),
        };
        let template2 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
            computed_gas_price_wei: Some(6000),
        };
        let templates = NewTxTemplates(vec![template1.clone(), template2.clone()]);

        let collected: Vec<NewTxTemplate> = templates.into_iter().collect();

        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], template1);
        assert_eq!(collected[1], template2);
    }

    #[test]
    fn new_tx_templates_can_be_created_from_payable_accounts() {
        let wallet1 = make_wallet("wallet1");
        let wallet2 = make_wallet("wallet2");
        let payable_accounts = vec![
            PayableAccount {
                wallet: wallet1.clone(),
                balance_wei: 1000,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: wallet2.clone(),
                balance_wei: 2000,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
        ];

        let new_tx_templates = NewTxTemplates::from(&payable_accounts);

        assert_eq!(new_tx_templates.len(), 2);
        assert_eq!(new_tx_templates[0].base.receiver_address, wallet1.address());
        assert_eq!(new_tx_templates[0].base.amount_in_wei, 1000);
        assert_eq!(new_tx_templates[1].base.receiver_address, wallet2.address());
        assert_eq!(new_tx_templates[1].base.amount_in_wei, 2000);
    }
}
