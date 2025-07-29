use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use std::ops::Deref;
use web3::types::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseTxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTxTemplate {
    pub base: BaseTxTemplate,
}

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct GasPriceOnlyTxTemplate {
//     pub base: BaseTxTemplate,
//     pub gas_price_wei: u128,
// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_gas_price_wei: u128,
    pub prev_nonce: u64,
}

impl From<&PayableAccount> for BaseTxTemplate {
    fn from(payable_account: &PayableAccount) -> Self {
        todo!()
    }
}

impl From<&PayableAccount> for NewTxTemplate {
    fn from(payable: &PayableAccount) -> Self {
        todo!()
    }
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
pub struct NewTxTemplates(pub Vec<NewTxTemplate>);

impl Deref for NewTxTemplates {
    type Target = Vec<NewTxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// TODO: GH-605: It can be a reference instead
impl From<Vec<PayableAccount>> for NewTxTemplates {
    fn from(payable_accounts: Vec<PayableAccount>) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::scanners::payable_scanner::data_structures::{
        BaseTxTemplate, NewTxTemplate, NewTxTemplates, RetryTxTemplate,
    };
    use crate::blockchain::test_utils::{make_address, make_tx_hash};

    #[test]
    fn new_tx_template_can_be_created_from_payable_account() {
        todo!()
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
    fn new_tx_templates_deref_provides_access_to_inner_vector() {
        let template1 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
            },
        };
        let template2 = NewTxTemplate {
            base: BaseTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
            },
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
}
