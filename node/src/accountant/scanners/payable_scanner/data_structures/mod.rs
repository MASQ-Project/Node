use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use web3::types::Address;

pub mod new_tx_template;
pub mod priced_new_tx_template;
pub mod priced_retry_tx_template;
pub mod retry_tx_template;
pub mod signable_tx_template;
pub mod test_utils;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BaseTxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
}

impl From<&PayableAccount> for BaseTxTemplate {
    fn from(payable_account: &PayableAccount) -> Self {
        Self {
            receiver_address: payable_account.wallet.address(),
            amount_in_wei: payable_account.balance_wei,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    #[test]
    fn base_tx_template_can_be_created_from_payable_account() {
        let wallet = make_wallet("some wallet");
        let balance_wei = 1_000_000;
        let payable_account = PayableAccount {
            wallet: wallet.clone(),
            balance_wei,
            last_paid_timestamp: SystemTime::now(),
            pending_payable_opt: None,
        };

        let base_tx_template = BaseTxTemplate::from(&payable_account);

        assert_eq!(base_tx_template.receiver_address, wallet.address());
        assert_eq!(base_tx_template.amount_in_wei, balance_wei);
    }
}
