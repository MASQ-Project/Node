use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use web3::types::Address;

pub mod new_tx_template;
pub mod retry_tx_template;

#[derive(Debug, Clone, PartialEq, Eq)]
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
