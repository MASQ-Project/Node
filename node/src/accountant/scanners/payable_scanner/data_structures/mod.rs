use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use itertools::Either;
use web3::types::Address;

pub mod new_tx_template;
pub mod priced_new_tx_template;
pub mod priced_retry_tx_template;
pub mod retry_tx_template;
pub mod signable_tx_template;
pub mod test_utils;

// TODO: GH-605: Rename this to TxTemplates Message
#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BaseTxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
}

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
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
