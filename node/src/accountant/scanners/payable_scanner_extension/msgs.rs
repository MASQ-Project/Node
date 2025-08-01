// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::data_structures::new_tx_template::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_new_tx_template::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::priced_retry_tx_template::PricedRetryTxTemplates;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplates;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::test_utils::make_address;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use actix::Message;
use itertools::Either;
use std::fmt::Debug;
use std::ops::Deref;
use web3::types::Address;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PricedQualifiedPayables {
    pub payables: Vec<QualifiedPayableWithGasPrice>,
}

impl Into<Vec<PayableAccount>> for PricedQualifiedPayables {
    fn into(self) -> Vec<PayableAccount> {
        self.payables
            .into_iter()
            .map(|qualified_payable| qualified_payable.payable)
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayableWithGasPrice {
    pub payable: PayableAccount,
    pub gas_price_minor: u128,
}

impl QualifiedPayableWithGasPrice {
    pub fn new(payable: PayableAccount, gas_price_minor: u128) -> Self {
        Self {
            payable,
            gas_price_minor,
        }
    }
}

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        priced_templates: Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            priced_templates,
            agent,
            response_skeleton_opt,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::scanners::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
    use crate::accountant::scanners::payable_scanner_extension::test_utils::BlockchainAgentMock;
    use crate::blockchain::test_utils::{make_address, make_tx_hash};
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    impl Clone for BlockchainAgentWithContextMessage {
        fn clone(&self) -> Self {
            let original_agent_id = self.agent.arbitrary_id_stamp();
            let cloned_agent =
                BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
            Self {
                priced_templates: self.priced_templates.clone(),
                agent: Box::new(cloned_agent),
                response_skeleton_opt: self.response_skeleton_opt,
            }
        }
    }
}
