// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub qualified_payables: Vec<PayableAccount>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl QualifiedPayablesMessage {
    pub(in crate::accountant) fn new(
        qualified_payables: Vec<PayableAccount>,
        consuming_wallet: Wallet,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            consuming_wallet,
            response_skeleton_opt,
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
    pub qualified_payables: Vec<PayableAccount>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        qualified_payables: Vec<PayableAccount>,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            agent,
            response_skeleton_opt,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::accountant::scanners::payable_scanner::msgs::BlockchainAgentWithContextMessage;
    use crate::accountant::scanners::payable_scanner::test_utils::BlockchainAgentMock;

    impl Clone for BlockchainAgentWithContextMessage {
        fn clone(&self) -> Self {
            let original_agent_id = self.agent.arbitrary_id_stamp();
            let cloned_agent =
                BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
            Self {
                qualified_payables: self.qualified_payables.clone(),
                agent: Box::new(cloned_agent),
                response_skeleton_opt: self.response_skeleton_opt,
            }
        }
    }
}
