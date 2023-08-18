// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent::BlockchainAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    // On purpose restricted visibility
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl QualifiedPayablesMessage {
    // On purpose restricted visibility
    pub(in crate::accountant) fn new(
        qualified_payables: Vec<PayableAccount>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
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
    pub payables: QualifiedPayablesMessage,
    pub agent: Box<dyn BlockchainAgent>,
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        qualified_payables_msg: QualifiedPayablesMessage,
        blockchain_agent: Box<dyn BlockchainAgent>,
    ) -> Self {
        Self {
            payables: qualified_payables_msg,
            agent: blockchain_agent,
        }
    }
}
