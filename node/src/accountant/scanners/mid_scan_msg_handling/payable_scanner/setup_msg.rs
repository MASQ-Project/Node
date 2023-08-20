// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::ProtectedPayables;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub qualified_payables: ProtectedPayables,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl QualifiedPayablesMessage {
    pub(in crate::accountant) fn new(
        qualified_payables: ProtectedPayables,
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
    pub qualified_payables: ProtectedPayables,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl Clone for BlockchainAgentWithContextMessage {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        qualified_payables: ProtectedPayables,
        blockchain_agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            agent: blockchain_agent,
            response_skeleton_opt,
        }
    }
}
