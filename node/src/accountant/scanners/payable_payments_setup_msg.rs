// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct PayablePaymentsSetupMsgPayload {
    // On purpose restricted visibility
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl PayablePaymentsSetupMsgPayload {
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

impl SkeletonOptHolder for PayablePaymentsSetupMsgPayload {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Message)]
pub struct PayablePaymentsSetupMsg {
    pub payload: PayablePaymentsSetupMsgPayload,
    pub agent: Box<dyn PayablePaymentsAgent>,
}

// To be able to construct that msg outside Accountant
impl
    From<(
        PayablePaymentsSetupMsgPayload,
        Box<dyn PayablePaymentsAgent>,
    )> for PayablePaymentsSetupMsg
{
    fn from(
        (payload, agent): (
            PayablePaymentsSetupMsgPayload,
            Box<dyn PayablePaymentsAgent>,
        ),
    ) -> Self {
        PayablePaymentsSetupMsg { payload, agent }
    }
}
