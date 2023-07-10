// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct PayablePaymentsSetupMsgPayload {
    // This field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl PayablePaymentsSetupMsgPayload {
    // This function should stay private for anybody outside Accountant
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

#[derive(Debug, Clone, Message)]
pub struct PayablePaymentsSetupMsg {
    pub payload: PayablePaymentsSetupMsgPayload,
    pub agent: Box<dyn PayablePaymentsAgent>,
}

// Derive version of PartialEq blows up because of the agent in it. Complaint about
// disability to use Copy in order to move out from behind a reference (???). Only the added
// references helped me move forward
#[allow(clippy::op_ref)]
impl PartialEq for PayablePaymentsSetupMsg {
    fn eq(&self, other: &Self) -> bool {
        self.payload.qualified_payables == other.payload.qualified_payables
            && &self.agent == &other.agent
            && self.payload.response_skeleton_opt == other.payload.response_skeleton_opt
    }
}

// This gives you at least a limited ability to construct the msg also outside Accountant
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

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent_web3::PayablePaymentsAgentWeb3;
    use crate::accountant::scanners::payable_payments_setup_msg::{
        PayablePaymentsSetupMsg, PayablePaymentsSetupMsgPayload,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::ResponseSkeleton;
    use web3::types::U256;

    #[test]
    fn payable_payments_setup_msg_implements_partial_eq() {
        let mut msg_one = PayablePaymentsSetupMsg {
            payload: PayablePaymentsSetupMsgPayload {
                qualified_payables: vec![make_payable_account(456)],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 333,
                    context_id: 777,
                }),
            },
            agent: Box::new(PayablePaymentsAgentWeb3::new(4_555)),
        };
        let mut msg_two = msg_one.clone();

        assert_eq!(msg_one, msg_two);
        msg_one.payload.qualified_payables = vec![];
        assert_ne!(msg_one, msg_two);
        msg_two.payload.qualified_payables = vec![];
        assert_eq!(msg_one, msg_two);
        msg_one
            .agent
            .set_up_pending_transaction_id(U256::from(7_777));
        assert_ne!(msg_one, msg_two);
        msg_two
            .agent
            .set_up_pending_transaction_id(U256::from(7_777));
        assert_eq!(msg_one, msg_two);
        msg_one.payload.response_skeleton_opt = None;
        assert_ne!(msg_one, msg_two);
        msg_two.payload.response_skeleton_opt = None;
        assert_eq!(msg_one, msg_two)
    }
}
