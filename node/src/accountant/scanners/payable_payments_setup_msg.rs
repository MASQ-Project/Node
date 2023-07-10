// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use actix::Message;
use std::fmt::Debug;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct InitialPayablePaymentsSetupMsg {
    //this field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for InitialPayablePaymentsSetupMsg {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Debug, Clone, Message)]
pub struct PayablePaymentsSetupMsg {
    // this field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub agent: Box<dyn PayablePaymentsAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

// derive version of PartialEq get stuck because of the field with the agent; Rust complains about
// disability to move out from behind a reference (???); only the added references helped me
// move forward
#[allow(clippy::op_ref)]
impl PartialEq for PayablePaymentsSetupMsg {
    fn eq(&self, other: &Self) -> bool {
        self.qualified_payables == other.qualified_payables
            && &self.agent == &other.agent
            && self.response_skeleton_opt == other.response_skeleton_opt
    }
}

// this allows you to construct the PayablePaymentsSetupMsg even outside Accountant
impl
    From<(
        InitialPayablePaymentsSetupMsg,
        Box<dyn PayablePaymentsAgent>,
    )> for PayablePaymentsSetupMsg
{
    fn from(
        (initial_msg, agent): (
            InitialPayablePaymentsSetupMsg,
            Box<dyn PayablePaymentsAgent>,
        ),
    ) -> Self {
        PayablePaymentsSetupMsg {
            qualified_payables: initial_msg.qualified_payables,
            agent,
            response_skeleton_opt: initial_msg.response_skeleton_opt,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_payments_agent_web3::PayablePaymentsAgentWeb3;
    use crate::accountant::scanners::payable_payments_setup_msg::PayablePaymentsSetupMsg;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::ResponseSkeleton;
    use web3::types::U256;

    #[test]
    fn payable_payments_setup_msg_implements_partial_eq() {
        let mut msg_one = PayablePaymentsSetupMsg {
            qualified_payables: vec![make_payable_account(456)],
            agent: Box::new(PayablePaymentsAgentWeb3::new(4_555)),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 333,
                context_id: 777,
            }),
        };
        let mut msg_two = msg_one.clone();

        assert_eq!(msg_one, msg_two);
        msg_one.qualified_payables = vec![];
        assert_ne!(msg_one, msg_two);
        msg_two.qualified_payables = vec![];
        assert_eq!(msg_one, msg_two);
        msg_one
            .agent
            .set_up_pending_transaction_id(U256::from(7_777));
        assert_ne!(msg_one, msg_two);
        msg_two
            .agent
            .set_up_pending_transaction_id(U256::from(7_777));
        assert_eq!(msg_one, msg_two);
        msg_one.response_skeleton_opt = None;
        assert_ne!(msg_one, msg_two);
        msg_two.response_skeleton_opt = None;
        assert_eq!(msg_one, msg_two)
    }
}