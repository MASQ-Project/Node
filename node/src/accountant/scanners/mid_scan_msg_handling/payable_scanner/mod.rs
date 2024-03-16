// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod agent_null;
pub mod agent_web3;
pub mod blockchain_agent;
pub mod msgs;
pub mod test_utils;

use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::Scanner;
use crate::accountant::{QualifiedPayableAccount, ResponseSkeleton};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait MultistagePayableScanner<BeginMessage, EndMessage>:
    Scanner<BeginMessage, EndMessage> + SolvencySensitivePaymentInstructor
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait SolvencySensitivePaymentInstructor {
    fn try_skipping_payment_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Option<Either<OutboundPaymentsInstructions, PreparedAdjustment>>;

    fn perform_payment_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> Option<OutboundPaymentsInstructions>;
}

pub struct PreparedAdjustment {
    pub qualified_payables: Vec<QualifiedPayableAccount>,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
    pub adjustment: Adjustment,
}

impl PreparedAdjustment {
    pub fn new(
        qualified_payables: Vec<QualifiedPayableAccount>,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
        adjustment: Adjustment,
    ) -> Self {
        Self {
            qualified_payables,
            agent,
            response_skeleton_opt,
            adjustment,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;

    impl Clone for PreparedAdjustment {
        fn clone(&self) -> Self {
            Self {
                qualified_payables: self.qualified_payables.clone(),
                agent: self.agent.dup(),
                response_skeleton_opt: self.response_skeleton_opt,
                adjustment: self.adjustment.clone(),
            }
        }
    }
}
