// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_agent;
pub mod agent_null;
pub mod agent_web3;
pub mod setup_msg;

use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::setup_msg::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait MultistagePayableScanner<BeginMessage, EndMessage>:
    Scanner<BeginMessage, EndMessage> + MidScanPayableHandlingScanner
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait MidScanPayableHandlingScanner {
    fn try_skipping_payment_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String>;

    fn perform_payment_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPayables(pub(in crate::accountant) Vec<u8>);

#[derive(Clone)]
pub struct PreparedAdjustment {
    pub original_setup_msg: BlockchainAgentWithContextMessage,
    pub adjustment: Adjustment,
}

impl PreparedAdjustment {
    pub fn new(
        original_setup_msg: BlockchainAgentWithContextMessage,
        adjustment: Adjustment,
    ) -> Self {
        Self {
            original_setup_msg,
            adjustment,
        }
    }
}
