// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod agent_abstract_layer;
pub mod agent_web3;
pub mod setup_msg;

use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::mid_scan_procedures::payable_scanner::setup_msg::PayablePaymentsSetupMsg;
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait MultistagePayableScanner<BeginMessage, EndMessage>:
    Scanner<BeginMessage, EndMessage> + PayableScannerMidScanProcedures
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait PayableScannerMidScanProcedures {
    fn try_skipping_payment_adjustment(
        &self,
        _msg: PayablePaymentsSetupMsg,
        _logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        intentionally_blank!()
    }

    fn perform_payment_adjustment(
        &self,
        _setup: PreparedAdjustment,
        _logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        intentionally_blank!()
    }
}

pub struct PreparedAdjustment {
    pub original_setup_msg: PayablePaymentsSetupMsg,
    pub adjustment: Adjustment,
}

impl PreparedAdjustment {
    pub fn new(original_setup_msg: PayablePaymentsSetupMsg, adjustment: Adjustment) -> Self {
        Self {
            original_setup_msg,
            adjustment,
        }
    }
}
