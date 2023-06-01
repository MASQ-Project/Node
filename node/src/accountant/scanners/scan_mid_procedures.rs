// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::payable_scan_setup_msgs::PayablePaymentSetup;
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutcomingPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait PayableScannerWithMiddleProcedures<BeginMessage, EndMessage>:
    Scanner<BeginMessage, EndMessage> + PayableScannerMiddleProcedures
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait PayableScannerMiddleProcedures {
    fn try_softly(
        &self,
        _msg: PayablePaymentSetup,
        _logger: &Logger,
    ) -> Result<Either<OutcomingPaymentsInstructions, AwaitingAdjustment>, String> {
        intentionally_blank!()
    }
    fn get_special_payments_instructions(
        &self,
        _setup: AwaitingAdjustment,
        _logger: &Logger,
    ) -> OutcomingPaymentsInstructions {
        intentionally_blank!()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AwaitingAdjustment {
    pub original_msg: PayablePaymentSetup,
    pub adjustment: Adjustment,
}

impl AwaitingAdjustment {
    pub fn new(original_msg: PayablePaymentSetup, adjustment: Adjustment) -> Self {
        Self {
            original_msg,
            adjustment,
        }
    }
}
