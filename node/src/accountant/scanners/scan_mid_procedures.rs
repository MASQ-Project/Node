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
    fn try_skipping_payment_adjustment(
        &self,
        _msg: PayablePaymentSetup,
        _logger: &Logger,
    ) -> Result<Either<OutcomingPaymentsInstructions, AwaitedAdjustment>, ()> {
        intentionally_blank!()
    }
    fn perform_payment_adjustment(
        &mut self,
        _setup: AwaitedAdjustment,
    ) -> Result<OutcomingPaymentsInstructions, String> {
        intentionally_blank!()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AwaitedAdjustment {
    pub original_setup_msg: PayablePaymentSetup,
    pub adjustment: Adjustment,
}

impl AwaitedAdjustment {
    pub fn new(original_setup_msg: PayablePaymentSetup, adjustment: Adjustment) -> Self {
        Self {
            original_setup_msg,
            adjustment,
        }
    }
}
