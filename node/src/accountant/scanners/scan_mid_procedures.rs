// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scan_setup_msgs::{
    ConsumingWalletBalancesAndGasParams, PayablePaymentSetup,
};
use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutcomingPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait PayableScannerWithMidProcedures<BeginMessage, EndMessage>:
    Scanner<BeginMessage, EndMessage> + PayableScannerMidProcedures
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait PayableScannerMidProcedures {
    fn process_softly(
        &self,
        msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasParams>,
        logger: &Logger,
    ) -> Result<Either<OutcomingPaymentsInstructions, AwaitingAdjustment>, String>;
    fn process_with_adjustment(
        &self,
        setup: AwaitingAdjustment,
        logger: &Logger,
    ) -> OutcomingPaymentsInstructions;
}

#[derive(Debug, PartialEq, Eq)]
pub struct AwaitingAdjustment {
    pub original_msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasParams>,
    pub adjustment: Adjustment,
}

impl AwaitingAdjustment {
    pub fn new(
        original_msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasParams>,
        adjustment: Adjustment,
    ) -> Self {
        todo!()
    }
}
