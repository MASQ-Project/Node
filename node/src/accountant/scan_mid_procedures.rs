// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_scan_setup_msgs::inter_actor_communication_for_payable_scanner::{
    ConsumingWalletBalancesAndGasPrice, PayablePaymentSetup,
};
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutcomingPayamentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;
use crate::accountant::payment_adjuster::{Adjustment};

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
        msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>,
        logger: &Logger,
    ) -> Result<
        Either<
            OutcomingPayamentsInstructions,
            AwaitingAdjustment,
        >,
        String,
    >;
    fn process_with_adjustment(
        &self,
        setup: AwaitingAdjustment,
        logger: &Logger,
    ) -> OutcomingPayamentsInstructions;
}

#[derive(Debug, PartialEq, Eq)]
pub struct AwaitingAdjustment{
    pub original_msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>,
    pub adjustment: Adjustment
}

impl AwaitingAdjustment{
    pub fn new(original_msg: PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>, adjustment: Adjustment)->Self{
        todo!()
    }
}