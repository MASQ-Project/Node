// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::accountant::inter_actor_communication_for_payable_scanner::ConsumingWalletBalancesAndQualifiedPayables;
use crate::accountant::scanners::Scanner;
use crate::sub_lib::blockchain_bridge::OutcomingPayamentsInstructions;
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
    fn mid_procedure_soft(
        &self,
        msg: ConsumingWalletBalancesAndQualifiedPayables,
        logger: &Logger,
    ) -> Either<OutcomingPayamentsInstructions, ConsumingWalletBalancesAndQualifiedPayables>;
    fn mid_procedure_hard(
        &self,
        msg: ConsumingWalletBalancesAndQualifiedPayables,
        logger: &Logger,
    ) -> OutcomingPayamentsInstructions;
}
