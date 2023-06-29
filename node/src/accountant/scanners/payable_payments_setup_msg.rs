// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::payable_payments_agent_abstract_layer::PayablePaymentsAgent;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
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
    //this field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub agent: Box<dyn PayablePaymentsAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl PartialEq for PayablePaymentsSetupMsg {
    fn eq(&self, other: &Self) -> bool {
        todo!()
    }
}

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
        todo!()
        // PayablePaymentsSetup {
        //     qualified_payables: previous_msg.qualified_payables,
        //     this_stage_data_opt: Some(this_stage_data),
        //     response_skeleton_opt: previous_msg.response_skeleton_opt,
        // }
    }
}

impl From<(PayablePaymentsSetupMsg, Box<dyn PayablePaymentsAgent>)> for PayablePaymentsSetupMsg {
    fn from(
        (previous_msg, agent): (PayablePaymentsSetupMsg, Box<dyn PayablePaymentsAgent>),
    ) -> Self {
        todo!()
        // PayablePaymentsSetup {
        //     qualified_payables: previous_msg.qualified_payables,
        //     this_stage_data_opt: Some(this_stage_data),
        //     response_skeleton_opt: previous_msg.response_skeleton_opt,
        // }
    }
}

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum StageData {
//     PreliminaryContext(PreliminaryContext),
// }
//
// impl StageData {
//     pub fn preliminary_context(&self) -> &PreliminaryContext {
//         match self {
//             StageData::PreliminaryContext(context) => context,
//         }
//     }
// }
//
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct PreliminaryContext {
//     pub consuming_wallet_balances: ConsumingWalletBalances,
//     pub transaction_fees_calculator: Box<dyn TransactionFeesCalculator>,
// }
//
// //TODO will be generalized as part of GH-696
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct SingleTransactionFee {
//     pub gas_price_gwei: u64,
//     pub estimated_gas_limit: u64,
// }
