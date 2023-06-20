// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::ResponseSkeleton;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use actix::Message;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct PayablePaymentsSetup {
    //this field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub this_stage_data_opt: Option<StageData>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl From<(PayablePaymentsSetup, StageData)> for PayablePaymentsSetup {
    fn from((previous_msg, this_stage_data): (PayablePaymentsSetup, StageData)) -> Self {
        PayablePaymentsSetup {
            qualified_payables: previous_msg.qualified_payables,
            this_stage_data_opt: Some(this_stage_data),
            response_skeleton_opt: previous_msg.response_skeleton_opt,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StageData {
    PreliminaryContext(PreliminaryContext),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PreliminaryContext {
    pub consuming_wallet_balances: ConsumingWalletBalances,
    pub transaction_fee_specification: SingleTransactionFee,
}

//TODO will be generalized as part of GH-696
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SingleTransactionFee {
    pub gas_price_gwei: u64,
    pub estimated_gas_limit: u64,
}
