// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::ResponseSkeleton;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use actix::Message;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct PayablePaymentSetup {
    //this field should stay private for anybody outside Accountant
    pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
    pub this_stage_data_opt: Option<StageData>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl From<(PayablePaymentSetup, StageData)> for PayablePaymentSetup {
    fn from((previous_msg, this_stage_data): (PayablePaymentSetup, StageData)) -> Self {
        PayablePaymentSetup {
            qualified_payables: previous_msg.qualified_payables,
            this_stage_data_opt: Some(this_stage_data),
            response_skeleton_opt: previous_msg.response_skeleton_opt,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StageData {
    FinancialAndTechDetails(FinancialAndTechDetails),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FinancialAndTechDetails {
    pub consuming_wallet_balances: ConsumingWalletBalances,
    pub desired_transaction_fee_price_major: u64,
    //rather technical stuff below
    pub estimated_gas_limit_per_transaction: u64,
}
