// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::sub_lib::neighborhood::PaymentAdjusterQueryMessage;
use actix::Recipient;
use web3::types::U256;

pub struct PaymentAdjuster {
    neighborhood_sub: Recipient<PaymentAdjusterQueryMessage>,
}

impl PaymentAdjuster {
    pub fn new(neighborhood_sub: Recipient<PaymentAdjusterQueryMessage>) -> Self {
        Self { neighborhood_sub }
    }

    pub fn adjust_payments(
        &self,
        payments_over_our_budget: Vec<PayableAccount>,
        current_token_balance_wei: U256,
    ) -> Vec<PayableAccount> {
        todo!()
    }
}
