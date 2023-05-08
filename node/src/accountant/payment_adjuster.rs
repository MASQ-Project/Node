// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use web3::types::U256;

pub struct PaymentAdjuster {
}

impl PaymentAdjuster {
    pub fn new() -> Self {
        Self {}
    }

    pub fn adjust_payments(
        &self,
        payments_over_our_budget: Vec<PayableAccount>,
        current_token_balance_wei: U256,
    ) -> Vec<PayableAccount> {
        todo!()
    }
}
