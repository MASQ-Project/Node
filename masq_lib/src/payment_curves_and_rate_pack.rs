// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::{Deserialize, Serialize};
use std::fmt;

#[derive(PartialEq, Debug, Clone)]
pub struct PaymentCurves {
    pub payment_suggested_after_sec: i64,
    pub payment_grace_before_ban_sec: i64,
    pub permanent_debt_allowed_gwei: i64,
    pub balance_to_decrease_from_gwei: i64,
    pub balance_decreases_for_sec: i64,
    pub unban_when_balance_below_gwei: i64,
}

//this code is used in tests in Accountant
impl PaymentCurves {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - self.payment_suggested_after_sec - self.payment_grace_before_ban_sec
    }

    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - self.balance_decreases_for_sec
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RatePack {
    pub routing_byte_rate: u64,
    pub routing_service_rate: u64,
    pub exit_byte_rate: u64,
    pub exit_service_rate: u64,
}

impl fmt::Display for RatePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}+{}b route {}+{}b exit",
            self.routing_service_rate,
            self.routing_byte_rate,
            self.exit_service_rate,
            self.exit_byte_rate
        )
    }
}
