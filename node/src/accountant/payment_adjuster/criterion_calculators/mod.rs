// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod balance_calculator;

use crate::accountant::payment_adjuster::inner::PaymentAdjusterInner;
use crate::accountant::QualifiedPayableAccount;

// Caution: always remember to use checked math operations in the criteria formulas!
pub trait CriterionCalculator {
    fn calculate(&self, account: &QualifiedPayableAccount, context: &PaymentAdjusterInner) -> u128;

    fn parameter_name(&self) -> &'static str;
}
