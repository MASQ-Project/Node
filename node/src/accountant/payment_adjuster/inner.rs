// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::SystemTime;

pub trait PaymentAdjusterInner {
    fn now(&self) -> SystemTime {
        PaymentAdjusterInnerNull::panicking_operation("now()")
    }
    fn gas_limitation_opt(&self) -> Option<u16> {
        PaymentAdjusterInnerNull::panicking_operation("gas_limitation_opt()")
    }
    fn cw_masq_balance(&self) -> u128 {
        PaymentAdjusterInnerNull::panicking_operation("cw_masq_balance()")
    }

    //TODO this method should use RefCell internally...and we could have PaymentAdjuster with &self instead of &mut self
    fn lower_remaining_cw_balance(&mut self, subtrahend: u128) {
        PaymentAdjusterInnerNull::panicking_operation("lower_remaining_cw_balance()")
    }
}

pub struct PaymentAdjusterInnerReal {
    now: SystemTime,
    gas_limitation_opt: Option<u16>,
    cw_masq_balance: u128,
}

impl PaymentAdjusterInnerReal {
    pub fn new(now: SystemTime, gas_limitation_opt: Option<u16>, cw_masq_balance: u128) -> Self {
        Self {
            now,
            gas_limitation_opt,
            cw_masq_balance,
        }
    }
}

impl PaymentAdjusterInner for PaymentAdjusterInnerReal {
    fn now(&self) -> SystemTime {
        self.now
    }
    fn gas_limitation_opt(&self) -> Option<u16> {
        self.gas_limitation_opt
    }
    fn cw_masq_balance(&self) -> u128 {
        self.cw_masq_balance
    }

    fn lower_remaining_cw_balance(&mut self, subtrahend: u128) {
        let lowered_theoretical_cw_balance = self
            .cw_masq_balance
            .checked_sub(subtrahend)
            .expect("should always subtract a small enough amount");
        self.cw_masq_balance = lowered_theoretical_cw_balance
    }
}

pub struct PaymentAdjusterInnerNull {}

impl PaymentAdjusterInnerNull {
    fn panicking_operation(operation: &str) -> ! {
        panic!(
            "Called the null implementation of the {} method in PaymentAdjusterInner",
            operation
        )
    }
}

impl PaymentAdjusterInner for PaymentAdjusterInnerNull {}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::inner::{
        PaymentAdjusterInner, PaymentAdjusterInnerNull,
    };

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the now() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_now() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.now();
    }

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the cw_masq_balance() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_cw_masq_balance() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.cw_masq_balance();
    }

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the gas_limitation_opt() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_gas_limitation_opt() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.gas_limitation_opt();
    }

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the lower_remaining_cw_balance() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_lower_remaining_cw_balance() {
        let mut subject = PaymentAdjusterInnerNull {};

        let _ = subject.lower_remaining_cw_balance(123);
    }
}
