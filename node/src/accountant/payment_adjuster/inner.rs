// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::SystemTime;

pub trait PaymentAdjusterInner {
    fn now(&self) -> SystemTime;
    fn transaction_fee_count_limit_opt(&self) -> Option<u16>;
    fn original_cw_service_fee_balance_minor(&self) -> u128;
    fn unallocated_cw_service_fee_balance_minor(&self) -> u128;
    fn subtract_from_unallocated_cw_service_fee_balance_minor(&mut self, subtrahend: u128);
}

pub struct PaymentAdjusterInnerReal {
    now: SystemTime,
    transaction_fee_count_limit_opt: Option<u16>,
    original_cw_service_fee_balance_minor: u128,
    unallocated_cw_service_fee_balance_minor: u128,
}

impl PaymentAdjusterInnerReal {
    pub fn new(
        now: SystemTime,
        transaction_fee_count_limit_opt: Option<u16>,
        cw_service_fee_balance_minor: u128,
    ) -> Self {
        Self {
            now,
            transaction_fee_count_limit_opt,
            original_cw_service_fee_balance_minor: cw_service_fee_balance_minor,
            unallocated_cw_service_fee_balance_minor: cw_service_fee_balance_minor,
        }
    }
}

impl PaymentAdjusterInner for PaymentAdjusterInnerReal {
    fn now(&self) -> SystemTime {
        self.now
    }
    fn transaction_fee_count_limit_opt(&self) -> Option<u16> {
        self.transaction_fee_count_limit_opt
    }
    fn original_cw_service_fee_balance_minor(&self) -> u128 {
        self.original_cw_service_fee_balance_minor
    }
    fn unallocated_cw_service_fee_balance_minor(&self) -> u128 {
        self.unallocated_cw_service_fee_balance_minor
    }
    fn subtract_from_unallocated_cw_service_fee_balance_minor(&mut self, subtrahend: u128) {
        let updated_thought_cw_balance = self
            .unallocated_cw_service_fee_balance_minor
            .checked_sub(subtrahend)
            .expect("should never go beyond zero");
        self.unallocated_cw_service_fee_balance_minor = updated_thought_cw_balance
    }
}

pub struct PaymentAdjusterInnerNull {}

impl PaymentAdjusterInnerNull {
    fn panicking_operation(operation: &str) -> ! {
        panic!(
            "Broken code: Broken code: Called the null implementation of the {} method in PaymentAdjusterInner",
            operation
        )
    }
}

impl PaymentAdjusterInner for PaymentAdjusterInnerNull {
    fn now(&self) -> SystemTime {
        PaymentAdjusterInnerNull::panicking_operation("now()")
    }
    fn transaction_fee_count_limit_opt(&self) -> Option<u16> {
        PaymentAdjusterInnerNull::panicking_operation("transaction_fee_count_limit_opt()")
    }
    fn original_cw_service_fee_balance_minor(&self) -> u128 {
        PaymentAdjusterInnerNull::panicking_operation("original_cw_service_fee_balance_minor()")
    }
    fn unallocated_cw_service_fee_balance_minor(&self) -> u128 {
        PaymentAdjusterInnerNull::panicking_operation("unallocated_cw_service_fee_balance_minor()")
    }
    fn subtract_from_unallocated_cw_service_fee_balance_minor(&mut self, _subtrahend: u128) {
        PaymentAdjusterInnerNull::panicking_operation(
            "subtract_from_unallocated_cw_service_fee_balance_minor()",
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::inner::{
        PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
    };
    use std::time::SystemTime;

    #[test]
    fn inner_real_is_constructed_correctly() {
        let now = SystemTime::now();
        let transaction_fee_count_limit_opt = Some(3);
        let cw_service_fee_balance = 123_456_789;
        let result = PaymentAdjusterInnerReal::new(
            now,
            transaction_fee_count_limit_opt,
            cw_service_fee_balance,
        );

        assert_eq!(result.now, now);
        assert_eq!(
            result.transaction_fee_count_limit_opt,
            transaction_fee_count_limit_opt
        );
        assert_eq!(
            result.original_cw_service_fee_balance_minor,
            cw_service_fee_balance
        );
        assert_eq!(
            result.unallocated_cw_service_fee_balance_minor,
            cw_service_fee_balance
        )
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the now() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_now() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.now();
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the transaction_fee_count_limit_opt() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_transaction_fee_count_limit_opt() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.transaction_fee_count_limit_opt();
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the original_cw_service_fee_balance_minor() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_original_cw_service_fee_balance_minor() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.original_cw_service_fee_balance_minor();
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the unallocated_cw_service_fee_balance_minor() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_unallocated_cw_balance() {
        let subject = PaymentAdjusterInnerNull {};

        let _ = subject.unallocated_cw_service_fee_balance_minor();
    }

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the subtract_from_unallocated_cw_service_fee_balance_minor() method in PaymentAdjusterInner"
    )]
    fn inner_null_calling_subtract_from_unallocated_cw_service_fee_balance_minor() {
        let mut subject = PaymentAdjusterInnerNull {};

        let _ = subject.subtract_from_unallocated_cw_service_fee_balance_minor(123);
    }
}
