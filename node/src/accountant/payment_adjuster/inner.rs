// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cell::RefCell;

pub struct PaymentAdjusterInner {
    initialized_guts_opt: RefCell<Option<GutsOfPaymentAdjusterInner>>,
}

impl Default for PaymentAdjusterInner {
    fn default() -> Self {
        PaymentAdjusterInner {
            initialized_guts_opt: RefCell::new(None),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GutsOfPaymentAdjusterInner {
    transaction_count_limit_opt: Option<u16>,
    max_debt_above_threshold_in_qualified_payables_minor: u128,
    original_cw_service_fee_balance_minor: u128,
    remaining_cw_service_fee_balance_minor: u128,
}

impl GutsOfPaymentAdjusterInner {
    pub fn new(
        transaction_count_limit_opt: Option<u16>,
        cw_service_fee_balance_minor: u128,
        max_debt_above_threshold_in_qualified_payables_minor: u128,
    ) -> Self {
        Self {
            transaction_count_limit_opt,
            max_debt_above_threshold_in_qualified_payables_minor,
            original_cw_service_fee_balance_minor: cw_service_fee_balance_minor,
            remaining_cw_service_fee_balance_minor: cw_service_fee_balance_minor,
        }
    }
}

impl PaymentAdjusterInner {
    pub fn initialize_guts(
        &self,
        tx_count_limit_opt: Option<u16>,
        cw_service_fee_balance: u128,
        max_debt_above_threshold_in_qualified_payables_minor: u128,
    ) {
        let initialized_guts = GutsOfPaymentAdjusterInner::new(
            tx_count_limit_opt,
            cw_service_fee_balance,
            max_debt_above_threshold_in_qualified_payables_minor,
        );

        self.initialized_guts_opt
            .borrow_mut()
            .replace(initialized_guts);
    }

    pub fn max_debt_above_threshold_in_qualified_payables_minor(&self) -> u128 {
        self.get_value(
            "max_debt_above_threshold_in_qualified_payables_minor",
            |guts_ref| guts_ref.max_debt_above_threshold_in_qualified_payables_minor,
        )
    }

    pub fn transaction_count_limit_opt(&self) -> Option<u16> {
        self.get_value("transaction_count_limit_opt", |guts_ref| {
            guts_ref.transaction_count_limit_opt
        })
    }
    pub fn original_cw_service_fee_balance_minor(&self) -> u128 {
        self.get_value("original_cw_service_fee_balance_minor", |guts_ref| {
            guts_ref.original_cw_service_fee_balance_minor
        })
    }
    pub fn remaining_cw_service_fee_balance_minor(&self) -> u128 {
        self.get_value("remaining_cw_service_fee_balance_minor", |guts_ref| {
            guts_ref.remaining_cw_service_fee_balance_minor
        })
    }
    pub fn subtract_from_remaining_cw_service_fee_balance_minor(&self, subtrahend: u128) {
        let updated_thought_cw_balance = self.get_value(
            "subtract_from_remaining_cw_service_fee_balance_minor",
            |guts_ref| {
                guts_ref
                    .remaining_cw_service_fee_balance_minor
                    .checked_sub(subtrahend)
                    .expect("should never go beyond zero")
            },
        );
        self.set_value(
            "subtract_from_remaining_cw_service_fee_balance_minor",
            |guts_mut| guts_mut.remaining_cw_service_fee_balance_minor = updated_thought_cw_balance,
        )
    }

    pub fn invalidate_guts(&self) {
        self.initialized_guts_opt.replace(None);
    }

    fn get_value<T, F>(&self, method: &str, getter: F) -> T
    where
        F: FnOnce(&GutsOfPaymentAdjusterInner) -> T,
    {
        let guts_borrowed_opt = self.initialized_guts_opt.borrow();

        let guts_ref = guts_borrowed_opt
            .as_ref()
            .unwrap_or_else(|| Self::uninitialized_panic(method));

        getter(guts_ref)
    }

    fn set_value<F>(&self, method: &str, mut setter: F)
    where
        F: FnMut(&mut GutsOfPaymentAdjusterInner),
    {
        let mut guts_borrowed_mut_opt = self.initialized_guts_opt.borrow_mut();

        let guts_mut = guts_borrowed_mut_opt
            .as_mut()
            .unwrap_or_else(|| Self::uninitialized_panic(method));

        setter(guts_mut)
    }

    fn uninitialized_panic(method: &str) -> ! {
        panic!(
            "PaymentAdjusterInner is uninitialized. It was identified during the execution of \
        '{method}()'"
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::inner::{
        GutsOfPaymentAdjusterInner, PaymentAdjusterInner,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn defaulted_payment_adjuster_inner() {
        let subject = PaymentAdjusterInner::default();

        let guts_is_none = subject.initialized_guts_opt.borrow().is_none();
        assert_eq!(guts_is_none, true)
    }

    #[test]
    fn initialization_and_getters_of_payment_adjuster_inner_work() {
        let subject = PaymentAdjusterInner::default();
        let tx_count_limit_opt = Some(3);
        let cw_service_fee_balance = 123_456_789;
        let max_debt_above_threshold_in_qualified_payables_minor = 44_555_666;

        subject.initialize_guts(
            tx_count_limit_opt,
            cw_service_fee_balance,
            max_debt_above_threshold_in_qualified_payables_minor,
        );
        let read_max_debt_above_threshold_in_qualified_payables_minor =
            subject.max_debt_above_threshold_in_qualified_payables_minor();
        let read_tx_count_limit_opt = subject.transaction_count_limit_opt();
        let read_original_cw_service_fee_balance_minor =
            subject.original_cw_service_fee_balance_minor();
        let read_remaining_cw_service_fee_balance_minor =
            subject.remaining_cw_service_fee_balance_minor();

        assert_eq!(
            read_max_debt_above_threshold_in_qualified_payables_minor,
            max_debt_above_threshold_in_qualified_payables_minor
        );
        assert_eq!(read_tx_count_limit_opt, tx_count_limit_opt);
        assert_eq!(
            read_original_cw_service_fee_balance_minor,
            cw_service_fee_balance
        );
        assert_eq!(
            read_remaining_cw_service_fee_balance_minor,
            cw_service_fee_balance
        );
    }

    #[test]
    fn reducing_remaining_cw_service_fee_balance_works() {
        let initial_cw_service_fee_balance_minor = 123_123_678_678;
        let subject = PaymentAdjusterInner::default();
        subject.initialize_guts(None, initial_cw_service_fee_balance_minor, 12345);
        let amount_to_subtract = 555_666_777;

        subject.subtract_from_remaining_cw_service_fee_balance_minor(amount_to_subtract);

        let remaining_cw_service_fee_balance_minor =
            subject.remaining_cw_service_fee_balance_minor();
        assert_eq!(
            remaining_cw_service_fee_balance_minor,
            initial_cw_service_fee_balance_minor - amount_to_subtract
        )
    }

    #[test]
    fn inner_can_be_invalidated_by_removing_its_guts() {
        let subject = PaymentAdjusterInner::default();
        subject
            .initialized_guts_opt
            .replace(Some(GutsOfPaymentAdjusterInner {
                transaction_count_limit_opt: None,
                max_debt_above_threshold_in_qualified_payables_minor: 0,
                original_cw_service_fee_balance_minor: 0,
                remaining_cw_service_fee_balance_minor: 0,
            }));

        subject.invalidate_guts();

        let guts_removed = subject.initialized_guts_opt.borrow().is_none();
        assert_eq!(guts_removed, true)
    }

    #[test]
    fn reasonable_panics_about_lacking_initialization_for_respective_methods() {
        let uninitialized_subject = PaymentAdjusterInner::default();
        test_properly_implemented_panic(
            &uninitialized_subject,
            "max_debt_above_threshold_in_qualified_payables_minor",
            |subject| {
                subject.max_debt_above_threshold_in_qualified_payables_minor();
            },
        );
        test_properly_implemented_panic(
            &uninitialized_subject,
            "transaction_count_limit_opt",
            |subject| {
                subject.transaction_count_limit_opt();
            },
        );
        test_properly_implemented_panic(
            &uninitialized_subject,
            "original_cw_service_fee_balance_minor",
            |subject| {
                subject.original_cw_service_fee_balance_minor();
            },
        );
        test_properly_implemented_panic(
            &uninitialized_subject,
            "remaining_cw_service_fee_balance_minor",
            |subject| {
                subject.remaining_cw_service_fee_balance_minor();
            },
        );
        test_properly_implemented_panic(
            &uninitialized_subject,
            "subtract_from_remaining_cw_service_fee_balance_minor",
            |subject| {
                subject.subtract_from_remaining_cw_service_fee_balance_minor(123456);
            },
        )
    }

    fn test_properly_implemented_panic(
        subject: &PaymentAdjusterInner,
        method_name: &str,
        call_panicking_method: fn(&PaymentAdjusterInner),
    ) {
        let caught_panic =
            catch_unwind(AssertUnwindSafe(|| call_panicking_method(subject))).unwrap_err();
        let actual_panic_msg = caught_panic.downcast_ref::<String>().unwrap().to_owned();
        let expected_msg = format!(
            "PaymentAdjusterInner is uninitialized. It was \
        identified during the execution of '{method_name}()'"
        );
        assert_eq!(
            actual_panic_msg, expected_msg,
            "We expected this panic message: {}, but the panic looked different: {}",
            expected_msg, actual_panic_msg
        )
    }
}
