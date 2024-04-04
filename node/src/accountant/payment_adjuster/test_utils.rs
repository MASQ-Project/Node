// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationGauge;
use crate::accountant::payment_adjuster::inner::{PaymentAdjusterInner, PaymentAdjusterInnerReal};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, UnconfirmedAdjustment,
};
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
use crate::accountant::QualifiedPayableAccount;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::test_utils::make_wallet;
use itertools::Either;
use lazy_static::lazy_static;
use masq_lib::constants::MASQ_TOTAL_SUPPLY;
use masq_lib::logger::Logger;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR: u128 =
        MASQ_TOTAL_SUPPLY as u128 * 10_u128.pow(18);
    pub static ref ONE_MONTH_LONG_DEBT_SEC: u64 = 30 * 24 * 60 * 60;
}

pub fn make_initialized_subject(
    now: SystemTime,
    cw_service_fee_balance_minor_opt: Option<u128>,
    logger_opt: Option<Logger>,
) -> PaymentAdjusterReal {
    let cw_masq_balance_minor = cw_service_fee_balance_minor_opt.unwrap_or(0);
    let logger = logger_opt.unwrap_or(Logger::new("test"));
    let mut subject = PaymentAdjusterReal::default();
    subject.logger = logger;
    subject.inner = Box::new(PaymentAdjusterInnerReal::new(
        now,
        None,
        cw_masq_balance_minor,
    ));
    subject
}

pub fn make_extreme_payables(
    months_of_debt_and_balance_minor: Either<(Vec<usize>, u128), Vec<(usize, u128)>>,
    now: SystemTime,
) -> Vec<PayableAccount> {
    let accounts_seeds: Vec<(usize, u128)> = match months_of_debt_and_balance_minor {
        Either::Left((vec_of_months, constant_balance)) => vec_of_months
            .into_iter()
            .map(|months| (months, constant_balance))
            .collect(),
        Either::Right(specific_months_and_specific_balance) => specific_months_and_specific_balance,
    };
    accounts_seeds
        .into_iter()
        .enumerate()
        .map(|(idx, (months_count, balance_minor))| PayableAccount {
            wallet: make_wallet(&format!("blah{}", idx)),
            balance_wei: balance_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    months_count as u64 * (*ONE_MONTH_LONG_DEBT_SEC),
                ))
                .unwrap(),
            pending_payable_opt: None,
        })
        .collect()
}

pub(in crate::accountant::payment_adjuster) const PRESERVED_TEST_PAYMENT_THRESHOLDS:
    PaymentThresholds = PaymentThresholds {
    debt_threshold_gwei: 2_000_000,
    maturity_threshold_sec: 1_000,
    payment_grace_period_sec: 1_000,
    permanent_debt_allowed_gwei: 1_000_000,
    threshold_interval_sec: 500_000,
    unban_below_gwei: 1_000_000,
};

pub fn assert_constants_and_remind_checking_sync_of_calculators_if_any_constant_changes(
    constants_and_expected_values: &[(i128, i128)],
    expected_num_sum: i128,
) {
    constants_and_expected_values.iter().enumerate().for_each(
        |(idx, (constant, expected_value))| {
            assert_eq!(
                constant, expected_value,
                "constant wrong value at position {}",
                idx
            )
        },
    );

    // This matters only if the constants participate in the calculator's formula. If that's not
    // true, simply update the num sum and ignore the concern about synchronization
    let actual_sum: i128 = constants_and_expected_values
        .iter()
        .map(|(val, _)| *val)
        .sum();
    assert_eq!(actual_sum, expected_num_sum,
               "The sum of constants used to calibre the calculator has changed, therefore you ought to see about \n\
               maintenance of the whole system with its all parameters (e.g. debt age, debt balance,...) and make \n\
               sure the weights coming from them are sensibly proportionate. There is a tool that can help you with \n\
               that, look for a global flag in the file 'diagnostics' in the PaymentAdjuster module. It will enable \n\
               rendering characteristics of the curves the calculations of these parameters are based on."
    )
}

pub fn make_non_guaranteed_unconfirmed_adjustment(n: u64) -> UnconfirmedAdjustment {
    let qualified_payable = make_non_guaranteed_qualified_payable(n);
    let proposed_adjusted_balance_minor =
        (qualified_payable.qualified_as.balance_wei / 2) * (n as f64).sqrt() as u128;
    UnconfirmedAdjustment {
        non_finalized_account: AdjustedAccountBeforeFinalization {
            qualified_payable,
            proposed_adjusted_balance_minor,
        },
        weight: (n as u128).pow(3),
    }
}

#[derive(Default)]
pub struct CriterionCalculatorMock {
    calculate_results: RefCell<Vec<u128>>,
}

impl CriterionCalculator for CriterionCalculatorMock {
    fn calculate(
        &self,
        _account: &QualifiedPayableAccount,
        _context: &dyn PaymentAdjusterInner,
    ) -> u128 {
        // TODO consider using params assertions
        self.calculate_results.borrow_mut().remove(0)
    }

    fn parameter_name(&self) -> &'static str {
        "MOCKED CALCULATOR"
    }
}

impl CriterionCalculatorMock {
    pub fn calculate_result(self, result: u128) -> Self {
        self.calculate_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct DisqualificationGaugeMock {
    determine_limit_params: Arc<Mutex<Vec<(u128, u128, u128)>>>,
    determine_limit_results: RefCell<Vec<u128>>,
}

impl DisqualificationGauge for DisqualificationGaugeMock {
    fn determine_limit(
        &self,
        account_balance_wei: u128,
        threshold_intercept_wei: u128,
        permanent_debt_allowed_wei: u128,
    ) -> u128 {
        self.determine_limit_params.lock().unwrap().push((
            account_balance_wei,
            threshold_intercept_wei,
            permanent_debt_allowed_wei,
        ));
        self.determine_limit_results.borrow_mut().remove(0)
    }
}

impl DisqualificationGaugeMock {
    pub fn determine_limit_params(mut self, params: &Arc<Mutex<Vec<(u128, u128, u128)>>>) -> Self {
        self.determine_limit_params = params.clone();
        self
    }

    pub fn determine_limit_result(mut self, result: u128) -> Self {
        self.determine_limit_results.borrow_mut().push(result);
        self
    }
}
