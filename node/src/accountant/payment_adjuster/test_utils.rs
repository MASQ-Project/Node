// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::disqualification_arbiter::{
    DisqualificationArbiter, DisqualificationGauge,
};
use crate::accountant::payment_adjuster::inner::{PaymentAdjusterInner, PaymentAdjusterInnerReal};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustmentIterationResult, UnconfirmedAdjustment, WeightedPayable,
};
use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjuster;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::accountant::test_utils::{make_analyzed_account, make_non_guaranteed_qualified_payable};
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
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
    now_opt: Option<SystemTime>,
    cw_service_fee_balance_minor_opt: Option<u128>,
    criterion_calculator_mock_opt: Option<CriterionCalculatorMock>,
    largest_exceeding_balance_recently_qualified: Option<u128>,
    logger_opt: Option<Logger>,
) -> PaymentAdjusterReal {
    let cw_service_fee_balance_minor = cw_service_fee_balance_minor_opt.unwrap_or(0);
    let logger = logger_opt.unwrap_or(Logger::new("test"));
    let mut subject = PaymentAdjusterReal::default();
    subject.logger = logger;
    subject.inner = Box::new(PaymentAdjusterInnerReal::new(
        now_opt.unwrap_or(SystemTime::now()),
        None,
        cw_service_fee_balance_minor,
        largest_exceeding_balance_recently_qualified.unwrap_or(0),
    ));
    if let Some(calculator) = criterion_calculator_mock_opt {
        subject.calculators = vec![Box::new(calculator)]
    }
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

pub fn make_non_guaranteed_unconfirmed_adjustment(n: u64) -> UnconfirmedAdjustment {
    let qualified_account = make_non_guaranteed_qualified_payable(n);
    let proposed_adjusted_balance_minor =
        (qualified_account.bare_account.balance_wei / 2) * (n as f64).sqrt() as u128;
    let disqualification_limit_minor = (3 * proposed_adjusted_balance_minor) / 4;
    let analyzed_account =
        AnalyzedPayableAccount::new(qualified_account, disqualification_limit_minor);
    let weight = (n as u128).pow(3);
    UnconfirmedAdjustment::new(
        WeightedPayable::new(analyzed_account, weight),
        proposed_adjusted_balance_minor,
    )
}

#[derive(Default)]
pub struct CriterionCalculatorMock {
    calculate_params: Arc<Mutex<Vec<QualifiedPayableAccount>>>,
    calculate_results: RefCell<Vec<u128>>,
}

impl CriterionCalculator for CriterionCalculatorMock {
    fn calculate(
        &self,
        account: &QualifiedPayableAccount,
        _context: &dyn PaymentAdjusterInner,
    ) -> u128 {
        self.calculate_params.lock().unwrap().push(account.clone());
        self.calculate_results.borrow_mut().remove(0)
    }

    fn parameter_name(&self) -> &'static str {
        "MOCKED CALCULATOR"
    }
}

impl CriterionCalculatorMock {
    pub fn calculate_params(mut self, params: &Arc<Mutex<Vec<QualifiedPayableAccount>>>) -> Self {
        self.calculate_params = params.clone();
        self
    }
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

    pub fn determine_limit_result(self, result: u128) -> Self {
        self.determine_limit_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct ServiceFeeAdjusterMock {
    perform_adjustment_by_service_fee_params: Arc<Mutex<Vec<(Vec<WeightedPayable>, u128)>>>,
    perform_adjustment_by_service_fee_results: RefCell<Vec<AdjustmentIterationResult>>,
}
impl ServiceFeeAdjuster for ServiceFeeAdjusterMock {
    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        _disqualification_arbiter: &DisqualificationArbiter,
        unallocated_cw_service_fee_balance_minor: u128,
        _logger: &Logger,
    ) -> AdjustmentIterationResult {
        self.perform_adjustment_by_service_fee_params
            .lock()
            .unwrap()
            .push((weighted_accounts, unallocated_cw_service_fee_balance_minor));
        self.perform_adjustment_by_service_fee_results
            .borrow_mut()
            .remove(0)
    }
}

impl ServiceFeeAdjusterMock {
    pub fn perform_adjustment_by_service_fee_params(
        mut self,
        params: &Arc<Mutex<Vec<(Vec<WeightedPayable>, u128)>>>,
    ) -> Self {
        self.perform_adjustment_by_service_fee_params = params.clone();
        self
    }

    pub fn perform_adjustment_by_service_fee_result(
        self,
        result: AdjustmentIterationResult,
    ) -> Self {
        self.perform_adjustment_by_service_fee_results
            .borrow_mut()
            .push(result);
        self
    }
}

pub fn multiple_by_billion(num: u128) -> u128 {
    num * 10_u128.pow(9)
}
pub fn make_analyzed_account_by_wallet(wallet_address_segment: &str) -> AnalyzedPayableAccount {
    let num = u64::from_str_radix(wallet_address_segment, 16).unwrap();
    let wallet = make_wallet(wallet_address_segment);
    let mut account = make_analyzed_account(num);
    account.qualified_as.bare_account.wallet = wallet;
    account
}

pub fn make_weighed_account(n: u64) -> WeightedPayable {
    WeightedPayable::new(make_analyzed_account(n), 123456789)
}

// Should stay test only!
impl From<QualifiedPayableAccount> for AnalyzedPayableAccount {
    fn from(qualified_account: QualifiedPayableAccount) -> Self {
        let disqualification_limit =
            DisqualificationArbiter::default().calculate_disqualification_edge(&qualified_account);
        AnalyzedPayableAccount::new(qualified_account, disqualification_limit)
    }
}
