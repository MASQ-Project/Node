// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::auxiliary_fns::{log_2, x_or_1};
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
    compute_progressive_characteristics, DiagnosticsConfig, AGE_DIAGNOSTICS_CONFIG_OPT,
    BALANCE_DIAGNOSTICS_CONFIG_OPT, COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS,
};
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use std::fmt::Debug;
use std::sync::Mutex;
use std::time::SystemTime;

//caution: always remember to use checked math operations in the formula!
pub trait CriterionCalculator {
    type Input;
    fn formula(&self) -> &dyn Fn(Self::Input) -> u128;
    fn input_from_account(&self, account: &PayableAccount) -> Self::Input;

    fn add_calculated_criterion(
        &self,
        (criteria_sum, account): (u128, PayableAccount),
    ) -> (u128, PayableAccount)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        #[cfg(test)]
        self.diagnostics();

        let updated_criteria_sum = criteria_sum + self.formula()(self.input_from_account(&account));
        (updated_criteria_sum, account)
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>>;
    #[cfg(test)]
    fn diagnostics_config_opt(&self) -> Option<DiagnosticsConfig<Self::Input>> {
        self.diagnostics_config_location()
            .lock()
            .expect("diagnostics poisoned")
            .take()
    }
    #[cfg(test)]
    fn diagnostics(&self)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        if COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS {
            compute_progressive_characteristics(self.diagnostics_config_opt(), self.formula())
        }
    }
}

const AGE_MAIN_EXPONENT: u32 = 3;
// divisor^(numerator/denominator)
const AGE_DIVISOR_EXP_IN_NUMERATOR: u32 = 3;
const AGE_MULTIPLIER: u128 = 150;
const AGE_DESC_MULTIPLIER_ARG_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER: u128 = 1_000;
const AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER: u128 = 10;
const AGE_DESC_MULTIPLIER_DIVISOR_EXP: u32 = 3;

pub struct AgeCriterionCalculator {
    formula: Box<dyn Fn(SystemTime) -> u128>,
}

impl AgeCriterionCalculator {
    pub fn new(payment_adjuster: &PaymentAdjusterReal) -> Self {
        let now = payment_adjuster.inner.now();
        let formula = Box::new(move |last_paid_timestamp: SystemTime| {
            let elapsed_secs: u64 = now
                .duration_since(last_paid_timestamp)
                .expect("time traveller")
                .as_secs();
            let divisor = Self::compute_divisor(elapsed_secs);
            let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);
            (elapsed_secs as u128)
                .checked_pow(AGE_MAIN_EXPONENT)
                .unwrap_or(u128::MAX) //TODO sensible and tested ????
                .checked_div(divisor)
                .expect("div overflow")
                .checked_mul(log_multiplier)
                .expect("mul overflow")
        });
        Self { formula }
    }

    fn compute_divisor(elapsed_sec: u64) -> u128 {
        (elapsed_sec as f64).sqrt().ceil() as u128
    }

    fn compute_descending_multiplier(elapsed_secs: u64, divisor: u128) -> u128 {
        let fast_growing_argument = (elapsed_secs as u128)
            .checked_pow(AGE_DESC_MULTIPLIER_ARG_EXP)
            .expect("pow blew up") as f64;
        let log = fast_growing_argument.ln();
        let log_stressed = (log as u128).pow(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP)
            * AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER;
        let final_log_multiplier = (log_stressed
            / (divisor * AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER))
            .pow(AGE_DESC_MULTIPLIER_DIVISOR_EXP);
        x_or_1(final_log_multiplier)
    }
}

impl CriterionCalculator for AgeCriterionCalculator {
    type Input = SystemTime;

    fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
        self.formula.as_ref()
    }

    fn input_from_account(&self, account: &PayableAccount) -> Self::Input {
        account.last_paid_timestamp
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>> {
        &AGE_DIAGNOSTICS_CONFIG_OPT
    }
}

// this parameter affects the steepness (sensitivity on increase in balance)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 33;

pub struct BalanceCriterionCalculator {
    formula: Box<dyn Fn(u128) -> u128>,
}

impl BalanceCriterionCalculator {
    pub fn new() -> Self {
        let formula = Box::new(|balance_wei: u128| {
            let binary_weight = log_2(Self::compute_binary_argument(balance_wei));
            balance_wei
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
        });
        Self { formula }
    }

    fn compute_binary_argument(balance_wei: u128) -> u128 {
        x_or_1(balance_wei / BALANCE_LOG_2_ARG_DIVISOR)
    }
}

impl CriterionCalculator for BalanceCriterionCalculator {
    type Input = u128;

    fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
        self.formula.as_ref()
    }

    fn input_from_account(&self, account: &PayableAccount) -> Self::Input {
        account.balance_wei
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>> {
        &BALANCE_DIAGNOSTICS_CONFIG_OPT
    }
}

pub(in crate::accountant::payment_adjuster) struct CriteriaIterator<I, C> {
    iter: I,
    calculator: C,
}

impl<I, C> CriteriaIterator<I, C> {
    fn new(iter: I, calculator: C) -> Self {
        Self { iter, calculator }
    }
}

impl<I, C> Iterator for CriteriaIterator<I, C>
where
    I: Iterator<Item = (u128, PayableAccount)>,
    C: CriterionCalculator,
    <C as CriterionCalculator>::Input: Debug,
{
    type Item = (u128, PayableAccount);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|item| self.calculator.add_calculated_criterion(item))
    }
}

pub(in crate::accountant::payment_adjuster) trait CriteriaIteratorAdaptor<C: CriterionCalculator> {
    fn iterate_for_criteria(self, calculator: C) -> CriteriaIterator<Self, C>
    where
        Self: Sized;
}

impl<C: CriterionCalculator, I: Iterator> CriteriaIteratorAdaptor<C> for I {
    fn iterate_for_criteria(self, calculator: C) -> CriteriaIterator<Self, C> {
        CriteriaIterator::new(self, calculator)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::auxiliary_fns::log_2;
    use crate::accountant::payment_adjuster::criteria_calculators::{
        AgeCriterionCalculator, BalanceCriterionCalculator, CriterionCalculator,
        AGE_DESC_MULTIPLIER_ARG_EXP, AGE_DESC_MULTIPLIER_DIVISOR_EXP,
        AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, AGE_DESC_MULTIPLIER_LOG_STRESS_EXP,
        AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, AGE_DIVISOR_EXP_IN_NUMERATOR, AGE_MAIN_EXPONENT,
        AGE_MULTIPLIER, BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::test_utils::make_initialized_subject;
    use std::time::{Duration, SystemTime};

    #[test]
    fn constants_are_correct() {
        assert_eq!(AGE_MAIN_EXPONENT, 3);
        assert_eq!(AGE_DIVISOR_EXP_IN_NUMERATOR, 3);
        assert_eq!(AGE_MULTIPLIER, 10);
        assert_eq!(AGE_DESC_MULTIPLIER_ARG_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, 1_000);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, 10);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_EXP, 3);
    }

    #[test]
    fn compute_divisor_works() {
        let result: Vec<_> = [100, 81, 82, 80]
            .into_iter()
            .map(|secs| AgeCriterionCalculator::compute_divisor(secs))
            .collect();

        assert_eq!(result, vec![10, 9, 10, 9])
    }

    #[test]
    fn compute_descending_multiplier_works() {
        let result: Vec<_> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18]
            .into_iter()
            .take(12)
            .map(|exp| 10_u64.pow(exp))
            .map(|seconds_elapsed| {
                let divisor = AgeCriterionCalculator::compute_divisor(seconds_elapsed);
                AgeCriterionCalculator::compute_descending_multiplier(seconds_elapsed, divisor)
            })
            .collect();

        assert_eq!(
            result,
            vec![
                64000000, 531441000, 147197952, 34012224, 4574296, 373248, 32768, 1728, 125, 1, 1,
                1
            ]
        )
    }

    #[test]
    fn age_criteria_calculation_works() {
        let now = SystemTime::now();
        let payment_adjuster = make_initialized_subject(now, None, None);
        let subject = AgeCriterionCalculator::new(&payment_adjuster);
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(1500))
            .unwrap();

        let result = subject.formula()(last_paid_timestamp);

        let expected_criterion = {
            let elapsed_secs: u64 = now.duration_since(last_paid_timestamp).unwrap().as_secs();
            let divisor = AgeCriterionCalculator::compute_divisor(elapsed_secs);
            let log_multiplier =
                AgeCriterionCalculator::compute_descending_multiplier(elapsed_secs, divisor);
            (elapsed_secs as u128)
                .checked_pow(AGE_MAIN_EXPONENT)
                .unwrap()
                .checked_div(divisor)
                .unwrap()
                .checked_mul(log_multiplier)
                .unwrap()
        };
        assert_eq!(result, expected_criterion)
    }

    #[test]
    fn compute_binary_argument_works() {
        let inputs = [
            1,
            BALANCE_LOG_2_ARG_DIVISOR - 1,
            BALANCE_LOG_2_ARG_DIVISOR,
            BALANCE_LOG_2_ARG_DIVISOR + 1,
            BALANCE_LOG_2_ARG_DIVISOR + 1000,
        ];

        let result: Vec<_> = inputs
            .into_iter()
            .map(|arg| BalanceCriterionCalculator::compute_binary_argument(arg))
            .collect();

        assert_eq!(
            result,
            vec![
                1,
                1,
                1,
                1,
                (BALANCE_LOG_2_ARG_DIVISOR + 1000) / BALANCE_LOG_2_ARG_DIVISOR
            ]
        )
    }

    #[test]
    fn balance_criteria_calculation_works() {
        let subject = BalanceCriterionCalculator::new();
        let balance_wei = 111_333_555_777;

        let result = subject.formula()(balance_wei);

        let expected_result = {
            let binary_weight = log_2(BalanceCriterionCalculator::compute_binary_argument(
                balance_wei,
            ));
            balance_wei
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
        };
        assert_eq!(result, expected_result)
    }
}
