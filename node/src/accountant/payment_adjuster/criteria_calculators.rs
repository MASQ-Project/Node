// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics::{
    compute_progressive_characteristics, COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS,
};
use libc::scanf;
use std::fmt::Debug;
use std::time::SystemTime;
use crate::accountant::payment_adjuster::auxiliary_fns::x_or_1;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;

pub trait CriterionCalculator {
    type Input;
    fn formula(&self) -> fn(Self::Input) -> u128;
    fn form_input(&self, account: &PayableAccount) -> Self::Input;
    fn diagnostics_config_opt(&self) -> Option<DiagnosticsConfig<Self::Input>>;

    fn add_calculated_criterion(
        &self,
        (criteria_sum, account): (u128, PayableAccount),
    ) -> (u128, PayableAccount)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        self.diagnostics();
        let updated_criteria_sum = criteria_sum + self.formula()(self.form_input(&account));
        (
            updated_criteria_sum,
            account,
        )
    }
    fn diagnostics(&self)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        if COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS {
            compute_progressive_characteristics(self.diagnostics_config_opt(), self.formula())
        }
    }
}

pub struct DiagnosticsConfig<A> {
    pub label: &'static str,
    pub safe_index_at_examples: usize,
    pub progressive_set_of_args: Vec<A>,
}

pub struct AgeCriterionCalculator<'a>{
    payment_adjuster: &'a PaymentAdjusterReal
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

impl <'a> AgeCriterionCalculator<'a>{
    pub fn new(payment_adjuster: &'a PaymentAdjusterReal)->Self{
        todo!()
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

impl CriterionCalculator for AgeCriterionCalculator<'_> {
    type Input = SystemTime;

    fn formula(&self) -> fn(Self::Input) -> u128 {
        todo!()
    }

    fn form_input(&self, account: &PayableAccount) -> Self::Input {
        todo!()
    }

    fn diagnostics_config_opt(&self) -> Option<DiagnosticsConfig<Self::Input>> {
        todo!()
    }

    // let formula = |last_paid_timestamp: SystemTime| {
    //     let elapsed_secs: u64 = self
    //         .inner
    //         .now()
    //         .duration_since(last_paid_timestamp)
    //         .expect("time traveller")
    //         .as_secs();
    //     let divisor = Self::compute_divisor(elapsed_secs);
    //     let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);
    //     (elapsed_secs as u128)
    //         .checked_pow(AGE_MAIN_EXPONENT)
    //         .unwrap_or(u128::MAX) //TODO sensible and tested ????
    //         .checked_div(divisor)
    //         .expect("div overflow")
    //         .checked_mul(log_multiplier)
    //         .expect("mul overflow")
    // };
    // let criterion = formula(account.last_paid_timestamp);
    //
    // CriteriaWithDiagnostics {
    //     account,
    //     criterion,
    //     criteria_sum_so_far,
    //     diagnostics: DiagnosticsSetting {
    //         label: "AGE",
    //         diagnostics_adaptive_formula: |x: u128| {
    //             let secs_in_the_past = Duration::from_secs(x as u64);
    //             let approx_time_anchor = SystemTime::now()
    //                 .checked_sub(secs_in_the_past)
    //                 .expect("age formula characteristics blew up");
    //             formula(approx_time_anchor)
    //         },
    //         singleton_ref: &AGE_SINGLETON,
    //         bonds_safe_count_to_print: 10,
    //     },
    // }
    //     .diagnose_and_sum()
}

pub struct BalanceCriterionCalculator<'a>{
    payment_adjuster:&'a PaymentAdjusterReal
}

impl <'a> BalanceCriterionCalculator<'a>{
    pub fn new(payment_adjuster: &'a PaymentAdjusterReal)->Self{
        todo!()
    }
}

impl CriterionCalculator for BalanceCriterionCalculator<'_> {
    type Input = u128;

    fn formula(&self) -> fn(Self::Input) -> u128 {
        todo!()
    }

    fn form_input(&self, account: &PayableAccount) -> Self::Input {
        todo!()
    }

    fn diagnostics_config_opt(&self) -> Option<DiagnosticsConfig<Self::Input>> {
        todo!()
    }

    // // constants used to keep the weights of balance and time balanced
    // let formula = |balance_wei: u128| {
    //     let binary_weight = log_2(Self::compute_binary_argument(balance_wei));
    //     let multiplied = balance_wei
    //         .checked_mul(binary_weight as u128)
    //         .expect("mul overflow");
    //     multiplied
    // };
    // let criterion = formula(account.balance_wei);
    //
    // CriteriaWithDiagnostics {
    //     account,
    //     criterion,
    //     criteria_sum_so_far,
    //     diagnostics: DiagnosticsSetting {
    //         label: "BALANCE",
    //         diagnostics_adaptive_formula: |x: u128| formula(x),
    //         singleton_ref: &BALANCE_SINGLETON,
    //         bonds_safe_count_to_print: EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS.len(),
    //     },
    // }
    //     .diagnose_and_sum()
}

pub(in crate::accountant::payment_adjuster) struct CriteriaIterator<I, C> {
    iter: I,
    calculator: C,
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
    fn map_criteria(self, calculator: C) -> CriteriaIterator<Self, C>
    where
        Self: Sized;
}

impl<C: CriterionCalculator, I: Iterator> CriteriaIteratorAdaptor<C> for I {
    fn map_criteria(self, calculator: C) -> CriteriaIterator<Self, C> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::criteria_calculators::{AGE_DESC_MULTIPLIER_ARG_EXP, AGE_DESC_MULTIPLIER_DIVISOR_EXP, AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, AGE_DESC_MULTIPLIER_LOG_STRESS_EXP, AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, AGE_DIVISOR_EXP_IN_NUMERATOR, AGE_MAIN_EXPONENT, AGE_MULTIPLIER, AgeCriterionCalculator, CriterionCalculator};
    use crate::accountant::payment_adjuster::diagnostics::EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS;
    use crate::accountant::payment_adjuster::PaymentAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::make_initialized_subject;
    use crate::test_utils::make_wallet;

    #[test]
    fn constants_are_correct(){
        assert_eq!(AGE_MAIN_EXPONENT, 4);
        assert_eq!(AGE_DIVISOR_EXP_IN_NUMERATOR, 3);
        assert_eq!(AGE_MULTIPLIER, 10);
        assert_eq!(AGE_DESC_MULTIPLIER_ARG_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP, 2);
        assert_eq!(AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, 1_000);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, 10);
        assert_eq!(AGE_DESC_MULTIPLIER_DIVISOR_EXP, 3);
    }

    // let formula = |last_paid_timestamp: SystemTime| {
    //     let elapsed_secs: u64 = self
    //         .inner
    //         .now()
    //         .duration_since(last_paid_timestamp)
    //         .expect("time traveller")
    //         .as_secs();
    //     let divisor = Self::compute_divisor(elapsed_secs);
    //     let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);
    //     (elapsed_secs as u128)
    //         .checked_pow(AGE_MAIN_EXPONENT)
    //         .unwrap_or(u128::MAX) //TODO sensible and tested ????
    //         .checked_div(divisor)
    //         .expect("div overflow")
    //         .checked_mul(log_multiplier)
    //         .expect("mul overflow")
    // };

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
        let result: Vec<_> = EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS
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
    fn age_criteria_calculation_works(){
        let now = SystemTime::now();
        let payment_adjuster = make_initialized_subject(now, None, None);
        let subject = AgeCriterionCalculator::new(&payment_adjuster);
        let input = SystemTime::now().checked_sub(Duration::from_secs(1500)).unwrap();

        let result = subject.formula()(input);

        let expected_criterion = {
            let elapsed_secs: u64 = subject.payment_adjuster.inner
                .now()
                .duration_since(input)
                .unwrap()
                .as_secs();
            let divisor = AgeCriterionCalculator::compute_divisor(elapsed_secs);
            let log_multiplier = AgeCriterionCalculator::compute_descending_multiplier(elapsed_secs, divisor);
            (elapsed_secs as u128)
                .checked_pow(AGE_MAIN_EXPONENT)
                .unwrap_or(u128::MAX) //TODO sensible and tested ????
                .checked_div(divisor)
                .unwrap()
                .checked_mul(log_multiplier)
                .unwrap()
        };
        assert_eq!(result, expected_criterion)
    }

    #[test]
    fn balance_criteria_calculation_works(){
        todo!()
    }

}
