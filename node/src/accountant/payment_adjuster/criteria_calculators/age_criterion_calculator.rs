// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::criteria_calculators::{
    CalculatorInputHolder, CalculatorType, CriterionCalculator,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::x_or_1;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use std::time::SystemTime;

// Base is the main body of the growing value
const AGE_EXPONENT_FOR_BASE: u32 = 3;

// Descending multiplier is the parameter that slows down the growth of the base. We start with a huge multiplier that
// diminishes as the age of the debt stretches
const AGE_DESC_MULTIPLIER_ARG_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER: u128 = 550;
const AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER: u128 = 13;
const AGE_DESC_MULTIPLIER_DIVISOR_EXP: u32 = 4;

pub struct AgeCriterionCalculator {
    formula: Box<dyn Fn(CalculatorInputHolder) -> u128>,
}

impl CriterionCalculator for AgeCriterionCalculator {
    fn formula(&self) -> &dyn Fn(CalculatorInputHolder) -> u128 {
        &self.formula
    }

    fn calculator_type(&self) -> CalculatorType {
        CalculatorType::DebtAge
    }
}

impl AgeCriterionCalculator {
    pub fn new(payment_adjuster: &PaymentAdjusterReal) -> Self {
        let now = payment_adjuster.inner.now();

        let formula = Box::new(
            move |last_paid_timestamp_in_holder: CalculatorInputHolder| {
                let last_paid_timestamp = last_paid_timestamp_in_holder.age_input();
                let elapsed_secs: u64 = Self::nonzero_elapsed(now, last_paid_timestamp);

                // This argument slows down the growth of the power of 3 in the base value, but unlike to the descending
                // multiplier below, this happens consistently
                let divisor = Self::nonzero_compute_divisor(elapsed_secs);

                // This argument impacts the curve so that it progresses slower the further in time we get
                // (The idea is: it's not already such a difference if it is weeks or months. Put differently, while
                // the age of the debt can overrule easily smaller balances, because it progresses more aggressively
                // than metrics for the debt size, in contrary, we don't want it to shade the large ones)
                let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);

                (elapsed_secs as u128)
                    .checked_pow(AGE_EXPONENT_FOR_BASE)
                    .expect("pow overflow")
                    .checked_div(divisor)
                    .expect("div overflow")
                    .checked_mul(log_multiplier)
                    .expect("mul overflow")
            },
        );
        Self { formula }
    }

    fn nonzero_elapsed(now: SystemTime, previous_timestamp: SystemTime) -> u64 {
        let elapsed = now
            .duration_since(previous_timestamp)
            .expect("time traveller")
            .as_secs();
        if elapsed > 0 {
            elapsed
        } else {
            1
        }
    }

    fn nonzero_compute_divisor(elapsed_sec: u64) -> u128 {
        (elapsed_sec as f64).sqrt().ceil() as u128
    }

    fn nonzero_log_value(num: f64) -> u128 {
        if num < 2.0 {
            1
        } else {
            num.log2() as u128
        }
    }

    // This multiplier is meant to push against the growth of the age criterion,
    // slowing it down more and more as the time parameter increases.
    // The reason is that balance numbers soon get huge but yet are not so unrealistic.
    // For a balanced solution, the age criterion formula is designed to progress
    // more steeply in the area of rather smaller amounts of seconds, while if
    // we move on towards a couple of days, weeks, months and so on, the impact of the parameter
    // diminishes
    fn compute_descending_multiplier(elapsed_secs: u64, divisor: u128) -> u128 {
        let fast_growing_argument = (elapsed_secs as u128)
            .checked_pow(AGE_DESC_MULTIPLIER_ARG_EXP)
            .expect("pow blew up") as f64;

        let log_value = Self::nonzero_log_value(fast_growing_argument);

        let log_stressed = log_value.pow(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP)
            * AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER;

        let divisor_stressed = divisor * AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER;

        let final_log_multiplier =
            (log_stressed / divisor_stressed).pow(AGE_DESC_MULTIPLIER_DIVISOR_EXP);

        x_or_1(final_log_multiplier)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::{
        AgeCriterionCalculator, AGE_DESC_MULTIPLIER_ARG_EXP, AGE_DESC_MULTIPLIER_DIVISOR_EXP,
        AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER, AGE_DESC_MULTIPLIER_LOG_STRESS_EXP,
        AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER, AGE_EXPONENT_FOR_BASE,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CalculatorInputHolder, CalculatorType, CriterionCalculator,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        assert_constants_and_remind_checking_sync_of_calculators_if_any_constant_changes,
        make_initialized_subject,
    };
    use std::time::{Duration, SystemTime};

    #[test]
    fn constants_are_correct() {
        let constants_and_their_expected_values: Vec<(i128, i128)> = vec![
            (AGE_EXPONENT_FOR_BASE.try_into().unwrap(), 3),
            (AGE_DESC_MULTIPLIER_ARG_EXP.try_into().unwrap(), 2),
            (AGE_DESC_MULTIPLIER_LOG_STRESS_EXP.try_into().unwrap(), 2),
            (
                AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER
                    .try_into()
                    .unwrap(),
                550,
            ),
            (
                AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER.try_into().unwrap(),
                13,
            ),
            (AGE_DESC_MULTIPLIER_DIVISOR_EXP.try_into().unwrap(), 4),
        ];

        assert_constants_and_remind_checking_sync_of_calculators_if_any_constant_changes(
            &constants_and_their_expected_values,
            574,
        )
    }

    #[test]
    fn nonzero_compute_divisor_works() {
        let result: Vec<_> = [1, 100, 81, 82, 80]
            .into_iter()
            .map(|secs| AgeCriterionCalculator::nonzero_compute_divisor(secs))
            .collect();

        assert_eq!(result, vec![1, 10, 9, 10, 9])
    }

    #[test]
    fn nonzero_elapsed_works() {
        let now = SystemTime::now();
        let result: Vec<_> = [
            // The first entry is normally considered 0 s
            now.checked_sub(Duration::from_nanos(55)).unwrap(),
            now.checked_sub(Duration::from_secs(1)).unwrap(),
            now.checked_sub(Duration::from_secs(2)).unwrap(),
        ]
        .into_iter()
        .map(|timestamp| AgeCriterionCalculator::nonzero_elapsed(now, timestamp))
        .collect();

        assert_eq!(result, vec![1, 1, 2])
    }

    #[test]
    fn compute_descending_multiplier_works() {
        let result: Vec<_> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18]
            .into_iter()
            .take(12)
            .map(|exp| 10_u64.pow(exp))
            .map(|seconds_elapsed| {
                let divisor = AgeCriterionCalculator::nonzero_compute_divisor(seconds_elapsed);
                AgeCriterionCalculator::compute_descending_multiplier(seconds_elapsed, divisor)
            })
            .collect();

        assert_eq!(
            result,
            vec![
                729000000, 4826809000, 1435249152, 308915776, 40353607, 3511808, 287496, 21952,
                1331, 1, 1, 1
            ]
        )
    }

    #[test]
    fn nonzero_log_works() {
        let result = vec![0.0, 0.6, 1.3, 1.99999, 2.0, 2.1, 5.0, 9.0]
            .into_iter()
            .map(|num| AgeCriterionCalculator::nonzero_log_value(num))
            .collect::<Vec<u128>>();

        assert_eq!(result, vec![1, 1, 1, 1, 1, 1, 2, 3])
    }

    #[test]
    fn calculator_knows_its_type() {
        let payment_adjuster = make_initialized_subject(SystemTime::now(), None, None);
        let subject = AgeCriterionCalculator::new(&payment_adjuster);

        let result = subject.calculator_type();

        assert_eq!(result, CalculatorType::DebtAge)
    }

    #[test]
    fn age_criteria_calculation_works() {
        let now = SystemTime::now();
        let payment_adjuster = make_initialized_subject(now, None, None);
        let subject = AgeCriterionCalculator::new(&payment_adjuster);
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(1500))
            .unwrap();
        let last_paid_timestamp_holder = CalculatorInputHolder::DebtAge {
            last_paid_timestamp,
        };

        let result = subject.formula()(last_paid_timestamp_holder);

        let expected_criterion = {
            let elapsed_secs: u64 = now.duration_since(last_paid_timestamp).unwrap().as_secs();
            let divisor = AgeCriterionCalculator::nonzero_compute_divisor(elapsed_secs);
            let log_multiplier =
                AgeCriterionCalculator::compute_descending_multiplier(elapsed_secs, divisor);
            (elapsed_secs as u128)
                .checked_pow(AGE_EXPONENT_FOR_BASE)
                .unwrap()
                .checked_div(divisor)
                .unwrap()
                .checked_mul(log_multiplier)
                .unwrap()
        };
        assert_eq!(result, expected_criterion)
    }
}
