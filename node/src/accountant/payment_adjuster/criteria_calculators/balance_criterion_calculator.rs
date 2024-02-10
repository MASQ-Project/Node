// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::criteria_calculators::{
    CalculatorInputHolder, CalculatorType, CriterionCalculator,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::log_2;

// This parameter affects the steepness inversely, but just slowly.
//
// Don't worry to joggle with this number; it's not as scientific as it looks like.
// True, I arrived at it after many attempts when I finally became aligned with
// the tuning, compared to the values the Age criterion calculator get
// (in order to follow my steps you'll need to enable the rendering tools from
// the 'diagnostics' module giving you a close look into the characteristics of
// the formulas and therefore also the effects of your new settings)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 18_490_000;
// This parameter affects the steepness analogously, but energetically
const BALANCE_FINAL_MULTIPLIER: u128 = 2;

pub struct BalanceCriterionCalculator {
    formula: Box<dyn Fn(CalculatorInputHolder) -> u128>,
}

impl CriterionCalculator for BalanceCriterionCalculator {
    fn formula(&self) -> &dyn Fn(CalculatorInputHolder) -> u128 {
        &self.formula
    }

    fn calculator_type(&self) -> CalculatorType {
        CalculatorType::DebtBalance
    }
}

impl BalanceCriterionCalculator {
    pub fn new() -> Self {
        let formula = Box::new(|balance_minor_holder: CalculatorInputHolder| {
            let balance_minor = balance_minor_holder.balance_input();
            let argument_for_log = Self::calculate_binary_argument(balance_minor);
            let binary_weight = Self::nonzero_log2(argument_for_log);
            balance_minor
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
                * BALANCE_FINAL_MULTIPLIER
        });
        Self { formula }
    }

    fn nonzero_log2(input: u128) -> u32 {
        let log = log_2(input);
        if log > 0 {
            log
        } else {
            1
        }
    }

    fn calculate_binary_argument(balance_minor: u128) -> u128 {
        balance_minor / BALANCE_LOG_2_ARG_DIVISOR
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::{
        BalanceCriterionCalculator, BALANCE_FINAL_MULTIPLIER, BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CalculatorInputHolder, CalculatorType, CriterionCalculator,
    };

    #[test]
    fn constants_are_correct() {
        assert_eq!(BALANCE_LOG_2_ARG_DIVISOR, 18_490_000);
        assert_eq!(BALANCE_FINAL_MULTIPLIER, 2)
    }

    #[test]
    fn compute_binary_argument_works() {
        let arg_values = [
            1,
            BALANCE_LOG_2_ARG_DIVISOR - 1,
            BALANCE_LOG_2_ARG_DIVISOR,
            BALANCE_LOG_2_ARG_DIVISOR + 1,
            BALANCE_LOG_2_ARG_DIVISOR + 1000,
        ];

        let result: Vec<_> = arg_values
            .into_iter()
            .map(|arg| BalanceCriterionCalculator::calculate_binary_argument(arg))
            .collect();

        assert_eq!(
            result,
            vec![
                0,
                0,
                1,
                1,
                (BALANCE_LOG_2_ARG_DIVISOR + 1000) / BALANCE_LOG_2_ARG_DIVISOR
            ]
        )
    }

    #[test]
    fn nonzero_log2_works() {
        let result: Vec<_> = [0, 1, 2, 5, 66, 100, 131, 132, u64::MAX as u128 + 1]
            .into_iter()
            .map(|balance| BalanceCriterionCalculator::nonzero_log2(balance))
            .collect();

        assert_eq!(result, vec![1, 1, 1, 2, 6, 6, 7, 7, 64])
    }

    #[test]
    fn balance_criterion_calculator_knows_its_type() {
        let subject = BalanceCriterionCalculator::new();

        let result = subject.calculator_type();

        assert_eq!(result, CalculatorType::DebtBalance)
    }

    #[test]
    fn balance_criteria_calculation_works() {
        let subject = BalanceCriterionCalculator::new();
        let balance_wei = 111_333_555_777;
        let balance_wei_inside_input_holder = CalculatorInputHolder::DebtBalance(balance_wei);

        let result = subject.formula()(balance_wei_inside_input_holder);

        let expected_result = {
            let binary_weight = BalanceCriterionCalculator::nonzero_log2(
                BalanceCriterionCalculator::calculate_binary_argument(balance_wei),
            );
            balance_wei
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
                * BALANCE_FINAL_MULTIPLIER
        };
        assert_eq!(result, expected_result)
    }
}
