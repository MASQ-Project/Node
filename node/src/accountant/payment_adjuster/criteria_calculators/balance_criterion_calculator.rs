// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::{
    CriterionCalculator, CalculatorWithNamedMainParameter,
};
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
    DiagnosticsConfig,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{log_2};
use std::sync::Mutex;
use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::characteristics_config::BALANCE_DIAGNOSTICS_CONFIG_OPT;

// This parameter affects the steepness (sensitivity to balance increase)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 33;

pub struct BalanceCriterionCalculator {
    formula: Box<dyn Fn(BalanceInput) -> u128>,
}

impl BalanceCriterionCalculator {
    pub fn new() -> Self {
        let formula = Box::new(|wrapped_balance_minor: BalanceInput| {
            let balance_minor = wrapped_balance_minor.0;
            let binary_weight = log_2(Self::calculate_binary_argument(balance_minor));
            balance_minor
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
        });
        Self { formula }
    }

    fn nonzero_log2(balance_minor: u128) -> u32 {
        let log = log_2(Self::calculate_binary_argument(balance_minor));
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

impl CriterionCalculator for BalanceCriterionCalculator {
    type Input = BalanceInput;

    fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
        self.formula.as_ref()
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>> {
        &BALANCE_DIAGNOSTICS_CONFIG_OPT
    }
}

impl CalculatorWithNamedMainParameter for BalanceCriterionCalculator {
    fn main_parameter_name(&self) -> &'static str {
        "BALANCE"
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BalanceInput(pub u128);

impl From<&PayableAccount> for BalanceInput {
    fn from(account: &PayableAccount) -> Self {
        BalanceInput(account.balance_wei)
    }
}

#[cfg(test)]
pub mod characteristics_config {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceInput;
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::DiagnosticsConfig;
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    lazy_static! {
        pub static ref BALANCE_DIAGNOSTICS_CONFIG_OPT: Mutex<Option<DiagnosticsConfig<BalanceInput>>> = {
            let horisontal_axis_decimal_exponents = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18, 21, 25]
                .into_iter()
                .map(|exp| 10_u128.pow(exp))
                .collect();
            Mutex::new(Some(DiagnosticsConfig {
                horizontal_axis_progressive_supply: horisontal_axis_decimal_exponents,
                horizontal_axis_native_type_formatter: Box::new(|balance_wei| {
                    BalanceInput(balance_wei)
                }),
            }))
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::{
        BalanceCriterionCalculator, BalanceInput, BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CalculatorWithNamedMainParameter, CriterionCalculator,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::log_2;

    #[test]
    fn constants_are_correct() {
        assert_eq!(BALANCE_LOG_2_ARG_DIVISOR, 33)
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
        let result: Vec<_> = [0, 5, 66, 100, 131, 132]
            .into_iter()
            .map(|balance| BalanceCriterionCalculator::nonzero_log2(balance))
            .collect();

        assert_eq!(result, vec![1, 1, 1, 1, 1, 2])
    }

    #[test]
    fn calculator_returns_the_right_main_param_name() {
        let subject = BalanceCriterionCalculator::new();

        let result = subject.main_parameter_name();

        assert_eq!(result, "BALANCE")
    }

    #[test]
    fn balance_criteria_calculation_works() {
        let subject = BalanceCriterionCalculator::new();
        let balance_wei_wrapped = BalanceInput(111_333_555_777);

        let result = subject.formula()(balance_wei_wrapped);

        let expected_result = {
            let binary_weight = log_2(BalanceCriterionCalculator::calculate_binary_argument(
                balance_wei_wrapped.0,
            ));
            balance_wei_wrapped
                .0
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
        };
        assert_eq!(result, expected_result)
    }
}
