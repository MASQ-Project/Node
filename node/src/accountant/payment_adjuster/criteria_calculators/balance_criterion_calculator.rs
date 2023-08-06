// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
    DiagnosticsConfig, BALANCE_DIAGNOSTICS_CONFIG_OPT,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{log_2, x_or_1};
use std::sync::Mutex;

// this parameter affects the steepness (sensitivity on balance increase)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 33;

pub struct BalanceCriterionCalculator {
    formula: Box<dyn Fn(BalanceInput) -> u128>,
}

impl BalanceCriterionCalculator {
    pub fn new() -> Self {
        let formula = Box::new(|wrapped_balance_wei: BalanceInput| {
            let balance_wei = wrapped_balance_wei.0;
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
    type Input = BalanceInput;

    fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
        self.formula.as_ref()
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>> {
        &BALANCE_DIAGNOSTICS_CONFIG_OPT
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
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::{
        BalanceCriterionCalculator, BalanceInput, BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::log_2;

    #[test]
    fn constants_are_correct() {
        assert_eq!(BALANCE_LOG_2_ARG_DIVISOR, 33)
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
        let balance_wei = BalanceInput(111_333_555_777);

        let result = subject.formula()(balance_wei);

        let expected_result = {
            let binary_weight = log_2(BalanceCriterionCalculator::compute_binary_argument(
                balance_wei.0,
            ));
            balance_wei
                .0
                .checked_mul(binary_weight as u128)
                .expect("mul overflow")
        };
        assert_eq!(result, expected_result)
    }
}
