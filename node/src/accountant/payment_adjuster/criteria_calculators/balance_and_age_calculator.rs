// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculator;
use crate::accountant::QualifiedPayableAccount;

// This parameter affects the steepness inversely, but just slowly.
//
// Don't worry to joggle with this number; it's not as scientific as it looks like. True, I arrived at it after many
// attempts when I finally aligned myself with the tuning. The issue is it needs to be carefully compared to the values
// the Age criterion calculator yields.
// (If you are preparing to follow my steps you'll need to enable the rendering from the 'diagnostics' module, getting
// back a chance for a close look into each characteristic of the calculators formulas and therefore also how sync
// they are. See and think about the effects of your new settings)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 18_490_000;
// This parameter affects the steepness analogously, but energetically
const BALANCE_FINAL_MULTIPLIER: u128 = 2;

pub struct BalanceAndAgeCriterionCalculator {}

impl CriterionCalculator for BalanceAndAgeCriterionCalculator {
    fn calculate(&self, account: &QualifiedPayableAccount) -> u128 {
        todo!()
    }

    fn parameter_name(&self) -> &'static str {
        todo!()
    }
}

impl BalanceAndAgeCriterionCalculator {
    pub fn new() -> Self {
        todo!()
        // let formula = Box::new(|balance_minor_holder: CalculatorInputHolder| {
        //     let balance_minor = balance_minor_holder.balance_input();
        //     let argument_for_log = Self::calculate_binary_argument(balance_minor);
        //     let binary_weight = Self::nonzero_log2(argument_for_log);
        //     balance_minor
        //         .checked_mul(binary_weight as u128)
        //         .expect("mul overflow")
        //         * BALANCE_FINAL_MULTIPLIER
        // });
        // Self { formula }
    }

    // fn nonzero_log2(input: u128) -> u32 {
    //     let log = log_2(input);
    //     if log > 0 {
    //         log
    //     } else {
    //         1
    //     }
    // }
    //
    // fn calculate_binary_argument(balance_minor: u128) -> u128 {
    //     balance_minor / BALANCE_LOG_2_ARG_DIVISOR
    // }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::criteria_calculators::balance_and_age_calculator::{
        BalanceAndAgeCriterionCalculator, BALANCE_FINAL_MULTIPLIER, BALANCE_LOG_2_ARG_DIVISOR,
    };
    use crate::accountant::payment_adjuster::criteria_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::test_utils::assert_constants_and_remind_checking_sync_of_calculators_if_any_constant_changes;

    #[test]
    fn constants_are_correct() {
        let constants_and_their_expected_values: Vec<(i128, i128)> = vec![
            (BALANCE_LOG_2_ARG_DIVISOR.try_into().unwrap(), 18_490_000),
            (BALANCE_FINAL_MULTIPLIER.try_into().unwrap(), 2),
        ];

        assert_constants_and_remind_checking_sync_of_calculators_if_any_constant_changes(
            &constants_and_their_expected_values,
            18490002,
        )
    }

    #[test]
    fn balance_criteria_calculation_works() {
        let subject = BalanceAndAgeCriterionCalculator::new();
        let balance_wei = 111_333_555_777_u128;
        let account = todo!();

        let result = subject.calculate(account);

        let expected_result = todo!();
        assert_eq!(result, expected_result)
    }
}
