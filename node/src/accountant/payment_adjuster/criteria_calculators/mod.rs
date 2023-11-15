// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod age_criterion_calculator;
pub mod balance_criterion_calculator;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceCriterionCalculator;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::calculator_local_diagnostics;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use std::fmt::Debug;
test_only_use!(
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
        compute_progressive_characteristics, DiagnosticsAxisX, COMPUTE_FORMULAS_CHARACTERISTICS,
    };
    use std::sync::Mutex;
);

// Caution: always remember to use checked math operations in the criteria formulas!
pub trait CriterionCalculator:
    ParameterCriterionCalculator + Iterator<Item = (u128, PayableAccount)>
{
    // The additional trait constrain comes from efforts to write the API more Rust-like.
    // This implementation has its own pros and cons; the little cons are we must learn to
    // understand the need to have a special wrapper, for the input of any additional calculator.
    // Don't be fooled to try writing a From implementation for third-part data types to satisfy
    // the requirements. Because it is disallowed, this specific design has arisen.
    type Input: for<'a> From<&'a PayableAccount>;

    // This is the only function you are supposed to implement for your calculator.
    // All it does is to link the formula from inside of your calculator (see the existing
    // implementations), and expose it to outside
    fn formula(&self) -> &dyn Fn(Self::Input) -> u128;

    fn calculate_and_add_to_criteria_sum(
        &self,
        (criteria_sum, account): (u128, PayableAccount),
    ) -> (u128, PayableAccount)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        #[cfg(test)]
        self.formula_characteristics_diagnostics();

        let criterion: u128 = self.formula()((&account).into());
        let new_sum = criteria_sum + criterion;

        calculator_local_diagnostics(&account.wallet, self, criterion, new_sum);

        (criteria_sum + criterion, account)
    }

    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsAxisX<Self::Input>>>;
    #[cfg(test)]
    fn diagnostics_config_opt(&self) -> Option<DiagnosticsAxisX<Self::Input>> {
        self.diagnostics_config_location()
            .lock()
            .expect("diagnostics poisoned")
            .take()
    }
    #[cfg(test)]
    fn formula_characteristics_diagnostics(&self)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        if COMPUTE_FORMULAS_CHARACTERISTICS {
            compute_progressive_characteristics(
                self.parameter_name(),
                self.diagnostics_config_opt(),
                self.formula(),
            )
        }
    }
}

pub trait CriteriaCalculators {
    fn calculate_age_criteria(
        self,
        payment_adjuster: &PaymentAdjusterReal,
    ) -> AgeCriterionCalculator<Self>
    where
        Self: Iterator<Item = (u128, PayableAccount)> + Sized;

    fn calculate_balance_criteria(self) -> BalanceCriterionCalculator<Self>
    where
        Self: Iterator<Item = (u128, PayableAccount)> + Sized;
}

impl<I> CriteriaCalculators for I
where
    I: Iterator<Item = (u128, PayableAccount)>,
{
    fn calculate_age_criteria(
        self,
        payment_adjuster: &PaymentAdjusterReal,
    ) -> AgeCriterionCalculator<Self> {
        AgeCriterionCalculator::new(self, payment_adjuster)
    }

    fn calculate_balance_criteria(self) -> BalanceCriterionCalculator<Self> {
        BalanceCriterionCalculator::new(self)
    }
}

pub trait ParameterCriterionCalculator {
    fn parameter_name(&self) -> &'static str;
}

#[macro_export]
macro_rules! standard_impls_for_calculator {
    ($calculator: tt, $input_type: tt, $param_name: literal, $diagnostics_config_opt: expr) => {
        impl<I> Iterator for $calculator<I>
        where
            I: Iterator<Item = (u128, PayableAccount)>,
        {
            type Item = (u128, PayableAccount);

            fn next(&mut self) -> Option<Self::Item> {
                self.iter.next().map(|criteria_sum_and_account| {
                    self.calculate_and_add_to_criteria_sum(criteria_sum_and_account.into())
                })
            }
        }

        impl<I> CriterionCalculator for $calculator<I>
        where
            I: Iterator<Item = (u128, PayableAccount)>,
        {
            type Input = $input_type;

            fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
                self.formula.as_ref()
            }

            #[cfg(test)]
            fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsAxisX<Self::Input>>> {
                &$diagnostics_config_opt
            }
        }

        impl<I> ParameterCriterionCalculator for $calculator<I>
        where
            I: Iterator<Item = (u128, PayableAccount)>,
        {
            fn parameter_name(&self) -> &'static str {
                $param_name
            }
        }
    };
}
