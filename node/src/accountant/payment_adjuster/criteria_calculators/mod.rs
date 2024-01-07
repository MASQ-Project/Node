// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod age_criterion_calculator;
pub mod balance_criterion_calculator;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceCriterionCalculator;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::inside_calculator_local_diagnostics;
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
    Iterator<Item = (u128, PayableAccount)> + CriterionCalculatorDiagnostics
{
    // The additional trait constrain comes from efforts to write the API more Rust-like.
    // This implementation has its own pros and cons; the little cons are we have to learn to
    // understand the need for a special wrapper of the input parameter.
    // Don't be fooled trying writing a From implementation for third-party data types, hoping to
    // satisfy the requirements. Because Rust disallow such things, this design has arisen.
    type Input: for<'a> From<&'a PayableAccount>;

    // Good news, this is the only function you are supposed to implement for your calculator!
    // All it does is to refer to the formula from inside of your calculator (see the existing
    // implementations) and provide it for the outside
    fn formula(&self) -> &dyn Fn(Self::Input) -> u128;

    fn calculate_criterion_and_add_in_total_weight(
        &self,
        (weight, account): (u128, PayableAccount),
    ) -> (u128, PayableAccount)
    where
        <Self as CriterionCalculator>::Input: Debug,
    {
        #[cfg(test)]
        self.compute_formula_characteristics_for_diagnostics();

        let input_wrapper = Self::Input::from(&account);
        let criterion: u128 = self.formula()(input_wrapper);
        let updated_weight = weight + criterion;

        inside_calculator_local_diagnostics(&account.wallet, self, criterion, updated_weight);

        (updated_weight, account)
    }
}

pub trait CriterionCalculatorDiagnostics {
    fn input_parameter_name(&self) -> &'static str;
    #[cfg(test)]
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsAxisX<Self::Input>>>
    where
        Self: CriterionCalculator;
    #[cfg(test)]
    fn diagnostics_config_opt(&self) -> Option<DiagnosticsAxisX<Self::Input>>
    where
        Self: CriterionCalculator,
    {
        self.diagnostics_config_location()
            .lock()
            .expect("diagnostics poisoned")
            .take()
    }
    #[cfg(test)]
    fn compute_formula_characteristics_for_diagnostics(&self)
    where
        Self::Input: Debug,
        Self: CriterionCalculator,
    {
        if COMPUTE_FORMULAS_CHARACTERISTICS {
            compute_progressive_characteristics(
                self.input_parameter_name(),
                self.diagnostics_config_opt(),
                self.formula(),
            )
        }
    }
}

pub trait CriteriaCalculatorIterators {
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

impl<I> CriteriaCalculatorIterators for I
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

#[macro_export]
macro_rules! all_standard_impls_for_criterion_calculator {
    ($calculator: tt, $input_type: tt, $param_name: literal, $diagnostics_config_opt: expr) => {
        impl<I> Iterator for $calculator<I>
        where
            I: Iterator<Item = (u128, PayableAccount)>,
        {
            type Item = (u128, PayableAccount);

            fn next(&mut self) -> Option<Self::Item> {
                self.iter.next().map(|weight_and_account| {
                    self.calculate_criterion_and_add_in_total_weight(weight_and_account.into())
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
        }

        impl<I> CriterionCalculatorDiagnostics for $calculator<I>
        where
            I: Iterator<Item = (u128, PayableAccount)>,
        {
            fn input_parameter_name(&self) -> &'static str {
                $param_name
            }

            #[cfg(test)]
            fn diagnostics_config_location(
                &self,
            ) -> &Mutex<Option<DiagnosticsAxisX<<Self as CriterionCalculator>::Input>>> {
                &$diagnostics_config_opt
            }
        }
    };
}
