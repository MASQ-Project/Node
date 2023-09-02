// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod age_criterion_calculator;
pub mod balance_criterion_calculator;

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
    compute_progressive_characteristics, DiagnosticsConfig,
    COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS,
};
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::calculator_local_diagnostics;
use std::fmt::Debug;
use std::sync::Mutex;

// Caution: always remember to use checked math operations in the formula!
pub trait CriterionCalculator: CalculatorWithNamedMainParameter {
    // The additional trait constrain comes from efforts convert write the API more Rust-like.
    // This implementation has its own pros and cons; the little cons for you are that whenever
    // you must see the pattern of defining a wrapper for the input of your calculator. Refrain
    // from writing a From implementation for third part types to satisfy the requirement.
    type Input: for<'a> From<&'a PayableAccount>;

    // This is the only function you are supposed to implement for your calculator.
    // All it does is linking the formula from inside of your calculator (see implementations),
    // and exposes it to outside
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
    fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsConfig<Self::Input>>>;
    #[cfg(test)]
    fn diagnostics_config_opt(&self) -> Option<DiagnosticsConfig<Self::Input>> {
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
        if COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS {
            compute_progressive_characteristics(
                self.main_parameter_name(),
                self.diagnostics_config_opt(),
                self.formula(),
            )
        }
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
            .map(|item| self.calculator.calculate_and_add_to_criteria_sum(item))
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

pub trait CalculatorWithNamedMainParameter {
    fn main_parameter_name(&self) -> &'static str;
}
