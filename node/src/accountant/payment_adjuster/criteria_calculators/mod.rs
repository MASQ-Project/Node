// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod age_criterion_calculator;
pub mod balance_criterion_calculator;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::inside_calculator_local_diagnostics;
use std::fmt::{Debug, Display, Formatter};
use std::time::SystemTime;
use variant_count::VariantCount;
test_only_use!(
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::{
        compute_progressive_characteristics, DiagnosticsAxisX, COMPUTE_FORMULAS_CHARACTERISTICS,
    };
    use std::sync::Mutex;
);

// Caution: always remember to use checked math operations in the criteria formulas!
pub trait CriterionCalculator {
    // Reference to the formula that is meant by design to be stored inside the calculator.
    // The formula can keep its own context if required
    fn formula(&self) -> &dyn Fn(CalculatorInputHolder) -> u128;

    fn calculator_type(&self) -> CalculatorType;
}

#[derive(PartialEq, Debug, VariantCount, Clone, Copy)]
pub enum CalculatorType {
    DebtBalance,
    DebtAge,
}

#[derive(PartialEq, Debug, VariantCount)]
pub enum CalculatorInputHolder {
    DebtBalance(u128),
    DebtAge { last_paid_timestamp: SystemTime },
}

impl CalculatorInputHolder {
    fn age_input(self) -> SystemTime {
        if let CalculatorInputHolder::DebtAge {
            last_paid_timestamp,
        } = self
        {
            last_paid_timestamp
        } else {
            todo!()
        }
    }

    fn balance_input(self) -> u128 {
        if let CalculatorInputHolder::DebtBalance(balance_wei) = self {
            balance_wei
        } else {
            todo!()
        }
    }
}

impl<'a> From<((CalculatorType, &'a PayableAccount))> for CalculatorInputHolder {
    fn from((calculator_type, account): (CalculatorType, &'a PayableAccount)) -> Self {
        match calculator_type {
            CalculatorType::DebtBalance => CalculatorInputHolder::DebtBalance(account.balance_wei),
            CalculatorType::DebtAge => CalculatorInputHolder::DebtAge {
                last_paid_timestamp: account.last_paid_timestamp,
            },
        }
    }
}

impl Display for CalculatorType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CalculatorType::DebtBalance => write!(f, "BALANCE"),
            CalculatorType::DebtAge => write!(f, "AGE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::criteria_calculators::{
        CalculatorInputHolder, CalculatorType,
    };
    use crate::accountant::payment_adjuster::PaymentAdjusterReal;
    use crate::accountant::test_utils::make_payable_account;
    use crate::test_utils::make_wallet;
    use std::panic::{catch_unwind, RefUnwindSafe};
    use std::time::{Duration, SystemTime};

    #[test]
    fn input_holders_can_be_derived_from_calculator_type_and_payable_account() {
        let payment_adjuster = PaymentAdjusterReal::new();
        let balance_wei = 135_792_468;
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap();
        let account = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei,
            last_paid_timestamp,
            pending_payable_opt: None,
        };

        let result = [CalculatorType::DebtAge, CalculatorType::DebtBalance]
            .into_iter()
            .map(|calculator_type| CalculatorInputHolder::from((calculator_type, &account)))
            .collect::<Vec<_>>();

        let expected = vec![
            CalculatorInputHolder::DebtAge {
                last_paid_timestamp,
            },
            CalculatorInputHolder::DebtBalance(balance_wei),
        ];
        assert_eq!(result.len(), CalculatorInputHolder::VARIANT_COUNT);
        assert_eq!(result, expected);
    }

    #[test]
    fn calculator_type_implements_display() {
        assert_eq!(CalculatorType::DebtBalance.to_string(), "BALANCE");
        assert_eq!(CalculatorType::DebtAge.to_string(), "AGE")
    }

    #[test]
    fn input_values_can_be_fetched_from_input_holder() {
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_millis(1234))
            .unwrap();
        let age_input_holder = CalculatorInputHolder::DebtAge {
            last_paid_timestamp,
        };
        let balance = 333_444_555_666;
        let balance_input_holder = CalculatorInputHolder::DebtBalance(balance);

        let result = vec![age_input_holder, balance_input_holder];

        assert_eq!(result.len(), CalculatorInputHolder::VARIANT_COUNT);
        let mut result = result.into_iter();
        assert_eq!(result.next().unwrap().age_input(), last_paid_timestamp);
        assert_eq!(result.next().unwrap().balance_input(), balance);
        assert_eq!(result.next(), None)
    }

    #[test]
    fn there_is_same_amount_of_calculator_types_as_calculator_input_holders() {
        assert_eq!(
            CalculatorType::VARIANT_COUNT,
            CalculatorInputHolder::VARIANT_COUNT
        )
    }

    #[test]
    fn panics_for_age_input_when_the_enum_is_not_age_input_holder() {
        test_panics_for_mismatched_input_holder(
            CalculatorType::DebtAge,
            |calculator_type, account| {
                CalculatorInputHolder::from((calculator_type, account)).age_input();
                // should cause panic
            },
        )
    }

    #[test]
    fn panics_for_balance_input_when_the_enum_is_not_balance_input_holder() {
        test_panics_for_mismatched_input_holder(
            CalculatorType::DebtBalance,
            |calculator_type, account| {
                CalculatorInputHolder::from((calculator_type, account)).balance_input();
                // should cause panic
            },
        )
    }

    fn test_panics_for_mismatched_input_holder<F>(
        the_only_correct_type: CalculatorType,
        tested_function_call_for_panics: F,
    ) where
        F: Fn(CalculatorType, &PayableAccount) + RefUnwindSafe,
    {
        let account = make_payable_account(123);
        let all_types = vec![CalculatorType::DebtBalance, CalculatorType::DebtAge];

        assert_eq!(all_types.len(), CalculatorType::VARIANT_COUNT);
        all_types
            .into_iter()
            .filter(|calculator_type| calculator_type != &the_only_correct_type)
            .for_each(|calculator_type| {
                let result =
                    catch_unwind(|| tested_function_call_for_panics(calculator_type, &account))
                        .unwrap_err();
                let panic_msg = result.downcast_ref::<&str>().unwrap();
                assert_eq!(panic_msg, &"blaaaaaaaaaaaah");
            })
    }
}

//
// pub trait CriterionCalculatorDiagnostics {
//     fn input_parameter_name(&self) -> &'static str;
//     #[cfg(test)]
//     fn diagnostics_config_location(&self) -> &Mutex<Option<DiagnosticsAxisX<Self::Input>>>
//     where
//         Self: CriterionCalculator;
//     #[cfg(test)]
//     fn diagnostics_config_opt(&self) -> Option<DiagnosticsAxisX<Self::Input>>
//     where
//         Self: CriterionCalculator,
//     {
//         self.diagnostics_config_location()
//             .lock()
//             .expect("diagnostics poisoned")
//             .take()
//     }
//     #[cfg(test)]
//     fn compute_formula_characteristics_for_diagnostics(&self)
//     where
//         Self::Input: Debug,
//         Self: CriterionCalculator,
//     {
//         if COMPUTE_FORMULAS_CHARACTERISTICS {
//             compute_progressive_characteristics(
//                 self.input_parameter_name(),
//                 self.diagnostics_config_opt(),
//                 self.formula(),
//             )
//         }
//     }
// }

// pub trait CriteriaCalculatorIterators {
//     fn calculate_age_criteria(
//         self,
//         payment_adjuster: &PaymentAdjusterReal,
//     ) -> AgeCriterionCalculator<Self>
//     where
//         Self: Iterator<Item = (u128, PayableAccount)> + Sized;
//
//     fn calculate_balance_criteria(self) -> BalanceCriterionCalculator<Self>
//     where
//         Self: Iterator<Item = (u128, PayableAccount)> + Sized;
// }

// impl<I> CriteriaCalculatorIterators for I
// where
//     I: Iterator<Item = (u128, PayableAccount)>,
// {
//     fn calculate_age_criteria(
//         self,
//         payment_adjuster: &PaymentAdjusterReal,
//     ) -> AgeCriterionCalculator<Self> {
//         AgeCriterionCalculator::new(self, payment_adjuster)
//     }
//
//     fn calculate_balance_criteria(self) -> BalanceCriterionCalculator<Self> {
//         BalanceCriterionCalculator::new(self)
//     }
// }
//
// #[macro_export]
// macro_rules! all_standard_impls_for_criterion_calculator {
//     ($calculator: tt, $input_type: tt, $param_name: literal, $diagnostics_config_opt: expr) => {
//         impl<I> Iterator for $calculator<I>
//         where
//             I: Iterator<Item = (u128, PayableAccount)>,
//         {
//             type Item = (u128, PayableAccount);
//
//             fn next(&mut self) -> Option<Self::Item> {
//                 self.iter.next().map(|weight_and_account| {
//                     let wrapped_input = Self::Item::from(weight_and_account);
//                     self.calculate_criterion_and_add_in_total_weight(wrapped_input)
//                 })
//             }
//         }
//
//         impl<I> CriterionCalculator for $calculator<I>
//         where
//             I: Iterator<Item = (u128, PayableAccount)>,
//         {
//             type Input = $input_type;
//
//             fn formula(&self) -> &dyn Fn(Self::Input) -> u128 {
//                 self.formula.as_ref()
//             }
//         }
//
//         impl<I> CriterionCalculatorDiagnostics for $calculator<I>
//         where
//             I: Iterator<Item = (u128, PayableAccount)>,
//         {
//             fn input_parameter_name(&self) -> &'static str {
//                 $param_name
//             }
//
//             #[cfg(test)]
//             fn diagnostics_config_location(
//                 &self,
//             ) -> &Mutex<Option<DiagnosticsAxisX<<Self as CriterionCalculator>::Input>>> {
//                 &$diagnostics_config_opt
//             }
//         }
//     };
// }
