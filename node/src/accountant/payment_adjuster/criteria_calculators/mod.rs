// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod age_criterion_calculator;
pub mod balance_criterion_calculator;

use crate::accountant::QualifiedPayableAccount;
use std::fmt::{Debug, Display, Formatter};
use std::time::SystemTime;
use variant_count::VariantCount;

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
            self.mismatched_call_panic("age")
        }
    }

    fn balance_input(self) -> u128 {
        if let CalculatorInputHolder::DebtBalance(balance_wei) = self {
            balance_wei
        } else {
            self.mismatched_call_panic("balance")
        }
    }

    fn mismatched_call_panic(&self, param_name: &str) -> ! {
        panic!(
            "Call for {} while the underlying enum variant is {:?}",
            param_name, self
        )
    }
}

impl<'account> From<(CalculatorType, &'account QualifiedPayableAccount)> for CalculatorInputHolder {
    fn from(
        (calculator_type, qualified_payable): (CalculatorType, &'account QualifiedPayableAccount),
    ) -> Self {
        match calculator_type {
            CalculatorType::DebtBalance => {
                CalculatorInputHolder::DebtBalance(qualified_payable.payable.balance_wei)
            }
            CalculatorType::DebtAge => CalculatorInputHolder::DebtAge {
                last_paid_timestamp: qualified_payable.payable.last_paid_timestamp,
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
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use crate::accountant::QualifiedPayableAccount;
    use crate::test_utils::make_wallet;
    use std::panic::{catch_unwind, RefUnwindSafe};
    use std::time::{Duration, SystemTime};

    #[test]
    fn input_holders_can_be_derived_from_calculator_type_and_payable_account() {
        let balance_wei = 135_792_468;
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap();
        let payable = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei,
            last_paid_timestamp,
            pending_payable_opt: None,
        };
        let payment_threshold_intercept = 65432;
        let qualified_account = QualifiedPayableAccount {
            payable,
            payment_threshold_intercept,
        };
        let result = [CalculatorType::DebtAge, CalculatorType::DebtBalance]
            .into_iter()
            .map(|calculator_type| {
                CalculatorInputHolder::from((calculator_type, &qualified_account))
            })
            .collect::<Vec<_>>();

        let expected = vec![
            CalculatorInputHolder::DebtAge {
                last_paid_timestamp,
            },
            CalculatorInputHolder::DebtBalance(balance_wei - payment_threshold_intercept),
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
        F: Fn(CalculatorType, &QualifiedPayableAccount) + RefUnwindSafe,
    {
        let mut qualified_payable = make_non_guaranteed_qualified_payable(12345);
        qualified_payable.payable.balance_wei = 2_000_000;
        qualified_payable.payment_threshold_intercept = 778_899;
        let difference =
            qualified_payable.payable.balance_wei - qualified_payable.payment_threshold_intercept;
        let all_types = vec![
            (
                CalculatorType::DebtBalance,
                "balance",
                format!("DebtBalance({difference})"),
            ),
            (
                CalculatorType::DebtAge,
                "age",
                "DebtAge { last_paid_timestamp: SystemTime { tv_sec: 0, tv_nsec: 0 } }".to_string(),
            ),
        ];

        assert_eq!(all_types.len(), CalculatorType::VARIANT_COUNT);
        let (_, the_right_param_literal_name, _) = all_types
            .iter()
            .find(|(calculator_type, _, _)| calculator_type == &the_only_correct_type)
            .unwrap();
        // To be able to shut the reference before we consume the vec
        let the_right_param_literal_name = the_right_param_literal_name.to_string();
        all_types
            .into_iter()
            .filter(|(calculator_type, _, _)| calculator_type != &the_only_correct_type)
            .for_each(
                |(calculator_type, _, debug_rendering_of_the_corresponding_input_holder)| {
                    let result = catch_unwind(|| {
                        tested_function_call_for_panics(calculator_type, &qualified_payable)
                    })
                    .unwrap_err();
                    let panic_msg = result.downcast_ref::<String>().unwrap();
                    assert_eq!(
                        panic_msg,
                        &format!(
                            "Call for {} while the underlying enum variant is {}",
                            the_right_param_literal_name,
                            debug_rendering_of_the_corresponding_input_holder
                        )
                    );
                },
            )
    }
}
