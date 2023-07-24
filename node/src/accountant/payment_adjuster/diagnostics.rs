// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::{
    COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS, PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS,
};
use crate::sub_lib::wallet::Wallet;
use std::sync::Once;
use thousands::Separable;

pub static AGE_SINGLETON: Once = Once::new();
pub static BALANCE_SINGLETON: Once = Once::new();

pub fn diagnostics<F>(account: &Wallet, description: &str, value_renderer: F)
where
    F: Fn() -> String,
{
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        eprintln!(
            "{} {:<length$} {}",
            account,
            value_renderer(),
            description,
            length = 40
        )
    }
}

pub fn diagnostics_collective(label: &str, accounts: &[PayableAccount]) {
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub fn compute_progressive_characteristics<F>(
    label: &str,
    formula: F,
    singleton: &Once,
    examples_count: usize,
) where
    F: Fn(u128) -> u128,
{
    if COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS {
        singleton.call_once(|| {
            let different_values_for_chief_parameter: Vec<(u128, u32)> = vec![
                (10, 1),
                (10, 3),
                (10, 4),
                (10, 5),
                (10, 6),
                (10, 7),
                (10, 8),
                (10, 9),
                (10, 12),
                (10, 15),
                (10, 18),
            ];

            eprintln!("{}", label);
            different_values_for_chief_parameter
                .into_iter()
                .take(examples_count)
                .map(|(base, factor)| base.pow(factor))
                .for_each(|num| {
                    let value = formula(num);
                    eprintln!("x: {:<length$} y: {}", num, value, length = 40)
                });
            eprintln!()
        })
    }
}

pub struct FinalizationAndDiagnostics<'a, F>
where
    F: Fn(u128) -> u128,
{
    pub account: PayableAccount,
    pub criterion: u128,
    pub criteria_sum_so_far: u128,
    // below only diagnostics purposes
    pub label: &'static str,
    pub diagnostics_adapted_formula: F,
    pub singleton_ref: &'a Once,
    // max 9
    pub safe_count_of_examples_to_print: usize,
}

impl<F> FinalizationAndDiagnostics<'_, F>
where
    F: Fn(u128) -> u128,
{
    pub fn perform(self) -> (u128, PayableAccount) {
        diagnostics(
            &self.account.wallet,
            &format!("COMPUTED {} CRITERIA", self.label),
            || self.criterion.separate_with_commas(),
        );
        compute_progressive_characteristics(
            &format!("CHARACTERISTICS FOR {} FORMULA", self.label),
            self.diagnostics_adapted_formula,
            self.singleton_ref,
            self.safe_count_of_examples_to_print,
        );

        (
            self.criteria_sum_so_far
                .checked_add(self.criterion)
                .expect("add overflow"),
            self.account,
        )
    }
}
