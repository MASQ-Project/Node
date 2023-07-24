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
const EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS: [u32; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18];

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

pub struct FinalizationAndDiagnostics<'a, F>
where
    F: Fn(u128) -> u128,
{
    pub account: PayableAccount,
    pub criterion: u128,
    pub criteria_sum_so_far: u128,
    pub diagnostics: DiagnosticsSetting<'a, F>,
}

pub struct DiagnosticsSetting<'a, F>
where
    F: Fn(u128) -> u128,
{
    pub label: &'static str,
    pub diagnostics_adaptive_formula: F,
    pub singleton_ref: &'a Once,
    pub bonds_safe_count_to_print: usize,
}

impl<'a, F> DiagnosticsSetting<'a, F>
where
    F: Fn(u128) -> u128,
{
    pub fn compute_progressive_characteristics(&self) {
        if COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS {
            self.singleton_ref.call_once(|| {
                eprintln!("CHARACTERISTICS FOR {} FORMULA", self.label);
                EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS
                    .into_iter()
                    .take(self.bonds_safe_count_to_print)
                    .map(|exponent| 10_u128.pow(exponent))
                    .for_each(|num| {
                        let value = (self.diagnostics_adaptive_formula)(num);
                        eprintln!("x: {:<length$} y: {}", num, value, length = 40)
                    });
                eprintln!()
            })
        }
    }
}

impl<F> FinalizationAndDiagnostics<'_, F>
where
    F: Fn(u128) -> u128,
{
    pub fn perform(self) -> (u128, PayableAccount) {
        diagnostics(
            &self.account.wallet,
            &format!("COMPUTED {} CRITERIA", self.diagnostics.label),
            || self.criterion.separate_with_commas(),
        );
        self.diagnostics.compute_progressive_characteristics();

        (
            self.criteria_sum_so_far
                .checked_add(self.criterion)
                .expect("add overflow"),
            self.account,
        )
    }
}
