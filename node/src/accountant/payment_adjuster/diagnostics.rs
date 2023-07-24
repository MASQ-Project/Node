// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::{
    COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS, PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS,
};
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use std::sync::Once;
use thousands::Separable;

pub static AGE_SINGLETON: Once = Once::new();
pub static BALANCE_SINGLETON: Once = Once::new();
pub const EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS: [u32; 13] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18, 21];

pub const fn diagnostics_x_axis_exponents_len() -> usize {
    EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS.len()
}
pub const DIAGNOSTICS_MIDDLE_COLUMN_WIDTH: usize = 40;

#[macro_export]
macro_rules! diagnostics {
    ($description: literal, $value_renderer: expr) => {
        diagnostics(|| Either::Left(""), $description, $value_renderer)
    };
    ($wallet_ref: expr, $description: expr, $value_renderer: expr) => {
        diagnostics(
            || Either::Right($wallet_ref.to_string()),
            $description,
            $value_renderer,
        )
    };
}

pub fn diagnostics<F1, F2>(subject_renderer: F1, description: &str, value_renderer: F2)
where
    F1: Fn() -> Either<&'static str, String>,
    F2: Fn() -> String,
{
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        eprintln!(
            "{:<subject_column_length$} {:<length$} {}",
            subject_renderer(),
            value_renderer(),
            description,
            subject_column_length = 42,
            length = DIAGNOSTICS_MIDDLE_COLUMN_WIDTH
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

//TODO kill this when you have CriteriaCumputers that can take characteristics tests on them
pub struct CriteriaWithDiagnostics<'a, F>
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
                    .for_each(|input_num| {
                        let value = (self.diagnostics_adaptive_formula)(input_num);
                        eprintln!(
                            "x: {:<length$} y: {}",
                            input_num.separate_with_commas(),
                            value.separate_with_commas(),
                            length = 40
                        )
                    });
                eprintln!()
            })
        }
    }
}

impl<F> CriteriaWithDiagnostics<'_, F>
where
    F: Fn(u128) -> u128,
{
    pub fn diagnose_and_sum(self) -> (u128, PayableAccount) {
        let account = &self.account.wallet;
        let description = format!("COMPUTED {} CRITERIA", self.diagnostics.label);
        let value_renderer = || self.criterion.separate_with_commas();
        diagnostics!(account, &description, value_renderer);
        self.diagnostics.compute_progressive_characteristics();

        (
            self.criteria_sum_so_far
                .checked_add(self.criterion)
                .expect("add overflow"),
            self.account,
        )
    }
}
