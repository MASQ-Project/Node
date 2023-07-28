// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criteria_calculators::DiagnosticsConfig;
use crate::accountant::payment_adjuster::PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS;
use itertools::Itertools;
use std::fmt::Debug;
use std::sync::{Mutex, Once};
use thousands::Separable;

pub static AGE_SINGLETON: Once = Once::new();
pub static BALANCE_SINGLETON: Once = Once::new();

pub const COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS: bool = true;
pub const FORMULAS_DIAGNOSTICS_SINGLETON: Once = Once::new();

pub const EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS: [u32; 14] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18, 21, 25];

pub const DIAGNOSTICS_MIDDLE_COLUMN_WIDTH: usize = 60;

#[macro_export]
macro_rules! diagnostics {
    ($description: literal, $($arg: tt)*) => {
        diagnostics(None::<fn()->String>, $description, || format!($($arg)*))
    };
    ($wallet_ref: expr, $description: expr,  $($arg: tt)*) => {
        diagnostics(
            Some(||$wallet_ref.to_string()),
            $description,
            || format!($($arg)*)
        )
    };
}

pub fn diagnostics<F1, F2>(subject_renderer_opt: Option<F1>, description: &str, value_renderer: F2)
where
    F1: Fn() -> String,
    F2: Fn() -> String,
{
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        let subject = if let Some(subject_renderer) = subject_renderer_opt {
            subject_renderer()
        } else {
            "".to_string()
        };
        eprintln!(
            "{:<subject_column_length$} {:<length$} {}",
            subject,
            description,
            value_renderer(),
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

// impl<F> CriteriaWithDiagnostics<'_, F>
// where
//     F: Fn(u128) -> u128,
// {
//     pub fn diagnose_and_sum(self) -> (u128, PayableAccount) {
//         let account = &self.account.wallet;
//         let description = format!("COMPUTED {} CRITERIA", self.diagnostics.label);
//         diagnostics!(
//             account,
//             &description,
//             "{}",
//             self.criterion.separate_with_commas()
//         );
//         self.diagnostics.compute_progressive_characteristics();
//
//         (
//             self.criteria_sum_so_far
//                 .checked_add(self.criterion)
//                 .expect("add overflow"),
//             self.account,
//         )
//     }
// }

pub const STRINGS_WITH_FORMULAS_CHARACTERISTICS: Mutex<Vec<String>> = Mutex::new(vec![]);

fn print_formulas_diagnostics() {
    FORMULAS_DIAGNOSTICS_SINGLETON.call_once(|| {
        let report = STRINGS_WITH_FORMULAS_CHARACTERISTICS
            .lock()
            .expect("diagnostics poisoned")
            .join("\n\n");
        eprintln!("{}", report)
    })
}

pub fn compute_progressive_characteristics<A>(
    config_opt: Option<DiagnosticsConfig<A>>,
    formula: fn(A) -> u128,
) where
    A: Debug,
{
    config_opt.map(|config| {
        let characteristics = config
            .progressive_set_of_args
            .into_iter()
            .map(|input| {
                let input_print = format!("{:?}", input);
                format!(
                    "x: {:<length$} y: {}",
                    input_print,
                    formula(input).separate_with_commas(),
                    length = 40
                )
            })
            .join("\n");
        STRINGS_WITH_FORMULAS_CHARACTERISTICS
            .lock()
            .expect("diagnostics poisoned")
            .push(characteristics);
    });
}
