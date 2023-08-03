// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;

const PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS: bool = true;

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

pub fn diagnostics_for_collections<D: Debug>(label: &str, accounts: &[D]) {
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

#[cfg(test)]
pub mod formulas_progressive_characteristics {
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use std::fmt::Debug;
    use std::iter::once;
    use std::sync::{Mutex, Once};
    use std::time::Duration;
    use std::time::SystemTime;
    use thousands::Separable;
    pub const COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS: bool = false;
    //mutex should be fine for debugging, no need for mut static
    static STRINGS_WITH_FORMULAS_CHARACTERISTICS: Mutex<Vec<String>> = Mutex::new(vec![]);
    static FORMULAS_CHARACTERISTICS_SINGLETON: Once = Once::new();

    pub struct DiagnosticsConfig<A> {
        label: &'static str,
        progressive_x_axis_supply_non_native: Vec<u128>,
        x_axis_native_type_formatter: Box<dyn Fn(u128) -> A + Send>,
    }

    lazy_static! {
        pub static ref AGE_DIAGNOSTICS_CONFIG_OPT: Mutex<Option<DiagnosticsConfig<SystemTime>>> = {
            let now = SystemTime::now();
            let x_axis_supply = {
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 12]
                    .into_iter()
                    .map(|exp| 10_u128.pow(exp))
                    .collect()
            };
            Mutex::new(Some(DiagnosticsConfig {
                label: "AGE",
                progressive_x_axis_supply_non_native: x_axis_supply,
                x_axis_native_type_formatter: Box::new(move |secs_since_last_paid_payable| {
                    now.checked_sub(Duration::from_secs(secs_since_last_paid_payable as u64))
                        .expect("time travelling")
                }),
            }))
        };
        pub static ref BALANCE_DIAGNOSTICS_CONFIG_OPT: Mutex<Option<DiagnosticsConfig<u128>>> = {
            let x_axis_supply = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 15, 18, 21, 25]
                .into_iter()
                .map(|exp| 10_u128.pow(exp))
                .collect();
            Mutex::new(Some(DiagnosticsConfig {
                label: "BALANCE",
                progressive_x_axis_supply_non_native: x_axis_supply,
                x_axis_native_type_formatter: Box::new(|balance_wei| balance_wei),
            }))
        };
    }

    pub fn print_formulas_characteristics_for_diagnostics() {
        if COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS {
            FORMULAS_CHARACTERISTICS_SINGLETON.call_once(|| {
                let report = STRINGS_WITH_FORMULAS_CHARACTERISTICS
                    .lock()
                    .expect("diagnostics poisoned")
                    .join("\n\n");
                eprintln!("{}", report)
            })
        }
    }

    pub fn compute_progressive_characteristics<A>(
        config_opt: Option<DiagnosticsConfig<A>>,
        formula: &dyn Fn(A) -> u128,
    ) where
        A: Debug,
    {
        config_opt.map(|config| {
            let config_x_axis_type_formatter = config.x_axis_native_type_formatter;
            let characteristics =
                config
                    .progressive_x_axis_supply_non_native
                    .into_iter()
                    .map(|input| {
                        let correctly_formatted_input = config_x_axis_type_formatter(input);
                        format!(
                            "x: {:<length$} y: {}",
                            input,
                            formula(correctly_formatted_input).separate_with_commas(),
                            length = 40
                        )
                    });
            let head = once(format!(
                "CHARACTERISTICS OF THE FORMULA FOR {}",
                config.label
            ));
            let full_text = head.into_iter().chain(characteristics).join("\n");
            STRINGS_WITH_FORMULAS_CHARACTERISTICS
                .lock()
                .expect("diagnostics poisoned")
                .push(full_text);
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS;
    use crate::accountant::payment_adjuster::diagnostics::PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS, false);
        assert_eq!(COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS, false)
    }
}
