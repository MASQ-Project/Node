// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;

const PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS: bool = false;

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

pub mod separately_defined_diagnostic_functions {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::criteria_calculators::CalculatorWithNamedMainParameter;
    use crate::accountant::payment_adjuster::diagnostics;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::sub_lib::wallet::Wallet;
    use thousands::Separable;

    pub fn possibly_outweighed_accounts_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            &account_info.original_account.wallet,
            "OUTWEIGHED ACCOUNT FOUND",
            "Original balance: {}, proposed balance: {}",
            account_info
                .original_account
                .balance_wei
                .separate_with_commas(),
            account_info
                .proposed_adjusted_balance
                .separate_with_commas()
        );
    }

    pub fn account_nominated_for_disqualification_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
        proposed_adjusted_balance: u128,
        disqualification_edge: u128,
    ) {
        diagnostics!(
            account_info.original_account.wallet,
            "ACCOUNT NOMINATED FOR DISQUALIFICATION FOR INSIGNIFICANCE AFTER ADJUSTMENT",
            "Proposed: {}, disqualification limit: {}",
            proposed_adjusted_balance.separate_with_commas(),
            disqualification_edge.separate_with_commas()
        );
    }

    pub fn exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) {
        diagnostics!(
            "EXHAUSTING CW ON PAYMENT",
            "For account {} from proposed {} to the possible maximum of {}",
            non_finalized_account_info.original_account.wallet,
            non_finalized_account_info.proposed_adjusted_balance,
            non_finalized_account_info.proposed_adjusted_balance + possible_extra_addition
        );
    }

    pub fn not_exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            "FULLY EXHAUSTED CW, PASSING ACCOUNT OVER",
            "Account {} with original balance {} must be finalized with proposed {}",
            non_finalized_account_info.original_account.wallet,
            non_finalized_account_info.original_account.balance_wei,
            non_finalized_account_info.proposed_adjusted_balance
        );
    }

    pub fn non_finalized_adjusted_accounts_diagnostics(
        account: &PayableAccount,
        proposed_adjusted_balance: u128,
    ) {
        diagnostics!(
            &account.wallet,
            "PROPOSED ADJUSTED BALANCE",
            "{}",
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    pub fn try_finding_an_account_to_disqualify_diagnostics(
        disqualification_suspected_accounts: &[&AdjustedAccountBeforeFinalization],
        wallet: &Wallet,
    ) {
        diagnostics!(
            "PICKED DISQUALIFIED ACCOUNT",
            "From {:?} picked {}",
            disqualification_suspected_accounts,
            wallet
        );
    }

    pub fn calculator_local_diagnostics<N: CalculatorWithNamedMainParameter + ?Sized>(
        wallet_ref: &Wallet,
        calculator: &N,
        criterion: u128,
        added_in_the_sum: u128,
    ) {
        const FIRST_COLUMN_WIDTH: usize = 30;
        diagnostics!(
            wallet_ref,
            "PARTIAL CRITERION CALCULATED",
            "{:<width$} {} and summed up as {}",
            calculator.main_parameter_name(),
            criterion.separate_with_commas(),
            added_in_the_sum.separate_with_commas(),
            width = FIRST_COLUMN_WIDTH
        );
    }
}

#[cfg(test)]
pub mod formulas_progressive_characteristics {
    use itertools::Itertools;
    use std::fmt::Debug;
    use std::iter::once;
    use std::sync::{Mutex, Once};
    use thousands::Separable;

    pub const COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS: bool = false;
    //mutex should be fine for debugging, no need for mut static
    static STRINGS_WITH_FORMULAS_CHARACTERISTICS: Mutex<Vec<String>> = Mutex::new(vec![]);
    static FORMULAS_CHARACTERISTICS_SINGLETON: Once = Once::new();

    pub struct DiagnosticsConfig<A> {
        pub horizontal_axis_progressive_supply: Vec<u128>,
        pub horizontal_axis_native_type_formatter: Box<dyn Fn(u128) -> A + Send>,
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
        main_param_name: &'static str,
        config_opt: Option<DiagnosticsConfig<A>>,
        formula: &dyn Fn(A) -> u128,
    ) where
        A: Debug,
    {
        config_opt.map(|config| {
            let config_x_axis_type_formatter = config.horizontal_axis_native_type_formatter;
            let characteristics =
                config
                    .horizontal_axis_progressive_supply
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
                main_param_name
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
