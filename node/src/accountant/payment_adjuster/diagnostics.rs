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

pub fn collection_diagnostics<D: Debug>(label: &str, accounts: &[D]) {
    if PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub mod separately_defined_diagnostic_functions {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::criteria_calculators::ParameterCriterionCalculator;
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

    pub fn calculator_local_diagnostics<N: ParameterCriterionCalculator + ?Sized>(
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
            calculator.parameter_name(),
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

    // Only for debugging; in order to see the characteristic values of distinct parameter
    // you only have to run one (no matter if more) test which executes including the core part
    // where the criteria are applied, in other words computed. You cannot grab a wrong one if
    // you are picking from high level tests of the PaymentAdjuster class
    pub const COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS: bool = true;
    //mutex should be fine for debugging, no need for mut static
    static SUMMARIES_OF_FORMULA_CHARACTERISTICS_SEPARATE_BY_PARAMETERS: Mutex<Vec<String>> =
        Mutex::new(vec![]);
    static FORMULAS_CHARACTERISTICS_SINGLETON: Once = Once::new();

    pub struct DiagnosticsAxisX<A> {
        pub non_remarkable_values_supply: Vec<u128>,
        pub remarkable_values_opt: Option<Vec<(u128, &'static str)>>,
        pub convertor_to_expected_formula_input_type: Box<dyn Fn(u128) -> A + Send>,
    }

    impl<A> DiagnosticsAxisX<A> {
        fn finalize_input_with_remarkable_values(&self) -> Vec<u128> {
            match self.remarkable_values_opt.as_ref() {
                Some(vals) => {
                    let filtered_remarkable_values = vals.iter().map(|(num, _)| num);
                    let standard_input = self.non_remarkable_values_supply.iter();
                    filtered_remarkable_values
                        .chain(standard_input)
                        .sorted()
                        .dedup()
                        .map(|num| *num)
                        .collect()
                }
                None => self.non_remarkable_values_supply.clone(),
            }
        }
    }

    pub fn render_formulas_characteristics_for_diagnostics_if_enabled() {
        if COMPUTE_FORMULAS_PROGRESSIVE_CHARACTERISTICS {
            FORMULAS_CHARACTERISTICS_SINGLETON.call_once(|| {
                let comprehend_debug_summary =
                    SUMMARIES_OF_FORMULA_CHARACTERISTICS_SEPARATE_BY_PARAMETERS
                        .lock()
                        .expect("diagnostics poisoned")
                        .join("\n\n");

                eprintln!("{}", comprehend_debug_summary)
            })
        }
    }

    fn render_notation(
        coordinate_value: u128,
        remarkable_vals: Option<&Vec<(u128, &'static str)>>,
    ) -> String {
        match should_mark_be_used(coordinate_value, remarkable_vals) {
            Some(mark) => format!("{}  {}", coordinate_value.separate_with_commas(), mark),
            None => coordinate_value.separate_with_commas(),
        }
    }
    fn should_mark_be_used(
        coordinate_value: u128,
        remarkable_vals: Option<&Vec<(u128, &'static str)>>,
    ) -> Option<&'static str> {
        match remarkable_vals {
            Some(vals) => vals
                .iter()
                .find(|(val, _)| coordinate_value == *val)
                .map(|(_, mark)| *mark),
            None => None,
        }
    }

    pub fn compute_progressive_characteristics<A>(
        main_param_name: &'static str,
        config_opt: Option<DiagnosticsAxisX<A>>,
        formula: &dyn Fn(A) -> u128,
    ) where
        A: Debug,
    {
        config_opt.map(|mut config| {
            let input_values = config.finalize_input_with_remarkable_values();
            let remarkable = config.remarkable_values_opt.take();
            let config_x_axis_type_formatter = config.convertor_to_expected_formula_input_type;
            let characteristics = input_values.into_iter().map(|single_coordinate| {
                let correctly_formatted_input = config_x_axis_type_formatter(single_coordinate);
                let input_with_commas = render_notation(single_coordinate, remarkable.as_ref());
                let computed_value_with_commas =
                    formula(correctly_formatted_input).separate_with_commas();
                format!(
                    "x: {:<length$} y: {}",
                    input_with_commas,
                    computed_value_with_commas,
                    length = 40
                )
            });
            let head = once(format!(
                "CHARACTERISTICS OF THE FORMULA FOR {}",
                main_param_name
            ));
            let full_text = head.into_iter().chain(characteristics).join("\n");
            SUMMARIES_OF_FORMULA_CHARACTERISTICS_SEPARATE_BY_PARAMETERS
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
