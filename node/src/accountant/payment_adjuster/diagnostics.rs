// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use std::fmt::Debug;

const PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS: bool = true;

pub const DIAGNOSTICS_MIDDLE_COLUMN_WIDTH: usize = 58;

#[macro_export]
macro_rules! diagnostics {
    // Displays only a description of an event
    ($description: literal) => {
       diagnostics(
           None::<fn()->String>,
           $description,
           None::<fn()->String>
       )
    };
    // Displays a brief description and values from a collection
    ($description: literal, $debuggable_collection: expr) => {
        collection_diagnostics($description, $debuggable_collection)
    };
    // Displays a brief description and formatted literal with arguments
    ($description: literal, $($formatted_values: tt)*) => {
        diagnostics(
            None::<fn()->String>,
            $description,
            Some(|| format!($($formatted_values)*))
        )
    };
    // Displays an account by wallet address, brief description and formatted literal with arguments
    ($wallet_ref: expr, $description: expr,  $($formatted_values: tt)*) => {
        diagnostics(
            Some(||$wallet_ref.to_string()),
            $description,
            Some(|| format!($($formatted_values)*))
        )
    };
}

// Intended to be used through the overloaded macro diagnostics!() for better clearness
// and differentiation from the primary functionality
pub fn diagnostics<F1, F2>(
    subject_renderer_opt: Option<F1>,
    description: &str,
    value_renderer_opt: Option<F2>,
) where
    F1: FnOnce() -> String,
    F2: FnOnce() -> String,
{
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        let subject_column_length = if subject_renderer_opt.is_some() {
            WALLET_ADDRESS_LENGTH + 2
        } else {
            0
        };
        let subject = no_text_or_by_renderer(subject_renderer_opt);
        let values = no_text_or_by_renderer(value_renderer_opt);
        let description_length = DIAGNOSTICS_MIDDLE_COLUMN_WIDTH;
        eprintln!(
            "\n{:<subject_column_length$}{:<description_length$}  {}",
            subject, description, values,
        )
    }
}

fn no_text_or_by_renderer<F>(renderer_opt: Option<F>) -> String
where
    F: FnOnce() -> String,
{
    if let Some(renderer) = renderer_opt {
        renderer()
    } else {
        "".to_string()
    }
}

// Should be used via the macro diagnostics!() for better clearness and differentiation from
// the prime functionality
pub fn collection_diagnostics<DebuggableAccount: Debug>(
    label: &str,
    accounts: &[DebuggableAccount],
) {
    if PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub mod ordinary_diagnostic_functions {
    use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::diagnostics;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment,
    };
    use crate::accountant::QualifiedPayableAccount;
    use crate::sub_lib::wallet::Wallet;
    use thousands::Separable;

    pub fn possibly_outweighed_accounts_diagnostics(
        account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            &account_info.original_qualified_account.payable.wallet,
            "OUTWEIGHED ACCOUNT FOUND",
            "Original balance: {}, proposed balance: {}",
            account_info
                .original_qualified_account
                .payable
                .balance_wei
                .separate_with_commas(),
            account_info
                .proposed_adjusted_balance_minor
                .separate_with_commas()
        );
    }

    pub fn account_nominated_for_disqualification_diagnostics(
        account_info: &UnconfirmedAdjustment,
        proposed_adjusted_balance: u128,
        disqualification_edge: u128,
    ) {
        diagnostics!(
            account_info
                .non_finalized_account
                .original_qualified_account
                .payable
                .wallet,
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
            non_finalized_account_info
                .original_qualified_account
                .payable
                .wallet,
            non_finalized_account_info.proposed_adjusted_balance_minor,
            non_finalized_account_info.proposed_adjusted_balance_minor + possible_extra_addition
        );
    }

    pub fn not_exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
    ) {
        diagnostics!(
            "FULLY EXHAUSTED CW, PASSING ACCOUNT OVER",
            "Account {} with original balance {} must be finalized with proposed {}",
            non_finalized_account_info
                .original_qualified_account
                .payable
                .wallet,
            non_finalized_account_info
                .original_qualified_account
                .payable
                .balance_wei,
            non_finalized_account_info.proposed_adjusted_balance_minor
        );
    }

    pub fn proposed_adjusted_balance_diagnostics(
        account: &QualifiedPayableAccount,
        proposed_adjusted_balance: u128,
    ) {
        diagnostics!(
            &account.payable.wallet,
            "PROPOSED ADJUSTED BALANCE",
            "{}",
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    pub fn try_finding_an_account_to_disqualify_diagnostics(
        disqualification_suspected_accounts: &[&UnconfirmedAdjustment],
        wallet: &Wallet,
    ) {
        diagnostics!(
            "PICKED DISQUALIFIED ACCOUNT",
            "From {:?} picked {}",
            disqualification_suspected_accounts,
            wallet
        );
    }

    pub fn calculated_criterion_and_weight_diagnostics(
        wallet_ref: &Wallet,
        calculator: &dyn CriterionCalculator,
        criterion: u128,
        added_in_the_sum: u128,
    ) {
        const FIRST_COLUMN_WIDTH: usize = 30;

        diagnostics!(
            wallet_ref,
            "PARTIAL CRITERION CALCULATED",
            "For {:<width$} {} and summed up to {}",
            calculator.parameter_name(),
            criterion.separate_with_commas(),
            added_in_the_sum.separate_with_commas(),
            width = FIRST_COLUMN_WIDTH
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::diagnostics::PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PRINT_RESULTS_OF_PARTIAL_COMPUTATIONS, false);
    }
}
