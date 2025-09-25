// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use std::fmt::Debug;

const RUN_DIAGNOSTICS_FOR_DEVS: bool = false;

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
    ($wallet_address: expr, $description: expr,  $($formatted_values: tt)*) => {
        diagnostics(
            Some(||format!("{:?}", $wallet_address)),
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
    if RUN_DIAGNOSTICS_FOR_DEVS {
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
    if RUN_DIAGNOSTICS_FOR_DEVS {
        eprintln!("{}", label);
        accounts
            .iter()
            .for_each(|account| eprintln!("{:?}", account));
    }
}

pub mod ordinary_diagnostic_functions {
    use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
    use crate::accountant::payment_adjuster::diagnostics;
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationSuspectedAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeighedPayable,
    };
    use thousands::Separable;
    use web3::types::Address;

    pub fn diagnostics_for_accounts_above_disqualification_limit(
        account_info: &UnconfirmedAdjustment,
        disqualification_limit: u128,
    ) {
        diagnostics!(
            &account_info.wallet(),
            "THRIVING COMPETITOR FOUND",
            "Disqualification limit: {}, proposed balance: {}",
            disqualification_limit.separate_with_commas(),
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
            account_info.wallet(),
            "ACCOUNT NOMINATED FOR DISQUALIFICATION FOR INSIGNIFICANCE AFTER ADJUSTMENT",
            "Proposed: {}, disqualification limit: {}",
            proposed_adjusted_balance.separate_with_commas(),
            disqualification_edge.separate_with_commas()
        );
    }

    pub fn minimal_acceptable_balance_assigned_diagnostics(
        weighed_account: &WeighedPayable,
        disqualification_limit: u128,
    ) {
        diagnostics!(
            weighed_account.wallet(),
            "MINIMAL ACCEPTABLE BALANCE ASSIGNED",
            "Used disqualification limit for given account {}",
            disqualification_limit.separate_with_commas()
        )
    }

    pub fn exhausting_cw_balance_diagnostics(
        non_finalized_account_info: &AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) {
        diagnostics!(
            "EXHAUSTING CW ON PAYMENT",
            "Account {} from proposed {} to the possible maximum of {}",
            non_finalized_account_info.original_account.wallet,
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
            non_finalized_account_info.original_account.wallet,
            non_finalized_account_info.original_account.balance_wei,
            non_finalized_account_info.proposed_adjusted_balance_minor
        );
    }

    pub fn proposed_adjusted_balance_diagnostics(
        account: &WeighedPayable,
        proposed_adjusted_balance: u128,
    ) {
        diagnostics!(
            account.wallet(),
            "PROPOSED ADJUSTED BALANCE",
            "{}",
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    pub fn try_finding_an_account_to_disqualify_diagnostics(
        disqualification_suspected_accounts: &[DisqualificationSuspectedAccount],
        wallet: Address,
    ) {
        diagnostics!(
            "PICKED DISQUALIFIED ACCOUNT",
            "Picked {} from nominated accounts {:?}",
            wallet,
            disqualification_suspected_accounts
        );
    }

    pub fn calculated_criterion_and_weight_diagnostics(
        wallet: Address,
        calculator: &dyn CriterionCalculator,
        criterion: u128,
        added_in_the_sum: u128,
    ) {
        const FIRST_COLUMN_WIDTH: usize = 30;

        diagnostics!(
            wallet,
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
    use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::RUN_DIAGNOSTICS_FOR_DEVS;

    #[test]
    fn constants_are_correct() {
        assert_eq!(RUN_DIAGNOSTICS_FOR_DEVS, false);
    }
}
