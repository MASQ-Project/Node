// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::DecidedAccounts::{
    LowGainingAccountEliminated, SomeAccountsProcessed,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, UnconfirmedAdjustment,
    WeightedPayable,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::
ordinary_diagnostic_functions::{proposed_adjusted_balance_diagnostics};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    compute_mul_coefficient_preventing_fractional_numbers, weights_total,
};
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::utils::convert_collection;
use std::vec;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::thriving_competitor_found_diagnostics;

pub trait ServiceFeeAdjuster {
    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        disqualification_arbiter: &DisqualificationArbiter,
        unallocated_cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult;
}

pub struct ServiceFeeAdjusterReal {
    adjustment_computer: AdjustmentComputer,
}

impl ServiceFeeAdjuster for ServiceFeeAdjusterReal {
    fn perform_adjustment_by_service_fee(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        disqualification_arbiter: &DisqualificationArbiter,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult {
        let unconfirmed_adjustments = self
            .adjustment_computer
            .compute_unconfirmed_adjustments(weighted_accounts, cw_service_fee_balance_minor);

        let checked_accounts = Self::handle_winning_accounts(unconfirmed_adjustments);

        match checked_accounts {
            Either::Left(no_thriving_competitors) => Self::disqualify_single_account(
                disqualification_arbiter,
                no_thriving_competitors,
                logger,
            ),
            Either::Right(thriving_competitors) => thriving_competitors,
        }
    }
}

impl Default for ServiceFeeAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceFeeAdjusterReal {
    fn new() -> Self {
        Self {
            adjustment_computer: Default::default(),
        }
    }

    // The thin term "outweighed account" coma from a phenomenon with an account whose weight
    // increases significantly based on a different parameter than the debt size. Untreated, we
    // would wind up granting the account (much) more money than what it got recorded by
    // the Accountant.
    //
    // Each outweighed account, as well as any one with the proposed balance computed as a value
    // between the disqualification limit of this account and the entire balance (originally
    // requested), will gain instantly the same portion that equals the disqualification limit
    // of this account. Anything below that is, in turn, considered unsatisfying, hence a reason
    // for that account to go away simply disqualified.
    //
    // The idea is that we want to spare as much as possible in the held means that could be
    // continuously distributed among the rest of accounts until it is possible to adjust an account
    // and unmeet the condition for a disqualification.
    //
    // On the other hand, if it begins being clear that the remaining money can keep no other
    // account up in the selection there is yet another operation to come where the already
    // selected accounts are reviewed again in the order of their significance and some of
    // the unused money is poured into them, which goes on until zero.
    fn handle_winning_accounts(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let (thriving_competitors, losing_competitors) =
            Self::filter_and_process_winners(unconfirmed_adjustments);

        if thriving_competitors.is_empty() {
            Either::Left(losing_competitors)
        } else {
            let remaining_undecided_accounts: Vec<WeightedPayable> =
                convert_collection(losing_competitors);
            let pre_processed_decided_accounts: Vec<AdjustedAccountBeforeFinalization> =
                convert_collection(thriving_competitors);
            Either::Right(AdjustmentIterationResult {
                decided_accounts: SomeAccountsProcessed(pre_processed_decided_accounts),
                remaining_undecided_accounts,
            })
        }
    }

    fn disqualify_single_account(
        disqualification_arbiter: &DisqualificationArbiter,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
        logger: &Logger,
    ) -> AdjustmentIterationResult {
        let disqualified_account_wallet = disqualification_arbiter
            .find_an_account_to_disqualify_in_this_iteration(&unconfirmed_adjustments, logger);

        let remaining = unconfirmed_adjustments
            .into_iter()
            .filter(|account_info| account_info.wallet() != &disqualified_account_wallet)
            .collect();

        let remaining_reverted = convert_collection(remaining);

        AdjustmentIterationResult {
            decided_accounts: LowGainingAccountEliminated,
            remaining_undecided_accounts: remaining_reverted,
        }
    }

    fn filter_and_process_winners(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<UnconfirmedAdjustment>,
    ) {
        let init: (Vec<UnconfirmedAdjustment>, Vec<UnconfirmedAdjustment>) = (vec![], vec![]);
        let (thriving_competitors, losing_competitors) = unconfirmed_adjustments.into_iter().fold(
            init,
            |(mut thriving_competitors, mut losing_competitors), current| {
                let disqualification_limit = current.disqualification_limit_minor();
                if current.proposed_adjusted_balance_minor >= disqualification_limit {
                    thriving_competitor_found_diagnostics(&current, disqualification_limit);
                    let mut adjusted = current;
                    adjusted.proposed_adjusted_balance_minor = disqualification_limit;
                    thriving_competitors.push(adjusted)
                } else {
                    losing_competitors.push(current)
                }
                (thriving_competitors, losing_competitors)
            },
        );

        let decided_accounts = if thriving_competitors.is_empty() {
            vec![]
        } else {
            convert_collection(thriving_competitors)
        };

        (decided_accounts, losing_competitors)
    }
}

#[derive(Default)]
pub struct AdjustmentComputer {}

impl AdjustmentComputer {
    pub fn compute_unconfirmed_adjustments(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        unallocated_cw_service_fee_balance_minor: u128,
    ) -> Vec<UnconfirmedAdjustment> {
        let weights_total = weights_total(&weighted_accounts);
        let cw_service_fee_balance = unallocated_cw_service_fee_balance_minor;

        let multiplication_coefficient =
            compute_mul_coefficient_preventing_fractional_numbers(cw_service_fee_balance);

        let proportional_cw_balance_fragment = Self::compute_proportional_cw_fragment(
            cw_service_fee_balance,
            weights_total,
            multiplication_coefficient,
        );

        let compute_proposed_adjusted_balance =
            |weight: u128| weight * proportional_cw_balance_fragment / multiplication_coefficient;

        weighted_accounts
            .into_iter()
            .map(|weighted_account| {
                let proposed_adjusted_balance =
                    compute_proposed_adjusted_balance(weighted_account.weight);

                proposed_adjusted_balance_diagnostics(&weighted_account, proposed_adjusted_balance);

                UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance)
            })
            .collect()
    }

    fn compute_proportional_cw_fragment(
        cw_service_fee_balance_minor: u128,
        weights_total: u128,
        multiplication_coefficient: u128,
    ) -> u128 {
        cw_service_fee_balance_minor
            // Considered safe due to the process of getting this coefficient
            .checked_mul(multiplication_coefficient)
            .unwrap_or_else(|| {
                panic!(
                    "mul overflow from {} * {}",
                    cw_service_fee_balance_minor, multiplication_coefficient
                )
            })
            .checked_div(weights_total)
            .expect("div overflow")
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::{
        make_non_guaranteed_unconfirmed_adjustment, multiple_by_billion,
    };

    #[test]
    fn filter_and_process_winners_limits_them_by_their_disqualification_edges() {
        let mut account_1 = make_non_guaranteed_unconfirmed_adjustment(111);
        let weight_1 = account_1.weighted_account.weight;
        account_1
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_1
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(1_800_000_000);
        account_1.proposed_adjusted_balance_minor = multiple_by_billion(3_000_000_000);
        let mut account_2 = make_non_guaranteed_unconfirmed_adjustment(222);
        let weight_2 = account_2.weighted_account.weight;
        account_2
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(5_000_000_000);
        account_2
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(4_200_000_000) - 1;
        account_2.proposed_adjusted_balance_minor = multiple_by_billion(4_200_000_000);
        let mut account_3 = make_non_guaranteed_unconfirmed_adjustment(333);
        account_3
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(3_000_000_000);
        account_3
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(2_000_000_000) + 1;
        account_3.proposed_adjusted_balance_minor = multiple_by_billion(2_000_000_000);
        let mut account_4 = make_non_guaranteed_unconfirmed_adjustment(444);
        let weight_4 = account_4.weighted_account.weight;
        account_4
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(1_500_000_000);
        account_4
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(500_000_000);
        account_4.proposed_adjusted_balance_minor = multiple_by_billion(500_000_000);
        let mut account_5 = make_non_guaranteed_unconfirmed_adjustment(555);
        account_5
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_5
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(1_000_000_000) + 1;
        account_5.proposed_adjusted_balance_minor = multiple_by_billion(1_000_000_000);
        let unconfirmed_accounts = vec![
            account_1.clone(),
            account_2.clone(),
            account_3.clone(),
            account_4.clone(),
            account_5.clone(),
        ];

        let (thriving_competitors, losing_competitors) =
            ServiceFeeAdjusterReal::filter_and_process_winners(unconfirmed_accounts);

        assert_eq!(losing_competitors, vec![account_3, account_5]);
        let expected_adjusted_outweighed_accounts = vec![
            AdjustedAccountBeforeFinalization::new(
                account_1
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_1,
                multiple_by_billion(1_800_000_000),
            ),
            AdjustedAccountBeforeFinalization::new(
                account_2
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_2,
                multiple_by_billion(4_200_000_000) - 1,
            ),
            AdjustedAccountBeforeFinalization::new(
                account_4
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_4,
                multiple_by_billion(500_000_000),
            ),
        ];
        assert_eq!(thriving_competitors, expected_adjusted_outweighed_accounts)
    }
}
