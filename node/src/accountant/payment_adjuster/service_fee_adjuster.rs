// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::proposed_adjusted_balance_diagnostics;
use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::SpecialHandling::{
    InsignificantAccountEliminated, OutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, UnconfirmedAdjustment,
    WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    adjust_account_balance_if_outweighed, compute_mul_coefficient_preventing_fractional_numbers,
    find_largest_weight, weights_total,
};
use crate::accountant::QualifiedPayableAccount;
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::utils::convert_collection;

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
        let non_finalized_adjusted_accounts = self
            .adjustment_computer
            .compute_unconfirmed_adjustments(weighted_accounts, cw_service_fee_balance_minor);

        let still_unchecked_for_disqualified =
            match Self::handle_possibly_outweighed_accounts(non_finalized_adjusted_accounts) {
                Either::Left(first_check_passing_accounts) => first_check_passing_accounts,
                Either::Right(with_some_outweighed) => return with_some_outweighed,
            };

        let verified_accounts = match Self::consider_account_disqualification(
            disqualification_arbiter,
            still_unchecked_for_disqualified,
            logger,
        ) {
            Either::Left(verified_accounts) => verified_accounts,
            Either::Right(with_some_disqualified) => return with_some_disqualified,
        };

        AdjustmentIterationResult::AllAccountsProcessed(verified_accounts)
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

    // The term "outweighed account" comes from a phenomenon with account weight increasing
    // significantly based on a different parameter than the debt size. Untreated, we would which
    // grant the account (much) more money than what the accountancy has recorded for it.
    fn handle_possibly_outweighed_accounts(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let init = (vec![], vec![]);

        let (outweighed, properly_adjusted_accounts) = unconfirmed_adjustments
            .into_iter()
            .fold(init, adjust_account_balance_if_outweighed);

        if outweighed.is_empty() {
            Either::Left(properly_adjusted_accounts)
        } else {
            let remaining_undecided_accounts: Vec<QualifiedPayableAccount> =
                convert_collection(properly_adjusted_accounts);
            let pre_processed_outweighed: Vec<AdjustedAccountBeforeFinalization> =
                convert_collection(outweighed);
            Either::Right(AdjustmentIterationResult::IterationWithSpecialHandling {
                case: OutweighedAccounts(pre_processed_outweighed),
                remaining_undecided_accounts,
            })
        }
    }

    fn consider_account_disqualification(
        disqualification_arbiter: &DisqualificationArbiter,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
        logger: &Logger,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        if let Some(disqualified_account_wallet) = disqualification_arbiter
            .try_finding_an_account_to_disqualify_in_this_iteration(
                &unconfirmed_adjustments,
                logger,
            )
        {
            let remaining = unconfirmed_adjustments.into_iter().filter(|account_info| {
                account_info
                    .non_finalized_account
                    .qualified_payable
                    .qualified_as
                    .wallet
                    != disqualified_account_wallet
            });

            let remaining_reverted = remaining
                .map(|account_info| {
                    //TODO maybe implement from like before
                    account_info.non_finalized_account.qualified_payable
                    // PayableAccount::from(NonFinalizedAdjustmentWithResolution::new(
                    //     account_info.non_finalized_account,
                    //     AdjustmentResolution::Revert,
                    // ))
                })
                .collect();

            Either::Right(AdjustmentIterationResult::IterationWithSpecialHandling {
                case: InsignificantAccountEliminated,
                remaining_undecided_accounts: remaining_reverted,
            })
        } else {
            Either::Left(convert_collection(unconfirmed_adjustments))
        }
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
        let largest_weight = find_largest_weight(&weighted_accounts);
        let cw_service_fee_balance = unallocated_cw_service_fee_balance_minor;

        let multiplication_coefficient = compute_mul_coefficient_preventing_fractional_numbers(
            cw_service_fee_balance,
            largest_weight,
        );

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

                proposed_adjusted_balance_diagnostics(
                    &weighted_account.qualified_account,
                    proposed_adjusted_balance,
                );

                UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance)
            })
            .collect()
    }

    fn compute_proportional_cw_fragment(
        cw_service_fee_balance: u128,
        weights_total: u128,
        multiplication_coefficient: u128,
    ) -> u128 {
        cw_service_fee_balance
            // Considered safe due to the process of getting this coefficient
            .checked_mul(multiplication_coefficient)
            .unwrap_or_else(|| {
                panic!(
                    "mul overflow from {} * {}",
                    weights_total, multiplication_coefficient
                )
            })
            .checked_div(weights_total)
            .expect("div overflow")
    }
}

// fn perform_adjustment_by_service_fee(
//     &self,
//     weighted_accounts: Vec<WeightedPayable>,
// ) -> AdjustmentIterationResult {
//     let non_finalized_adjusted_accounts =
//         self.compute_unconfirmed_adjustments(weighted_accounts);
//
//     let still_unchecked_for_disqualified =
//         match self.handle_possibly_outweighed_accounts(non_finalized_adjusted_accounts) {
//             Either::Left(first_check_passing_accounts) => first_check_passing_accounts,
//             Either::Right(with_some_outweighed) => return with_some_outweighed,
//         };
//
//     let verified_accounts = match self
//         .consider_account_disqualification(still_unchecked_for_disqualified, &self.logger)
//     {
//         Either::Left(verified_accounts) => verified_accounts,
//         Either::Right(with_some_disqualified) => return with_some_disqualified,
//     };
//
//     AdjustmentIterationResult::AllAccountsProcessed(verified_accounts)
// }

// TODO Should this become a helper? ...with which I can catch mid-results and assert on them?
//
// fn compute_unconfirmed_adjustments(
//     &self,
//     weighted_accounts: Vec<WeightedPayable>,
// ) -> Vec<UnconfirmedAdjustment> {
//     let weights_total = weights_total(&weighted_accounts);
//     let largest_weight = find_largest_weight(&weighted_accounts);
//     let cw_service_fee_balance = self.inner.unallocated_cw_service_fee_balance_minor();
//
//     let multiplication_coefficient = compute_mul_coefficient_preventing_fractional_numbers(
//         cw_service_fee_balance,
//         largest_weight,
//     );
//
//     let proportional_cw_balance_fragment = Self::compute_proportional_cw_fragment(
//         cw_service_fee_balance,
//         weights_total,
//         multiplication_coefficient,
//     );
//     let compute_proposed_adjusted_balance =
//         |weight: u128| weight * proportional_cw_balance_fragment / multiplication_coefficient;
//
//     weighted_accounts
//         .into_iter()
//         .map(|weighted_account| {
//             let proposed_adjusted_balance =
//                 compute_proposed_adjusted_balance(weighted_account.weight);
//
//             proposed_adjusted_balance_diagnostics(
//                 &weighted_account.qualified_account,
//                 proposed_adjusted_balance,
//             );
//
//             UnconfirmedAdjustment::new(weighted_account, proposed_adjusted_balance)
//         })
//         .collect()
// }
