// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::{
    outweighed_accounts_diagnostics, proposed_adjusted_balance_diagnostics,
};
use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::SpecialHandling::{
    InsignificantAccountEliminated, OutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, UnconfirmedAdjustment,
    WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    compute_mul_coefficient_preventing_fractional_numbers, weights_total,
};
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

        let still_unchecked_for_disqualified = match Self::handle_possibly_outweighed_accounts(
            disqualification_arbiter,
            non_finalized_adjusted_accounts,
        ) {
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
        disqualification_arbiter: &DisqualificationArbiter,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let (outweighed, properly_adjusted_accounts) = Self::adjust_account_balance_if_outweighed(
            disqualification_arbiter,
            unconfirmed_adjustments,
        );

        if outweighed.is_empty() {
            Either::Left(properly_adjusted_accounts)
        } else {
            let remaining_undecided_accounts: Vec<WeightedPayable> =
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
            let remaining = unconfirmed_adjustments
                .into_iter()
                .filter(|account_info| {
                    account_info
                        .weighted_account
                        .qualified_account
                        .bare_account
                        .wallet
                        != disqualified_account_wallet
                })
                .collect();

            let remaining_reverted = convert_collection(remaining);

            Either::Right(AdjustmentIterationResult::IterationWithSpecialHandling {
                case: InsignificantAccountEliminated,
                remaining_undecided_accounts: remaining_reverted,
            })
        } else {
            Either::Left(convert_collection(unconfirmed_adjustments))
        }
    }

    fn adjust_account_balance_if_outweighed(
        disqualification_arbiter: &DisqualificationArbiter,
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<UnconfirmedAdjustment>,
    ) {
        let (outweighed, properly_adjusted_accounts): (Vec<_>, Vec<_>) = unconfirmed_adjustments
            .into_iter()
            .partition(|adjustment_info| {
                adjustment_info.proposed_adjusted_balance_minor
                    > adjustment_info
                        .weighted_account
                        .qualified_account
                        .bare_account
                        .balance_wei
            });

        let outweighed_adjusted = outweighed
            .into_iter()
            .map(|account| {
                outweighed_accounts_diagnostics(&account);

                let maximized_proposed_adjusted_balance_minor = disqualification_arbiter
                    .calculate_disqualification_edge(&account.weighted_account.qualified_account);
                AdjustedAccountBeforeFinalization::new(
                    account.weighted_account.qualified_account.bare_account,
                    maximized_proposed_adjusted_balance_minor,
                )
            })
            .collect();

        (outweighed_adjusted, properly_adjusted_accounts)
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
        eprintln!("multiplication coeff {}", multiplication_coefficient);

        let proportional_cw_balance_fragment = Self::compute_proportional_cw_fragment(
            cw_service_fee_balance,
            weights_total,
            multiplication_coefficient,
        );
        eprintln!("proportional fragment {}", proportional_cw_balance_fragment);
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
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::{
        make_non_guaranteed_unconfirmed_adjustment, multiple_by_billion, DisqualificationGaugeMock,
    };

    #[test]
    fn adjust_account_balance_if_outweighed_limits_them_by_the_standard_disqualification_edge() {
        let mut account_1 = make_non_guaranteed_unconfirmed_adjustment(111);
        account_1
            .weighted_account
            .qualified_account
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_1.proposed_adjusted_balance_minor = multiple_by_billion(2_000_000_000) + 1;
        let mut account_2 = make_non_guaranteed_unconfirmed_adjustment(222);
        account_2
            .weighted_account
            .qualified_account
            .bare_account
            .balance_wei = multiple_by_billion(5_000_000_000);
        account_2.proposed_adjusted_balance_minor = multiple_by_billion(5_000_000_000) + 1;
        let mut account_3 = make_non_guaranteed_unconfirmed_adjustment(333);
        account_3
            .weighted_account
            .qualified_account
            .bare_account
            .balance_wei = multiple_by_billion(3_000_000_000);
        account_3.proposed_adjusted_balance_minor = multiple_by_billion(3_000_000_000);
        let mut account_4 = make_non_guaranteed_unconfirmed_adjustment(444);
        account_4
            .weighted_account
            .qualified_account
            .bare_account
            .balance_wei = multiple_by_billion(1_500_000_000);
        account_4.proposed_adjusted_balance_minor = multiple_by_billion(3_000_000_000);
        let mut account_5 = make_non_guaranteed_unconfirmed_adjustment(555);
        account_5
            .weighted_account
            .qualified_account
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_5.proposed_adjusted_balance_minor = multiple_by_billion(2_000_000_000) - 1;
        let unconfirmed_accounts = vec![
            account_1.clone(),
            account_2.clone(),
            account_3.clone(),
            account_4.clone(),
            account_5.clone(),
        ];
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(multiple_by_billion(1_700_000_000))
            .determine_limit_result(multiple_by_billion(4_000_000_000))
            .determine_limit_result(multiple_by_billion(1_250_555_555));
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));

        let (outweighed_accounts, properly_adjusted_accounts) =
            ServiceFeeAdjusterReal::adjust_account_balance_if_outweighed(
                &disqualification_arbiter,
                unconfirmed_accounts,
            );

        assert_eq!(properly_adjusted_accounts, vec![account_3, account_5]);
        let expected_adjusted_outweighed_accounts = vec![
            AdjustedAccountBeforeFinalization {
                original_account: account_1.weighted_account.qualified_account.bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(1_700_000_000),
            },
            AdjustedAccountBeforeFinalization {
                original_account: account_2.weighted_account.qualified_account.bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(4_000_000_000),
            },
            AdjustedAccountBeforeFinalization {
                original_account: account_4.weighted_account.qualified_account.bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(1_250_555_555),
            },
        ];
        assert_eq!(outweighed_accounts, expected_adjusted_outweighed_accounts)
    }
}
