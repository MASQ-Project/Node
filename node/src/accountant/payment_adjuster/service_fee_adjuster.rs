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
ordinary_diagnostic_functions::{minimal_acceptable_balance_assigned_diagnostics, outweighed_accounts_diagnostics, proposed_adjusted_balance_diagnostics};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    compute_mul_coefficient_preventing_fractional_numbers, weights_total,
};
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::utils::convert_collection;
use std::vec;

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

        match Self::handle_sufficiently_filled_accounts(unconfirmed_adjustments) {
            Either::Left(without_gainers) => {
                //TODO arbiter, what about it here?
                Self::disqualify_single_account(disqualification_arbiter, without_gainers, logger)
            }
            Either::Right(with_gainers) => with_gainers,
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

    //TODO review this text
    // The term "outweighed account" comes from a phenomenon with account weight increasing
    // significantly based on a different parameter than the debt size. Untreated, we would
    // grant the account (much) more money than what the accountancy has actually recorded.
    //
    // Outweighed accounts gain instantly the portion that tallies with the disqualification
    // limit for this account. That's why we use the disqualification arbiter also in other
    // places than only where we test an account on its minimal allowed size, considering
    // elimination of such accounts.
    //
    // The idea is that we want to spare as much as possible means that could be distributed
    // among the rest of accounts. Given we declare that accounts having at least the size
    // of the disqualification limit are fine, we don't exhaust the means right away on
    // these.
    //
    // On the other hand, if it turns out the spared money cannot be effectively used
    // to adjust more accounts for the minimal necessary value, letting them fall away
    // eventually, there is still the ending operation where the already prepared accounts
    // are reconsidered to be give more bits from the fund of unallocated money, all down
    // to zero.
    fn handle_sufficiently_filled_accounts(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let (sufficient_gainers, low_gainers) =
            Self::filter_and_process_sufficient_gainers(unconfirmed_adjustments);

        if sufficient_gainers.is_empty() {
            Either::Left(low_gainers)
        } else {
            let remaining_undecided_accounts: Vec<WeightedPayable> =
                convert_collection(low_gainers);
            let pre_processed_decided_accounts: Vec<AdjustedAccountBeforeFinalization> =
                convert_collection(sufficient_gainers);
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

    fn filter_and_process_sufficient_gainers(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<UnconfirmedAdjustment>,
    ) {
        let init: (Vec<UnconfirmedAdjustment>, Vec<UnconfirmedAdjustment>) = (vec![], vec![]);
        let (sufficient_gainers, low_gainers) = unconfirmed_adjustments.into_iter().fold(
            init,
            |(mut sufficient_gainers, mut low_gainers), current| {
                let disqualification_limit = current.disqualification_limit_minor();
                if current.proposed_adjusted_balance_minor >= disqualification_limit
                //TODO is the operator tested??
                {
                    outweighed_accounts_diagnostics(&current);
                    let mut adjusted = current;
                    adjusted.proposed_adjusted_balance_minor = disqualification_limit;
                    sufficient_gainers.push(adjusted)
                } else {
                    low_gainers.push(current)
                }
                (sufficient_gainers, low_gainers)
            },
        );

        // let outweighed_adjusted = if outweighed.is_empty() {
        //     vec![]
        // } else {
        //     Self::assign_accounts_their_minimal_acceptable_balance(
        //         outweighed,
        //         disqualification_arbiter,
        //     )
        // };

        let outweighed_adjusted = if sufficient_gainers.is_empty() {
            vec![]
        } else {
            // Self::assign_accounts_their_minimal_acceptable_balance(
            //     outweighed,
            //     disqualification_arbiter,
            // )
            convert_collection(sufficient_gainers)
        };
        //TODO Maybe consider to return the two return types just right from the fold
        (outweighed_adjusted, low_gainers)
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
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment,
    };
    use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::{
        make_non_guaranteed_unconfirmed_adjustment, multiple_by_billion, DisqualificationGaugeMock,
    };

    #[test]
    fn filter_and_process_sufficient_gainers_limits_them_by_the_standard_disqualification_edge() {
        let proposed_adjusted_balance_1 = multiple_by_billion(3_000_000_000);
        let mut account_1 = make_non_guaranteed_unconfirmed_adjustment(111);
        account_1
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_1.proposed_adjusted_balance_minor = proposed_adjusted_balance_1;
        account_1
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(1_800_000_000);
        let proposed_adjusted_balance_2 = multiple_by_billion(4_200_000_000);
        let mut account_2 = make_non_guaranteed_unconfirmed_adjustment(222);
        account_2
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(5_000_000_000);
        account_2.proposed_adjusted_balance_minor = proposed_adjusted_balance_2;
        account_2
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(4_200_000_000) - 1;
        let proposed_adjusted_balance_3 = multiple_by_billion(2_000_000_000);
        let mut account_3 = make_non_guaranteed_unconfirmed_adjustment(333);
        account_3
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(3_000_000_000);
        account_3.proposed_adjusted_balance_minor = proposed_adjusted_balance_3;
        account_3
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(2_000_000_000) + 1;
        let proposed_adjusted_balance_4 = multiple_by_billion(500_000_000);
        let mut account_4 = make_non_guaranteed_unconfirmed_adjustment(444);
        account_4
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(1_500_000_000);
        account_4.proposed_adjusted_balance_minor = proposed_adjusted_balance_4;
        account_4
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(500_000_000);
        let proposed_adjusted_balance_5 = multiple_by_billion(1_000_000_000);
        let mut account_5 = make_non_guaranteed_unconfirmed_adjustment(555);
        account_5
            .weighted_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiple_by_billion(2_000_000_000);
        account_5.proposed_adjusted_balance_minor = proposed_adjusted_balance_5;
        account_5
            .weighted_account
            .analyzed_account
            .disqualification_limit_minor = multiple_by_billion(1_000_000_000) + 1;
        let unconfirmed_accounts = vec![
            account_1.clone(),
            account_2.clone(),
            account_3.clone(),
            account_4.clone(),
            account_5.clone(),
        ];

        let (sufficient_gainers, low_gainers) =
            ServiceFeeAdjusterReal::filter_and_process_sufficient_gainers(unconfirmed_accounts);

        assert_eq!(low_gainers, vec![account_3, account_5]);
        let expected_adjusted_outweighed_accounts = vec![
            AdjustedAccountBeforeFinalization {
                original_account: account_1
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(1_800_000_000),
            },
            AdjustedAccountBeforeFinalization {
                original_account: account_2
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(4_200_000_000) - 1,
            },
            AdjustedAccountBeforeFinalization {
                original_account: account_4
                    .weighted_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                proposed_adjusted_balance_minor: multiple_by_billion(500_000_000),
            },
        ];
        assert_eq!(sufficient_gainers, expected_adjusted_outweighed_accounts)
    }
}
