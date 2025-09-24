// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, UnconfirmedAdjustment,
    WeighedPayable,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::
ordinary_diagnostic_functions::{proposed_adjusted_balance_diagnostics};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{compute_mul_coefficient_preventing_fractional_numbers, sum_as};
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::utils::convert_collection;
use std::vec;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::diagnostics_for_accounts_above_disqualification_limit;

pub trait ServiceFeeAdjuster {
    fn perform_adjustment_by_service_fee(
        &self,
        weighed_accounts: Vec<WeighedPayable>,
        disqualification_arbiter: &DisqualificationArbiter,
        remaining_cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult;
}

#[derive(Default)]
pub struct ServiceFeeAdjusterReal {}

impl ServiceFeeAdjuster for ServiceFeeAdjusterReal {
    fn perform_adjustment_by_service_fee(
        &self,
        weighed_accounts: Vec<WeighedPayable>,
        disqualification_arbiter: &DisqualificationArbiter,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> AdjustmentIterationResult {
        let unconfirmed_adjustments =
            compute_unconfirmed_adjustments(weighed_accounts, cw_service_fee_balance_minor);

        let checked_accounts = Self::try_confirm_some_accounts(unconfirmed_adjustments);

        match checked_accounts {
            Either::Left(only_accounts_below_disq_limit) => Self::disqualify_single_account(
                disqualification_arbiter,
                only_accounts_below_disq_limit,
                logger,
            ),
            Either::Right(some_accounts_above_or_even_to_disq_limit) => {
                some_accounts_above_or_even_to_disq_limit
            }
        }
    }
}

impl ServiceFeeAdjusterReal {
    // The thin term "outweighed account" comes from a phenomenon related to an account whose weight
    // increases significantly based on a different parameter than the debt size. Untreated, it
    // could easily wind up with granting the account (much) more money than it was recorded by
    // the Accountant.
    //
    // Each outweighed account, and even further, also any account with the proposed adjusted
    // balance higher than its disqualification limit, will gain instantly equally to its
    // disqualification limit. Anything below that is, in turn, considered unsatisfying, hence
    // the reason to be disqualified.
    //
    // The idea is that we try to spare as much as possible from the means that could be, if done
    // wisely, better redistributed among the rest of accounts, as much as the wider group of them
    // can be satisfied, even though just partially.
    //
    // However, if it begins to be clear that the remaining money doesn't allow keeping any
    // additional account in the selection, there is the next step to come, where the already
    // selected accounts are reviewed again in the order of their significance resolved from
    // remembering their weights from the earlier processing, and the unused money is poured into,
    // until all resources are used.

    fn try_confirm_some_accounts(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> Either<Vec<UnconfirmedAdjustment>, AdjustmentIterationResult> {
        let (accounts_above_or_even_to_disq_limit, accounts_below_disq_limit) =
            Self::filter_and_process_confirmable_accounts(unconfirmed_adjustments);

        if accounts_above_or_even_to_disq_limit.is_empty() {
            Either::Left(accounts_below_disq_limit)
        } else {
            let remaining_undecided_accounts: Vec<WeighedPayable> =
                convert_collection(accounts_below_disq_limit);
            let pre_processed_decided_accounts: Vec<AdjustedAccountBeforeFinalization> =
                convert_collection(accounts_above_or_even_to_disq_limit);
            Either::Right(AdjustmentIterationResult {
                decided_accounts: pre_processed_decided_accounts,
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
            .filter(|account_info| account_info.wallet() != disqualified_account_wallet)
            .collect();

        let remaining_reverted = convert_collection(remaining);

        AdjustmentIterationResult {
            decided_accounts: vec![],
            remaining_undecided_accounts: remaining_reverted,
        }
    }

    fn filter_and_process_confirmable_accounts(
        unconfirmed_adjustments: Vec<UnconfirmedAdjustment>,
    ) -> (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<UnconfirmedAdjustment>,
    ) {
        let init: (Vec<UnconfirmedAdjustment>, Vec<UnconfirmedAdjustment>) = (vec![], vec![]);
        let fold_guts =
            |(mut above_or_even_to_disq_limit, mut below_disq_limit): (Vec<_>, Vec<_>),
             current: UnconfirmedAdjustment| {
                let disqualification_limit = current.disqualification_limit_minor();
                if current.proposed_adjusted_balance_minor >= disqualification_limit {
                    diagnostics_for_accounts_above_disqualification_limit(
                        &current,
                        disqualification_limit,
                    );
                    let mut adjusted = current;
                    adjusted.proposed_adjusted_balance_minor = disqualification_limit;
                    above_or_even_to_disq_limit.push(adjusted)
                } else {
                    below_disq_limit.push(current)
                }
                (above_or_even_to_disq_limit, below_disq_limit)
            };

        let (accounts_above_or_even_to_disq_limit, accounts_below_disq_limit) =
            unconfirmed_adjustments.into_iter().fold(init, fold_guts);

        let decided_accounts = if accounts_above_or_even_to_disq_limit.is_empty() {
            vec![]
        } else {
            convert_collection(accounts_above_or_even_to_disq_limit)
        };

        (decided_accounts, accounts_below_disq_limit)
    }
}

fn compute_unconfirmed_adjustments(
    weighed_accounts: Vec<WeighedPayable>,
    remaining_cw_service_fee_balance_minor: u128,
) -> Vec<UnconfirmedAdjustment> {
    let weights_total = sum_as(&weighed_accounts, |weighed_account| weighed_account.weight);

    let multiplication_coefficient = compute_mul_coefficient_preventing_fractional_numbers(
        remaining_cw_service_fee_balance_minor,
    );

    let proportional_cw_fragment = compute_proportional_cw_fragment(
        remaining_cw_service_fee_balance_minor,
        weights_total,
        multiplication_coefficient,
    );

    let compute_proposed_adjusted_balance =
        |weight| weight * proportional_cw_fragment / multiplication_coefficient;

    weighed_accounts
        .into_iter()
        .map(|weighed_account| {
            let proposed_adjusted_balance =
                compute_proposed_adjusted_balance(weighed_account.weight);

            proposed_adjusted_balance_diagnostics(&weighed_account, proposed_adjusted_balance);

            UnconfirmedAdjustment::new(weighed_account, proposed_adjusted_balance)
        })
        .collect()
}

fn compute_proportional_cw_fragment(
    cw_service_fee_balance_minor: u128,
    weights_total: u128,
    multiplication_coefficient: u128,
) -> u128 {
    cw_service_fee_balance_minor
        // Considered safe as to the nature of the calculus producing this coefficient
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

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::local_utils::{
        make_meaningless_unconfirmed_adjustment, multiply_by_quintillion,
        multiply_by_quintillion_concise,
    };

    #[test]
    fn filter_and_process_confirmable_accounts_limits_them_by_their_disqualification_edges() {
        let mut account_1 = make_meaningless_unconfirmed_adjustment(111);
        let weight_1 = account_1.weighed_account.weight;
        account_1
            .weighed_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiply_by_quintillion(2);
        account_1
            .weighed_account
            .analyzed_account
            .disqualification_limit_minor = multiply_by_quintillion_concise(1.8);
        account_1.proposed_adjusted_balance_minor = multiply_by_quintillion_concise(3.0);
        let mut account_2 = make_meaningless_unconfirmed_adjustment(222);
        let weight_2 = account_2.weighed_account.weight;
        account_2
            .weighed_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiply_by_quintillion(5);
        account_2
            .weighed_account
            .analyzed_account
            .disqualification_limit_minor = multiply_by_quintillion_concise(4.2) - 1;
        account_2.proposed_adjusted_balance_minor = multiply_by_quintillion_concise(4.2);
        let mut account_3 = make_meaningless_unconfirmed_adjustment(333);
        account_3
            .weighed_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiply_by_quintillion(3);
        account_3
            .weighed_account
            .analyzed_account
            .disqualification_limit_minor = multiply_by_quintillion(2) + 1;
        account_3.proposed_adjusted_balance_minor = multiply_by_quintillion(2);
        let mut account_4 = make_meaningless_unconfirmed_adjustment(444);
        let weight_4 = account_4.weighed_account.weight;
        account_4
            .weighed_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiply_by_quintillion_concise(1.5);
        account_4
            .weighed_account
            .analyzed_account
            .disqualification_limit_minor = multiply_by_quintillion_concise(0.5);
        account_4.proposed_adjusted_balance_minor = multiply_by_quintillion_concise(0.5);
        let mut account_5 = make_meaningless_unconfirmed_adjustment(555);
        account_5
            .weighed_account
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = multiply_by_quintillion(2);
        account_5
            .weighed_account
            .analyzed_account
            .disqualification_limit_minor = multiply_by_quintillion(1) + 1;
        account_5.proposed_adjusted_balance_minor = multiply_by_quintillion(1);
        let unconfirmed_accounts = vec![
            account_1.clone(),
            account_2.clone(),
            account_3.clone(),
            account_4.clone(),
            account_5.clone(),
        ];

        let (thriving_competitors, losing_competitors) =
            ServiceFeeAdjusterReal::filter_and_process_confirmable_accounts(unconfirmed_accounts);

        assert_eq!(losing_competitors, vec![account_3, account_5]);
        let expected_adjusted_outweighed_accounts = vec![
            AdjustedAccountBeforeFinalization::new(
                account_1
                    .weighed_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_1,
                multiply_by_quintillion_concise(1.8),
            ),
            AdjustedAccountBeforeFinalization::new(
                account_2
                    .weighed_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_2,
                multiply_by_quintillion_concise(4.2) - 1,
            ),
            AdjustedAccountBeforeFinalization::new(
                account_4
                    .weighed_account
                    .analyzed_account
                    .qualified_as
                    .bare_account,
                weight_4,
                multiply_by_quintillion_concise(0.5),
            ),
        ];
        assert_eq!(thriving_competitors, expected_adjusted_outweighed_accounts)
    }
}

#[cfg(test)]
pub mod illustrative_util {
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::WeighedPayable;
    use crate::accountant::payment_adjuster::service_fee_adjuster::compute_unconfirmed_adjustments;
    use thousands::Separable;
    use web3::types::Address;

    pub fn illustrate_why_we_need_to_prevent_exceeding_the_original_value(
        cw_service_fee_balance_minor: u128,
        weighed_accounts: Vec<WeighedPayable>,
        wallet_of_expected_outweighed: Address,
        original_balance_of_outweighed_account: u128,
    ) {
        let unconfirmed_adjustments =
            compute_unconfirmed_adjustments(weighed_accounts, cw_service_fee_balance_minor);
        // The results are sorted from the biggest weights down
        assert_eq!(
            unconfirmed_adjustments[1].wallet(),
            wallet_of_expected_outweighed
        );
        // To prevent unjust reallocation, we secured a rule an account could never demand more
        // than 100% of its size.

        // Later it was changed to a different policy, the so-called "outweighed" account is given
        // automatically a balance equal to its disqualification limit. Still, it's quite likely
        // some accounts will acquire slightly more by a distribution of the last bits of funds
        // away out of the consuming wallet.

        // Here, though, the assertion illustrates what the latest policy intends to fight off,
        // as the unprotected proposed adjusted balance rises over the original balance.
        let proposed_adjusted_balance = unconfirmed_adjustments[1].proposed_adjusted_balance_minor;
        assert!(
            proposed_adjusted_balance > (original_balance_of_outweighed_account * 11 / 10),
            "we expected the proposed balance to be unsound, bigger than the original balance \
            (at least 1.1 times more) which would be {} but it was {}",
            original_balance_of_outweighed_account.separate_with_commas(),
            proposed_adjusted_balance.separate_with_commas()
        );
    }
}
