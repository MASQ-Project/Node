// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::{
    proposed_adjusted_balance_diagnostics,
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
        let non_finalized_adjusted_accounts = self.generate_adjustments(
            weighted_accounts,
            disqualification_arbiter,
            cw_service_fee_balance_minor,
        );

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
    pub fn assign_accounts_their_minimal_acceptable_balance<InputAccount, OutputAccounts>(
        accounts: Vec<InputAccount>,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> Vec<OutputAccounts>
    where
        WeightedPayable: From<InputAccount>,
        OutputAccounts: From<UnconfirmedAdjustment>,
    {
        // In some cases taking advantage of that Rust std library implements also From<T> for T
        let weighted_accounts: Vec<WeightedPayable> = convert_collection(accounts);

        let unconfirmed_accounts = weighted_accounts
            .into_iter()
            .map(|weighted_account| {
                let disqualification_limit = disqualification_arbiter
                    .calculate_disqualification_edge(&weighted_account.qualified_account);
                UnconfirmedAdjustment::new(weighted_account, disqualification_limit)
            })
            .collect();

        convert_collection(unconfirmed_accounts)
    }

    fn new() -> Self {
        Self {
            adjustment_computer: Default::default(),
        }
    }

    fn generate_adjustments(
        &self,
        weighted_accounts: Vec<WeightedPayable>,
        disqualification_arbiter: &DisqualificationArbiter,
        cw_service_fee_balance_minor: u128,
    ) -> Vec<UnconfirmedAdjustment> {
        if weighted_accounts.len() == 1 {
            let last_account = {
                let mut weighted_accounts = weighted_accounts;
                weighted_accounts.remove(0)
            };
            vec![Self::handle_last_account(
                last_account,
                disqualification_arbiter,
                cw_service_fee_balance_minor,
            )]
        } else {
            self.adjustment_computer
                .compute_unconfirmed_adjustments(weighted_accounts, cw_service_fee_balance_minor)
        }
    }

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

        let outweighed_adjusted = Self::assign_accounts_their_minimal_acceptable_balance(
            outweighed,
            disqualification_arbiter,
        );

        (outweighed_adjusted, properly_adjusted_accounts)
    }

    fn handle_last_account(
        account: WeightedPayable,
        disqualification_arbiter: &DisqualificationArbiter,
        cw_service_fee_balance_minor: u128,
    ) -> UnconfirmedAdjustment {
        let disqualification_limit =
            disqualification_arbiter.calculate_disqualification_edge(&account.qualified_account);
        if disqualification_limit >= cw_service_fee_balance_minor {
            UnconfirmedAdjustment::new(account, cw_service_fee_balance_minor)
        } else {
            UnconfirmedAdjustment::new(account, disqualification_limit)
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
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
    use crate::accountant::payment_adjuster::test_utils::{
        make_non_guaranteed_unconfirmed_adjustment, multiple_by_billion, DisqualificationGaugeMock,
    };
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;

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

    #[test]
    fn assign_accounts_their_minimal_acceptable_balance_works_for_unconfirmed_accounts() {
        let unconfirmed_account_1 = make_non_guaranteed_unconfirmed_adjustment(111);
        let weighted_account_1 = unconfirmed_account_1.weighted_account.clone();
        let unconfirmed_account_2 = make_non_guaranteed_unconfirmed_adjustment(222);
        let weighted_account_2 = unconfirmed_account_2.weighted_account.clone();
        let accounts = vec![unconfirmed_account_1, unconfirmed_account_2];
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(123456789)
            .determine_limit_result(987654321);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));

        let result: Vec<UnconfirmedAdjustment> =
            ServiceFeeAdjusterReal::assign_accounts_their_minimal_acceptable_balance(
                accounts,
                &disqualification_arbiter,
            );

        let expected_result = vec![
            UnconfirmedAdjustment::new(weighted_account_1, 123456789),
            UnconfirmedAdjustment::new(weighted_account_2, 987654321),
        ];
        assert_eq!(result, expected_result)
    }

    #[test]
    fn assign_accounts_their_minimal_acceptable_balance_works_for_non_finalized_accounts() {
        let unconfirmed_account_1 = make_non_guaranteed_unconfirmed_adjustment(111);
        let payable_account_1 = unconfirmed_account_1
            .weighted_account
            .qualified_account
            .bare_account
            .clone();
        let unconfirmed_account_2 = make_non_guaranteed_unconfirmed_adjustment(222);
        let payable_account_2 = unconfirmed_account_2
            .weighted_account
            .qualified_account
            .bare_account
            .clone();
        let accounts = vec![unconfirmed_account_1, unconfirmed_account_2];
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(1111111)
            .determine_limit_result(2222222);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));

        let result: Vec<AdjustedAccountBeforeFinalization> =
            ServiceFeeAdjusterReal::assign_accounts_their_minimal_acceptable_balance(
                accounts,
                &disqualification_arbiter,
            );

        let expected_result = vec![
            AdjustedAccountBeforeFinalization::new(payable_account_1, 1111111),
            AdjustedAccountBeforeFinalization::new(payable_account_2, 2222222),
        ];
        assert_eq!(result, expected_result)
    }

    #[test]
    fn handle_last_account_works_for_remaining_cw_balance_compared_to_the_disqualification_limit() {
        let cw_service_fee_balance_minor = 123_000;
        let expected_proposed_balances = vec![
            cw_service_fee_balance_minor - 1,
            cw_service_fee_balance_minor,
            cw_service_fee_balance_minor,
        ];
        let qualified_account = make_non_guaranteed_qualified_payable(456);
        let weighted_account = WeightedPayable::new(qualified_account, 1111111);
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(cw_service_fee_balance_minor - 1)
            .determine_limit_result(cw_service_fee_balance_minor)
            .determine_limit_result(cw_service_fee_balance_minor + 1);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = ServiceFeeAdjusterReal::default();
        expected_proposed_balances
            .iter()
            .for_each(|expected_proposed_balance| {
                let result = subject.generate_adjustments(
                    vec![weighted_account.clone()],
                    &disqualification_arbiter,
                    cw_service_fee_balance_minor,
                );

                assert_eq!(
                    result,
                    vec![UnconfirmedAdjustment::new(
                        weighted_account.clone(),
                        *expected_proposed_balance
                    )]
                )
            });
    }
}
