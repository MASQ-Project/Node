// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::{
    exhausting_cw_balance_diagnostics, not_exhausting_cw_balance_diagnostics,
    possibly_outweighed_accounts_diagnostics,
};
use crate::accountant::payment_adjuster::miscellaneous::data_sructures::{
    AdjustedAccountBeforeFinalization, ResolutionAfterFullyDetermined,
};
use crate::accountant::payment_adjuster::{diagnostics, ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE};
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use std::iter::successors;
use thousands::Separable;

const MAX_EXPONENT_FOR_10_IN_U128: u32 = 38;
const EMPIRIC_PRECISION_COEFFICIENT: usize = 8;

pub fn sum_as<N, T, F>(collection: &[T], arranger: F) -> N
where
    N: From<u128>,
    F: Fn(&T) -> u128,
{
    collection.iter().map(arranger).sum::<u128>().into()
}

pub fn criteria_total(accounts_with_individual_criteria: &[(u128, PayableAccount)]) -> u128 {
    sum_as(&accounts_with_individual_criteria, |(criteria, _)| {
        *criteria
    })
}

pub fn cut_back_by_excessive_transaction_fee(
    weights_and_accounts: Vec<(u128, PayableAccount)>,
    limit: u16,
) -> Vec<(u128, PayableAccount)> {
    diagnostics!(
        "ACCOUNTS CUTBACK FOR TRANSACTION FEE",
        "keeping {} out of {} accounts",
        limit,
        weights_and_accounts.len()
    );
    weights_and_accounts
        .into_iter()
        .take(limit as usize)
        .collect()
}

pub fn compute_fraction_preventing_mul_coeff(cw_masq_balance: u128, criteria_sum: u128) -> u128 {
    let criteria_sum_digits_count = log_10(criteria_sum);
    let cw_balance_digits_count = log_10(cw_masq_balance);
    let positive_difference = criteria_sum_digits_count
        .checked_sub(cw_balance_digits_count)
        .unwrap_or(0);
    let safe_mul_coeff = positive_difference + EMPIRIC_PRECISION_COEFFICIENT;
    10_u128
        .checked_pow(safe_mul_coeff as u32)
        .unwrap_or_else(|| 10_u128.pow(MAX_EXPONENT_FOR_10_IN_U128))
}

pub fn possibly_outweighed_accounts_fold_guts(
    (mut outweighed, mut passing_through): (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<AdjustedAccountBeforeFinalization>,
    ),
    account_info: AdjustedAccountBeforeFinalization,
) -> (
    Vec<AdjustedAccountBeforeFinalization>,
    Vec<AdjustedAccountBeforeFinalization>,
) {
    if account_info.proposed_adjusted_balance > account_info.original_account.balance_wei {
        possibly_outweighed_accounts_diagnostics(&account_info);

        let new_account_info = AdjustedAccountBeforeFinalization {
            proposed_adjusted_balance: account_info.original_account.balance_wei,
            ..account_info
        };

        outweighed.push(new_account_info);
        (outweighed, passing_through)
    } else {
        passing_through.push(account_info);
        (outweighed, passing_through)
    }
}

pub fn find_disqualified_account_with_smallest_proposed_balance(
    accounts: &[&AdjustedAccountBeforeFinalization],
) -> Wallet {
    let account_ref = accounts.iter().reduce(|smallest_so_far, current| {
        if current.proposed_adjusted_balance > smallest_so_far.proposed_adjusted_balance {
            smallest_so_far
        } else {
            current
        }
    });
    account_ref
        .expect("the iterator was empty but we had checked it")
        .original_account
        .wallet
        .clone()
}

pub fn exhaust_cw_balance_totally(
    verified_accounts: Vec<AdjustedAccountBeforeFinalization>,
    original_cw_masq_balance: u128,
) -> Vec<PayableAccount> {
    fn fold_guts(
        status: ExhaustionStatus,
        non_finalized_account_info: AdjustedAccountBeforeFinalization,
    ) -> ExhaustionStatus {
        if status.remainder != 0 {
            let balance_gap = non_finalized_account_info
                .original_account
                .balance_wei
                .checked_sub(non_finalized_account_info.proposed_adjusted_balance)
                .unwrap_or_else(|| {
                    panic!(
                        "proposed balance should never bigger than the original but proposed: {} \
                        and original: {}",
                        non_finalized_account_info.proposed_adjusted_balance,
                        non_finalized_account_info.original_account.balance_wei
                    )
                });
            let possible_extra_addition = if balance_gap < status.remainder {
                balance_gap
            } else {
                status.remainder
            };

            exhausting_cw_balance_diagnostics(&non_finalized_account_info, possible_extra_addition);

            status.update_and_add(non_finalized_account_info, possible_extra_addition)
        } else {
            not_exhausting_cw_balance_diagnostics(&non_finalized_account_info);

            status.add(non_finalized_account_info)
        }
    }

    let adjusted_balances_total: u128 = sum_as(&verified_accounts, |account_info| {
        account_info.proposed_adjusted_balance
    });

    let cw_reminder = original_cw_masq_balance
        .checked_sub(adjusted_balances_total)
        .unwrap_or_else(|| {
            panic!(
                "remainder should've been a positive number but was not after {} - {}",
                original_cw_masq_balance, adjusted_balances_total
            )
        });

    let init = ExhaustionStatus::new(cw_reminder);
    verified_accounts
        .into_iter()
        .sorted_by(|info_a, info_b| {
            Ord::cmp(
                &info_a.proposed_adjusted_balance,
                &info_b.proposed_adjusted_balance,
            )
        })
        .fold(init, fold_guts)
        .already_finalized_accounts
        .into_iter()
        .sorted_by(|account_a, account_b| Ord::cmp(&account_b.balance_wei, &account_a.balance_wei))
        .collect()
}

struct ExhaustionStatus {
    remainder: u128,
    already_finalized_accounts: Vec<PayableAccount>,
}

impl ExhaustionStatus {
    fn new(remainder: u128) -> Self {
        Self {
            remainder,
            already_finalized_accounts: vec![],
        }
    }

    fn update_and_add(
        mut self,
        mut non_finalized_account_info: AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) -> Self {
        let corrected_adjusted_account_before_finalization = {
            non_finalized_account_info.proposed_adjusted_balance =
                non_finalized_account_info.proposed_adjusted_balance + possible_extra_addition;
            non_finalized_account_info
        };
        self.remainder = self
            .remainder
            .checked_sub(possible_extra_addition)
            .expect("we hit zero");
        self.add(corrected_adjusted_account_before_finalization)
    }

    fn add(mut self, non_finalized_account_info: AdjustedAccountBeforeFinalization) -> Self {
        let finalized_account = PayableAccount::from((
            non_finalized_account_info,
            ResolutionAfterFullyDetermined::Finalize,
        ));
        self.already_finalized_accounts.push(finalized_account);
        self
    }
}

pub fn sort_in_descendant_order_by_weights(
    unsorted: impl Iterator<Item = (u128, PayableAccount)>,
) -> Vec<(u128, PayableAccount)> {
    unsorted
        .sorted_by(|(weight_a, _), (weight_b, _)| Ord::cmp(weight_b, weight_a))
        .collect()
}

pub fn rebuild_accounts(criteria_and_accounts: Vec<(u128, PayableAccount)>) -> Vec<PayableAccount> {
    criteria_and_accounts
        .into_iter()
        .map(|(_, account)| account)
        .collect()
}

pub fn list_accounts_under_the_disqualification_limit(
    non_finalized_adjusted_accounts: &[AdjustedAccountBeforeFinalization],
) -> Vec<&AdjustedAccountBeforeFinalization> {
    non_finalized_adjusted_accounts
        .iter()
        .flat_map(|account_info| {
            let original_balance = account_info.original_account.balance_wei;
            let balance_at_the_edge = (ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier
                * original_balance)
                / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor;
            let proposed_adjusted_balance = account_info.proposed_adjusted_balance;
            if proposed_adjusted_balance <= balance_at_the_edge {
                diagnostics!(
                    &account_info.original_account.wallet,
                    "ACCOUNT DISQUALIFIED FOR INSIGNIFICANCE AFTER ADJUSTMENT",
                    "Proposed: {}, qualification limit: {}",
                    proposed_adjusted_balance.separate_with_commas(),
                    balance_at_the_edge.separate_with_commas()
                );

                Some(&*account_info)
            } else {
                None
            }
        })
        .collect()
}

// replace with `account_1.balance_wei.checked_ilog10().unwrap() + 1`
// which will be introduced by Rust 1.67.0; this was written with 1.63.0
pub fn log_10(num: u128) -> usize {
    successors(Some(num), |&n| (n >= 10).then(|| n / 10)).count()
}

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub fn log_2(x: u128) -> u32 {
    if x < 1 {
        panic!("log2 of 0 not supported")
    }
    num_bits::<i128>() as u32 - x.leading_zeros() - 1
}

pub fn x_or_1(x: u128) -> u128 {
    if x == 0 {
        1
    } else {
        x
    }
}

impl
    From<(
        AdjustedAccountBeforeFinalization,
        ResolutionAfterFullyDetermined,
    )> for PayableAccount
{
    fn from(
        (account_info, resolution): (
            AdjustedAccountBeforeFinalization,
            ResolutionAfterFullyDetermined,
        ),
    ) -> Self {
        match resolution {
            ResolutionAfterFullyDetermined::Finalize => PayableAccount {
                balance_wei: account_info.proposed_adjusted_balance,
                ..account_info.original_account
            },
            ResolutionAfterFullyDetermined::Revert => account_info.original_account,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_sructures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        compute_fraction_preventing_mul_coeff, exhaust_cw_balance_totally,
        find_disqualified_account_with_smallest_proposed_balance,
        list_accounts_under_the_disqualification_limit, log_10, log_2,
        possibly_outweighed_accounts_fold_guts, ExhaustionStatus, EMPIRIC_PRECISION_COEFFICIENT,
        MAX_EXPONENT_FOR_10_IN_U128,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        make_extreme_accounts, make_initialized_subject, MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
    };
    use crate::accountant::payment_adjuster::ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE;
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use std::time::SystemTime;

    #[test]
    fn constants_are_correct() {
        assert_eq!(MAX_EXPONENT_FOR_10_IN_U128, 38);
        assert_eq!(EMPIRIC_PRECISION_COEFFICIENT, 8)
    }

    #[test]
    fn log_10_works() {
        [
            (4_565_u128, 4),
            (1_666_777, 7),
            (3, 1),
            (123, 3),
            (111_111_111_111_111_111, 18),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| assert_eq!(log_10(num), expected_result))
    }

    #[test]
    fn log_2_works() {
        [
            (1, 0),
            (2, 1),
            (4, 2),
            (8192, 13),
            (18446744073709551616, 64),
            (1267650600228229401496703205376, 100),
            (170141183460469231731687303715884105728, 127),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| assert_eq!(log_2(num), expected_result))
    }

    #[test]
    #[should_panic(expected = "log2 of 0 not supported")]
    fn log_2_dislikes_0() {
        let _ = log_2(0);
    }

    #[test]
    fn multiplication_coeff_for_integers_to_be_above_one_instead_of_fractional_numbers() {
        let final_criteria_sum = 5_000_000_000_000_u128;
        let consuming_wallet_balances = vec![
            222_222_222_222_u128,
            100_000,
            123_456_789,
            5_555_000_000_000,
            5_000_555_000_000_000,
            1_000_000_000_000_000_000, //1 MASQ
        ];

        let result = consuming_wallet_balances
            .clone()
            .into_iter()
            .map(|cw_balance| compute_fraction_preventing_mul_coeff(cw_balance, final_criteria_sum))
            .collect::<Vec<u128>>();

        assert_eq!(
            result,
            vec![
                1_000_000_000,
                1_000_000_000_000_000,
                1_000_000_000_000,
                100_000_000,
                100_000_000,
                100_000_000
            ]
        )
    }

    #[test]
    fn multiplication_coeff_showing_extreme_feeding_and_safety_ceiling() {
        // the coeff is multiples of 10 we need to multiply the cw balance with
        // in order to get at a number bigger than the total criteria sum (and the more extra 10s we add, the more
        // accurate numbers we can expect at the results of the entire payment adjuster machinery)
        //
        // we cannot say by heart which of the criteria sums of these parameters evaluates to is for sure bigger than another,
        // therefore we could hardly put them into an order
        let accounts_as_months_and_balances = vec![
            (1, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR),
            (5, 10_u128.pow(18)),
            (12, 10_u128.pow(18)),
            (120, 10_u128.pow(20)),
            (600, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR),
            (1200, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR),
            (1200, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR * 1000),
        ];
        let (different_accounts_with_criteria, initial_accounts_order_from_the_seeds) =
            get_extreme_criteria_and_initial_accounts_order(accounts_as_months_and_balances);
        let cw_balance_in_minor = 1;

        let results = different_accounts_with_criteria
            .into_iter()
            .map(|(criteria_sum, account)| {
                // scenario simplification: we asume there is always just one account in a time
                let final_criteria_total = criteria_sum;
                let resulted_coeff = compute_fraction_preventing_mul_coeff(
                    cw_balance_in_minor,
                    final_criteria_total,
                );
                (resulted_coeff, account.wallet, criteria_sum)
            })
            .collect::<Vec<(u128, Wallet, u128)>>();

        eprintln!("results {:?}", results);
        let initial_accounts_order_from_the_seeds_iter =
            initial_accounts_order_from_the_seeds.iter().enumerate();
        let coeffs_and_criteria_sums_matching_the_order_of_the_original_inputs = results
            .into_iter()
            .map(|(coeff, wallet, criteria_sum)| {
                let (idx, _) = initial_accounts_order_from_the_seeds_iter
                    .clone()
                    .find(|(_, wallet_ordered)| wallet_ordered == &&wallet)
                    .unwrap();
                (idx, coeff, criteria_sum)
            })
            .sorted_by(|(a_idx, _, _), (b_idx, _, _)| Ord::cmp(&b_idx, &a_idx))
            .map(|(_, coeff, criteria_sum)| (coeff, criteria_sum))
            .collect::<Vec<(u128, u128)>>();
        //to preserve easy visual checks
        #[rustfmt::skip]
        fn expected_result() -> Vec<(u128, u128)> {
            vec![
                (
                    100000000000000000000000000000000000000,
                    3337514568138519074931415968855
                ),
                (
                    100000000000000000000000000000000000,
                    2977068138519074931415968855
                ),
                (
                    100000000000000000000000000000000000,
                    2968604285622712478129675136
                ),
                (
                    10000000000000000000000000000000,
                    879662486510538526960128
                ),
                (
                    1000000000000000000000000000000,
                    43211890301705270704000
                ),
                (
                    1000000000000000000000000000000,
                    13327534955520000000000
                ),
                (
                    100000000000000000000000000000000000,
                    2962501520859680498325341824
                )
            ]
        }
        assert_eq!(
            coeffs_and_criteria_sums_matching_the_order_of_the_original_inputs,
            expected_result()
        )
    }

    #[test]
    fn find_disqualified_account_with_smallest_proposed_balance_when_accounts_with_equal_balances()
    {
        let account_info = AdjustedAccountBeforeFinalization {
            original_account: make_payable_account(111),
            proposed_adjusted_balance: 1_234_567_890,
            criteria_sum: 400_000_000,
        };
        let wallet_1 = make_wallet("abc");
        let wallet_2 = make_wallet("def");
        let mut account_info_1 = account_info.clone();
        account_info_1.original_account.wallet = wallet_1;
        let mut account_info_2 = account_info;
        account_info_2.original_account.wallet = wallet_2.clone();
        let accounts = vec![&account_info_1, &account_info_2];

        let result = find_disqualified_account_with_smallest_proposed_balance(&accounts);

        assert_eq!(result, wallet_2)
    }

    #[test]
    fn algorithm_is_left_cold_by_accounts_with_original_balance_equal_to_proposed_one() {
        let account_info = AdjustedAccountBeforeFinalization {
            original_account: PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: 9_000_000_000,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
            proposed_adjusted_balance: 9_000_000_000,
            criteria_sum: 123456789,
        };

        let (outweighed, ok) =
            possibly_outweighed_accounts_fold_guts((vec![], vec![]), account_info.clone());

        assert_eq!(outweighed, vec![]);
        assert_eq!(ok, vec![account_info])
    }

    fn make_non_finalized_adjusted_account(
        wallet: &Wallet,
        original_balance: u128,
        proposed_adjusted_balance: u128,
    ) -> AdjustedAccountBeforeFinalization {
        AdjustedAccountBeforeFinalization {
            original_account: PayableAccount {
                wallet: wallet.clone(),
                balance_wei: original_balance,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            },
            proposed_adjusted_balance,
            criteria_sum: 123456,
        }
    }

    fn assert_correct_payable_accounts_after_finalization(
        actual_accounts: Vec<PayableAccount>,
        expected_parameters: Vec<(Wallet, u128)>,
    ) {
        let actual_accounts_simplified_and_sorted = actual_accounts
            .into_iter()
            .map(|account| (account.wallet.address(), account.balance_wei))
            .sorted()
            .collect::<Vec<_>>();
        let expected_parameters_sorted = expected_parameters
            .into_iter()
            .map(|(wallet, expected_balance)| (wallet.address(), expected_balance))
            .sorted()
            .collect::<Vec<_>>();
        assert_eq!(
            actual_accounts_simplified_and_sorted,
            expected_parameters_sorted
        )
    }

    #[test]
    fn exhaustive_status_is_constructed_properly() {
        let cw_balance_remainder = 45678;

        let result = ExhaustionStatus::new(cw_balance_remainder);

        assert_eq!(result.remainder, cw_balance_remainder);
        assert_eq!(result.already_finalized_accounts, vec![])
    }

    #[test]
    fn exhaust_cw_balance_totally_for_three_non_exhaustive_accounts_all_filled() {
        // this can happen because some of the pre-qualified accounts could be
        // eliminated for an insignificant pay and free the means for the other
        // accounts and then we went through adjustment computation with some
        // losses on precision, here we're gonna add in what was missing
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 45_000_000_000;
        let proposed_adjusted_balance_1 = 44_999_897_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 33_487_999_999;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 41_000_000;
        let proposed_adjusted_balance_3 = 40_980_000;
        let unallocated_cw_balance = original_requested_balance_1
            + original_requested_balance_2
            + original_requested_balance_3
            + 5000;
        let non_finalized_adjusted_accounts = vec![
            make_non_finalized_adjusted_account(
                &wallet_1,
                original_requested_balance_1,
                proposed_adjusted_balance_1,
            ),
            make_non_finalized_adjusted_account(
                &wallet_2,
                original_requested_balance_2,
                proposed_adjusted_balance_2,
            ),
            make_non_finalized_adjusted_account(
                &wallet_3,
                original_requested_balance_3,
                proposed_adjusted_balance_3,
            ),
        ];

        let result =
            exhaust_cw_balance_totally(non_finalized_adjusted_accounts, unallocated_cw_balance);

        let expected_resulted_balances = vec![
            (wallet_1, original_requested_balance_1),
            (wallet_2, original_requested_balance_2),
            (wallet_3, original_requested_balance_3),
        ];
        assert_correct_payable_accounts_after_finalization(result, expected_resulted_balances)
    }

    #[test]
    fn exhaust_cw_balance_totally_three_non_exhaustive_accounts_with_some_completely_filled_some_not(
    ) {
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 54_000_000_000;
        let proposed_adjusted_balance_1 = 53_898_000_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 33_487_999_999;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 41_000_000;
        let proposed_adjusted_balance_3 = 40_980_000;
        let unallocated_cw_balance = original_requested_balance_2
            + original_requested_balance_3
            + proposed_adjusted_balance_1
            - 2_000_000;
        let non_finalized_adjusted_accounts = vec![
            make_non_finalized_adjusted_account(
                &wallet_1,
                original_requested_balance_1,
                proposed_adjusted_balance_1,
            ),
            make_non_finalized_adjusted_account(
                &wallet_2,
                original_requested_balance_2,
                proposed_adjusted_balance_2,
            ),
            make_non_finalized_adjusted_account(
                &wallet_3,
                original_requested_balance_3,
                proposed_adjusted_balance_3,
            ),
        ];

        let result =
            exhaust_cw_balance_totally(non_finalized_adjusted_accounts, unallocated_cw_balance);
        eprintln!("{:?}", result);

        let expected_resulted_balances = vec![
            (wallet_1, proposed_adjusted_balance_1),
            (wallet_2, 33_498_000_000),
            (wallet_3, original_requested_balance_3),
        ];
        let check_sum: u128 = expected_resulted_balances
            .iter()
            .map(|(_, balance)| balance)
            .sum();
        let is_equal = check_sum == unallocated_cw_balance;
        assert_correct_payable_accounts_after_finalization(result, expected_resulted_balances);
        assert!(is_equal)
    }

    #[test]
    fn exhaust_cw_balance_totally_three_non_exhaustive_accounts_with_two_of_them_completely_filled()
    {
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 54_000_000_000;
        let proposed_adjusted_balance_1 = 53_898_000_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 33_487_999_999;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 41_000_000;
        let proposed_adjusted_balance_3 = 40_980_000;
        let unallocated_cw_balance = original_requested_balance_2
            + original_requested_balance_3
            + proposed_adjusted_balance_1
            + 2_000_000;
        let non_finalized_adjusted_accounts = vec![
            make_non_finalized_adjusted_account(
                &wallet_1,
                original_requested_balance_1,
                proposed_adjusted_balance_1,
            ),
            make_non_finalized_adjusted_account(
                &wallet_2,
                original_requested_balance_2,
                proposed_adjusted_balance_2,
            ),
            make_non_finalized_adjusted_account(
                &wallet_3,
                original_requested_balance_3,
                proposed_adjusted_balance_3,
            ),
        ];

        let result =
            exhaust_cw_balance_totally(non_finalized_adjusted_accounts, unallocated_cw_balance);

        let expected_resulted_balances = vec![
            (wallet_1, 53_900_000_000),
            (wallet_2, original_requested_balance_2),
            (wallet_3, original_requested_balance_3),
        ];
        assert_correct_payable_accounts_after_finalization(result, expected_resulted_balances)
    }

    #[test]
    fn list_accounts_under_the_disqualification_limit_employs_manifest_consts_of_insignificance() {
        let account_balance = 1_000_000;
        let prepare_account = |n: u64| {
            let mut account = make_payable_account(n);
            account.balance_wei = account_balance;
            account
        };
        let payable_account_1 = prepare_account(1);
        let payable_account_2 = prepare_account(2);
        let payable_account_3 = prepare_account(3);
        const IRRELEVANT_CRITERIA_SUM: u128 = 1111;
        let edge = account_balance / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
            * ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier;
        let proposed_ok_balance = edge + 1;
        let account_info_1 = AdjustedAccountBeforeFinalization::new(
            payable_account_1,
            proposed_ok_balance,
            IRRELEVANT_CRITERIA_SUM,
        );
        let proposed_bad_balance_because_equal = edge;
        let account_info_2 = AdjustedAccountBeforeFinalization::new(
            payable_account_2,
            proposed_bad_balance_because_equal,
            IRRELEVANT_CRITERIA_SUM,
        );
        let proposed_bad_balance_because_smaller = edge - 1;
        let account_info_3 = AdjustedAccountBeforeFinalization::new(
            payable_account_3,
            proposed_bad_balance_because_smaller,
            IRRELEVANT_CRITERIA_SUM,
        );
        let accounts_with_unchecked_adjustment = vec![
            account_info_1,
            account_info_2.clone(),
            account_info_3.clone(),
        ];

        let result =
            list_accounts_under_the_disqualification_limit(&accounts_with_unchecked_adjustment);

        let expected_disqualified_accounts = vec![&account_info_2, &account_info_3];
        assert_eq!(result, expected_disqualified_accounts)
    }

    fn get_extreme_criteria_and_initial_accounts_order(
        months_of_debt_and_balances_matrix: Vec<(usize, u128)>,
    ) -> (Vec<(u128, PayableAccount)>, Vec<Wallet>) {
        let now = SystemTime::now();
        let accounts =
            make_extreme_accounts(Either::Right(months_of_debt_and_balances_matrix), now);
        let wallets_in_order = accounts
            .iter()
            .map(|account| account.wallet.clone())
            .collect();
        let subject = make_initialized_subject(now, None, None);
        // when criteria are applied the collection will get sorted and will not necessarily have to match the initial order
        let criteria_and_accounts = subject.calculate_criteria_sums_for_accounts(accounts);
        eprintln!("wallets in order {:?}", wallets_in_order);
        (criteria_and_accounts, wallets_in_order)
    }
}
