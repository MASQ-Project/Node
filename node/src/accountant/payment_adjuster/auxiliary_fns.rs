// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::{
    AccountWithUncheckedAdjustment, ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE,
};
use crate::diagnostics;
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use std::iter::successors;

const MAX_EXPONENT_FOR_10_IN_U128: u32 = 38;
const EMPIRIC_PRECISION_COEFFICIENT: usize = 8;

pub fn sum_as<N, T, F>(collection: &[T], arranger: F) -> N
where
    N: From<u128>,
    F: Fn(&T) -> u128,
{
    collection.iter().map(arranger).sum::<u128>().into()
}

pub fn balance_total(accounts_with_individual_criteria: &[(u128, PayableAccount)]) -> u128 {
    sum_as(&accounts_with_individual_criteria, |(_, account)| {
        account.balance_wei
    })
}

pub fn criteria_total(accounts_with_individual_criteria: &[(u128, PayableAccount)]) -> u128 {
    sum_as(&accounts_with_individual_criteria, |(criteria, _)| {
        *criteria
    })
}

pub fn cut_back_by_gas_count_limit(
    weights_and_accounts: Vec<(u128, PayableAccount)>,
    limit: u16,
) -> Vec<(u128, PayableAccount)> {
    weights_and_accounts
        .into_iter()
        .take(limit as usize)
        .collect()
}

pub fn compute_fractions_preventing_mul_coeff(cw_masq_balance: u128, criteria_sum: u128) -> u128 {
    let criteria_sum_digits_count = log_10(criteria_sum);
    let cw_balance_digits_count = log_10(cw_masq_balance);
    let positive_difference = criteria_sum_digits_count
        .checked_sub(cw_balance_digits_count)
        .unwrap_or(0);
    let safe_mul_coeff = positive_difference + EMPIRIC_PRECISION_COEFFICIENT;
    eprintln!(
        "criteria sum {}, safe mul coeff {}",
        criteria_sum, safe_mul_coeff
    );
    10_u128
        .checked_pow(safe_mul_coeff as u32)
        .unwrap_or_else(|| 10_u128.pow(MAX_EXPONENT_FOR_10_IN_U128))
}

pub fn find_disqualified_account_with_smallest_proposed_balance(
    accounts: &[&AccountWithUncheckedAdjustment],
) -> Wallet {
    let account_ref = accounts.iter().reduce(|previous, current| {
        if current.proposed_adjusted_balance <= previous.proposed_adjusted_balance {
            current
        } else {
            previous
        }
    });
    account_ref
        .expect("the iterator was empty but we had checked it")
        .original_account
        .wallet
        .clone()
}

pub fn drop_criteria_and_leave_accounts(
    accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
) -> Vec<PayableAccount> {
    accounts_with_individual_criteria
        .into_iter()
        .map(|(_, account)| account)
        .collect()
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

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::auxiliary_fns::{
        compute_fractions_preventing_mul_coeff,
        find_disqualified_account_with_smallest_proposed_balance, log_10, log_2,
        EMPIRIC_PRECISION_COEFFICIENT, MAX_EXPONENT_FOR_10_IN_U128,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        get_extreme_accounts, make_initialized_subject, MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
    };
    use crate::accountant::payment_adjuster::{
        AccountWithUncheckedAdjustment, PaymentAdjusterReal,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use std::time::{Duration, SystemTime};

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
            .map(|cw_balance| {
                compute_fractions_preventing_mul_coeff(cw_balance, final_criteria_sum)
            })
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
        // the coeff is how many multiples of 10 we need to use to multiply the cw balance
        // in order to get at a number bigger than the criteria sum (and the bigger the more
        // accurate numbers calculated afterwards, so we add some for better precision)
        //
        // we cannot say by heart what the criteria sum of a debt of these parameters evaluates to,
        // so we also can hardly put them in an order
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
                let resulted_coeff = compute_fractions_preventing_mul_coeff(
                    cw_balance_in_minor,
                    final_criteria_total,
                );
                (resulted_coeff, account.wallet, criteria_sum)
            })
            .collect::<Vec<(u128, Wallet, u128)>>();

        eprintln!("results {:?}", results);
        let mut initial_accounts_order_from_the_seeds_iter =
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
        };
        assert_eq!(
            coeffs_and_criteria_sums_matching_the_order_of_the_original_inputs,
            expected_result()
        )
    }

    #[test]
    fn find_disqualified_account_with_smallest_proposed_balance_when_accounts_with_equal_balances()
    {
        let account_info = AccountWithUncheckedAdjustment {
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

    fn get_extreme_criteria_and_initial_accounts_order(
        months_of_debt_and_balances_matrix: Vec<(usize, u128)>,
    ) -> (Vec<(u128, PayableAccount)>, Vec<Wallet>) {
        let now = SystemTime::now();
        let accounts = get_extreme_accounts(Either::Right(months_of_debt_and_balances_matrix), now);
        let wallets_in_order = accounts
            .iter()
            .map(|account| account.wallet.clone())
            .collect();
        let subject = make_initialized_subject(now, None, None);
        // when criteria are applied the collection will get sorted and will not necessarily have to match the initial order
        let criteria_and_accounts = subject.add_criteria_sums_to_accounts(accounts);
        eprintln!("wallets in order {:?}", wallets_in_order);
        (criteria_and_accounts, wallets_in_order)
    }
}
