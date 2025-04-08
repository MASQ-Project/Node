// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::iter::Sum;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::{
    exhausting_cw_balance_diagnostics, not_exhausting_cw_balance_diagnostics,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AdjustedAccountBeforeFinalization, WeighedPayable};
use crate::accountant::{AnalyzedPayableAccount};
use itertools::{Either, Itertools};

pub fn no_affordable_accounts_found(
    accounts: &Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
) -> bool {
    match accounts {
        Either::Left(vector) => vector.is_empty(),
        Either::Right(vector) => vector.is_empty(),
    }
}

pub fn sum_as<N, T, F>(collection: &[T], arranger: F) -> N
where
    N: Sum<N>,
    F: Fn(&T) -> N,
{
    collection.iter().map(arranger).sum::<N>()
}

pub fn eliminate_accounts_by_tx_fee_limit(
    weighed_accounts: Vec<WeighedPayable>,
    affordable_transaction_count: u16,
) -> Vec<WeighedPayable> {
    let sorted_accounts = sort_in_descending_order_by_weights(weighed_accounts);

    diagnostics!(
        "ACCOUNTS CUTBACK FOR TRANSACTION FEE",
        "Keeping {} out of {} accounts. Dumping these accounts: {:?}",
        affordable_transaction_count,
        sorted_accounts.len(),
        sorted_accounts
            .iter()
            .skip(affordable_transaction_count as usize)
    );

    sorted_accounts
        .into_iter()
        .take(affordable_transaction_count as usize)
        .collect()
}

fn sort_in_descending_order_by_weights(unsorted: Vec<WeighedPayable>) -> Vec<WeighedPayable> {
    unsorted
        .into_iter()
        .sorted_by(|account_a, account_b| Ord::cmp(&account_b.weight, &account_a.weight))
        .collect()
}

pub fn compute_mul_coefficient_preventing_fractional_numbers(
    cw_service_fee_balance_minor: u128,
) -> u128 {
    u128::MAX / cw_service_fee_balance_minor
}

pub fn find_largest_exceeding_balance(qualified_accounts: &[AnalyzedPayableAccount]) -> u128 {
    let diffs = qualified_accounts
        .iter()
        .map(|account| {
            account
                .qualified_as
                .bare_account
                .balance_wei
                .checked_sub(account.qualified_as.payment_threshold_intercept_minor)
                .expect("should be: balance > intercept!")
        })
        .collect::<Vec<u128>>();
    *diffs.iter().max().expect("No account found")
}

pub fn exhaust_cw_balance_entirely(
    approved_accounts: Vec<AdjustedAccountBeforeFinalization>,
    original_cw_service_fee_balance_minor: u128,
) -> Vec<PayableAccount> {
    let adjusted_balances_total: u128 = sum_as(&approved_accounts, |account_info| {
        account_info.proposed_adjusted_balance_minor
    });

    let cw_remaining = original_cw_service_fee_balance_minor
        .checked_sub(adjusted_balances_total)
        .unwrap_or_else(|| {
            panic!(
                "Remainder should've been a positive number but wasn't after {} - {}",
                original_cw_service_fee_balance_minor, adjusted_balances_total
            )
        });

    let init = ConsumingWalletExhaustingStatus::new(cw_remaining);
    approved_accounts
        .into_iter()
        .sorted_by(|info_a, info_b| Ord::cmp(&info_b.weight, &info_a.weight))
        .fold(
            init,
            run_cw_exhausting_on_possibly_sub_optimal_adjusted_balances,
        )
        .accounts_finalized_so_far
}

fn run_cw_exhausting_on_possibly_sub_optimal_adjusted_balances(
    status: ConsumingWalletExhaustingStatus,
    non_finalized_account: AdjustedAccountBeforeFinalization,
) -> ConsumingWalletExhaustingStatus {
    if !status.is_cw_exhausted_to_0() {
        let balance_gap_minor = non_finalized_account
            .original_account
            .balance_wei
            .checked_sub(non_finalized_account.proposed_adjusted_balance_minor)
            .unwrap_or_else(|| {
                panic!(
                    "Proposed balance should never be bigger than the original one. Proposed: \
                        {}, original: {}",
                    non_finalized_account.proposed_adjusted_balance_minor,
                    non_finalized_account.original_account.balance_wei
                )
            });
        let possible_extra_addition = if balance_gap_minor < status.remaining_cw_balance {
            balance_gap_minor
        } else {
            status.remaining_cw_balance
        };

        exhausting_cw_balance_diagnostics(&non_finalized_account, possible_extra_addition);

        let updated_non_finalized_account = ConsumingWalletExhaustingStatus::update_account_balance(
            non_finalized_account,
            possible_extra_addition,
        );
        let updated_status = status.reduce_cw_balance_remaining(possible_extra_addition);
        updated_status.add(updated_non_finalized_account)
    } else {
        not_exhausting_cw_balance_diagnostics(&non_finalized_account);

        status.add(non_finalized_account)
    }
}

struct ConsumingWalletExhaustingStatus {
    remaining_cw_balance: u128,
    accounts_finalized_so_far: Vec<PayableAccount>,
}

impl ConsumingWalletExhaustingStatus {
    fn new(remaining_cw_balance: u128) -> Self {
        Self {
            remaining_cw_balance,
            accounts_finalized_so_far: vec![],
        }
    }

    fn is_cw_exhausted_to_0(&self) -> bool {
        self.remaining_cw_balance == 0
    }

    fn reduce_cw_balance_remaining(mut self, subtrahend: u128) -> Self {
        self.remaining_cw_balance = self
            .remaining_cw_balance
            .checked_sub(subtrahend)
            .expect("we hit zero");
        self
    }

    fn update_account_balance(
        mut non_finalized_account: AdjustedAccountBeforeFinalization,
        addition: u128,
    ) -> AdjustedAccountBeforeFinalization {
        non_finalized_account.proposed_adjusted_balance_minor += addition;
        non_finalized_account
    }

    fn add(mut self, non_finalized_account_info: AdjustedAccountBeforeFinalization) -> Self {
        let finalized_account = PayableAccount::from(non_finalized_account_info);
        self.accounts_finalized_so_far.push(finalized_account);
        self
    }
}
#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        compute_mul_coefficient_preventing_fractional_numbers, eliminate_accounts_by_tx_fee_limit,
        exhaust_cw_balance_entirely, find_largest_exceeding_balance, no_affordable_accounts_found,
        ConsumingWalletExhaustingStatus,
    };
    use crate::accountant::payment_adjuster::test_utils::local_utils::make_meaningless_weighed_account;
    use crate::accountant::test_utils::{make_meaningless_analyzed_account, make_payable_account};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use std::time::SystemTime;

    #[test]
    fn no_affordable_accounts_found_returns_true_for_non_finalized_accounts() {
        let result = no_affordable_accounts_found(&Either::Left(vec![]));

        assert_eq!(result, true)
    }

    #[test]
    fn no_affordable_accounts_found_returns_false_for_non_finalized_accounts() {
        let result = no_affordable_accounts_found(&Either::Left(vec![
            AdjustedAccountBeforeFinalization::new(make_payable_account(456), 5678, 1234),
        ]));

        assert_eq!(result, false)
    }

    #[test]
    fn no_affordable_accounts_found_returns_true_for_finalized_accounts() {
        let result = no_affordable_accounts_found(&Either::Right(vec![]));

        assert_eq!(result, true)
    }

    #[test]
    fn no_affordable_accounts_found_returns_false_for_finalized_accounts() {
        let result = no_affordable_accounts_found(&Either::Right(vec![make_payable_account(123)]));

        assert_eq!(result, false)
    }

    #[test]
    fn find_largest_exceeding_balance_works() {
        let mut account_1 = make_meaningless_analyzed_account(111);
        account_1.qualified_as.bare_account.balance_wei = 5_000_000_000;
        account_1.qualified_as.payment_threshold_intercept_minor = 2_000_000_001;
        let mut account_2 = make_meaningless_analyzed_account(222);
        account_2.qualified_as.bare_account.balance_wei = 5_000_000_000;
        account_2.qualified_as.payment_threshold_intercept_minor = 2_000_000_001;
        let mut account_3 = make_meaningless_analyzed_account(333);
        account_3.qualified_as.bare_account.balance_wei = 5_000_000_000;
        account_3.qualified_as.payment_threshold_intercept_minor = 1_999_999_999;
        let mut account_4 = make_meaningless_analyzed_account(444);
        account_4.qualified_as.bare_account.balance_wei = 5_000_000_000;
        account_4.qualified_as.payment_threshold_intercept_minor = 2_000_000_000;
        let qualified_accounts = &[account_1, account_2, account_3, account_4];

        let result = find_largest_exceeding_balance(qualified_accounts);

        assert_eq!(result, 5_000_000_000 - 1_999_999_999)
    }

    #[test]
    fn eliminate_accounts_by_tx_fee_limit_works() {
        let mut account_1 = make_meaningless_weighed_account(123);
        account_1.weight = 1_000_000_000;
        let mut account_2 = make_meaningless_weighed_account(456);
        account_2.weight = 999_999_999;
        let mut account_3 = make_meaningless_weighed_account(789);
        account_3.weight = 999_999_999;
        let mut account_4 = make_meaningless_weighed_account(1011);
        account_4.weight = 1_000_000_001;
        let affordable_transaction_count = 2;

        let result = eliminate_accounts_by_tx_fee_limit(
            vec![account_1.clone(), account_2, account_3, account_4.clone()],
            affordable_transaction_count,
        );

        let expected_result = vec![account_4, account_1];
        assert_eq!(result, expected_result)
    }

    #[test]
    fn compute_mul_coefficient_preventing_fractional_numbers_works() {
        let cw_service_fee_balance_minor = 12345678;

        let result =
            compute_mul_coefficient_preventing_fractional_numbers(cw_service_fee_balance_minor);

        let expected_result_conceptually = u128::MAX / cw_service_fee_balance_minor;
        let expected_result_exact = 27562873980751681962171264100016;
        assert_eq!(result, expected_result_exact);
        assert_eq!(expected_result_exact, expected_result_conceptually)
    }

    fn make_non_finalized_adjusted_account(
        wallet: &Wallet,
        original_balance: u128,
        weight: u128,
        proposed_adjusted_balance: u128,
    ) -> AdjustedAccountBeforeFinalization {
        let garbage_last_paid_timestamp = SystemTime::now();
        let payable_account = PayableAccount {
            wallet: wallet.clone(),
            balance_wei: original_balance,
            last_paid_timestamp: garbage_last_paid_timestamp,
            pending_payable_opt: None,
        };
        AdjustedAccountBeforeFinalization::new(payable_account, weight, proposed_adjusted_balance)
    }

    fn assert_payable_accounts_after_adjustment_finalization(
        actual_accounts: Vec<PayableAccount>,
        expected_account_parts: Vec<(Wallet, u128)>,
    ) {
        let actual_accounts_simplified_and_sorted = actual_accounts
            .into_iter()
            .map(|account| (account.wallet.address(), account.balance_wei))
            .sorted()
            .collect::<Vec<_>>();
        let expected_account_parts_sorted = expected_account_parts
            .into_iter()
            .map(|(expected_wallet, expected_balance)| {
                (expected_wallet.address(), expected_balance)
            })
            .sorted()
            .collect::<Vec<_>>();
        assert_eq!(
            actual_accounts_simplified_and_sorted,
            expected_account_parts_sorted
        )
    }

    #[test]
    fn exhaustive_status_is_constructed_properly() {
        let cw_remaining_balance = 45678;

        let result = ConsumingWalletExhaustingStatus::new(cw_remaining_balance);

        assert_eq!(result.remaining_cw_balance, cw_remaining_balance);
        assert_eq!(result.accounts_finalized_so_far, vec![])
    }

    #[test]
    fn proposed_balance_refills_up_to_original_balance_for_all_three_non_exhaustive_accounts() {
        // Despite looking irrational, this can happen if some of those originally qualified
        // payables were eliminated. That would free some assets to be eventually used for
        // the accounts left. Going forward, we've got a confirmed final accounts but with
        // suboptimal balances caused by, so far, declaring them by their disqualification limits
        // and no more. Therefore, we can live on a situation where the consuming wallet balance is
        // more than the final, already reduced, set of accounts. This tested operation should
        // ensure that the available assets will be given out maximally, resulting in a total
        // pay-off on those selected accounts.
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 45_000_000_000;
        let proposed_adjusted_balance_1 = 44_999_897_000;
        let weight_1 = 2_000_000_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 33_487_999_999;
        let weight_2 = 6_000_000_000;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 41_000_000;
        let proposed_adjusted_balance_3 = 40_980_000;
        let weight_3 = 20_000_000_000;
        let original_cw_balance = original_requested_balance_1
            + original_requested_balance_2
            + original_requested_balance_3
            + 5000;
        let non_finalized_adjusted_accounts = vec![
            make_non_finalized_adjusted_account(
                &wallet_1,
                original_requested_balance_1,
                weight_1,
                proposed_adjusted_balance_1,
            ),
            make_non_finalized_adjusted_account(
                &wallet_2,
                original_requested_balance_2,
                weight_2,
                proposed_adjusted_balance_2,
            ),
            make_non_finalized_adjusted_account(
                &wallet_3,
                original_requested_balance_3,
                weight_3,
                proposed_adjusted_balance_3,
            ),
        ];

        let result =
            exhaust_cw_balance_entirely(non_finalized_adjusted_accounts, original_cw_balance);

        let expected_resulted_balances = vec![
            (wallet_1, original_requested_balance_1),
            (wallet_2, original_requested_balance_2),
            (wallet_3, original_requested_balance_3),
        ];
        assert_payable_accounts_after_adjustment_finalization(result, expected_resulted_balances)
    }

    #[test]
    fn three_non_exhaustive_accounts_with_one_completely_refilled_one_partly_one_not_at_all() {
        // The smallest proposed adjusted balance gets refilled first, and then gradually on...
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 41_000_000;
        let proposed_adjusted_balance_1 = 39_700_000;
        let weight_1 = 38_000_000_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 32_487_999_999;
        let weight_2 = 25_000_000_000;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 50_000_000_000;
        let proposed_adjusted_balance_3 = 43_000_000_000;
        let weight_3 = 38_000_000;
        let original_cw_balance = original_requested_balance_1
            + proposed_adjusted_balance_2
            + proposed_adjusted_balance_3
            + 222_000_000;
        let non_finalized_adjusted_accounts = vec![
            make_non_finalized_adjusted_account(
                &wallet_1,
                original_requested_balance_1,
                weight_1,
                proposed_adjusted_balance_1,
            ),
            make_non_finalized_adjusted_account(
                &wallet_2,
                original_requested_balance_2,
                weight_2,
                proposed_adjusted_balance_2,
            ),
            make_non_finalized_adjusted_account(
                &wallet_3,
                original_requested_balance_3,
                weight_3,
                proposed_adjusted_balance_3,
            ),
        ];

        let result =
            exhaust_cw_balance_entirely(non_finalized_adjusted_accounts, original_cw_balance);

        let expected_resulted_balances = vec![
            (wallet_1, original_requested_balance_1),
            (wallet_2, proposed_adjusted_balance_2 + 222_000_000),
            (wallet_3, proposed_adjusted_balance_3),
        ];
        let check_sum: u128 = expected_resulted_balances
            .iter()
            .map(|(_, balance)| balance)
            .sum();
        assert_payable_accounts_after_adjustment_finalization(result, expected_resulted_balances);
        assert_eq!(check_sum, original_cw_balance)
    }
}
