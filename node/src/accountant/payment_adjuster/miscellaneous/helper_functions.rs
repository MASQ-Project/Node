// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::{
    exhausting_cw_balance_diagnostics, not_exhausting_cw_balance_diagnostics,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AccountsEliminatedByTxFeeInfo, AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable};
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use itertools::{Either, Itertools};

pub fn zero_affordable_accounts_found(
    accounts: &Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
) -> bool {
    match accounts {
        Either::Left(vector) => vector.is_empty(),
        Either::Right(vector) => vector.is_empty(),
    }
}

pub fn sum_as<N, T, F>(collection: &[T], arranger: F) -> N
where
    N: From<u128>,
    F: Fn(&T) -> u128,
{
    collection.iter().map(arranger).sum::<u128>().into()
}

pub fn weights_total(weights_and_accounts: &[WeightedPayable]) -> u128 {
    sum_as(weights_and_accounts, |weighted_account| {
        weighted_account.weight
    })
}

pub fn dump_unaffordable_accounts_by_transaction_fee(
    weighted_accounts_in_descending_order: Vec<WeightedPayable>,
    affordable_transaction_count: u16,
) -> (Vec<WeightedPayable>, AccountsEliminatedByTxFeeInfo) {
    let to_be_dumped = weighted_accounts_in_descending_order
        .iter()
        .skip(affordable_transaction_count as usize)
        .collect::<Vec<_>>();
    let elimination_info = {
        let count = to_be_dumped.len();
        let sum_of_balances = sum_as(&to_be_dumped, |account| {
            account
                .analyzed_account
                .qualified_as
                .bare_account
                .balance_wei
        });
        AccountsEliminatedByTxFeeInfo {
            count,
            sum_of_balances,
        }
    };

    diagnostics!(
        "ACCOUNTS CUTBACK FOR TRANSACTION FEE",
        "Keeping {} out of {} accounts. Dumping these accounts: {:?}",
        affordable_transaction_count,
        weighted_accounts_in_descending_order.len(),
        to_be_dumped
    );

    let kept_accounts = weighted_accounts_in_descending_order
        .into_iter()
        .take(affordable_transaction_count as usize)
        .collect();

    (kept_accounts, elimination_info)
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
    find_largest_u128(&diffs)
}

fn find_largest_u128(slice: &[u128]) -> u128 {
    slice
        .iter()
        .fold(0, |largest_so_far, num| largest_so_far.max(*num))
}

pub fn exhaust_cw_balance_entirely(
    approved_accounts: Vec<AdjustedAccountBeforeFinalization>,
    original_cw_service_fee_balance_minor: u128,
) -> Vec<PayableAccount> {
    let adjusted_balances_total: u128 = sum_as(&approved_accounts, |account_info| {
        account_info.proposed_adjusted_balance_minor
    });

    let cw_reminder = original_cw_service_fee_balance_minor
        .checked_sub(adjusted_balances_total)
        .unwrap_or_else(|| {
            panic!(
                "Remainder should've been a positive number but wasn't after {} - {}",
                original_cw_service_fee_balance_minor, adjusted_balances_total
            )
        });

    let init = ConsumingWalletExhaustingStatus::new(cw_reminder);
    approved_accounts
        .into_iter()
        .sorted_by(|info_a, info_b| {
            Ord::cmp(
                &info_a.proposed_adjusted_balance_minor,
                &info_b.proposed_adjusted_balance_minor,
            )
        })
        .fold(
            init,
            run_cw_exhausting_on_possibly_sub_optimal_account_balances,
        )
        .accounts_finalized_so_far
}

fn run_cw_exhausting_on_possibly_sub_optimal_account_balances(
    status: ConsumingWalletExhaustingStatus,
    non_finalized_account: AdjustedAccountBeforeFinalization,
) -> ConsumingWalletExhaustingStatus {
    if status.remainder != 0 {
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
        let possible_extra_addition = if balance_gap_minor < status.remainder {
            balance_gap_minor
        } else {
            status.remainder
        };

        exhausting_cw_balance_diagnostics(&non_finalized_account, possible_extra_addition);

        status.handle_balance_update_and_add(non_finalized_account, possible_extra_addition)
    } else {
        not_exhausting_cw_balance_diagnostics(&non_finalized_account);

        status.add(non_finalized_account)
    }
}

struct ConsumingWalletExhaustingStatus {
    remainder: u128,
    accounts_finalized_so_far: Vec<PayableAccount>,
}

impl ConsumingWalletExhaustingStatus {
    fn new(remainder: u128) -> Self {
        Self {
            remainder,
            accounts_finalized_so_far: vec![],
        }
    }

    fn handle_balance_update_and_add(
        mut self,
        mut non_finalized_account_info: AdjustedAccountBeforeFinalization,
        possible_extra_addition: u128,
    ) -> Self {
        let corrected_adjusted_account_before_finalization = {
            non_finalized_account_info.proposed_adjusted_balance_minor += possible_extra_addition;
            non_finalized_account_info
        };
        self.remainder = self
            .remainder
            .checked_sub(possible_extra_addition)
            .expect("we hit zero");
        self.add(corrected_adjusted_account_before_finalization)
    }

    fn add(mut self, non_finalized_account_info: AdjustedAccountBeforeFinalization) -> Self {
        let finalized_account = PayableAccount::from(non_finalized_account_info);
        self.accounts_finalized_so_far.push(finalized_account);
        self
    }
}

pub fn sort_in_descendant_order_by_weights(
    unsorted: impl Iterator<Item = WeightedPayable>,
) -> Vec<WeightedPayable> {
    unsorted
        .sorted_by(|account_a, account_b| Ord::cmp(&account_b.weight, &account_a.weight))
        .collect()
}

pub fn drop_no_longer_needed_weights_away_from_accounts(
    weights_and_accounts: Vec<WeightedPayable>,
) -> Vec<PayableAccount> {
    weights_and_accounts
        .into_iter()
        .map(|weighted_account| weighted_account.analyzed_account.qualified_as.bare_account)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        compute_mul_coefficient_preventing_fractional_numbers, exhaust_cw_balance_entirely,
        find_largest_exceeding_balance, find_largest_u128, zero_affordable_accounts_found,
        ConsumingWalletExhaustingStatus,
    };
    use crate::accountant::test_utils::{
        make_analyzed_account, make_non_guaranteed_qualified_payable, make_payable_account,
    };
    use crate::accountant::{CreditorThresholds, QualifiedPayableAccount};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use std::time::SystemTime;

    #[test]
    fn found_zero_affordable_accounts_found_returns_true_for_non_finalized_accounts() {
        let result = zero_affordable_accounts_found(&Either::Left(vec![]));

        assert_eq!(result, true)
    }

    #[test]
    fn zero_affordable_accounts_found_returns_false_for_non_finalized_accounts() {
        let result = zero_affordable_accounts_found(&Either::Left(vec![
            AdjustedAccountBeforeFinalization::new(make_payable_account(456), 1234),
        ]));

        assert_eq!(result, false)
    }

    #[test]
    fn found_zero_affordable_accounts_returns_true_for_finalized_accounts() {
        let result = zero_affordable_accounts_found(&Either::Right(vec![]));

        assert_eq!(result, true)
    }

    #[test]
    fn found_zero_affordable_accounts_returns_false_for_finalized_accounts() {
        let result =
            zero_affordable_accounts_found(&Either::Right(vec![make_payable_account(123)]));

        assert_eq!(result, false)
    }

    #[test]
    fn find_largest_u128_begins_with_zero() {
        let result = find_largest_u128(&[]);

        assert_eq!(result, 0)
    }

    #[test]
    fn find_largest_u128_works() {
        let result = find_largest_u128(&[45, 2, 456565, 0, 2, 456565, 456564]);

        assert_eq!(result, 456565)
    }

    #[test]
    fn find_largest_exceeding_balance_works() {
        let mut account_1 = make_analyzed_account(111);
        account_1.qualified_as.bare_account.balance_wei = 5_000_000_000;
        account_1.qualified_as.payment_threshold_intercept_minor = 2_000_000_000;
        let mut account_2 = make_analyzed_account(222);
        account_2.qualified_as.bare_account.balance_wei = 4_000_000_000;
        account_2.qualified_as.payment_threshold_intercept_minor = 800_000_000;
        let qualified_accounts = &[account_1, account_2];

        let result = find_largest_exceeding_balance(qualified_accounts);

        assert_eq!(result, 4_000_000_000 - 800_000_000)
    }

    #[test]
    fn compute_mul_coefficient_preventing_fractional_numbers_works() {
        let cw_service_fee_balance_minor = 12345678;

        let result =
            compute_mul_coefficient_preventing_fractional_numbers(cw_service_fee_balance_minor);

        let expected_result = u128::MAX / cw_service_fee_balance_minor;
        assert_eq!(result, expected_result)
    }

    fn make_non_finalized_adjusted_account(
        wallet: &Wallet,
        original_balance: u128,
        proposed_adjusted_balance: u128,
    ) -> AdjustedAccountBeforeFinalization {
        let garbage_last_paid_timestamp = SystemTime::now();
        let payable_account = PayableAccount {
            wallet: wallet.clone(),
            balance_wei: original_balance,
            last_paid_timestamp: garbage_last_paid_timestamp,
            pending_payable_opt: None,
        };
        AdjustedAccountBeforeFinalization::new(payable_account, proposed_adjusted_balance)
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
        let cw_balance_remainder = 45678;

        let result = ConsumingWalletExhaustingStatus::new(cw_balance_remainder);

        assert_eq!(result.remainder, cw_balance_remainder);
        assert_eq!(result.accounts_finalized_so_far, vec![])
    }

    #[test]
    fn three_non_exhaustive_accounts_all_refilled() {
        // A seemingly irrational situation, this can happen when some of those
        // originally qualified payables could get disqualified. Those would free some
        // means that could be used for the other accounts.
        // In the end, we have a final set with suboptimal balances, despite
        // the unallocated cw balance is larger than the entire sum of the original balances
        // for this few resulting accounts.
        // We can pay every account fully, so, why did we need to call the PaymentAdjuster
        // in first place?
        // The detail is in the loss of some accounts, allowing to pay more for the others.
        let wallet_1 = make_wallet("abc");
        let original_requested_balance_1 = 45_000_000_000;
        let proposed_adjusted_balance_1 = 44_999_897_000;
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 33_487_999_999;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 41_000_000;
        let proposed_adjusted_balance_3 = 40_980_000;
        let original_cw_balance = original_requested_balance_1
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
        let wallet_2 = make_wallet("def");
        let original_requested_balance_2 = 33_500_000_000;
        let proposed_adjusted_balance_2 = 32_487_999_999;
        let wallet_3 = make_wallet("ghi");
        let original_requested_balance_3 = 50_000_000_000;
        let proposed_adjusted_balance_3 = 43_000_000_000;
        let original_cw_balance = original_requested_balance_1
            + proposed_adjusted_balance_2
            + proposed_adjusted_balance_3
            + 222_000_000;
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
