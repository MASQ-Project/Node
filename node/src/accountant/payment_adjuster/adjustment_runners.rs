// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::maybe_find_an_account_to_disqualify_in_this_iteration;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;
use std::vec;

pub trait AdjustmentRunner {
    type ReturnType;

    // This method:
    // a) helps with writing tests aimed at edge cases
    // b) avoids performing an unnecessary computation for an obvious result
    // c) makes the condition in the initial check for adjustment possibility achievable in its pureness
    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: PayableAccount,
    ) -> Self::ReturnType;

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        accounts_with_individual_criteria_sorted: Vec<(u128, PayableAccount)>,
    ) -> Self::ReturnType;
}

pub struct MasqAndTransactionFeeRunner {}

impl AdjustmentRunner for MasqAndTransactionFeeRunner {
    type ReturnType = Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    >;

    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: PayableAccount,
    ) -> Self::ReturnType {
        let adjusted_account_vec = adjust_last_one(payment_adjuster, last_account);
        Ok(Either::Left(empty_or_single_element(adjusted_account_vec)))
    }

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
    ) -> Self::ReturnType {
        match payment_adjuster.inner.transaction_fee_count_limit_opt() {
            Some(limit) => {
                return payment_adjuster.begin_adjustment_by_transaction_fee(
                    criteria_and_accounts_in_descending_order,
                    limit,
                )
            }
            None => (),
        };

        Ok(Either::Left(
            payment_adjuster
                .propose_possible_adjustment_recursively(criteria_and_accounts_in_descending_order),
        ))
    }
}

pub struct MasqOnlyRunner {}

impl AdjustmentRunner for MasqOnlyRunner {
    type ReturnType = Vec<AdjustedAccountBeforeFinalization>;

    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: PayableAccount,
    ) -> Self::ReturnType {
        empty_or_single_element(adjust_last_one(payment_adjuster, last_account))
    }

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
    ) -> Self::ReturnType {
        payment_adjuster
            .propose_possible_adjustment_recursively(criteria_and_accounts_in_descending_order)
    }
}

fn adjust_last_one(
    payment_adjuster: &PaymentAdjusterReal,
    last_account: PayableAccount,
) -> Option<AdjustedAccountBeforeFinalization> {
    let cw_balance = payment_adjuster.inner.unallocated_cw_masq_balance_minor();
    let proposed_adjusted_balance = if last_account.balance_wei.checked_sub(cw_balance) == None {
        last_account.balance_wei
    } else {
        diagnostics!(
            "LAST REMAINING ACCOUNT",
            "Balance adjusted to {} by exhausting the cw balance",
            cw_balance
        );

        cw_balance
    };
    let mut proposed_adjustment_vec = vec![AdjustedAccountBeforeFinalization::new(
        last_account,
        proposed_adjusted_balance,
    )];

    let logger = &payment_adjuster.logger;

    match maybe_find_an_account_to_disqualify_in_this_iteration(&proposed_adjustment_vec, logger) {
        Some(_) => None,
        None => Some(proposed_adjustment_vec.remove(0)),
    }
}

fn empty_or_single_element(
    adjusted_account_opt: Option<AdjustedAccountBeforeFinalization>,
) -> Vec<AdjustedAccountBeforeFinalization> {
    match adjusted_account_opt {
        Some(elem) => vec![elem],
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::{
        adjust_last_one, empty_or_single_element, AdjustmentRunner, MasqAndTransactionFeeRunner,
        MasqOnlyRunner,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::scanners::payable_scan_setup_msgs::FinancialAndTechDetails;
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use std::fmt::Debug;
    use std::time::{Duration, SystemTime};

    fn prepare_payment_adjuster(cw_balance: u128, now: SystemTime) -> PaymentAdjusterReal {
        let details = FinancialAndTechDetails {
            consuming_wallet_balances: ConsumingWalletBalances {
                transaction_fee_minor: 0,
                masq_tokens_minor: cw_balance,
            },
            agreed_transaction_fee_per_computed_unit_major: 30,
            estimated_gas_limit_per_transaction: 100,
        };
        let adjustment = Adjustment::MasqToken;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(details, adjustment, now);
        payment_adjuster
    }

    fn test_adjust_last_one<AR, R>(
        subject: AR,
        expected_return_type_finalizer: fn(Vec<AdjustedAccountBeforeFinalization>) -> R,
    ) where
        AR: AdjustmentRunner<ReturnType = R>,
        R: Debug + PartialEq,
    {
        let now = SystemTime::now();
        let wallet_1 = make_wallet("abc");
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 9_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let cw_balance = 8_645_123_505;
        let mut payment_adjuster = prepare_payment_adjuster(cw_balance, now);

        let result = subject.adjust_last_one(&mut payment_adjuster, account_1.clone());

        assert_eq!(
            result,
            expected_return_type_finalizer(vec![AdjustedAccountBeforeFinalization {
                original_account: account_1,
                proposed_adjusted_balance: cw_balance,
            }])
        )
    }

    #[test]
    fn masq_and_transaction_fee_adjust_single_works() {
        test_adjust_last_one(MasqAndTransactionFeeRunner {}, |expected_vec| {
            Ok(Either::Left(expected_vec))
        })
    }

    #[test]
    fn masq_only_adjust_single_works() {
        test_adjust_last_one(MasqOnlyRunner {}, |expected_vec| expected_vec)
    }

    #[test]
    fn adjust_last_one_for_requested_balance_smaller_than_cw_balance() {
        let now = SystemTime::now();
        let cw_balance = 8_645_123_505;
        let account = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 4_333_222_111,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let payment_adjuster = prepare_payment_adjuster(cw_balance, now);

        let result = adjust_last_one(&payment_adjuster, account.clone());

        assert_eq!(
            result,
            Some(AdjustedAccountBeforeFinalization {
                original_account: account,
                proposed_adjusted_balance: 4_333_222_111,
            })
        )
    }

    #[test]
    fn adjust_last_one_decides_for_adjusted_account_disqualification() {
        let now = SystemTime::now();
        let account_balance = 4_000_444;
        let account = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: account_balance,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let cw_balance = 4_000_444 / 2;
        let payment_adjuster = prepare_payment_adjuster(cw_balance, now);

        let result = adjust_last_one(&payment_adjuster, account.clone());

        assert_eq!(result, None)
    }

    #[test]
    fn masq_only_adjust_multiple_is_not_supposed_to_care_about_transaction_fee() {
        let now = SystemTime::now();
        let cw_balance = 9_000_000;
        let details = FinancialAndTechDetails {
            consuming_wallet_balances: ConsumingWalletBalances {
                transaction_fee_minor: 0,
                masq_tokens_minor: cw_balance,
            },
            agreed_transaction_fee_per_computed_unit_major: 30,
            estimated_gas_limit_per_transaction: 100,
        };
        let wallet_1 = make_wallet("abc");
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 5_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("def");
        let mut account_2 = account_1.clone();
        account_2.wallet = wallet_2.clone();
        let accounts = vec![account_1, account_2];
        let adjustment = Adjustment::PriorityTransactionFee {
            affordable_transaction_count: 1,
        };
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(details, adjustment, now);
        let subject = MasqOnlyRunner {};
        let seeds = payment_adjuster.calculate_criteria_sums_for_accounts(accounts);

        let result = subject.adjust_multiple(&mut payment_adjuster, seeds);

        let returned_accounts_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts_accounts, vec![wallet_1, wallet_2])
        // if the transaction_fee adjustment had been available to perform, only one account would've been
        // returned, therefore test passes
    }

    #[test]
    fn empty_or_single_element_for_none() {
        let result = empty_or_single_element(None);

        assert_eq!(result, vec![])
    }

    #[test]
    fn empty_or_single_element_for_some() {
        let account_info = AdjustedAccountBeforeFinalization {
            original_account: make_payable_account(123),
            proposed_adjusted_balance: 123_456_789,
        };
        let result = empty_or_single_element(Some(account_info.clone()));

        assert_eq!(result, vec![account_info])
    }
}
