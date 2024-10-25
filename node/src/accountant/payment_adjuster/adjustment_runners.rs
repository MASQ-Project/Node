// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;
use masq_lib::utils::convert_collection;

pub trait AdjustmentRunner {
    type ReturnType;

    fn adjust_accounts(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts: Vec<WeightedPayable>,
    ) -> Self::ReturnType;
}

pub struct TransactionAndServiceFeeAdjustmentRunner {}

impl AdjustmentRunner for TransactionAndServiceFeeAdjustmentRunner {
    type ReturnType = Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    >;

    fn adjust_accounts(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts: Vec<WeightedPayable>,
    ) -> Self::ReturnType {
        if let Some(limit) = payment_adjuster.inner.transaction_fee_count_limit_opt() {
            return payment_adjuster
                .begin_with_adjustment_by_transaction_fee(weighted_accounts, limit);
        }

        Ok(Either::Left(
            payment_adjuster.propose_possible_adjustment_recursively(weighted_accounts),
        ))
    }
}

pub struct ServiceFeeOnlyAdjustmentRunner {}

impl AdjustmentRunner for ServiceFeeOnlyAdjustmentRunner {
    type ReturnType = Vec<AdjustedAccountBeforeFinalization>;

    fn adjust_accounts(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts: Vec<WeightedPayable>,
    ) -> Self::ReturnType {
        let check_sum: u128 = sum_as(&weighted_accounts, |weighted_account| {
            weighted_account.initial_balance_minor()
        });

        let unallocated_cw_balance = payment_adjuster
            .inner
            .unallocated_cw_service_fee_balance_minor();

        if check_sum <= unallocated_cw_balance {
            // Fast return after a direct conversion into the expected type
            return convert_collection(weighted_accounts);
        }

        payment_adjuster.propose_possible_adjustment_recursively(weighted_accounts)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::adjustment_runners::{
        AdjustmentRunner, ServiceFeeOnlyAdjustmentRunner,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::test_utils::make_initialized_subject;
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::test_utils::{
        make_meaningless_analyzed_account, make_meaningless_qualified_payable,
    };
    use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use std::time::SystemTime;

    fn initialize_payment_adjuster(
        now: SystemTime,
        service_fee_balance: u128,
        max_portion_of_balance_over_threshold_in_qualified_payables: u128,
    ) -> PaymentAdjusterReal {
        make_initialized_subject(
            Some(now),
            Some(service_fee_balance),
            None,
            Some(max_portion_of_balance_over_threshold_in_qualified_payables),
            None,
        )
    }

    fn make_weighted_payable(n: u64, initial_balance_minor: u128) -> WeightedPayable {
        let mut payable =
            WeightedPayable::new(make_meaningless_analyzed_account(111), n as u128 * 1234);
        payable
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = initial_balance_minor;
        payable
    }

    fn test_surplus_incurred_after_disqualification_in_previous_iteration(
        subject: ServiceFeeOnlyAdjustmentRunner,
        initial_balance_for_each_account: u128,
        untaken_cw_service_fee_balance_minor: u128,
    ) {
        // Explanation: The hypothesis is that the previous iteration disqualified an account after
        // which the remaining means are enough for the other accounts.
        // We could assign the accounts the same as they initially requested but a fairer way to
        // do sp is to give out only up to the disqualification limit of these accounts. Later
        // on, the accounts that deserves it the most, according to the ordering they gain by their
        // weights, will gradually get hold of the rest of the money.
        let now = SystemTime::now();
        let mut payable_1 = make_weighted_payable(111, initial_balance_for_each_account);
        payable_1.analyzed_account.disqualification_limit_minor = 3_444_333_444;
        let mut payable_2 = make_weighted_payable(222, initial_balance_for_each_account);
        payable_2.analyzed_account.disqualification_limit_minor = 3_555_333_555;
        let weighted_payables = vec![payable_1, payable_2];
        let mut payment_adjuster =
            initialize_payment_adjuster(now, untaken_cw_service_fee_balance_minor, 12345678);

        let result = subject.adjust_accounts(&mut payment_adjuster, weighted_payables.clone());

        let expected_result = weighted_payables
            .into_iter()
            .map(|weighted_payable| {
                AdjustedAccountBeforeFinalization::new(
                    weighted_payable.analyzed_account.qualified_as.bare_account,
                    weighted_payable.weight,
                    // Here, this is the proposed balance at the moment
                    weighted_payable
                        .analyzed_account
                        .disqualification_limit_minor,
                )
            })
            .collect_vec();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn untaken_cw_balance_equals_full_two_debts_after_loosing_an_account_results_in_constrained_balances(
    ) {
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let initial_balance_for_each_account = 5_000_000_000;
        let untaken_cw_service_fee_balance_minor =
            initial_balance_for_each_account + initial_balance_for_each_account;

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            subject,
            initial_balance_for_each_account,
            untaken_cw_service_fee_balance_minor,
        )
    }

    #[test]
    fn untaken_cw_balance_is_more_than_full_two_debts_after_loosing_an_account_results_in_constrained_balances(
    ) {
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let initial_balance_for_each_account = 5_000_000_000;
        let untaken_cw_service_fee_balance_minor =
            initial_balance_for_each_account + initial_balance_for_each_account + 1;

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            subject,
            initial_balance_for_each_account,
            untaken_cw_service_fee_balance_minor,
        )
    }

    #[test]
    fn adjust_accounts_for_service_fee_only_runner_is_not_supposed_to_care_about_transaction_fee() {
        let common_balance = 5_000_000_000;
        let mut account = make_meaningless_qualified_payable(111);
        account.bare_account.balance_wei = common_balance;
        let wallet_1 = make_wallet("abc");
        let wallet_2 = make_wallet("def");
        let mut account_1 = account.clone();
        account_1.bare_account.wallet = wallet_1.clone();
        let mut account_2 = account;
        account_2.bare_account.wallet = wallet_2.clone();
        let weighted_account = |account: QualifiedPayableAccount| WeightedPayable {
            analyzed_account: AnalyzedPayableAccount::new(account, 3_000_000_000),
            weight: 4_000_000_000,
        };
        let weighted_accounts = vec![weighted_account(account_1), weighted_account(account_2)];
        // We instruct a performance of adjustment by the transaction fee, as if there were
        // two transaction, but we had enough fee just for one. Still, you can see at the end of
        // the test that this reduction didn't take place which shows that we used the kind of
        // runner which ignore this instruction.
        let adjustment_type = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let cw_service_fee_balance_minor = (10 * common_balance) / 8;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(
            cw_service_fee_balance_minor,
            adjustment_type,
            123456789,
            SystemTime::now(),
        );
        let subject = ServiceFeeOnlyAdjustmentRunner {};

        let result = subject.adjust_accounts(&mut payment_adjuster, weighted_accounts);

        let returned_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts, vec![wallet_1, wallet_2])
        // If the transaction fee adjustment had been available to be performed, only one account
        // would've been returned. This test passes
    }
}
