// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;
use masq_lib::utils::convert_collection;

// TODO review this comment
// There are only two runners. They perform adjustment either by both the transaction and service
// fee, or exclusively by the transaction fee. The idea is that the adjustment by the transaction
// fee may ever appear in the initial iteration of the recursion. In any of the other iterations,
// if it proceeded, this feature would be staying around useless. Therefor the runner with more
// features is used only at the beginning. Its benefit is that it also allows to short-circuit
// through the computation of the account weights, because it can detect that dropped accounts due
// to the transaction fee scarcity lowered demand for the service fee and this adjustment is not
// needed. For the things just described, each runner gives back a different result type.
pub trait AdjustmentRunner {
    type ReturnType;

    fn adjust_accounts(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts_in_descending_order: Vec<WeightedPayable>,
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
        weighted_accounts_in_descending_order: Vec<WeightedPayable>,
    ) -> Self::ReturnType {
        match payment_adjuster.inner.transaction_fee_count_limit_opt() {
            Some(limit) => {
                return payment_adjuster.begin_with_adjustment_by_transaction_fee(
                    weighted_accounts_in_descending_order,
                    limit,
                )
            }
            None => (),
        };

        Ok(Either::Left(
            payment_adjuster
                .propose_possible_adjustment_recursively(weighted_accounts_in_descending_order),
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
            weighted_account.balance_minor()
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
    use crate::accountant::payment_adjuster::test_utils::{
        make_initialized_subject, multiple_by_billion,
    };
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::test_utils::{
        make_analyzed_account, make_non_guaranteed_qualified_payable,
    };
    use crate::accountant::{AnalyzedPayableAccount, CreditorThresholds, QualifiedPayableAccount};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    fn initialize_payment_adjuster(
        now: SystemTime,
        service_fee_balance: u128,
        largest_exceeding_balance_recently_qualified: u128,
    ) -> PaymentAdjusterReal {
        make_initialized_subject(
            Some(now),
            Some(service_fee_balance),
            None,
            Some(largest_exceeding_balance_recently_qualified),
            None,
        )
    }

    fn make_weighed_payable(n: u64, initial_balance_minor: u128) -> WeightedPayable {
        let mut payable = WeightedPayable::new(make_analyzed_account(111), n as u128 * 1234);
        payable
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = initial_balance_minor;
        payable
    }

    fn test_surplus_incurred_after_disqualification_in_previous_iteration(
        subject: ServiceFeeOnlyAdjustmentRunner,
        payable_1: WeightedPayable,
        payable_2: WeightedPayable,
        cw_service_fee_balance_minor: u128,
        expected_proposed_balance_1: u128,
        expected_proposed_balance_2: u128,
    ) {
        // Explanation: The hypothesis is that the previous iteration disqualified an account after
        // which the remaining means are enough for the other accounts.
        // We could assign the accounts all they initially requested but a fairer way to do that
        // is to give out only that much up to the disqualification limit of these accounts. Later on,
        // the accounts that deserves it more will split the rest of the means among them (Their
        // weights were higher).
        let now = SystemTime::now();
        let mut payment_adjuster =
            initialize_payment_adjuster(now, cw_service_fee_balance_minor, 12345678);
        let initial_balance_minor_1 = payable_1.balance_minor();
        let initial_balance_minor_2 = payable_2.balance_minor();

        let result = subject.adjust_accounts(
            &mut payment_adjuster,
            vec![payable_1.clone(), payable_2.clone()],
        );

        assert_eq!(
            result,
            vec![
                AdjustedAccountBeforeFinalization {
                    original_account: payable_1.analyzed_account.qualified_as.bare_account,
                    proposed_adjusted_balance_minor: expected_proposed_balance_1
                },
                AdjustedAccountBeforeFinalization {
                    original_account: payable_2.analyzed_account.qualified_as.bare_account,
                    proposed_adjusted_balance_minor: expected_proposed_balance_2
                }
            ]
        )
    }

    fn weighted_payable_setup_for_surplus_test(
        n: u64,
        initial_balance_minor: u128,
    ) -> WeightedPayable {
        let mut account = make_weighed_payable(n, initial_balance_minor);
        account
            .analyzed_account
            .qualified_as
            .payment_threshold_intercept_minor = 3_000_000_000;
        account.analyzed_account.qualified_as.creditor_thresholds =
            CreditorThresholds::new(1_000_000_000);
        account
    }

    #[test]
    fn means_equal_requested_money_after_dsq_in_previous_iteration_to_return_capped_accounts() {
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let cw_service_fee_balance_minor = 10_000_000_000;
        let mut payable_1 = weighted_payable_setup_for_surplus_test(111, 5_000_000_000);
        payable_1.analyzed_account.disqualification_limit_minor = 3_444_333_444;
        let mut payable_2 = weighted_payable_setup_for_surplus_test(222, 5_000_000_000);
        payable_2.analyzed_account.disqualification_limit_minor = 3_555_333_555;
        let expected_proposed_balance_1 = 3_444_333_444;
        let expected_proposed_balance_2 = 3_555_333_555;

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            subject,
            payable_1,
            payable_2,
            cw_service_fee_balance_minor,
            expected_proposed_balance_1,
            expected_proposed_balance_2,
        )
    }

    #[test]
    fn means_become_bigger_than_requested_after_dsq_in_previous_iteration_to_return_capped_accounts(
    ) {
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let cw_service_fee_balance_minor = 10_000_000_000;
        let mut payable_1 = weighted_payable_setup_for_surplus_test(111, 5_000_000_000);
        payable_1.analyzed_account.disqualification_limit_minor = 3_444_333_444;
        let mut payable_2 = weighted_payable_setup_for_surplus_test(222, 4_999_999_999);
        payable_2.analyzed_account.disqualification_limit_minor = 3_555_333_555;
        let expected_proposed_balance_1 = 3_444_333_444;
        let expected_proposed_balance_2 = 3_555_333_555;

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            subject,
            payable_1,
            payable_2,
            cw_service_fee_balance_minor,
            expected_proposed_balance_1,
            expected_proposed_balance_2,
        )
    }

    #[test]
    fn adjust_accounts_for_service_fee_only_runner_is_not_supposed_to_care_about_transaction_fee() {
        let balance = 5_000_000_000;
        let mut account = make_non_guaranteed_qualified_payable(111);
        account.bare_account.balance_wei = balance;
        let wallet_1 = make_wallet("abc");
        let wallet_2 = make_wallet("def");
        let mut account_1 = account.clone();
        account_1.bare_account.wallet = wallet_1.clone();
        let mut account_2 = account;
        account_2.bare_account.wallet = wallet_2.clone();
        let adjustment = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let service_fee_balance_minor = (10 * balance) / 8;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(
            service_fee_balance_minor,
            adjustment,
            123456789,
            SystemTime::now(),
        );
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let weighted_account = |account: QualifiedPayableAccount| WeightedPayable {
            analyzed_account: AnalyzedPayableAccount::new(account, 3_000_000_000),
            weight: 4_000_000_000,
        };
        let weighted_accounts = vec![weighted_account(account_1), weighted_account(account_2)];

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
