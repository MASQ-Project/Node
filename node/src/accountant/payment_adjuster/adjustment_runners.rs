// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::service_fee_adjuster::ServiceFeeAdjusterReal;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;

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
            weighted_account.qualified_account.bare_account.balance_wei
        });

        let unallocated_cw_balance = payment_adjuster
            .inner
            .unallocated_cw_service_fee_balance_minor();

        if check_sum <= unallocated_cw_balance {
            // Fast return after a direct conversion into the expected type
            return ServiceFeeAdjusterReal::assign_accounts_their_minimal_acceptable_balance(
                weighted_accounts,
                &payment_adjuster.disqualification_arbiter,
            );
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
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use crate::accountant::{CreditorThresholds, QualifiedPayableAccount};
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
        let mut payable = WeightedPayable {
            qualified_account: make_non_guaranteed_qualified_payable(111),
            weight: n as u128 * 1234,
        };
        payable.qualified_account.bare_account.balance_wei = initial_balance_minor;
        payable
    }

    fn test_surplus_incurred_after_disqualification_in_previous_iteration(
        payable_1: WeightedPayable,
        payable_2: WeightedPayable,
        cw_service_fee_balance_minor: u128,
    ) {
        // The disqualification doesn't take part in here, it is just an explanation for those who
        // wonder why the implied surplus may happen
        let now = SystemTime::now();
        let mut payment_adjuster =
            initialize_payment_adjuster(now, cw_service_fee_balance_minor, 12345678);
        let initial_balance_minor_1 = payable_1.qualified_account.bare_account.balance_wei;
        let initial_balance_minor_2 = payable_2.qualified_account.bare_account.balance_wei;
        let subject = ServiceFeeOnlyAdjustmentRunner {};

        let result = subject.adjust_accounts(
            &mut payment_adjuster,
            vec![payable_1.clone(), payable_2.clone()],
        );

        assert_eq!(
            result,
            vec![
                AdjustedAccountBeforeFinalization {
                    original_account: payable_1.qualified_account.bare_account,
                    proposed_adjusted_balance_minor: initial_balance_minor_1
                },
                AdjustedAccountBeforeFinalization {
                    original_account: payable_2.qualified_account.bare_account,
                    proposed_adjusted_balance_minor: initial_balance_minor_2
                }
            ]
        )
    }

    #[test]
    fn service_fee_only_runner_cw_balance_equals_requested_money_after_dsq_in_previous_iteration() {
        let cw_service_fee_balance_minor = 10_000_000_000;
        let payable_1 = make_weighed_payable(111, 5_000_000_000);
        let payable_2 = make_weighed_payable(222, 5_000_000_000);

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            payable_1,
            payable_2,
            cw_service_fee_balance_minor,
        )
    }

    #[test]
    fn service_fee_only_runner_handles_means_bigger_requested_money_after_dsq_in_previous_iteration(
    ) {
        let cw_service_fee_balance_minor = 10_000_000_000;
        let payable_1 = make_weighed_payable(111, 5_000_000_000);
        let payable_2 = make_weighed_payable(222, 4_999_999_999);

        test_surplus_incurred_after_disqualification_in_previous_iteration(
            payable_1,
            payable_2,
            cw_service_fee_balance_minor,
        )
    }

    #[test]
    fn adjust_accounts_for_service_fee_only_runner_is_not_supposed_to_care_about_transaction_fee() {
        let mut payment_thresholds = PaymentThresholds::default();
        payment_thresholds.maturity_threshold_sec = 100;
        payment_thresholds.threshold_interval_sec = 1000;
        payment_thresholds.permanent_debt_allowed_gwei = 1;
        let balance = 5_000_000_000;
        let mut account = make_non_guaranteed_qualified_payable(111);
        account.bare_account.balance_wei = 5_000_000_000;
        account.payment_threshold_intercept_minor = 4_000_000_000;
        account.creditor_thresholds = CreditorThresholds::new(1_000_000_000);
        let wallet_1 = make_wallet("abc");
        let wallet_2 = make_wallet("def");
        let mut account_1 = account.clone();
        account_1.bare_account.wallet = wallet_1.clone();
        let mut account_2 = account;
        account_2.bare_account.wallet = wallet_2.clone();
        let adjustment = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let service_fee_balance_minor = (5 * balance) / 3;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(
            service_fee_balance_minor,
            adjustment,
            123456789,
            SystemTime::now(),
        );
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let weighted_account = |account: QualifiedPayableAccount| WeightedPayable {
            qualified_account: account,
            weight: 4_000_000_000,
        };
        let criteria_and_accounts = vec![weighted_account(account_1), weighted_account(account_2)];

        let result = subject.adjust_accounts(&mut payment_adjuster, criteria_and_accounts);

        let returned_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts, vec![wallet_1, wallet_2])
        // If the transaction fee adjustment had been available to be performed, only one account
        // would've been returned. This test passes
    }
}
