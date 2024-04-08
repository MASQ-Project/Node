// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use crate::accountant::QualifiedPayableAccount;
use itertools::Either;
use masq_lib::utils::convert_collection;
use std::vec;

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

    //TODO old code
    // This specialized method:
    // a) helps with writing tests targeting edge cases,
    // b) allows to avoid performing unnecessary computation for an evident result
    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: QualifiedPayableAccount,
    ) -> Self::ReturnType;

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

    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: QualifiedPayableAccount,
    ) -> Self::ReturnType {
        todo!("to be pulled out");
        let account_opt = payment_adjuster.adjust_last_account_opt(last_account);
        Ok(Either::Left(empty_or_single_element_vector(account_opt)))
    }

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

    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: QualifiedPayableAccount,
    ) -> Self::ReturnType {
        todo!("to be pulled out");
        let account_opt = payment_adjuster.adjust_last_account_opt(last_account);
        empty_or_single_element_vector(account_opt)
    }

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
            return convert_collection(weighted_accounts);
        }

        payment_adjuster.propose_possible_adjustment_recursively(weighted_accounts)
    }
}

fn empty_or_single_element_vector(
    adjusted_account_opt: Option<AdjustedAccountBeforeFinalization>,
) -> Vec<AdjustedAccountBeforeFinalization> {
    match adjusted_account_opt {
        Some(elem) => vec![elem],
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::{
        empty_or_single_element_vector, AdjustmentRunner, ServiceFeeOnlyAdjustmentRunner,
        TransactionAndServiceFeeAdjustmentRunner,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        make_initialized_subject, make_non_guaranteed_unconfirmed_adjustment,
    };
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::test_utils::{
        make_guaranteed_qualified_payables, make_non_guaranteed_qualified_payable,
    };
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use std::fmt::Debug;
    use std::time::{Duration, SystemTime};

    fn test_adjust_last_one<AR, RT>(
        subject: AR,
        expected_return_type_finalizer: fn(Vec<AdjustedAccountBeforeFinalization>) -> RT,
    ) where
        AR: AdjustmentRunner<ReturnType = RT>,
        RT: Debug + PartialEq,
    {
        todo!()
        // let now = SystemTime::now();
        // let wallet = make_wallet("abc");
        // let mut qualified_payable = make_non_guaranteed_qualified_payable(111);
        // qualified_payable.bare_account.balance_wei = 9_000_000_000;
        // qualified_payable.payment_threshold_intercept_minor = 7_000_000_000;
        // qualified_payable
        //     .creditor_thresholds
        //     .permanent_debt_allowed_wei = 2_000_000_000;
        // let cw_balance = 8_645_123_505;
        // let adjustment = Adjustment::ByServiceFee;
        // let mut payment_adjuster = PaymentAdjusterReal::new();
        // payment_adjuster.initialize_inner(cw_balance.into(), adjustment, now);
        //
        // let result = subject.adjust_last_one(&mut payment_adjuster, qualified_payable.clone());
        //
        // assert_eq!(
        //     result,
        //     expected_return_type_finalizer(vec![AdjustedAccountBeforeFinalization {
        //         weighted_account: qualified_payable,
        //         proposed_adjusted_balance_minor: cw_balance,
        //     }])
        // )
    }

    #[test]
    fn transaction_and_service_fee_adjust_last_one_works() {
        test_adjust_last_one(
            TransactionAndServiceFeeAdjustmentRunner {},
            |expected_vec| Ok(Either::Left(expected_vec)),
        )
    }

    #[test]
    fn service_fee_only_adjust_last_one_works() {
        test_adjust_last_one(ServiceFeeOnlyAdjustmentRunner {}, |expected_vec| {
            expected_vec
        })
    }

    fn initialize_payment_adjuster(
        now: SystemTime,
        service_fee_balance: u128,
    ) -> PaymentAdjusterReal {
        make_initialized_subject(Some(now), Some(service_fee_balance), None, None)
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
        let mut payment_adjuster = initialize_payment_adjuster(now, cw_service_fee_balance_minor);
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
    fn service_fee_only_runner_cw_balance_equals_requested_money_after_dql_in_previous_iteration() {
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
    fn service_fee_only_runner_handles_means_bigger_requested_money_after_dql_in_previous_iteration(
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
        let now = SystemTime::now();
        let wallet_1 = make_wallet("abc");
        let mut payment_thresholds = PaymentThresholds::default();
        payment_thresholds.maturity_threshold_sec = 100;
        payment_thresholds.threshold_interval_sec = 1000;
        payment_thresholds.permanent_debt_allowed_gwei = 1;
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 5_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("def");
        let mut account_2 = account_1.clone();
        account_2.wallet = wallet_2.clone();
        let wallet_3 = make_wallet("ghj");
        let mut account_3 = account_1.clone();
        account_3.wallet = wallet_3;
        let accounts = vec![account_1, account_2];
        let qualified_payables =
            make_guaranteed_qualified_payables(accounts, &payment_thresholds, now);
        let adjustment = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let service_fee_balance_wei = 10_000_000_000;
        let mut payment_adjuster = initialize_payment_adjuster(now, service_fee_balance_wei);
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let criteria_and_accounts =
            payment_adjuster.calculate_weights_for_accounts(qualified_payables);

        let result = subject.adjust_accounts(&mut payment_adjuster, criteria_and_accounts);

        let returned_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts, vec![wallet_1, wallet_2])
        // If the transaction fee adjustment had been available to be performed, only one account
        // would've been returned. This test passes
    }

    #[test]
    fn empty_or_single_element_vector_for_none() {
        let result = empty_or_single_element_vector(None);

        assert_eq!(result, vec![])
    }

    #[test]
    fn empty_or_single_element_vector_for_some() {
        todo!()
        // let account_info = AdjustedAccountBeforeFinalization {
        //     weighted_account: make_non_guaranteed_qualified_payable(123),
        //     proposed_adjusted_balance_minor: 123_456_789,
        // };
        // let result = empty_or_single_element_vector(Some(account_info.clone()));
        //
        // assert_eq!(result, vec![account_info])
    }
}
