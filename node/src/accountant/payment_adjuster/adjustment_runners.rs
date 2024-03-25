// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, WeightedAccount,
};
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use crate::accountant::QualifiedPayableAccount;
use itertools::Either;
use std::vec;

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

    // This specialized method:
    // a) helps with writing tests targeting edge cases,
    // b) allows to avoid performing unnecessary computation for an evident result
    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: QualifiedPayableAccount,
    ) -> Self::ReturnType;

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts_in_descending_order: Vec<WeightedAccount>,
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
        let account_opt = payment_adjuster.adjust_last_account_opt(last_account);
        Ok(Either::Left(empty_or_single_element_vector(account_opt)))
    }

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts_in_descending_order: Vec<WeightedAccount>,
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
        let account_opt = payment_adjuster.adjust_last_account_opt(last_account);
        empty_or_single_element_vector(account_opt)
    }

    fn adjust_multiple(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        weighted_accounts_in_descending_order: Vec<WeightedAccount>,
    ) -> Self::ReturnType {
        payment_adjuster
            .propose_possible_adjustment_recursively(weighted_accounts_in_descending_order)
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
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
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
        let now = SystemTime::now();
        let wallet = make_wallet("abc");
        let mut qualified_payable = make_non_guaranteed_qualified_payable(111);
        qualified_payable.payable.balance_wei = 9_000_000_000;
        qualified_payable.payment_threshold_intercept_minor = 7_000_000_000;
        qualified_payable
            .creditor_thresholds
            .permanent_debt_allowed_wei = 2_000_000_000;
        let cw_balance = 8_645_123_505;
        let adjustment = Adjustment::ByServiceFee;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(cw_balance.into(), adjustment, now);

        let result = subject.adjust_last_one(&mut payment_adjuster, qualified_payable.clone());

        assert_eq!(
            result,
            expected_return_type_finalizer(vec![AdjustedAccountBeforeFinalization {
                original_qualified_account: qualified_payable,
                proposed_adjusted_balance_minor: cw_balance,
            }])
        )
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

    #[test]
    fn adjust_multiple_for_service_fee_only_runner_is_not_supposed_to_care_about_transaction_fee() {
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
        let accounts = vec![account_1, account_2];
        let qualified_payables =
            make_guaranteed_qualified_payables(accounts, &payment_thresholds, now);
        let adjustment = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let mut payment_adjuster = PaymentAdjusterReal::new();
        let cw_balance = 10_000_000_000;
        payment_adjuster.initialize_inner(cw_balance, adjustment, now);
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let criteria_and_accounts =
            payment_adjuster.calculate_weights_for_accounts(qualified_payables);

        let result = subject.adjust_multiple(&mut payment_adjuster, criteria_and_accounts);

        let returned_accounts = result
            .into_iter()
            .map(|account| account.original_qualified_account.payable.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts, vec![wallet_1, wallet_2])
        // If the transaction fee adjustment had been available to perform, only one account would've been
        // returned. This test passes
    }

    #[test]
    fn empty_or_single_element_vector_for_none() {
        let result = empty_or_single_element_vector(None);

        assert_eq!(result, vec![])
    }

    #[test]
    fn empty_or_single_element_vector_for_some() {
        let account_info = AdjustedAccountBeforeFinalization {
            original_qualified_account: make_non_guaranteed_qualified_payable(123),
            proposed_adjusted_balance_minor: 123_456_789,
        };
        let result = empty_or_single_element_vector(Some(account_info.clone()));

        assert_eq!(result, vec![account_info])
    }
}
