// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics;
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, UnconfirmedAdjustment, WeightedAccount,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::try_finding_an_account_to_disqualify_in_this_iteration;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;
use std::vec;
use crate::accountant::QualifiedPayableAccount;

// There are just two runners. Different by the adjustment they can perform, either adjusting by
// both the transaction fee and service fee, or exclusively by the transaction fee. The idea is
// that the adjustment by the transaction fee may ever appear in the initial iteration of
// the recursion. In any of the next iterations, if it proceed that far, this feature would be
// staying around useless. Therefor the runner with more features is used only at the beginning.
// Its speciality is that it allows also to short-circuit the weights computation for accounts,
// because it can detect that after some dropped accounts due to the transaction fee scarcity
// another adjustment, by the service fee, is not needed and therefore there is no point in going
// through any extra assessment. Mostly for the things just described each runner provides
// a different result type.
pub trait AdjustmentRunner {
    type ReturnType;

    // This specialized method:
    // a) helps with writing tests that target edge cases,
    // b) allows to avoid performing unnecessary computation for an evident result
    fn adjust_last_one(
        &self,
        payment_adjuster: &PaymentAdjusterReal,
        last_account: PayableAccount,
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
        last_account: PayableAccount,
    ) -> Self::ReturnType {
        Ok(Either::Left(empty_or_single_element_vector(
            adjust_last_one_opt(payment_adjuster, last_account),
        )))
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
        last_account: PayableAccount,
    ) -> Self::ReturnType {
        empty_or_single_element_vector(adjust_last_one_opt(payment_adjuster, last_account))
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

fn adjust_last_one_opt(
    payment_adjuster: &PaymentAdjusterReal,
    last_account: PayableAccount,
) -> Option<AdjustedAccountBeforeFinalization> {
    let cw_balance = payment_adjuster
        .inner
        .unallocated_cw_service_fee_balance_minor();
    let proposed_adjusted_balance = if last_account.balance_wei.checked_sub(cw_balance) == None {
        last_account.balance_wei
    } else {
        diagnostics!(
            "LAST REMAINING ACCOUNT",
            "Balance adjusted to {} by exhausting the cw balance fully",
            cw_balance
        );

        cw_balance
    };
    let mut proposed_adjustment_vec = vec![UnconfirmedAdjustment::new(
        WeightedAccount::new(last_account, u128::MAX), // The weight doesn't matter really and is made up
        proposed_adjusted_balance,
    )];

    let logger = &payment_adjuster.logger;

    match try_finding_an_account_to_disqualify_in_this_iteration(&proposed_adjustment_vec, logger) {
        Some(_) => None,
        None => Some(proposed_adjustment_vec.remove(0).non_finalized_account),
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
        adjust_last_one_opt, empty_or_single_element_vector, AdjustmentRunner,
        ServiceFeeOnlyAdjustmentRunner, TransactionAndServiceFeeAdjustmentRunner,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustedAccountBeforeFinalization;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::calculate_disqualification_edge;
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use std::fmt::Debug;
    use std::time::{Duration, SystemTime};
    use crate::accountant::QualifiedPayableAccount;

    fn prepare_payment_adjuster(cw_balance: u128, now: SystemTime) -> PaymentAdjusterReal {
        let adjustment = Adjustment::ByServiceFee;
        let mut payment_adjuster = PaymentAdjusterReal::new();
        payment_adjuster.initialize_inner(cw_balance.into(), adjustment, now);
        payment_adjuster
    }

    fn test_adjust_last_one<AR, RT>(
        subject: AR,
        expected_return_type_finalizer: fn(Vec<AdjustedAccountBeforeFinalization>) -> RT,
    ) where
        AR: AdjustmentRunner<ReturnType = RT>,
        RT: Debug + PartialEq,
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
    fn adjust_last_one_for_requested_balance_smaller_than_cw_but_not_needed_disqualified() {
        let now = SystemTime::now();
        let account_balance = 4_500_600;
        let cw_balance = calculate_disqualification_edge(account_balance) + 1;
        let account = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: account_balance,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let payment_adjuster = prepare_payment_adjuster(cw_balance, now);

        let result = adjust_last_one_opt(&payment_adjuster, account.clone());

        assert_eq!(
            result,
            Some(AdjustedAccountBeforeFinalization {
                original_account: account,
                proposed_adjusted_balance: cw_balance,
            })
        )
    }

    fn test_adjust_last_one_when_disqualified(cw_balance: u128, account_balance: u128) {
        let now = SystemTime::now();
        let account = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: account_balance,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(2_500)).unwrap(),
            pending_payable_opt: None,
        };
        let payment_adjuster = prepare_payment_adjuster(cw_balance, now);

        let result = adjust_last_one_opt(&payment_adjuster, account.clone());

        assert_eq!(result, None)
    }

    #[test]
    fn account_facing_much_smaller_cw_balance_hits_disqualification_when_adjustment_evens_the_edge()
    {
        let account_balance = 4_000_444;
        let cw_balance = calculate_disqualification_edge(account_balance);

        test_adjust_last_one_when_disqualified(cw_balance, account_balance)
    }

    #[test]
    fn account_facing_much_smaller_cw_balance_hits_disqualification_when_adjustment_slightly_under()
    {
        let account_balance = 4_000_444;
        let cw_balance = calculate_disqualification_edge(account_balance) - 1;

        test_adjust_last_one_when_disqualified(cw_balance, account_balance)
    }

    #[test]
    fn adjust_multiple_for_service_fee_only_runner_is_not_supposed_to_care_about_transaction_fee() {
        let now = SystemTime::now();
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
        let adjustment = Adjustment::TransactionFeeInPriority {
            affordable_transaction_count: 1,
        };
        let mut payment_adjuster = PaymentAdjusterReal::new();
        let cw_balance = 9_000_000;
        payment_adjuster.initialize_inner(cw_balance, adjustment, now);
        let subject = ServiceFeeOnlyAdjustmentRunner {};
        let criteria_and_accounts = payment_adjuster.calculate_weights_for_accounts(accounts);

        let result = subject.adjust_multiple(&mut payment_adjuster, criteria_and_accounts);

        let returned_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
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
            original_account: make_payable_account(123),
            proposed_adjusted_balance: 123_456_789,
        };
        let result = empty_or_single_element_vector(Some(account_info.clone()));

        assert_eq!(result, vec![account_info])
    }
}
