// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::miscellaneous::data_sructures::AdjustedAccountBeforeFinalization;
use crate::accountant::payment_adjuster::{PaymentAdjusterError, PaymentAdjusterReal};
use itertools::Either;

pub trait AdjustmentRunner {
    type ReturnType;

    fn adjust(
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

    fn adjust(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
    ) -> Self::ReturnType {
        match payment_adjuster.inner.transaction_fee_count_limit_opt() {
            Some(limit) => {
                return payment_adjuster.begin_with_adjustment_by_transaction_fees(
                    criteria_and_accounts_in_descending_order,
                    limit,
                )
            }
            None => (),
        };

        Ok(Either::Left(
            payment_adjuster
                .propose_adjustment_recursively(criteria_and_accounts_in_descending_order),
        ))
    }
}

pub struct MasqOnlyRunner {}

impl AdjustmentRunner for MasqOnlyRunner {
    type ReturnType = Vec<AdjustedAccountBeforeFinalization>;

    fn adjust(
        &self,
        payment_adjuster: &mut PaymentAdjusterReal,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
    ) -> Self::ReturnType {
        payment_adjuster.propose_adjustment_recursively(criteria_and_accounts_in_descending_order)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::{
        AdjustmentRunner, MasqOnlyRunner,
    };
    use crate::accountant::payment_adjuster::{Adjustment, PaymentAdjusterReal};
    use crate::accountant::scanners::payable_scan_setup_msgs::FinancialAndTechDetails;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use std::time::{Duration, SystemTime};

    #[test]
    fn masq_only_adjuster_is_not_meant_to_adjust_also_by_transaction_fee() {
        let now = SystemTime::now();
        let cw_balance = 9_000_000;
        let details = FinancialAndTechDetails {
            consuming_wallet_balances: ConsumingWalletBalances {
                transaction_fee_minor: 0,
                masq_tokens_minor: cw_balance,
            },
            desired_transaction_fee_price_major: 30,
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
        let seeds = payment_adjuster.calculate_criteria_sums_for_accounts(accounts);
        let adjustment_runner = MasqOnlyRunner {};

        let result = adjustment_runner.adjust(&mut payment_adjuster, seeds);

        let returned_accounts_accounts = result
            .into_iter()
            .map(|account| account.original_account.wallet)
            .collect::<Vec<Wallet>>();
        assert_eq!(returned_accounts_accounts, vec![wallet_1, wallet_2])
        //if the transaction_fee adjustment had been available, only one account would've been returned, the test passes
    }
}
