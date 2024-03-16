// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::log_fns::{
    log_adjustment_by_service_fee_is_required, log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    TransactionCountsWithin16bits, WeightedAccount,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    calculate_disqualification_edge, sum_as,
};
use crate::accountant::payment_adjuster::PaymentAdjusterError;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::QualifiedPayableAccount;
use ethereum_types::U256;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;

pub struct PreAdjustmentAnalyzer {}

impl PreAdjustmentAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn determine_transaction_count_limit_by_transaction_fee(
        &self,
        agent: &dyn BlockchainAgent,
        number_of_qualified_accounts: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, PaymentAdjusterError> {
        let cw_transaction_fee_balance_minor = agent.transaction_fee_balance_minor();
        let per_transaction_requirement_minor =
            agent.estimated_transaction_fee_per_transaction_minor();

        let max_possible_tx_count = Self::max_possible_tx_count(
            cw_transaction_fee_balance_minor,
            per_transaction_requirement_minor,
        );

        let detected_tx_counts =
            TransactionCountsWithin16bits::new(max_possible_tx_count, number_of_qualified_accounts);

        let max_tx_count_we_can_afford_u16 = detected_tx_counts.affordable;
        let required_tx_count_u16 = detected_tx_counts.required;

        if max_tx_count_we_can_afford_u16 == 0 {
            Err(
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: number_of_qualified_accounts,
                    per_transaction_requirement_minor,
                    cw_transaction_fee_balance_minor,
                },
            )
        } else if max_tx_count_we_can_afford_u16 >= required_tx_count_u16 {
            Ok(None)
        } else {
            log_insufficient_transaction_fee_balance(
                logger,
                required_tx_count_u16,
                cw_transaction_fee_balance_minor,
                max_tx_count_we_can_afford_u16,
            );
            Ok(Some(max_tx_count_we_can_afford_u16))
        }
    }

    fn max_possible_tx_count(
        cw_transaction_fee_balance_minor: U256,
        tx_fee_requirement_per_tx_minor: u128,
    ) -> u128 {
        let max_possible_tx_count_u256 =
            cw_transaction_fee_balance_minor / U256::from(tx_fee_requirement_per_tx_minor);
        u128::try_from(max_possible_tx_count_u256).unwrap_or_else(|e| {
            panic!(
                "Transaction fee balance {} wei in the consuming wallet cases panic given estimated \
                    transaction fee per tx {} wei and resulting ratio {}, that should fit in u128, \
                    respectively: \"{}\"",
                cw_transaction_fee_balance_minor,
                tx_fee_requirement_per_tx_minor,
                max_possible_tx_count_u256,
                e
            )
        })
    }

    pub fn check_need_of_adjustment_by_service_fee(
        &self,
        logger: &Logger,
        payables: Either<&[QualifiedPayableAccount], &[WeightedAccount]>,
        cw_service_fee_balance_minor: u128,
    ) -> Result<bool, PaymentAdjusterError> {
        let qualified_payables: Vec<&PayableAccount> = match payables {
            Either::Left(accounts) => accounts
                .iter()
                .map(|qualified_payable| &qualified_payable.payable)
                .collect(),
            Either::Right(weighted_accounts) => weighted_accounts
                .iter()
                .map(|weighted_account| &weighted_account.qualified_account.payable)
                .collect(),
        };

        let required_service_fee_sum: u128 =
            sum_as(&qualified_payables, |account: &&PayableAccount| {
                account.balance_wei
            });

        if cw_service_fee_balance_minor >= required_service_fee_sum {
            Ok(false)
        } else {
            TransactionFeeAdjustmentPossibilityVerifier {}
                .verify_lowest_detectable_adjustment_possibility(
                    &qualified_payables,
                    cw_service_fee_balance_minor,
                )?;

            log_adjustment_by_service_fee_is_required(
                logger,
                required_service_fee_sum,
                cw_service_fee_balance_minor,
            );
            Ok(true)
        }
    }
}

pub struct TransactionFeeAdjustmentPossibilityVerifier {}

impl TransactionFeeAdjustmentPossibilityVerifier {
    // We cannot do much in this area, only step in if the balance can be zero or nearly zero by
    // assumption we make about the smallest debt in the set and the disqualification limit applied
    // on it. If so, we don't want to bother payment adjuster and so we will abort instead.
    pub fn verify_lowest_detectable_adjustment_possibility(
        &self,
        accounts: &[&PayableAccount],
        cw_service_fee_balance_minor: u128,
    ) -> Result<(), PaymentAdjusterError> {
        let sorted = accounts
            .iter()
            .sorted_by(|account_a, account_b| {
                Ord::cmp(&account_a.balance_wei, &account_b.balance_wei)
            })
            .collect::<Vec<_>>();
        let smallest_account = sorted.first().expect("should be one at minimum");

        if calculate_disqualification_edge(smallest_account.balance_wei)
            <= cw_service_fee_balance_minor
        {
            Ok(())
        } else {
            let total_amount_demanded_minor = sum_as(accounts, |account| account.balance_wei);
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: accounts.len(),
                    total_amount_demanded_minor,
                    cw_service_fee_balance_minor,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::calculate_disqualification_edge;
    use crate::accountant::payment_adjuster::pre_adjustment_analyzer::{
        PreAdjustmentAnalyzer, TransactionFeeAdjustmentPossibilityVerifier,
    };
    use crate::accountant::payment_adjuster::PaymentAdjusterError;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::test_utils::make_payable_account;
    use ethereum_types::U256;
    use masq_lib::logger::Logger;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn tx_fee_check_panics_on_ration_between_tx_fee_balance_and_estimated_tx_fee_bigger_than_u128()
    {
        let deadly_ratio = U256::from(u128::MAX) + 1;
        let estimated_transaction_fee_per_one_tx_minor = 123_456_789;
        let critical_wallet_balance =
            deadly_ratio * U256::from(estimated_transaction_fee_per_one_tx_minor);
        let blockchain_agent = BlockchainAgentMock::default()
            .estimated_transaction_fee_per_transaction_minor_result(
                estimated_transaction_fee_per_one_tx_minor,
            )
            .transaction_fee_balance_minor_result(critical_wallet_balance);
        let subject = PreAdjustmentAnalyzer::new();

        let panic_err = catch_unwind(AssertUnwindSafe(|| {
            subject.determine_transaction_count_limit_by_transaction_fee(
                &blockchain_agent,
                123,
                &Logger::new("test"),
            )
        }))
        .unwrap_err();

        let err_msg = panic_err.downcast_ref::<String>().unwrap();
        let expected_panic = format!(
            "Transaction fee balance {} wei in the consuming wallet cases panic given estimated \
            transaction fee per tx {} wei and resulting ratio {}, that should fit in u128, \
            respectively: \"integer overflow when casting to u128\"",
            critical_wallet_balance, estimated_transaction_fee_per_one_tx_minor, deadly_ratio
        );
        assert_eq!(err_msg, &expected_panic)
    }

    fn test_body_for_adjustment_possibility_nearly_rejected(
        original_accounts: Vec<PayableAccount>,
        cw_service_fee_balance: u128,
    ) {
        let accounts_in_expected_format =
            original_accounts.iter().collect::<Vec<&PayableAccount>>();
        let subject = TransactionFeeAdjustmentPossibilityVerifier {};

        let result = subject.verify_lowest_detectable_adjustment_possibility(
            &accounts_in_expected_format,
            cw_service_fee_balance,
        );

        assert_eq!(result, Ok(()))
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_one_more() {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(333);
        account_2.balance_wei = 1_000_000_000;
        let cw_service_fee_balance = calculate_disqualification_edge(account_2.balance_wei) + 1;
        let original_accounts = vec![account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_equal() {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(333);
        account_2.balance_wei = 1_000_000_000;
        let cw_service_fee_balance = calculate_disqualification_edge(account_2.balance_wei);
        let original_accounts = vec![account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn adjustment_possibility_err_from_insufficient_balance_for_at_least_single_account_adjustment()
    {
        let mut account_1 = make_payable_account(111);
        account_1.balance_wei = 2_000_000_000;
        let mut account_2 = make_payable_account(222);
        account_2.balance_wei = 2_000_000_002;
        let mut account_3 = make_payable_account(333);
        account_3.balance_wei = 1_000_000_002;
        let cw_service_fee_balance = calculate_disqualification_edge(account_3.balance_wei) - 1;
        let original_accounts = vec![account_1, account_2, account_3];
        let accounts_in_expected_format =
            original_accounts.iter().collect::<Vec<&PayableAccount>>();
        let subject = TransactionFeeAdjustmentPossibilityVerifier {};

        let result = subject.verify_lowest_detectable_adjustment_possibility(
            &accounts_in_expected_format,
            cw_service_fee_balance,
        );

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: 2_000_000_000 + 2_000_000_002 + 1_000_000_002,
                    cw_service_fee_balance_minor: cw_service_fee_balance
                }
            )
        )
    }
}
