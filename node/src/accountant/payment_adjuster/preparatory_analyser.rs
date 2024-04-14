// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    log_adjustment_by_service_fee_is_required, log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    TransactionCountsWithin16bits, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::PaymentAdjusterError;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::QualifiedPayableAccount;
use ethereum_types::U256;
use itertools::Either;
use masq_lib::logger::Logger;

pub struct PreparatoryAnalyzer {}

impl PreparatoryAnalyzer {
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

        let verified_tx_counts = Self::transaction_counts_verification(
            cw_transaction_fee_balance_minor,
            per_transaction_requirement_minor,
            number_of_qualified_accounts,
        );

        let max_tx_count_we_can_afford_u16 = verified_tx_counts.affordable;
        let required_tx_count_u16 = verified_tx_counts.required;

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

    fn transaction_counts_verification(
        cw_transaction_fee_balance_minor: U256,
        fee_requirement_per_tx_minor: u128,
        number_of_qualified_accounts: usize,
    ) -> TransactionCountsWithin16bits {
        let max_possible_tx_count_u256 = Self::max_possible_tx_count(
            cw_transaction_fee_balance_minor,
            fee_requirement_per_tx_minor,
        );
        TransactionCountsWithin16bits::new(max_possible_tx_count_u256, number_of_qualified_accounts)
    }

    fn max_possible_tx_count(
        cw_transaction_fee_balance_minor: U256,
        fee_requirement_per_tx_minor: u128,
    ) -> U256 {
        cw_transaction_fee_balance_minor / U256::from(fee_requirement_per_tx_minor)
    }

    pub fn check_need_of_adjustment_by_service_fee(
        &self,
        disqualification_arbiter: &DisqualificationArbiter,
        payables: Either<&[QualifiedPayableAccount], &[WeightedPayable]>,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> Result<bool, PaymentAdjusterError> {
        let qualified_payables = Self::comb_qualified_payables(payables);

        let required_service_fee_sum: u128 =
            sum_as(&qualified_payables, |qa| qa.bare_account.balance_wei);

        if cw_service_fee_balance_minor >= required_service_fee_sum {
            Ok(false)
        } else {
            self.analyse_smallest_adjustment_possibility(
                disqualification_arbiter,
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

    fn comb_qualified_payables<'payables>(
        payables: Either<&'payables [QualifiedPayableAccount], &'payables [WeightedPayable]>,
    ) -> Vec<&'payables QualifiedPayableAccount> {
        match payables {
            Either::Left(accounts) => accounts.iter().collect(),
            Either::Right(weighted_accounts) => weighted_accounts
                .iter()
                .map(|weighted_account| &weighted_account.qualified_account)
                .collect(),
        }
    }

    // We cannot do much in this area but stepping in if the cw balance is zero or nearly zero with
    // the assumption that the debt with the lowest disqualification limit in the set fits in the
    // available balance. If it doesn't, we won't want to bother the payment adjuster by its work,
    // so we'll abort and no payments will come out.
    fn analyse_smallest_adjustment_possibility(
        &self,
        disqualification_arbiter: &DisqualificationArbiter,
        qualified_payables: &[&QualifiedPayableAccount],
        cw_service_fee_balance_minor: u128,
    ) -> Result<(), PaymentAdjusterError> {
        let lowest_disqualification_limit =
            Self::find_lowest_dsq_limit(qualified_payables, disqualification_arbiter);

        if lowest_disqualification_limit <= cw_service_fee_balance_minor {
            Ok(())
        } else {
            let total_amount_demanded_minor =
                sum_as(qualified_payables, |qp| qp.bare_account.balance_wei);
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: qualified_payables.len(),
                    total_amount_demanded_minor,
                    cw_service_fee_balance_minor,
                },
            )
        }
    }

    fn find_lowest_dsq_limit(
        qualified_payables: &[&QualifiedPayableAccount],
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> u128 {
        qualified_payables
            .iter()
            .map(|account| disqualification_arbiter.calculate_disqualification_edge(account))
            .fold(u128::MAX, |lowest_so_far, limit| lowest_so_far.min(limit))
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::preparatory_analyser::PreparatoryAnalyzer;
    use crate::accountant::payment_adjuster::test_utils::DisqualificationGaugeMock;
    use crate::accountant::payment_adjuster::PaymentAdjusterError;
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use crate::accountant::QualifiedPayableAccount;
    use std::sync::{Arc, Mutex};

    #[test]
    fn find_lowest_dsq_limit_begins_at_u128_max() {
        let disqualification_arbiter = DisqualificationArbiter::default();
        let result = PreparatoryAnalyzer::find_lowest_dsq_limit(&[], &disqualification_arbiter);

        assert_eq!(result, u128::MAX)
    }

    #[test]
    fn find_lowest_dsq_limit_when_multiple_accounts_with_the_same_limit() {
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(200_000_000)
            .determine_limit_result(200_000_000);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let account_1 = make_non_guaranteed_qualified_payable(111);
        let account_2 = make_non_guaranteed_qualified_payable(222);
        let accounts = vec![&account_1, &account_2];

        let result =
            PreparatoryAnalyzer::find_lowest_dsq_limit(&accounts, &disqualification_arbiter);

        assert_eq!(result, 200_000_000)
    }

    fn test_body_for_adjustment_possibility_nearly_rejected(
        disqualification_gauge: DisqualificationGaugeMock,
        original_accounts: [QualifiedPayableAccount; 2],
        cw_service_fee_balance: u128,
    ) {
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let disqualification_gauge =
            disqualification_gauge.determine_limit_params(&determine_limit_params_arc);
        let accounts_in_expected_format = original_accounts
            .iter()
            .collect::<Vec<&QualifiedPayableAccount>>();
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = PreparatoryAnalyzer {};

        let result = subject.analyse_smallest_adjustment_possibility(
            &disqualification_arbiter,
            &accounts_in_expected_format,
            cw_service_fee_balance,
        );

        assert_eq!(result, Ok(()));
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        let account_1 = &original_accounts[0];
        let account_2 = &original_accounts[1];
        assert_eq!(
            *determine_limit_params,
            vec![
                (
                    account_1.bare_account.balance_wei,
                    account_1.payment_threshold_intercept_minor,
                    account_1.creditor_thresholds.permanent_debt_allowed_wei
                ),
                (
                    account_2.bare_account.balance_wei,
                    account_2.payment_threshold_intercept_minor,
                    account_2.creditor_thresholds.permanent_debt_allowed_wei
                )
            ]
        )
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_slightly_bigger() {
        let mut account_1 = make_non_guaranteed_qualified_payable(111);
        account_1.bare_account.balance_wei = 1_000_000_000;
        let mut account_2 = make_non_guaranteed_qualified_payable(333);
        account_2.bare_account.balance_wei = 2_000_000_000;
        let cw_service_fee_balance = 750_000_001;
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(750_000_000)
            .determine_limit_result(1_500_000_000);
        let original_accounts = [account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(
            disqualification_gauge,
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn adjustment_possibility_nearly_rejected_when_cw_balance_equal() {
        let mut account_1 = make_non_guaranteed_qualified_payable(111);
        account_1.bare_account.balance_wei = 2_000_000_000;
        let mut account_2 = make_non_guaranteed_qualified_payable(333);
        account_2.bare_account.balance_wei = 1_000_000_000;
        let cw_service_fee_balance = 750_000_000;
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(1_500_000_000)
            .determine_limit_result(750_000_000);
        let original_accounts = [account_1, account_2];

        test_body_for_adjustment_possibility_nearly_rejected(
            disqualification_gauge,
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn adjustment_possibility_err_from_insufficient_balance_for_even_the_least_demanding_account() {
        let mut account_1 = make_non_guaranteed_qualified_payable(111);
        account_1.bare_account.balance_wei = 2_000_000_000;
        let mut account_2 = make_non_guaranteed_qualified_payable(222);
        account_2.bare_account.balance_wei = 1_000_050_000;
        let mut account_3 = make_non_guaranteed_qualified_payable(333);
        account_3.bare_account.balance_wei = 1_000_111_111;
        let cw_service_fee_balance = 1_000_000_100;
        let original_accounts = vec![account_1, account_2, account_3];
        let accounts_in_expected_format = original_accounts
            .iter()
            .collect::<Vec<&QualifiedPayableAccount>>();
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(1_500_000_000)
            .determine_limit_result(1_000_000_101)
            .determine_limit_result(1_000_000_222);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = PreparatoryAnalyzer {};

        let result = subject.analyse_smallest_adjustment_possibility(
            &disqualification_arbiter,
            &accounts_in_expected_format,
            cw_service_fee_balance,
        );

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: 2_000_000_000 + 1_000_050_000 + 1_000_111_111,
                    cw_service_fee_balance_minor: cw_service_fee_balance
                }
            )
        )
    }
}
