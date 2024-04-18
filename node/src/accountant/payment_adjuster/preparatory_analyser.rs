// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    log_adjustment_by_service_fee_is_required, log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    TransactionCountsBy16bits, TransactionFeeLimitation, TransactionFeePastActionsContext,
    WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{Adjustment, AdjustmentAnalysis, PaymentAdjusterError};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use ethereum_types::U256;
use futures::collect;
use itertools::{Either, Product};
use masq_lib::logger::Logger;
use std::cmp::Ordering;

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
    ) -> Result<Option<TransactionFeeLimitation>, PaymentAdjusterError> {
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
            let transaction_fee_limitation_opt = todo!();
            Ok(Some(transaction_fee_limitation_opt))
        }
    }

    fn transaction_counts_verification(
        cw_transaction_fee_balance_minor: U256,
        txn_fee_required_per_txn_minor: u128,
        number_of_qualified_accounts: usize,
    ) -> TransactionCountsBy16bits {
        let max_possible_tx_count_u256 =
            cw_transaction_fee_balance_minor / U256::from(txn_fee_required_per_txn_minor);

        TransactionCountsBy16bits::new(max_possible_tx_count_u256, number_of_qualified_accounts)
    }

    pub fn check_need_of_adjustment_by_service_fee<IncomingAccount, AnalyzedAccount>(
        &self,
        disqualification_arbiter: &DisqualificationArbiter,
        transaction_fee_past_actions_context: TransactionFeePastActionsContext,
        payables: Vec<IncomingAccount>,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> Result<Either<Vec<IncomingAccount>, Vec<AnalyzedAccount>>, PaymentAdjusterError>
    where
        IncomingAccount: DisqualificationAnalysableAccount<AnalyzedAccount>,
        AnalyzedAccount: BalanceProvidingAccount + DisqualificationLimitProvidingAccount,
    {
        let required_service_fee_total =
            Self::compute_total_of_service_fee_required::<IncomingAccount>(&payables);

        if cw_service_fee_balance_minor >= required_service_fee_total {
            Ok(Either::Left(payables))
        } else {
            let prepared_accounts = Self::prepare_accounts_with_disqualification_limits(
                payables,
                disqualification_arbiter,
            );

            let lowest_disqualification_limit =
                Self::find_lowest_disqualification_limit(&prepared_accounts);

            Self::analyse_lowest_adjustment_possibility(
                transaction_fee_past_actions_context,
                lowest_disqualification_limit,
                cw_service_fee_balance_minor,
            )?;

            log_adjustment_by_service_fee_is_required(
                logger,
                required_service_fee_total,
                cw_service_fee_balance_minor,
            );

            Ok(Either::Right(prepared_accounts))
        }
    }

    fn compute_total_of_service_fee_required<Account>(payables: &[Account]) -> u128
    where
        Account: BalanceProvidingAccount,
    {
        sum_as(payables, |account| account.balance_minor())
    }

    fn prepare_accounts_with_disqualification_limits<Account, Product>(
        accounts: Vec<Account>,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> Vec<Product>
    where
        Account: DisqualificationAnalysableAccount<Product>,
        Product: BalanceProvidingAccount + DisqualificationLimitProvidingAccount,
    {
        accounts
            .into_iter()
            .map(|account| account.prepare_analyzable_account(disqualification_arbiter))
            .collect()
    }

    fn find_lowest_disqualification_limit<Account>(accounts: &[Account]) -> u128
    where
        Account: DisqualificationLimitProvidingAccount,
    {
        todo!()
    }

    // We cannot do much in this area but stepping in if the cw balance is zero or nearly zero with
    // the assumption that the debt with the lowest disqualification limit in the set fits in the
    // available balance. If it doesn't, we're not going to bother the payment adjuster by that work,
    // so it'll abort and no payments will come out.
    fn analyse_lowest_adjustment_possibility(
        transaction_fee_past_actions_context: TransactionFeePastActionsContext,
        lowest_disqualification_limit: u128,
        cw_service_fee_balance_minor: u128,
    ) -> Result<(), PaymentAdjusterError> {
        if lowest_disqualification_limit <= cw_service_fee_balance_minor {
            Ok(())
        } else {
            let (number_of_accounts, total_amount_demanded_minor, transaction_fee_appendix_opt): (
                usize,
                u128,
                Option<TransactionFeeLimitation>,
            ) = match transaction_fee_past_actions_context {
                TransactionFeePastActionsContext::TransactionFeeCheckDone { limitation_opt } => {
                    todo!()
                }
                TransactionFeePastActionsContext::TransactionFeeAccountsDumped {
                    past_txs_count: txs_count,
                    past_sum_of_service_fee_balances: sum_of_transaction_fee_balances,
                } => todo!(),
            };

            // if let Some(info) = summary_for_potential_error_opt {
            //     (info.count, info.sum_of_balances)
            // } else {
            //     let required_service_fee_total =
            //         sum_as(&prepared_accounts, |account| account.balance_minor());
            //     (prepared_accounts.len(), required_service_fee_total)
            // };
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts,
                    total_amount_demanded_minor,
                    cw_service_fee_balance_minor,
                    appendix_opt: transaction_fee_appendix_opt,
                },
            )
        }
    }
}

pub trait DisqualificationAnalysableAccount<Product>: BalanceProvidingAccount
where
    Product: BalanceProvidingAccount + DisqualificationLimitProvidingAccount,
{
    // fn process_findings(insufficiency_found: bool)->
    fn prepare_analyzable_account(
        self,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> Product;
}

pub trait BalanceProvidingAccount {
    fn balance_minor(&self) -> u128;
}

pub trait DisqualificationLimitProvidingAccount {
    fn disqualification_limit(&self) -> u128;
}

impl DisqualificationAnalysableAccount<AnalyzedPayableAccount> for QualifiedPayableAccount {
    fn prepare_analyzable_account(
        self,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> AnalyzedPayableAccount {
        let dsq_limit = disqualification_arbiter.calculate_disqualification_edge(&self);
        AnalyzedPayableAccount::new(self, dsq_limit)
    }
}

impl BalanceProvidingAccount for QualifiedPayableAccount {
    fn balance_minor(&self) -> u128 {
        self.bare_account.balance_wei
    }
}

impl BalanceProvidingAccount for AnalyzedPayableAccount {
    fn balance_minor(&self) -> u128 {
        todo!()
    }
}

impl DisqualificationLimitProvidingAccount for WeightedPayable {
    fn disqualification_limit(&self) -> u128 {
        todo!()
    }
}

impl DisqualificationAnalysableAccount<WeightedPayable> for WeightedPayable {
    fn prepare_analyzable_account(
        self,
        _disqualification_arbiter: &DisqualificationArbiter,
    ) -> WeightedPayable {
        self
    }
}

impl BalanceProvidingAccount for WeightedPayable {
    fn balance_minor(&self) -> u128 {
        self.analyzed_account.qualified_as.bare_account.balance_wei
    }
}

impl DisqualificationLimitProvidingAccount for AnalyzedPayableAccount {
    fn disqualification_limit(&self) -> u128 {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::TransactionFeePastActionsContext;
    use crate::accountant::payment_adjuster::preparatory_analyser::PreparatoryAnalyzer;
    use crate::accountant::payment_adjuster::test_utils::{
        make_weighed_account, multiple_by_billion, DisqualificationGaugeMock,
    };
    use crate::accountant::payment_adjuster::PaymentAdjusterError;
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::convert_collection;
    use std::sync::{Arc, Mutex};

    fn test_adjustment_possibility_nearly_rejected(
        test_name: &str,
        disqualification_gauge: DisqualificationGaugeMock,
        original_accounts: [QualifiedPayableAccount; 2],
        cw_service_fee_balance: u128,
    ) {
        init_test_logging();
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let disqualification_gauge =
            disqualification_gauge.determine_limit_params(&determine_limit_params_arc);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = PreparatoryAnalyzer {};
        let service_fee_error_context =
            TransactionFeePastActionsContext::accounts_dumped_context(&vec![]);

        let result = subject.check_need_of_adjustment_by_service_fee(
            &disqualification_arbiter,
            service_fee_error_context,
            original_accounts.clone().to_vec(),
            cw_service_fee_balance,
            &Logger::new(test_name),
        );

        let expected_analyzed_accounts = convert_collection(original_accounts.to_vec());
        assert_eq!(result, Ok(Either::Right(expected_analyzed_accounts)));
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        let account_1 = &original_accounts[0];
        let account_2 = &original_accounts[1];
        let expected_params = vec![
            (
                account_1.bare_account.balance_wei,
                account_1.payment_threshold_intercept_minor,
                account_1.creditor_thresholds.permanent_debt_allowed_minor,
            ),
            (
                account_2.bare_account.balance_wei,
                account_2.payment_threshold_intercept_minor,
                account_2.creditor_thresholds.permanent_debt_allowed_minor,
            ),
        ];
        assert_eq!(*determine_limit_params, expected_params);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Total of \
        blah wei in MASQ was ordered while the consuming wallet held only bluh wei of \
        the MASQ token. Adjustment in their count or the amounts is required."
        ));
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

        test_adjustment_possibility_nearly_rejected(
            "adjustment_possibility_nearly_rejected_when_cw_balance_slightly_bigger",
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

        test_adjustment_possibility_nearly_rejected(
            "adjustment_possibility_nearly_rejected_when_cw_balance_equal",
            disqualification_gauge,
            original_accounts,
            cw_service_fee_balance,
        )
    }

    #[test]
    fn insufficient_balance_for_even_the_least_demanding_account_causes_error() {
        let mut account_1 = make_non_guaranteed_qualified_payable(111);
        account_1.bare_account.balance_wei = 2_000_000_000;
        let mut account_2 = make_non_guaranteed_qualified_payable(222);
        account_2.bare_account.balance_wei = 1_000_050_000;
        let mut account_3 = make_non_guaranteed_qualified_payable(333);
        account_3.bare_account.balance_wei = 1_000_111_111;
        let cw_service_fee_balance = 1_000_000_100;
        let original_accounts = vec![account_1, account_2, account_3];
        let required_fee_total = 2_000_000_000 + 1_000_050_000 + 1_000_111_111;
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(1_500_000_000)
            .determine_limit_result(1_000_000_101)
            .determine_limit_result(1_000_000_222);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let transaction_fee_past_actions_context =
            TransactionFeePastActionsContext::TransactionFeeCheckDone {
                limitation_opt: None,
            };
        let subject = PreparatoryAnalyzer {};

        let result = subject.check_need_of_adjustment_by_service_fee(
            &disqualification_arbiter,
            transaction_fee_past_actions_context,
            original_accounts,
            cw_service_fee_balance,
            &Logger::new("test"),
        );

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: required_fee_total,
                    cw_service_fee_balance_minor: cw_service_fee_balance,
                    appendix_opt: None,
                }
            )
        )
    }

    #[test]
    fn accounts_analyzing_works_even_for_weighted_payable() {
        let weighted_account_1 = make_weighed_account(123);
        let weighted_account_2 = make_weighed_account(456);
        let accounts = vec![weighted_account_1, weighted_account_2];
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(DisqualificationGaugeMock::default()));

        let analyzed_accounts = PreparatoryAnalyzer::prepare_accounts_with_disqualification_limits(
            accounts.clone(),
            &disqualification_arbiter,
        );

        assert_eq!(analyzed_accounts, accounts)
    }

    #[test]
    fn fold_for_find_lowest_weight_and_prepare_accounts_to_proceed_starts_with_u128_max() {
        let accounts: Vec<AnalyzedPayableAccount> = vec![];

        let minimal_disqualification_limit =
            PreparatoryAnalyzer::find_lowest_disqualification_limit(&accounts);

        assert_eq!(minimal_disqualification_limit, u128::MAX);
    }
}
