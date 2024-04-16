// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    log_adjustment_by_service_fee_is_required, log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    ServiceFeeCheckErrorContext, TransactionCountsWithin16bits, TransactionFeeLimitation,
    WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::sum_as;
use crate::accountant::payment_adjuster::{Adjustment, AdjustmentAnalysis, PaymentAdjusterError};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use ethereum_types::U256;
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
            let limitation = todo!();
            Ok(Some(limitation))
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

    pub fn check_need_of_adjustment_by_service_fee<
        MidProduct,
        IncomingAccount,
        AdjustmentNeededValue,
    >(
        &self,
        disqualification_arbiter: &DisqualificationArbiter,
        error_context: ServiceFeeCheckErrorContext,
        payables: Vec<IncomingAccount>,
        cw_service_fee_balance_minor: u128,
        logger: &Logger,
    ) -> Result<Either<Vec<IncomingAccount>, AdjustmentNeededValue>, PaymentAdjusterError>
    where
        IncomingAccount: DisqualificationAnalysableAccount<MidProduct>,
        MidProduct: BalanceProvidingAccount,
        Vec<MidProduct>: ProcessableReturnTypeFromServiceFeeCheck<
            AdjustmentNeededReturnValue = AdjustmentNeededValue,
        >,
    {
        let required_service_fee_total =
            Self::compute_total_of_service_fee_required::<IncomingAccount, MidProduct>(&payables);

        if cw_service_fee_balance_minor >= required_service_fee_total {
            if matches!(
                error_context,
                ServiceFeeCheckErrorContext::TransactionFeeLimitationInspectionResult { .. }
            ) {
                todo!()
            } else {
                Ok(Either::Left(payables))
            }
        } else {
            let result = self
                .analyse_smallest_adjustment_possibility::<IncomingAccount, MidProduct>(
                    disqualification_arbiter,
                    error_context,
                    payables,
                    cw_service_fee_balance_minor,
                )?;

            log_adjustment_by_service_fee_is_required(
                logger,
                required_service_fee_total,
                cw_service_fee_balance_minor,
            );

            Ok(Either::Right(result.prepare_return()))
        }
    }

    fn compute_total_of_service_fee_required<Account, Product>(payables: &[Account]) -> u128
    where
        Account: DisqualificationAnalysableAccount<Product>,
        Product: BalanceProvidingAccount,
    {
        sum_as(payables, |account| account.balance_minor())
    }

    fn find_smallest_weight_and_prepare_accounts_to_proceed<Account, Product>(
        accounts: Vec<Account>,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> (u128, Vec<Product>)
    where
        Account: DisqualificationAnalysableAccount<Product>,
        Product: BalanceProvidingAccount,
    {
        accounts.into_iter().fold(
            (u128::MAX, vec![]),
            |(min_dsq_limit, mut analyzed_accounts), current| {
                let (current_dsq_limit, analyzed_account) =
                    current.analyse_limit(disqualification_arbiter);
                let next_min_dsq_limit = match min_dsq_limit.cmp(&current_dsq_limit) {
                    Ordering::Less => min_dsq_limit,
                    Ordering::Equal => min_dsq_limit,
                    Ordering::Greater => current_dsq_limit,
                };
                analyzed_accounts.push(analyzed_account);
                (next_min_dsq_limit, analyzed_accounts)
            },
        )
    }

    // We cannot do much in this area but stepping in if the cw balance is zero or nearly zero with
    // the assumption that the debt with the lowest disqualification limit in the set fits in the
    // available balance. If it doesn't, we won't want to bother the payment adjuster by its work,
    // so we'll abort and no payments will come out.
    fn analyse_smallest_adjustment_possibility<Account, Product>(
        &self,
        disqualification_arbiter: &DisqualificationArbiter,
        error_context: ServiceFeeCheckErrorContext,
        accounts: Vec<Account>,
        cw_service_fee_balance_minor: u128,
    ) -> Result<Vec<Product>, PaymentAdjusterError>
    where
        Account: DisqualificationAnalysableAccount<Product>,
        Product: BalanceProvidingAccount, //TODO is this necessary?
    {
        let (lowest_disqualification_limit, prepared_accounts) =
            Self::find_smallest_weight_and_prepare_accounts_to_proceed(
                accounts,
                disqualification_arbiter,
            );

        if lowest_disqualification_limit <= cw_service_fee_balance_minor {
            Ok(prepared_accounts)
        } else {
            let (number_of_accounts, total_amount_demanded_minor, transaction_fee_appendix_opt): (
                usize,
                u128,
                Option<TransactionFeeLimitation>,
            ) = match error_context {
                ServiceFeeCheckErrorContext::TransactionFeeLimitationInspectionResult {
                    limitation_opt: limitation,
                } => todo!(),
                ServiceFeeCheckErrorContext::TransactionFeeAccountsDumpPerformed {
                    original_tx_count,
                    original_sum_of_service_fee_balances,
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
    Product: BalanceProvidingAccount,
{
    // fn process_findings(insufficiency_found: bool)->
    fn analyse_limit(self, disqualification_arbiter: &DisqualificationArbiter) -> (u128, Product);
}

pub trait BalanceProvidingAccount {
    fn balance_minor(&self) -> u128;
}

impl DisqualificationAnalysableAccount<AnalyzedPayableAccount> for QualifiedPayableAccount {
    fn analyse_limit(
        self,
        disqualification_arbiter: &DisqualificationArbiter,
    ) -> (u128, AnalyzedPayableAccount) {
        let dsq_limit = disqualification_arbiter.calculate_disqualification_edge(&self);
        let analyzed_account = AnalyzedPayableAccount::new(self, dsq_limit);
        (dsq_limit, analyzed_account)
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

impl DisqualificationAnalysableAccount<WeightedPayable> for WeightedPayable {
    fn analyse_limit(
        self,
        _disqualification_arbiter: &DisqualificationArbiter,
    ) -> (u128, WeightedPayable) {
        (self.analyzed_account.disqualification_limit_minor, self)
    }
}

impl BalanceProvidingAccount for WeightedPayable {
    fn balance_minor(&self) -> u128 {
        self.analyzed_account.qualified_as.bare_account.balance_wei
    }
}

pub trait ProcessableReturnTypeFromServiceFeeCheck {
    type AdjustmentNeededReturnValue;

    fn prepare_return(self) -> Self::AdjustmentNeededReturnValue;
}

impl ProcessableReturnTypeFromServiceFeeCheck for Vec<AnalyzedPayableAccount> {
    type AdjustmentNeededReturnValue = AdjustmentAnalysis;

    fn prepare_return(self) -> Self::AdjustmentNeededReturnValue {
        todo!()
    }
}

impl ProcessableReturnTypeFromServiceFeeCheck for Vec<WeightedPayable> {
    type AdjustmentNeededReturnValue = Vec<WeightedPayable>;

    fn prepare_return(self) -> Self::AdjustmentNeededReturnValue {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::ServiceFeeCheckErrorContext;
    use crate::accountant::payment_adjuster::preparatory_analyser::{
        PreparatoryAnalyzer,
    };
    use crate::accountant::payment_adjuster::test_utils::{multiple_by_billion, DisqualificationGaugeMock, make_weighed_account};
    use crate::accountant::payment_adjuster::PaymentAdjusterError;
    use crate::accountant::test_utils::make_non_guaranteed_qualified_payable;
    use crate::accountant::{QualifiedPayableAccount};
    use masq_lib::utils::convert_collection;
    use std::sync::{Arc, Mutex};

    fn test_adjustment_possibility_nearly_rejected(
        disqualification_gauge: DisqualificationGaugeMock,
        original_accounts: [QualifiedPayableAccount; 2],
        cw_service_fee_balance: u128,
    ) {
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let disqualification_gauge =
            disqualification_gauge.determine_limit_params(&determine_limit_params_arc);
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let subject = PreparatoryAnalyzer {};
        let service_fee_error_context = ServiceFeeCheckErrorContext::new_dump_context(&vec![]);

        let result = subject.analyse_smallest_adjustment_possibility(
            &disqualification_arbiter,
            service_fee_error_context,
            original_accounts.clone().to_vec(),
            cw_service_fee_balance,
        );

        let expected_analyzed_accounts = convert_collection(original_accounts.to_vec());
        assert_eq!(result, Ok(expected_analyzed_accounts));
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        let account_1 = &original_accounts[0];
        let account_2 = &original_accounts[1];
        let expected_params =    vec![
            (
                account_1.bare_account.balance_wei,
                account_1.payment_threshold_intercept_minor,
                account_1.creditor_thresholds.permanent_debt_allowed_minor
            ),
            (
                account_2.bare_account.balance_wei,
                account_2.payment_threshold_intercept_minor,
                account_2.creditor_thresholds.permanent_debt_allowed_minor
            )
        ];
        assert_eq!(
            *determine_limit_params,
            expected_params
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

        test_adjustment_possibility_nearly_rejected(
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
        let service_fee_check_error_context =
            ServiceFeeCheckErrorContext::TransactionFeeLimitationInspectionResult {
                limitation_opt: None,
            };
        let subject = PreparatoryAnalyzer {};

        let result = subject.analyse_smallest_adjustment_possibility(
            &disqualification_arbiter,
            service_fee_check_error_context,
            original_accounts,
            cw_service_fee_balance,
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
        let disqualification_limit_1 = multiple_by_billion(300_000) + 2;
        let mut weighted_account_1 = make_weighed_account(123);
        weighted_account_1.analyzed_account.disqualification_limit_minor = disqualification_limit_1;
        let disqualification_limit_2 = multiple_by_billion(300_000) + 2;
        let mut weighted_account_2 = make_weighed_account(456);
        weighted_account_2.analyzed_account.disqualification_limit_minor = disqualification_limit_2;
        let disqualification_limit_3 = multiple_by_billion(300_000) + 2;
        let mut weighted_account_3 = make_weighed_account(789);
        weighted_account_3.analyzed_account.disqualification_limit_minor = disqualification_limit_3;
        let disqualification_limit_4 = disqualification_limit_3;
        let mut weighted_account_4 = make_weighed_account(789);
        weighted_account_4.analyzed_account.disqualification_limit_minor = disqualification_limit_4;
        let accounts = vec![
            weighted_account_1.clone(),
            weighted_account_2.clone(),
            weighted_account_3.clone(),
            weighted_account_4.clone(),
        ];
        let disqualification_gauge = DisqualificationGaugeMock::default();
        let disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));

        let (minimal_disqualification_limit, analyzed_accounts) =
            PreparatoryAnalyzer::find_smallest_weight_and_prepare_accounts_to_proceed(
                accounts,
                &disqualification_arbiter,
            );

        assert_eq!(minimal_disqualification_limit, disqualification_limit_2);
        let expected_analyzed_accounts = vec![
            weighted_account_1,
            weighted_account_2,
            weighted_account_3,
            weighted_account_4,
        ];
        assert_eq!(analyzed_accounts, expected_analyzed_accounts)
    }

    #[test]
    fn fold_for_find_smallest_weight_and_prepare_accounts_to_proceed_starts_with_u128_max() {
        let disqualification_arbiter = DisqualificationArbiter::default();
        let accounts: Vec<QualifiedPayableAccount> = vec![];

        let (minimal_disqualification_limit, analyzed_accounts) =
            PreparatoryAnalyzer::find_smallest_weight_and_prepare_accounts_to_proceed(
                accounts,
                &disqualification_arbiter,
            );

        assert_eq!(minimal_disqualification_limit, u128::MAX);
        assert_eq!(analyzed_accounts, vec![])
    }
}
