// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// If possible, let these modules be private
mod adjustment_runners;
mod criterion_calculators;
mod disqualification_arbiter;
mod inner;
mod logging_and_diagnostics;
mod miscellaneous;
#[cfg(test)]
mod non_unit_tests;
mod preparatory_analyser;
mod service_fee_adjuster;
#[cfg(test)]
mod test_utils;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::adjustment_runners::{
    AdjustmentRunner, ServiceFeeOnlyAdjustmentRunner, TransactionAndServiceFeeAdjustmentRunner,
};
use crate::accountant::payment_adjuster::criterion_calculators::balance_and_age_calculator::BalanceAndAgeCriterionCalculator;
use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::calculated_criterion_and_weight_diagnostics;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::{collection_diagnostics, diagnostics};
use crate::accountant::payment_adjuster::disqualification_arbiter::{
    DisqualificationArbiter, DisqualificationGauge,
};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    accounts_before_and_after_debug,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::DecidedAccounts::{
    LowGainingAccountEliminated, SomeAccountsProcessed,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AdjustedAccountBeforeFinalization, AdjustmentIterationResult, AdjustmentPossibilityErrorBuilder, RecursionResults, TransactionFeeLimitation, TransactionFeePastCheckContext, WeightedPayable};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    dump_unaffordable_accounts_by_transaction_fee,
    exhaust_cw_balance_entirely, find_largest_exceeding_balance,
    sum_as, zero_affordable_accounts_found,
};
use crate::accountant::payment_adjuster::preparatory_analyser::PreparatoryAnalyzer;
use crate::accountant::payment_adjuster::service_fee_adjuster::{
    ServiceFeeAdjuster, ServiceFeeAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use crate::diagnostics;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;
use masq_lib::utils::convert_collection;

pub type AdjustmentAnalysisResult =
    Result<Either<Vec<QualifiedPayableAccount>, AdjustmentAnalysis>, PaymentAdjusterError>;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: Vec<QualifiedPayableAccount>,
        agent: &dyn BlockchainAgent,
    ) -> AdjustmentAnalysisResult;

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError>;

    as_any_in_trait!();
}

pub struct PaymentAdjusterReal {
    analyzer: PreparatoryAnalyzer,
    disqualification_arbiter: DisqualificationArbiter,
    service_fee_adjuster: Box<dyn ServiceFeeAdjuster>,
    calculators: Vec<Box<dyn CriterionCalculator>>,
    inner: Box<dyn PaymentAdjusterInner>,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: Vec<QualifiedPayableAccount>,
        agent: &dyn BlockchainAgent,
    ) -> AdjustmentAnalysisResult {
        self.analyzer.analyze_accounts(
            agent,
            &self.disqualification_arbiter,
            qualified_payables,
            &self.logger,
        )
    }

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError> {
        let analyzed_payables = setup.adjustment_analysis.accounts;
        let response_skeleton_opt = setup.response_skeleton_opt;
        let agent = setup.agent;
        let initial_service_fee_balance_minor = agent.service_fee_balance_minor();
        let required_adjustment = setup.adjustment_analysis.adjustment;
        let largest_exceeding_balance_recently_qualified =
            find_largest_exceeding_balance(&analyzed_payables);

        self.initialize_inner(
            initial_service_fee_balance_minor,
            required_adjustment,
            largest_exceeding_balance_recently_qualified,
            now,
        );

        let sketched_debug_info_opt = self.sketch_debug_info_opt(&analyzed_payables);

        let affordable_accounts = self.run_adjustment(analyzed_payables)?;

        self.complete_debug_info_if_enabled(sketched_debug_info_opt, &affordable_accounts);

        self.reset_inner();

        Ok(OutboundPaymentsInstructions::new(
            Either::Right(affordable_accounts),
            agent,
            response_skeleton_opt,
        ))
    }

    as_any_in_trait_impl!();
}

impl Default for PaymentAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentAdjusterReal {
    pub fn new() -> Self {
        Self {
            analyzer: PreparatoryAnalyzer::new(),
            disqualification_arbiter: DisqualificationArbiter::default(),
            service_fee_adjuster: Box::new(ServiceFeeAdjusterReal::default()),
            calculators: vec![Box::new(BalanceAndAgeCriterionCalculator::default())],
            inner: Box::new(PaymentAdjusterInnerNull::default()),
            logger: Logger::new("PaymentAdjuster"),
        }
    }

    fn initialize_inner(
        &mut self,
        cw_service_fee_balance: u128,
        required_adjustment: Adjustment,
        largest_exceeding_balance_recently_qualified: u128,
        now: SystemTime,
    ) {
        let transaction_fee_limitation_opt = match required_adjustment {
            Adjustment::TransactionFeeInPriority {
                affordable_transaction_count,
            } => Some(affordable_transaction_count),
            Adjustment::ByServiceFee => None,
        };

        let inner = PaymentAdjusterInnerReal::new(
            now,
            transaction_fee_limitation_opt,
            cw_service_fee_balance,
            largest_exceeding_balance_recently_qualified,
        );

        self.inner = Box::new(inner);
    }

    fn reset_inner(&mut self) {
        self.inner = Box::new(PaymentAdjusterInnerNull::default())
    }

    fn run_adjustment(
        &mut self,
        analyzed_accounts: Vec<AnalyzedPayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let weighted_accounts = self.calculate_weights(analyzed_accounts);
        let processed_accounts = self.propose_adjustments_recursively(
            weighted_accounts,
            TransactionAndServiceFeeAdjustmentRunner {},
        )?;

        if zero_affordable_accounts_found(&processed_accounts) {
            return Err(PaymentAdjusterError::AllAccountsEliminated);
        }

        match processed_accounts {
            Either::Left(non_exhausted_accounts) => {
                let original_cw_service_fee_balance_minor =
                    self.inner.original_cw_service_fee_balance_minor();
                let exhaustive_affordable_accounts = exhaust_cw_balance_entirely(
                    non_exhausted_accounts,
                    original_cw_service_fee_balance_minor,
                );
                Ok(exhaustive_affordable_accounts)
            }
            Either::Right(finalized_accounts) => Ok(finalized_accounts),
        }
    }

    fn propose_adjustments_recursively<AR, RT>(
        &mut self,
        unresolved_accounts: Vec<WeightedPayable>,
        adjustment_runner: AR,
    ) -> RT
    where
        AR: AdjustmentRunner<ReturnType = RT>,
    {
        diagnostics!(
            "\nUNRESOLVED QUALIFIED ACCOUNTS IN CURRENT ITERATION:",
            &unresolved_accounts
        );

        adjustment_runner.adjust_accounts(self, unresolved_accounts)
    }

    fn begin_with_adjustment_by_transaction_fee(
        &mut self,
        weighted_accounts: Vec<WeightedPayable>,
        already_known_affordable_transaction_count: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        let error_builder = AdjustmentPossibilityErrorBuilder::default().context(
            TransactionFeePastCheckContext::accounts_dumped(&weighted_accounts),
        );

        let weighted_accounts_affordable_by_transaction_fee =
            dump_unaffordable_accounts_by_transaction_fee(
                weighted_accounts,
                already_known_affordable_transaction_count,
            );

        let cw_service_fee_balance_minor = self.inner.original_cw_service_fee_balance_minor();

        if self.analyzer.recheck_if_service_fee_adjustment_is_needed(
            &weighted_accounts_affordable_by_transaction_fee,
            cw_service_fee_balance_minor,
            error_builder,
            &self.logger,
        )? {
            diagnostics!("STILL NECESSARY TO CONTINUE BY ADJUSTMENT IN BALANCES");

            let adjustment_result_before_verification = self
                .propose_possible_adjustment_recursively(
                    weighted_accounts_affordable_by_transaction_fee,
                );

            Ok(Either::Left(adjustment_result_before_verification))
        } else {
            let accounts_not_needing_adjustment =
                convert_collection(weighted_accounts_affordable_by_transaction_fee);

            Ok(Either::Right(accounts_not_needing_adjustment))
        }
    }

    fn propose_possible_adjustment_recursively(
        &mut self,
        weighed_accounts: Vec<WeightedPayable>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let disqualification_arbiter = &self.disqualification_arbiter;
        let unallocated_cw_service_fee_balance =
            self.inner.unallocated_cw_service_fee_balance_minor();
        let logger = &self.logger;

        let current_iteration_result = self.service_fee_adjuster.perform_adjustment_by_service_fee(
            weighed_accounts,
            disqualification_arbiter,
            unallocated_cw_service_fee_balance,
            logger,
        );

        let recursion_results = self.resolve_current_iteration_result(current_iteration_result);

        let merged = recursion_results.merge_results_from_recursion();

        diagnostics!(
            "\nFINAL SET OF ADJUSTED ACCOUNTS IN CURRENT ITERATION:",
            &merged
        );

        merged
    }

    fn resolve_current_iteration_result(
        &mut self,
        adjustment_iteration_result: AdjustmentIterationResult,
    ) -> RecursionResults {
        let remaining_undecided_accounts = adjustment_iteration_result.remaining_undecided_accounts;
        let here_decided_accounts = match adjustment_iteration_result.decided_accounts {
            LowGainingAccountEliminated => {
                if remaining_undecided_accounts.is_empty() {
                    return RecursionResults::new(vec![], vec![]);
                }

                vec![]
            }
            SomeAccountsProcessed(decided_accounts) => {
                if remaining_undecided_accounts.is_empty() {
                    return RecursionResults::new(decided_accounts, vec![]);
                }

                self.adjust_remaining_unallocated_cw_balance_down(&decided_accounts);
                decided_accounts
            }
        };

        let down_stream_decided_accounts = self.propose_adjustments_recursively(
            remaining_undecided_accounts,
            ServiceFeeOnlyAdjustmentRunner {},
        );

        RecursionResults::new(here_decided_accounts, down_stream_decided_accounts)
    }

    fn calculate_weights(&self, accounts: Vec<AnalyzedPayableAccount>) -> Vec<WeightedPayable> {
        self.apply_criteria(self.calculators.as_slice(), accounts)
    }

    fn apply_criteria(
        &self,
        criteria_calculators: &[Box<dyn CriterionCalculator>],
        qualified_accounts: Vec<AnalyzedPayableAccount>,
    ) -> Vec<WeightedPayable> {
        qualified_accounts
            .into_iter()
            .map(|payable| {
                let weight =
                    criteria_calculators
                        .iter()
                        .fold(0_u128, |weight, criterion_calculator| {
                            let new_criterion = criterion_calculator
                                .calculate(&payable.qualified_as, self.inner.as_ref());

                            let summed_up = weight + new_criterion;

                            calculated_criterion_and_weight_diagnostics(
                                &payable.qualified_as.bare_account.wallet,
                                criterion_calculator.as_ref(),
                                new_criterion,
                                summed_up,
                            );

                            summed_up
                        });

                WeightedPayable::new(payable, weight)
            })
            .collect()
    }

    fn adjust_remaining_unallocated_cw_balance_down(
        &mut self,
        processed_outweighed: &[AdjustedAccountBeforeFinalization],
    ) {
        let subtrahend_total: u128 = sum_as(processed_outweighed, |account| {
            account.proposed_adjusted_balance_minor
        });
        self.inner
            .subtract_from_unallocated_cw_service_fee_balance_minor(subtrahend_total);

        diagnostics!(
            "LOWERED CW BALANCE",
            "Unallocated balance lowered by {} to {}",
            subtrahend_total.separate_with_commas(),
            self.inner
                .unallocated_cw_service_fee_balance_minor()
                .separate_with_commas()
        )
    }

    fn sketch_debug_info_opt(
        &self,
        qualified_payables: &[AnalyzedPayableAccount],
    ) -> Option<HashMap<Wallet, u128>> {
        self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|payable| {
                    (
                        payable.qualified_as.bare_account.wallet.clone(),
                        payable.qualified_as.bare_account.balance_wei,
                    )
                })
                .collect::<HashMap<Wallet, u128>>()
        })
    }

    fn complete_debug_info_if_enabled(
        &self,
        sketched_debug_info_opt: Option<HashMap<Wallet, u128>>,
        affordable_accounts: &[PayableAccount],
    ) {
        self.logger.debug(|| {
            let sketched_debug_info =
                sketched_debug_info_opt.expect("debug is enabled, so info should exist");
            accounts_before_and_after_debug(sketched_debug_info, affordable_accounts)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adjustment {
    ByServiceFee,
    TransactionFeeInPriority { affordable_transaction_count: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjustmentAnalysis {
    pub adjustment: Adjustment,
    pub accounts: Vec<AnalyzedPayableAccount>,
}

impl AdjustmentAnalysis {
    pub fn new(adjustment: Adjustment, accounts: Vec<AnalyzedPayableAccount>) -> Self {
        AdjustmentAnalysis {
            adjustment,
            accounts,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentAdjusterError {
    NotEnoughTransactionFeeBalanceForSingleTx {
        number_of_accounts: usize,
        per_transaction_requirement_minor: u128,
        cw_transaction_fee_balance_minor: U256,
    },
    NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
        number_of_accounts: usize,
        total_service_fee_required_minor: u128,
        cw_service_fee_balance_minor: u128,
        transaction_fee_appendix_opt: Option<TransactionFeeLimitation>,
    },
    AllAccountsEliminated,
}

impl Display for PaymentAdjusterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                number_of_accounts,
                per_transaction_requirement_minor,
                cw_transaction_fee_balance_minor,
            } => write!(
                f,
                "Found transaction fee balance that is not enough for a single payment. Number of \
                canceled payments: {}. Transaction fee per payment: {} wei, while in wallet: {} wei",
                number_of_accounts,
                per_transaction_requirement_minor.separate_with_commas(),
                cw_transaction_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                number_of_accounts,
                total_service_fee_required_minor,
                cw_service_fee_balance_minor,
                transaction_fee_appendix_opt,
            } => match transaction_fee_appendix_opt{
                None => write!(
                f,
                "Found service fee balance that is not enough for a single payment. Number of \
                canceled payments: {}. Total amount required: {} wei, while in wallet: {} wei",
                number_of_accounts,
                total_service_fee_required_minor.separate_with_commas(),
                cw_service_fee_balance_minor.separate_with_commas()),
                Some(limitation) => write!(
                f,
                "Both transaction fee and service fee balances are not enough. Number of payments \
                considered: {}. Current transaction fee balance can cover {} payments only. Transaction \
                fee per payment: {} wei, while in wallet: {} wei. Neither does the service fee balance \
                allow a single payment. Total amount required: {} wei, while in wallet: {} wei",
                number_of_accounts,
                limitation.count_limit,
                limitation.per_transaction_required_fee_minor.separate_with_commas(),
                limitation.cw_transaction_fee_balance_minor.separate_with_commas(),
                total_service_fee_required_minor.separate_with_commas(),
                cw_service_fee_balance_minor.separate_with_commas()
                    )
                },
            PaymentAdjusterError::AllAccountsEliminated => write!(
                f,
                "The adjustment algorithm had to eliminate each payable from the recently urged \
                payment due to lack of resources."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::TransactionAndServiceFeeAdjustmentRunner;
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
    use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::DecidedAccounts::SomeAccountsProcessed;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustmentIterationResult, TransactionFeeLimitation, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::find_largest_exceeding_balance;
    use crate::accountant::payment_adjuster::service_fee_adjuster::AdjustmentComputer;
    use crate::accountant::payment_adjuster::test_utils::{
        make_analyzed_account_by_wallet, make_extreme_payables, make_initialized_subject,
        multiple_by_billion, CriterionCalculatorMock, DisqualificationGaugeMock,
        ServiceFeeAdjusterMock, MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR,
        PRESERVED_TEST_PAYMENT_THRESHOLDS,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, AdjustmentAnalysis, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
    use crate::accountant::test_utils::{
        make_analyzed_account, make_guaranteed_analyzed_payables,
        make_guaranteed_qualified_payables, make_payable_account,
    };
    use crate::accountant::{
        gwei_to_wei, CreditorThresholds, QualifiedPayableAccount, ResponseSkeleton,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::utils::convert_collection;
    use std::collections::HashMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use std::{usize, vec};
    use thousands::Separable;
    use web3::types::U256;

    #[test]
    #[should_panic(expected = "Broken code: Called the null implementation of \
        the unallocated_cw_service_fee_balance_minor() method in PaymentAdjusterInner")]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let result = PaymentAdjusterReal::new();

        let _ = result.inner.unallocated_cw_service_fee_balance_minor();
    }

    fn test_initialize_inner_works(
        required_adjustment: Adjustment,
        expected_tx_fee_limit_opt_result: Option<u16>,
    ) {
        let mut subject = PaymentAdjusterReal::default();
        let cw_service_fee_balance = 111_222_333_444;
        let largest_exceeding_balance_recently_qualified = 3_555_666;
        let now = SystemTime::now();

        subject.initialize_inner(
            cw_service_fee_balance,
            required_adjustment,
            largest_exceeding_balance_recently_qualified,
            now,
        );

        assert_eq!(subject.inner.now(), now);
        assert_eq!(
            subject.inner.transaction_fee_count_limit_opt(),
            expected_tx_fee_limit_opt_result
        );
        assert_eq!(
            subject.inner.original_cw_service_fee_balance_minor(),
            cw_service_fee_balance
        );
        assert_eq!(
            subject.inner.unallocated_cw_service_fee_balance_minor(),
            cw_service_fee_balance
        );
        assert_eq!(
            subject.inner.largest_exceeding_balance_recently_qualified(),
            largest_exceeding_balance_recently_qualified
        )
    }

    #[test]
    fn initialize_inner_processes_works() {
        test_initialize_inner_works(Adjustment::ByServiceFee, None);
        test_initialize_inner_works(
            Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 5,
            },
            Some(5),
        );
    }

    #[test]
    fn search_for_indispensable_adjustment_happy_path() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_gives_negative_answer";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // Service fee balance > payments
        let input_1 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Right(vec![
                    gwei_to_wei::<u128, u64>(85),
                    gwei_to_wei::<u128, u64>(15) - 1,
                ]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );
        // Service fee balance == payments
        let input_2 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Left(vec![85, 15]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );
        // transaction fee balance > payments
        let input_3 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_per_transaction: 53_000,
                cw_transaction_fee_balance_major: (100 * 6 * 53_000) + 1,
            }),
        );
        // transaction fee balance == payments
        let input_4 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_per_transaction: 53_000,
                cw_transaction_fee_balance_major: 100 * 6 * 53_000,
            }),
        );

        [input_1, input_2, input_3, input_4]
            .into_iter()
            .enumerate()
            .for_each(|(idx, (qualified_payables, agent))| {
                assert_eq!(
                    subject
                        .search_for_indispensable_adjustment(qualified_payables.clone(), &*agent),
                    Ok(Either::Left(qualified_payables)),
                    "failed for tested input number {:?}",
                    idx + 1
                )
            });

        TestLogHandler::new().exists_no_log_containing(&format!("WARN: {test_name}:"));
    }

    #[test]
    fn search_for_indispensable_adjustment_sad_path_for_transaction_fee() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_sad_path_positive_for_transaction_fee";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let number_of_accounts = 3;
        let service_fee_balances_config_opt = None;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            service_fee_balances_config_opt,
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 100 * 3 * 55_000 - 1,
            }),
        );
        let analyzed_payables = convert_collection(qualified_payables.clone());

        let result = subject.search_for_indispensable_adjustment(qualified_payables, &*agent);

        assert_eq!(
            result,
            Ok(Either::Right(AdjustmentAnalysis::new(
                Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count: 2
                },
                analyzed_payables
            )))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Your transaction fee balance 16,499,999,000,000,000 wei is not \
            going to cover the anticipated fees to send 3 transactions. Maximum is set to 2. \
            Adjustment will be performed."
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that abandoning your debts is going to result in \
            delinquency bans. In order to consume services without limitations, you will need to \
            place more funds into your consuming wallet."
        ));
    }

    #[test]
    fn search_for_indispensable_adjustment_sad_path_for_service_fee_balance() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_service_fee_balance";
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Right(vec![
                    gwei_to_wei::<u128, u64>(85),
                    gwei_to_wei::<u128, u64>(15) + 1,
                ]),
                cw_balance_minor: gwei_to_wei(100_u64),
            }),
            None,
        );
        let analyzed_payables = convert_collection(qualified_payables.clone());

        let result = subject.search_for_indispensable_adjustment(qualified_payables, &*agent);

        assert_eq!(
            result,
            Ok(Either::Right(AdjustmentAnalysis::new(
                Adjustment::ByServiceFee,
                analyzed_payables
            )))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 100,000,\
        000,001 wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of \
        MASQ token. Adjustment of their count or balances is required."));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that abandoning your debts is going to result in \
            delinquency bans. In order to consume services without limitations, you will need to \
            place more funds into your consuming wallet."
        ));
    }

    #[test]
    fn checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_is_unbearably_low()
    {
        let test_name = "checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_is_unbearably_low";
        let cw_service_fee_balance_minor = gwei_to_wei::<u128, _>(120_u64) / 2 - 1; // this would normally kick a serious error
        let service_fee_balances_config_opt = Some(TestConfigForServiceFeeBalances {
            account_balances: Either::Left(vec![120, 300, 500]),
            cw_balance_minor: cw_service_fee_balance_minor,
        });
        let (qualified_payables, agent) =
            make_input_for_initial_check_tests(service_fee_balances_config_opt, None);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);

        let result = subject.search_for_indispensable_adjustment(qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_service_fee_required_minor: 920_000_000_000,
                    cw_service_fee_balance_minor,
                    transaction_fee_appendix_opt: None,
                }
            )
        );
    }

    #[test]
    fn not_enough_transaction_fee_balance_for_even_a_single_transaction() {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 3;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                account_balances: Either::Left(vec![123]),
                cw_balance_minor: gwei_to_wei::<u128, u64>(444),
            }),
            Some(TestConfigForTransactionFees {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 54_000 * 100,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts,
                    per_transaction_requirement_minor: 55_000 * gwei_to_wei::<u128, u64>(100),
                    cw_transaction_fee_balance_minor: U256::from(54_000)
                        * gwei_to_wei::<U256, u64>(100)
                }
            )
        );
    }

    #[test]
    fn payment_adjuster_error_implements_display() {
        vec![
            (
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 5,
                    total_service_fee_required_minor: 6_000_000_000,
                    cw_service_fee_balance_minor: 333_000_000,
                    transaction_fee_appendix_opt: None,
                },
                "Found service fee balance that is not enough for a single payment. Number of \
                canceled payments: 5. Total amount required: 6,000,000,000 wei, while in wallet: \
                333,000,000 wei",
            ),
            (
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 5,
                    total_service_fee_required_minor: 7_000_000_000,
                    cw_service_fee_balance_minor: 100_000_000,
                    transaction_fee_appendix_opt: Some(TransactionFeeLimitation {
                        count_limit: 3,
                        cw_transaction_fee_balance_minor: 3_000_000_000,
                        per_transaction_required_fee_minor: 5_000_000_000,
                    }),
                },
                "Both transaction fee and service fee balances are not enough. Number of payments \
                considered: 5. Current transaction fee balance can cover 3 payments only. \
                Transaction fee per payment: 5,000,000,000 wei, while in wallet: 3,000,000,000 \
                wei. Neither does the service fee balance allow a single payment. Total amount \
                required: 7,000,000,000 wei, while in wallet: 100,000,000 wei",
            ),
            (
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: 4,
                    per_transaction_requirement_minor: 70_000_000_000_000,
                    cw_transaction_fee_balance_minor: U256::from(90_000),
                },
                "Found transaction fee balance that is not enough for a single payment. Number of \
                canceled payments: 4. Transaction fee per payment: 70,000,000,000,000 wei, while in \
                wallet: 90,000 wei",
            ),
            (
                PaymentAdjusterError::AllAccountsEliminated,
                "The adjustment algorithm had to eliminate each payable from the recently urged \
                payment due to lack of resources.",
            ),
        ]
        .into_iter()
        .for_each(|(error, expected_msg)| assert_eq!(error.to_string(), expected_msg))
    }

    #[test]
    fn tinier_but_larger_in_weight_account_is_prioritized_and_gains_up_to_its_disqualification_limit(
    ) {
        let cw_service_fee_balance_minor = multiple_by_billion(4_200_000);
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let mut account_1 = make_analyzed_account_by_wallet("abc");
        let balance_1 = multiple_by_billion(3_000_000);
        let disqualification_limit_1 = multiple_by_billion(2_300_000);
        account_1.qualified_as.bare_account.balance_wei = balance_1;
        account_1.disqualification_limit_minor = disqualification_limit_1;
        let mut account_2 = make_analyzed_account_by_wallet("def");
        let wallet_2 = account_2.qualified_as.bare_account.wallet.clone();
        let balance_2 = multiple_by_billion(2_500_000);
        let disqualification_limit_2 = multiple_by_billion(1_800_000);
        account_2.qualified_as.bare_account.balance_wei = balance_2;
        account_2.disqualification_limit_minor = disqualification_limit_2;
        let largest_exceeding_balance = (balance_1
            - account_1.qualified_as.payment_threshold_intercept_minor)
            .max(balance_2 - account_2.qualified_as.payment_threshold_intercept_minor);
        let mut subject = make_initialized_subject(
            None,
            Some(cw_service_fee_balance_minor),
            None,
            Some(largest_exceeding_balance),
            None,
        );
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(disqualification_limit_2)
            .determine_limit_result(disqualification_limit_1)
            .determine_limit_result(disqualification_limit_1)
            .determine_limit_params(&determine_limit_params_arc);
        subject.disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let weighted_payables = vec![
            WeightedPayable::new(account_1, multiple_by_billion(2_000_100)),
            WeightedPayable::new(account_2, multiple_by_billion(3_999_900)),
        ];

        let mut result = subject
            .propose_adjustments_recursively(
                weighted_payables.clone(),
                TransactionAndServiceFeeAdjustmentRunner {},
            )
            .unwrap()
            .left()
            .unwrap();

        // Let's have an example to explain why this test is important.
        prove_that_proposed_adjusted_balance_could_have_exceeded_the_original_value(
            subject,
            cw_service_fee_balance_minor,
            weighted_payables.clone(),
            wallet_2,
            balance_2,
        );
        // So the assertion above showed the concern true.
        let first_returned_account = result.remove(0);
        // Outweighed accounts always take the first places
        assert_eq!(
            &first_returned_account.original_account,
            &weighted_payables[1]
                .analyzed_account
                .qualified_as
                .bare_account
        );
        assert_eq!(
            first_returned_account.proposed_adjusted_balance_minor,
            disqualification_limit_2
        );
        let second_returned_account = result.remove(0);
        assert_eq!(
            &second_returned_account.original_account,
            &weighted_payables[0]
                .analyzed_account
                .qualified_as
                .bare_account
        );
        assert_eq!(
            second_returned_account.proposed_adjusted_balance_minor,
            2_300_000_000_000_000
        );
        assert!(result.is_empty());
    }

    fn prove_that_proposed_adjusted_balance_could_have_exceeded_the_original_value(
        mut subject: PaymentAdjusterReal,
        cw_service_fee_balance_minor: u128,
        weighted_accounts: Vec<WeightedPayable>,
        wallet_of_expected_outweighed: Wallet,
        original_balance_of_outweighed_account: u128,
    ) {
        let garbage_largest_exceeding_balance_recently_qualified = 123456789;
        subject.inner = Box::new(PaymentAdjusterInnerReal::new(
            SystemTime::now(),
            None,
            cw_service_fee_balance_minor,
            garbage_largest_exceeding_balance_recently_qualified,
        ));
        let unconfirmed_adjustments = AdjustmentComputer::default()
            .compute_unconfirmed_adjustments(weighted_accounts, cw_service_fee_balance_minor);
        // The results are sorted from the biggest weights down
        assert_eq!(
            unconfirmed_adjustments[1].wallet(),
            &wallet_of_expected_outweighed
        );
        // The weight of this account grew progressively due to the additional criterion added
        // in to the sum. Consequences would've been that redistribution of the adjusted balances
        // would've attributed this account with a larger amount to pay than it would've
        // contained before the test started. To prevent that, we used to secure a rule that
        // an account could never demand more than 100% of itself.
        //
        // Later it was changed to other
        // policy. so called "outweighed" account gains automatically a balance equal to its
        // disqualification limit, also a prominent front position in the resulting set of
        // the accounts to pay out. Additionally, due to its favorable position, it can be given
        // a bit more from the remains still languishing in the consuming wallet.
        let proposed_adjusted_balance = unconfirmed_adjustments[1].proposed_adjusted_balance_minor;
        assert!(
            proposed_adjusted_balance > (original_balance_of_outweighed_account * 11 / 10),
            "we expected the proposed balance at least 1.1 times bigger than the original balance \
            which is {} but it was {}",
            original_balance_of_outweighed_account.separate_with_commas(),
            proposed_adjusted_balance.separate_with_commas()
        );
    }

    #[test]
    fn adjustment_started_but_all_accounts_were_eliminated_anyway() {
        let test_name = "adjustment_started_but_all_accounts_were_eliminated_anyway";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(3_000_000);
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: balance_1,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(50_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_2 = multiple_by_billion(2_000_000);
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(50_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_3 = multiple_by_billion(5_000_000);
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: balance_3,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(70_000)).unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2, account_3];
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(2_000_000_000))
            .calculate_result(0)
            .calculate_result(0);
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators.push(Box::new(calculator_mock));
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let cw_service_fee_balance_minor = balance_2;
        let disqualification_arbiter = &subject.disqualification_arbiter;
        let agent_for_analysis = BlockchainAgentMock::default()
            .service_fee_balance_minor_result(cw_service_fee_balance_minor)
            .transaction_fee_balance_minor_result(U256::MAX)
            .estimated_transaction_fee_per_transaction_minor_result(12356);
        let analysis_result = subject.analyzer.analyze_accounts(
            &agent_for_analysis,
            disqualification_arbiter,
            qualified_payables,
            &subject.logger,
        );
        // If the initial analysis at the entry into the PaymentAdjuster concludes there is no point
        // going off because even the least demanding account could not be satisfied, and we would
        // get an error here.
        // However, it can only assess the lowest disqualification limit of an account in that set.
        // Probably not as usual, but this particular account can be later outplayed by another one
        // that is equipped with some extra significance while its disqualification limit does not
        // fit inder the consuming wallet balance anymore. A late error, possibly two different, is
        // born.
        let adjustment_analysis = match analysis_result {
            Ok(Either::Right(analysis)) => analysis,
            x => panic!(
                "We expected to be let it for an adjustments with AnalyzedAccounts but got: {:?}",
                x
            ),
        };
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(cw_service_fee_balance_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            agent,
            response_skeleton_opt: None,
            adjustment_analysis,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        let err = match result {
            Err(e) => e,
            Ok(ok) => panic!(
                "we expected to get an error but it was ok: {:?}",
                ok.affordable_accounts
            ),
        };
        assert_eq!(err, PaymentAdjusterError::AllAccountsEliminated)
    }

    #[test]
    fn account_disqualification_makes_the_rest_outweighed_as_cw_balance_becomes_excessive_for_them()
    {
        // Tests a condition to short-circuit through is integrated into for situations when
        // a disqualification frees means for other accounts and there is suddenly more to give
        // than how much the remaining accounts require us to pay
        init_test_logging();
        let test_name = "account_disqualification_makes_the_rest_outweighed_as_cw_balance_becomes_excessive_for_them";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(80_000_000_000);
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: balance_1,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(24_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_2 = multiple_by_billion(60_000_000_000);
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(200_000)).unwrap(),
            pending_payable_opt: None,
        };
        let balance_3 = multiple_by_billion(40_000_000_000);
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: balance_3,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(160_000)).unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2.clone(), account_3.clone()];
        let analyzed_accounts =
            make_guaranteed_analyzed_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(0)
            .calculate_result(multiple_by_billion(50_000_000_000))
            .calculate_result(multiple_by_billion(50_000_000_000));
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators.push(Box::new(calculator_mock));
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum: u128 = balance_1 + balance_2 + balance_3;
        let service_fee_balance_in_minor_units = accounts_sum - ((balance_1 * 90) / 100);
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            agent,
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::ByServiceFee,
                analyzed_accounts,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_affordable_accounts = { vec![account_3, account_2] };
        assert_eq!(result.affordable_accounts, expected_affordable_accounts);
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp)
    }

    #[test]
    fn overloading_with_exaggerated_debt_conditions_to_see_if_we_can_pass_through_safely() {
        init_test_logging();
        let test_name =
            "overloading_with_exaggerated_debt_conditions_to_see_if_we_can_pass_through_safely";
        let now = SystemTime::now();
        // Each of the 3 accounts refers to a debt sized as the entire masq token supply and being 10 years old which
        // generates enormously large numbers in the criteria
        let extreme_payables = {
            let debt_age_in_months = vec![120, 120, 120];
            make_extreme_payables(
                Either::Left((
                    debt_age_in_months,
                    *MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR,
                )),
                now,
            )
        };
        let analyzed_payables = make_guaranteed_analyzed_payables(
            extreme_payables,
            &PRESERVED_TEST_PAYMENT_THRESHOLDS,
            now,
        );
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // In turn, tiny cw balance
        let cw_service_fee_balance = 1_000;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            agent,
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::ByServiceFee,
                analyzed_payables,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        // The error isn't important. Received just because we set an almost empty wallet
        let err = match result {
            Ok(_) => panic!("we expected err but got ok"),
            Err(e) => e,
        };
        assert_eq!(err, PaymentAdjusterError::AllAccountsEliminated);
        let expected_log = |wallet: &str, proposed_adjusted_balance_in_this_iteration: u64| {
            format!(
                "INFO: {test_name}: Shortage of MASQ in your consuming wallet will impact payable \
                {wallet}, ruled out from this round of payments. The proposed adjustment {} wei was \
                below the disqualification limit {} wei",
                proposed_adjusted_balance_in_this_iteration.separate_with_commas(),
                (*MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR).separate_with_commas()
            )
        };
        let log_handler = TestLogHandler::new();
        // Notice that the proposals grow as one disqualified account drops out in each iteration
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616830",
            333,
        ));
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616831",
            499,
        ));
        log_handler.exists_log_containing(&expected_log(
            "0x000000000000000000000000000000626c616832",
            999,
        ));
    }

    fn meaningless_timestamp() -> SystemTime {
        SystemTime::now()
    }

    // This function should take just such essential args as balances and those that play rather
    // a secondary role, yet an important one in the verification processes for proposed adjusted
    // balances. Refrain from employing more of the weights-affecting parameters as they would
    // only burden us with their consideration in these tests.
    fn make_plucked_qualified_account(
        wallet_addr_fragment: &str,
        balance_minor: u128,
        threshold_intercept_major: u128,
        permanent_debt_allowed_major: u128,
    ) -> QualifiedPayableAccount {
        QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet(wallet_addr_fragment),
                balance_wei: balance_minor,
                last_paid_timestamp: meaningless_timestamp(),
                pending_payable_opt: None,
            },
            multiple_by_billion(threshold_intercept_major),
            CreditorThresholds::new(multiple_by_billion(permanent_debt_allowed_major)),
        )
    }

    #[test]
    fn count_of_qualified_accounts_before_equals_the_one_of_payments_after() {
        // In other words, adjustment by service fee with no account eliminated
        init_test_logging();
        let test_name = "count_of_qualified_accounts_before_equals_the_one_of_payments_after";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(5_444_444_444);
        let qualified_account_1 =
            make_plucked_qualified_account("abc", balance_1, 2_000_000_000, 1_000_000_000);
        let balance_2 = multiple_by_billion(6_000_000_000);
        let qualified_account_2 =
            make_plucked_qualified_account("def", balance_2, 2_500_000_000, 2_000_000_000);
        let balance_3 = multiple_by_billion(6_666_666_666);
        let qualified_account_3 =
            make_plucked_qualified_account("ghi", balance_3, 2_000_000_000, 1_111_111_111);
        let qualified_payables = vec![
            qualified_account_1.clone(),
            qualified_account_2.clone(),
            qualified_account_3.clone(),
        ];
        let analyzed_payables = convert_collection(qualified_payables);
        let mut subject = PaymentAdjusterReal::new();
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(4_500_000_000))
            .calculate_result(multiple_by_billion(4_200_000_000))
            .calculate_result(multiple_by_billion(3_800_000_000));
        subject.calculators = vec![Box::new(calculator_mock)];
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum_minor = balance_1 + balance_2 + balance_3;
        let cw_service_fee_balance_minor = accounts_sum_minor - multiple_by_billion(2_000_000_000);
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor);
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::ByServiceFee,
                analyzed_payables,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_adjusted_balance_1 = 4_833_333_333_000_000_000;
        let expected_adjusted_balance_2 = 5_500_000_000_000_000_000;
        let expected_adjusted_balance_3 = 5_777_777_777_000_000_000;
        let expected_criteria_computation_output = {
            let account_1_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_1,
                ..qualified_account_1.bare_account
            };
            let account_2_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_2,
                ..qualified_account_2.bare_account
            };
            let account_3_adjusted = PayableAccount {
                balance_wei: expected_adjusted_balance_3,
                ..qualified_account_3.bare_account
            };
            vec![account_1_adjusted, account_2_adjusted, account_3_adjusted]
        };
        assert_eq!(
            result.affordable_accounts,
            expected_criteria_computation_output
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000676869 {}
|                                           {}
|0x0000000000000000000000000000000000646566 {}
|                                           {}
|0x0000000000000000000000000000000000616263 {}
|                                           {}",
            balance_3.separate_with_commas(),
            expected_adjusted_balance_3.separate_with_commas(),
            balance_2.separate_with_commas(),
            expected_adjusted_balance_2.separate_with_commas(),
            balance_1.separate_with_commas(),
            expected_adjusted_balance_1.separate_with_commas()
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices() {
        init_test_logging();
        let test_name =
            "only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(111_000_000);
        let account_1 = make_plucked_qualified_account("abc", balance_1, 100_000_000, 20_000_000);
        let balance_2 = multiple_by_billion(300_000_000);
        let account_2 = make_plucked_qualified_account("def", balance_2, 120_000_000, 50_000_000);
        let balance_3 = multiple_by_billion(222_222_222);
        let account_3 = make_plucked_qualified_account("ghi", balance_3, 100_000_000, 40_000_000);
        let qualified_payables = vec![account_1.clone(), account_2, account_3.clone()];
        let analyzed_payables = convert_collection(qualified_payables);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(400_000_000))
            // This account will be cut off because it has the lowest weight and only two accounts
            // can be kept according to the limitations detected in the transaction fee balance
            .calculate_result(multiple_by_billion(120_000_000))
            .calculate_result(multiple_by_billion(250_000_000));
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators = vec![Box::new(calculator_mock)];
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(u128::MAX);
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count: 2,
                },
                analyzed_payables,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // The account 1 takes the first place for its weight being the biggest
        assert_eq!(
            result.affordable_accounts,
            vec![account_1.bare_account, account_3.bare_account]
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000676869 222,222,222,000,000,000
|                                           222,222,222,000,000,000
|0x0000000000000000000000000000000000616263 111,000,000,000,000,000
|                                           111,000,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000646566 300,000,000,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn both_balances_insufficient_but_adjustment_by_service_fee_will_not_affect_the_payments_count()
    {
        // The course of events:
        // 1) adjustment by transaction fee (always means accounts elimination),
        // 2) adjustment by service fee (can but not have to cause an account drop-off)
        init_test_logging();
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(111_000_000);
        let account_1 = make_plucked_qualified_account("abc", balance_1, 50_000_000, 10_000_000);
        let balance_2 = multiple_by_billion(333_000_000);
        let account_2 = make_plucked_qualified_account("def", balance_2, 200_000_000, 50_000_000);
        let balance_3 = multiple_by_billion(222_000_000);
        let account_3 = make_plucked_qualified_account("ghi", balance_3, 100_000_000, 35_000_000);
        let disqualification_arbiter = DisqualificationArbiter::default();
        let disqualification_limit_1 =
            disqualification_arbiter.calculate_disqualification_edge(&account_1);
        let disqualification_limit_3 =
            disqualification_arbiter.calculate_disqualification_edge(&account_3);
        let qualified_payables = vec![account_1.clone(), account_2, account_3.clone()];
        let analyzed_payables = convert_collection(qualified_payables);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(400_000_000))
            .calculate_result(multiple_by_billion(200_000_000))
            .calculate_result(multiple_by_billion(300_000_000));
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators = vec![Box::new(calculator_mock)];
        let cw_service_fee_balance_minor =
            disqualification_limit_1 + disqualification_limit_3 + multiple_by_billion(10_000_000);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor);
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); // Just hardening, not so important
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count: 2,
                },
                analyzed_payables,
            ),
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // Account 2, the least important one, was eliminated for a lack of transaction fee in the cw
        let expected_accounts = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 81_000_000_000_000_000,
                ..account_1.bare_account
            };
            let account_3_adjusted = PayableAccount {
                balance_wei: 157_000_000_000_000_000,
                ..account_3.bare_account
            };
            vec![account_1_adjusted, account_3_adjusted]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn only_service_fee_balance_limits_the_payments_count() {
        init_test_logging();
        let test_name = "only_service_fee_balance_limits_the_payments_count";
        let now = SystemTime::now();
        // Account to be adjusted to keep as much as it is left in the cw balance
        let balance_1 = multiple_by_billion(333_000_000);
        let account_1 = make_plucked_qualified_account("abc", balance_1, 200_000_000, 50_000_000);
        // Account to be outweighed and fully preserved
        let balance_2 = multiple_by_billion(111_000_000);
        let account_2 = make_plucked_qualified_account("def", balance_2, 50_000_000, 10_000_000);
        // Account to be disqualified
        let balance_3 = multiple_by_billion(600_000_000);
        let account_3 = make_plucked_qualified_account("ghi", balance_3, 400_000_000, 100_000_000);
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3];
        let analyzed_payables = convert_collection(qualified_payables);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(900_000_000))
            .calculate_result(multiple_by_billion(1_100_000_000))
            .calculate_result(multiple_by_billion(600_000_000));
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators = vec![Box::new(calculator_mock)];
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = balance_1 + balance_2 - 55;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 11,
            context_id: 234,
        });
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::ByServiceFee,
                analyzed_payables,
            ),
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let mut account_1_adjusted = account_1;
            account_1_adjusted.bare_account.balance_wei -= 55;
            vec![account_2.bare_account, account_1_adjusted.bare_account]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(
            result.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 11,
                context_id: 234
            })
        );
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Shortage of MASQ in your consuming wallet will impact payable \
            0x0000000000000000000000000000000000676869, ruled out from this round of payments. \
            The proposed adjustment 189,999,999,999,999,944 wei was below the disqualification \
            limit 300,000,000,000,000,000 wei"
        ));
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn reminder() {
        todo!("change gainers for losing and thriving competitors")
    }

    #[test]
    fn service_fee_as_well_as_transaction_fee_limits_the_payments_count() {
        init_test_logging();
        let test_name = "service_fee_as_well_as_transaction_fee_limits_the_payments_count";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(100_000_000_000);
        let account_1 =
            make_plucked_qualified_account("abc", balance_1, 60_000_000_000, 10_000_000_000);
        // The second is thrown away first in a response to the shortage of transaction fee,
        // as its weight is the least significant
        let balance_2 = multiple_by_billion(500_000_000_000);
        let account_2 =
            make_plucked_qualified_account("def", balance_2, 100_000_000_000, 30_000_000_000);
        // Thrown away as the second one due to a shortage in the service fee,
        // listed among accounts to disqualify and picked eventually for its
        // lowest weight
        let balance_3 = multiple_by_billion(250_000_000_000);
        let account_3 =
            make_plucked_qualified_account("ghi", balance_3, 90_000_000_000, 20_000_000_000);
        let qualified_payables = vec![account_1.clone(), account_2, account_3];
        let analyzed_payables = convert_collection(qualified_payables);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(900_000_000_000))
            .calculate_result(multiple_by_billion(500_000_000_000))
            .calculate_result(multiple_by_billion(750_000_000_000));
        let mut subject = PaymentAdjusterReal::new();
        subject.calculators = vec![Box::new(calculator_mock)];
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor = balance_1 - multiple_by_billion(10_000_000_000);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(service_fee_balance_in_minor);
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count: 2,
                },
                analyzed_payables,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let mut account = account_1;
            account.bare_account.balance_wei = service_fee_balance_in_minor;
            vec![account.bare_account]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000616263 100,000,000,000,000,000,000
|                                           90,000,000,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000646566 500,000,000,000,000,000,000
|0x0000000000000000000000000000000000676869 250,000,000,000,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient(
    ) {
        init_test_logging();
        let test_name = "late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient";
        let now = SystemTime::now();
        let balance_1 = multiple_by_billion(500_000_000_000);
        let account_1 =
            make_plucked_qualified_account("abc", balance_1, 300_000_000_000, 100_000_000_000);
        // This account is eliminated in the transaction fee cut
        let balance_2 = multiple_by_billion(111_000_000_000);
        let account_2 =
            make_plucked_qualified_account("def", balance_2, 50_000_000_000, 10_000_000_000);
        let balance_3 = multiple_by_billion(300_000_000_000);
        let account_3 =
            make_plucked_qualified_account("ghi", balance_3, 150_000_000_000, 50_000_000_000);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let disqualification_arbiter = DisqualificationArbiter::default();
        let disqualification_limit_2 =
            disqualification_arbiter.calculate_disqualification_edge(&account_2);
        // This is exactly the amount which will provoke an error
        let service_fee_balance_in_minor_units = disqualification_limit_2 - 1;
        let qualified_payables = vec![account_1, account_2, account_3];
        let analyzed_payables = convert_collection(qualified_payables);
        let agent = BlockchainAgentMock::default()
            .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysis::new(
                Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count: 2,
                },
                analyzed_payables,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        let err = match result {
            Ok(_) => panic!("expected an error but got Ok()"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                number_of_accounts: 3,
                total_service_fee_required_minor: balance_1 + balance_2 + balance_3,
                cw_service_fee_balance_minor: service_fee_balance_in_minor_units,
                transaction_fee_appendix_opt: None,
            }
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &format!(
                "WARN: {test_name}: Total of 411,000,000,000,000,000,000 wei in MASQ was \
            ordered while the consuming wallet held only 70,999,999,999,999,999,999 wei of MASQ \
            token. Adjustment of their count or balances is required."
            ),
            &format!(
                "INFO: {test_name}: Please be aware that abandoning your debts is going to \
            result in delinquency bans. In order to consume services without limitations, you \
            will need to place more funds into your consuming wallet.",
            ),
            &format!(
                "ERROR: {test_name}: {}",
                LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY
            ),
        ]);
    }

    struct TestConfigForServiceFeeBalances {
        // Either gwei or wei
        account_balances: Either<Vec<u64>, Vec<u128>>,
        cw_balance_minor: u128,
    }

    struct TestConfigForTransactionFees {
        agreed_transaction_fee_per_computed_unit_major: u64,
        number_of_accounts: usize,
        estimated_transaction_fee_units_per_transaction: u64,
        cw_transaction_fee_balance_major: u64,
    }

    fn make_input_for_initial_check_tests(
        service_fee_balances_config_opt: Option<TestConfigForServiceFeeBalances>,
        transaction_fee_config_opt: Option<TestConfigForTransactionFees>,
    ) -> (Vec<QualifiedPayableAccount>, Box<dyn BlockchainAgent>) {
        let service_fee_balances_config =
            get_service_fee_balances_config(service_fee_balances_config_opt);
        let balances_of_accounts_minor =
            get_service_fee_balances(service_fee_balances_config.account_balances);
        let accounts_count_from_sf_config = balances_of_accounts_minor.len();

        let transaction_fee_config =
            get_transaction_fee_config(transaction_fee_config_opt, accounts_count_from_sf_config);

        let payable_accounts = prepare_payable_accounts(
            transaction_fee_config.number_of_accounts,
            accounts_count_from_sf_config,
            balances_of_accounts_minor,
        );
        let qualified_payables = prepare_qualified_payables(payable_accounts);

        let blockchain_agent = make_agent(
            transaction_fee_config.cw_transaction_fee_balance_major,
            transaction_fee_config.estimated_transaction_fee_units_per_transaction,
            transaction_fee_config.agreed_transaction_fee_per_computed_unit_major,
            service_fee_balances_config.cw_balance_minor,
        );

        (qualified_payables, blockchain_agent)
    }

    fn get_service_fee_balances_config(
        service_fee_balances_config_opt: Option<TestConfigForServiceFeeBalances>,
    ) -> TestConfigForServiceFeeBalances {
        service_fee_balances_config_opt.unwrap_or_else(|| TestConfigForServiceFeeBalances {
            account_balances: Either::Left(vec![1, 1]),
            cw_balance_minor: u64::MAX as u128,
        })
    }
    fn get_service_fee_balances(account_balances: Either<Vec<u64>, Vec<u128>>) -> Vec<u128> {
        match account_balances {
            Either::Left(in_major) => in_major
                .into_iter()
                .map(|major| gwei_to_wei(major))
                .collect(),
            Either::Right(in_minor) => in_minor,
        }
    }

    fn get_transaction_fee_config(
        transaction_fee_config_opt: Option<TestConfigForTransactionFees>,
        accounts_count_from_sf_config: usize,
    ) -> TestConfigForTransactionFees {
        transaction_fee_config_opt.unwrap_or(TestConfigForTransactionFees {
            agreed_transaction_fee_per_computed_unit_major: 120,
            number_of_accounts: accounts_count_from_sf_config,
            estimated_transaction_fee_units_per_transaction: 55_000,
            cw_transaction_fee_balance_major: u64::MAX,
        })
    }

    fn prepare_payable_accounts(
        accounts_count_from_tf_config: usize,
        accounts_count_from_sf_config: usize,
        balances_of_accounts_minor: Vec<u128>,
    ) -> Vec<PayableAccount> {
        if accounts_count_from_tf_config != accounts_count_from_sf_config {
            (0..accounts_count_from_tf_config)
                .map(|idx| make_payable_account(idx as u64))
                .collect()
        } else {
            balances_of_accounts_minor
                .into_iter()
                .enumerate()
                .map(|(idx, balance)| {
                    let mut account = make_payable_account(idx as u64);
                    account.balance_wei = balance;
                    account
                })
                .collect()
        }
    }

    fn prepare_qualified_payables(
        payable_accounts: Vec<PayableAccount>,
    ) -> Vec<QualifiedPayableAccount> {
        payable_accounts
            .into_iter()
            .map(|payable| {
                let balance = payable.balance_wei;
                QualifiedPayableAccount {
                    bare_account: payable,
                    payment_threshold_intercept_minor: (balance / 10) * 7,
                    creditor_thresholds: CreditorThresholds {
                        permanent_debt_allowed_minor: (balance / 10) * 7,
                    },
                }
            })
            .collect()
    }

    fn make_agent(
        cw_balance_transaction_fee_major: u64,
        estimated_transaction_fee_units_per_transaction: u64,
        agreed_transaction_fee_price: u64,
        cw_service_fee_balance_minor: u128,
    ) -> Box<dyn BlockchainAgent> {
        let cw_transaction_fee_minor = gwei_to_wei(cw_balance_transaction_fee_major);
        let estimated_transaction_fee_per_transaction_minor = gwei_to_wei(
            estimated_transaction_fee_units_per_transaction * agreed_transaction_fee_price,
        );

        let blockchain_agent = BlockchainAgentMock::default()
            .transaction_fee_balance_minor_result(cw_transaction_fee_minor)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor)
            .estimated_transaction_fee_per_transaction_minor_result(
                estimated_transaction_fee_per_transaction_minor,
            );

        Box::new(blockchain_agent)
    }

    fn test_inner_was_reset_to_null(subject: PaymentAdjusterReal) {
        let err = catch_unwind(AssertUnwindSafe(|| {
            subject.inner.original_cw_service_fee_balance_minor()
        }))
        .unwrap_err();
        let panic_msg = err.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Broken code: Broken code: Called the null implementation of \
        the original_cw_service_fee_balance_minor() method in PaymentAdjusterInner"
        )
    }

    // The following tests together prove the use of correct calculators in the production code

    #[test]
    fn each_of_defaulted_calculators_returns_different_value() {
        let now = SystemTime::now();
        let payment_adjuster = PaymentAdjusterReal::default();
        let qualified_payable = QualifiedPayableAccount {
            bare_account: PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: gwei_to_wei::<u128, u64>(444_666_888),
                last_paid_timestamp: now.checked_sub(Duration::from_secs(123_000)).unwrap(),
                pending_payable_opt: None,
            },
            payment_threshold_intercept_minor: gwei_to_wei::<u128, u64>(20_000),
            creditor_thresholds: CreditorThresholds::new(gwei_to_wei::<u128, u64>(10_000)),
        };
        let cw_service_fee_balance_minor = gwei_to_wei::<u128, u64>(3_000);
        let exceeding_balance = qualified_payable.bare_account.balance_wei
            - qualified_payable.payment_threshold_intercept_minor;
        let context = PaymentAdjusterInnerReal::new(
            now,
            None,
            cw_service_fee_balance_minor,
            exceeding_balance,
        );
        let _ = payment_adjuster
            .calculators
            .into_iter()
            .map(|calculator| calculator.calculate(&qualified_payable, &context))
            .fold(0, |previous_result, current_result| {
                let min = (current_result * 97) / 100;
                let max = (current_result * 97) / 100;
                assert_ne!(current_result, 0);
                assert!(min <= previous_result || previous_result <= max);
                current_result
            });
    }

    type InputMatrixConfigurator = fn(
        (QualifiedPayableAccount, QualifiedPayableAccount, SystemTime),
    ) -> Vec<[(QualifiedPayableAccount, u128); 2]>;

    #[test]
    fn defaulted_calculators_react_on_correct_params() {
        // When adding a test case for a new calculator, you need to make an array of inputs. Don't
        // create brand-new accounts but clone the provided nominal accounts and modify them
        // accordingly. Modify only those parameters that affect your calculator.
        // It's recommended to orientate the modifications rather positively (additions), because
        // there is a smaller chance you would run into some limit
        let input_matrix: InputMatrixConfigurator =
            |(nominal_account_1, nominal_account_2, _now)| {
                vec![
                    // First test case: BalanceAndAgeCalculator
                    {
                        let mut account_1 = nominal_account_1;
                        account_1.bare_account.balance_wei += 123_456_789;
                        let mut account_2 = nominal_account_2;
                        account_2.bare_account.balance_wei += 999_999_999;
                        [(account_1, 8000001876543209), (account_2, 8000000999999999)]
                    },
                ]
            };
        // This is the value that is computed if the account stays unmodified. Same for both nominal
        // accounts.
        let current_nominal_weight = 8000000000000000;

        test_calculators_reactivity(input_matrix, current_nominal_weight)
    }

    #[derive(Clone, Copy)]
    struct TemplateComputedWeight {
        common_weight: u128,
    }

    struct SingleAccountInput {
        account: QualifiedPayableAccount,
        assertion_value: AssertionValue,
    }

    //TODO implement this in
    struct AssertionValue {
        wallet_to_match_result_with: Wallet,
        expected_computed_weight: u128,
    }

    fn test_calculators_reactivity(
        input_matrix_configurator: InputMatrixConfigurator,
        nominal_weight: u128,
    ) {
        let calculators_count = PaymentAdjusterReal::default().calculators.len();
        let now = SystemTime::now();
        let cw_service_fee_balance_minor = gwei_to_wei::<u128, u64>(1_000_000);
        let (template_accounts, template_computed_weight) =
            prepare_nominal_data_before_loading_actual_test_input(
                now,
                cw_service_fee_balance_minor,
            );
        assert_eq!(template_computed_weight.common_weight, nominal_weight);
        let mut template_accounts = template_accounts.to_vec();
        let mut pop_account = || template_accounts.remove(0);
        let nominal_account_1 = pop_account();
        let nominal_account_2 = pop_account();
        let input_matrix = input_matrix_configurator((nominal_account_1, nominal_account_2, now));
        assert_eq!(
            input_matrix.len(),
            calculators_count,
            "If you've recently added in a new calculator, you should add in its new test case to \
            this test. See the input matrix, it is the place where you should use the two accounts \
            you can clone. Make sure you modify only those parameters processed by your new calculator "
        );
        test_accounts_from_input_matrix(
            input_matrix,
            now,
            cw_service_fee_balance_minor,
            template_computed_weight,
        )
    }

    fn prepare_nominal_data_before_loading_actual_test_input(
        now: SystemTime,
        cw_service_fee_balance_minor: u128,
    ) -> ([QualifiedPayableAccount; 2], TemplateComputedWeight) {
        let template_accounts = initialize_template_accounts(now);
        let template_weight = compute_common_weight_for_templates(
            template_accounts.clone(),
            now,
            cw_service_fee_balance_minor,
        );
        (template_accounts, template_weight)
    }

    fn initialize_template_accounts(now: SystemTime) -> [QualifiedPayableAccount; 2] {
        let make_qualified_payable = |wallet| QualifiedPayableAccount {
            bare_account: PayableAccount {
                wallet,
                balance_wei: gwei_to_wei::<u128, u64>(20_000_000),
                last_paid_timestamp: now.checked_sub(Duration::from_secs(10_000)).unwrap(),
                pending_payable_opt: None,
            },
            payment_threshold_intercept_minor: gwei_to_wei::<u128, u64>(12_000_000),
            creditor_thresholds: CreditorThresholds::new(gwei_to_wei::<u128, u64>(1_000_000)),
        };

        [
            make_qualified_payable(make_wallet("abc")),
            make_qualified_payable(make_wallet("def")),
        ]
    }

    fn compute_common_weight_for_templates(
        template_accounts: [QualifiedPayableAccount; 2],
        now: SystemTime,
        cw_service_fee_balance_minor: u128,
    ) -> TemplateComputedWeight {
        let template_results = exercise_production_code_to_get_weighted_accounts(
            template_accounts.to_vec(),
            now,
            cw_service_fee_balance_minor,
        );
        let templates_common_weight = template_results
            .iter()
            .map(|account| account.weight)
            .reduce(|previous, current| {
                assert_eq!(previous, current);
                current
            })
            .unwrap();
        // Formal test if the value is different from zero,
        // and ideally much bigger than that
        assert!(1_000_000_000_000 < templates_common_weight);
        TemplateComputedWeight {
            common_weight: templates_common_weight,
        }
    }

    fn exercise_production_code_to_get_weighted_accounts(
        qualified_payables: Vec<QualifiedPayableAccount>,
        now: SystemTime,
        cw_service_fee_balance_minor: u128,
    ) -> Vec<WeightedPayable> {
        let analyzed_payables = convert_collection(qualified_payables);
        let largest_exceeding_balance_recently_qualified =
            find_largest_exceeding_balance(&analyzed_payables);
        let mut subject = make_initialized_subject(
            Some(now),
            Some(cw_service_fee_balance_minor),
            None,
            Some(largest_exceeding_balance_recently_qualified),
            None,
        );
        let perform_adjustment_by_service_fee_params_arc = Arc::new(Mutex::new(Vec::new()));
        let service_fee_adjuster_mock = ServiceFeeAdjusterMock::default()
            // We use this container to intercept those values we are after
            .perform_adjustment_by_service_fee_params(&perform_adjustment_by_service_fee_params_arc)
            // This is just a sentinel that allows us to shorten the adjustment execution.
            // We care only for the params captured inside the container from above
            .perform_adjustment_by_service_fee_result(AdjustmentIterationResult {
                decided_accounts: SomeAccountsProcessed(vec![]),
                remaining_undecided_accounts: vec![],
            });
        subject.service_fee_adjuster = Box::new(service_fee_adjuster_mock);

        let result = subject.run_adjustment(analyzed_payables);

        less_important_constant_assertions_and_weighted_accounts_extraction(
            result,
            perform_adjustment_by_service_fee_params_arc,
            cw_service_fee_balance_minor,
        )
    }

    fn less_important_constant_assertions_and_weighted_accounts_extraction(
        actual_result: Result<Vec<PayableAccount>, PaymentAdjusterError>,
        perform_adjustment_by_service_fee_params_arc: Arc<Mutex<Vec<(Vec<WeightedPayable>, u128)>>>,
        cw_service_fee_balance_minor: u128,
    ) -> Vec<WeightedPayable> {
        // This error should be ignored, as it has no real meaning.
        // It allows to halt the code executions without a dive in the recursion
        assert_eq!(
            actual_result,
            Err(PaymentAdjusterError::AllAccountsEliminated)
        );
        let mut perform_adjustment_by_service_fee_params =
            perform_adjustment_by_service_fee_params_arc.lock().unwrap();
        let (weighted_accounts, captured_cw_service_fee_balance_minor) =
            perform_adjustment_by_service_fee_params.remove(0);
        assert_eq!(
            captured_cw_service_fee_balance_minor,
            cw_service_fee_balance_minor
        );
        assert!(perform_adjustment_by_service_fee_params.is_empty());
        weighted_accounts
    }

    fn test_accounts_from_input_matrix(
        input_matrix: Vec<[(QualifiedPayableAccount, u128); 2]>,
        now: SystemTime,
        cw_service_fee_balance_minor: u128,
        template_computed_weight: TemplateComputedWeight,
    ) {
        fn prepare_args_expected_weights_for_comparison(
            (qualified_payable, expected_computed_payable): (QualifiedPayableAccount, u128),
        ) -> (QualifiedPayableAccount, (Wallet, u128)) {
            let wallet = qualified_payable.bare_account.wallet.clone();
            (qualified_payable, (wallet, expected_computed_payable))
        }

        input_matrix
            .into_iter()
            .map(|test_case| {
                test_case
                    .into_iter()
                    .map(prepare_args_expected_weights_for_comparison)
                    .collect::<Vec<_>>()
            })
            .for_each(|qualified_payments_and_expected_computed_weights| {
                let (qualified_payments, expected_computed_weights): (Vec<_>, Vec<_>) =
                    qualified_payments_and_expected_computed_weights
                        .into_iter()
                        .unzip();

                let weighted_accounts = exercise_production_code_to_get_weighted_accounts(
                    qualified_payments,
                    now,
                    cw_service_fee_balance_minor,
                );

                assert_results(
                    weighted_accounts,
                    expected_computed_weights,
                    template_computed_weight,
                )
            });
    }

    fn make_comparison_hashmap(
        weighted_accounts: Vec<WeightedPayable>,
    ) -> HashMap<Wallet, WeightedPayable> {
        let feeding_iterator = weighted_accounts
            .into_iter()
            .map(|account| (account.wallet().clone(), account));
        HashMap::from_iter(feeding_iterator)
    }

    fn assert_results(
        weighted_accounts: Vec<WeightedPayable>,
        expected_computed_weights: Vec<(Wallet, u128)>,
        template_computed_weight: TemplateComputedWeight,
    ) {
        let weighted_accounts_as_hash_map = make_comparison_hashmap(weighted_accounts);
        expected_computed_weights.into_iter().fold(
            0,
            |previous_account_actual_weight, (account_wallet, expected_computed_weight)| {
                let actual_account = weighted_accounts_as_hash_map
                    .get(&account_wallet)
                    .unwrap_or_else(|| {
                        panic!("Account for wallet {:?} disappeared", account_wallet)
                    });
                assert_ne!(
                    actual_account.weight, template_computed_weight.common_weight,
                    "Weight is exactly the same as that one from the template. The inputs \
                    (modifications in the template accounts) are supposed to cause the weight to \
                    evaluated differently."
                );
                assert_eq!(
                    actual_account.weight,
                    expected_computed_weight,
                    "Computed weight {} differs from what was expected {}",
                    actual_account.weight.separate_with_commas(),
                    expected_computed_weight.separate_with_commas()
                );
                assert_ne!(
                    actual_account.weight, previous_account_actual_weight,
                    "You were expected to prepare two accounts with at least slightly \
                    different parameters. Therefore, the evenness of their weights is \
                    highly improbable and suspicious."
                );
                actual_account.weight
            },
        );
    }
}
