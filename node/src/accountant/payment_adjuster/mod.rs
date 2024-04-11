// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// If possible, let these modules be private
mod adjustment_runners;
mod criterion_calculators;
mod diagnostics;
mod disqualification_arbiter;
mod inner;
#[cfg(test)]
mod loading_test;
mod log_fns;
mod miscellaneous;
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
use crate::accountant::payment_adjuster::diagnostics::ordinary_diagnostic_functions::calculated_criterion_and_weight_diagnostics;
use crate::accountant::payment_adjuster::diagnostics::{collection_diagnostics, diagnostics};
use crate::accountant::payment_adjuster::disqualification_arbiter::{
    DisqualificationArbiter, DisqualificationGauge,
};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::log_fns::{
    accounts_before_and_after_debug, log_transaction_fee_adjustment_ok_but_by_service_fee_undoable,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::SpecialHandling::{
    InsignificantAccountEliminated, OutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, RecursionResults,
    UnconfirmedAdjustment, WeightedPayable,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    drop_no_longer_needed_weights_away_from_accounts, dump_unaffordable_accounts_by_txn_fee,
    exhaust_cw_till_the_last_drop, find_largest_exceeding_balance,
    sort_in_descendant_order_by_weights, sum_as, zero_affordable_accounts_found,
};
use crate::accountant::payment_adjuster::preparatory_analyser::PreparatoryAnalyzer;
use crate::accountant::payment_adjuster::service_fee_adjuster::{
    ServiceFeeAdjuster, ServiceFeeAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::accountant::QualifiedPayableAccount;
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

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
        agent: &dyn BlockchainAgent,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError>;

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
    inner: Box<dyn PaymentAdjusterInner>,
    service_fee_adjuster: Box<dyn ServiceFeeAdjuster>,
    calculators: Vec<Box<dyn CriterionCalculator>>,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
        agent: &dyn BlockchainAgent,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError> {
        let number_of_counts = qualified_payables.len();

        match self
            .analyzer
            .determine_transaction_count_limit_by_transaction_fee(
                agent,
                number_of_counts,
                &self.logger,
            ) {
            Ok(None) => (),
            Ok(Some(affordable_transaction_count)) => {
                return Ok(Some(Adjustment::TransactionFeeInPriority {
                    affordable_transaction_count,
                }))
            }
            Err(e) => return Err(e),
        };

        let service_fee_balance_minor = agent.service_fee_balance_minor();
        match self.analyzer.check_need_of_adjustment_by_service_fee(
            &self.disqualification_arbiter,
            Either::Left(qualified_payables),
            service_fee_balance_minor,
            &self.logger,
        ) {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(Adjustment::ByServiceFee)),
            Err(e) => Err(e),
        }
    }

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError> {
        let qualified_payables = setup.qualified_payables;
        let response_skeleton_opt = setup.response_skeleton_opt;
        let agent = setup.agent;
        let initial_service_fee_balance_minor = agent.service_fee_balance_minor();
        let required_adjustment = setup.adjustment;
        let largest_exceeding_balance_recently_qualified =
            find_largest_exceeding_balance(&qualified_payables);

        self.initialize_inner(
            initial_service_fee_balance_minor,
            required_adjustment,
            largest_exceeding_balance_recently_qualified,
            now,
        );

        let sketched_debug_info_opt = self.sketch_debug_info_opt(&qualified_payables);

        let affordable_accounts = self.run_adjustment(qualified_payables)?;

        self.complete_debug_info_if_enabled(sketched_debug_info_opt, &affordable_accounts);

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
            inner: Box::new(PaymentAdjusterInnerNull {}),
            service_fee_adjuster: Box::new(ServiceFeeAdjusterReal::default()),
            calculators: vec![Box::new(BalanceAndAgeCriterionCalculator::default())],
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

    fn run_adjustment(
        &mut self,
        qualified_accounts: Vec<QualifiedPayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let weighted_accounts_sorted = self.calculate_weights_for_accounts(qualified_accounts);
        let processed_accounts = self.calculate_criteria_and_propose_adjustments_recursively(
            weighted_accounts_sorted,
            TransactionAndServiceFeeAdjustmentRunner {},
        )?;

        if zero_affordable_accounts_found(&processed_accounts) {
            return Err(PaymentAdjusterError::AllAccountsEliminated);
        }

        match processed_accounts {
            Either::Left(non_exhausted_accounts) => {
                let original_cw_service_fee_balance_minor =
                    self.inner.original_cw_service_fee_balance_minor();
                let exhaustive_affordable_accounts = exhaust_cw_till_the_last_drop(
                    non_exhausted_accounts,
                    original_cw_service_fee_balance_minor,
                );
                Ok(exhaustive_affordable_accounts)
            }
            Either::Right(finalized_accounts) => Ok(finalized_accounts),
        }
    }

    fn calculate_criteria_and_propose_adjustments_recursively<AR, RT>(
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
        weighted_accounts_in_descending_order: Vec<WeightedPayable>,
        already_known_affordable_transaction_count: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        let weighted_accounts_affordable_by_transaction_fee = dump_unaffordable_accounts_by_txn_fee(
            weighted_accounts_in_descending_order,
            already_known_affordable_transaction_count,
        );

        let cw_service_fee_balance = self.inner.original_cw_service_fee_balance_minor();

        let is_service_fee_adjustment_needed =
            match self.analyzer.check_need_of_adjustment_by_service_fee(
                &self.disqualification_arbiter,
                Either::Right(&weighted_accounts_affordable_by_transaction_fee),
                cw_service_fee_balance,
                &self.logger,
            ) {
                Ok(answer) => answer,
                Err(e) => {
                    log_transaction_fee_adjustment_ok_but_by_service_fee_undoable(&self.logger);
                    return Err(e);
                }
            };

        match is_service_fee_adjustment_needed {
            true => {
                diagnostics!("STILL NECESSARY TO CONTINUE BY ADJUSTMENT IN BALANCES");

                let adjustment_result_before_verification = self
                    .propose_possible_adjustment_recursively(
                        weighted_accounts_affordable_by_transaction_fee,
                    );
                Ok(Either::Left(adjustment_result_before_verification))
            }
            false => {
                let accounts_not_needing_adjustment =
                    drop_no_longer_needed_weights_away_from_accounts(
                        weighted_accounts_affordable_by_transaction_fee,
                    );
                Ok(Either::Right(accounts_not_needing_adjustment))
            }
        }
    }

    fn propose_possible_adjustment_recursively(
        &mut self,
        weighed_accounts: Vec<WeightedPayable>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let unallocated_cw_service_fee_balance =
            self.inner.unallocated_cw_service_fee_balance_minor();
        let disqualification_arbiter = &self.disqualification_arbiter;
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
        match adjustment_iteration_result {
            AdjustmentIterationResult::AllAccountsProcessed(decided_accounts) => {
                RecursionResults::new(decided_accounts, vec![])
            }
            AdjustmentIterationResult::IterationWithSpecialHandling {
                case,
                remaining_undecided_accounts,
            } => {
                let here_decided_accounts = match case {
                    InsignificantAccountEliminated => {
                        if remaining_undecided_accounts.is_empty() {
                            return RecursionResults::new(vec![], vec![]);
                        }

                        vec![]
                    }
                    OutweighedAccounts(outweighed) => {
                        if remaining_undecided_accounts.is_empty() {
                            // The only known reason for this would be an account disqualification,
                            // after which the unallocated cw balance begins to suffice for the rest
                            // of those unresolved accounts.
                            // Because it is definitely possible, there is a check aimed at this
                            // in the AdjustmentRunner's adjust_accounts()
                            unreachable!("This shouldn't be possible due to a preceding check");
                        }

                        self.adjust_remaining_unallocated_cw_balance_down(&outweighed);
                        outweighed
                    }
                };

                let down_stream_decided_accounts = self
                    .calculate_criteria_and_propose_adjustments_recursively(
                        remaining_undecided_accounts,
                        ServiceFeeOnlyAdjustmentRunner {},
                    );

                RecursionResults::new(here_decided_accounts, down_stream_decided_accounts)
            }
        }
    }

    fn calculate_weights_for_accounts(
        &self,
        accounts: Vec<QualifiedPayableAccount>,
    ) -> Vec<WeightedPayable> {
        self.apply_criteria(self.calculators.as_slice(), accounts)
    }

    fn apply_criteria(
        &self,
        criteria_calculators: &[Box<dyn CriterionCalculator>],
        qualified_accounts: Vec<QualifiedPayableAccount>,
    ) -> Vec<WeightedPayable> {
        let weighted_accounts = qualified_accounts.into_iter().map(|payable| {
            let weight =
                criteria_calculators
                    .iter()
                    .fold(0_u128, |weight, criterion_calculator| {
                        let new_criterion =
                            criterion_calculator.calculate(&payable, self.inner.as_ref());

                        let summed_up = weight + new_criterion;

                        calculated_criterion_and_weight_diagnostics(
                            &payable.bare_account.wallet,
                            criterion_calculator.as_ref(),
                            new_criterion,
                            summed_up,
                        );

                        summed_up
                    });

            WeightedPayable::new(payable, weight)
        });

        sort_in_descendant_order_by_weights(weighted_accounts)
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
            subtrahend_total,
            self.inner.unallocated_cw_service_fee_balance_minor()
        )
    }

    fn sketch_debug_info_opt(
        &self,
        qualified_payables: &[QualifiedPayableAccount],
    ) -> Option<HashMap<Wallet, u128>> {
        self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|payable| {
                    (
                        payable.bare_account.wallet.clone(),
                        payable.bare_account.balance_wei,
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

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentAdjusterError {
    NotEnoughTransactionFeeBalanceForSingleTx {
        number_of_accounts: usize,
        per_transaction_requirement_minor: u128,
        cw_transaction_fee_balance_minor: U256,
    },
    NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
        number_of_accounts: usize,
        total_amount_demanded_minor: u128,
        cw_service_fee_balance_minor: u128,
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
                "Found a smaller transaction fee balance than it does for a single payment. \
                Number of canceled payments: {}. Transaction fee by single account: {} wei. \
                Consuming wallet balance: {} wei",
                number_of_accounts,
                per_transaction_requirement_minor.separate_with_commas(),
                cw_transaction_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                number_of_accounts,
                total_amount_demanded_minor,
                cw_service_fee_balance_minor,
            } => write!(
                f,
                "Found a smaller service fee balance than it does for a single payment. \
                Number of canceled payments: {}. Total amount demanded: {} wei. Consuming \
                wallet balance: {} wei",
                number_of_accounts.separate_with_commas(),
                total_amount_demanded_minor.separate_with_commas(),
                cw_service_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::AllAccountsEliminated => write!(
                f,
                "The adjustment algorithm had to eliminate each payable from the recently urged payment \
                due to lack of resources."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::TransactionAndServiceFeeAdjustmentRunner;
    use crate::accountant::payment_adjuster::criterion_calculators::balance_and_age_calculator::BalanceAndAgeCriterionCalculator;
    use crate::accountant::payment_adjuster::disqualification_arbiter::DisqualificationArbiter;
    use crate::accountant::payment_adjuster::inner::{
        PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::SpecialHandling::{
        InsignificantAccountEliminated, OutweighedAccounts,
    };
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustedAccountBeforeFinalization, AdjustmentIterationResult, SpecialHandling,
        UnconfirmedAdjustment, WeightedPayable,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        find_largest_exceeding_balance, weights_total,
    };
    use crate::accountant::payment_adjuster::service_fee_adjuster::{
        AdjustmentComputer, ServiceFeeAdjusterReal,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        make_extreme_payables, make_initialized_subject, make_qualified_payable_by_wallet,
        multiple_by_billion, CriterionCalculatorMock, DisqualificationGaugeMock,
        ServiceFeeAdjusterMock, MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR,
        PRESERVED_TEST_PAYMENT_THRESHOLDS,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
    use crate::accountant::test_utils::{
        make_guaranteed_qualified_payables, make_non_guaranteed_qualified_payable,
        make_payable_account,
    };
    use crate::accountant::{
        gwei_to_wei, CreditorThresholds, QualifiedPayableAccount, ResponseSkeleton,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use itertools::Either;
    use lazy_static::lazy_static;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use rand::rngs::mock;
    use std::collections::HashMap;
    use std::iter::zip;
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
                    subject.search_for_indispensable_adjustment(&qualified_payables, &*agent),
                    Ok(None),
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

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Ok(Some(Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2
            }))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Transaction fee amount 16,499,999,000,000,000 wei from your wallet \
            will not cover anticipated fees to send 3 transactions. Maximum is 2. The payments \
            count needs to be adjusted."
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

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(result, Ok(Some(Adjustment::ByServiceFee)));
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 100,000,\
        000,001 wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of \
        the MASQ token. Adjustment in their count or the amounts is required."));
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

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(
                PaymentAdjusterError::NotEnoughServiceFeeBalanceEvenForTheSmallestTransaction {
                    number_of_accounts: 3,
                    total_amount_demanded_minor: 920_000_000_000,
                    cw_service_fee_balance_minor
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

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

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
                    total_amount_demanded_minor: 6_000_000_000,
                    cw_service_fee_balance_minor: 333_000_000,
                },
                "Found a smaller service fee balance than it does for a single payment. \
                Number of canceled payments: 5. Total amount demanded: 6,000,000,000 wei. \
                Consuming wallet balance: 333,000,000 wei",
            ),
            (
                PaymentAdjusterError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: 4,
                    per_transaction_requirement_minor: 70_000_000_000_000,
                    cw_transaction_fee_balance_minor: U256::from(90_000),
                },
                "Found a smaller transaction fee balance than it does for a single \
                payment. Number of canceled payments: 4. Transaction fee by single \
                account: 70,000,000,000,000 wei. Consuming wallet balance: 90,000 \
                wei",
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
    fn apply_criteria_returns_accounts_sorted_by_criteria_in_descending_order() {
        let calculator = CriterionCalculatorMock::default()
            .calculate_result(1_000_000_002)
            .calculate_result(1_000_000_001)
            .calculate_result(1_000_000_003);
        let subject = make_initialized_subject(None, None, Some(calculator), Some(12345678), None);
        let make_account = |n: u64| {
            let account = make_non_guaranteed_qualified_payable(n);
            let wallet = account.bare_account.wallet.clone();
            (wallet, account)
        };
        let (wallet_1, payable_1) = make_account(111);
        let (wallet_2, payable_2) = make_account(222);
        let (wallet_3, payable_3) = make_account(333);

        let criteria_and_accounts =
            subject.calculate_weights_for_accounts(vec![payable_1, payable_2, payable_3]);

        let mut previous_weight = u128::MAX;
        let accounts_alone = criteria_and_accounts
            .into_iter()
            .map(|weighted_account| {
                assert!(
                    previous_weight > weighted_account.weight,
                    "Previous criteria {} wasn't larger than {} but should've been",
                    previous_weight,
                    weighted_account.weight
                );
                previous_weight = weighted_account.weight;
                weighted_account.qualified_account.bare_account.wallet
            })
            .collect::<Vec<Wallet>>();
        assert_eq!(accounts_alone, vec![wallet_3, wallet_1, wallet_2])
    }

    #[test]
    fn tinier_but_larger_in_weight_account_is_prioritized_outweighed_up_to_its_original_balance() {
        let now = SystemTime::now();
        let cw_service_fee_balance_minor = multiple_by_billion(3_500_000);
        let determine_limit_params_arc = Arc::new(Mutex::new(vec![]));
        let mut account_1 = make_qualified_payable_by_wallet("abc");
        let balance_1 = multiple_by_billion(3_000_000);
        account_1.bare_account.balance_wei = balance_1;
        let threshold_intercept_minor = account_1.payment_threshold_intercept_minor;
        let permanent_debt_allowed_minor = account_1.creditor_thresholds.permanent_debt_allowed_wei;
        let mut account_2 = make_qualified_payable_by_wallet("def");
        let wallet_2 = account_2.bare_account.wallet.clone();
        let balance_2 = multiple_by_billion(1_000_000);
        account_2.bare_account.balance_wei = balance_2;
        let largest_exceeding_balance = (balance_1 - account_1.payment_threshold_intercept_minor)
            .max(balance_2 - account_2.payment_threshold_intercept_minor);
        let mut subject = make_initialized_subject(
            None,
            Some(cw_service_fee_balance_minor),
            None,
            Some(largest_exceeding_balance),
            None,
        );
        let disqualification_gauge = DisqualificationGaugeMock::default()
            .determine_limit_result(cw_service_fee_balance_minor / 2)
            .determine_limit_params(&determine_limit_params_arc);
        subject.disqualification_arbiter =
            DisqualificationArbiter::new(Box::new(disqualification_gauge));
        let weighted_payables_in_descending_order = vec![
            WeightedPayable::new(account_2, multiple_by_billion(3_999_900)),
            WeightedPayable::new(account_1, multiple_by_billion(2_000_100)),
        ];

        let mut result = subject
            .calculate_criteria_and_propose_adjustments_recursively(
                weighted_payables_in_descending_order.clone(),
                TransactionAndServiceFeeAdjustmentRunner {},
            )
            .unwrap()
            .left()
            .unwrap();

        // Let's have an example to explain why this test is important.
        // First, the mock must be renewed; the available cw balance updated to the original value.
        prove_that_proposed_adjusted_balance_would_exceed_the_original_value(
            subject,
            cw_service_fee_balance_minor,
            weighted_payables_in_descending_order.clone(),
            wallet_2,
            balance_2,
            2.3,
        );
        // // So the assertion above showed the concern true.
        let first_returned_account = result.remove(0);
        // Outweighed accounts always take the first places
        assert_eq!(
            &first_returned_account.original_account,
            &weighted_payables_in_descending_order[0]
                .qualified_account
                .bare_account
        );
        assert_eq!(
            first_returned_account.proposed_adjusted_balance_minor,
            balance_2
        );
        let second_returned_account = result.remove(0);
        assert_eq!(
            &second_returned_account.original_account,
            &weighted_payables_in_descending_order[1]
                .qualified_account
                .bare_account
        );
        assert_eq!(
            second_returned_account.proposed_adjusted_balance_minor,
            2499999999999999
        );
        assert!(result.is_empty());
        let determine_limit_params = determine_limit_params_arc.lock().unwrap();
        assert_eq!(
            *determine_limit_params,
            vec![(
                balance_1,
                threshold_intercept_minor,
                permanent_debt_allowed_minor
            )]
        )
    }

    fn prove_that_proposed_adjusted_balance_would_exceed_the_original_value(
        mut subject: PaymentAdjusterReal,
        cw_service_fee_balance_minor: u128,
        weighted_accounts: Vec<WeightedPayable>,
        wallet_of_expected_outweighed: Wallet,
        original_balance_of_outweighed_account: u128,
        outweighed_by_multiple_of: f64,
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
        let proposed_adjusted_balance = unconfirmed_adjustments[0].proposed_adjusted_balance_minor;
        assert_eq!(
            unconfirmed_adjustments[0]
                .weighted_account
                .qualified_account
                .bare_account
                .wallet,
            wallet_of_expected_outweighed
        );
        // The weight of this account grew progressively due to the additional criterion added
        // in to the sum. Consequences would've been that redistribution of the adjusted balances
        // would've attributed this account with a larger amount to pay than it would've
        // contained before the test started. To prevent that, we secure a rule that an account can
        // never demand more than 100% of itself, ever
        assert!(
            proposed_adjusted_balance
                > (outweighed_by_multiple_of * original_balance_of_outweighed_account as f64)
                    as u128,
            "we expected the proposed balance clearly bigger than the original which is {} \
            but it was {}",
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
        let service_fee_balance_in_minor_units = balance_2;
        let disqualification_arbiter = &subject.disqualification_arbiter;
        let analysis_result = subject.analyzer.check_need_of_adjustment_by_service_fee(
            disqualification_arbiter,
            Either::Left(&qualified_payables),
            service_fee_balance_in_minor_units,
            &subject.logger,
        );
        // If concluded at the entry into the PaymentAdjuster that it has no point going off
        // because away the least demanding account cannot be satisfied we would get an error here.
        // However, it can only assess the balance (that early - in the real world) and accounts
        // with the smallest balance is outplayed by the other one gaining some kind of extra
        // significance
        assert_eq!(analysis_result, Ok(true));
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
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
    #[should_panic(
        expected = "internal error: entered unreachable code: This shouldn't be possible due to a preceding check"
    )]
    fn outweighed_accounts_with_no_remaining_accounts_is_not_possible() {
        let mut subject = PaymentAdjusterReal::new();
        let iteration_result = AdjustmentIterationResult::IterationWithSpecialHandling {
            case: OutweighedAccounts(vec![AdjustedAccountBeforeFinalization::new(
                make_payable_account(123),
                123456,
            )]),
            remaining_undecided_accounts: vec![],
        };

        let _ = subject.resolve_current_iteration_result(iteration_result);
    }

    #[test]
    fn account_disqualification_makes_the_rest_outweighed_as_cw_balance_becomes_excessive_for_them()
    {
        // Tests that a condition to short-circuit through is integrated for situations when
        // a disqualification frees means for other accounts and there is suddenly more to give
        // than how much the remaining accounts demand
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
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
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
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
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
        let qualified_payables = make_guaranteed_qualified_payables(
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
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
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

    // This function should take just such args that affects the adjustment mechanism, except
    // those that work as pure criteria parameters (= make up the weights). These should be
    // limited to minimum because in this kind of tests we don't want to be burdened with their
    // consideration.
    fn make_plucked_qualified_account(
        wallet_addr_fragment: &str,
        balance_major: u128,
        threshold_intercept_major: u128,
        permanent_debt_allowed_major: u128,
    ) -> QualifiedPayableAccount {
        QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet(wallet_addr_fragment),
                balance_wei: multiple_by_billion(balance_major),
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
        let balance_1 = 5_444_444_444;
        let qualified_account_1 =
            make_plucked_qualified_account("abc", balance_1, 2_000_000_000, 1_000_000_000);
        let balance_2 = 6_000_000_000;
        let qualified_account_2 =
            make_plucked_qualified_account("def", balance_2, 2_500_000_000, 2_000_000_000);
        let balance_3 = 6_666_666_666;
        let qualified_account_3 =
            make_plucked_qualified_account("ghi", balance_3, 3_000_000_000, 1_111_111_111);
        let qualified_payables = vec![
            qualified_account_1.clone(),
            qualified_account_2.clone(),
            qualified_account_3.clone(),
        ];
        let mut subject = PaymentAdjusterReal::new();
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiple_by_billion(4_500_000_000))
            .calculate_result(multiple_by_billion(4_200_000_000))
            .calculate_result(multiple_by_billion(3_800_000_000));
        subject.calculators = vec![Box::new(calculator_mock)];
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum_minor = balance_1 + balance_2 + balance_3;
        let service_fee_balance_in_minor_units =
            multiple_by_billion(accounts_sum_minor) - multiple_by_billion(3_000_000_000);
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_adjusted_balance_1 = 3_878_112_909_226_659_278;
        let expected_adjusted_balance_2 = 5_941_743_288_347_289_696;
        let expected_adjusted_balance_3 = 4_291_254_912_870_495_470;
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
            vec![account_2_adjusted, account_3_adjusted, account_1_adjusted]
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
|0x0000000000000000000000000000000000646566 {}
|                                           {}
|0x0000000000000000000000000000000000676869 {}
|                                           {}
|0x0000000000000000000000000000000000616263 {}
|                                           {}",
            balance_2.separate_with_commas(),
            expected_adjusted_balance_2.separate_with_commas(),
            balance_3.separate_with_commas(),
            expected_adjusted_balance_3.separate_with_commas(),
            balance_1.separate_with_commas(),
            expected_adjusted_balance_1.separate_with_commas()
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices() {
        init_test_logging();
        let test_name =
            "only_transaction_fee_causes_limitations_and_the_service_fee_balance_suffices";
        let now = SystemTime::now();
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghi"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(10_u128.pow(22));
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // The account 3 takes the first place for its age
        // (it weights more if the balance is so small)
        assert_eq!(
            result.affordable_accounts,
            vec![account_3.bare_account, account_2.bare_account]
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
|0x0000000000000000000000000000000000646566 333,000,000,000,000
|                                           333,000,000,000,000
|0x0000000000000000000000000000000000676869 222,000,000,000,000
|                                           222,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000616263 111,000,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn both_balances_insufficient_but_adjustment_by_service_fee_will_not_affect_the_payments_count()
    {
        // The course of events:
        // 1) adjustment by transaction fee (always means accounts elimination),
        // 2) adjustment by service fee (can but not have to cause an account drop-off)
        init_test_logging();
        let now = SystemTime::now();
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghk"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let service_fee_balance_in_minor_units = 111_000_000_000_000_u128 + 333_000_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); //just hardening, not so important
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // Account_1, the least important one, was eliminated for not big enough transaction fee balance
        let expected_accounts = {
            let account_2_adjusted = PayableAccount {
                balance_wei: 222_000_000_000_000,
                ..account_2.bare_account
            };
            vec![account_3.bare_account, account_2_adjusted]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
    }

    #[test]
    fn only_service_fee_balance_limits_the_payments_count() {
        init_test_logging();
        let test_name = "only_service_fee_balance_limits_the_payments_count";
        let now = SystemTime::now();
        let wallet_1 = make_wallet("def");
        // Account to be adjusted to keep as much as how much is left in the cw balance
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_1.clone(),
                balance_wei: 333_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(12000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Account to be outweighed and fully preserved
        let wallet_2 = make_wallet("abc");
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_2.clone(),
                balance_wei: 111_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(8000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Account to be disqualified
        let wallet_3 = make_wallet("ghk");
        let balance_3 = 600_000_000_000;
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_3.clone(),
                balance_wei: balance_3,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(6000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = 333_000_000_000 + 50_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 111,
            context_id: 234,
        });
        // Another place where I pick a populated response skeleton for hardening
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 272_000_000_000,
                ..account_1.bare_account
            };
            vec![account_1_adjusted, account_2.bare_account]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(
            result.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234
            })
        );
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Shortage of MASQ \
        in your consuming wallet impacts on payable 0x000000000000000000000000000000000067686b, \
        ruled out from this round of payments. The proposed adjustment 79,556,958,958 wei was less \
        than half of the recorded debt, 600,000,000,000 wei"
        ));
    }

    struct CompetitiveAccountsTestInputs<'a> {
        common: WalletsSetup<'a>,
        account_1_balance_positive_correction_minor: u128,
        account_2_balance_positive_correction_minor: u128,
        account_1_age_positive_correction_secs: u64,
        account_2_age_positive_correction_secs: u64,
    }

    #[derive(Clone, Copy)]
    struct WalletsSetup<'a> {
        wallet_1: &'a Wallet,
        wallet_2: &'a Wallet,
    }

    fn test_two_competitive_accounts_with_one_disqualified<'a>(
        test_scenario_name: &str,
        inputs: CompetitiveAccountsTestInputs,
        expected_wallet_of_the_winning_account: &'a Wallet,
    ) {
        let now = SystemTime::now();
        let cw_service_fee_balance_in_minor = 100_000_000_000_000 - 1;
        let standard_balance_per_account = 100_000_000_000_000;
        let standard_age_per_account = 12000;
        let account_1 = PayableAccount {
            wallet: inputs.common.wallet_1.clone(),
            balance_wei: standard_balance_per_account
                + inputs.account_1_balance_positive_correction_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.account_1_age_positive_correction_secs,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: inputs.common.wallet_2.clone(),
            balance_wei: standard_balance_per_account
                + inputs.account_2_balance_positive_correction_minor,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.account_2_age_positive_correction_secs,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2];
        let qualified_payables =
            make_guaranteed_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let mut subject = PaymentAdjusterReal::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance_in_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::ByServiceFee,
            response_skeleton_opt: None,
        };

        let mut result = subject
            .adjust_payments(adjustment_setup, now)
            .unwrap()
            .affordable_accounts;

        let winning_account = result.remove(0);
        assert_eq!(
            &winning_account.wallet, expected_wallet_of_the_winning_account,
            "{}: expected wallet {} but got {}",
            test_scenario_name, winning_account.wallet, expected_wallet_of_the_winning_account
        );
        assert_eq!(
            winning_account.balance_wei, cw_service_fee_balance_in_minor,
            "{}: expected full cw balance {}, but the account had {}",
            test_scenario_name, winning_account.balance_wei, cw_service_fee_balance_in_minor
        );
        assert!(
            result.is_empty(),
            "{}: is not empty, {:?} remains",
            test_scenario_name,
            result
        )
    }

    #[test]
    fn not_enough_service_fee_for_both_accounts_at_least_by_their_half_so_only_one_wins() {
        fn merge_test_name_with_test_scenario(description: &str) -> String {
            format!(
                "not_enough_service_fee_for_both_accounts_at_least_by_their_half_so_only_one_wins{}",
                description
            )
        }

        let w1 = make_wallet("abcd");
        let w2 = make_wallet("cdef");
        let common_input = WalletsSetup {
            wallet_1: &w1,
            wallet_2: &w2,
        };
        // scenario A
        let first_scenario_name = merge_test_name_with_test_scenario("when equally significant");
        let expected_wallet_of_the_winning_account = &w2;

        test_two_competitive_accounts_with_one_disqualified(
            &first_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 0,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 0,
            },
            expected_wallet_of_the_winning_account,
        );
        //--------------------------------------------------------------------
        // scenario B
        let second_scenario_name =
            merge_test_name_with_test_scenario("first more significant by balance");
        let expected_wallet_of_the_winning_account = &w1;

        test_two_competitive_accounts_with_one_disqualified(
            &second_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 1,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 0,
            },
            expected_wallet_of_the_winning_account,
        );
        //--------------------------------------------------------------------
        // scenario C
        let third_scenario_name =
            merge_test_name_with_test_scenario("second more significant by age");
        let expected_wallet_of_the_winning_account = &w2;

        test_two_competitive_accounts_with_one_disqualified(
            &third_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                account_1_balance_positive_correction_minor: 0,
                account_2_balance_positive_correction_minor: 0,
                account_1_age_positive_correction_secs: 0,
                account_2_age_positive_correction_secs: 1,
            },
            expected_wallet_of_the_winning_account,
        );
    }

    #[test]
    fn service_fee_as_well_as_transaction_fee_limits_the_payments_count() {
        init_test_logging();
        let test_name = "service_fee_as_well_as_transaction_fee_limits_the_payments_count";
        let now = SystemTime::now();
        // Thrown away as the second one due to shortage of service fee,
        // for the proposed adjusted balance insignificance (the third account withdraws
        // most of the available balance from the consuming wallet for itself)
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 10_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        // Thrown away as the first one due to shortage of transaction fee,
        // as it is the least significant by criteria at the moment
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 55_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let wallet_3 = make_wallet("ghi");
        let last_paid_timestamp_3 = now.checked_sub(Duration::from_secs(29000)).unwrap();
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: wallet_3.clone(),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2, account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor = 300_000_000_000_000_u128;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_in_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(
            result.affordable_accounts,
            vec![PayableAccount {
                wallet: wallet_3,
                balance_wei: service_fee_balance_in_minor,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            }]
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
|0x0000000000000000000000000000000000676869 333,000,000,000,000
|                                           300,000,000,000,000
|
|Ruled Out Accounts                         Original
|
|0x0000000000000000000000000000000000616263 10,000,000,000,000
|0x0000000000000000000000000000000000646566 55,000,000,000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient(
    ) {
        init_test_logging();
        let test_name = "late_error_after_transaction_fee_adjustment_but_rechecked_transaction_fee_found_fatally_insufficient";
        let now = SystemTime::now();
        // This account is eliminated in the transaction fee cut
        let account_1 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: 111_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_2 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("def"),
                balance_wei: 333_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let account_3 = QualifiedPayableAccount::new(
            PayableAccount {
                wallet: make_wallet("ghi"),
                balance_wei: 222_000_000_000_000,
                last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
                pending_payable_opt: None,
            },
            todo!(),
            todo!(),
        );
        let qualified_payables = vec![account_1, account_2, account_3];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // This is exactly the amount which will provoke an error
        let service_fee_balance_in_minor_units = (111_000_000_000_000 / 2) - 1;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::TransactionFeeInPriority {
                affordable_transaction_count: 2,
            },
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
                number_of_accounts: 2,
                total_amount_demanded_minor: 333_000_000_000_000 + 222_000_000_000_000,
                cw_service_fee_balance_minor: service_fee_balance_in_minor_units
            }
        );
        TestLogHandler::new()
            .exists_log_containing(&format!(
            "ERROR: {test_name}: Passed successfully adjustment by transaction fee but noticing \
            critical scarcity of MASQ balance. Operation will abort."));
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
            .enumerate()
            .map(|(idx, payable)| {
                let balance = payable.balance_wei;
                QualifiedPayableAccount {
                    bare_account: payable,
                    payment_threshold_intercept_minor: (balance / 10) * 7,
                    creditor_thresholds: CreditorThresholds {
                        permanent_debt_allowed_wei: (balance / 10) * 7,
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
            |(nominal_account_1, nominal_account_2, now)| {
                vec![
                    // First stage: BalanceAndAgeCalculator
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

    struct AssertionValue {
        wallet_to_match_result_with: Wallet,
        expected_computed_weight: u128,
    }

    fn test_calculators_reactivity(
        input_matrix_configurator: InputMatrixConfigurator,
        nominal_weight: u128,
    ) {
        let defaulted_payment_adjuster = PaymentAdjusterReal::default();
        let calculators_count = defaulted_payment_adjuster.calculators.len();
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
            "If you've recently added in a new \
        calculator, you should add a single test case for it this test. See the input matrix, \
        it is the place where you should use the two accounts you can clone. Make sure you \
        modify only those parameters processed by your new calculator "
        );
        test_accounts_from_input_matrix(
            input_matrix,
            defaulted_payment_adjuster,
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
        let largest_exceeding_balance_recently_qualified =
            find_largest_exceeding_balance(&qualified_payables);
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
            // This is just a sentinel for an actual result.
            // We care only for the params
            .perform_adjustment_by_service_fee_result(
                AdjustmentIterationResult::AllAccountsProcessed(vec![]),
            );
        subject.service_fee_adjuster = Box::new(service_fee_adjuster_mock);

        let result = subject.run_adjustment(qualified_payables.to_vec());

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
        defaulted_payment_adjuster: PaymentAdjusterReal,
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
            .zip(defaulted_payment_adjuster.calculators.into_iter())
            .for_each(
                |((qualified_payments_and_expected_computed_weights), calculator)| {
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
                },
            );
    }

    fn make_comparison_hashmap(
        weighted_accounts: Vec<WeightedPayable>,
    ) -> HashMap<Wallet, WeightedPayable> {
        let feeding_iterator = weighted_accounts.into_iter().map(|account| {
            (
                account.qualified_account.bare_account.wallet.clone(),
                account,
            )
        });
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
