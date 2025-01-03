// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

// If possible, keep these modules private
mod criterion_calculators;
mod disqualification_arbiter;
mod inner;
mod logging_and_diagnostics;
mod miscellaneous;
#[cfg(test)]
mod non_unit_tests;
mod preparatory_analyser;
mod service_fee_adjuster;
// Intentionally public
#[cfg(test)]
pub mod test_utils;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::criterion_calculators::balance_calculator::BalanceCriterionCalculator;
use crate::accountant::payment_adjuster::criterion_calculators::CriterionCalculator;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::ordinary_diagnostic_functions::calculated_criterion_and_weight_diagnostics;
use crate::accountant::payment_adjuster::logging_and_diagnostics::diagnostics::{collection_diagnostics, diagnostics};
use crate::accountant::payment_adjuster::disqualification_arbiter::{
    DisqualificationArbiter,
};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner,
};
use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::{
    accounts_before_and_after_debug,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{AdjustedAccountBeforeFinalization, WeighedPayable};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    eliminate_accounts_by_tx_fee_limit,
    exhaust_cw_balance_entirely, find_largest_exceeding_balance,
    sum_as, no_affordable_accounts_found,
};
use crate::accountant::payment_adjuster::preparatory_analyser::{LateServiceFeeSingleTxErrorFactory, PreparatoryAnalyzer};
use crate::accountant::payment_adjuster::service_fee_adjuster::{
    ServiceFeeAdjuster, ServiceFeeAdjusterReal,
};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
use crate::accountant::{AnalyzedPayableAccount, QualifiedPayableAccount};
use crate::diagnostics;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use itertools::Either;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;
use thousands::Separable;
use variant_count::VariantCount;
use web3::types::{Address, U256};
use masq_lib::utils::convert_collection;
use crate::accountant::payment_adjuster::preparatory_analyser::accounts_abstraction::DisqualificationLimitProvidingAccount;

// PaymentAdjuster is a recursive and scalable algorithm that inspects payments under conditions
// of an acute insolvency. You can easily expand the range of evaluated parameters to determine
// an optimized allocation of scarce assets by writing your own CriterionCalculator. The calculator
// is supposed to be dedicated to a single parameter that can be tracked for each payable account.
//
// For parameters that can't be derived from each account, or even one at all, there is a way to
// provide such data up into the calculator. This can be achieved via the PaymentAdjusterInner.
//
// Once the new calculator exists, its place belongs in the vector of calculators which is the heart
// of this module.

pub type AdjustmentAnalysisResult =
    Result<Either<IntactOriginalAccounts, AdjustmentAnalysisReport>, PaymentAdjusterError>;

pub type IntactOriginalAccounts = Vec<QualifiedPayableAccount>;

pub trait PaymentAdjuster {
    fn consider_adjustment(
        &self,
        qualified_payables: Vec<QualifiedPayableAccount>,
        agent: &dyn BlockchainAgent,
    ) -> AdjustmentAnalysisResult;

    fn adjust_payments(
        &self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError>;
}

pub struct PaymentAdjusterReal {
    analyzer: PreparatoryAnalyzer,
    disqualification_arbiter: DisqualificationArbiter,
    service_fee_adjuster: Box<dyn ServiceFeeAdjuster>,
    calculators: Vec<Box<dyn CriterionCalculator>>,
    inner: PaymentAdjusterInner,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn consider_adjustment(
        &self,
        qualified_payables: Vec<QualifiedPayableAccount>,
        agent: &dyn BlockchainAgent,
    ) -> AdjustmentAnalysisResult {
        let disqualification_arbiter = &self.disqualification_arbiter;
        let logger = &self.logger;

        self.analyzer
            .analyze_accounts(agent, disqualification_arbiter, qualified_payables, logger)
    }

    fn adjust_payments(
        &self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutboundPaymentsInstructions, PaymentAdjusterError> {
        let analyzed_payables = setup.adjustment_analysis.accounts;
        let response_skeleton_opt = setup.response_skeleton_opt;
        let agent = setup.agent;
        let initial_service_fee_balance_minor = agent.service_fee_balance_minor();
        let required_adjustment = setup.adjustment_analysis.adjustment;
        let max_debt_above_threshold_in_qualified_payables_minor =
            find_largest_exceeding_balance(&analyzed_payables);

        self.initialize_inner(
            required_adjustment,
            initial_service_fee_balance_minor,
            max_debt_above_threshold_in_qualified_payables_minor,
            now,
        );

        let sketched_debug_log_opt = self.sketch_debug_log_opt(&analyzed_payables);

        let affordable_accounts = self.run_adjustment(analyzed_payables)?;

        self.complete_debug_log_if_enabled(sketched_debug_log_opt, &affordable_accounts);

        self.inner.invalidate_guts();

        Ok(OutboundPaymentsInstructions::new(
            Either::Right(affordable_accounts),
            agent,
            response_skeleton_opt,
        ))
    }
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
            calculators: vec![Box::new(BalanceCriterionCalculator::default())],
            inner: PaymentAdjusterInner::default(),
            logger: Logger::new("PaymentAdjuster"),
        }
    }

    fn initialize_inner(
        &self,
        required_adjustment: Adjustment,
        initial_service_fee_balance_minor: u128,
        max_debt_above_threshold_in_qualified_payables_minor: u128,
        now: SystemTime,
    ) {
        let transaction_fee_limitation_opt = match required_adjustment {
            Adjustment::BeginByTransactionFee {
                transaction_count_limit,
            } => Some(transaction_count_limit),
            Adjustment::ByServiceFee => None,
        };

        self.inner.initialize_guts(
            transaction_fee_limitation_opt,
            initial_service_fee_balance_minor,
            max_debt_above_threshold_in_qualified_payables_minor,
            now,
        )
    }

    fn run_adjustment(
        &self,
        analyzed_accounts: Vec<AnalyzedPayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let weighed_accounts = self.calculate_weights(analyzed_accounts);
        let processed_accounts = self.resolve_initial_adjustment_dispatch(weighed_accounts)?;

        if no_affordable_accounts_found(&processed_accounts) {
            return Err(PaymentAdjusterError::RecursionDrainedAllAccounts);
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

    fn resolve_initial_adjustment_dispatch(
        &self,
        weighed_payables: Vec<WeighedPayable>,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        if let Some(limit) = self.inner.transaction_count_limit_opt() {
            return self.begin_with_adjustment_by_transaction_fee(weighed_payables, limit);
        }

        Ok(Either::Left(
            self.propose_possible_adjustment_recursively(weighed_payables),
        ))
    }

    fn begin_with_adjustment_by_transaction_fee(
        &self,
        weighed_accounts: Vec<WeighedPayable>,
        transaction_count_limit: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        diagnostics!(
            "\nBEGINNING WITH ADJUSTMENT BY TRANSACTION FEE FOR ACCOUNTS:",
            &weighed_accounts
        );

        let error_factory = LateServiceFeeSingleTxErrorFactory::new(&weighed_accounts);

        let weighed_accounts_affordable_by_transaction_fee =
            eliminate_accounts_by_tx_fee_limit(weighed_accounts, transaction_count_limit);

        let cw_service_fee_balance_minor = self.inner.original_cw_service_fee_balance_minor();

        if self.analyzer.recheck_if_service_fee_adjustment_is_needed(
            &weighed_accounts_affordable_by_transaction_fee,
            cw_service_fee_balance_minor,
            error_factory,
            &self.logger,
        )? {
            let final_set_before_exhausting_cw_balance = self
                .propose_possible_adjustment_recursively(
                    weighed_accounts_affordable_by_transaction_fee,
                );

            Ok(Either::Left(final_set_before_exhausting_cw_balance))
        } else {
            let accounts_not_needing_adjustment =
                convert_collection(weighed_accounts_affordable_by_transaction_fee);

            Ok(Either::Right(accounts_not_needing_adjustment))
        }
    }

    fn propose_possible_adjustment_recursively(
        &self,
        weighed_accounts: Vec<WeighedPayable>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        diagnostics!(
            "\nUNRESOLVED ACCOUNTS IN CURRENT ITERATION:",
            &weighed_accounts
        );

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

        let decided_accounts = current_iteration_result.decided_accounts;
        let remaining_undecided_accounts = current_iteration_result.remaining_undecided_accounts;

        if remaining_undecided_accounts.is_empty() {
            return decided_accounts;
        }

        if !decided_accounts.is_empty() {
            self.adjust_remaining_unallocated_cw_balance_down(&decided_accounts)
        }

        let merged =
            if self.is_cw_balance_enough_to_remaining_accounts(&remaining_undecided_accounts) {
                Self::merge_accounts(
                    decided_accounts,
                    convert_collection(remaining_undecided_accounts),
                )
            } else {
                Self::merge_accounts(
                    decided_accounts,
                    self.propose_possible_adjustment_recursively(remaining_undecided_accounts),
                )
            };

        diagnostics!(
            "\nFINAL SET OF ADJUSTED ACCOUNTS IN CURRENT ITERATION:",
            &merged
        );

        merged
    }

    fn is_cw_balance_enough_to_remaining_accounts(
        &self,
        remaining_undecided_accounts: &[WeighedPayable],
    ) -> bool {
        let unallocated_cw_service_fee_balance =
            self.inner.unallocated_cw_service_fee_balance_minor();
        let minimum_sum_required: u128 = sum_as(remaining_undecided_accounts, |weighed_account| {
            weighed_account.disqualification_limit()
        });
        minimum_sum_required <= unallocated_cw_service_fee_balance
    }

    fn merge_accounts(
        mut previously_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
        newly_decided_accounts: Vec<AdjustedAccountBeforeFinalization>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        previously_decided_accounts.extend(newly_decided_accounts);
        previously_decided_accounts
    }

    fn calculate_weights(&self, accounts: Vec<AnalyzedPayableAccount>) -> Vec<WeighedPayable> {
        self.apply_criteria(self.calculators.as_slice(), accounts)
    }

    fn apply_criteria(
        &self,
        criteria_calculators: &[Box<dyn CriterionCalculator>],
        qualified_accounts: Vec<AnalyzedPayableAccount>,
    ) -> Vec<WeighedPayable> {
        qualified_accounts
            .into_iter()
            .map(|payable| {
                let weight =
                    criteria_calculators
                        .iter()
                        .fold(0_u128, |weight, criterion_calculator| {
                            let new_criterion =
                                criterion_calculator.calculate(&payable.qualified_as, &self.inner);

                            let summed_up = weight + new_criterion;

                            calculated_criterion_and_weight_diagnostics(
                                payable.qualified_as.bare_account.wallet.address(),
                                criterion_calculator.as_ref(),
                                new_criterion,
                                summed_up,
                            );

                            summed_up
                        });

                WeighedPayable::new(payable, weight)
            })
            .collect()
    }

    fn adjust_remaining_unallocated_cw_balance_down(
        &self,
        decided_accounts: &[AdjustedAccountBeforeFinalization],
    ) {
        let subtrahend_total: u128 = sum_as(decided_accounts, |account| {
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

    fn sketch_debug_log_opt(
        &self,
        qualified_payables: &[AnalyzedPayableAccount],
    ) -> Option<HashMap<Address, u128>> {
        self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|payable| {
                    (
                        payable.qualified_as.bare_account.wallet.address(),
                        payable.qualified_as.bare_account.balance_wei,
                    )
                })
                .collect()
        })
    }

    fn complete_debug_log_if_enabled(
        &self,
        sketched_debug_info_opt: Option<HashMap<Address, u128>>,
        fully_processed_accounts: &[PayableAccount],
    ) {
        self.logger.debug(|| {
            let sketched_debug_info =
                sketched_debug_info_opt.expect("debug is enabled, so info should exist");
            accounts_before_and_after_debug(sketched_debug_info, fully_processed_accounts)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adjustment {
    ByServiceFee,
    BeginByTransactionFee { transaction_count_limit: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjustmentAnalysisReport {
    pub adjustment: Adjustment,
    pub accounts: Vec<AnalyzedPayableAccount>,
}

impl AdjustmentAnalysisReport {
    pub fn new(adjustment: Adjustment, accounts: Vec<AnalyzedPayableAccount>) -> Self {
        AdjustmentAnalysisReport {
            adjustment,
            accounts,
        }
    }
}

#[derive(Debug, PartialEq, Eq, VariantCount)]
pub enum PaymentAdjusterError {
    AbsolutelyInsufficientBalance {
        number_of_accounts: usize,
        transaction_fee_opt: Option<TransactionFeeImmoderateInsufficiency>,
        service_fee_opt: Option<ServiceFeeImmoderateInsufficiency>,
    },
    AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
        original_number_of_accounts: usize,
        number_of_accounts: usize,
        original_total_service_fee_required_minor: u128,
        cw_service_fee_balance_minor: u128,
    },
    RecursionDrainedAllAccounts,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TransactionFeeImmoderateInsufficiency {
    pub per_transaction_requirement_minor: u128,
    pub cw_transaction_fee_balance_minor: U256,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceFeeImmoderateInsufficiency {
    pub total_service_fee_required_minor: u128,
    pub cw_service_fee_balance_minor: u128,
}

impl PaymentAdjusterError {
    pub fn insolvency_detected(&self) -> bool {
        match self {
            PaymentAdjusterError::AbsolutelyInsufficientBalance { .. } => true,
            PaymentAdjusterError::AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
                ..
            } => true,
            PaymentAdjusterError::RecursionDrainedAllAccounts => true,
            // We haven't needed to worry in this matter yet, this is rather a future alarm that
            // will draw attention after somebody adds a possibility for an error not necessarily
            // implying that an insolvency was detected before. At the moment, each error occurs
            // only alongside an actual insolvency. (Hint: There might be consequences for
            // the wording of the error message whose forming takes place back out, nearer to the
            // Accountant's general area)
        }
    }
}

impl Display for PaymentAdjusterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts,
                transaction_fee_opt,
                service_fee_opt,
            } => {
                match (transaction_fee_opt, service_fee_opt) {
                    (Some(transaction_fee_check_summary), None) =>
                        write!(
                        f,
                        "Current transaction fee balance is not enough to pay a single payment. \
                        Number of canceled payments: {}. Transaction fee per payment: {} wei, while \
                        the wallet contains: {} wei",
                        number_of_accounts,
                        transaction_fee_check_summary.per_transaction_requirement_minor.separate_with_commas(),
                        transaction_fee_check_summary.cw_transaction_fee_balance_minor.separate_with_commas()
                    ),
                    (None, Some(service_fee_check_summary)) =>
                        write!(
                        f,
                        "Current service fee balance is not enough to pay a single payment. \
                        Number of canceled payments: {}. Total amount required: {} wei, while the wallet \
                        contains: {} wei",
                        number_of_accounts,
                        service_fee_check_summary.total_service_fee_required_minor.separate_with_commas(),
                        service_fee_check_summary.cw_service_fee_balance_minor.separate_with_commas()),
                    (Some(transaction_fee_check_summary), Some(service_fee_check_summary)) =>
                        write!(
                        f,
                        "Neither transaction fee nor service fee balance is enough to pay a single payment. \
                        Number of payments considered: {}. Transaction fee per payment: {} wei, while in \
                        wallet: {} wei. Total service fee required: {} wei, while in wallet: {} wei",
                        number_of_accounts,
                        transaction_fee_check_summary.per_transaction_requirement_minor.separate_with_commas(),
                        transaction_fee_check_summary.cw_transaction_fee_balance_minor.separate_with_commas(),
                        service_fee_check_summary.total_service_fee_required_minor.separate_with_commas(),
                        service_fee_check_summary.cw_service_fee_balance_minor.separate_with_commas()
                ),
                    (None, None) => unreachable!("This error contains no specifications")
                }
            },
            PaymentAdjusterError::AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
                original_number_of_accounts,
                number_of_accounts,
                original_total_service_fee_required_minor,
                cw_service_fee_balance_minor,
            } => write!(f, "The original set with {} accounts was adjusted down to {} due to \
                transaction fee. The new set was tested on service fee later again and did not \
                pass. Original required amount of service fee: {} wei, while the wallet \
                contains {} wei.",
                original_number_of_accounts,
                number_of_accounts,
                        original_total_service_fee_required_minor.separate_with_commas(),
                cw_service_fee_balance_minor.separate_with_commas()
            ),
            PaymentAdjusterError::RecursionDrainedAllAccounts => write!(
                f,
                "The payments adjusting process failed to find any combination of payables that \
                can be paid immediately with the finances provided."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::inner::PaymentAdjusterInner;
    use crate::accountant::payment_adjuster::logging_and_diagnostics::log_functions::LATER_DETECTED_SERVICE_FEE_SEVERE_SCARCITY;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
        AdjustmentIterationResult, WeighedPayable,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
        find_largest_exceeding_balance, sum_as,
    };
    use crate::accountant::payment_adjuster::service_fee_adjuster::illustrative_util::illustrate_why_we_need_to_prevent_exceeding_the_original_value;
    use crate::accountant::payment_adjuster::test_utils::exposed_utils::convert_qualified_into_analyzed_payables_in_test;
    use crate::accountant::payment_adjuster::test_utils::local_utils::{
        make_mammoth_payables, make_meaningless_analyzed_account_by_wallet, multiply_by_billion,
        multiply_by_billion_concise, multiply_by_quintillion, multiply_by_quintillion_concise,
        CriterionCalculatorMock, PaymentAdjusterBuilder, ServiceFeeAdjusterMock,
        MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR, PRESERVED_TEST_PAYMENT_THRESHOLDS,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, AdjustmentAnalysisReport, PaymentAdjuster, PaymentAdjusterError,
        PaymentAdjusterReal, ServiceFeeImmoderateInsufficiency,
        TransactionFeeImmoderateInsufficiency,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
    use crate::accountant::test_utils::{
        make_analyzed_payables, make_meaningless_analyzed_account, make_payable_account,
        make_qualified_payables,
    };
    use crate::accountant::{
        AnalyzedPayableAccount, CreditorThresholds, QualifiedPayableAccount, ResponseSkeleton,
    };
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::TX_FEE_MARGIN_IN_PERCENT;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use itertools::{Either, Itertools};
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::HashMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use std::{usize, vec};
    use thousands::Separable;
    use web3::types::{Address, U256};

    #[test]
    #[should_panic(
        expected = "PaymentAdjusterInner is uninitialized. It was identified during \
        the execution of 'unallocated_cw_service_fee_balance_minor()'"
    )]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let subject = PaymentAdjusterReal::new();

        let _ = subject.inner.unallocated_cw_service_fee_balance_minor();
    }

    #[test]
    fn consider_adjustment_happy_path() {
        init_test_logging();
        let test_name = "consider_adjustment_happy_path";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // Service fee balance > payments
        let input_1 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![
                    multiply_by_billion(85),
                    multiply_by_billion(15) - 1,
                ],
                cw_balance_minor: multiply_by_billion(100),
            }),
            None,
        );
        // Service fee balance == payments
        let input_2 = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![
                    multiply_by_billion(85),
                    multiply_by_billion(15),
                ],
                cw_balance_minor: multiply_by_billion(100),
            }),
            None,
        );
        let transaction_fee_balance_exactly_required_minor: u128 = {
            let base_value = (100 * 6 * 53_000) as u128;
            let with_margin = TX_FEE_MARGIN_IN_PERCENT.add_percent_to(base_value);
            multiply_by_billion(with_margin)
        };
        // Transaction fee balance > payments
        let input_3 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                gas_price_major: 100,
                number_of_accounts: 6,
                tx_computation_units: 53_000,
                cw_transaction_fee_balance_minor: transaction_fee_balance_exactly_required_minor
                    + 1,
            }),
        );
        // Transaction fee balance == payments
        let input_4 = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                gas_price_major: 100,
                number_of_accounts: 6,
                tx_computation_units: 53_000,
                cw_transaction_fee_balance_minor: transaction_fee_balance_exactly_required_minor,
            }),
        );

        [input_1, input_2, input_3, input_4]
            .into_iter()
            .enumerate()
            .for_each(|(idx, (qualified_payables, agent))| {
                assert_eq!(
                    subject.consider_adjustment(qualified_payables.clone(), &*agent),
                    Ok(Either::Left(qualified_payables)),
                    "failed for tested input number {:?}",
                    idx + 1
                )
            });

        TestLogHandler::new().exists_no_log_containing(&format!("WARN: {test_name}:"));
    }

    #[test]
    fn consider_adjustment_sad_path_for_transaction_fee() {
        init_test_logging();
        let test_name = "consider_adjustment_sad_path_for_transaction_fee";
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let number_of_accounts = 3;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            None,
            Some(TestConfigForTransactionFees {
                gas_price_major: 100,
                number_of_accounts,
                tx_computation_units: 55_000,
                cw_transaction_fee_balance_minor: TX_FEE_MARGIN_IN_PERCENT
                    .add_percent_to(multiply_by_billion(100 * 3 * 55_000))
                    - 1,
            }),
        );

        let result = subject.consider_adjustment(qualified_payables.clone(), &*agent);

        let analyzed_payables =
            convert_qualified_into_analyzed_payables_in_test(qualified_payables);
        assert_eq!(
            result,
            Ok(Either::Right(AdjustmentAnalysisReport::new(
                Adjustment::BeginByTransactionFee {
                    transaction_count_limit: 2
                },
                analyzed_payables
            )))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Transaction fee balance of 18,974,999,999,999,999 wei cannot cover \
            the anticipated 18,975,000,000,000,000 wei for 3 transactions. Maximal count is set to 2. \
            Adjustment must be performed."
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that abandoning your debts is going to result in \
            delinquency bans. In order to consume services without limitations, you will need to \
            place more funds into your consuming wallet."
        ));
    }

    #[test]
    fn consider_adjustment_sad_path_for_service_fee_balance() {
        init_test_logging();
        let test_name = "consider_adjustment_positive_for_service_fee_balance";
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![
                    multiply_by_billion(85),
                    multiply_by_billion(15) + 1,
                ],
                cw_balance_minor: multiply_by_billion(100),
            }),
            None,
        );

        let result = subject.consider_adjustment(qualified_payables.clone(), &*agent);

        let analyzed_payables =
            convert_qualified_into_analyzed_payables_in_test(qualified_payables);
        assert_eq!(
            result,
            Ok(Either::Right(AdjustmentAnalysisReport::new(
                Adjustment::ByServiceFee,
                analyzed_payables
            )))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Mature payables \
        amount to 100,000,000,001 MASQ wei while the consuming wallet holds only 100,000,000,000 \
        wei. Adjustment in their count or balances is necessary."
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Please be aware that abandoning your debts is going to result in \
            delinquency bans. In order to consume services without limitations, you will need to \
            place more funds into your consuming wallet."
        ));
    }

    #[test]
    fn service_fee_balance_is_fine_but_transaction_fee_balance_throws_error() {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 3;
        let tx_fee_exactly_required_for_single_tx = {
            let base_minor = multiply_by_billion(55_000 * 100);
            TX_FEE_MARGIN_IN_PERCENT.add_percent_to(base_minor)
        };
        let cw_transaction_fee_balance_minor = tx_fee_exactly_required_for_single_tx - 1;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![multiply_by_billion(123)],
                cw_balance_minor: multiply_by_billion(444),
            }),
            Some(TestConfigForTransactionFees {
                gas_price_major: 100,
                number_of_accounts,
                tx_computation_units: 55_000,
                cw_transaction_fee_balance_minor,
            }),
        );

        let result = subject.consider_adjustment(qualified_payables, &*agent);

        let per_transaction_requirement_minor = {
            let base_minor = multiply_by_billion(55_000 * 100);
            TX_FEE_MARGIN_IN_PERCENT.add_percent_to(base_minor)
        };
        assert_eq!(
            result,
            Err(PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts,
                transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency {
                    per_transaction_requirement_minor,
                    cw_transaction_fee_balance_minor: cw_transaction_fee_balance_minor.into(),
                }),
                service_fee_opt: None
            })
        );
    }

    #[test]
    fn checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_throws_error() {
        let test_name = "checking_three_accounts_happy_for_transaction_fee_but_service_fee_balance_throws_error";
        let garbage_cw_service_fee_balance = u128::MAX;
        let service_fee_balances_config_opt = Some(TestConfigForServiceFeeBalances {
            payable_account_balances_minor: vec![
                multiply_by_billion(120),
                multiply_by_billion(300),
                multiply_by_billion(500),
            ],
            cw_balance_minor: garbage_cw_service_fee_balance,
        });
        let (qualified_payables, boxed_agent) =
            make_input_for_initial_check_tests(service_fee_balances_config_opt, None);
        let analyzed_accounts =
            convert_qualified_into_analyzed_payables_in_test(qualified_payables.clone());
        let minimal_disqualification_limit = analyzed_accounts
            .iter()
            .map(|account| account.disqualification_limit_minor)
            .min()
            .unwrap();
        // Condition for the error to be thrown
        let actual_insufficient_cw_service_fee_balance = minimal_disqualification_limit - 1;
        let agent_accessible = reconstruct_mock_agent(boxed_agent);
        // Dropping the garbage value on the floor
        let _ = agent_accessible.service_fee_balance_minor();
        let agent = agent_accessible
            .service_fee_balance_minor_result(actual_insufficient_cw_service_fee_balance);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consider_adjustment(qualified_payables, &agent);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts: 3,
                transaction_fee_opt: None,
                service_fee_opt: Some(ServiceFeeImmoderateInsufficiency {
                    total_service_fee_required_minor: multiply_by_billion(920),
                    cw_service_fee_balance_minor: actual_insufficient_cw_service_fee_balance
                })
            })
        );
    }

    #[test]
    fn both_balances_are_not_enough_even_for_single_transaction() {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 2;
        let (qualified_payables, agent) = make_input_for_initial_check_tests(
            Some(TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![
                    multiply_by_billion(200),
                    multiply_by_billion(300),
                ],
                cw_balance_minor: 0,
            }),
            Some(TestConfigForTransactionFees {
                gas_price_major: 123,
                number_of_accounts,
                tx_computation_units: 55_000,
                cw_transaction_fee_balance_minor: 0,
            }),
        );

        let result = subject.consider_adjustment(qualified_payables, &*agent);

        let per_transaction_requirement_minor =
            TX_FEE_MARGIN_IN_PERCENT.add_percent_to(55_000 * multiply_by_billion(123));
        assert_eq!(
            result,
            Err(PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts,
                transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency {
                    per_transaction_requirement_minor,
                    cw_transaction_fee_balance_minor: U256::zero(),
                }),
                service_fee_opt: Some(ServiceFeeImmoderateInsufficiency {
                    total_service_fee_required_minor: multiply_by_billion(500),
                    cw_service_fee_balance_minor: 0
                })
            })
        );
    }

    #[test]
    fn payment_adjuster_error_implements_display() {
        let inputs = vec![
            (
                PaymentAdjusterError::AbsolutelyInsufficientBalance {
                    number_of_accounts: 4,
                    transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency{
                        per_transaction_requirement_minor: multiply_by_billion(70_000),
                        cw_transaction_fee_balance_minor: U256::from(90_000),
                    }),
                    service_fee_opt: None
                },
                "Current transaction fee balance is not enough to pay a single payment. Number of \
                canceled payments: 4. Transaction fee per payment: 70,000,000,000,000 wei, while \
                the wallet contains: 90,000 wei",
            ),
            (
                PaymentAdjusterError::AbsolutelyInsufficientBalance {
                    number_of_accounts: 5,
                    transaction_fee_opt: None,
                    service_fee_opt: Some(ServiceFeeImmoderateInsufficiency{
                        total_service_fee_required_minor: 6_000_000_000,
                        cw_service_fee_balance_minor: 333_000_000,
                    })
                },
                "Current service fee balance is not enough to pay a single payment. Number of \
                canceled payments: 5. Total amount required: 6,000,000,000 wei, while the wallet \
                contains: 333,000,000 wei",
            ),
            (
                PaymentAdjusterError::AbsolutelyInsufficientBalance {
                    number_of_accounts: 5,
                    transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency{
                        per_transaction_requirement_minor:  5_000_000_000,
                        cw_transaction_fee_balance_minor: U256::from(3_000_000_000_u64)
                    }),
                    service_fee_opt: Some(ServiceFeeImmoderateInsufficiency{
                        total_service_fee_required_minor: 7_000_000_000,
                        cw_service_fee_balance_minor: 100_000_000
                    })
                },
                "Neither transaction fee nor service fee balance is enough to pay a single payment. \
                 Number of payments considered: 5. Transaction fee per payment: 5,000,000,000 wei, \
                 while in wallet: 3,000,000,000 wei. Total service fee required: 7,000,000,000 wei, \
                 while in wallet: 100,000,000 wei",
            ),
            (
                PaymentAdjusterError::AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
                    original_number_of_accounts: 6,
                    number_of_accounts: 3,
                    original_total_service_fee_required_minor: 1234567891011,
                    cw_service_fee_balance_minor: 333333,
                },
                "The original set with 6 accounts was adjusted down to 3 due to transaction fee. \
                The new set was tested on service fee later again and did not pass. Original \
                required amount of service fee: 1,234,567,891,011 wei, while the wallet contains \
                333,333 wei."),
            (
                PaymentAdjusterError::RecursionDrainedAllAccounts,
                "The payments adjusting process failed to find any combination of payables that \
                can be paid immediately with the finances provided.",
            ),
        ];
        let inputs_count = inputs.len();
        inputs
            .into_iter()
            .for_each(|(error, expected_msg)| assert_eq!(error.to_string(), expected_msg));
        assert_eq!(inputs_count, PaymentAdjusterError::VARIANT_COUNT + 2)
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: This error contains no \
    specifications"
    )]
    fn error_message_for_input_referring_to_no_issues_cannot_be_made() {
        let _ = PaymentAdjusterError::AbsolutelyInsufficientBalance {
            number_of_accounts: 0,
            transaction_fee_opt: None,
            service_fee_opt: None,
        }
        .to_string();
    }

    #[test]
    fn we_can_say_if_error_occurred_after_insolvency_was_detected() {
        let inputs = vec![
            PaymentAdjusterError::RecursionDrainedAllAccounts,
            PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts: 0,
                transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency {
                    per_transaction_requirement_minor: 0,
                    cw_transaction_fee_balance_minor: Default::default(),
                }),
                service_fee_opt: None,
            },
            PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts: 0,
                transaction_fee_opt: None,
                service_fee_opt: Some(ServiceFeeImmoderateInsufficiency {
                    total_service_fee_required_minor: 0,
                    cw_service_fee_balance_minor: 0,
                }),
            },
            PaymentAdjusterError::AbsolutelyInsufficientBalance {
                number_of_accounts: 0,
                transaction_fee_opt: Some(TransactionFeeImmoderateInsufficiency {
                    per_transaction_requirement_minor: 0,
                    cw_transaction_fee_balance_minor: Default::default(),
                }),
                service_fee_opt: Some(ServiceFeeImmoderateInsufficiency {
                    total_service_fee_required_minor: 0,
                    cw_service_fee_balance_minor: 0,
                }),
            },
            PaymentAdjusterError::AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
                original_number_of_accounts: 0,
                number_of_accounts: 0,
                original_total_service_fee_required_minor: 0,
                cw_service_fee_balance_minor: 0,
            },
        ];
        let inputs_count = inputs.len();
        let results = inputs
            .into_iter()
            .map(|err| err.insolvency_detected())
            .collect::<Vec<_>>();
        assert_eq!(results, vec![true, true, true, true, true]);
        assert_eq!(inputs_count, PaymentAdjusterError::VARIANT_COUNT + 2)
    }

    #[test]
    fn adjusted_balance_threats_to_outgrow_the_original_account_but_is_capped_by_disqualification_limit(
    ) {
        let cw_service_fee_balance_minor = multiply_by_billion(4_200_000);
        let mut account_1 = make_meaningless_analyzed_account_by_wallet("abc");
        let balance_1 = multiply_by_billion(3_000_000);
        let disqualification_limit_1 = multiply_by_billion(2_300_000);
        account_1.qualified_as.bare_account.balance_wei = balance_1;
        account_1.disqualification_limit_minor = disqualification_limit_1;
        let weight_account_1 = multiply_by_billion(2_000_100);
        let mut account_2 = make_meaningless_analyzed_account_by_wallet("def");
        let wallet_2 = account_2.qualified_as.bare_account.wallet.clone();
        let balance_2 = multiply_by_billion(2_500_000);
        let disqualification_limit_2 = multiply_by_billion(1_800_000);
        account_2.qualified_as.bare_account.balance_wei = balance_2;
        account_2.disqualification_limit_minor = disqualification_limit_2;
        let weighed_account_2 = multiply_by_billion(3_999_900);
        let largest_exceeding_balance = (balance_1
            - account_1.qualified_as.payment_threshold_intercept_minor)
            .max(balance_2 - account_2.qualified_as.payment_threshold_intercept_minor);
        let subject = PaymentAdjusterBuilder::default()
            .cw_service_fee_balance_minor(cw_service_fee_balance_minor)
            .max_debt_above_threshold_in_qualified_payables_minor(largest_exceeding_balance)
            .build();
        let weighed_payables = vec![
            WeighedPayable::new(account_1, weight_account_1),
            WeighedPayable::new(account_2, weighed_account_2),
        ];

        let mut result = subject
            .resolve_initial_adjustment_dispatch(weighed_payables.clone())
            .unwrap()
            .left()
            .unwrap();

        // This shows how the weights can turn tricky for which it's important to have a hard upper
        // limit, chosen quite down, as the disqualification limit, for optimisation. In its
        // extremity, the naked algorithm of the reallocation of funds could have granted a value
        // above the original debt size, which is clearly unfair.
        illustrate_why_we_need_to_prevent_exceeding_the_original_value(
            cw_service_fee_balance_minor,
            weighed_payables.clone(),
            wallet_2.address(),
            balance_2,
        );
        let payable_account_1 = &weighed_payables[0]
            .analyzed_account
            .qualified_as
            .bare_account;
        let payable_account_2 = &weighed_payables[1]
            .analyzed_account
            .qualified_as
            .bare_account;
        let first_returned_account = result.remove(0);
        assert_eq!(&first_returned_account.original_account, payable_account_2);
        assert_eq!(
            first_returned_account.proposed_adjusted_balance_minor,
            disqualification_limit_2
        );
        let second_returned_account = result.remove(0);
        assert_eq!(&second_returned_account.original_account, payable_account_1);
        assert_eq!(
            second_returned_account.proposed_adjusted_balance_minor,
            disqualification_limit_1
        );
        assert!(result.is_empty());
    }

    #[test]
    fn adjustment_started_but_all_accounts_were_eliminated_anyway() {
        let test_name = "adjustment_started_but_all_accounts_were_eliminated_anyway";
        let now = SystemTime::now();
        // This simplifies the overall picture, the debt age doesn't mean anything to our calculator,
        // still, it influences the height of the intercept point read out from the payment thresholds
        // which can induce an impact on the value of the disqualification limit which is derived
        // from the intercept
        let common_unimportant_age_for_accounts =
            now.checked_sub(Duration::from_secs(200_000)).unwrap();
        let balance_1 = multiply_by_quintillion_concise(0.003);
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: balance_1,
            last_paid_timestamp: common_unimportant_age_for_accounts,
            pending_payable_opt: None,
        };
        let balance_2 = multiply_by_quintillion_concise(0.002);
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: balance_2,
            last_paid_timestamp: common_unimportant_age_for_accounts,
            pending_payable_opt: None,
        };
        let balance_3 = multiply_by_quintillion_concise(0.005);
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: balance_3,
            last_paid_timestamp: common_unimportant_age_for_accounts,
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2, account_3];
        let qualified_payables =
            make_qualified_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(multiply_by_quintillion(2))
            .calculate_result(0)
            .calculate_result(0);
        let mut subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .logger(Logger::new(test_name))
            .build();
        subject.calculators.push(Box::new(calculator_mock));
        let cw_service_fee_balance_minor = balance_2;
        let disqualification_arbiter = &subject.disqualification_arbiter;
        let agent_for_analysis = BlockchainAgentMock::default()
            .gas_price_margin_result(*TX_FEE_MARGIN_IN_PERCENT)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor)
            .transaction_fee_balance_minor_result(U256::MAX)
            .estimated_transaction_fee_per_transaction_minor_result(12356);
        let analysis_result = subject.analyzer.analyze_accounts(
            &agent_for_analysis,
            disqualification_arbiter,
            qualified_payables,
            &subject.logger,
        );
        // The initial intelligent check that PA runs can feel out if the hypothetical adjustment
        // would have some minimal chance to complete successfully. Still, this aspect of it is
        // rather a weak spot, as the only guarantee it sets on works for an assurance that at
        // least the smallest account, with its specific disqualification limit, can be fulfilled
        // by the available funds.
        // In this test it would be a yes there. There's even a surplus in case of the second
        // account.
        // Then the adjustment itself spins off. The accounts get their weights. The second one as
        // to its lowest size should be granted a big one, wait until the other two are eliminated
        // by the recursion and win for the scarce money as paid in the full scale.
        // Normally, what was said would hold true. The big difference is caused by an extra,
        // actually made up, parameter which comes in with the mock calculator stuck in to join
        // the others. It changes the distribution of weights among those three accounts and makes
        // the first account be the most important one. Because of that two other accounts are
        // eliminated, the account three first, and then the account two.
        // When we look back to the preceding entry check, the minimal condition was exercised on
        // the account two, because at that time the weights hadn't been known yet. As the result,
        // the recursion will continue to even eliminate the last account, the account one, for
        // which there isn't enough money to get over its disqualification limit.
        let adjustment_analysis = match analysis_result {
            Ok(Either::Right(analysis)) => analysis,
            x => panic!(
                "We expected to be let it for an adjustments with AnalyzedAccounts but got: {:?}",
                x
            ),
        };
        let agent = Box::new(
            BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance_minor),
        );
        let adjustment_setup = PreparedAdjustment {
            agent,
            response_skeleton_opt: None,
            adjustment_analysis,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        let err = match result {
            Err(e) => e,
            Ok(ok) => panic!(
                "we expected to get an error, but it was ok: {:?}",
                ok.affordable_accounts
            ),
        };
        assert_eq!(err, PaymentAdjusterError::RecursionDrainedAllAccounts)
    }

    #[test]
    fn account_disqualification_makes_the_rest_flooded_with_enough_money_suddenly() {
        // We test a condition to short-circuit that is built in for the case of an account
        // disqualification has just been processed which has freed means, until then tied with this
        // account that is gone now, and which will become an extra portion newly available for
        // the other accounts from which they can gain, however, at the same time the remaining
        // accounts require together less than how much can be given out.
        init_test_logging();
        let test_name =
            "account_disqualification_makes_the_rest_flooded_with_enough_money_suddenly";
        let now = SystemTime::now();
        // This common value simplifies the settings for visualisation, the debt age doesn't mean
        // anything, especially with all calculators mocked out, it only influences the height of
        // the intercept with the payment thresholds which can in turn take role in evaluating
        // the disqualification limit in each account
        let common_age_for_accounts_as_unimportant =
            now.checked_sub(Duration::from_secs(200_000)).unwrap();
        let balance_1 = multiply_by_quintillion(80);
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: balance_1,
            last_paid_timestamp: common_age_for_accounts_as_unimportant,
            pending_payable_opt: None,
        };
        let balance_2 = multiply_by_quintillion(60);
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: balance_2,
            last_paid_timestamp: common_age_for_accounts_as_unimportant,
            pending_payable_opt: None,
        };
        let balance_3 = multiply_by_quintillion(40);
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: balance_3,
            last_paid_timestamp: common_age_for_accounts_as_unimportant,
            pending_payable_opt: None,
        };
        let payables = vec![account_1, account_2.clone(), account_3.clone()];
        let analyzed_accounts =
            make_analyzed_payables(payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let calculator_mock = CriterionCalculatorMock::default()
            // If we consider that the consuming wallet holds less than the sum of
            // the disqualification limits of all these 3 accounts (as also formally checked by one
            // of the attached assertions below), this must mean that disqualification has to be
            // ruled in the first round, where the first account is eventually eliminated for its
            // lowest weight.
            .calculate_result(multiply_by_quintillion(10))
            .calculate_result(multiply_by_quintillion(30))
            .calculate_result(multiply_by_quintillion(50));
        let sum_of_disqualification_limits = sum_as(&analyzed_accounts, |account| {
            account.disqualification_limit_minor
        });
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .logger(Logger::new(test_name))
            .build();
        let agent_id_stamp = ArbitraryIdStamp::new();
        let service_fee_balance_minor = balance_2 + balance_3 + ((balance_1 * 10) / 100);
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_minor_result(service_fee_balance_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            agent,
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::ByServiceFee,
                analyzed_accounts,
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_affordable_accounts = { vec![account_3, account_2] };
        assert_eq!(result.affordable_accounts, expected_affordable_accounts);
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        // This isn't any kind of universal requirement, but this condition is enough to be
        // certain that at least one account must be offered a smaller amount than what says its
        // disqualification limit, and therefore a disqualification needs to take place.
        assert!(sum_of_disqualification_limits > service_fee_balance_minor);
    }

    #[test]
    fn overloaded_by_mammoth_debts_to_see_if_we_can_pass_through_without_blowing_up() {
        init_test_logging();
        let test_name =
            "overloaded_by_mammoth_debts_to_see_if_we_can_pass_through_without_blowing_up";
        let now = SystemTime::now();
        // Each of the 3 accounts refers to a debt sized as the entire MASQ token supply and being
        // 10 years old which generates enormously large numbers in the algorithm, especially for
        // the calculated criteria of over accounts
        let extreme_payables = {
            let debt_age_in_months = vec![120, 120, 120];
            make_mammoth_payables(
                Either::Left((
                    debt_age_in_months,
                    *MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR,
                )),
                now,
            )
        };
        let analyzed_payables =
            make_analyzed_payables(extreme_payables, &PRESERVED_TEST_PAYMENT_THRESHOLDS, now);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // In turn, tiny cw balance
        let cw_service_fee_balance_minor = 1_000;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_minor_result(cw_service_fee_balance_minor);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            agent,
            adjustment_analysis: AdjustmentAnalysisReport::new(
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
        assert_eq!(err, PaymentAdjusterError::RecursionDrainedAllAccounts);
        let expected_log = |wallet: &str| {
            format!(
                "INFO: {test_name}: Ready payment to {wallet} was eliminated to spare MASQ for \
                those higher prioritized. {} wei owed at the moment.",
                (*MAX_POSSIBLE_SERVICE_FEE_BALANCE_IN_MINOR).separate_with_commas()
            )
        };
        let log_handler = TestLogHandler::new();
        [
            "0x000000000000000000000000000000626c616830",
            "0x000000000000000000000000000000626c616831",
            "0x000000000000000000000000000000626c616832",
        ]
        .into_iter()
        .for_each(|address| {
            let _ = log_handler.exists_log_containing(&expected_log(address));
        });

        // Nothing blew up from the giant inputs, the test was a success
    }

    fn make_weighed_payable(n: u64, initial_balance_minor: u128) -> WeighedPayable {
        let mut payable =
            WeighedPayable::new(make_meaningless_analyzed_account(111), n as u128 * 1234);
        payable
            .analyzed_account
            .qualified_as
            .bare_account
            .balance_wei = initial_balance_minor;
        payable
    }

    fn test_is_cw_balance_enough_to_remaining_accounts(
        initial_disqualification_limit_for_each_account: u128,
        untaken_cw_service_fee_balance_minor: u128,
        expected_result: bool,
    ) {
        let subject = PaymentAdjusterReal::new();
        subject.initialize_inner(
            Adjustment::ByServiceFee,
            untaken_cw_service_fee_balance_minor,
            1234567,
            SystemTime::now(),
        );
        let mut payable_1 =
            make_weighed_payable(111, 2 * initial_disqualification_limit_for_each_account);
        payable_1.analyzed_account.disqualification_limit_minor =
            initial_disqualification_limit_for_each_account;
        let mut payable_2 =
            make_weighed_payable(222, 3 * initial_disqualification_limit_for_each_account);
        payable_2.analyzed_account.disqualification_limit_minor =
            initial_disqualification_limit_for_each_account;
        let weighed_payables = vec![payable_1, payable_2];

        let result = subject.is_cw_balance_enough_to_remaining_accounts(&weighed_payables);

        assert_eq!(result, expected_result)
    }

    #[test]
    fn untaken_balance_is_equal_to_sum_of_disqualification_limits_in_remaining_accounts() {
        let disqualification_limit_for_each_account = multiply_by_billion(5);
        let untaken_cw_service_fee_balance_minor =
            disqualification_limit_for_each_account + disqualification_limit_for_each_account;

        test_is_cw_balance_enough_to_remaining_accounts(
            disqualification_limit_for_each_account,
            untaken_cw_service_fee_balance_minor,
            true,
        )
    }

    #[test]
    fn untaken_balance_is_more_than_sum_of_disqualification_limits_in_remaining_accounts() {
        let disqualification_limit_for_each_account = multiply_by_billion(5);
        let untaken_cw_service_fee_balance_minor =
            disqualification_limit_for_each_account + disqualification_limit_for_each_account + 1;

        test_is_cw_balance_enough_to_remaining_accounts(
            disqualification_limit_for_each_account,
            untaken_cw_service_fee_balance_minor,
            true,
        )
    }

    #[test]
    fn untaken_balance_is_less_than_sum_of_disqualification_limits_in_remaining_accounts() {
        let disqualification_limit_for_each_account = multiply_by_billion(5);
        let untaken_cw_service_fee_balance_minor =
            disqualification_limit_for_each_account + disqualification_limit_for_each_account - 1;

        test_is_cw_balance_enough_to_remaining_accounts(
            disqualification_limit_for_each_account,
            untaken_cw_service_fee_balance_minor,
            false,
        )
    }

    //----------------------------------------------------------------------------------------------
    // The following overall tests demonstrate showcases for PA through different situations that
    // can come about during an adjustment

    #[test]
    fn accounts_count_does_not_change_during_adjustment() {
        init_test_logging();
        let calculate_params_arc = Arc::new(Mutex::new(vec![]));
        let test_name = "accounts_count_does_not_change_during_adjustment";
        let now = SystemTime::now();
        let balance_account_1 = 5_100_100_100_200_200_200;
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: balance_account_1,
            threshold_intercept_major: 2_000_000_000,
            permanent_debt_allowed_major: 1_000_000_000,
        };

        let balance_account_2 = 6_000_000_000_123_456_789;
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: balance_account_2,
            threshold_intercept_major: 2_500_000_000,
            permanent_debt_allowed_major: 2_000_000_000,
        };
        let balance_account_3 = 6_666_666_666_666_666_666;
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: balance_account_3,
            threshold_intercept_major: 2_000_000_000,
            permanent_debt_allowed_major: 1_111_111_111,
        };
        let total_weight_account_1 = multiply_by_quintillion_concise(0.4);
        let total_weight_account_2 = multiply_by_quintillion_concise(0.3);
        let total_weight_account_3 = multiply_by_quintillion_concise(0.2);
        let account_seeds = [
            sketched_account_1.clone(),
            sketched_account_2.clone(),
            sketched_account_3.clone(),
        ];
        let (analyzed_payables, actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(account_seeds);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_params(&calculate_params_arc)
            .calculate_result(total_weight_account_1)
            .calculate_result(total_weight_account_2)
            .calculate_result(total_weight_account_3);
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .logger(Logger::new(test_name))
            .build();
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum_minor = balance_account_1 + balance_account_2 + balance_account_3;
        let cw_service_fee_balance_minor = accounts_sum_minor - multiply_by_billion(2_000_000_000);
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor);
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::ByServiceFee,
                analyzed_payables.clone().into(),
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        actual_disqualification_limits.validate_against_expected(
            4_100_100_100_200_200_200,
            5_500_000_000_123_456_789,
            5_777_777_777_666_666_666,
        );
        let expected_adjusted_balance_1 = 4_488_988_989_200_200_200;
        let expected_adjusted_balance_2 = 5_500_000_000_123_456_789;
        let expected_adjusted_balance_3 = 5_777_777_777_666_666_666;
        let expected_criteria_computation_output = {
            let account_1_adjusted =
                account_with_new_balance(&analyzed_payables[0], expected_adjusted_balance_1);
            let account_2_adjusted =
                account_with_new_balance(&analyzed_payables[1], expected_adjusted_balance_2);
            let account_3_adjusted =
                account_with_new_balance(&analyzed_payables[2], expected_adjusted_balance_3);
            vec![account_1_adjusted, account_2_adjusted, account_3_adjusted]
        };
        assert_eq!(
            result.affordable_accounts,
            expected_criteria_computation_output
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let calculate_params = calculate_params_arc.lock().unwrap();
        let expected_calculate_params = analyzed_payables
            .into_iter()
            .map(|account| account.qualified_as)
            .collect_vec();
        assert_eq!(*calculate_params, expected_calculate_params);
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
            balance_account_3.separate_with_commas(),
            expected_adjusted_balance_3.separate_with_commas(),
            balance_account_2.separate_with_commas(),
            expected_adjusted_balance_2.separate_with_commas(),
            balance_account_1.separate_with_commas(),
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
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: multiply_by_quintillion_concise(0.111),
            threshold_intercept_major: multiply_by_billion_concise(0.1),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.02),
        };
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: multiply_by_quintillion_concise(0.3),
            threshold_intercept_major: multiply_by_billion_concise(0.12),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.05),
        };
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: multiply_by_billion(222_222_222),
            threshold_intercept_major: multiply_by_billion_concise(0.1),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.04),
        };
        let total_weight_account_1 = multiply_by_quintillion_concise(0.4);
        // This account will have to fall off because of its lowest weight and that only two
        // accounts can be kept according to the limitations detected in the transaction fee
        // balance
        let total_weight_account_2 = multiply_by_quintillion_concise(0.2);
        let total_weight_account_3 = multiply_by_quintillion_concise(0.3);
        let sketched_accounts = [sketched_account_1, sketched_account_2, sketched_account_3];
        let (analyzed_payables, _actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(sketched_accounts);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(total_weight_account_1)
            .calculate_result(total_weight_account_2)
            .calculate_result(total_weight_account_3);
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .logger(Logger::new(test_name))
            .build();
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(u128::MAX);
        let transaction_count_limit = 2;
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::BeginByTransactionFee {
                    transaction_count_limit,
                },
                analyzed_payables.clone().into(),
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // The account 1 takes the first place for its weight being the biggest
        let expected_affordable_accounts = {
            let mut analyzed_payables = analyzed_payables.to_vec();
            let account_1_unchanged = analyzed_payables.remove(0).qualified_as.bare_account;
            let _ = analyzed_payables.remove(0);
            let account_3_unchanged = analyzed_payables.remove(0).qualified_as.bare_account;
            vec![account_1_unchanged, account_3_unchanged]
        };
        assert_eq!(result.affordable_accounts, expected_affordable_accounts);
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
    fn both_balances_insufficient_but_adjustment_by_service_fee_will_not_affect_the_payment_count()
    {
        // The course of events:
        // 1) adjustment by transaction fee (always means accounts elimination),
        // 2) adjustment by service fee (can but not have to cause an account drop-off)
        init_test_logging();
        let now = SystemTime::now();
        let balance_account_1 = multiply_by_quintillion_concise(0.111);
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: balance_account_1,
            threshold_intercept_major: multiply_by_billion_concise(0.05),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.010),
        };
        let balance_account_2 = multiply_by_quintillion_concise(0.333);
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: balance_account_2,
            threshold_intercept_major: multiply_by_billion_concise(0.2),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.05),
        };
        let balance_account_3 = multiply_by_quintillion_concise(0.222);
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: balance_account_3,
            threshold_intercept_major: multiply_by_billion_concise(0.1),
            permanent_debt_allowed_major: multiply_by_billion_concise(0.035),
        };
        let total_weight_account_1 = multiply_by_quintillion_concise(0.4);
        let total_weight_account_2 = multiply_by_quintillion_concise(0.2);
        let total_weight_account_3 = multiply_by_quintillion_concise(0.3);
        let sketched_accounts = [sketched_account_1, sketched_account_2, sketched_account_3];
        let (analyzed_payables, actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(sketched_accounts);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(total_weight_account_1)
            .calculate_result(total_weight_account_2)
            .calculate_result(total_weight_account_3);
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .build();
        let cw_service_fee_balance_minor = actual_disqualification_limits.account_1
            + actual_disqualification_limits.account_3
            + multiply_by_quintillion_concise(0.01);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(cw_service_fee_balance_minor);
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); // Just hardening, not so important
        let transaction_count_limit = 2;
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::BeginByTransactionFee {
                    transaction_count_limit,
                },
                analyzed_payables.clone().into(),
            ),
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        actual_disqualification_limits.validate_against_expected(
            multiply_by_quintillion_concise(0.071),
            multiply_by_quintillion_concise(0.183),
            multiply_by_quintillion_concise(0.157),
        );
        // Account 2, the least important one, was eliminated for a lack of transaction fee in the cw
        let expected_adjusted_balance_1 = multiply_by_quintillion_concise(0.081);
        let expected_adjusted_balance_3 = multiply_by_quintillion_concise(0.157);
        let expected_accounts = {
            let account_1_adjusted =
                account_with_new_balance(&analyzed_payables[0], expected_adjusted_balance_1);
            let account_3_adjusted =
                account_with_new_balance(&analyzed_payables[2], expected_adjusted_balance_3);
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
        let balance_account_1 = multiply_by_billion(333_000_000);
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: balance_account_1,
            threshold_intercept_major: 200_000_000,
            permanent_debt_allowed_major: 50_000_000,
        };
        // Account to be outweighed and fully preserved
        let balance_account_2 = multiply_by_billion(111_000_000);
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: balance_account_2,
            threshold_intercept_major: 50_000_000,
            permanent_debt_allowed_major: 10_000_000,
        };
        // Account to be disqualified
        let balance_account_3 = multiply_by_billion(600_000_000);
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: balance_account_3,
            threshold_intercept_major: 400_000_000,
            permanent_debt_allowed_major: 100_000_000,
        };
        let total_weight_account_1 = multiply_by_billion(900_000_000);
        let total_weight_account_2 = multiply_by_billion(1_100_000_000);
        let total_weight_account_3 = multiply_by_billion(600_000_000);
        let sketched_accounts = [sketched_account_1, sketched_account_2, sketched_account_3];
        let (analyzed_payables, actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(sketched_accounts);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(total_weight_account_1)
            .calculate_result(total_weight_account_2)
            .calculate_result(total_weight_account_3);
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .logger(Logger::new(test_name))
            .build();
        let service_fee_balance_in_minor_units = actual_disqualification_limits.account_1
            + actual_disqualification_limits.account_2
            + 123_456_789;
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
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::ByServiceFee,
                analyzed_payables.clone().into(),
            ),
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        actual_disqualification_limits.validate_against_expected(
            multiply_by_billion(183_000_000),
            multiply_by_billion(71_000_000),
            multiply_by_billion(300_000_000),
        );
        let expected_accounts = {
            let adjusted_account_2 = account_with_new_balance(
                &analyzed_payables[1],
                actual_disqualification_limits.account_2 + 123_456_789,
            );
            let adjusted_account_1 = account_with_new_balance(
                &analyzed_payables[0],
                actual_disqualification_limits.account_1,
            );
            vec![adjusted_account_2, adjusted_account_1]
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
            "INFO: {test_name}: Ready payment to 0x0000000000000000000000000000000000676869 was \
            eliminated to spare MASQ for those higher prioritized. 600,000,000,000,000,000 wei owed \
            at the moment."
        ));
        test_inner_was_reset_to_null(subject)
    }

    #[test]
    fn service_fee_as_well_as_transaction_fee_limits_the_payments_count() {
        init_test_logging();
        let test_name = "service_fee_as_well_as_transaction_fee_limits_the_payments_count";
        let now = SystemTime::now();
        let balance_account_1 = multiply_by_quintillion(100);
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: balance_account_1,
            threshold_intercept_major: multiply_by_billion(60),
            permanent_debt_allowed_major: multiply_by_billion(10),
        };
        // The second is thrown away first in a response to the shortage of transaction fee,
        // as its weight is the least significant
        let balance_account_2 = multiply_by_quintillion(500);
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: balance_account_2,
            threshold_intercept_major: multiply_by_billion(100),
            permanent_debt_allowed_major: multiply_by_billion(30),
        };
        // Thrown away as the second one due to a shortage in the service fee,
        // listed among accounts to disqualify and picked eventually for its
        // lowest weight
        let balance_account_3 = multiply_by_quintillion(250);
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: balance_account_3,
            threshold_intercept_major: multiply_by_billion(90),
            permanent_debt_allowed_major: multiply_by_billion(20),
        };
        let total_weight_account_1 = multiply_by_quintillion(900);
        let total_weight_account_2 = multiply_by_quintillion(500);
        let total_weight_account_3 = multiply_by_quintillion(750);
        let sketched_accounts = [sketched_account_1, sketched_account_2, sketched_account_3];
        let (analyzed_payables, actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(sketched_accounts);
        let calculator_mock = CriterionCalculatorMock::default()
            .calculate_result(total_weight_account_1)
            .calculate_result(total_weight_account_2)
            .calculate_result(total_weight_account_3);
        let subject = PaymentAdjusterBuilder::default()
            .start_with_inner_null()
            .replace_calculators_with_mock(calculator_mock)
            .logger(Logger::new(test_name))
            .build();
        let service_fee_balance_in_minor = balance_account_1 - multiply_by_quintillion(10);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .service_fee_balance_minor_result(service_fee_balance_in_minor);
        let transaction_count_limit = 2;
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::BeginByTransactionFee {
                    transaction_count_limit,
                },
                analyzed_payables.clone().into(),
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        actual_disqualification_limits.validate_against_expected(
            multiply_by_quintillion(50),
            multiply_by_quintillion(460),
            multiply_by_quintillion(200),
        );
        let expected_accounts = vec![account_with_new_balance(
            &analyzed_payables[0],
            service_fee_balance_in_minor,
        )];
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

    #[derive(Debug, PartialEq, Clone)]
    struct SketchedPayableAccount {
        wallet_addr_seed: &'static str,
        balance_minor: u128,
        threshold_intercept_major: u128,
        permanent_debt_allowed_major: u128,
    }

    #[derive(Debug, PartialEq)]
    struct QuantifiedDisqualificationLimits {
        account_1: u128,
        account_2: u128,
        account_3: u128,
    }

    impl QuantifiedDisqualificationLimits {
        fn validate_against_expected(
            &self,
            expected_limit_account_1: u128,
            expected_limit_account_2: u128,
            expected_limit_account_3: u128,
        ) {
            let actual = [self.account_1, self.account_2, self.account_3];
            let expected = [
                expected_limit_account_1,
                expected_limit_account_2,
                expected_limit_account_3,
            ];
            assert_eq!(
                actual, expected,
                "Test manifests disqualification limits as {:?} to help with visualising \
                the conditions but such limits are ot true, because the accounts in the input \
                actually evaluates to these limits {:?}",
                expected, actual
            );
        }
    }

    impl From<&[AnalyzedPayableAccount; 3]> for QuantifiedDisqualificationLimits {
        fn from(accounts: &[AnalyzedPayableAccount; 3]) -> Self {
            Self {
                account_1: accounts[0].disqualification_limit_minor,
                account_2: accounts[1].disqualification_limit_minor,
                account_3: accounts[2].disqualification_limit_minor,
            }
        }
    }

    fn make_analyzed_accounts_and_show_their_actual_disqualification_limits(
        accounts_seeds: [SketchedPayableAccount; 3],
    ) -> (
        [AnalyzedPayableAccount; 3],
        QuantifiedDisqualificationLimits,
    ) {
        let qualified_payables: Vec<_> = accounts_seeds
            .into_iter()
            .map(|account_seed| {
                QualifiedPayableAccount::new(
                    PayableAccount {
                        wallet: make_wallet(account_seed.wallet_addr_seed),
                        balance_wei: account_seed.balance_minor,
                        last_paid_timestamp: meaningless_timestamp(),
                        pending_payable_opt: None,
                    },
                    multiply_by_billion(account_seed.threshold_intercept_major),
                    CreditorThresholds::new(multiply_by_billion(
                        account_seed.permanent_debt_allowed_major,
                    )),
                )
            })
            .collect();
        let analyzed_accounts =
            convert_qualified_into_analyzed_payables_in_test(qualified_payables);
        let analyzed_accounts: [AnalyzedPayableAccount; 3] = analyzed_accounts.try_into().unwrap();
        let disqualification_limits: QuantifiedDisqualificationLimits = (&analyzed_accounts).into();
        (analyzed_accounts, disqualification_limits)
    }

    fn meaningless_timestamp() -> SystemTime {
        SystemTime::now()
    }

    fn account_with_new_balance(
        analyzed_payable: &AnalyzedPayableAccount,
        adjusted_balance: u128,
    ) -> PayableAccount {
        PayableAccount {
            balance_wei: adjusted_balance,
            ..analyzed_payable.qualified_as.bare_account.clone()
        }
    }

    //----------------------------------------------------------------------------------------------
    // End of happy path section

    #[test]
    fn late_error_after_tx_fee_adjusted_but_rechecked_service_fee_found_fatally_insufficient() {
        init_test_logging();
        let test_name =
            "late_error_after_tx_fee_adjusted_but_rechecked_service_fee_found_fatally_insufficient";
        let now = SystemTime::now();
        let balance_account_1 = multiply_by_quintillion(500);
        let sketched_account_1 = SketchedPayableAccount {
            wallet_addr_seed: "abc",
            balance_minor: balance_account_1,
            threshold_intercept_major: multiply_by_billion(300),
            permanent_debt_allowed_major: multiply_by_billion(100),
        };
        // This account is eliminated in the transaction fee cut
        let balance_account_2 = multiply_by_quintillion(111);
        let sketched_account_2 = SketchedPayableAccount {
            wallet_addr_seed: "def",
            balance_minor: balance_account_2,
            threshold_intercept_major: multiply_by_billion(50),
            permanent_debt_allowed_major: multiply_by_billion(10),
        };
        let balance_account_3 = multiply_by_quintillion(300);
        let sketched_account_3 = SketchedPayableAccount {
            wallet_addr_seed: "ghi",
            balance_minor: balance_account_3,
            threshold_intercept_major: multiply_by_billion(150),
            permanent_debt_allowed_major: multiply_by_billion(50),
        };
        let sketched_accounts = [sketched_account_1, sketched_account_2, sketched_account_3];
        let (analyzed_payables, actual_disqualification_limits) =
            make_analyzed_accounts_and_show_their_actual_disqualification_limits(sketched_accounts);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // This is exactly the amount which provokes an error
        let cw_service_fee_balance_minor = actual_disqualification_limits.account_2 - 1;
        let agent = BlockchainAgentMock::default()
            .service_fee_balance_minor_result(cw_service_fee_balance_minor);
        let transaction_count_limit = 2;
        let adjustment_setup = PreparedAdjustment {
            agent: Box::new(agent),
            adjustment_analysis: AdjustmentAnalysisReport::new(
                Adjustment::BeginByTransactionFee {
                    transaction_count_limit,
                },
                analyzed_payables.into(),
            ),
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        actual_disqualification_limits.validate_against_expected(
            multiply_by_quintillion(300),
            multiply_by_quintillion(71),
            multiply_by_quintillion(250),
        );
        let err = match result {
            Ok(_) => panic!("expected an error but got Ok()"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            PaymentAdjusterError::AbsolutelyInsufficientServiceFeeBalancePostTxFeeAdjustment {
                original_number_of_accounts: 3,
                number_of_accounts: 2,
                original_total_service_fee_required_minor: balance_account_1
                    + balance_account_2
                    + balance_account_3,
                cw_service_fee_balance_minor
            }
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &format!(
                "WARN: {test_name}: Mature payables amount to 411,000,000,000,000,000,000 MASQ \
                wei while the consuming wallet holds only 70,999,999,999,999,999,999 wei. \
                Adjustment in their count or balances is necessary."
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
        payable_account_balances_minor: Vec<u128>,
        cw_balance_minor: u128,
    }

    impl Default for TestConfigForServiceFeeBalances {
        fn default() -> Self {
            TestConfigForServiceFeeBalances {
                payable_account_balances_minor: vec![1, 2],
                cw_balance_minor: u64::MAX as u128,
            }
        }
    }

    struct TestConfigForTransactionFees {
        gas_price_major: u64,
        number_of_accounts: usize,
        tx_computation_units: u64,
        cw_transaction_fee_balance_minor: u128,
    }

    fn make_input_for_initial_check_tests(
        service_fee_config_opt: Option<TestConfigForServiceFeeBalances>,
        tx_fee_config_opt: Option<TestConfigForTransactionFees>,
    ) -> (Vec<QualifiedPayableAccount>, Box<dyn BlockchainAgent>) {
        let service_fee_balances_config = service_fee_config_opt.unwrap_or_default();
        let balances_of_accounts_minor = service_fee_balances_config.payable_account_balances_minor;
        let accounts_count_from_sf_config = balances_of_accounts_minor.len();

        let transaction_fee_config = tx_fee_config_opt
            .unwrap_or_else(|| default_transaction_fee_config(accounts_count_from_sf_config));
        let payable_accounts = if transaction_fee_config.number_of_accounts
            != accounts_count_from_sf_config
        {
            prepare_payable_accounts_from(Either::Left(transaction_fee_config.number_of_accounts))
        } else {
            prepare_payable_accounts_from(Either::Right(balances_of_accounts_minor))
        };
        let qualified_payables = prepare_qualified_payables(payable_accounts);

        let blockchain_agent = prepare_agent(
            transaction_fee_config.cw_transaction_fee_balance_minor,
            transaction_fee_config.tx_computation_units,
            transaction_fee_config.gas_price_major,
            service_fee_balances_config.cw_balance_minor,
        );

        (qualified_payables, blockchain_agent)
    }

    fn default_transaction_fee_config(
        accounts_count_from_sf_config: usize,
    ) -> TestConfigForTransactionFees {
        TestConfigForTransactionFees {
            gas_price_major: 120,
            number_of_accounts: accounts_count_from_sf_config,
            tx_computation_units: 55_000,
            cw_transaction_fee_balance_minor: u128::MAX,
        }
    }

    fn prepare_payable_accounts_from(
        balances_or_desired_accounts_count: Either<usize, Vec<u128>>,
    ) -> Vec<PayableAccount> {
        match balances_or_desired_accounts_count {
            Either::Left(desired_accounts_count) => (0..desired_accounts_count)
                .map(|idx| make_payable_account(idx as u64))
                .collect(),
            Either::Right(balances_of_accounts_minor) => balances_of_accounts_minor
                .into_iter()
                .enumerate()
                .map(|(idx, balance)| {
                    let mut account = make_payable_account(idx as u64);
                    account.balance_wei = balance;
                    account
                })
                .collect(),
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

    fn prepare_agent(
        cw_transaction_fee_minor: u128,
        tx_computation_units: u64,
        gas_price: u64,
        cw_service_fee_balance_minor: u128,
    ) -> Box<dyn BlockchainAgent> {
        let estimated_transaction_fee_per_transaction_minor =
            multiply_by_billion((tx_computation_units * gas_price) as u128);

        let blockchain_agent = BlockchainAgentMock::default()
            .gas_price_margin_result(*TX_FEE_MARGIN_IN_PERCENT)
            .transaction_fee_balance_minor_result(cw_transaction_fee_minor.into())
            .service_fee_balance_minor_result(cw_service_fee_balance_minor)
            .estimated_transaction_fee_per_transaction_minor_result(
                estimated_transaction_fee_per_transaction_minor,
            );

        Box::new(blockchain_agent)
    }

    fn reconstruct_mock_agent(boxed: Box<dyn BlockchainAgent>) -> BlockchainAgentMock {
        BlockchainAgentMock::default()
            .gas_price_margin_result(boxed.gas_price_margin())
            .transaction_fee_balance_minor_result(boxed.transaction_fee_balance_minor())
            .service_fee_balance_minor_result(boxed.service_fee_balance_minor())
            .estimated_transaction_fee_per_transaction_minor_result(
                boxed.estimated_transaction_fee_per_transaction_minor(),
            )
    }

    fn test_inner_was_reset_to_null(subject: PaymentAdjusterReal) {
        let err = catch_unwind(AssertUnwindSafe(|| {
            subject.inner.original_cw_service_fee_balance_minor()
        }))
        .unwrap_err();
        let panic_msg = err.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "PaymentAdjusterInner is uninitialized. It was identified during the execution of \
            'original_cw_service_fee_balance_minor()'"
        )
    }

    // The following tests put together evidences pointing to the use of correct calculators in
    // the production code

    #[test]
    fn each_of_defaulted_calculators_returns_different_value() {
        let now = SystemTime::now();
        let payment_adjuster = PaymentAdjusterReal::default();
        let qualified_payable = QualifiedPayableAccount {
            bare_account: PayableAccount {
                wallet: make_wallet("abc"),
                balance_wei: multiply_by_billion(444_666_888),
                last_paid_timestamp: now.checked_sub(Duration::from_secs(123_000)).unwrap(),
                pending_payable_opt: None,
            },
            payment_threshold_intercept_minor: multiply_by_billion(20_000),
            creditor_thresholds: CreditorThresholds::new(multiply_by_billion(10_000)),
        };
        let cw_service_fee_balance_minor = multiply_by_billion(3_000);
        let exceeding_balance = qualified_payable.bare_account.balance_wei
            - qualified_payable.payment_threshold_intercept_minor;
        let context = PaymentAdjusterInner::default();
        context.initialize_guts(None, cw_service_fee_balance_minor, exceeding_balance, now);

        payment_adjuster
            .calculators
            .into_iter()
            .map(|calculator| calculator.calculate(&qualified_payable, &context))
            .fold(0, |previous_result, current_result| {
                let slightly_less_than_current = (current_result * 97) / 100;
                let slightly_more_than_current = (current_result * 103) / 100;
                assert_ne!(current_result, 0);
                assert!(
                    previous_result <= slightly_less_than_current
                        || slightly_more_than_current <= previous_result
                );
                current_result
            });
    }

    struct CalculatorTestScenario {
        payable: QualifiedPayableAccount,
        expected_weight: u128,
    }

    type InputMatrixConfigurator = fn(
        (QualifiedPayableAccount, QualifiedPayableAccount, SystemTime),
    ) -> Vec<[CalculatorTestScenario; 2]>;

    // This is the value that is computed if the account stays unmodified. Same for both nominal
    // accounts.
    const NOMINAL_ACCOUNT_WEIGHT: u128 = 8000000000000000;

    #[test]
    fn defaulted_calculators_react_on_correct_params() {
        // When adding a test case for a new calculator, you need to make a two-dimensional array
        // of inputs. Don't create brand-new accounts but clone the provided nominal accounts and
        // modify them accordingly. Modify only those parameters that affect your calculator.
        // It's recommended to orientate the modifications rather positively (additions), because
        // there is a smaller chance you would run into some limit
        let input_matrix: InputMatrixConfigurator =
            |(nominal_account_1, nominal_account_2, _now)| {
                vec![
                    // This puts only the first calculator on test, the BalanceCalculator...
                    {
                        let mut account_1 = nominal_account_1;
                        account_1.bare_account.balance_wei += 123456789;
                        let mut account_2 = nominal_account_2;
                        account_2.bare_account.balance_wei += 999999999;
                        [
                            CalculatorTestScenario {
                                payable: account_1,
                                expected_weight: 8000001876543209,
                            },
                            CalculatorTestScenario {
                                payable: account_2,
                                expected_weight: 8000000999999999,
                            },
                        ]
                    },
                    // ...your newly added calculator should come here, and so on...
                ]
            };

        test_calculators_reactivity(input_matrix)
    }

    #[derive(Clone, Copy)]
    struct TemplateComputedWeight {
        common_weight: u128,
    }

    struct ExpectedWeightWithWallet {
        wallet: Address,
        weight: u128,
    }

    fn test_calculators_reactivity(input_matrix_configurator: InputMatrixConfigurator) {
        let calculators_count = PaymentAdjusterReal::default().calculators.len();
        let now = SystemTime::now();
        let cw_service_fee_balance_minor = multiply_by_billion(1_000_000);
        let (template_accounts, template_computed_weight) =
            prepare_nominal_data_before_loading_actual_test_input(
                now,
                cw_service_fee_balance_minor,
            );
        assert_eq!(
            template_computed_weight.common_weight,
            NOMINAL_ACCOUNT_WEIGHT
        );
        let mut template_accounts = template_accounts.to_vec();
        let mut pop_account = || template_accounts.remove(0);
        let nominal_account_1 = pop_account();
        let nominal_account_2 = pop_account();
        let input_matrix = input_matrix_configurator((nominal_account_1, nominal_account_2, now));
        assert_eq!(
            input_matrix.len(),
            calculators_count,
            "Testing production code, the number of defaulted calculators should match the number \
            of test scenarios included in this test. If there are any missing, and you've recently \
            added in a new calculator, you should construct a new test case to it. See the input \
            matrix, it is the place where you should use the two accounts you can clone. Be careful \
            to modify only those parameters that are processed within your new calculator "
        );
        test_accounts_from_input_matrix(
            now,
            input_matrix,
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
                balance_wei: multiply_by_quintillion_concise(0.02),
                last_paid_timestamp: now.checked_sub(Duration::from_secs(10_000)).unwrap(),
                pending_payable_opt: None,
            },
            payment_threshold_intercept_minor: multiply_by_quintillion_concise(0.012),
            creditor_thresholds: CreditorThresholds::new(multiply_by_quintillion_concise(0.001)),
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
        let template_results = exercise_production_code_to_get_weighed_accounts(
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

    fn exercise_production_code_to_get_weighed_accounts(
        qualified_payables: Vec<QualifiedPayableAccount>,
        now: SystemTime,
        cw_service_fee_balance_minor: u128,
    ) -> Vec<WeighedPayable> {
        let analyzed_payables =
            convert_qualified_into_analyzed_payables_in_test(qualified_payables);
        let max_debt_above_threshold_in_qualified_payables_minor =
            find_largest_exceeding_balance(&analyzed_payables);
        let mut subject = PaymentAdjusterBuilder::default()
            .now(now)
            .cw_service_fee_balance_minor(cw_service_fee_balance_minor)
            .max_debt_above_threshold_in_qualified_payables_minor(
                max_debt_above_threshold_in_qualified_payables_minor,
            )
            .build();
        let perform_adjustment_by_service_fee_params_arc = Arc::new(Mutex::new(Vec::new()));
        let service_fee_adjuster_mock = ServiceFeeAdjusterMock::default()
            // We use this container to intercept those values we are after
            .perform_adjustment_by_service_fee_params(&perform_adjustment_by_service_fee_params_arc)
            // This is just a sentinel that allows us to shorten the adjustment execution.
            // We care only for the params captured inside the container from above
            .perform_adjustment_by_service_fee_result(AdjustmentIterationResult {
                decided_accounts: vec![],
                remaining_undecided_accounts: vec![],
            });
        subject.service_fee_adjuster = Box::new(service_fee_adjuster_mock);

        let result = subject.run_adjustment(analyzed_payables);

        less_important_constant_assertions_and_weighed_accounts_extraction(
            result,
            perform_adjustment_by_service_fee_params_arc,
            cw_service_fee_balance_minor,
        )
    }

    fn less_important_constant_assertions_and_weighed_accounts_extraction(
        actual_result: Result<Vec<PayableAccount>, PaymentAdjusterError>,
        perform_adjustment_by_service_fee_params_arc: Arc<Mutex<Vec<(Vec<WeighedPayable>, u128)>>>,
        cw_service_fee_balance_minor: u128,
    ) -> Vec<WeighedPayable> {
        // This error should be ignored, as it has no real meaning.
        // It allows to halt the code executions without a dive in the recursion
        assert_eq!(
            actual_result,
            Err(PaymentAdjusterError::RecursionDrainedAllAccounts)
        );
        let mut perform_adjustment_by_service_fee_params =
            perform_adjustment_by_service_fee_params_arc.lock().unwrap();
        let (weighed_accounts, captured_cw_service_fee_balance_minor) =
            perform_adjustment_by_service_fee_params.remove(0);
        assert_eq!(
            captured_cw_service_fee_balance_minor,
            cw_service_fee_balance_minor
        );
        assert!(perform_adjustment_by_service_fee_params.is_empty());
        weighed_accounts
    }

    fn test_accounts_from_input_matrix(
        now: SystemTime,
        input_matrix: Vec<[CalculatorTestScenario; 2]>,
        cw_service_fee_balance_minor: u128,
        template_computed_weight: TemplateComputedWeight,
    ) {
        fn prepare_inputs_with_expected_weights(
            particular_calculator_scenario: CalculatorTestScenario,
        ) -> (QualifiedPayableAccount, ExpectedWeightWithWallet) {
            let wallet = particular_calculator_scenario
                .payable
                .bare_account
                .wallet
                .address();
            let weight = particular_calculator_scenario.expected_weight;
            let expected_weight = ExpectedWeightWithWallet { wallet, weight };
            (particular_calculator_scenario.payable, expected_weight)
        }

        input_matrix
            .into_iter()
            .map(|test_case| {
                test_case
                    .into_iter()
                    .map(prepare_inputs_with_expected_weights)
                    .collect::<Vec<_>>()
            })
            .for_each(|qualified_payables_and_their_expected_weights| {
                let (qualified_payments, expected_computed_weights): (Vec<_>, Vec<_>) =
                    qualified_payables_and_their_expected_weights
                        .into_iter()
                        .unzip();

                let actual_weighed_accounts = exercise_production_code_to_get_weighed_accounts(
                    qualified_payments,
                    now,
                    cw_service_fee_balance_minor,
                );

                assert_results(
                    actual_weighed_accounts,
                    expected_computed_weights,
                    template_computed_weight,
                )
            });
    }

    fn make_comparison_hashmap(
        weighed_accounts: Vec<WeighedPayable>,
    ) -> HashMap<Address, WeighedPayable> {
        let feeding_iterator = weighed_accounts
            .into_iter()
            .map(|account| (account.wallet(), account));
        HashMap::from_iter(feeding_iterator)
    }

    fn assert_results(
        weighed_accounts: Vec<WeighedPayable>,
        expected_computed_weights: Vec<ExpectedWeightWithWallet>,
        template_computed_weight: TemplateComputedWeight,
    ) {
        let weighed_accounts_as_hash_map = make_comparison_hashmap(weighed_accounts);
        expected_computed_weights.into_iter().fold(
            0,
            |previous_account_actual_weight, expected_account_weight| {
                let wallet = expected_account_weight.wallet;
                let actual_account = weighed_accounts_as_hash_map
                    .get(&wallet)
                    .unwrap_or_else(|| panic!("Account for wallet {:?} disappeared", wallet));
                assert_ne!(
                    actual_account.weight, template_computed_weight.common_weight,
                    "Weight is exactly the same as that one from the template. The inputs \
                    (modifications in the template accounts) are supposed to cause the weight to \
                    evaluated differently."
                );
                assert_eq!(
                    actual_account.weight,
                    expected_account_weight.weight,
                    "Computed weight {} differs from what was expected {}",
                    actual_account.weight.separate_with_commas(),
                    expected_account_weight.weight.separate_with_commas()
                );
                assert_ne!(
                    actual_account.weight, previous_account_actual_weight,
                    "You were expected to prepare two accounts with at least slightly different \
                    parameters. Therefore, the evenness of their weights is highly improbable and \
                    suspicious."
                );
                actual_account.weight
            },
        );
    }
}
