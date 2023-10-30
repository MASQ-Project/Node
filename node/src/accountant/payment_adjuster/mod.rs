// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//try to keep these modules private
mod adjustment_runners;
mod criteria_calculators;
mod diagnostics;
mod inner;
mod log_fns;
mod miscellaneous;
mod test_utils;
mod verifier;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::adjustment_runners::{
    AdjustmentRunner, MasqAndTransactionFeeRunner, MasqOnlyRunner,
};
use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::CriteriaIteratorAdaptor;
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::print_formulas_characteristics_for_diagnostics;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::non_finalized_adjusted_accounts_diagnostics;
use crate::accountant::payment_adjuster::diagnostics::{diagnostics, collection_diagnostics};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::log_fns::{
    before_and_after_debug_msg, log_adjustment_by_masq_required,
    log_transaction_fee_adjustment_ok_but_masq_balance_undoable,
    log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::AfterAdjustmentSpecialTreatment::{
    TreatInsignificantAccount, TreatOutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_structures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, ProposedAdjustmentResolution,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{compute_fractional_numbers_preventing_mul_coefficient, criteria_total, exhaust_cw_till_the_last_drop, finalize_collection, try_finding_an_account_to_disqualify_in_this_iteration, possibly_outweighed_accounts_fold_guts, drop_criteria_sums_and_leave_accounts, keep_only_transaction_fee_affordable_count_of_accounts_and_drop_the_rest, sort_in_descendant_order_by_criteria_sums, sum_as};
use crate::accountant::payment_adjuster::verifier::MasqAdjustmentPossibilityVerifier;
use crate::diagnostics;
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[PayableAccount],
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
    inner: Box<dyn PaymentAdjusterInner>,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        qualified_payables: &[PayableAccount],
        agent: &dyn BlockchainAgent,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError> {
        let required_tx_count = qualified_payables.len();

        match Self::determine_transaction_count_limit_by_transaction_fee(
            agent,
            required_tx_count,
            &self.logger,
        ) {
            Ok(None) => (),
            Ok(Some(affordable_transaction_count)) => {
                return Ok(Some(Adjustment::PriorityTransactionFee {
                    affordable_transaction_count,
                }))
            }
            Err(e) => return Err(e),
        };

        let service_fee_balance_minor = agent.service_fee_balance();
        match Self::check_need_of_masq_adjustment(
            &self.logger,
            Either::Left(qualified_payables),
            service_fee_balance_minor,
        ) {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(Adjustment::MasqToken)),
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
        let initial_service_fee_balance_minor = agent.service_fee_balance();
        let required_adjustment = setup.adjustment;

        self.initialize_inner(initial_service_fee_balance_minor, required_adjustment, now);

        let debug_info_opt = self.debug_info_opt(&qualified_payables);

        let adjusted_accounts = self.run_adjustment(qualified_payables)?;

        debug!(
            self.logger,
            "{}",
            before_and_after_debug_msg(debug_info_opt.expectv("debug info"), &adjusted_accounts)
        );

        Ok(OutboundPaymentsInstructions {
            affordable_accounts: adjusted_accounts,
            response_skeleton_opt,
            agent,
        })
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
            inner: Box::new(PaymentAdjusterInnerNull {}),
            logger: Logger::new("PaymentAdjuster"),
        }
    }

    fn determine_transaction_count_limit_by_transaction_fee(
        agent: &dyn BlockchainAgent,
        required_tx_count: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, PaymentAdjusterError> {
        let per_transaction_requirement_minor = agent.estimated_transaction_fee_per_transaction();

        let cw_transaction_fee_balance_minor = agent.transaction_fee_balance();

        let max_doable_tx_count = u128::try_from(
            cw_transaction_fee_balance_minor / U256::from(per_transaction_requirement_minor),
        )
        .expect("consuming wallet with too a big balance for the transaction fee");

        let (max_doable_tx_count_u16, required_tx_count_u16) =
            Self::put_bigger_unsigned_integers_under_u16_ceiling(
                max_doable_tx_count,
                required_tx_count,
            );

        if max_doable_tx_count_u16 == 0 {
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: required_tx_count,
                    per_transaction_requirement_minor,
                    cw_transaction_fee_balance_minor,
                },
            ))
        } else if max_doable_tx_count_u16 >= required_tx_count_u16 {
            Ok(None)
        } else {
            log_insufficient_transaction_fee_balance(
                logger,
                required_tx_count_u16,
                cw_transaction_fee_balance_minor,
                max_doable_tx_count_u16,
            );
            Ok(Some(max_doable_tx_count_u16))
        }
    }

    fn put_bigger_unsigned_integers_under_u16_ceiling(
        max_doable_tx_count: u128,
        required_tx_count: usize,
    ) -> (u16, u16) {
        (
            u16::try_from(max_doable_tx_count).unwrap_or(u16::MAX),
            u16::try_from(required_tx_count).unwrap_or(u16::MAX),
        )
    }

    fn check_need_of_masq_adjustment(
        logger: &Logger,
        payables: Either<&[PayableAccount], &[(u128, PayableAccount)]>,
        cw_masq_balance_minor: u128,
    ) -> Result<bool, PaymentAdjusterError> {
        let qualified_payables: Vec<&PayableAccount> = match payables {
            Either::Left(accounts) => accounts.iter().collect(),
            Either::Right(criteria_and_accounts) => criteria_and_accounts
                .iter()
                .map(|(_, account)| account)
                .collect(),
        };

        let required_masq_sum: u128 = sum_as(&qualified_payables, |account: &&PayableAccount| {
            account.balance_wei
        });

        if cw_masq_balance_minor >= required_masq_sum {
            Ok(false)
        } else {
            MasqAdjustmentPossibilityVerifier {}
                .verify_adjustment_possibility(&qualified_payables, cw_masq_balance_minor)?;

            log_adjustment_by_masq_required(logger, required_masq_sum, cw_masq_balance_minor);
            Ok(true)
        }
    }

    fn initialize_inner(
        &mut self,
        cw_service_fee_balance: u128,
        required_adjustment: Adjustment,
        now: SystemTime,
    ) {
        let transaction_fee_limitation_opt = match required_adjustment {
            Adjustment::PriorityTransactionFee {
                affordable_transaction_count,
            } => Some(affordable_transaction_count),
            Adjustment::MasqToken => None,
        };

        let inner = PaymentAdjusterInnerReal::new(
            now,
            transaction_fee_limitation_opt,
            cw_service_fee_balance,
        );

        self.inner = Box::new(inner);
    }

    fn run_adjustment(
        &mut self,
        qualified_accounts: Vec<PayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let accounts = self.calculate_criteria_and_propose_adjustments_recursively(
            qualified_accounts,
            MasqAndTransactionFeeRunner {},
        )?;
        match accounts {
            Either::Left(non_exhausted_accounts) => {
                let accounts_by_fully_exhausted_cw = exhaust_cw_till_the_last_drop(
                    non_exhausted_accounts,
                    self.inner.original_cw_masq_balance_minor(),
                );
                Ok(accounts_by_fully_exhausted_cw)
            }
            Either::Right(finalized_accounts) => Ok(finalized_accounts),
        }
    }

    fn calculate_criteria_and_propose_adjustments_recursively<A, R>(
        &mut self,
        mut unresolved_qualified_accounts: Vec<PayableAccount>,
        adjustment_runner: A,
    ) -> R
    where
        A: AdjustmentRunner<ReturnType = R>,
    {
        collection_diagnostics(
            "\nUNRESOLVED QUALIFIED ACCOUNTS:",
            &unresolved_qualified_accounts,
        );

        if unresolved_qualified_accounts.len() == 1 {
            return adjustment_runner
                .adjust_last_one(self, unresolved_qualified_accounts.remove(0));
        }

        let accounts_with_individual_criteria_sorted =
            self.calculate_criteria_sums_for_accounts(unresolved_qualified_accounts);

        adjustment_runner.adjust_multiple(self, accounts_with_individual_criteria_sorted)
    }

    fn begin_adjustment_by_transaction_fee(
        &mut self,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
        already_known_affordable_transaction_count: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        let weighted_accounts_affordable_by_transaction_fee =
            keep_only_transaction_fee_affordable_count_of_accounts_and_drop_the_rest(
                criteria_and_accounts_in_descending_order,
                already_known_affordable_transaction_count,
            );
        let unallocated_balance = self.inner.unallocated_cw_masq_balance_minor();

        let is_masq_adjustment_needed = match Self::check_need_of_masq_adjustment(
            &self.logger,
            Either::Right(&weighted_accounts_affordable_by_transaction_fee),
            unallocated_balance,
        ) {
            Ok(answer) => answer,
            Err(e) => {
                log_transaction_fee_adjustment_ok_but_masq_balance_undoable(&self.logger);
                return Err(e);
            }
        };

        match is_masq_adjustment_needed {
            true => {
                let adjustment_result_before_verification = self
                    .propose_possible_adjustment_recursively(
                        weighted_accounts_affordable_by_transaction_fee,
                    );
                Ok(Either::Left(adjustment_result_before_verification))
            }
            false => {
                let finalized_accounts = drop_criteria_sums_and_leave_accounts(
                    weighted_accounts_affordable_by_transaction_fee,
                );
                Ok(Either::Right(finalized_accounts))
            }
        }
    }

    fn calculate_criteria_sums_for_accounts(
        &self,
        accounts: Vec<PayableAccount>,
    ) -> Vec<(u128, PayableAccount)> {
        let accounts_with_zero_criteria = Self::initialize_zero_criteria(accounts);
        self.apply_criteria(accounts_with_zero_criteria)
    }

    fn propose_possible_adjustment_recursively(
        &mut self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let adjustment_iteration_result =
            self.perform_masq_adjustment(accounts_with_individual_criteria);

        let (here_decided_accounts, downstream_decided_accounts) =
            self.resolve_iteration_result(adjustment_iteration_result);

        let here_decided_iter = here_decided_accounts.into_iter();
        let downstream_decided_iter = downstream_decided_accounts.into_iter();
        let merged: Vec<AdjustedAccountBeforeFinalization> =
            here_decided_iter.chain(downstream_decided_iter).collect();

        collection_diagnostics("\nFINAL ADJUSTED ACCOUNTS:", &merged);

        merged
    }

    fn resolve_iteration_result(
        &mut self,
        adjustment_iteration_result: AdjustmentIterationResult,
    ) -> (
        Vec<AdjustedAccountBeforeFinalization>,
        Vec<AdjustedAccountBeforeFinalization>,
    ) {
        match adjustment_iteration_result {
            AdjustmentIterationResult::AllAccountsProcessedSmoothly(decided_accounts) => {
                (decided_accounts, vec![])
            }
            AdjustmentIterationResult::SpecialTreatmentNeeded {
                case: special_case,
                remaining,
            } => {
                let here_decided_accounts = match special_case {
                    TreatInsignificantAccount => {
                        if remaining.is_empty() {
                            debug!(self.logger, "Last remaining account ended up disqualified");

                            return (vec![], vec![]);
                        }

                        vec![]
                    }
                    TreatOutweighedAccounts(outweighed) => {
                        self.adjust_cw_balance_down_as_result_of_this_last_iteration(&outweighed);
                        outweighed
                    }
                };

                let down_stream_decided_accounts = self
                    .calculate_criteria_and_propose_adjustments_recursively(
                        remaining,
                        MasqOnlyRunner {},
                    );

                (here_decided_accounts, down_stream_decided_accounts)
            }
        }
    }

    fn initialize_zero_criteria(
        qualified_payables: Vec<PayableAccount>,
    ) -> impl Iterator<Item = (u128, PayableAccount)> {
        fn only_zero_criteria_iterator(accounts_count: usize) -> impl Iterator<Item = u128> {
            let one_element = once(0_u128);
            let endlessly_repeated = one_element.into_iter().cycle();
            endlessly_repeated.take(accounts_count)
        }

        let accounts_count = qualified_payables.len();
        let criteria_iterator = only_zero_criteria_iterator(accounts_count);
        criteria_iterator.zip(qualified_payables.into_iter())
    }

    fn apply_criteria(
        &self,
        accounts_with_zero_criteria: impl Iterator<Item = (u128, PayableAccount)>,
    ) -> Vec<(u128, PayableAccount)> {
        let criteria_and_accounts = accounts_with_zero_criteria
            .iterate_for_criteria(AgeCriterionCalculator::new(self))
            .iterate_for_criteria(BalanceCriterionCalculator::new());

        let collected_accounts_with_criteria =
            sort_in_descendant_order_by_criteria_sums(criteria_and_accounts);

        // effective only if the iterator is collected
        print_formulas_characteristics_for_diagnostics();

        collected_accounts_with_criteria
    }

    fn perform_masq_adjustment(
        &self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentIterationResult {
        let criteria_total = criteria_total(&accounts_with_individual_criteria);
        let non_finalized_adjusted_accounts = self.compute_adjusted_but_non_finalized_accounts(
            accounts_with_individual_criteria,
            criteria_total,
        );

        let still_unchecked_for_disqualified =
            match self.handle_possibly_outweighed_accounts(non_finalized_adjusted_accounts) {
                Either::Left(first_check_passing_accounts) => first_check_passing_accounts,
                Either::Right(with_some_outweighed) => return with_some_outweighed,
            };

        let verified_accounts = match Self::consider_account_disqualification(
            still_unchecked_for_disqualified,
            &self.logger,
        ) {
            Either::Left(verified_accounts) => verified_accounts,
            Either::Right(with_some_disqualified) => return with_some_disqualified,
        };

        AdjustmentIterationResult::AllAccountsProcessedSmoothly(verified_accounts)
    }

    fn compute_adjusted_but_non_finalized_accounts(
        &self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        criteria_total: u128,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let cw_masq_balance = self.inner.unallocated_cw_masq_balance_minor();
        let cpm_coeff =
            compute_fractional_numbers_preventing_mul_coefficient(cw_masq_balance, criteria_total);
        let multiplication_coeff_u256 = U256::from(cpm_coeff);

        let proportional_fragment_of_cw_balance = Self::compute_proportional_fragment(
            cw_masq_balance,
            criteria_total,
            multiplication_coeff_u256,
        );

        let turn_account_into_adjusted_account_before_finalization =
            |(criteria_sum, account): (u128, PayableAccount)| {
                let proposed_adjusted_balance = (U256::from(criteria_sum)
                    * proportional_fragment_of_cw_balance
                    / multiplication_coeff_u256)
                    .as_u128();

                non_finalized_adjusted_accounts_diagnostics(&account, proposed_adjusted_balance);

                AdjustedAccountBeforeFinalization::new(account, proposed_adjusted_balance)
            };

        accounts_with_individual_criteria
            .into_iter()
            .map(turn_account_into_adjusted_account_before_finalization)
            .collect()
    }

    fn compute_proportional_fragment(
        cw_masq_balance: u128,
        criteria_total: u128,
        multiplication_coeff: U256,
    ) -> U256 {
        let cw_masq_balance_u256 = U256::from(cw_masq_balance);
        let criteria_total_u256 = U256::from(criteria_total);

        cw_masq_balance_u256
            .checked_mul(multiplication_coeff)
            .unwrap_or_else(|| {
                panic!(
                    "mul overflow from {} * {}",
                    criteria_total_u256, multiplication_coeff
                )
            })
            .checked_div(criteria_total_u256)
            .expect("div overflow")
    }

    fn consider_account_disqualification(
        non_finalized_adjusted_accounts: Vec<AdjustedAccountBeforeFinalization>,
        logger: &Logger,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        if let Some(disqualified_account_wallet) =
            try_finding_an_account_to_disqualify_in_this_iteration(
                &non_finalized_adjusted_accounts,
                logger,
            )
        {
            let remaining = non_finalized_adjusted_accounts
                .into_iter()
                .filter(|account_info| {
                    account_info.original_account.wallet != disqualified_account_wallet
                })
                .collect::<Vec<_>>();

            let remaining_reverted = remaining
                .into_iter()
                .map(|account_info| {
                    PayableAccount::from((account_info, ProposedAdjustmentResolution::Revert))
                })
                .collect();

            Either::Right(AdjustmentIterationResult::SpecialTreatmentNeeded {
                case: TreatInsignificantAccount,
                remaining: remaining_reverted,
            })
        } else {
            Either::Left(non_finalized_adjusted_accounts)
        }
    }

    fn handle_possibly_outweighed_accounts(
        &self,
        non_finalized_adjusted_accounts: Vec<AdjustedAccountBeforeFinalization>,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        let init = (vec![], vec![]);
        let (outweighed, passing_through) = non_finalized_adjusted_accounts
            .into_iter()
            .fold(init, possibly_outweighed_accounts_fold_guts);

        if outweighed.is_empty() {
            Either::Left(passing_through)
        } else {
            let remaining =
                finalize_collection(passing_through, ProposedAdjustmentResolution::Revert);
            Either::Right(AdjustmentIterationResult::SpecialTreatmentNeeded {
                case: TreatOutweighedAccounts(outweighed),
                remaining,
            })
        }
    }

    fn adjust_cw_balance_down_as_result_of_this_last_iteration(
        &mut self,
        processed_outweighed: &[AdjustedAccountBeforeFinalization],
    ) {
        let subtrahend_total: u128 = sum_as(processed_outweighed, |account| {
            account.proposed_adjusted_balance
        });
        self.inner
            .update_unallocated_cw_balance_minor(subtrahend_total);

        diagnostics!(
            "LOWERED CW BALANCE",
            "Unallocated balance lowered by {} to {}",
            subtrahend_total,
            self.inner.unallocated_cw_masq_balance_minor()
        )
    }

    fn debug_info_opt(
        &self,
        qualified_payables: &[PayableAccount],
    ) -> Option<HashMap<Wallet, u128>> {
        self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|account| (account.wallet.clone(), account.balance_wei))
                .collect::<HashMap<Wallet, u128>>()
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adjustment {
    MasqToken,
    PriorityTransactionFee { affordable_transaction_count: u16 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum PaymentAdjusterError {
    AnalysisError(AnalysisError),
    AllAccountsUnexpectedlyEliminated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {
    NotEnoughTransactionFeeBalanceForSingleTx {
        number_of_accounts: usize,
        per_transaction_requirement_minor: u128,
        cw_transaction_fee_balance_minor: U256,
    },
    RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
        number_of_accounts: usize,
        cw_masq_balance_minor: u128,
    },
}

impl Display for PaymentAdjusterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentAdjusterError::AnalysisError(analysis_error) => match analysis_error {
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts,
                    per_transaction_requirement_minor,
                    cw_transaction_fee_balance_minor,
                } => write!(
                    f,
                    "Found smaller transaction fee balance than does for a single payment. \
                 Number of canceled payments: {}. Transaction fee for a single account: {} wei. \
                 Current consuming wallet balance: {} wei",
                    number_of_accounts,
                    per_transaction_requirement_minor.separate_with_commas(),
                    cw_transaction_fee_balance_minor.separate_with_commas()
                ),
                AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts,
                    cw_masq_balance_minor,
                } => write!(
                    f,
                    "Analysis has projected a likely unacceptable adjustment leaving each \
                of the payable accounts with too a low adjusted amount to pay. Please, proceed by \
                sending funds to your wallet. Number of canceled payments: {}. Current consuming \
                wallet balance: {} wei of MASQ",
                    number_of_accounts.separate_with_commas(),
                    cw_masq_balance_minor.separate_with_commas()
                ),
            },
            PaymentAdjusterError::AllAccountsUnexpectedlyEliminated => write!(
                f,
                "Despite \
            the preliminary analysis had expected a possibility to compute some executable \
            adjusted payments, the algorithm eventually rejected them all"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::MasqAndTransactionFeeRunner;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AdjustmentIterationResult;
    use crate::accountant::payment_adjuster::miscellaneous::data_structures::AfterAdjustmentSpecialTreatment::TreatInsignificantAccount;
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::criteria_total;
    use crate::accountant::payment_adjuster::test_utils::{
        make_extreme_accounts, make_initialized_subject, MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, AnalysisError, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, ResponseSkeleton};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use std::{usize, vec};
    use thousands::Separable;
    use web3::types::U256;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::PreparedAdjustment;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;

    #[test]
    #[should_panic(
        expected = "Broken code: Called the null implementation of the unallocated_cw_masq_balance_minor() method in PaymentAdjusterInner"
    )]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let result = PaymentAdjusterReal::new();

        let _ = result.inner.unallocated_cw_masq_balance_minor();
    }

    struct PayableBalancesAndCWBalanceTestConfig {
        balances_of_accounts: Either<Vec<u64>, Vec<u128>>,
        cw_balance_major: u64,
    }

    #[test]
    fn search_for_indispensable_adjustment_negative_answer() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_negative_answer";
        let mut subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        subject.logger = logger;
        // MASQ balance > payments
        let input_1 = make_qualified_payables_and_blockchain_agent_for_initial_check(
            Some(PayableBalancesAndCWBalanceTestConfig {
                balances_of_accounts: Either::Right(vec![
                    gwei_to_wei::<u128, u64>(85),
                    gwei_to_wei::<u128, u64>(15) - 1,
                ]),
                cw_balance_major: 100,
            }),
            None,
        );
        // MASQ balance == payments
        let input_2 = make_qualified_payables_and_blockchain_agent_for_initial_check(
            Some(PayableBalancesAndCWBalanceTestConfig {
                balances_of_accounts: Either::Left(vec![85, 15]),
                cw_balance_major: 100,
            }),
            None,
        );
        // transaction fee balance > payments
        let input_3 = make_qualified_payables_and_blockchain_agent_for_initial_check(
            None,
            Some(TransactionFeeTestConfig {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_limit_per_transaction: 53_000,
                cw_transaction_fee_balance_major: (100 * 6 * 53_000) + 1,
            }),
        );
        // transaction fee balance == payments
        let input_4 = make_qualified_payables_and_blockchain_agent_for_initial_check(
            None,
            Some(TransactionFeeTestConfig {
                agreed_transaction_fee_per_computed_unit_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_limit_per_transaction: 53_000,
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
    fn search_for_indispensable_adjustment_positive_for_transaction_fee() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_transaction_fee";
        // means a confidently big balance is picked in the behind
        let masq_balances_setup_opt = None;
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let number_of_accounts = 3;
        let (qualified_payables, agent) =
            make_qualified_payables_and_blockchain_agent_for_initial_check(
                masq_balances_setup_opt,
                Some(TransactionFeeTestConfig {
                    agreed_transaction_fee_per_computed_unit_major: 100,
                    number_of_accounts,
                    estimated_transaction_fee_units_limit_per_transaction: 55_000,
                    cw_transaction_fee_balance_major: 100 * 3 * 55_000 - 1,
                }),
            );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Ok(Some(Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2
            }))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Gas amount 16,499,999,000,000,000 wei \
        cannot cover anticipated fees from sending 3 transactions. Maximum is 2. \
        The payments need to be adjusted in their count."
        ));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue consuming \
        services from other Nodes and avoid delinquency bans it is necessary to allocate more funds in \
        your consuming wallet."));
    }

    #[test]
    fn search_for_indispensable_adjustment_positive_for_masq_token() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_masq_token";
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let (qualified_payables, agent) =
            make_qualified_payables_and_blockchain_agent_for_initial_check(
                Some(PayableBalancesAndCWBalanceTestConfig {
                    balances_of_accounts: Either::Right(vec![
                        gwei_to_wei::<u128, u64>(85),
                        gwei_to_wei::<u128, u64>(15) + 1,
                    ]),
                    cw_balance_major: 100,
                }),
                None,
            );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(result, Ok(Some(Adjustment::MasqToken)));
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 100,000,000,001 \
        wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of the MASQ token. \
        Adjustment in their count or the amounts is required."));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue consuming services \
        from other Nodes and avoid delinquency bans it is necessary to allocate more funds in your consuming \
        wallet."));
    }

    #[test]
    fn checking_three_accounts_positive_for_transaction_fee_but_mask_balance_is_unbearably_low() {
        let test_name = "checking_three_accounts_positive_for_transaction_fee_but_mask_balance_is_unbearably_low";
        let masq_too_low_major = 120 / 2 - 1; // this would normally kick a serious error
        let masq_balances_setup_opt = Some(PayableBalancesAndCWBalanceTestConfig {
            balances_of_accounts: Either::Left(vec![120, 300, 500]),
            cw_balance_major: masq_too_low_major,
        });
        let (qualified_payables, agent) =
            make_qualified_payables_and_blockchain_agent_for_initial_check(
                masq_balances_setup_opt,
                None,
            );
        let mut subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        subject.logger = logger;

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: 3,
                    cw_masq_balance_minor: gwei_to_wei(masq_too_low_major)
                }
            ))
        );
    }

    #[test]
    fn not_enough_transaction_fee_balance_for_even_a_single_transaction() {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 3;
        let (qualified_payables, agent) =
            make_qualified_payables_and_blockchain_agent_for_initial_check(
                Some(PayableBalancesAndCWBalanceTestConfig {
                    balances_of_accounts: Either::Left(vec![123]),
                    cw_balance_major: 444,
                }),
                Some(TransactionFeeTestConfig {
                    agreed_transaction_fee_per_computed_unit_major: 100,
                    number_of_accounts,
                    estimated_transaction_fee_units_limit_per_transaction: 55_000,
                    cw_transaction_fee_balance_major: 54_000 * 100,
                }),
            );

        let result = subject.search_for_indispensable_adjustment(&qualified_payables, &*agent);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts,
                    per_transaction_requirement_minor: 55_000 * gwei_to_wei::<u128, u64>(100),
                    cw_transaction_fee_balance_minor: U256::from(54_000)
                        * gwei_to_wei::<U256, u64>(100)
                }
            ))
        );
    }

    #[test]
    fn payment_adjuster_error_implements_display() {
        vec![
            (
                PaymentAdjusterError::AnalysisError(
                    AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                        number_of_accounts: 5,
                        cw_masq_balance_minor: 333_000_000,
                    },
                ),
                "Analysis has projected a likely unacceptable adjustment leaving each of the payable \
                accounts with too a low adjusted amount to pay. Please, proceed by sending funds to \
                your wallet. Number of canceled payments: 5. Current consuming wallet balance: \
                333,000,000 wei of MASQ",
            ),
            (
                PaymentAdjusterError::AnalysisError(
                    AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                        number_of_accounts: 4,
                        per_transaction_requirement_minor: 70_000_000_000_000,
                        cw_transaction_fee_balance_minor: U256::from(90_000),
                    },
                ),
                "Found smaller transaction fee balance than does for a single payment. \
                Number of canceled payments: 4. Transaction fee for a single account: \
                70,000,000,000,000 wei. Current consuming wallet balance: 90,000 wei",
            ),
            (
                PaymentAdjusterError::AllAccountsUnexpectedlyEliminated,
                "Despite the preliminary analysis had expected a possibility to compute some \
                executable adjusted payments, the algorithm eventually rejected them all",
            ),
        ]
        .into_iter()
        .for_each(|(error, expected_msg)| assert_eq!(error.to_string(), expected_msg))
    }

    fn u16_max_plus_minus_correction(correction: i8) -> usize {
        if correction < 0 {
            (u16::MAX - correction.abs() as u16) as usize
        } else {
            u16::MAX as usize + correction as usize
        }
    }

    #[test]
    fn there_is_u16_ceiling_for_doable_txs_count() {
        let result = [-3_i8, -1, 0, 1, 10]
            .into_iter()
            .map(|correction| u16_max_plus_minus_correction(correction) as u128)
            .map(|max_doable_txs_count_u256| {
                let (doable_txs_count, _) =
                    PaymentAdjusterReal::put_bigger_unsigned_integers_under_u16_ceiling(
                        max_doable_txs_count_u256,
                        123,
                    );
                doable_txs_count
            })
            .collect::<Vec<_>>();

        assert_eq!(
            result,
            vec![u16::MAX - 3, u16::MAX - 1, u16::MAX, u16::MAX, u16::MAX]
        )
    }

    #[test]
    fn there_is_u16_ceiling_for_required_txs_count() {
        let result = [-9_i8, -1, 0, 1, 5]
            .into_iter()
            .map(|correction| u16_max_plus_minus_correction(correction))
            .map(|required_tx_count_usize| {
                let (_, required_tx_count) =
                    PaymentAdjusterReal::put_bigger_unsigned_integers_under_u16_ceiling(
                        123,
                        required_tx_count_usize,
                    );
                required_tx_count
            })
            .collect::<Vec<_>>();

        assert_eq!(
            result,
            vec![u16::MAX - 9, u16::MAX - 1, u16::MAX, u16::MAX, u16::MAX]
        )
    }

    #[test]
    fn apply_criteria_returns_accounts_sorted_by_criteria_in_descending_order() {
        let now = SystemTime::now();
        let subject = make_initialized_subject(now, None, None);
        let account_1 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 444_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];

        let criteria_and_accounts =
            subject.calculate_criteria_sums_for_accounts(qualified_payables);

        let mut previous_criteria_sum = u128::MAX;
        let only_accounts = criteria_and_accounts
            .into_iter()
            .map(|(criteria_sum, account)| {
                assert!(
                    previous_criteria_sum > criteria_sum,
                    "Previous criteria {} wasn't larger than {} but should've been",
                    previous_criteria_sum,
                    criteria_sum
                );
                previous_criteria_sum = criteria_sum;
                account
            })
            .collect::<Vec<PayableAccount>>();
        assert_eq!(only_accounts, vec![account_3, account_1, account_2])
    }

    #[test]
    fn minor_but_highly_aged_debt_takes_priority_as_called_outweighed_and_stays_at_its_original_balance(
    ) {
        let now = SystemTime::now();
        let cw_masq_balance = 1_500_000_000_000_u128 - 25_000_000 - 1000;
        let mut subject = make_initialized_subject(now, Some(cw_masq_balance), None);
        let balance_1 = 1_500_000_000_000;
        let balance_2 = 25_000_000;
        let wallet_1 = make_wallet("blah");
        let last_paid_timestamp_1 = now.checked_sub(Duration::from_secs(5_500)).unwrap();
        let account_1 = PayableAccount {
            wallet: wallet_1,
            balance_wei: balance_1,
            last_paid_timestamp: last_paid_timestamp_1,
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("argh"),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(20_000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone()];

        let mut result = subject
            .calculate_criteria_and_propose_adjustments_recursively(
                qualified_payables.clone(),
                MasqAndTransactionFeeRunner {},
            )
            .unwrap()
            .left()
            .unwrap();

        // First, a presentation of why this test is important
        let criteria_and_accounts =
            subject.calculate_criteria_sums_for_accounts(qualified_payables);
        let criteria_total = criteria_total(&criteria_and_accounts);
        let proposed_adjustments = subject
            .compute_adjusted_but_non_finalized_accounts(criteria_and_accounts, criteria_total);
        let proposed_adjusted_balance_2 = proposed_adjustments[1].proposed_adjusted_balance;
        // The criteria sum of the second account grew very progressively due to the effect of the greater age;
        // consequences would've been that redistributing the new balances according to the computed criteria would've
        // attributed the second account with more tokens to pay than it would've had before the test started;
        // to prevent it, we set a logical rule that no account can ever demand more than the 100% of itself
        assert!(
            proposed_adjusted_balance_2 > 10 * balance_2,
            "we expected the proposed balance \
        much bigger than the original which is {} but it was {}",
            balance_2,
            proposed_adjusted_balance_2
        );
        let first_returned_account = result.remove(0);
        // Outweighed accounts always take the first places
        assert_eq!(first_returned_account.original_account, account_2);
        assert_eq!(first_returned_account.proposed_adjusted_balance, balance_2);
        let second_returned_account = result.remove(0);
        assert_eq!(second_returned_account.original_account, account_1);
        let upper_limit = 1_500_000_000_000_u128 - 25_000_000 - 25_000_000 - 1000;
        let lower_limit = (upper_limit * 9) / 10;
        assert!(
            lower_limit <= second_returned_account.proposed_adjusted_balance
                && second_returned_account.proposed_adjusted_balance <= upper_limit,
            "we expected the roughly adjusted account to be between {} and {} but was {}",
            lower_limit,
            upper_limit,
            second_returned_account.proposed_adjusted_balance
        );
        assert!(result.is_empty());
    }

    #[test]
    fn account_never_becomes_outweighed_and_stuck_with_balance_higher_than_the_cw_balance_has_because_there_are_accounts_to_disqualify_first(
    ) {
        // NOTE that the same is true for more outweighed accounts together that would require more than the whole cw balance, therefore there is no such a test either.
        // This test answers what is happening when the cw MASQ balance cannot cover the outweighed accounts at the first try but if there are outweighed accounts
        // some other accounts must be also around of which some are under the disqualification limit and one of these would definitely be heading to disqualification.
        // With enough money, the other account might not need to meet disqualification which means the initial concern is still groundless: there must be enough money
        // to cover the outweighed account if there is other one which is qualified neither as outweighed or disqualified.
        const SECONDS_IN_3_DAYS: u64 = 259_200;
        let test_name =
            "account_never_becomes_outweighed_and_stuck_with_balance_higher_than_the_cw_balance_has_because_there_are_accounts_to_disqualify_first";
        let now = SystemTime::now();
        let consuming_wallet_balance = 1_000_000_000_000_u128 - 1;
        let account_1 = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: 1_000_000_000_000,
            last_paid_timestamp: now
                // Greater age like this together with smaller balance usually causes the account to be qualified as outweighed
                .checked_sub(Duration::from_secs(SECONDS_IN_3_DAYS))
                .unwrap(),
            pending_payable_opt: None,
        };
        let balance_2 = 8_000_000_000_000_000;
        let wallet_2 = make_wallet("booga");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: balance_2,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let accounts = vec![account_1.clone(), account_2.clone()];
        let subject = make_initialized_subject(
            now,
            Some(consuming_wallet_balance),
            Some(Logger::new(test_name)),
        );
        let accounts_with_individual_criteria =
            subject.calculate_criteria_sums_for_accounts(accounts);

        let result = subject.perform_masq_adjustment(accounts_with_individual_criteria.clone());

        let remaining = match result {
            AdjustmentIterationResult::SpecialTreatmentNeeded {
                case: TreatInsignificantAccount,
                remaining,
            } => remaining,
            x => panic!("we expected to see a disqualified account but got: {:?}", x),
        };
        assert_eq!(remaining, vec![account_1])
    }

    #[test]
    fn there_are_doors_leading_out_if_we_happen_to_end_up_with_disqualified_account_while_no_remaining_accounts(
    ) {
        init_test_logging();
        let test_name = "there_are_doors_leading_out_if_we_happen_to_end_up_with_disqualified_account_while_no_remaining_accounts";
        let mut subject =
            make_initialized_subject(SystemTime::now(), Some(123), Some(Logger::new(test_name)));
        let adjustment_iteration_result = AdjustmentIterationResult::SpecialTreatmentNeeded {
            case: TreatInsignificantAccount,
            remaining: vec![],
        };

        let (here_decided_accounts, downstream_decided_accounts) =
            subject.resolve_iteration_result(adjustment_iteration_result);

        assert!(here_decided_accounts.is_empty());
        assert!(downstream_decided_accounts.is_empty());
        // Even though we normally don't assert on DEBUG logs, this one hardens the test
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Last remaining account ended up disqualified"
        ));
    }

    #[test]
    fn loading_the_entire_process_with_exaggerated_debt_conditions_to_see_if_it_handles_overly_large_numbers(
    ) {
        init_test_logging();
        let test_name = "loading_the_entire_process_with_exaggerated_debt_conditions_to_see_if_it_handles_such_big_numbers";
        let now = SystemTime::now();
        // each of 3 accounts contains the full token supply is 10 years old which generates extremely big numbers in the criteria
        let qualified_payables = {
            let debt_age_in_months = vec![120, 120, 120];
            make_extreme_accounts(
                Either::Left((debt_age_in_months, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR)),
                now,
            )
        };
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        // for change extremely small cw balance
        let cw_masq_balance = 1_000;
        let agent = {
            let mock = BlockchainAgentMock::default().service_fee_balance_result(cw_masq_balance);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::MasqToken,
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // None on the output, because the proposed final balances are way lower than (at least) the half of the original balances;
        // normally, the initial feasibility check wouldn't allow this
        assert_eq!(result.affordable_accounts, vec![]);
        let expected_log = |wallet: &str, proposed_adjusted_balance_in_this_iteration: u64| {
            format!(
                "INFO: {test_name}: Dealing with the consuming wallet being short of MASQ. \
            Seems unavoidable to disregard payable {wallet} at the moment. \
            Reason is the computed possible payment of {} wei \
            would not be at least half of the original debt {}",
                proposed_adjusted_balance_in_this_iteration.separate_with_commas(),
                (*MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR).separate_with_commas()
            )
        };
        let log_handler = TestLogHandler::new();
        // Notice that the proposals grow as one disqualified account drops in each iteration
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
            1000,
        ));
    }

    #[test]
    fn adjust_payments_when_the_initial_transaction_count_evens_the_final_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_the_initial_transaction_count_evens_the_final_count";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 4_444_444_444_444_444_444,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100_234)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 6_000_000_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(150_000)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: 6_666_666_666_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100_000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let accounts_sum: u128 =
            4_444_444_444_444_444_444 + 6_000_000_000_000_000_000 + 6_666_666_666_000_000_000;
        let service_fee_balance_in_minor_units = accounts_sum - 2_000_000_000_000_000_000;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::MasqToken, //this means the computation happens regardless the actual transaction_fee balance limitations
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_criteria_computation_output = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 3_918_231_688_187_775_576,
                ..account_1
            };
            let account_2_adjusted = PayableAccount {
                balance_wei: 5_921_593_128_688_275_336,
                ..account_2
            };
            let account_3_adjusted = PayableAccount {
                balance_wei: 5_271_286_293_568_393_532,
                ..account_3
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
|----------------------------------------------------------
|Successfully Adjusted                      Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 6000000000000000000
|                                           5921593128688275336
|0x0000000000000000000000000000000000676869 6666666666000000000
|                                           5271286293568393532
|0x0000000000000000000000000000000000616263 4444444444444444444
|                                           3918231688187775576"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn adjust_payments_when_only_transaction_fee_limits_the_final_transaction_count_and_the_masq_balance_is_comfortably_large(
    ) {
        init_test_logging();
        let test_name = "adjust_payments_when_only_transaction_fee_limits_the_final_transaction_count_and_the_masq_balance_is_comfortably_large";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: 222_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(10_u128.pow(22));
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(result.affordable_accounts, vec![account_3, account_2]);
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|----------------------------------------------------------
|Successfully Adjusted                      Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 333000000000000
|                                           333000000000000
|0x0000000000000000000000000000000000676869 222000000000000
|                                           222000000000000
|
|Ruled Out                                  Original
|
|0x0000000000000000000000000000000000616263 111000000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn both_balances_are_insufficient_but_adjustment_by_masq_will_not_affect_the_accounts_count() {
        init_test_logging();
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 222_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let service_fee_balance_in_minor_units = 111_000_000_000_000_u128 + 333_000_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); //just hardening, not so important
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // account_1, the least important one, was eliminated for missing enough
        // transaction fee balance
        let expected_accounts = {
            let account_2_adjusted = PayableAccount {
                balance_wei: 222_000_000_000_000,
                ..account_2
            };
            vec![account_3, account_2_adjusted]
        };
        assert_eq!(result.affordable_accounts, expected_accounts);
        assert_eq!(result.response_skeleton_opt, response_skeleton_opt);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
    }

    #[test]
    fn adjust_payments_when_only_masq_balance_limits_the_final_transaction_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_only_masq_balance_limits_the_final_transaction_count";
        let now = SystemTime::now();
        let wallet_1 = make_wallet("def");
        // account to be adjusted up to maximum
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 333_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(12000)).unwrap(),
            pending_payable_opt: None,
        };
        // account to be outweighed and fully taken
        let wallet_2 = make_wallet("abc");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: 111_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(8000)).unwrap(),
            pending_payable_opt: None,
        };
        // account to be disqualified
        let wallet_3 = make_wallet("ghk");
        let balance_3 = 600_000_000_000;
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: balance_3,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(6000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = 333_000_000_000 + 50_000_000_000;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 111,
            context_id: 234,
        });
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::MasqToken,
            response_skeleton_opt,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 272_000_000_000,
                ..account_1
            };
            vec![account_1_adjusted, account_2]
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
        TestLogHandler::new().exists_log_containing(&format!("INFO: {test_name}: Dealing with the consuming wallet \
        being short of MASQ. Seems unavoidable to disregard payable 0x000000000000000000000000000000000067686b \
        at the moment. Reason is the computed possible payment of 69,153,257,937 wei \
        would not be at least half of the original debt 600,000,000,000"));
    }

    struct CompetitiveAccountsTestInputs<'a> {
        common: WalletsSetup<'a>,
        balance_correction_minor_account_1: u128,
        balance_correction_minor_account_2: u128,
        age_correction_secs_account_1: u64,
        age_correction_secs_account_2: u64,
    }

    #[derive(Clone, Copy)]
    struct WalletsSetup<'a> {
        wallet_1: &'a Wallet,
        wallet_2: &'a Wallet,
    }

    fn test_two_competitive_accounts_with_one_disqualified<'a>(
        test_scenario_name: &str,
        inputs: CompetitiveAccountsTestInputs,
        expected_winning_account_wallet: &'a Wallet,
    ) {
        let now = SystemTime::now();
        let service_fee_balance_in_minor_units = 100_000_000_000_000_u128 - 1;
        let standard_balance_per_account = 100_000_000_000_000;
        let standard_age_per_account = 12000;
        let account_1 = PayableAccount {
            wallet: inputs.common.wallet_1.clone(),
            balance_wei: standard_balance_per_account + inputs.balance_correction_minor_account_1,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.age_correction_secs_account_1,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: inputs.common.wallet_2.clone(),
            balance_wei: standard_balance_per_account + inputs.balance_correction_minor_account_2,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    standard_age_per_account + inputs.age_correction_secs_account_2,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2];
        let mut subject = PaymentAdjusterReal::new();
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::MasqToken,
            response_skeleton_opt: None,
        };

        let mut result = subject
            .adjust_payments(adjustment_setup, now)
            .unwrap()
            .affordable_accounts;

        let winning_account = result.remove(0);
        assert_eq!(
            &winning_account.wallet, expected_winning_account_wallet,
            "{}: expected wallet {} but got {}",
            test_scenario_name, winning_account.wallet, expected_winning_account_wallet
        );
        assert_eq!(
            winning_account.balance_wei, service_fee_balance_in_minor_units,
            "{}: expected full cw balance {}, but the account had {}",
            test_scenario_name, winning_account.balance_wei, service_fee_balance_in_minor_units
        );
        assert!(
            result.is_empty(),
            "{}: is not empty, {:?} remains",
            test_scenario_name,
            result
        )
    }

    #[test]
    fn adjust_payments_when_not_enough_masq_to_pay_both_at_least_by_their_half() {
        fn merge_test_name_with_test_case(description: &str) -> String {
            format!(
                "adjust_payments_when_not_enough_masq_to_pay_both_at_least_by_their_half{}",
                description
            )
        }

        let wallet_1 = make_wallet("abcd");
        let wallet_2 = make_wallet("cdef");
        let common_input = WalletsSetup {
            wallet_1: &wallet_1,
            wallet_2: &wallet_2,
        };
        // scenario A
        let first_scenario_name = merge_test_name_with_test_case("when equal");
        let expected_winning_account = &wallet_2;

        test_two_competitive_accounts_with_one_disqualified(
            &first_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                balance_correction_minor_account_1: 0,
                balance_correction_minor_account_2: 0,
                age_correction_secs_account_1: 0,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        );

        // scenario B
        let second_scenario_name = merge_test_name_with_test_case("first heavier by balance");
        let expected_winning_account = &wallet_2;

        test_two_competitive_accounts_with_one_disqualified(
            &second_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                balance_correction_minor_account_1: 1,
                balance_correction_minor_account_2: 0,
                age_correction_secs_account_1: 0,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        );

        // scenario C
        let third_scenario_name = merge_test_name_with_test_case("second heavier by age");
        let expected_winning_account = &wallet_1;

        test_two_competitive_accounts_with_one_disqualified(
            &third_scenario_name,
            CompetitiveAccountsTestInputs {
                common: common_input,
                balance_correction_minor_account_1: 0,
                balance_correction_minor_account_2: 0,
                age_correction_secs_account_1: 1,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        )
    }

    #[test]
    fn adjust_payments_when_masq_as_well_as_transaction_fee_limits_the_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_masq_as_well_as_transaction_fee_limits_the_count";
        let now = SystemTime::now();
        // Thrown away as the second for the proposed balance insignificance
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 10_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        // Thrown away as the first one for the proposed balance insignificance
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 55_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghi");
        let last_paid_timestamp_3 = now.checked_sub(Duration::from_secs(29000)).unwrap();
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: last_paid_timestamp_3,
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2, account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = 300_000_000_000_000_u128;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(
            result.affordable_accounts,
            vec![PayableAccount {
                wallet: wallet_3,
                balance_wei: service_fee_balance_in_minor_units,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            }]
        );
        assert_eq!(result.response_skeleton_opt, None);
        assert_eq!(result.agent.arbitrary_id_stamp(), agent_id_stamp);
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Payable Account                            Balance Wei
|----------------------------------------------------------
|Successfully Adjusted                      Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000676869 333000000000000
|                                           300000000000000
|
|Ruled Out                                  Original
|
|0x0000000000000000000000000000000000616263 10000000000000
|0x0000000000000000000000000000000000646566 55000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn error_from_the_depths_after_transaction_fee_adjusted_but_masq_balance_is_rechecked_and_found_fully_insufficient(
    ) {
        init_test_logging();
        let test_name = "error_from_the_depths_after_transaction_fee_adjusted_but_masq_balance_is_rechecked_and_found_fully_insufficient";
        let now = SystemTime::now();
        //this account gets eliminated in the transaction-fee cut
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghi"),
            balance_wei: 222_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2, account_3];
        let mut subject = PaymentAdjusterReal::new();
        // This is exactly the amount which will provoke an error
        subject.logger = Logger::new(test_name);
        let service_fee_balance_in_minor_units = (111_000_000_000_000 / 2) - 1;
        let agent = {
            let mock = BlockchainAgentMock::default()
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables,
            agent,
            adjustment: Adjustment::PriorityTransactionFee {
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
            PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfWastedAdjustmentWithAllAccountsEventuallyEliminated {
                    number_of_accounts: 2,
                    cw_masq_balance_minor: service_fee_balance_in_minor_units
                }
            )
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Passing successful payment adjustment by the transaction fee, but \
            facing critical scarcity of MASQ balance. Operation will abort."
        ));
    }

    #[test]
    fn entry_check_predicts_worth_of_trying_for_potential_adjustment_aptly_despite_many_eliminated_accounts(
    ) {
        let test_name = "entry_check_predicts_worth_of_trying_for_potential_adjustment_aptly_despite_many_eliminated_accounts";
        let now = SystemTime::now();
        // Disqualified in the first iteration
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 10_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        // Disqualified in the second iteration
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 550_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(15000)).unwrap(),
            pending_payable_opt: None,
        };
        // Eventually picked fulfilling the keep condition and returned
        let wallet_3 = make_wallet("ghi");
        let last_paid_timestamp_3 = now.checked_sub(Duration::from_secs(29000)).unwrap();
        let balance_3 = 100_000_000_000;
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: balance_3,
            last_paid_timestamp: last_paid_timestamp_3,
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1, account_2, account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        subject.logger = logger.clone();
        // This cw balance should be enough to fulfill the entry check. After eliminating two accounts,
        // the final winning resolution of the third account will work out because of the only
        // additional one.
        // The strategies advance reversed. The initial check seeks the smallest account,
        // the disqualification strategy always takes from the largest accounts first.
        // As a result, we can forecast the chances if the adjustment would succeed, not having to
        // move forward beyond the entry check.
        let service_fee_balance_in_minor_units = (balance_3 / 2) + 1;
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = {
            let mock = BlockchainAgentMock::default()
                .set_arbitrary_id_stamp(agent_id_stamp)
                .service_fee_balance_result(service_fee_balance_in_minor_units);
            Box::new(mock)
        };
        let adjustment_setup = PreparedAdjustment {
            qualified_payables: qualified_payables.clone(),
            agent,
            adjustment: Adjustment::MasqToken,
            response_skeleton_opt: None,
        };

        let check_result = PaymentAdjusterReal::check_need_of_masq_adjustment(
            &logger,
            Either::Left(&qualified_payables),
            service_fee_balance_in_minor_units,
        );
        let adjustment_result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(check_result, Ok(true));
        assert_eq!(
            adjustment_result.affordable_accounts,
            vec![PayableAccount {
                wallet: wallet_3,
                balance_wei: service_fee_balance_in_minor_units,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            }]
        );
        assert_eq!(adjustment_result.response_skeleton_opt, None);
        assert_eq!(adjustment_result.agent.arbitrary_id_stamp(), agent_id_stamp)
    }

    struct TransactionFeeTestConfig {
        agreed_transaction_fee_per_computed_unit_major: u64,
        number_of_accounts: usize,
        estimated_transaction_fee_units_limit_per_transaction: u64,
        cw_transaction_fee_balance_major: u64,
    }

    fn make_qualified_payables_and_blockchain_agent_for_initial_check(
        masq_balances_config_opt: Option<PayableBalancesAndCWBalanceTestConfig>,
        transaction_fee_config_opt: Option<TransactionFeeTestConfig>,
    ) -> (Vec<PayableAccount>, Box<dyn BlockchainAgent>) {
        let masq_balances_setup = match masq_balances_config_opt {
            Some(config) => config,
            None => PayableBalancesAndCWBalanceTestConfig {
                balances_of_accounts: Either::Left(vec![1, 1]),
                cw_balance_major: u64::MAX,
            },
        };

        let cw_service_fee_minor: u128 = gwei_to_wei(masq_balances_setup.cw_balance_major);

        let balances_of_accounts_minor = match masq_balances_setup.balances_of_accounts {
            Either::Left(in_major) => in_major
                .into_iter()
                .map(|major| gwei_to_wei(major))
                .collect(),
            Either::Right(in_minor) => in_minor,
        };

        let accounts_count = balances_of_accounts_minor.len();

        let (
            desired_transaction_fee_price,
            number_of_payments,
            estimated_transaction_fee_unit_limit_per_transaction,
            cw_balance_transaction_fee_major,
        ) = match transaction_fee_config_opt {
            Some(conditions) => (
                conditions.agreed_transaction_fee_per_computed_unit_major,
                conditions.number_of_accounts,
                conditions.estimated_transaction_fee_units_limit_per_transaction,
                conditions.cw_transaction_fee_balance_major,
            ),
            None => (120, accounts_count, 55_000, u64::MAX),
        };

        let qualified_payables: Vec<_> = if number_of_payments != accounts_count {
            (0..number_of_payments)
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
        };
        let cw_transaction_fee_minor = gwei_to_wei(cw_balance_transaction_fee_major);
        let estimated_transaction_fee_per_transaction_minor = gwei_to_wei(
            estimated_transaction_fee_unit_limit_per_transaction * desired_transaction_fee_price,
        );
        let blockchain_agent = BlockchainAgentMock::default()
            .transaction_fee_balance_result(cw_transaction_fee_minor)
            .service_fee_balance_result(cw_service_fee_minor)
            .estimated_transaction_fee_per_transaction_result(
                estimated_transaction_fee_per_transaction_minor,
            );
        // PayablePaymentSetup {
        //     qualified_payables,
        //     this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
        //         FinancialAndTechDetails {
        //             consuming_wallet_balances: ConsumingWalletBalances {
        //                 transaction_fee_minor: cw_transaction_fee_minor,
        //                 masq_tokens_minor: cw_masq_balance_minor,
        //             },
        //             estimated_gas_limit_per_transaction: estimated_transaction_fee_limit_per_tx,
        //             agreed_transaction_fee_per_computed_unit_major: desired_transaction_fee_price,
        //         },
        //     )),
        //     response_skeleton_opt: None,
        // }
        (qualified_payables, Box::new(blockchain_agent))
    }
}
