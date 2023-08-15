// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//keep these modules private
mod adjustment_runners;
mod criteria_calculators;
mod diagnostics;
mod inner;
mod log_fns;
mod miscellaneous;
mod test_utils;

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::gwei_to_wei;
use crate::accountant::payment_adjuster::adjustment_runners::{
    AdjustmentRunner, MasqAndTransactionFeeRunner, MasqOnlyRunner,
};
use crate::accountant::payment_adjuster::criteria_calculators::age_criterion_calculator::AgeCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::balance_criterion_calculator::BalanceCriterionCalculator;
use crate::accountant::payment_adjuster::criteria_calculators::CriteriaIteratorAdaptor;
use crate::accountant::payment_adjuster::diagnostics::formulas_progressive_characteristics::print_formulas_characteristics_for_diagnostics;
use crate::accountant::payment_adjuster::diagnostics::separately_defined_diagnostic_functions::{
    maybe_find_an_account_to_disqualify_diagnostics, non_finalized_adjusted_accounts_diagnostics,
};
use crate::accountant::payment_adjuster::diagnostics::{diagnostics, diagnostics_for_collections};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::log_fns::{
    before_and_after_debug_msg, log_adjustment_by_masq_required,
    log_error_for_transaction_fee_adjustment_ok_but_masq_balance_insufficient,
    log_info_for_disqualified_account, log_insufficient_transaction_fee_balance,
};
use crate::accountant::payment_adjuster::miscellaneous::data_sructures::SpecialTreatment::{
    TreatInsignificantAccount, TreatOutweighedAccounts,
};
use crate::accountant::payment_adjuster::miscellaneous::data_sructures::{
    AdjustedAccountBeforeFinalization, AdjustmentIterationResult, DisqualifiedPayableAccount,
    ResolutionAfterFullyDetermined,
};
use crate::accountant::payment_adjuster::miscellaneous::helper_functions::{
    assess_potential_masq_adjustment_feasibility, compute_fraction_preventing_mul_coeff,
    criteria_total, cut_back_by_excessive_transaction_fee, exhaust_cw_balance_totally,
    find_largest_debt_account_generic, list_accounts_under_the_disqualification_limit,
    possibly_outweighed_accounts_fold_guts, rebuild_accounts, sort_in_descendant_order_by_weights,
    sum_as,
};
use crate::accountant::scanners::payable_scan_setup_msgs::{
    FinancialAndTechDetails, PayablePaymentSetup, StageData,
};
use crate::accountant::scanners::scan_mid_procedures::PreparedAdjustment;
use crate::diagnostics;
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::OutcomingPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::iter::once;
use std::ops::Not;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &PayablePaymentSetup,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError>;

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutcomingPaymentsInstructions, PaymentAdjusterError>;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {
    inner: Box<dyn PaymentAdjusterInner>,
    logger: Logger,
}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &PayablePaymentSetup,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError> {
        let qualified_payables = msg.qualified_payables.as_slice();
        let this_stage_data = match msg
            .this_stage_data_opt
            .as_ref()
            .expect("always some at this stage")
        {
            StageData::FinancialAndTechDetails(details) => details,
        };

        let transaction_fee_adjustment_opt =
            Self::determine_transactions_count_limit_by_transaction_fee(
                &this_stage_data,
                qualified_payables.len(),
                &self.logger,
            )?;

        let is_masq_adjustment_needed = Self::check_need_of_masq_balances_adjustment(
            &self.logger,
            Either::Left(qualified_payables),
            this_stage_data.consuming_wallet_balances.masq_tokens_minor,
        )?;

        match (transaction_fee_adjustment_opt, is_masq_adjustment_needed) {
            (Some(affordable_transaction_count), _) => {
                Ok(Some(Adjustment::PriorityTransactionFee {
                    affordable_transaction_count,
                }))
            }
            (None, true) => Ok(Some(Adjustment::MasqToken)),
            _ => Ok(None),
        }
    }

    fn adjust_payments(
        &mut self,
        setup: PreparedAdjustment,
        now: SystemTime,
    ) -> Result<OutcomingPaymentsInstructions, PaymentAdjusterError> {
        let msg = setup.original_setup_msg;
        let qualified_payables: Vec<PayableAccount> = msg.qualified_payables;
        let response_skeleton_opt = msg.response_skeleton_opt;
        let current_stage_data = match msg.this_stage_data_opt.expectv("complete setup data") {
            StageData::FinancialAndTechDetails(details) => details,
        };
        let required_adjustment = setup.adjustment;

        self.initialize_inner(current_stage_data, required_adjustment, now);

        let debug_info_opt = self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|account| (account.wallet.clone(), account.balance_wei))
                .collect::<HashMap<Wallet, u128>>()
        });

        let adjusted_accounts = self.run_adjustment(qualified_payables)?;

        debug!(
            self.logger,
            "{}",
            before_and_after_debug_msg(debug_info_opt.expectv("debug info"), &adjusted_accounts)
        );

        Ok(OutcomingPaymentsInstructions {
            accounts: adjusted_accounts,
            response_skeleton_opt,
        })
    }

    implement_as_any!();
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

    fn determine_transactions_count_limit_by_transaction_fee(
        tech_info: &FinancialAndTechDetails,
        required_tx_count: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, PaymentAdjusterError> {
        let transaction_fee_required_per_transaction_major =
            tech_info.estimated_gas_limit_per_transaction as u128
                * tech_info.desired_transaction_fee_price_major as u128;

        let transaction_fee_required_minor: u128 =
            gwei_to_wei(transaction_fee_required_per_transaction_major);
        let available_balance_minor = tech_info.consuming_wallet_balances.transaction_fee_minor;
        let max_doable_tx_count_loose_boundaries =
            available_balance_minor / transaction_fee_required_minor;
        let (max_doable_tx_count_u16, required_tx_count_u16) =
            Self::cast_big_numbers_down_with_possible_ceiling(
                max_doable_tx_count_loose_boundaries,
                required_tx_count,
            );
        if max_doable_tx_count_u16 == 0 {
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts: required_tx_count,
                    per_transaction_requirement_minor: transaction_fee_required_minor,
                    cw_transaction_fee_balance_minor: available_balance_minor,
                },
            ))
        } else if max_doable_tx_count_u16 >= required_tx_count_u16 {
            Ok(None)
        } else {
            log_insufficient_transaction_fee_balance(
                logger,
                required_tx_count_u16,
                tech_info.consuming_wallet_balances.transaction_fee_minor,
                max_doable_tx_count_u16,
            );
            Ok(Some(max_doable_tx_count_u16))
        }
    }

    fn cast_big_numbers_down_with_possible_ceiling(
        max_doable_tx_count: u128,
        required_tx_count: usize,
    ) -> (u16, u16) {
        (
            u16::try_from(max_doable_tx_count).unwrap_or(u16::MAX),
            u16::try_from(required_tx_count).unwrap_or(u16::MAX),
        )
    }

    fn check_need_of_masq_balances_adjustment(
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
            assess_potential_masq_adjustment_feasibility(
                &qualified_payables,
                cw_masq_balance_minor,
            )?;
            log_adjustment_by_masq_required(logger, required_masq_sum, cw_masq_balance_minor);
            Ok(true)
        }
    }

    fn initialize_inner(
        &mut self,
        setup: FinancialAndTechDetails,
        required_adjustment: Adjustment,
        now: SystemTime,
    ) {
        let transaction_fee_limitation_opt = match required_adjustment {
            Adjustment::PriorityTransactionFee {
                affordable_transaction_count,
            } => Some(affordable_transaction_count),
            Adjustment::MasqToken => None,
        };
        let cw_masq_balance = setup.consuming_wallet_balances.masq_tokens_minor;
        let inner =
            PaymentAdjusterInnerReal::new(now, transaction_fee_limitation_opt, cw_masq_balance);
        self.inner = Box::new(inner);
    }

    fn run_adjustment(
        &mut self,
        qualified_accounts: Vec<PayableAccount>,
    ) -> Result<Vec<PayableAccount>, PaymentAdjusterError> {
        let accounts = self.calculate_criteria_and_propose_adjustment_recursively(
            qualified_accounts,
            MasqAndTransactionFeeRunner {},
        )?;
        match accounts {
            Either::Left(non_exhausted_accounts) => Ok(exhaust_cw_balance_totally(
                non_exhausted_accounts,
                self.inner.original_cw_masq_balance(),
            )),
            Either::Right(finalized_accounts) => Ok(finalized_accounts),
        }
    }

    fn calculate_criteria_and_propose_adjustment_recursively<A, R>(
        &mut self,
        unresolved_qualified_accounts: Vec<PayableAccount>,
        purpose_specific_adjuster: A,
    ) -> R
    where
        A: AdjustmentRunner<ReturnType = R>,
    {
        diagnostics_for_collections(
            "\nUNRESOLVED QUALIFIED ACCOUNTS:",
            &unresolved_qualified_accounts,
        );

        let accounts_with_individual_criteria_sorted =
            self.calculate_criteria_sums_for_accounts(unresolved_qualified_accounts);

        purpose_specific_adjuster.adjust(self, accounts_with_individual_criteria_sorted)
    }

    fn begin_with_adjustment_by_transaction_fees(
        &mut self,
        criteria_and_accounts_in_descending_order: Vec<(u128, PayableAccount)>,
        already_known_count_limit: u16,
    ) -> Result<
        Either<Vec<AdjustedAccountBeforeFinalization>, Vec<PayableAccount>>,
        PaymentAdjusterError,
    > {
        let transaction_fee_affordable_weighted_accounts = cut_back_by_excessive_transaction_fee(
            criteria_and_accounts_in_descending_order,
            already_known_count_limit,
        );
        let unallocated_balance = self.inner.unallocated_cw_masq_balance();
        let definite_answer = match Self::check_need_of_masq_balances_adjustment(
            &self.logger,
            Either::Right(&transaction_fee_affordable_weighted_accounts),
            unallocated_balance,
        ) {
            Ok(answer) => answer,
            Err(e) => {
                log_error_for_transaction_fee_adjustment_ok_but_masq_balance_insufficient(
                    &self.logger,
                );
                return Err(e);
            }
        };
        match definite_answer {
            true => {
                let result_awaiting_verification = self
                    .propose_adjustment_recursively(transaction_fee_affordable_weighted_accounts);
                Ok(Either::Left(result_awaiting_verification))
            }
            false => {
                let finalized_accounts =
                    rebuild_accounts(transaction_fee_affordable_weighted_accounts);
                Ok(Either::Right(finalized_accounts))
            }
        }
    }

    fn calculate_criteria_sums_for_accounts(
        &self,
        accounts: Vec<PayableAccount>,
    ) -> Vec<(u128, PayableAccount)> {
        let zero_criteria_accounts = Self::initialize_zero_criteria(accounts);
        self.apply_criteria(zero_criteria_accounts)
    }

    fn propose_adjustment_recursively(
        &mut self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let adjustment_iteration_result =
            self.perform_masq_token_adjustment(accounts_with_individual_criteria);

        let (here_decided_accounts, downstream_decided_accounts) =
            self.resolve_iteration_result(adjustment_iteration_result);

        let here_decided_iter = here_decided_accounts.into_iter();
        let downstream_decided_iter = downstream_decided_accounts.into_iter();
        let merged: Vec<AdjustedAccountBeforeFinalization> =
            here_decided_iter.chain(downstream_decided_iter).collect();
        diagnostics_for_collections("\nFINAL ADJUSTED ACCOUNTS:", &merged);
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
                special_case,
                remaining,
            } => {
                let here_decided_accounts = match special_case {
                    TreatInsignificantAccount(disqualified) => {
                        log_info_for_disqualified_account(&self.logger, &disqualified);

                        if remaining.is_empty() {
                            // We've reached a niche. The performed combination has eliminated all
                            // accounts in spite of the initial mechanism, that tried to weight
                            // whether it was possible to return minimally one adjusted account for
                            // the payments, was pushing hard to the edge, it actually did not manage
                            // to get it right. Being here means the prevention of possibly unnecessary
                            // computation has failed.
                            //
                            // To get out of here we want to be gentle and avoid another iteration
                            // (probably wouldn't be fatal though). Anyway, it's a win pf the choice for
                            // well determined behavior instead of letting the situation unwind down to
                            // waters we don't exactly know.
                            return (vec![], vec![]);
                        }

                        vec![]
                    }
                    TreatOutweighedAccounts(outweighed) => {
                        self.adjust_cw_balance_down_before_another_iteration(&outweighed);
                        outweighed
                    }
                };

                let down_stream_decided_accounts = self
                    .calculate_criteria_and_propose_adjustment_recursively(
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
            sort_in_descendant_order_by_weights(criteria_and_accounts);

        // effective only if the iterator is collected
        print_formulas_characteristics_for_diagnostics();

        collected_accounts_with_criteria
    }

    fn perform_masq_token_adjustment(
        &self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentIterationResult {
        let criteria_total = criteria_total(&accounts_with_individual_criteria);
        self.recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria,
            criteria_total,
        )
    }

    fn recreate_accounts_with_proportioned_balances(
        &self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        criteria_total: u128,
    ) -> AdjustmentIterationResult {
        let non_finalized_adjusted_accounts = self.compute_non_finalized_already_adjusted_accounts(
            accounts_with_individual_criteria,
            criteria_total,
        );

        let unchecked_for_disqualified =
            match self.handle_possibly_outweighed_account(non_finalized_adjusted_accounts) {
                Either::Left(still_not_fully_checked) => still_not_fully_checked,
                Either::Right(with_some_outweighed) => return with_some_outweighed,
            };

        let verified_accounts = match Self::consider_accounts_disqualification(
            unchecked_for_disqualified,
            &self.logger,
        ) {
            Either::Left(verified_accounts) => verified_accounts,
            Either::Right(with_some_disqualified) => return with_some_disqualified,
        };

        AdjustmentIterationResult::AllAccountsProcessedSmoothly(verified_accounts)
    }

    fn compute_non_finalized_already_adjusted_accounts(
        &self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        criteria_total: u128,
    ) -> Vec<AdjustedAccountBeforeFinalization> {
        let cw_masq_balance = self.inner.unallocated_cw_masq_balance();
        let multiplication_coeff =
            compute_fraction_preventing_mul_coeff(cw_masq_balance, criteria_total);
        let cw_masq_balance_u256 = U256::from(cw_masq_balance);
        let criteria_total_u256 = U256::from(criteria_total);
        let multiplication_coeff_u256 = U256::from(multiplication_coeff);

        let proportional_fragment_of_cw_balance = cw_masq_balance_u256
            .checked_mul(multiplication_coeff_u256)
            .unwrap_or_else(|| {
                panic!(
                    "mul overflow from {} * {}",
                    criteria_total_u256, multiplication_coeff_u256
                )
            })
            .checked_div(criteria_total_u256)
            .expect("div overflow");

        let turn_account_into_adjusted_account_before_finalization =
            |(criteria_sum, account): (u128, PayableAccount)| {
                let proposed_adjusted_balance = (U256::from(criteria_sum)
                    * proportional_fragment_of_cw_balance
                    / multiplication_coeff_u256)
                    .as_u128();

                non_finalized_adjusted_accounts_diagnostics(&account, proposed_adjusted_balance);

                AdjustedAccountBeforeFinalization::new(
                    account,
                    proposed_adjusted_balance,
                    criteria_sum,
                )
            };

        accounts_with_individual_criteria
            .into_iter()
            .map(turn_account_into_adjusted_account_before_finalization)
            .collect()
    }

    fn consider_accounts_disqualification(
        non_finalized_adjusted_accounts: Vec<AdjustedAccountBeforeFinalization>,
        logger: &Logger,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        if let Some(disq_account_wallet) =
            Self::maybe_find_an_account_to_disqualify_in_this_iteration(
                &non_finalized_adjusted_accounts,
                logger,
            )
        {
            let init = (
                None,
                Vec::with_capacity(non_finalized_adjusted_accounts.len() - 1),
            );

            type FoldAccumulator = (
                Option<AdjustedAccountBeforeFinalization>,
                Vec<AdjustedAccountBeforeFinalization>,
            );
            let fold_guts = |(disqualified_acc_opt, mut remaining_accounts): FoldAccumulator,
                             current_account: AdjustedAccountBeforeFinalization|
             -> FoldAccumulator {
                if current_account.original_account.wallet == disq_account_wallet {
                    (Some(current_account), remaining_accounts)
                } else {
                    remaining_accounts.push(current_account);
                    (disqualified_acc_opt, remaining_accounts)
                }
            };

            let (single_disqualified, remaining) = non_finalized_adjusted_accounts
                .into_iter()
                .fold(init, fold_guts);

            let debugable_disqualified = {
                let account_info =
                    single_disqualified.expect("already verified disqualified account is gone");
                DisqualifiedPayableAccount::new(
                    account_info.original_account.wallet,
                    account_info.original_account.balance_wei,
                    account_info.proposed_adjusted_balance,
                )
            };

            let remaining_reverted = remaining
                .into_iter()
                .map(|account_info| {
                    PayableAccount::from((account_info, ResolutionAfterFullyDetermined::Revert))
                })
                .collect();
            Either::Right(AdjustmentIterationResult::SpecialTreatmentNeeded {
                special_case: TreatInsignificantAccount(debugable_disqualified),
                remaining: remaining_reverted,
            })
        } else {
            Either::Left(non_finalized_adjusted_accounts)
        }
    }

    fn maybe_find_an_account_to_disqualify_in_this_iteration(
        non_finalized_adjusted_accounts: &[AdjustedAccountBeforeFinalization],
        logger: &Logger,
    ) -> Option<Wallet> {
        let disqualification_suspected_accounts =
            list_accounts_under_the_disqualification_limit(non_finalized_adjusted_accounts);
        disqualification_suspected_accounts
            .is_empty()
            .not()
            .then(|| {
                // comparison based on the criteria sum is more accurate than on the proposed adjusted balance
                // which comes rounded up to here
                let account_to_disqualify = find_largest_debt_account_generic(
                    &disqualification_suspected_accounts,
                    |account_info| account_info.criteria_sum,
                );

                let wallet = account_to_disqualify.original_account.wallet.clone();

                maybe_find_an_account_to_disqualify_diagnostics(
                    &disqualification_suspected_accounts,
                    &wallet,
                );

                trace!(
                    logger,
                    "Found accounts {:?} whose proposed new, adjusted balances laid under \
            the limit for disqualification. Choose the least desirable proposal of account {} to \
            be thrown away in this iteration.",
                    disqualification_suspected_accounts,
                    wallet
                );
                wallet
            })
    }

    fn handle_possibly_outweighed_account(
        &self,
        non_finalized_adjusted_accounts: Vec<AdjustedAccountBeforeFinalization>,
    ) -> Either<Vec<AdjustedAccountBeforeFinalization>, AdjustmentIterationResult> {
        let (outweighed, passing_through) = non_finalized_adjusted_accounts
            .into_iter()
            .fold((vec![], vec![]), possibly_outweighed_accounts_fold_guts);

        if outweighed.is_empty() {
            Either::Left(passing_through)
        } else {
            let remaining = AdjustedAccountBeforeFinalization::finalize_collection(
                passing_through,
                ResolutionAfterFullyDetermined::Revert,
            );
            Either::Right(AdjustmentIterationResult::SpecialTreatmentNeeded {
                special_case: TreatOutweighedAccounts(outweighed),
                remaining,
            })
        }
    }

    fn adjust_cw_balance_down_before_another_iteration(
        &mut self,
        processed_outweighed: &[AdjustedAccountBeforeFinalization],
    ) {
        let subtrahend_total: u128 = sum_as(processed_outweighed, |account| {
            account.proposed_adjusted_balance
        });
        self.inner.lower_unallocated_cw_balance(subtrahend_total);

        diagnostics!(
            "LOWERED CW BALANCE",
            "Unallocated balance lowered by {} to {}",
            subtrahend_total,
            self.inner.unallocated_cw_masq_balance()
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
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
        cw_transaction_fee_balance_minor: u128,
    },
    RiskOfAdjustmentWithTooLowMASQBalances {
        number_of_accounts: usize,
        cw_masq_balance_minor: u128,
    },
}

impl Display for PaymentAdjusterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentAdjusterError::AnalysisError(analysis_error) => match analysis_error{
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {number_of_accounts,per_transaction_requirement_minor, cw_transaction_fee_balance_minor } =>
                    write!(f, "Found less transaction fee balance than required by one payment. \
                 Number of canceled payments: {}. Transaction fee for a single account: {} wei. \
                 Current consuming wallet balance: {} wei", number_of_accounts, per_transaction_requirement_minor.separate_with_commas(),
                           cw_transaction_fee_balance_minor.separate_with_commas()),
                AnalysisError::RiskOfAdjustmentWithTooLowMASQBalances {number_of_accounts, cw_masq_balance_minor } =>
                    write!(f,"Analysis has revealed possibly unfavourable payment adjustments given \
                the anticipated resulting payments from the limited resources. Please, provide more \
                funds instead. Number of canceled payments: {}. Current consuming wallet balance: \
                {} wei of MASQ", number_of_accounts.separate_with_commas(),cw_masq_balance_minor.separate_with_commas())
            },
            PaymentAdjusterError::AllAccountsUnexpectedlyEliminated => write!(f, "Despite \
            the preliminary analysis had expected a possibility to compute some executable \
            adjusted payments, the algorithm eventually rejected them all")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::adjustment_runners::MasqAndTransactionFeeRunner;
    use crate::accountant::payment_adjuster::miscellaneous::data_sructures::SpecialTreatment::TreatInsignificantAccount;
    use crate::accountant::payment_adjuster::miscellaneous::data_sructures::{
        AdjustmentIterationResult, DisqualifiedPayableAccount, SpecialTreatment,
    };
    use crate::accountant::payment_adjuster::miscellaneous::helper_functions::criteria_total;
    use crate::accountant::payment_adjuster::test_utils::{
        make_extreme_accounts, make_initialized_subject, MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
    };
    use crate::accountant::payment_adjuster::{
        Adjustment, AnalysisError, PaymentAdjuster, PaymentAdjusterError, PaymentAdjusterReal,
    };
    use crate::accountant::scanners::payable_scan_setup_msgs::{
        FinancialAndTechDetails, PayablePaymentSetup, StageData,
    };
    use crate::accountant::scanners::scan_mid_procedures::PreparedAdjustment;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, ResponseSkeleton};
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPaymentsInstructions,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use std::{usize, vec};
    use thousands::Separable;

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the unallocated_cw_masq_balance() method in PaymentAdjusterInner"
    )]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let result = PaymentAdjusterReal::new();

        let _ = result.inner.unallocated_cw_masq_balance();
    }

    struct PayableBalancesAndCWBAlanceInTest {
        balances_of_accounts_major: Vec<u64>,
        cw_balance_major: u64,
    }

    #[test]
    fn search_for_indispensable_adjustment_negative_answer() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_negative_answer";
        let mut subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        subject.logger = logger;
        //masq balance > payments
        let msg_1 = make_payable_setup_msg_coming_from_blockchain_bridge(
            Some(PayableBalancesAndCWBAlanceInTest {
                balances_of_accounts_major: vec![85, 14],
                cw_balance_major: 100,
            }),
            None,
        );
        //masq balance = payments
        let msg_2 = make_payable_setup_msg_coming_from_blockchain_bridge(
            Some(PayableBalancesAndCWBAlanceInTest {
                balances_of_accounts_major: vec![85, 15],
                cw_balance_major: 100,
            }),
            None,
        );
        //transaction_fee balance > payments
        let msg_3 = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(TransactionFeeConditionsInTest {
                desired_transaction_fee_price_per_major: 111,
                number_of_accounts: 5,
                estimated_transaction_fee_units_limit_per_transaction: 53_000,
                cw_transaction_fee_balance_major: (111 * 5 * 53_000) + 1,
            }),
        );
        //transaction_fee balance = payments
        let msg_4 = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(TransactionFeeConditionsInTest {
                desired_transaction_fee_price_per_major: 100,
                number_of_accounts: 6,
                estimated_transaction_fee_units_limit_per_transaction: 53_000,
                cw_transaction_fee_balance_major: 100 * 6 * 53_000,
            }),
        );

        [msg_1, msg_2, msg_3, msg_4].into_iter().for_each(|msg| {
            assert_eq!(
                subject.search_for_indispensable_adjustment(&msg),
                Ok(None),
                "failed for msg {:?}",
                msg
            )
        });

        TestLogHandler::new().exists_no_log_containing(&format!("WARN: {test_name}:"));
    }

    #[test]
    fn search_for_indispensable_adjustment_positive_for_masq_token() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_masq_token";
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let msg = make_payable_setup_msg_coming_from_blockchain_bridge(
            Some(PayableBalancesAndCWBAlanceInTest {
                balances_of_accounts_major: vec![85, 16],
                cw_balance_major: 100,
            }),
            None,
        );

        let result = subject.search_for_indispensable_adjustment(&msg);

        assert_eq!(result, Ok(Some(Adjustment::MasqToken)));
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 101,000,000,000 \
        wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of the MASQ token. \
        Adjustment in their count or the amounts is required."));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue using services \
        of other Nodes and avoid delinquency bans you will need to put more funds into your consuming wallet."));
    }

    fn test_positive_transaction_fee_check_vs_masq_check(
        test_name: &str,
        masq_balances_setup_opt: Option<PayableBalancesAndCWBAlanceInTest>,
    ) -> Result<Option<Adjustment>, PaymentAdjusterError> {
        init_test_logging();
        let logger = Logger::new(test_name);
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = logger;
        let number_of_accounts = 3;
        let msg = make_payable_setup_msg_coming_from_blockchain_bridge(
            masq_balances_setup_opt,
            Some(TransactionFeeConditionsInTest {
                desired_transaction_fee_price_per_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_limit_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 100 * 3 * 55_000 - 1,
            }),
        );

        subject.search_for_indispensable_adjustment(&msg)
    }

    fn assert_logs(test_name: &str) {
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Gas amount 16,499,999,000,000,000 wei \
        cannot cover anticipated fees from sending 3 transactions. Maximum is 2. \
        The payments need to be adjusted in their count."
        ));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue using services \
        of other Nodes and avoid delinquency bans you will need to put more funds into your consuming wallet."));
    }

    #[test]
    fn search_on_three_accounts_positive_for_transaction_fee_when_masq_balance_is_enough() {
        let test_name =
            "search_on_three_accounts_positive_for_transaction_fee_when_masq_balance_is_enough";
        // means there is plenty of masq
        let masq_balances_setup_opt = None;

        let result =
            test_positive_transaction_fee_check_vs_masq_check(test_name, masq_balances_setup_opt);

        assert_eq!(
            result,
            Ok(Some(Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2
            }))
        );
        assert_logs(test_name)
    }

    #[test]
    fn search_on_three_accounts_positive_for_transaction_fee_but_masq_balance_is_feasibly_adjustable(
    ) {
        let test_name = "search_on_three_accounts_positive_for_transaction_fee_but_masq_balance_is_feasibly_adjustable";
        let masq_low_but_ok_major = 300 + 500;
        let masq_balances_setup_opt = Some(PayableBalancesAndCWBAlanceInTest {
            balances_of_accounts_major: vec![120, 300, 500],
            cw_balance_major: masq_low_but_ok_major,
        });

        let result =
            test_positive_transaction_fee_check_vs_masq_check(test_name, masq_balances_setup_opt);

        assert_eq!(
            result,
            Ok(Some(Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2
            }))
        );
        assert_logs(test_name)
    }

    #[test]
    fn search_on_three_accounts_positive_for_transaction_fee_but_mask_balance_is_desperately_low() {
        let test_name = "search_on_three_accounts_positive_for_transaction_fee_but_mask_balance_is_desperately_low";
        let masq_too_low_major = 500 / 2 - 1; // this will kick the limit
        let masq_balances_setup_opt = Some(PayableBalancesAndCWBAlanceInTest {
            balances_of_accounts_major: vec![120, 300, 500],
            cw_balance_major: masq_too_low_major,
        });

        let result =
            test_positive_transaction_fee_check_vs_masq_check(test_name, masq_balances_setup_opt);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfAdjustmentWithTooLowMASQBalances {
                    number_of_accounts: 3,
                    cw_masq_balance_minor: gwei_to_wei(masq_too_low_major)
                }
            ))
        );
        assert_logs(test_name)
    }

    #[test]
    fn search_for_indispensable_adjustment_unable_to_pay_even_for_a_single_transaction_because_of_transaction_fee(
    ) {
        let subject = PaymentAdjusterReal::new();
        let number_of_accounts = 3;
        let msg = make_payable_setup_msg_coming_from_blockchain_bridge(
            Some(PayableBalancesAndCWBAlanceInTest {
                balances_of_accounts_major: vec![123],
                cw_balance_major: 444,
            }),
            Some(TransactionFeeConditionsInTest {
                desired_transaction_fee_price_per_major: 100,
                number_of_accounts,
                estimated_transaction_fee_units_limit_per_transaction: 55_000,
                cw_transaction_fee_balance_major: 54_000 * 100,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&msg);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                    number_of_accounts,
                    per_transaction_requirement_minor: 55_000 * 100 * 1_000_000_000,
                    cw_transaction_fee_balance_minor: 54_000 * 100 * 1_000_000_000
                }
            ))
        );
    }

    #[test]
    fn payment_adjuster_error_implements_display() {
        vec![
            (
                PaymentAdjusterError::AnalysisError(
                    AnalysisError::RiskOfAdjustmentWithTooLowMASQBalances {
                        number_of_accounts: 5,
                        cw_masq_balance_minor: 333_000_000,
                    },
                ),
                "Analysis has revealed possibly unfavourable payment adjustments given \
                the anticipated resulting payments from the limited resources. Please, \
                provide more funds instead. Number of canceled payments: 5. Current \
                consuming wallet balance: 333,000,000 wei of MASQ",
            ),
            (
                PaymentAdjusterError::AnalysisError(
                    AnalysisError::NotEnoughTransactionFeeBalanceForSingleTx {
                        number_of_accounts: 4,
                        per_transaction_requirement_minor: 70_000_000_000_000,
                        cw_transaction_fee_balance_minor: 90_000,
                    },
                ),
                "Found less transaction fee balance than required by one payment. \
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

    #[test]
    fn there_is_u16_max_ceiling_for_doable_txs_count() {
        let result = [-3_i8, -1, 0, 1, 10]
            .into_iter()
            .map(|correction| {
                if correction < 0 {
                    (u16::MAX - correction.abs() as u16) as u128
                } else {
                    u16::MAX as u128 + correction as u128
                }
            })
            .map(|max_doable_txs_count_u256| {
                let (doable_txs_count, _) =
                    PaymentAdjusterReal::cast_big_numbers_down_with_possible_ceiling(
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
    fn there_is_u16_max_ceiling_for_required_txs_count() {
        let result = [-9_i8, -1, 0, 1, 5]
            .into_iter()
            .map(|correction| {
                if correction < 0 {
                    (u16::MAX - (correction.abs() as u16)) as usize
                } else {
                    u16::MAX as usize + correction as usize
                }
            })
            .map(|required_tx_count_usize| {
                let (_, required_tx_count) =
                    PaymentAdjusterReal::cast_big_numbers_down_with_possible_ceiling(
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
    fn apply_criteria_returns_accounts_sorted_by_final_weights_in_descending_order() {
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

        let only_accounts = criteria_and_accounts
            .iter()
            .map(|(_, account)| account)
            .collect::<Vec<&PayableAccount>>();
        assert_eq!(only_accounts, vec![&account_3, &account_1, &account_2])
    }

    #[test]
    fn only_the_most_demanding_one_is_picked_from_disqualified_accounts() {
        let test_name = "only_the_most_demanding_one_is_picked_from_disqualified_accounts";
        let now = SystemTime::now();
        let cw_masq_balance = 2_000_000_000_000;
        let logger = Logger::new(test_name);
        let subject = make_initialized_subject(now, Some(cw_masq_balance), None);
        let wallet_1 = make_wallet("abc");
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 700_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100_000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("def");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: 333_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1_000_000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghi");
        // balance big enough to be hard to match it up to the disqualification limit and 1 s more
        // than the first account
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: 700_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100_001)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_4 = make_wallet("jkl");
        let account_4 = PayableAccount {
            wallet: wallet_4.clone(),
            balance_wei: 120_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(7_000)).unwrap(),
            pending_payable_opt: None,
        };
        let accounts_with_individual_criteria = subject
            .calculate_criteria_sums_for_accounts(vec![account_1, account_2, account_3, account_4]);
        let criteria_total = criteria_total(&accounts_with_individual_criteria);
        let non_finalized_adjusted_accounts = subject
            .compute_non_finalized_already_adjusted_accounts(
                accounts_with_individual_criteria,
                criteria_total,
            );

        let result = PaymentAdjusterReal::maybe_find_an_account_to_disqualify_in_this_iteration(
            &non_finalized_adjusted_accounts,
            &logger,
        );

        assert_eq!(result, Some(wallet_3));
    }

    #[test]
    fn smaller_debt_with_extreme_age_is_picked_prioritized_as_outweighed_but_not_with_more_money_than_required(
    ) {
        const SAFETY_MULTIPLIER: u128 = 1_000_000_000_000_000;
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
            .calculate_criteria_and_propose_adjustment_recursively(
                qualified_payables.clone(),
                MasqAndTransactionFeeRunner {},
            )
            .unwrap()
            .left()
            .unwrap();

        //first a presentation of why this test is important
        let criteria_and_accounts =
            subject.calculate_criteria_sums_for_accounts(qualified_payables);
        let criteria_total = criteria_total(&criteria_and_accounts);
        let account_2_criterion = criteria_and_accounts[1].0;
        let cw_balance_fractional_safe = cw_masq_balance * SAFETY_MULTIPLIER;
        let proportional_fragment_of_cw_balance = cw_balance_fractional_safe / criteria_total;
        let proposed_adjusted_balance_2 =
            (account_2_criterion * proportional_fragment_of_cw_balance) / SAFETY_MULTIPLIER;
        //the weight of the second account grew very progressively due to the effect of the long age;
        //consequences are that redistributing the new balances according to the computed weights would've attributed
        //the second account with more tokens to pay than it'd had before the test started;
        //to prevent it, we've got a rule that no account can ever demand more than its 100%
        assert!(
            proposed_adjusted_balance_2 > 10 * balance_2,
            "we expected the proposed balance \
        much bigger than the original which is {} but it was {}",
            balance_2,
            proposed_adjusted_balance_2
        );
        let first_account = result.remove(0);
        //outweighed account takes the first place
        assert_eq!(first_account.original_account, account_2);
        assert_eq!(first_account.proposed_adjusted_balance, balance_2);
        let second_account = result.remove(0);
        assert_eq!(second_account.original_account, account_1);
        let upper_limit = ((1_500_000_000_000_u128 - 25_000_000 - 25_000_000 - 1000)
            * 999_999_999_999)
            / 1_000_000_000_000;
        let lower_limit = (upper_limit * 9) / 10;
        assert!(
            lower_limit < second_account.proposed_adjusted_balance
                && second_account.proposed_adjusted_balance < upper_limit,
            "we expected the roughly adjusted account to be between {} and {} but was {}",
            lower_limit,
            upper_limit,
            second_account.proposed_adjusted_balance
        );
        assert!(result.is_empty());
    }

    #[test]
    fn an_account_never_becomes_outweighed_and_needing_more_than_the_cw_balance_has_because_disqualified_accounts_need_to_be_eliminated_first(
    ) {
        // NOTE that the same is true for more outweighed accounts together that would require more than the whole cw balance, therefore there is no such a test at all.
        // This test answers what is happening when the cw MASQ balance cannot cover the outweighed accounts at the first try but if there are outweighed accounts
        // some other accounts must be also around of which one would definitely be heading to disqualification.
        // With enough money, the other account might not need to meet disqualification which means the concern about an outweighed account that
        // could not be paid by its full volume turns out to be groundless. Also meaning, that the algorithm strives not to cause another form of
        // insufficient, different from that one we had at the beginning
        const SECONDS_IN_3_DAYS: u64 = 259_200;
        let test_name =
            "an_account_never_becomes_outweighed_and_balance_full_while_cw_balance_smaller_than_that_because_disqualified_accounts_will_be_eliminated_first";
        let now = SystemTime::now();
        let consuming_wallet_balance = 1_000_000_000_000_u128 - 1;
        let subject = make_initialized_subject(
            now,
            Some(consuming_wallet_balance),
            Some(Logger::new(test_name)),
        );
        let account_1 = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: 1_000_000_000_000,
            last_paid_timestamp: now
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
        let accounts_with_individual_criteria =
            subject.calculate_criteria_sums_for_accounts(accounts);
        let criteria_total = criteria_total(&accounts_with_individual_criteria);

        let result = subject.recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria.clone(),
            criteria_total,
        );

        let (disqualified, remaining) = match result {
            AdjustmentIterationResult::SpecialTreatmentNeeded {
                special_case: TreatInsignificantAccount(disqualified),
                remaining,
            } => (disqualified, remaining),
            x => panic!("we expected to see a disqualified account but got: {:?}", x),
        };
        let expected_disqualified_account = DisqualifiedPayableAccount {
            wallet: wallet_2,
            proposed_adjusted_balance: 890_785_846,
            original_balance: balance_2,
        };
        assert_eq!(disqualified, expected_disqualified_account);
        assert_eq!(remaining, vec![account_1])
    }

    #[test]
    fn there_are_safe_doors_leading_out_if_we_happen_to_end_up_with_disqualified_account_while_no_remaining_accounts(
    ) {
        init_test_logging();
        let test_name = "there_are_safe_doors_leading_out_if_we_happen_to_end_up_with_disqualified_account_while_no_remaining_accounts";
        let mut subject =
            make_initialized_subject(SystemTime::now(), Some(123), Some(Logger::new(test_name)));
        let insignificant_account = DisqualifiedPayableAccount {
            wallet: make_wallet("abc"),
            proposed_adjusted_balance: 123,
            original_balance: 600,
        };
        let adjustment_iteration_result = AdjustmentIterationResult::SpecialTreatmentNeeded {
            special_case: SpecialTreatment::TreatInsignificantAccount(insignificant_account),
            remaining: vec![],
        };

        let (here_decided_accounts, downstream_decided_accounts) =
            subject.resolve_iteration_result(adjustment_iteration_result);

        assert!(here_decided_accounts.is_empty());
        assert!(downstream_decided_accounts.is_empty());
        TestLogHandler::new().exists_log_matching(&format!("INFO: {test_name}: .*unavoidable to disregard payable 0x0000000000000000000000000000000000616263"));
    }

    #[test]
    fn loading_the_complete_process_with_exaggerated_debt_conditions_without_blowing_up_on_math_operations(
    ) {
        init_test_logging();
        let test_name = "loading_the_complete_process_with_exaggerated_debt_conditions_without_blowing_up_on_math_operations";
        let now = SystemTime::now();
        //each of 3 accounts contains the full token supply and a 10-years-old debt which generates extremely big numbers in the criteria
        let qualified_payables = {
            let debt_age_in_months = vec![120, 120, 120];
            make_extreme_accounts(
                Either::Left((debt_age_in_months, *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR)),
                now,
            )
        };
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        //for change extremely small cw balance
        let cw_masq_balance = 1_000;
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: u32::MAX as u128,
                        masq_tokens_minor: cw_masq_balance,
                    },
                    estimated_gas_limit_per_transaction: 70_000,
                    desired_transaction_fee_price_major: 120,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        //because the proposed final balances all all way lower than (at least) the half of the original balances
        assert_eq!(result.accounts, vec![]);
        let expected_log = |wallet: &str, proposed_adjusted_balance_in_this_iteration: u64| {
            format!("INFO: {test_name}: Consuming wallet is short of MASQ. Seems unavoidable to \
            disregard payable {wallet} at the moment. Reason is the computed possible payment of {\
            proposed_adjusted_balance_in_this_iteration} wei would not be at least half of the original \
            debt {}", (*MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR).separate_with_commas())
        };
        let log_handler = TestLogHandler::new();
        // notice that the proposals grow by dropping one disqualified account in each iteration
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
        let accounts_sum: u128 =
            4_444_444_444_444_444_444 + 6_000_000_000_000_000_000 + 6_666_666_666_000_000_000;
        let consuming_wallet_masq_balance_minor = accounts_sum - 2_000_000_000_000_000_000;
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: u32::MAX as u128,
                        masq_tokens_minor: consuming_wallet_masq_balance_minor,
                    },
                    estimated_gas_limit_per_transaction: 70_000,
                    desired_transaction_fee_price_major: 120,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken, //this means the computation happens regardless the actual transaction_fee balance limitations
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
            result,
            OutcomingPaymentsInstructions {
                accounts: expected_criteria_computation_output,
                response_skeleton_opt: None
            }
        );
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
    fn adjust_payments_when_only_transaction_fee_limits_the_final_transaction_count_and_masq_will_do_after_the_transaction_fee_cut(
    ) {
        init_test_logging();
        let test_name = "adjust_payments_when_only_transaction_fee_limits_the_final_transaction_count_and_masq_will_do_after_the_transaction_fee_cut";
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
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: 5_544_000_000_000_000_u128 - 1,
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_minor: 10_u128.pow(22),
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_transaction_fee_price_major: 24,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        assert_eq!(
            result,
            OutcomingPaymentsInstructions {
                accounts: vec![account_3, account_2],
                response_skeleton_opt: None
            }
        );
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
|Ruled Out in Favor of the Others           Original
|
|0x0000000000000000000000000000000000616263 111000000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn both_balances_are_insufficient_but_adjustment_by_masq_cuts_down_no_accounts_it_just_adjusts_their_balances(
    ) {
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
        let consuming_wallet_masq_balance = 111_000_000_000_000_u128 + 333_000_000_000_000;
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 123,
            context_id: 321,
        }); //just hardening, not so important
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: 5_544_000_000_000_000_u128 - 1,
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_minor: consuming_wallet_masq_balance,
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_transaction_fee_price_major: 24,
                },
            )),
            response_skeleton_opt,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        // account_1, being the least important one, was eliminated as there wouldn't be enough
        // the transaction fee balance for all of them
        let expected_accounts = {
            let account_2_adjusted = PayableAccount {
                balance_wei: 222_000_000_000_000,
                ..account_2
            };
            vec![account_2_adjusted, account_3]
        };
        assert_eq!(
            result,
            OutcomingPaymentsInstructions {
                accounts: expected_accounts,
                response_skeleton_opt
            }
        );
    }

    #[test]
    fn adjust_payments_when_only_masq_token_limits_the_final_transaction_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_only_masq_token_limits_the_final_transaction_count";
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
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let consuming_wallet_masq_balance_minor = 333_000_000_000 + 50_000_000_000;
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: 5_000_000_000_000_000_000_000_000_u128,
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_minor: consuming_wallet_masq_balance_minor,
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_transaction_fee_price_major: 24,
                },
            )),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234,
            }),
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        let result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let expected_accounts = {
            let account_1_adjusted = PayableAccount {
                balance_wei: 272_000_000_000,
                ..account_1
            };
            vec![account_1_adjusted, account_2]
        };
        assert_eq!(result.accounts, expected_accounts);
        assert_eq!(
            result.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234
            })
        );
        TestLogHandler::new().exists_log_containing(&format!("INFO: {test_name}: Consuming wallet is \
        short of MASQ. Seems unavoidable to disregard payable 0x000000000000000000000000000000000067686b \
        at the moment. Reason is the computed possible payment of 69,153,257,937 wei \
        would not be at least half of the original debt 600,000,000,000"));
    }

    struct CompetitiveAccountsTestInput<'a> {
        common: WalletsSetup<'a>,
        balance_correction_account_1: u128,
        balance_correction_account_2: u128,
        age_correction_secs_account_1: u64,
        age_correction_secs_account_2: u64,
    }

    #[derive(Clone, Copy)]
    struct WalletsSetup<'a> {
        wallet_1: &'a Wallet,
        wallet_2: &'a Wallet,
    }

    fn test_competitive_accounts<'a>(
        test_scenario_name: &str,
        inputs: CompetitiveAccountsTestInput,
        expected_winning_account: &'a Wallet,
    ) {
        let consuming_wallet_balance_minor = 100_000_000_000_000_u128 - 1;
        let common_balance_account = 100_000_000_000_000;
        let common_age_secs_account = 12000;
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: inputs.common.wallet_1.clone(),
            balance_wei: inputs.balance_correction_account_1 + common_balance_account,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    inputs.age_correction_secs_account_1 + common_age_secs_account,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: inputs.common.wallet_2.clone(),
            balance_wei: inputs.balance_correction_account_2 + common_balance_account,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    inputs.age_correction_secs_account_2 + common_age_secs_account,
                ))
                .unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let consuming_wallet_masq_balance_wei = consuming_wallet_balance_minor;
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: u128::MAX,
                        masq_tokens_minor: consuming_wallet_masq_balance_wei,
                    },
                    estimated_gas_limit_per_transaction: 55_000,
                    desired_transaction_fee_price_major: 150,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        let mut result = subject
            .adjust_payments(adjustment_setup, now)
            .unwrap()
            .accounts;

        let winning_account = result.remove(0);
        assert_eq!(
            &winning_account.wallet, expected_winning_account,
            "{}: expected {} but got {}",
            test_scenario_name, winning_account.wallet, expected_winning_account
        );
        assert_eq!(
            winning_account.balance_wei, consuming_wallet_balance_minor,
            "{}: expected full cw balance {}, but the account had {}",
            test_scenario_name, winning_account.balance_wei, consuming_wallet_balance_minor
        );
        assert!(
            result.is_empty(),
            "{}: is not empty, {:?} remains",
            test_scenario_name,
            result
        )
    }

    #[test]
    fn adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account() {
        fn merge_main_test_name_with_test_case(description: &str) -> String {
            format!(
                "adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account_{}",
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
        let first_scenario_name = merge_main_test_name_with_test_case("when equal");
        let expected_winning_account = &wallet_2;

        test_competitive_accounts(
            &first_scenario_name,
            CompetitiveAccountsTestInput {
                common: common_input,
                balance_correction_account_1: 0,
                balance_correction_account_2: 0,
                age_correction_secs_account_1: 0,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        );

        // scenario B
        let second_scenario_name = merge_main_test_name_with_test_case("first heavier by balance");
        let expected_winning_account = &wallet_2;

        test_competitive_accounts(
            &second_scenario_name,
            CompetitiveAccountsTestInput {
                common: common_input,
                balance_correction_account_1: 1,
                balance_correction_account_2: 0,
                age_correction_secs_account_1: 0,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        );

        // scenario C
        let third_scenario_name = merge_main_test_name_with_test_case("second heavier by age");
        let expected_winning_account = &wallet_1;

        test_competitive_accounts(
            &third_scenario_name,
            CompetitiveAccountsTestInput {
                common: common_input,
                balance_correction_account_1: 0,
                balance_correction_account_2: 0,
                age_correction_secs_account_1: 1,
                age_correction_secs_account_2: 0,
            },
            expected_winning_account,
        )
    }

    #[test]
    fn adjust_payments_when_masq_as_well_as_transaction_fee_will_limit_the_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_masq_as_well_as_transaction_fee_will_limit_the_count";
        let now = SystemTime::now();
        //thrown away as the second one because of its insignificance (proposed adjusted balance is smaller than half the original)
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 10_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        //thrown away as the first one for insufficient transaction_fee
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
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let consuming_wallet_masq_balance = 300_000_000_000_000_u128;
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: 5_544_000_000_000_000_u128 - 1,
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_minor: consuming_wallet_masq_balance,
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_transaction_fee_price_major: 24,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
        };

        let mut result = subject.adjust_payments(adjustment_setup, now).unwrap();

        let only_account = result.accounts.remove(0);
        assert_eq!(
            only_account,
            PayableAccount {
                wallet: wallet_3,
                balance_wei: consuming_wallet_masq_balance,
                last_paid_timestamp: last_paid_timestamp_3,
                pending_payable_opt: None,
            }
        );
        assert_eq!(result.accounts.len(), 0);
        assert_eq!(result.response_skeleton_opt, None);
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
|Ruled Out in Favor of the Others           Original
|
|0x0000000000000000000000000000000000616263 10000000000000
|0x0000000000000000000000000000000000646566 55000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn error_returns_after_transaction_fee_adjustment_done_but_mask_balance_is_found_completely_insufficient(
    ) {
        init_test_logging();
        let test_name = "error_returns_after_transaction_fee_adjustment_done_but_mask_balance_is_found_completely_insufficient";
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
        let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let cw_masq_balance_minor = (333_000_000_000_000 / 2) - 1; //this is exactly the amount which will provoke an error
        subject.logger = Logger::new(test_name);
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: 5_544_000_000_000_000_u128 - 1,
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_minor: cw_masq_balance_minor,
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_transaction_fee_price_major: 24,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = PreparedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::PriorityTransactionFee {
                affordable_transaction_count: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now);

        assert_eq!(
            result,
            Err(PaymentAdjusterError::AnalysisError(
                AnalysisError::RiskOfAdjustmentWithTooLowMASQBalances {
                    number_of_accounts: 2,
                    cw_masq_balance_minor
                }
            ))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Passing successful \
        payment adjustment by the transaction fee, but facing critical scarcity of MASQ balance. \
        Operation will abort."
        ));
    }

    #[test]
    fn testing_reliability_by_long_loading_payment_adjuster_with_randomly_generated_accounts() {
        todo!("write this occasional test")
    }

    struct TransactionFeeConditionsInTest {
        desired_transaction_fee_price_per_major: u64,
        number_of_accounts: usize,
        estimated_transaction_fee_units_limit_per_transaction: u64,
        cw_transaction_fee_balance_major: u64,
    }

    fn make_payable_setup_msg_coming_from_blockchain_bridge(
        masq_balances_opt: Option<PayableBalancesAndCWBAlanceInTest>,
        transaction_fee_conditions_opt: Option<TransactionFeeConditionsInTest>,
    ) -> PayablePaymentSetup {
        let masq_balances_setup = masq_balances_opt.unwrap_or(PayableBalancesAndCWBAlanceInTest {
            balances_of_accounts_major: vec![1, 1],
            cw_balance_major: u64::MAX,
        });

        let accounts_count = masq_balances_setup.balances_of_accounts_major.len();

        let (
            desired_transaction_fee_price,
            number_of_payments,
            estimated_transaction_fee_limit_per_tx,
            cw_balance_transaction_fee_major,
        ) = match transaction_fee_conditions_opt {
            Some(conditions) => (
                conditions.desired_transaction_fee_price_per_major,
                conditions.number_of_accounts,
                conditions.estimated_transaction_fee_units_limit_per_transaction,
                conditions.cw_transaction_fee_balance_major,
            ),
            None => (120, accounts_count, 55_000, u64::MAX),
        };

        let qualified_payables: Vec<_> = match number_of_payments != accounts_count {
            true => (0..number_of_payments)
                .map(|idx| make_payable_account(idx as u64))
                .collect(),
            false => masq_balances_setup
                .balances_of_accounts_major
                .into_iter()
                .map(|balance| make_payable_account(balance))
                .collect(),
        };

        PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        transaction_fee_minor: gwei_to_wei(cw_balance_transaction_fee_major),
                        masq_tokens_minor: gwei_to_wei(masq_balances_setup.cw_balance_major),
                    },
                    estimated_gas_limit_per_transaction: estimated_transaction_fee_limit_per_tx,
                    desired_transaction_fee_price_major: desired_transaction_fee_price,
                },
            )),
            response_skeleton_opt: None,
        }
    }
}
