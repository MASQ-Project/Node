// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//keep these modules private
mod auxiliary_fns;
mod diagnostics;
mod inner;
mod log_fns;
mod test_utils;

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::auxiliary_fns::{
    compute_fractions_preventing_mul_coeff, criteria_total, cut_back_by_gas_count_limit, log_2,
    rebuild_accounts, sort_in_descendant_order_by_weights, sum_as, x_or_1,
};
use crate::accountant::payment_adjuster::diagnostics::{
    diagnostics, diagnostics_collective, diagnostics_x_axis_exponents_len, CriteriaWithDiagnostics,
    DiagnosticsSetting, AGE_SINGLETON, BALANCE_SINGLETON,
};
use crate::accountant::payment_adjuster::inner::{
    PaymentAdjusterInner, PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
};
use crate::accountant::payment_adjuster::log_fns::{
    before_and_after_debug_msg, log_adjustment_by_masq_required,
    log_info_for_disqualified_accounts, log_insufficient_transaction_fee_balance,
};
use crate::accountant::scanners::payable_scan_setup_msgs::{
    FinancialAndTechDetails, PayablePaymentSetup, StageData,
};
use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
use crate::accountant::{gwei_to_wei, wei_to_gwei};
use crate::diagnostics;
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, OutcomingPaymentsInstructions};
use crate::sub_lib::wallet::Wallet;
use itertools::Either::{Left, Right};
use itertools::{Either, Itertools};
use log::logger;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::collections::HashMap;
use std::iter::{once, successors};
use std::time::{Duration, SystemTime};
use thousands::Separable;
use web3::types::U256;

pub trait PaymentAdjuster {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &PayablePaymentSetup,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &mut self,
        setup: AwaitedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPaymentsInstructions;

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
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        let qualified_payables = msg.qualified_payables.as_slice();
        let this_stage_data = match msg
            .this_stage_data_opt
            .as_ref()
            .expect("always some at this level")
        {
            StageData::FinancialAndTechDetails(details) => details,
        };

        match Self::determine_transactions_count_limit_by_gas(
            &this_stage_data,
            qualified_payables.len(),
            logger,
        ) {
            Ok(None) => (),
            Ok(Some(limited_count_from_gas)) => {
                return Ok(Some(Adjustment::TransactionFeeDefinitelyOtherMaybe {
                    limited_count_from_gas,
                }))
            }
            Err(e) => return Err(e),
        };

        match Self::check_need_of_masq_balances_adjustment(
            logger,
            Either::Left(qualified_payables),
            this_stage_data
                .consuming_wallet_balances
                .masq_tokens_wei
                .as_u128(),
        ) {
            true => Ok(Some(Adjustment::MasqToken)),
            false => Ok(None),
        }
    }

    fn adjust_payments(
        &mut self,
        setup: AwaitedAdjustment,
        now: SystemTime,
        logger: &Logger, //TODO fix this later
    ) -> OutcomingPaymentsInstructions {
        let msg = setup.original_setup_msg;
        let qualified_payables: Vec<PayableAccount> = msg.qualified_payables;
        let response_skeleton_opt = msg.response_skeleton_opt;
        let current_stage_data = match msg.this_stage_data_opt.expectv("complete setup data") {
            StageData::FinancialAndTechDetails(details) => details,
        };
        let required_adjustment = setup.adjustment;

        self.set_up_new_inner(current_stage_data, required_adjustment, now);

        let debug_info_opt = self.logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|account| (account.wallet.clone(), account.balance_wei))
                .collect::<HashMap<Wallet, u128>>()
        });

        let adjusted_accounts = self.run_full_adjustment_procedure(qualified_payables, vec![]);

        debug!(
            self.logger,
            "{}",
            before_and_after_debug_msg(debug_info_opt.expectv("debug info"), &adjusted_accounts)
        );

        OutcomingPaymentsInstructions {
            accounts: adjusted_accounts,
            response_skeleton_opt,
        }
    }

    implement_as_any!();
}

const PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS: bool = true;
const COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS: bool = true;

const AGE_MAIN_EXPONENT: u32 = 3;
// divisor^(numerator/denominator)
const AGE_DIVISOR_EXP_IN_NUMERATOR: u32 = 3;
const AGE_MULTIPLIER: u128 = 150;
const AGE_DESC_MULTIPLIER_ARG_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_EXP: u32 = 2;
const AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER: u128 = 1_000;
const AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER: u128 = 10;
const AGE_DESC_MULTIPLIER_DIVISOR_EXP: u32 = 3;
// this parameter affects the steepness (sensitivity on increase in balance)
const BALANCE_LOG_2_ARG_DIVISOR: u128 = 33;
const BALANCE_TAIL_WEIGHT_MODULO_OPERAND: u128 = 1_000;
const BALANCE_TAIL_WEIGHT_EXPONENT: u32 = 2;
// represents 50%
const ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE: PercentageAccountInsignificance =
    PercentageAccountInsignificance {
        multiplier: 1,
        divisor: 2,
    };

// sets the minimal percentage of the original balance that must be
// proposed after the adjustment or the account will be eliminated for insignificance
#[derive(Debug, PartialEq, Eq)]
struct PercentageAccountInsignificance {
    // using integers means we have to represent accurate percentage
    // as set of two constants
    multiplier: u128,
    divisor: u128,
}

type CriterionFormula<'a> = Box<dyn FnMut((u128, PayableAccount)) -> (u128, PayableAccount) + 'a>;

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

    fn set_up_new_inner(
        &mut self,
        setup: FinancialAndTechDetails,
        required_adjustment: Adjustment,
        now: SystemTime,
    ) {
        let gas_limitation_opt = match required_adjustment {
            Adjustment::TransactionFeeDefinitelyOtherMaybe {
                limited_count_from_gas,
            } => Some(limited_count_from_gas),
            Adjustment::MasqToken => None,
        };
        let cw_masq_balance = setup.consuming_wallet_balances.masq_tokens_wei.as_u128();
        let inner = PaymentAdjusterInnerReal::new(now, gas_limitation_opt, cw_masq_balance);
        self.inner = Box::new(inner);
    }

    fn determine_transactions_count_limit_by_gas(
        tech_info: &FinancialAndTechDetails,
        required_transactions_count: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, AnalysisError> {
        let transaction_fee_required_per_transaction_in_major =
            u128::try_from(tech_info.estimated_gas_limit_per_transaction)
                .expectv("small number for gas limit")
                * u128::try_from(tech_info.desired_gas_price_gwei)
                    .expectv("small number for gas price");
        let tfrpt_in_minor: U256 = gwei_to_wei(transaction_fee_required_per_transaction_in_major);
        let available_balance_in_minor = tech_info.consuming_wallet_balances.gas_currency_wei;
        let limiting_max_possible_count = (available_balance_in_minor / tfrpt_in_minor).as_u128();
        if limiting_max_possible_count == 0 {
            Err(AnalysisError::BalanceBelowSingleTxFee {
                one_transaction_requirement: transaction_fee_required_per_transaction_in_major
                    as u64,
                cw_balance: wei_to_gwei(available_balance_in_minor),
            })
        } else if limiting_max_possible_count >= required_transactions_count as u128 {
            Ok(None)
        } else {
            let limiting_count = u16::try_from(limiting_max_possible_count)
                .expectv("small number for possible tx count");
            log_insufficient_transaction_fee_balance(
                logger,
                required_transactions_count,
                tech_info,
                limiting_count,
            );
            Ok(Some(limiting_count))
        }
    }

    fn check_need_of_masq_balances_adjustment(
        logger: &Logger,
        qualified_payables: Either<&[PayableAccount], &[(u128, PayableAccount)]>,
        consuming_wallet_balance_wei: u128,
    ) -> bool {
        let qualified_payables: Vec<&PayableAccount> = match qualified_payables {
            Either::Left(accounts) => accounts.iter().collect(),
            Either::Right(criteria_and_accounts) => criteria_and_accounts
                .iter()
                .map(|(_, account)| account)
                .collect(),
        };
        let required_masq_sum: u128 = sum_as(&qualified_payables, |account: &&PayableAccount| {
            account.balance_wei
        });

        if required_masq_sum <= consuming_wallet_balance_wei {
            false
        } else {
            log_adjustment_by_masq_required(
                logger,
                required_masq_sum,
                consuming_wallet_balance_wei,
            );
            true
        }
    }

    fn run_full_adjustment_procedure(
        &mut self,
        unresolved_qualified_accounts: Vec<PayableAccount>,
        resolved_qualified_accounts: Vec<PayableAccount>,
    ) -> Vec<PayableAccount> {
        diagnostics_collective("RESOLVED QUALIFIED ACCOUNTS:", &resolved_qualified_accounts);
        diagnostics_collective(
            "UNRESOLVED QUALIFIED ACCOUNTS:",
            &unresolved_qualified_accounts,
        );
        let accounts_with_zero_criteria =
            Self::initialize_zero_criteria(unresolved_qualified_accounts);
        let sorted_accounts_with_individual_criteria =
            self.apply_criteria(accounts_with_zero_criteria);

        self.run_adjustment_by_criteria_recursively(
            sorted_accounts_with_individual_criteria,
            resolved_qualified_accounts,
        )
    }

    fn run_adjustment_by_criteria_recursively(
        &mut self,
        sorted_accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        resolved_qualified_accounts: Vec<PayableAccount>,
    ) -> Vec<PayableAccount> {
        let adjustment_result: AdjustmentIterationSummary =
            match self.give_job_to_adjustment_workers(sorted_accounts_with_individual_criteria) {
                AdjustmentCompletion::Finished(accounts_adjusted) => return accounts_adjusted,
                AdjustmentCompletion::Continue(iteration_result) => iteration_result,
            };

        log_info_for_disqualified_accounts(&self.logger, &adjustment_result.disqualified_accounts);

        let adjusted_accounts = if adjustment_result.remaining_accounts.is_empty() {
            adjustment_result.decided_accounts
        } else {
            self.adjust_cw_balance_down_for_next_round(&adjustment_result.decided_accounts);
            return self.run_full_adjustment_procedure(
                adjustment_result.remaining_accounts,
                adjustment_result.decided_accounts,
            );
        };

        let adjusted_accounts_iter = adjusted_accounts.into_iter();
        let result: Vec<PayableAccount> = resolved_qualified_accounts
            .into_iter()
            .chain(adjusted_accounts_iter)
            .collect();
        diagnostics_collective("FINAL ADJUSTED ACCOUNTS:", &result);
        result
    }

    fn initialize_zero_criteria(
        qualified_payables: Vec<PayableAccount>,
    ) -> impl Iterator<Item = (u128, PayableAccount)> {
        fn just_zero_criteria_iterator(accounts_count: usize) -> impl Iterator<Item = u128> {
            let one_element = once(0_u128);
            let endlessly_repeated = one_element.into_iter().cycle();
            endlessly_repeated.take(accounts_count)
        }

        let accounts_count = qualified_payables.len();
        let criteria_iterator = just_zero_criteria_iterator(accounts_count);
        criteria_iterator.zip(qualified_payables.into_iter())
    }

    fn apply_criteria(
        &self,
        accounts_with_zero_criteria: impl Iterator<Item = (u128, PayableAccount)>,
    ) -> Vec<(u128, PayableAccount)> {
        //define individual criteria as closures to be used in a map()

        //caution: always remember to use checked math operations!

        let age_criterion_closure: CriterionFormula = Box::new(|(criteria_sum_so_far, account)| {
            let formula = |last_paid_timestamp: SystemTime| {
                let elapsed_secs: u64 = self
                    .inner
                    .now()
                    .duration_since(last_paid_timestamp)
                    .expect("time traveller")
                    .as_secs();
                let divisor = Self::compute_divisor(elapsed_secs);
                let log_multiplier = Self::compute_descending_multiplier(elapsed_secs, divisor);
                (elapsed_secs as u128)
                    .checked_pow(AGE_MAIN_EXPONENT)
                    .unwrap_or(u128::MAX) //TODO sensible and tested ????
                    .checked_div(divisor)
                    .expect("div overflow")
                    .checked_mul(log_multiplier)
                    .expect("mul overflow")
            };
            let criterion = formula(account.last_paid_timestamp);

            CriteriaWithDiagnostics {
                account,
                criterion,
                criteria_sum_so_far,
                diagnostics: DiagnosticsSetting {
                    label: "AGE",
                    diagnostics_adaptive_formula: |x: u128| {
                        let secs_in_the_past = Duration::from_secs(x as u64);
                        let approx_time_anchor = SystemTime::now()
                            .checked_sub(secs_in_the_past)
                            .expect("age formula characteristics blew up");
                        formula(approx_time_anchor)
                    },
                    singleton_ref: &AGE_SINGLETON,
                    bonds_safe_count_to_print: 10,
                },
            }
            .diagnose_and_sum()
        });
        let balance_criterion_closure: CriterionFormula =
            Box::new(|(criteria_sum_so_far, account)| {
                // constants used to keep the weights of balance and time balanced
                let formula = |balance_wei: u128| {
                    let binary_weight = log_2(Self::compute_binary_argument(balance_wei));
                    let multiplied = balance_wei
                        .checked_mul(binary_weight as u128)
                        .expect("mul overflow");
                    multiplied
                };
                let criterion = formula(account.balance_wei);

                CriteriaWithDiagnostics {
                    account,
                    criterion,
                    criteria_sum_so_far,
                    diagnostics: DiagnosticsSetting {
                        label: "BALANCE",
                        diagnostics_adaptive_formula: |x: u128| formula(x),
                        singleton_ref: &BALANCE_SINGLETON,
                        bonds_safe_count_to_print: diagnostics_x_axis_exponents_len(),
                    },
                }
                .diagnose_and_sum()
            });

        let weights_and_accounts = accounts_with_zero_criteria
            .map(age_criterion_closure)
            .map(balance_criterion_closure);

        sort_in_descendant_order_by_weights(weights_and_accounts)
    }

    //TODO this fn should later become property of the age criteria computing class e.g. "CriteriaComputer"
    fn compute_divisor(elapsed_sec: u64) -> u128 {
        (elapsed_sec as f64).sqrt().ceil() as u128
    }

    //TODO this fn should later become property of the age criteria computing class e.g. "CriteriaComputer"
    fn compute_descending_multiplier(elapsed_secs: u64, divisor: u128) -> u128 {
        let fast_growing_argument = (elapsed_secs as u128)
            .checked_pow(AGE_DESC_MULTIPLIER_ARG_EXP)
            .expect("pow blew up") as f64;
        let log = fast_growing_argument.ln();
        let log_stressed = (log as u128).pow(AGE_DESC_MULTIPLIER_LOG_STRESS_EXP)
            * AGE_DESC_MULTIPLIER_LOG_STRESS_MULTIPLIER;
        let final_log_multiplier = (log_stressed
            / (divisor * AGE_DESC_MULTIPLIER_DIVISOR_MULTIPLIER))
            .pow(AGE_DESC_MULTIPLIER_DIVISOR_EXP);
        x_or_1(final_log_multiplier)
    }

    //TODO this fn should later become property of the balance criteria computing class e.g. "CriteriaComputer"
    fn compute_binary_argument(balance_wei: u128) -> u128 {
        x_or_1(balance_wei / BALANCE_LOG_2_ARG_DIVISOR)
    }

    fn give_job_to_adjustment_workers(
        &mut self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentCompletion {
        match self.inner.gas_limitation_opt() {
            Some(limitation_by_gas) => {
                let weighted_accounts_cut_by_gas = cut_back_by_gas_count_limit(
                    accounts_with_individual_criteria,
                    limitation_by_gas,
                );
                match Self::check_need_of_masq_balances_adjustment(
                    &self.logger,
                    Either::Right(&weighted_accounts_cut_by_gas),
                    self.inner.cw_masq_balance(),
                ) {
                    true => AdjustmentCompletion::Continue(
                        self.handle_masq_token_adjustment(weighted_accounts_cut_by_gas),
                    ),
                    false => AdjustmentCompletion::Finished(rebuild_accounts(
                        weighted_accounts_cut_by_gas,
                    )),
                }
            }
            None => AdjustmentCompletion::Continue(
                self.handle_masq_token_adjustment(accounts_with_individual_criteria),
            ),
        }
    }

    fn handle_masq_token_adjustment(
        &mut self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentIterationSummary {
        //      let required_balance_total = Self::balance_total(&accounts_with_individual_criteria);
        let criteria_total = criteria_total(&accounts_with_individual_criteria);
        //TODO simplify this...one of these enums is probably redundant
        match self.recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria,
            criteria_total,
        ) {
            AccountsRecreationResult::AllAccountsCleanlyProcessed(decided_accounts) => {
                AdjustmentIterationSummary {
                    decided_accounts,
                    remaining_accounts: vec![],
                    disqualified_accounts: vec![],
                }
            }
            AccountsRecreationResult::InsignificantAccounts {
                disqualified,
                remaining,
            } => AdjustmentIterationSummary {
                decided_accounts: vec![],
                remaining_accounts: remaining,
                disqualified_accounts: disqualified,
            },
            AccountsRecreationResult::OutweighedAccounts {
                outweighed,
                remaining,
            } => AdjustmentIterationSummary {
                decided_accounts: outweighed,
                remaining_accounts: remaining,
                disqualified_accounts: vec![],
            },
        }
        // match self.handle_possibly_outweighed_accounts(
        //     accounts_with_individual_criteria,
        //     required_balance_total,
        //     criteria_total,
        // ) {
        //     Either::Left(accounts_with_individual_criteria) => {
        // self.perform_adjustment_and_determine_adjustment_iteration_result(
        //     accounts_with_individual_criteria,
        //     criteria_total,
        // )
        //     }
        //     Either::Right((outweighed, remaining)) => AdjustmentIterationSummary {
        //         decided_accounts: outweighed,
        //         remaining_accounts: remaining,
        //         disqualified_accounts: vec![],
        //     },
        // }
    }

    fn recreate_accounts_with_proportioned_balances(
        &mut self,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        criteria_total: u128,
    ) -> AccountsRecreationResult {
        let cw_masq_balance = self.inner.cw_masq_balance();
        let multiplication_coeff =
            compute_fractions_preventing_mul_coeff(cw_masq_balance, criteria_total);
        let cw_masq_balance_big_u256 = U256::from(cw_masq_balance);
        let criteria_total_u256 = U256::from(criteria_total);
        let multiplication_coeff_u256 = U256::from(multiplication_coeff);
        let proportional_piece_of_cw_balance = cw_masq_balance_big_u256
            .checked_mul(multiplication_coeff_u256)
            .unwrap() //TODO try killing this unwrap() in a test
            // TODO how to give the criteria some kind of ceiling? We don't want to exceed certain dangerous limit
            .checked_div(criteria_total_u256)
            .expect("div overflow");

        let accounts_with_unchecked_adjustment: Vec<_> = accounts_with_individual_criteria
            .into_iter()
            .map(|(criteria_sum, account)| {
                let proposed_adjusted_balance = (U256::from(criteria_sum)
                    * proportional_piece_of_cw_balance
                    / multiplication_coeff_u256)
                    .as_u128();

                diagnostics!(&account.wallet, "PROPOSED ADJUSTED BALANCE", || {
                    proposed_adjusted_balance.separate_with_commas()
                });
                AccountWithUncheckedAdjustment::new(
                    account,
                    proposed_adjusted_balance,
                    criteria_sum,
                )
            })
            .collect();

        let unchecked_for_disqualified =
            match self.handle_possibly_outweighed_account(accounts_with_unchecked_adjustment) {
                Left(still_not_fully_checked) => still_not_fully_checked,
                Right(with_some_outweighed) => return with_some_outweighed,
            };

        let finalized_accounts =
            match Self::consider_account_disqualification_from_percentage_insignificance(
                unchecked_for_disqualified,
            ) {
                Left(adjusted_accounts) => adjusted_accounts,
                Right(with_some_disqualified) => return with_some_disqualified,
            };

        AccountsRecreationResult::AllAccountsCleanlyProcessed(finalized_accounts)
    }

    fn consider_account_disqualification_from_percentage_insignificance(
        accounts_with_unchecked_adjustment: Vec<AccountWithUncheckedAdjustment>,
    ) -> Either<Vec<PayableAccount>, AccountsRecreationResult> {
        let wallets_of_accounts_to_disqualify: Vec<Wallet> = accounts_with_unchecked_adjustment
            .iter()
            .flat_map(|account_info| {
                let original_balance = account_info.original_account.balance_wei;
                let balance_at_the_edge = (ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier * original_balance * 10) //TODO what about these 10s?
                / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor;
                let proposed_adjusted_balance = account_info.proposed_adjusted_balance * 10;
                if proposed_adjusted_balance <= balance_at_the_edge {
                    diagnostics!(
                        &account_info.original_account.wallet,
                        "ACCOUNT DISQUALIFIED BASED ON THE PROPOSED BALANCE",
                        || format!(
                            "proposed adjusted balance: {}, qualification limit: {}",
                            proposed_adjusted_balance, balance_at_the_edge
                        )
                    );

                    Some(account_info.original_account.wallet.clone())
                } else {
                    None
                }
            })
            .collect();
        if wallets_of_accounts_to_disqualify.is_empty() {
            let finalized_accounts = AccountWithUncheckedAdjustment::finalize_collection(
                accounts_with_unchecked_adjustment,
                DecidedPayableAccountResolution::Finalize,
            );
            Left(finalized_accounts)
        } else {
            let (disqualified, remaining): (
                Vec<AccountWithUncheckedAdjustment>,
                Vec<AccountWithUncheckedAdjustment>,
            ) = accounts_with_unchecked_adjustment
                .into_iter()
                .partition(|account_info| {
                    wallets_of_accounts_to_disqualify
                        .contains(&account_info.original_account.wallet)
                });
            let debugable_disqualified = disqualified
                .into_iter()
                .map(|account_info| {
                    DisqualifiedPayableAccount::new(
                        account_info.original_account.wallet,
                        account_info.original_account.balance_wei,
                        account_info.proposed_adjusted_balance,
                    )
                })
                .collect();
            let remaining_stripped_off = remaining
                .into_iter()
                .map(|account_info| {
                    PayableAccount::from((account_info, DecidedPayableAccountResolution::Revert))
                })
                .collect();
            Right(AccountsRecreationResult::InsignificantAccounts {
                disqualified: debugable_disqualified,
                remaining: remaining_stripped_off,
            })
        }
    }

    fn handle_possibly_outweighed_account(
        &mut self,
        accounts_with_unchecked_adjustment: Vec<AccountWithUncheckedAdjustment>,
    ) -> Either<Vec<AccountWithUncheckedAdjustment>, AccountsRecreationResult> {
        let init: (
            Vec<(u128, PayableAccount)>,
            Vec<AccountWithUncheckedAdjustment>,
        ) = (vec![], vec![]);
        let (outweighed_with_already_made_criteria, passing_through) =
            accounts_with_unchecked_adjustment.into_iter().fold(
                init,
                |(mut outweighed, mut passing_through), account_info| {
                    if account_info.proposed_adjusted_balance
                        > account_info.original_account.balance_wei
                    //TODO test the operator against <=
                    {
                        diagnostics!(
                            &account_info.original_account.wallet,
                            "OUTWEIGHED ACCOUNT FOUND",
                            || format!(
                                "original balance: {}, proposed balance {}",
                                account_info.original_account.balance_wei,
                                account_info.proposed_adjusted_balance
                            )
                        );

                        let outweighed_record =
                            (account_info.criteria_sum, account_info.original_account);
                        outweighed.push(outweighed_record);
                        (outweighed, passing_through)
                    } else {
                        passing_through.push(account_info);
                        (outweighed, passing_through)
                    }
                },
            );

        if outweighed_with_already_made_criteria.is_empty() {
            Left(passing_through)
        } else {
            let clean_outweighed_accounts = self
                .adjust_balance_of_outweighed_accounts_to_cw_balance_if_necessary(
                    outweighed_with_already_made_criteria,
                );
            let remaining = AccountWithUncheckedAdjustment::finalize_collection(
                passing_through,
                DecidedPayableAccountResolution::Revert,
            );
            Right(AccountsRecreationResult::OutweighedAccounts {
                outweighed: clean_outweighed_accounts,
                remaining,
            })
        }

        //     None => Either::Left(account_with_individual_criteria),
        //     Some(wallets_of_outweighed) => Either::Right({
        //         eprintln!("wallets: {:?}", wallets_of_outweighed);
        //         debug!(
        //             self.logger,
        //             "Found outweighed accounts that will have to be readjusted ({:?}).",
        //             wallets_of_outweighed
        //         );
        //         let (unchecked_outweighed, remaining): (Vec<PayableAccount>, Vec<PayableAccount>) =
        //             account_with_individual_criteria
        //                 .into_iter()
        //                 .map(|(_, account)| account)
        //                 .partition(|account| wallets_of_outweighed.contains(&account.wallet));
        //
        //         (outweighed, remaining)
        //     }),
        // }
    }

    // fn check_for_outweighed_accounts(
    //     accounts_with_individual_criteria: &[(u128, PayableAccount)],
    //     required_balance_total: u128,
    //     criteria_total: u128,
    //     cw_masq_balance: u128, //TODO remove me after the experiment
    // ) -> Option<Vec<Wallet>> {
    //     let coeff = PaymentAdjusterReal::compute_fractions_preventing_mul_coeff(
    //         cw_masq_balance,
    //         criteria_total,
    //     );
    //     eprintln!("required bala {} coeff: {}", required_balance_total, coeff);
    //     let required_balance_total_for_safe_math = required_balance_total * 1000;
    //     let criteria_total_for_safe_math = criteria_total * 1000;
    //     let accounts_to_be_outweighed = accounts_with_individual_criteria
    //         .iter()
    //         .filter(|(criterion, account)| {
    //             //TODO maybe this part should have its own fn, where we could test closely the relation between the ration and the proposed balance
    //             let balance_ratio =
    //                 required_balance_total_for_safe_math / (account.balance_wei * 1000); //TODO also try giving each parameter a diff const in order to mitigate the sensitiveness
    //             let criterion_ratio = criteria_total_for_safe_math / (criterion * 1000); //TODO try moving with this constant and watch the impact on this check
    //                                                                                      // true means we would pay more than we were asked to pay at the beginning,
    //                                                                                      // this happens when the debt size is quite small but its age is large and
    //                                                                                      // plays the main factor
    //             // {
    //             //     let balance_fragment = cw_masq_balance
    //             //         .checked_mul(coeff)
    //             //         .unwrap()
    //             //         .checked_div(criteria_total)
    //             //         .unwrap();
    //             //     eprintln!(
    //             //         "account {} balance before {} and after {}",
    //             //         account.wallet,
    //             //         account.balance_wei.separate_with_commas(),
    //             //         ((balance_fragment * criterion).checked_div(coeff).unwrap())
    //             //             .separate_with_commas()
    //             //     );
    //             //     eprintln!(
    //             //         "this is current balance ratio: {}, this is current criterion ratio {}",
    //             //         balance_ratio, criterion_ratio
    //             //     )
    //             // };
    //             let is_highly_significant = balance_ratio > criterion_ratio;
    //             if is_highly_significant {
    //                 diagnostics(
    //                     &account.wallet,
    //                     "ACCOUNT PROPOSED WITH BALANCE HIGHER THAN THE ORIGIN ONE",
    //                     || {
    //                         format!(
    //                             "balance_ration ({}) > criterion_ration ({})",
    //                             balance_ratio, criterion_ratio
    //                         )
    //                     },
    //                 )
    //             }
    //
    //             is_highly_significant
    //         })
    //         .map(|(_, account)| account.wallet.clone())
    //         .collect::<Vec<Wallet>>();
    //     if !accounts_to_be_outweighed.is_empty() {
    //         Some(accounts_to_be_outweighed)
    //     } else {
    //         None
    //     }
    // }

    //TODO we probably want to drop the criteria before here where we've got no use for them........or maybe not...because the computation has always the same res
    fn adjust_balance_of_outweighed_accounts_to_cw_balance_if_necessary(
        &mut self,
        mut outweighed_with_criteria: Vec<(u128, PayableAccount)>,
    ) -> Vec<PayableAccount> {
        //TODO is this special condition for the single guy necessary??
        let cw_masq_balance = self.inner.cw_masq_balance();
        if outweighed_with_criteria.len() == 1 {
            let (_, only_account) = outweighed_with_criteria.remove(0);
            if only_account.balance_wei > cw_masq_balance {
                vec![PayableAccount {
                    balance_wei: cw_masq_balance,
                    ..only_account
                }]
            } else {
                vec![only_account]
            }
        } else if sum_as::<u128, _, _>(&outweighed_with_criteria, |(_, account)| {
            account.balance_wei
        }) > cw_masq_balance
        {
            self.run_adjustment_by_criteria_recursively(outweighed_with_criteria, vec![])
            //
            // if !adjustment_result.decided_accounts.is_empty() && adjustment_result.remaining_accounts.is_empty() && adjustment_result.disqualified_accounts.is_empty() {
            //     todo!()
            // } else {
            //     todo!("{:?}", adjustment_result)
            // }
        } else {
            todo!()
        }
    }

    fn adjust_cw_balance_down_for_next_round(&mut self, processed_outweighed: &[PayableAccount]) {
        let subtrahend_total: u128 = sum_as(processed_outweighed, |account| account.balance_wei);
        self.inner.lower_remaining_cw_balance(subtrahend_total);

        diagnostics!("LOWERED CW BALANCE", || format!(
            "lowered by {} to {}",
            subtrahend_total,
            self.inner.cw_masq_balance()
        ))
    }
}

#[derive(Debug)]
enum AccountsRecreationResult {
    AllAccountsCleanlyProcessed(Vec<PayableAccount>),
    InsignificantAccounts {
        disqualified: Vec<DisqualifiedPayableAccount>,
        remaining: Vec<PayableAccount>,
    },
    OutweighedAccounts {
        outweighed: Vec<PayableAccount>,
        remaining: Vec<PayableAccount>,
    },
}

#[derive(Debug)]
struct AdjustmentIterationSummary {
    decided_accounts: Vec<PayableAccount>,
    remaining_accounts: Vec<PayableAccount>,
    disqualified_accounts: Vec<DisqualifiedPayableAccount>,
}

//TODO rename???
#[derive(Clone, Copy)]
enum DecidedPayableAccountResolution {
    Finalize,
    Revert,
}

enum AdjustmentCompletion {
    Finished(Vec<PayableAccount>),
    Continue(AdjustmentIterationSummary),
}

impl
    From<(
        AccountWithUncheckedAdjustment,
        DecidedPayableAccountResolution,
    )> for PayableAccount
{
    fn from(
        (account_info, resolution): (
            AccountWithUncheckedAdjustment,
            DecidedPayableAccountResolution,
        ),
    ) -> Self {
        match resolution {
            DecidedPayableAccountResolution::Finalize => PayableAccount {
                balance_wei: account_info.proposed_adjusted_balance,
                ..account_info.original_account
            },
            DecidedPayableAccountResolution::Revert => account_info.original_account,
        }
    }
}

pub struct AccountWithUncheckedAdjustment {
    original_account: PayableAccount,
    proposed_adjusted_balance: u128,
    criteria_sum: u128,
}

impl AccountWithUncheckedAdjustment {
    fn new(
        original_account: PayableAccount,
        proposed_adjusted_balance: u128,
        criteria_sum: u128,
    ) -> Self {
        Self {
            original_account,
            proposed_adjusted_balance,
            criteria_sum,
        }
    }

    fn finalize_collection(
        account_infos: Vec<Self>,
        resolution: DecidedPayableAccountResolution,
    ) -> Vec<PayableAccount> {
        account_infos
            .into_iter()
            .map(|account_info| PayableAccount::from((account_info, resolution)))
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DisqualifiedPayableAccount {
    wallet: Wallet,
    proposed_adjusted_balance: u128,
    original_balance: u128,
}

impl DisqualifiedPayableAccount {
    fn new(wallet: Wallet, original_balance: u128, proposed_adjusted_balance: u128) -> Self {
        Self {
            wallet,
            proposed_adjusted_balance,
            original_balance,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Adjustment {
    MasqToken,
    TransactionFeeDefinitelyOtherMaybe { limited_count_from_gas: u16 },
}

#[derive(Clone, Copy)]
struct GasLimitationContext {
    limited_count_from_gas: u16,
    is_masq_token_insufficient: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {
    BalanceBelowSingleTxFee {
        one_transaction_requirement: u64,
        cw_balance: u64,
    },
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::auxiliary_fns::{
        balance_total, compute_fractions_preventing_mul_coeff, criteria_total, log_2,
    };
    use crate::accountant::payment_adjuster::diagnostics::EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS;
    use crate::accountant::payment_adjuster::inner::{
        PaymentAdjusterInnerNull, PaymentAdjusterInnerReal,
    };
    use crate::accountant::payment_adjuster::test_utils::{
        get_extreme_accounts, make_initialized_subject, MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
    };
    use crate::accountant::payment_adjuster::{
        AccountWithUncheckedAdjustment, AccountsRecreationResult, Adjustment, AnalysisError,
        DisqualifiedPayableAccount, PaymentAdjuster, PaymentAdjusterReal,
        PercentageAccountInsignificance, ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE,
        AGE_DIVISOR_EXP_IN_NUMERATOR, AGE_MAIN_EXPONENT, AGE_MULTIPLIER, BALANCE_LOG_2_ARG_DIVISOR,
        BALANCE_TAIL_WEIGHT_EXPONENT, COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS,
        PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS,
    };
    use crate::accountant::scanners::payable_scan_setup_msgs::{
        FinancialAndTechDetails, PayablePaymentSetup, StageData,
    };
    use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, wei_to_gwei, ResponseSkeleton};
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPaymentsInstructions,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Either::Left;
    use itertools::{Either, Itertools};
    use lazy_static::lazy_static;
    use masq_lib::constants::MASQ_TOTAL_SUPPLY;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::iter::once;
    use std::thread::current;
    use std::time::{Duration, SystemTime};
    use std::vec;
    use thousands::Separable;
    use web3::types::U256;

    fn make_payable_setup_msg_coming_from_blockchain_bridge(
        q_payables_gwei_and_cw_balance_gwei_opt: Option<(Vec<u64>, u64)>,
        gas_price_opt: Option<GasTestConditions>,
    ) -> PayablePaymentSetup {
        let (qualified_payables_gwei, consuming_wallet_masq_gwei) =
            q_payables_gwei_and_cw_balance_gwei_opt.unwrap_or((vec![1, 1], u64::MAX));

        let (
            desired_gas_price,
            number_of_payments,
            estimated_gas_limit_per_tx,
            cw_balance_gas_gwei,
        ) = match gas_price_opt {
            Some(conditions) => (
                conditions.desired_gas_price_gwei,
                conditions.number_of_payments,
                conditions.estimated_gas_limit_per_transaction,
                conditions.consuming_wallet_gas_gwei,
            ),
            None => (120, qualified_payables_gwei.len(), 55_000, u64::MAX),
        };

        let qualified_payables: Vec<_> = match number_of_payments != qualified_payables_gwei.len() {
            true => (0..number_of_payments)
                .map(|idx| make_payable_account(idx as u64))
                .collect(),
            false => qualified_payables_gwei
                .into_iter()
                .map(|balance| make_payable_account(balance))
                .collect(),
        };

        PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        gas_currency_wei: gwei_to_wei(cw_balance_gas_gwei),
                        masq_tokens_wei: gwei_to_wei(consuming_wallet_masq_gwei),
                    },
                    estimated_gas_limit_per_transaction: estimated_gas_limit_per_tx,
                    desired_gas_price_gwei: desired_gas_price,
                },
            )),
            response_skeleton_opt: None,
        }
    }

    struct GasTestConditions {
        desired_gas_price_gwei: u64,
        number_of_payments: usize,
        estimated_gas_limit_per_transaction: u64,
        consuming_wallet_gas_gwei: u64,
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS, false);
        assert_eq!(COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS, false);
        assert_eq!(AGE_MAIN_EXPONENT, 4);
        assert_eq!(AGE_DIVISOR_EXP_IN_NUMERATOR, 3);
        assert_eq!(AGE_MULTIPLIER, 10);
        assert_eq!(BALANCE_LOG_2_ARG_DIVISOR, 9);
        assert_eq!(
            ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE,
            PercentageAccountInsignificance {
                multiplier: 1,
                divisor: 2,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "Called the null implementation of the cw_masq_balance() method in PaymentAdjusterInner"
    )]
    fn payment_adjuster_new_is_created_with_inner_null() {
        let result = PaymentAdjusterReal::new();

        let _ = result.inner.cw_masq_balance();
    }

    #[test]
    fn search_for_indispensable_adjustment_negative_answer() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_negative_answer";
        let subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        //masq balance > payments
        let msg_1 =
            make_payable_setup_msg_coming_from_blockchain_bridge(Some((vec![85, 14], 100)), None);
        //masq balance = payments
        let msg_2 =
            make_payable_setup_msg_coming_from_blockchain_bridge(Some((vec![85, 15], 100)), None);
        //gas balance > payments
        let msg_3 = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(GasTestConditions {
                desired_gas_price_gwei: 111,
                number_of_payments: 5,
                estimated_gas_limit_per_transaction: 53_000,
                consuming_wallet_gas_gwei: (111 * 5 * 53_000) + 1,
            }),
        );
        //gas balance = payments
        let msg_4 = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(GasTestConditions {
                desired_gas_price_gwei: 100,
                number_of_payments: 6,
                estimated_gas_limit_per_transaction: 53_000,
                consuming_wallet_gas_gwei: 100 * 6 * 53_000,
            }),
        );

        [msg_1, msg_2, msg_3, msg_4].into_iter().for_each(|msg| {
            assert_eq!(
                subject.search_for_indispensable_adjustment(&msg, &logger),
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
        let subject = PaymentAdjusterReal::new();
        let msg =
            make_payable_setup_msg_coming_from_blockchain_bridge(Some((vec![85, 16], 100)), None);

        let result = subject.search_for_indispensable_adjustment(&msg, &logger);

        assert_eq!(result, Ok(Some(Adjustment::MasqToken)));
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Total of 101,000,000,000 \
        wei in MASQ was ordered while the consuming wallet held only 100,000,000,000 wei of the MASQ token. \
        Adjustment in their count or the amounts is required."));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue using services \
        of other Nodes and avoid delinquency bans you will need to put more funds into your consuming wallet."));
    }

    #[test]
    fn search_for_indispensable_adjustment_positive_for_gas() {
        init_test_logging();
        let test_name = "search_for_indispensable_adjustment_positive_for_gas";
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();
        let number_of_payments = 3;
        let msg = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(GasTestConditions {
                desired_gas_price_gwei: 100,
                number_of_payments,
                estimated_gas_limit_per_transaction: 55_000,
                consuming_wallet_gas_gwei: 100 * 3 * 55_000 - 1,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&msg, &logger);

        let expected_limiting_count = number_of_payments as u16 - 1;
        assert_eq!(
            result,
            Ok(Some(Adjustment::TransactionFeeDefinitelyOtherMaybe {
                limited_count_from_gas: expected_limiting_count
            }))
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Gas amount 18,446,744,073,709,551,615,000,000,000 wei \
        cannot cover anticipated fees from sending 3 transactions. Maximum is 2. \
        The payments need to be adjusted in their count."
        ));
        log_handler.exists_log_containing(&format!("INFO: {test_name}: In order to continue using services \
        of other Nodes and avoid delinquency bans you will need to put more funds into your consuming wallet."));
    }

    #[test]
    fn search_for_indispensable_adjustment_unable_to_pay_even_for_a_single_transaction_because_of_gas(
    ) {
        let subject = PaymentAdjusterReal::new();
        let number_of_payments = 3;
        let msg = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(GasTestConditions {
                desired_gas_price_gwei: 100,
                number_of_payments,
                estimated_gas_limit_per_transaction: 55_000,
                consuming_wallet_gas_gwei: 54_000 * 100,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&msg, &Logger::new("test"));

        assert_eq!(
            result,
            Err(AnalysisError::BalanceBelowSingleTxFee {
                one_transaction_requirement: 55_000 * 100,
                cw_balance: 54_000 * 100
            })
        );
    }

    #[test]
    fn consider_account_disqualification_from_percentage_insignificance_adheres_to_the_manifest_consts_of_insignificance(
    ) {
        let cw_masq_balance = 1_000_000;
        let mut subject = make_initialized_subject(SystemTime::now(), Some(cw_masq_balance), None);
        let account_balance = 1_000_000;
        let prepare_account = |n: u64| {
            let mut account = make_payable_account(n);
            account.balance_wei = account_balance;
            account
        };
        let payable_account_1 = prepare_account(1);
        let wallet_1 = payable_account_1.wallet.clone();
        let payable_account_2 = prepare_account(2);
        let wallet_2 = payable_account_2.wallet.clone();
        let payable_account_3 = prepare_account(3);
        let wallet_3 = payable_account_3.wallet.clone();
        const IRRELEVANT_CRITERIA_SUM: u128 = 1111;
        let edge = account_balance / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
            * ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier;
        let proposed_ok_balance = edge + 1;
        let account_info_1 = AccountWithUncheckedAdjustment::new(
            payable_account_1,
            proposed_ok_balance,
            IRRELEVANT_CRITERIA_SUM,
        );
        let proposed_bad_balance_because_equal = edge;
        let account_info_2 = AccountWithUncheckedAdjustment::new(
            payable_account_2,
            proposed_bad_balance_because_equal,
            IRRELEVANT_CRITERIA_SUM,
        );
        let proposed_bad_balance_because_smaller = edge - 1;
        let account_info_3 = AccountWithUncheckedAdjustment::new(
            payable_account_3,
            proposed_bad_balance_because_smaller,
            IRRELEVANT_CRITERIA_SUM,
        );
        let accounts_with_unchecked_adjustment =
            vec![account_info_1, account_info_2, account_info_3];

        let result =
            PaymentAdjusterReal::consider_account_disqualification_from_percentage_insignificance(
                accounts_with_unchecked_adjustment,
            )
            .right()
            .unwrap();

        let (disqualified, remaining) = match result {
            AccountsRecreationResult::InsignificantAccounts {
                disqualified,
                remaining,
            } => (disqualified, remaining),
            x => panic!(
                "we expected some disqualified accounts but got this: {:?}",
                x
            ),
        };
        let expected_disqualified_accounts = vec![wallet_2, wallet_3];
        disqualified.iter().for_each(|account_info| {
            assert!(expected_disqualified_accounts.contains(&account_info.wallet))
        });
        assert_eq!(remaining[0].wallet, wallet_1);
        assert_eq!(disqualified.len(), 2);
        assert_eq!(remaining.len(), 1);
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
        let zero_criteria_accounts =
            PaymentAdjusterReal::initialize_zero_criteria(qualified_payables);

        let weights_and_accounts = subject.apply_criteria(zero_criteria_accounts);

        let only_accounts = weights_and_accounts
            .iter()
            .map(|(_, account)| account)
            .collect::<Vec<&PayableAccount>>();
        assert_eq!(only_accounts, vec![&account_3, &account_1, &account_2])
    }

    #[test]
    fn compute_divisor_works() {
        let result: Vec<_> = [100, 81, 82, 80]
            .into_iter()
            .map(|secs| PaymentAdjusterReal::compute_divisor(secs))
            .collect();

        assert_eq!(result, vec![10, 9, 10, 9])
    }

    #[test]
    fn compute_descending_multiplier_works() {
        let result: Vec<_> = EXPONENTS_OF_10_AS_VALUES_FOR_X_AXIS
            .into_iter()
            .take(12)
            .map(|exp| 10_u64.pow(exp))
            .map(|seconds_elapsed| {
                let divisor = PaymentAdjusterReal::compute_divisor(seconds_elapsed);
                PaymentAdjusterReal::compute_descending_multiplier(seconds_elapsed, divisor)
            })
            .collect();

        assert_eq!(
            result,
            vec![
                64000000, 531441000, 147197952, 34012224, 4574296, 373248, 32768, 1728, 125, 1, 1,
                1
            ]
        )
    }

    #[test]
    fn compute_binary_argument_works() {
        let inputs = [
            1,
            BALANCE_LOG_2_ARG_DIVISOR - 1,
            BALANCE_LOG_2_ARG_DIVISOR,
            BALANCE_LOG_2_ARG_DIVISOR + 1,
            BALANCE_LOG_2_ARG_DIVISOR + 1000,
        ];

        let result: Vec<_> = inputs
            .into_iter()
            .map(|arg| PaymentAdjusterReal::compute_binary_argument(arg))
            .collect();

        assert_eq!(
            result,
            vec![
                1,
                1,
                1,
                1,
                (BALANCE_LOG_2_ARG_DIVISOR + 1000) / BALANCE_LOG_2_ARG_DIVISOR
            ]
        )
    }

    #[test]
    fn small_debt_with_extreme_age_is_paid_outweighed_but_not_with_more_money_than_required() {
        const SAFETY_MULTIPLIER: u128 = 1_000_000_000_000_000;
        let now = SystemTime::now();
        let cw_masq_balance = 1_500_000_000_000_u128 - 25_000_000;
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
        let logger = Logger::new("test");
        let qualified_payables = vec![account_1, account_2.clone()];

        let result = subject.run_full_adjustment_procedure(qualified_payables.clone(), vec![]);

        //first a presentation of why this test is important
        let zero_criteria_accounts =
            PaymentAdjusterReal::initialize_zero_criteria(qualified_payables);
        let criteria_and_accounts = subject.apply_criteria(zero_criteria_accounts);
        let criteria_total = criteria_total(&criteria_and_accounts);
        let account_2_criterion = criteria_and_accounts[1].0;
        let cw_balance_fractional_safe = cw_masq_balance * SAFETY_MULTIPLIER;
        let proportional_piece_of_cw_balance = cw_balance_fractional_safe / criteria_total;
        let proposed_adjusted_balance_2 =
            (account_2_criterion * proportional_piece_of_cw_balance) / SAFETY_MULTIPLIER;
        //the weight of the second account grew very progressively due to the effect of the long age;
        //consequences are that redistributing the new balances according to the computed weights would've attributed
        //the second account with more tokens to pay than it'd had before the test started;
        //to prevent it, we've got a rule that no account can ever demand more than its 100%
        assert!(proposed_adjusted_balance_2 > 10 * balance_2, "we expected the proposed balance much bigger than the original which is {} but it was {}", balance_2, proposed_adjusted_balance_2);
        assert_eq!(
            result,
            vec![
                account_2, //outweighed account takes the first place
                PayableAccount {
                    wallet: make_wallet("blah"),
                    //precisely should be 1_500_000_000_000 - (25_000_000 - 25_000_000) but close enough
                    balance_wei: 1_499_949_999_252,
                    last_paid_timestamp: last_paid_timestamp_1,
                    pending_payable_opt: None,
                },
            ]
        );
    }

    #[test]
    fn an_accounts_never_becomes_outweighed_while_cw_balance_is_less_than_its_balance_because_disqualified_accounts_come_considered_first(
    ) {
        //NOTE that the same applies for more than one outweighed accounts that would originally request more than the cw balance,
        //therefore there is no such a test either
        const SECONDS_IN_3_DAYS: u64 = 259_200;
        let test_name =
            "only_outweighed_account_gets_its_balance_cut_back_if_cw_balance_is_even_less";
        let now = SystemTime::now();
        let consuming_wallet_balance = 1_000_000_000_000_u128 - 1;
        let mut subject = make_initialized_subject(
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
        let accounts_with_zero_criteria = PaymentAdjusterReal::initialize_zero_criteria(vec![
            account_1.clone(),
            account_2.clone(),
        ]);
        let accounts_with_individual_criteria = subject.apply_criteria(accounts_with_zero_criteria);
        let required_balance_total = balance_total(&accounts_with_individual_criteria);
        let criteria_total = criteria_total(&accounts_with_individual_criteria);

        let result = subject.recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria.clone(),
            criteria_total,
        );

        let (disqualified, remaining) = match result {
            AccountsRecreationResult::InsignificantAccounts {
                disqualified,
                remaining,
            } => (disqualified, remaining),
            x => panic!("we expected to see a disqualified account but got: {:?}", x),
        };
        let expected_disqualified_account = DisqualifiedPayableAccount {
            wallet: wallet_2,
            proposed_adjusted_balance: 49_201,
            original_balance: balance_2,
        };
        assert_eq!(disqualified, vec![expected_disqualified_account]);
        assert_eq!(remaining, vec![account_1])
    }

    #[test]
    fn trying_to_go_through_the_complete_process_under_the_extremest_debt_conditions_without_getting_killed(
    ) {
        init_test_logging();
        let test_name = "trying_to_go_through_the_complete_process_under_the_extremest_debt_conditions_without_getting_killed";
        let now = SystemTime::now();
        //each of 3 accounts contains half of the full supply and a 10-years-old debt which generates extremely big numbers in the criteria
        let qualified_payables = {
            let mut accounts = get_extreme_accounts(
                Either::Left((vec![120, 120, 120], *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR)),
                now,
            );
            accounts
                .iter_mut()
                .for_each(|account| account.balance_wei = account.balance_wei / 2);
            accounts
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
                        gas_currency_wei: U256::from(u32::MAX),
                        masq_tokens_wei: U256::from(cw_masq_balance),
                    },
                    estimated_gas_limit_per_transaction: 70_000,
                    desired_gas_price_gwei: 120,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        //because the proposed final balances all all way lower than (at least) the half of the original balances
        assert_eq!(result.accounts, vec![]);
        let expected_log = |wallet: &str| {
            format!("INFO: {test_name}: Consuming wallet low in MASQ balance. Recently qualified \
            payable for wallet {} will not be paid as the consuming wallet handles to provide only 333 wei \
            which is not at least more than a half of the original debt {}", wallet,
                    (*MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR / 2).separate_with_commas())
        };
        let log_handler = TestLogHandler::new();
        log_handler
            .exists_log_containing(&expected_log("0x000000000000000000000000000000626c616830"));
        log_handler
            .exists_log_containing(&expected_log("0x000000000000000000000000000000626c616831"));
        log_handler
            .exists_log_containing(&expected_log("0x000000000000000000000000000000626c616832"));
    }

    #[test]
    fn adjust_payments_when_the_initial_transaction_count_evens_the_final_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_the_initial_transaction_count_evens_the_final_count";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 4_444_444_444_444_444_444,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1_234)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 6_666_666_666_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 60_000_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(50_000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let accounts_sum: u128 =
            4_444_444_444_444_444_444 + 6_666_666_666_000_000_000 + 60_000_000_000_000_000; //= 1_000_022_000_000_444_444
        let consuming_wallet_masq_balance_wei = U256::from(accounts_sum - 70_000_000_000_000_000);
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        gas_currency_wei: U256::from(u32::MAX),
                        masq_tokens_wei: consuming_wallet_masq_balance_wei,
                    },
                    estimated_gas_limit_per_transaction: 70_000,
                    desired_gas_price_gwei: 120,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken, //this means the computation happens regardless the actual gas balance limitations
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        let expected_criteria_computation_output = emulation_of_the_actual_adjustment_algorithm(
            account_1,
            account_2,
            Some(account_3),
            consuming_wallet_masq_balance_wei.as_u128(),
            now,
        );
        assert_eq!(
            result,
            OutcomingPaymentsInstructions {
                accounts: expected_criteria_computation_output,
                response_skeleton_opt: None
            }
        );
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Account wallet                             Balance wei
|
|Adjusted payables                          Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 6666666666000000000
|                                           6627452261727177476
|0x0000000000000000000000000000000000616263 4444444444444444444
|                                           4418301511592311819
|0x000000000000000000000000000000000067686b 60000000000000000
|                                           55357206066732915"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn adjust_payments_when_only_gas_limits_the_final_transaction_count_and_masq_will_do_after_the_gas_cut(
    ) {
        init_test_logging();
        let test_name = "adjust_payments_when_only_gas_limits_the_final_transaction_count_and_masq_will_do_after_the_gas_cut";
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
        subject.logger = Logger::new(test_name);
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        gas_currency_wei: U256::from(5_544_000_000_000_000_u128 - 1),
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_wei: U256::from(10_u128.pow(22)),
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_gas_price_gwei: 24,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::TransactionFeeDefinitelyOtherMaybe {
                limited_count_from_gas: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        assert_eq!(
            result,
            OutcomingPaymentsInstructions {
                accounts: vec![account_2, account_3],
                response_skeleton_opt: None
            }
        );
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Account wallet                             Balance wei
|
|Adjusted payables                          Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000646566 333000000000000
|                                           333000000000000
|0x000000000000000000000000000000000067686b 222000000000000
|                                           222000000000000
|
|Ignored minor payables                     Original
|
|0x0000000000000000000000000000000000616263 111000000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    #[test]
    fn adjust_payments_when_only_masq_token_limits_the_final_transaction_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_only_masq_token_limits_the_final_transaction_count";
        let now = SystemTime::now();
        let wallet_1 = make_wallet("def");
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: 333_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(12000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_2 = make_wallet("abc");
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: 111_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(8000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghk");
        let balance_3 = 600_000_000;
        let account_3 = PayableAccount {
            wallet: wallet_3.clone(),
            balance_wei: balance_3,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let mut subject = PaymentAdjusterReal::new();
        subject.logger = Logger::new(test_name);
        let consuming_wallet_masq_balance_wei = U256::from(333_000_000_000_u64 + 50_000_000_000);
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        gas_currency_wei: U256::from(5_000_000_000_000_000_000_000_000_u128),
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_wei: consuming_wallet_masq_balance_wei,
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_gas_price_gwei: 24,
                },
            )),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234,
            }),
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        let expected_accounts_first_iteration = emulation_of_the_actual_adjustment_algorithm(
            account_1.clone(),
            account_2.clone(),
            Some(account_3),
            consuming_wallet_masq_balance_wei.as_u128(),
            now,
        );
        let account_3_adjusted_balance = expected_accounts_first_iteration
            .iter()
            .find(|account| account.wallet == wallet_3)
            .unwrap()
            .balance_wei;
        let minimum_allowed = ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier * balance_3 * 10
            / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor;
        assert!(
            account_3_adjusted_balance * 10 < minimum_allowed,
            "balance for account 3 after adjustment from the first iteration is {} but we need it \
            smaller than {} to exercise what happens if the proposed balance is smaller than half \
            the original one",
            account_3_adjusted_balance.separate_with_commas(),
            minimum_allowed.separate_with_commas()
        );
        let expected_accounts = emulation_of_the_actual_adjustment_algorithm(
            account_1,
            account_2,
            None,
            consuming_wallet_masq_balance_wei.as_u128(),
            now,
        );
        let wallets_of_final_accounts = result
            .accounts
            .iter()
            .map(|account| account.wallet.clone())
            .collect::<Vec<Wallet>>();
        assert_eq!(wallets_of_final_accounts, vec![wallet_1, wallet_2]);
        assert_eq!(result.accounts, expected_accounts);
        assert_eq!(
            result.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 111,
                context_id: 234
            })
        );
        TestLogHandler::new().exists_log_containing(&format!("INFO: {test_name}: Consuming wallet \
        low in MASQ balance. Recently qualified payable for wallet 0x00000000000000000000000000000\
        0000067686b will not be paid as the consuming wallet handles to provide only 56,554,286 wei \
        which is not at least more than a half of the original debt 600,000,000"));
    }

    fn test_competitive_accounts(
        test_name_with_unique_description: &str,
        consuming_wallet_balance: u128,
        wallet_1: &Wallet,
        wallet_2: &Wallet,
        balance_account_1: u128,
        balance_account_2: u128,
        age_secs_account_1: u64,
        age_secs_account_2: u64,
    ) -> Vec<PayableAccount> {
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: wallet_1.clone(),
            balance_wei: balance_account_1,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(age_secs_account_1))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: wallet_2.clone(),
            balance_wei: balance_account_2,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(age_secs_account_2))
                .unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone()];
        let mut subject = PaymentAdjusterReal::new();
        let consuming_wallet_masq_balance_wei = U256::from(consuming_wallet_balance);
        let setup_msg = PayablePaymentSetup {
            qualified_payables,
            this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
                FinancialAndTechDetails {
                    consuming_wallet_balances: ConsumingWalletBalances {
                        gas_currency_wei: U256::from(u128::MAX),
                        masq_tokens_wei: consuming_wallet_masq_balance_wei,
                    },
                    estimated_gas_limit_per_transaction: 55_000,
                    desired_gas_price_gwei: 150,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::MasqToken,
        };

        subject
            .adjust_payments(
                adjustment_setup,
                now,
                &Logger::new(test_name_with_unique_description),
            )
            .accounts
    }

    //TODO write this test for balances under 1M and above
    #[test]
    fn adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account() {
        // accounts in this test are evenly significant and so one cannot compete another,
        // yet there is not enough balance to pay the minimum required which is a half of each
        // thus we conclude none can be paid
        fn merge_test_name_and_study_description(test_name: &str, description: &str) -> String {
            format!("{}/{}", test_name, description)
        }
        let test_name = "adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account";
        let consuming_wallet_balance = 100_000_000_000_000_u128 - 1;
        let wallet_1 = make_wallet("abcd");
        let wallet_2 = make_wallet("cdef");
        let balance_account_1 = 100_000_000_000_000;
        let balance_account_2 = 100_000_000_000_000;
        let age_account_1 = 12000;
        let age_account_2 = 12000;
        let first_scenario_name = merge_test_name_and_study_description(test_name, "when_equal");

        // scenario A
        let result = test_competitive_accounts(
            &first_scenario_name,
            consuming_wallet_balance,
            //TODO many args in these tests are always the same...refactor
            &wallet_1,
            &wallet_2,
            balance_account_1,
            balance_account_2,
            age_account_1,
            age_account_2,
        );

        assert_eq!(result, vec![]);
        // scenario B
        const TOLERATED_MAXIMAL_INEFFECTIVE_BALANCE_GAP_HALVED: u128 = 5_000_000;
        let second_scenario_name =
            merge_test_name_and_study_description(test_name, "first_heavier_by_balance");

        let result = test_competitive_accounts(
            &second_scenario_name,
            consuming_wallet_balance,
            &wallet_1,
            &wallet_2,
            balance_account_1 + TOLERATED_MAXIMAL_INEFFECTIVE_BALANCE_GAP_HALVED,
            balance_account_2 - TOLERATED_MAXIMAL_INEFFECTIVE_BALANCE_GAP_HALVED,
            age_account_1,
            age_account_2,
        );

        assert_eq!(result[0].wallet, wallet_1);
        assert_eq!(result.len(), 1);
        // scenario C
        const TOLERATED_MAXIMAL_INEFFECTIVE_AGE_GAP_SEC_HALVED: u64 = 30;
        let third_scenario_name =
            merge_test_name_and_study_description(test_name, "second_heavier_by_age");

        let result = test_competitive_accounts(
            &third_scenario_name,
            consuming_wallet_balance,
            &wallet_1,
            &wallet_2,
            balance_account_1,
            balance_account_2,
            age_account_1 - TOLERATED_MAXIMAL_INEFFECTIVE_AGE_GAP_SEC_HALVED,
            age_account_2 + TOLERATED_MAXIMAL_INEFFECTIVE_AGE_GAP_SEC_HALVED,
        );

        assert_eq!(result[0].wallet, wallet_2);
        assert_eq!(result.len(), 1)
    }

    //TODO do I really want to delete this test? Why? I probably don't
    // #[test]
    // fn adjust_payments_when_both_parameters_must_be_treated_but_masq_doesnt_cut_down_any_account_it_just_adjusts_the_balances(
    // ) {
    //     init_test_logging();
    //     let test_name = "adjust_payments_when_gas_limits_the_final_transaction_count";
    //     let now = SystemTime::now();
    //     let account_1 = PayableAccount {
    //         wallet: make_wallet("abc"),
    //         balance_wei: 111_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let account_2 = PayableAccount {
    //         wallet: make_wallet("def"),
    //         balance_wei: 333_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let account_3 = PayableAccount {
    //         wallet: make_wallet("ghk"),
    //         balance_wei: 222_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
    //     let subject = PaymentAdjusterReal::new();
    //     let consuming_wallet_masq_balance = 111_000_000_000_000_u128 + 333_000_000_000_000;
    //     let setup_msg = PayablePaymentSetup {
    //         qualified_payables,
    //         this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
    //             FinancialAndTechDetails {
    //                 consuming_wallet_balances: ConsumingWalletBalances {
    //                     gas_currency_wei: U256::from(5_544_000_000_000_000_u128 - 1),
    //                     //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
    //                     masq_tokens_wei: U256::from(consuming_wallet_masq_balance),
    //                 },
    //                 estimated_gas_limit_per_transaction: 77_000,
    //                 desired_gas_price_gwei: 24,
    //             },
    //         )),
    //         response_skeleton_opt: None,
    //     };
    //     let adjustment_setup = AwaitedAdjustment {
    //         original_setup_msg: setup_msg,
    //         adjustment: Adjustment::Both {
    //             limited_count_from_gas: 2,
    //         },
    //     };
    //
    //     let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));
    //
    //     let expected_accounts = emulation_of_the_actual_adjustment_algorithm(
    //         account_2,
    //         account_3,
    //         None,
    //         consuming_wallet_masq_balance,
    //         now,
    //     );
    //     assert_eq!(
    //         result,
    //         OutcomingPaymentsInstructions {
    //             accounts: expected_accounts,
    //             response_skeleton_opt: None
    //         }
    //     );
    // }

    //TODO do I really want to delete this test? Why?
    // #[test]
    // fn adjust_payments_when_both_parameters_are_supposed_to_be_treated_but_masq_will_do_after_the_gas_cut(
    // ) {
    //     init_test_logging();
    //     let test_name = "adjust_payments_when_both_parameters_are_supposed_to_be_treated_but_masq_will_do_after_the_gas_cut";
    //     let now = SystemTime::now();
    //     let account_1 = PayableAccount {
    //         wallet: make_wallet("abc"),
    //         balance_wei: 111_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let account_2 = PayableAccount {
    //         wallet: make_wallet("def"),
    //         balance_wei: 333_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(4444)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let account_3 = PayableAccount {
    //         wallet: make_wallet("ghk"),
    //         balance_wei: 222_000_000_000_000,
    //         last_paid_timestamp: now.checked_sub(Duration::from_secs(5555)).unwrap(),
    //         pending_payable_opt: None,
    //     };
    //     let qualified_payables = vec![account_1, account_2.clone(), account_3.clone()];
    //     let subject = PaymentAdjusterReal::new();
    //     let consuming_wallet_masq_balance = 333_000_000_000_000_u128 + 222_000_000_000_000 + 1;
    //     let setup_msg = PayablePaymentSetup {
    //         qualified_payables,
    //         this_stage_data_opt: Some(StageData::FinancialAndTechDetails(
    //             FinancialAndTechDetails {
    //                 consuming_wallet_balances: ConsumingWalletBalances {
    //                     gas_currency_wei: U256::from(5_544_000_000_000_000_u128 - 1),
    //                     //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
    //                     masq_tokens_wei: U256::from(consuming_wallet_masq_balance),
    //                 },
    //                 estimated_gas_limit_per_transaction: 77_000,
    //                 desired_gas_price_gwei: 24,
    //             },
    //         )),
    //         response_skeleton_opt: None,
    //     };
    //     let adjustment_setup = AwaitedAdjustment {
    //         original_setup_msg: setup_msg,
    //         adjustment: Adjustment::Both {
    //             limited_count_from_gas: 2,
    //         },
    //     };
    //
    //     let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));
    //
    //     assert_eq!(
    //         result,
    //         OutcomingPaymentsInstructions {
    //             accounts: vec![account_2, account_3],
    //             response_skeleton_opt: None
    //         }
    //     );
    // }

    #[test]
    fn adjust_payments_when_masq_as_well_as_gas_will_limit_the_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_masq_as_well_as_gas_will_limit_the_count";
        let now = SystemTime::now();
        //thrown away as the second one because of its insignificance (proposed adjusted balance is smaller than half the original)
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 10_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        //thrown away as the first one because of gas
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 55_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghk");
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
                        gas_currency_wei: U256::from(5_544_000_000_000_000_u128 - 1),
                        //gas amount to spent = 3 * 77_000 * 24 [gwei] = 5_544_000_000_000_000 wei
                        masq_tokens_wei: U256::from(consuming_wallet_masq_balance),
                    },
                    estimated_gas_limit_per_transaction: 77_000,
                    desired_gas_price_gwei: 24,
                },
            )),
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitedAdjustment {
            original_setup_msg: setup_msg,
            adjustment: Adjustment::TransactionFeeDefinitelyOtherMaybe {
                limited_count_from_gas: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.response_skeleton_opt, None);
        let only_account = &result.accounts[0];
        assert_eq!(&only_account.wallet, &wallet_3);
        assert!(
            ((300_000_000_000_000 * 1000) / 1001) <= only_account.balance_wei
                && only_account.balance_wei <= 300_000_000_000_000
        );
        assert_eq!(only_account.last_paid_timestamp, last_paid_timestamp_3);
        assert_eq!(only_account.pending_payable_opt, None);

        //TODO if there is the only account remaining why don't we use the exact value...just the original balance..we would fit easily
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Account wallet                             Balance wei
|
|Adjusted payables                          Original
|                                           Adjusted
|
|0x000000000000000000000000000000000067686b 333000000000000
|                                           299999993982547
|
|Ignored minor payables                     Original
|
|0x0000000000000000000000000000000000616263 10000000000000
|0x0000000000000000000000000000000000646566 55000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    fn secs_elapsed(timestamp: SystemTime, now: SystemTime) -> u128 {
        now.duration_since(timestamp).unwrap().as_secs() as u128
    }

    fn emulation_of_the_actual_adjustment_algorithm(
        account_1: PayableAccount,
        account_2: PayableAccount,
        account_3_opt: Option<PayableAccount>,
        consuming_wallet_masq_balance_wei: u128,
        now: SystemTime,
    ) -> Vec<PayableAccount> {
        let accounts = vec![
            Some(account_1.clone()),
            Some(account_2.clone()),
            account_3_opt.clone(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let age_criteria = accounts
            .iter()
            .map(|account| {
                let elapsed = secs_elapsed(account.last_paid_timestamp, now);
                let divisor =
                    (((elapsed as f64).sqrt().ceil()) as u128).pow(AGE_DIVISOR_EXP_IN_NUMERATOR);
                elapsed.pow(AGE_MAIN_EXPONENT) * AGE_MULTIPLIER / divisor
            })
            .collect();
        let balance_criteria = accounts
            .iter()
            .map(|account| {
                let balance = account.balance_wei;
                let significance = log_2(balance / BALANCE_LOG_2_ARG_DIVISOR) as u128;
                balance * significance
            } as u128)
            .collect();

        let final_criteria = vec![age_criteria, balance_criteria].into_iter().fold(
            vec![0, 0, 0],
            |acc: Vec<u128>, current: Vec<u128>| {
                acc.into_iter()
                    .zip(current.into_iter())
                    .map(|(partial_acc, partial_current)| partial_acc + partial_current)
                    .collect()
            },
        );
        let final_criteria_sum = final_criteria.iter().sum::<u128>();
        let multiplication_coeff = compute_fractions_preventing_mul_coeff(
            consuming_wallet_masq_balance_wei,
            final_criteria_sum,
        );
        let in_ratio_fragment_of_available_balance = consuming_wallet_masq_balance_wei
            .checked_mul(multiplication_coeff)
            .unwrap()
            .checked_div(final_criteria_sum)
            .unwrap();
        let balanced_portions = final_criteria
            .iter()
            .map(|criterion| {
                in_ratio_fragment_of_available_balance * criterion / multiplication_coeff
            })
            .collect::<Vec<u128>>();
        let new_total_amount_to_pay = balanced_portions.iter().sum::<u128>();
        assert!(new_total_amount_to_pay <= consuming_wallet_masq_balance_wei);
        assert!(
            new_total_amount_to_pay >= (consuming_wallet_masq_balance_wei * 100) / 102,
            "new total amount to pay: {}, consuming wallet masq balance: {}",
            new_total_amount_to_pay,
            consuming_wallet_masq_balance_wei
        );
        let mut account_1_adjusted = account_1;
        account_1_adjusted.balance_wei = balanced_portions[0];
        let mut account_2_adjusted = account_2;
        account_2_adjusted.balance_wei = balanced_portions[1];
        let account_3_adjusted_opt = {
            match account_3_opt {
                Some(mut account) => Some({
                    account.balance_wei = balanced_portions[2];
                    account
                }),
                None => None,
            }
        };

        vec![
            Some((final_criteria[0], account_1_adjusted)),
            Some((final_criteria[1], account_2_adjusted)),
            match account_3_adjusted_opt {
                Some(account) => Some((final_criteria[2], account)),
                None => None,
            },
        ]
        .into_iter()
        .flatten()
        .sorted_by(|(criterion_a, _), (criterion_b, _)| Ord::cmp(&criterion_b, &criterion_a))
        .map(|(_, account)| account)
        .collect()
    }

    fn compute_expected_balanced_portions_from_criteria(
        final_criteria: Vec<u128>,
        consuming_wallet_masq_balance_wei: u128,
    ) -> Vec<u128> {
        let final_criteria_sum = final_criteria.iter().sum::<u128>();
        let multiplication_coeff = compute_fractions_preventing_mul_coeff(
            consuming_wallet_masq_balance_wei,
            final_criteria_sum,
        );
        let in_ratio_fragment_of_available_balance = consuming_wallet_masq_balance_wei
            .checked_mul(multiplication_coeff)
            .unwrap()
            .checked_div(final_criteria_sum)
            .unwrap();
        let new_balanced_portions = final_criteria
            .iter()
            .map(|criterion| {
                in_ratio_fragment_of_available_balance * criterion / multiplication_coeff
            })
            .collect::<Vec<u128>>();
        let new_total_amount_to_pay = new_balanced_portions.iter().sum::<u128>();
        assert!(new_total_amount_to_pay <= consuming_wallet_masq_balance_wei);
        assert!(
            new_total_amount_to_pay >= (consuming_wallet_masq_balance_wei * 100) / 102,
            "new total amount to pay: {}, consuming wallet masq balance: {}",
            new_total_amount_to_pay,
            consuming_wallet_masq_balance_wei
        );
        new_balanced_portions
    }
}
