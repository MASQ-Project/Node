// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod diagnostics;
mod log_functions;

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::diagnostics::{
    diagnostics, diagnostics_collective, FinalizationAndDiagnostics, AGE_SINGLETON,
    BALANCE_SINGLETON,
};
use crate::accountant::payment_adjuster::log_functions::{
    before_and_after_debug_msg, log_adjustment_by_masq_required,
    log_info_for_disqualified_accounts, log_insufficient_transaction_fee_balance,
};
use crate::accountant::scanners::payable_scan_setup_msgs::{
    FinancialAndTechDetails, PayablePaymentSetup, StageData,
};
use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
use crate::accountant::{gwei_to_wei, wei_to_gwei};
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, OutcomingPaymentsInstructions};
use crate::sub_lib::wallet::Wallet;
use itertools::{Either, Itertools};
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
        &self,
        setup: AwaitedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPaymentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

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
                return Ok(Some(Adjustment::TransactionFeeFirstLaterMaybeMasq {
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
        &self,
        setup: AwaitedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPaymentsInstructions {
        let msg = setup.original_setup_msg;
        let current_stage_data = match msg.this_stage_data_opt.expectv("complete setup data") {
            StageData::FinancialAndTechDetails(details) => details,
        };
        let qualified_payables: Vec<PayableAccount> = msg.qualified_payables;

        let gas_limitation_opt = match setup.adjustment {
            Adjustment::TransactionFeeFirstLaterMaybeMasq {
                limited_count_from_gas,
            } => Some(limited_count_from_gas),
            Adjustment::MasqToken => None,
        };

        let debug_info_opt = logger.debug_enabled().then(|| {
            qualified_payables
                .iter()
                .map(|account| (account.wallet.clone(), account.balance_wei))
                .collect::<HashMap<Wallet, u128>>()
        });

        let adjusted_accounts = Self::run_recursively(
            vec![],
            qualified_payables,
            current_stage_data,
            gas_limitation_opt,
            now,
            logger,
        );

        debug!(
            logger,
            "{}",
            before_and_after_debug_msg(debug_info_opt.expectv("debug info"), &adjusted_accounts)
        );

        OutcomingPaymentsInstructions {
            accounts: adjusted_accounts,
            response_skeleton_opt: msg.response_skeleton_opt,
        }
    }

    implement_as_any!();
}

impl Default for PaymentAdjusterReal {
    fn default() -> Self {
        Self::new()
    }
}

const PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS: bool = true;
const COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS: bool = false;

const AGE_EXPONENT: u32 = 4;
const AGE_MULTIPLIER: u128 = 10;
// this parameter affects the steepness (sensitivity on increase in balance)
const BALANCE_LOG_2_BASE_MULTIPLIER: u128 = 9;
// this parameter affects proportion against the different criteria class
const BALANCE_OUTER_MULTIPLIER: u128 = 2;
const BALANCE_TAIL_WEIGHT_MASK: u128 = 0xFFF;
const BALANCE_TAIL_WEIGHT_EXPONENT: u32 = 2;
const BALANCE_TAIL_WEIGHT_MULTIPLIER: u128 = 3;
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

//TODO think about splitting this file into a folder of files

type CriterionFormula<'a> = Box<dyn FnMut((u128, PayableAccount)) -> (u128, PayableAccount) + 'a>;

impl PaymentAdjusterReal {
    pub fn new() -> Self {
        Self {}
    }

    fn sum_as<N, T, F>(collection: &[T], arranger: F) -> N
    where
        N: From<u128>,
        F: Fn(&T) -> u128,
    {
        collection.iter().map(arranger).sum::<u128>().into()
    }

    // fn find_smallest_debt(qualified_accounts: &[&PayableAccount]) -> u128 {
    //     qualified_accounts
    //         .iter()
    //         .sorted_by(|account_a, account_b| {
    //             Ord::cmp(&account_b.balance_wei, &account_a.balance_wei)
    //         })
    //         .last()
    //         .expect("at least one qualified payable must have been sent here")
    //         .balance_wei
    //         .into()
    // }

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
            Err(AnalysisError::TransactionFeeBalanceBelowOneTransaction {
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
        let required_masq_sum: u128 =
            Self::sum_as(&qualified_payables, |account: &&PayableAccount| {
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

    fn run_recursively(
        resolved_qualified_accounts: Vec<PayableAccount>,
        unresolved_qualified_accounts: Vec<PayableAccount>,
        collected_setup_data: FinancialAndTechDetails,
        gas_limitation_opt: Option<u16>,
        now: SystemTime,
        logger: &Logger,
    ) -> Vec<PayableAccount> {
        diagnostics_collective("RESOLVED QUALIFIED ACCOUNTS:", &resolved_qualified_accounts);
        diagnostics_collective(
            "UNRESOLVED QUALIFIED ACCOUNTS:",
            &unresolved_qualified_accounts,
        );
        let accounts_with_zero_criteria =
            Self::initialize_zero_criteria(unresolved_qualified_accounts);
        let sorted_accounts_with_individual_criteria =
            Self::apply_criteria(accounts_with_zero_criteria, now);

        let cw_masq_balance_wei = collected_setup_data
            .consuming_wallet_balances
            .masq_tokens_wei
            .as_u128();
        let adjustment_result: AdjustmentIterationResult =
            match Self::give_job_to_adjustment_workers(
                gas_limitation_opt,
                sorted_accounts_with_individual_criteria,
                cw_masq_balance_wei,
                logger,
            ) {
                AdjustmentCompletion::Finished(accounts_adjusted) => return accounts_adjusted,
                AdjustmentCompletion::Continue(iteration_result) => iteration_result,
            };

        log_info_for_disqualified_accounts(logger, &adjustment_result.disqualified_accounts);

        let adjusted_accounts = if adjustment_result.remaining_accounts.is_empty() {
            adjustment_result.decided_accounts
        } else {
            let adjusted_setup_data = Self::adjust_cw_balance_in_setup_data(
                collected_setup_data,
                &adjustment_result.decided_accounts,
            );
            //TODO what happens if we choose one that will get us into negative when subtracted
            return Self::run_recursively(
                adjustment_result.decided_accounts,
                adjustment_result.remaining_accounts,
                adjusted_setup_data,
                None,
                now,
                logger,
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
        accounts_with_zero_criteria: impl Iterator<Item = (u128, PayableAccount)>,
        now: SystemTime,
    ) -> Vec<(u128, PayableAccount)> {
        //define individual criteria as closures to be used in a map()

        //caution: always remember to use checked math operations!

        let age_criteria_closure: CriterionFormula = Box::new(|(criteria_sum_so_far, account)| {
            let formula = |last_paid_timestamp: SystemTime| {
                let elapsed_sec: u64 = now
                    .duration_since(last_paid_timestamp)
                    .expect("time traveller")
                    .as_secs();
                let divisor = (elapsed_sec as f64).sqrt().ceil() as u128;
                (elapsed_sec as u128)
                    .pow(AGE_EXPONENT)
                    .checked_div(divisor)
                    .expect("div overflow")
                    * AGE_MULTIPLIER
            };
            let criterion = formula(account.last_paid_timestamp);

            FinalizationAndDiagnostics {
                account,
                criterion,
                criteria_sum_so_far,
                label: "AGE",
                diagnostics_adapted_formula: |x: u128| {
                    let approx_before = SystemTime::now()
                        .checked_sub(Duration::from_secs(x as u64))
                        .expect("characteristics for age blew up");
                    formula(approx_before)
                },
                singleton_ref: &AGE_SINGLETON,
                safe_count_of_examples_to_print: 4,
            }
            .perform()
        });
        let balance_criteria_closure: CriterionFormula =
            Box::new(|(criteria_sum_so_far, account)| {
                // constants used to keep the weights of balance and time balanced
                let formula = |balance_wei: u128| {
                    let binary_weight = log_2(balance_wei * BALANCE_LOG_2_BASE_MULTIPLIER);
                    let multiplier = (binary_weight as u128) * BALANCE_OUTER_MULTIPLIER;
                    let multiplied = balance_wei.checked_mul(multiplier).expect("mul overflow");
                    let tail_weight = Self::balance_tail_weight(balance_wei);
                    eprintln!("tail weight {}", tail_weight);
                    let tail_weight_stressed = tail_weight.pow(BALANCE_TAIL_WEIGHT_EXPONENT)
                        * BALANCE_TAIL_WEIGHT_MULTIPLIER;
                    eprintln!("tail weight stressed {}", tail_weight_stressed);
                    multiplied + tail_weight_stressed
                };
                let criterion = formula(account.balance_wei);

                FinalizationAndDiagnostics {
                    account,
                    criterion,
                    criteria_sum_so_far,
                    label: "BALANCE",
                    diagnostics_adapted_formula: |x: u128| formula(x),
                    singleton_ref: &BALANCE_SINGLETON,
                    safe_count_of_examples_to_print: 9,
                }
                .perform()
            });

        let weights_and_accounts = accounts_with_zero_criteria
            .map(age_criteria_closure)
            .map(balance_criteria_closure);

        Self::sort_in_descendant_order_by_weights(weights_and_accounts)
    }

    //this enables to sense also small differences
    fn balance_tail_weight(balance_wei: u128) -> u128 {
        BALANCE_TAIL_WEIGHT_MASK - (balance_wei & BALANCE_TAIL_WEIGHT_MASK)
    }

    fn give_job_to_adjustment_workers(
        gas_limitation_opt: Option<u16>,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        cw_masq_balance_wei: u128,
        logger: &Logger,
    ) -> AdjustmentCompletion {
        match gas_limitation_opt {
            Some(gas_limit) => {
                let weighted_accounts_cut_by_gas =
                    Self::cut_back_by_gas_count_limit(accounts_with_individual_criteria, gas_limit);
                match Self::check_need_of_masq_balances_adjustment(
                    logger,
                    Either::Right(&weighted_accounts_cut_by_gas),
                    cw_masq_balance_wei,
                ) {
                    true => AdjustmentCompletion::Continue(Self::handle_masq_token_adjustment(
                        cw_masq_balance_wei,
                        weighted_accounts_cut_by_gas,
                    )),
                    false => AdjustmentCompletion::Finished(Self::rebuild_accounts(
                        weighted_accounts_cut_by_gas,
                    )),
                }
            }
            None => AdjustmentCompletion::Continue(Self::handle_masq_token_adjustment(
                cw_masq_balance_wei,
                accounts_with_individual_criteria,
            )),
        }
    }

    fn handle_masq_token_adjustment(
        cw_masq_balance: u128,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentIterationResult {
        let (required_balance_total, criteria_total) =
            Self::compute_balance_and_criteria_totals(&accounts_with_individual_criteria);

        match Self::try_separating_outweighed_accounts(
            accounts_with_individual_criteria,
            required_balance_total,
            criteria_total,
            cw_masq_balance,
        ) {
            Either::Left(accounts_with_individual_criteria) => {
                Self::perform_adjustment_and_determine_adjustment_iteration_result(
                    accounts_with_individual_criteria,
                    cw_masq_balance,
                    criteria_total,
                )
            }
            Either::Right((outweighed, remaining)) => {
                AdjustmentIterationResult {
                    decided_accounts: outweighed,
                    remaining_accounts: remaining,
                    disqualified_accounts: vec![],
                }
            }
        }
    }

    fn perform_adjustment_and_determine_adjustment_iteration_result(
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        cw_masq_balance: u128,
        criteria_total: u128,
    ) -> AdjustmentIterationResult {
        let (decided_accounts, disqualified_accounts): (
            Vec<ReversiblePayableAccount>,
            Vec<DisqualifiedPayableAccount>,
        ) = Self::recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria,
            cw_masq_balance,
            criteria_total,
        );

        if disqualified_accounts.is_empty() {
            let decided_accounts = Self::finalize_decided_accounts(
                decided_accounts,
                DecidedPayableAccountResolution::Finalize,
            );
            AdjustmentIterationResult {
                decided_accounts,
                remaining_accounts: vec![],
                disqualified_accounts: vec![],
            }
        } else {
            // reverting decided accounts because after we lose the disqualified ones from
            // the compilation it may be that the remaining accounts could be now paid
            // in more favorable proportions or even in the full size
            let remaining_accounts = Self::finalize_decided_accounts(
                decided_accounts,
                DecidedPayableAccountResolution::Revert,
            );
            AdjustmentIterationResult {
                decided_accounts: vec![],
                remaining_accounts,
                disqualified_accounts,
            }
        }
    }

    fn recreate_accounts_with_proportioned_balances(
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        cw_masq_balance: u128,
        criteria_total: u128,
    ) -> (
        Vec<ReversiblePayableAccount>,
        Vec<DisqualifiedPayableAccount>,
    ) {
        let multiplication_coeff =
            PaymentAdjusterReal::pick_mul_coeff_for_non_fractional_computation(
                cw_masq_balance,
                criteria_total,
            );

        let proportional_fragment_of_cw_balance = cw_masq_balance
            .checked_mul(multiplication_coeff)
            .expect("mul overflow")
            .checked_div(criteria_total)
            .expect("div overflow");

        accounts_with_individual_criteria.into_iter().fold(
            (vec![], vec![]),
            |(decided, disqualified), (criteria_sum, account)| {
                let original_balance = account.balance_wei;
                let proposed_adjusted_balance =
                    criteria_sum * proportional_fragment_of_cw_balance / multiplication_coeff;

                diagnostics(&account.wallet, "PROPOSED ADJUSTED BALANCE", || {
                    proposed_adjusted_balance.separate_with_commas()
                });

                Self::consider_account_disqualification_from_percentage_insignificance(
                    decided,
                    disqualified,
                    account,
                    original_balance,
                    proposed_adjusted_balance,
                )
            },
        )
    }

    fn consider_account_disqualification_from_percentage_insignificance(
        mut decided: Vec<ReversiblePayableAccount>,
        mut disqualified: Vec<DisqualifiedPayableAccount>,
        mut account: PayableAccount,
        original_balance: u128,
        proposed_adjusted_balance: u128,
    ) -> (
        Vec<ReversiblePayableAccount>,
        Vec<DisqualifiedPayableAccount>,
    ) {
        let balance_at_the_edge =
            ((ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier * original_balance * 10)
                / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor);
        if balance_at_the_edge <= (proposed_adjusted_balance * 10) {
            account.balance_wei = proposed_adjusted_balance;
            let decided_account = ReversiblePayableAccount::new(account, original_balance);
            decided.push(decided_account);
            (decided, disqualified)
        } else {
            let disqualified_account = DisqualifiedPayableAccount::new(
                account.wallet,
                original_balance,
                proposed_adjusted_balance,
            );
            disqualified.push(disqualified_account);
            (decided, disqualified)
        }
    }

    fn try_separating_outweighed_accounts(
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        required_balance_total: u128,
        criteria_total: u128,
        cw_masq_balance: u128
    ) -> Either<Vec<(u128, PayableAccount)>, (Vec<PayableAccount>, Vec<PayableAccount>)> {
        match Self::check_for_outweighed_accounts(
            &accounts_with_individual_criteria,
            required_balance_total,
            criteria_total,
        ) {
            None => Either::Left(accounts_with_individual_criteria),
            Some(wallets_of_outweighed) => Either::Right({
                let (outweighed, remaining) =
                    accounts_with_individual_criteria
                        .into_iter()
                        // TODO use the criteria later, if you have more than one outweighed accounts but you don't have enough balance for them...
                        .map(|(_, account)| account)
                        .partition(|account| wallets_of_outweighed.contains(&account.wallet));
                (outweighed, remaining)
            })
        }
    }

    fn check_for_outweighed_accounts(
        accounts_with_individual_criteria: &[(u128, PayableAccount)],
        required_balance_total: u128,
        criteria_total: u128,
    ) -> Option<Vec<Wallet>> {
        let required_balance_total_for_safe_math = required_balance_total * 10_000;
        let criteria_total_for_safe_math = criteria_total * 10_000;
        let accounts_to_be_outweighed = accounts_with_individual_criteria
            .iter()
            .filter(|(criterion, account)| {
                //account.balance_wei is still the original balance
                let balance_ratio =
                    required_balance_total_for_safe_math / (account.balance_wei * 10_000);
                let criterion_ratio = criteria_total_for_safe_math / (criterion * 10_000);
                // true means we would pay more than we were asked to pay at the beginning,
                // this happens when the debt size is quite small but its age is large and
                // plays the main factor
                let is_highly_significant = balance_ratio > criterion_ratio;

                if is_highly_significant {
                    diagnostics(
                        &account.wallet,
                        "ACCOUNT PROPOSED WITH BALANCE HIGHER THAN THE ORIGIN ONE",
                        || {
                            format!(
                                "balance_ration ({}) > criterion_ration ({})",
                                balance_ratio, criterion_ratio
                            )
                        },
                    )
                }

                is_highly_significant
            })
            .map(|(_, account)| account.wallet.clone())
            .collect::<Vec<Wallet>>();
        if !accounts_to_be_outweighed.is_empty() {
            Some(accounts_to_be_outweighed)
        } else {
            None
        }
    }

    fn adjust_cw_balance_in_setup_data(
        current_data: FinancialAndTechDetails,
        processed_outweighed: &[PayableAccount],
    ) -> FinancialAndTechDetails {
        let subtrahend_total: u128 =
            Self::sum_as(processed_outweighed, |account| account.balance_wei);
        eprintln!(
            "cw masq balance {} to subtract {}",
            current_data
                .consuming_wallet_balances
                .masq_tokens_wei
                .as_u128(),
            subtrahend_total
        );
        let consuming_wallet_balances = ConsumingWalletBalances {
            gas_currency_wei: current_data.consuming_wallet_balances.gas_currency_wei,
            masq_tokens_wei: U256::from(
                current_data
                    .consuming_wallet_balances
                    .masq_tokens_wei
                    .as_u128()
                    - subtrahend_total,
            ),
        };
        FinancialAndTechDetails {
            consuming_wallet_balances,
            ..current_data
        }
    }

    fn compute_balance_and_criteria_totals(
        accounts_with_individual_criteria: &[(u128, PayableAccount)],
    ) -> (u128, u128) {
        let required_balance_total: u128 =
            Self::sum_as(&accounts_with_individual_criteria, |(_, account)| {
                account.balance_wei
            });

        let criteria_total: u128 =
            Self::sum_as(&accounts_with_individual_criteria, |(criteria, _)| {
                *criteria
            });
        (required_balance_total, criteria_total)
    }

    fn pick_mul_coeff_for_non_fractional_computation(
        cw_masq_balance: u128,
        criteria_sum: u128,
    ) -> u128 {
        const EMPIRIC_PRECISION_COEFFICIENT: usize = 8;
        let criteria_sum_digits_count = log_10(criteria_sum);
        let cw_balance_digits_count = log_10(cw_masq_balance);
        let smallest_mul_coeff_between = criteria_sum_digits_count
            .checked_sub(cw_balance_digits_count)
            .unwrap_or(0);
        let safe_mul_coeff = smallest_mul_coeff_between + EMPIRIC_PRECISION_COEFFICIENT;
        10_u128.pow(safe_mul_coeff as u32)
    }

    fn finalize_decided_accounts(
        decided_accounts: Vec<ReversiblePayableAccount>,
        resolution: DecidedPayableAccountResolution,
    ) -> Vec<PayableAccount> {
        decided_accounts
            .into_iter()
            .map(|decided_account| PayableAccount::from((decided_account, resolution)))
            .collect()
    }

    fn cut_back_by_gas_count_limit(
        weights_and_accounts: Vec<(u128, PayableAccount)>,
        limit: u16,
    ) -> Vec<(u128, PayableAccount)> {
        weights_and_accounts
            .into_iter()
            .take(limit as usize)
            .collect()
    }

    fn sort_in_descendant_order_by_weights(
        unsorted: impl Iterator<Item = (u128, PayableAccount)>,
    ) -> Vec<(u128, PayableAccount)> {
        unsorted
            .sorted_by(|(weight_a, _), (weight_b, _)| Ord::cmp(weight_b, weight_a))
            .collect()
    }

    fn rebuild_accounts(criteria_and_accounts: Vec<(u128, PayableAccount)>) -> Vec<PayableAccount> {
        criteria_and_accounts
            .into_iter()
            .map(|(_, account)| account)
            .collect()
    }
}

// replace with `account_1.balance_wei.checked_ilog10().unwrap() + 1`
// which will be introduced by Rust 1.67.0; this was written with 1.63.0
fn log_10(num: u128) -> usize {
    successors(Some(num), |&n| (n >= 10).then(|| n / 10)).count()
}

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: u128) -> u32 {
    if x < 1 {
        panic!("log2 of 0 not supported")
    }
    num_bits::<i128>() as u32 - x.leading_zeros() - 1
}

#[derive(Debug)]
struct AdjustmentIterationResult {
    decided_accounts: Vec<PayableAccount>,
    remaining_accounts: Vec<PayableAccount>,
    disqualified_accounts: Vec<DisqualifiedPayableAccount>,
}

#[derive(Debug, PartialEq, Eq)]
struct ReversiblePayableAccount {
    adjusted_account: PayableAccount,
    former_balance: u128,
}

#[derive(Clone, Copy)]
enum DecidedPayableAccountResolution {
    Finalize,
    Revert,
}

enum AdjustmentCompletion {
    Finished(Vec<PayableAccount>),
    Continue(AdjustmentIterationResult),
}

impl ReversiblePayableAccount {
    fn new(adjusted_account: PayableAccount, former_balance: u128) -> Self {
        Self {
            adjusted_account,
            former_balance,
        }
    }
}

impl From<(ReversiblePayableAccount, DecidedPayableAccountResolution)> for PayableAccount {
    fn from(
        (decided_account, resolution): (ReversiblePayableAccount, DecidedPayableAccountResolution),
    ) -> Self {
        match resolution {
            DecidedPayableAccountResolution::Finalize => decided_account.adjusted_account,
            DecidedPayableAccountResolution::Revert => {
                let mut reverted_account = decided_account.adjusted_account;
                reverted_account.balance_wei = decided_account.former_balance;
                reverted_account
            }
        }
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
    TransactionFeeFirstLaterMaybeMasq { limited_count_from_gas: u16 },
}

#[derive(Clone, Copy)]
struct GasLimitationContext {
    limited_count_from_gas: u16,
    is_masq_token_insufficient: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {
    TransactionFeeBalanceBelowOneTransaction {
        one_transaction_requirement: u64,
        cw_balance: u64,
    },
}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::{
        log_10, log_2, Adjustment, AnalysisError, DisqualifiedPayableAccount, PaymentAdjuster,
        PaymentAdjusterReal, PercentageAccountInsignificance, ReversiblePayableAccount,
        ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE, AGE_EXPONENT, AGE_MULTIPLIER,
        BALANCE_LOG_2_BASE_MULTIPLIER, BALANCE_OUTER_MULTIPLIER, BALANCE_TAIL_WEIGHT_EXPONENT,
        BALANCE_TAIL_WEIGHT_MASK, BALANCE_TAIL_WEIGHT_MULTIPLIER,
        COMPUTE_CRITERIA_PROGRESSIVE_CHARACTERISTICS, PRINT_PARTIAL_COMPUTATIONS_FOR_DIAGNOSTICS,
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
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use masq_lib::constants::MASQ_TOTAL_SUPPLY;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::iter::once;
    use std::time::{Duration, SystemTime};
    use std::vec;
    use thousands::Separable;
    use web3::types::U256;

    lazy_static! {
        static ref MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR: u128 =
            MASQ_TOTAL_SUPPLY as u128 * 10_u128.pow(18);
        static ref FIVE_YEAR_LONG_DEBT_SEC: u64 = 5_u64 * 365 * 24 * 60 * 60;
    }

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
        assert_eq!(AGE_EXPONENT, 4);
        assert_eq!(AGE_MULTIPLIER, 10);
        assert_eq!(BALANCE_LOG_2_BASE_MULTIPLIER, 9);
        assert_eq!(BALANCE_OUTER_MULTIPLIER, 2);
        assert_eq!(
            ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE,
            PercentageAccountInsignificance {
                multiplier: 1,
                divisor: 2,
            }
        );
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
            Ok(Some(Adjustment::TransactionFeeFirstLaterMaybeMasq {
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
            Err(AnalysisError::TransactionFeeBalanceBelowOneTransaction {
                one_transaction_requirement: 55_000 * 100,
                cw_balance: 54_000 * 100
            })
        );
    }

    // #[test]
    // fn find_smallest_debt_works() {
    //     let mut payable_1 = make_payable_account(111);
    //     payable_1.balance_wei = 111_111;
    //     let mut payable_3 = make_payable_account(333);
    //     payable_3.balance_wei = 111_110;
    //     let mut payable_2 = make_payable_account(222);
    //     payable_2.balance_wei = 3_000_000;
    //     let qualified_payables = vec![payable_1, payable_2, payable_3];
    //     let referenced_qualified_payables = qualified_payables.iter().collect::<Vec<_>>();
    //
    //     let min = PaymentAdjusterReal::find_smallest_debt(&referenced_qualified_payables);
    //
    //     assert_eq!(min, 111_110)
    // }
    //
    // #[test]
    // fn find_smallest_debt_handles_just_one_account() {
    //     let payable = make_payable_account(111);
    //     let qualified_payables = vec![payable];
    //     let referenced_qualified_payables = qualified_payables.iter().collect::<Vec<_>>();
    //
    //     let min = PaymentAdjusterReal::find_smallest_debt(&referenced_qualified_payables);
    //
    //     assert_eq!(min, 111_000_000_000)
    // }

    #[test]
    fn balance_tail_weight_works() {
        vec![
            (0xfff_u128 - 1, BALANCE_TAIL_WEIGHT_MASK - (0xfff - 1)),
            (0xfff, BALANCE_TAIL_WEIGHT_MASK - 0xfff),
            (0x1fff, BALANCE_TAIL_WEIGHT_MASK - 0xfff),
            (0xfffff, BALANCE_TAIL_WEIGHT_MASK - 0xfff),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| {
            assert_eq!(
                PaymentAdjusterReal::balance_tail_weight(num),
                expected_result
            )
        })
    }

    #[test]
    fn log_10_works() {
        [
            (4_565_u128, 4),
            (1_666_777, 7),
            (3, 1),
            (123, 3),
            (111_111_111_111_111_111, 18),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| assert_eq!(log_10(num), expected_result))
    }

    #[test]
    fn log_2_works() {
        [
            (1, 0),
            (2, 1),
            (4, 2),
            (8192, 13),
            (18446744073709551616, 64),
            (1267650600228229401496703205376, 100),
            (170141183460469231731687303715884105728, 127),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| assert_eq!(log_2(num), expected_result))
    }

    #[test]
    #[should_panic(expected = "log2 of 0 not supported")]
    fn log_2_dislikes_0() {
        let _ = log_2(0);
    }

    #[test]
    fn multiplication_coeff_for_integers_to_be_above_one_instead_of_fractional_numbers() {
        let final_criteria_sum = 5_000_000_000_000_u128;
        let consuming_wallet_balances = vec![
            222_222_222_222_u128,
            100_000,
            123_456_789,
            5_555_000_000_000,
            5_000_555_000_000_000,
            1_000_000_000_000_000_000, //1 MASQ
        ];

        let result = consuming_wallet_balances
            .clone()
            .into_iter()
            .map(|cw_balance| {
                PaymentAdjusterReal::pick_mul_coeff_for_non_fractional_computation(
                    cw_balance,
                    final_criteria_sum,
                )
            })
            .collect::<Vec<u128>>();

        assert_eq!(
            result,
            vec![
                1_000_000_000,
                1_000_000_000_000_000,
                1_000_000_000_000,
                100_000_000,
                100_000_000,
                100_000_000
            ]
        )
    }

    #[test]
    fn multiplication_coeff_testing_upper_extreme() {
        let final_criteria = get_extreme_criteria(1);
        let final_criteria_total = final_criteria[0].0;
        let cw_balance_in_minor = 1;
        let result = PaymentAdjusterReal::pick_mul_coeff_for_non_fractional_computation(
            cw_balance_in_minor,
            final_criteria_total,
        );

        assert_eq!(result, 10_000_000_000_000_000_000_000_000_000_000_000_000)
        // enough space for our counts; mostly we use it for division and multiplication and
        // in both cases the coefficient is picked carefully to handle it (we near the extremes
        // either by increasing the criteria sum and decreasing the cw balance or vica versa)
        //
        // it allows operating without the use of point floating numbers
    }

    #[test]
    fn recreate_accounts_with_proportioned_balances_adheres_to_the_manifested_edge_of_insignificance(
    ) {
        let mut payable_account_1 = make_payable_account(1);
        payable_account_1.balance_wei = 1_000_000;
        let mut payable_account_2 = make_payable_account(2);
        payable_account_2.balance_wei = 1_000_001;
        let proportional_fragment_of_cw_balance = 200_000;
        let multiplication_coeff = 10;
        let proposed_adjusted_balance = 500_000;
        let criterion =
            proposed_adjusted_balance * multiplication_coeff / proportional_fragment_of_cw_balance; // = 25
        let weights_and_accounts = vec![
            (criterion, payable_account_1.clone()),
            (criterion, payable_account_2.clone()),
        ];

        let (decided_accounts, disqualified_accounts) =
            PaymentAdjusterReal::recreate_accounts_with_proportioned_balances(
                weights_and_accounts,
                proportional_fragment_of_cw_balance,
                multiplication_coeff,
            );

        // coefficients used reversely on purpose
        let ok_former_balance = proposed_adjusted_balance
            * ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.divisor
            / ACCOUNT_INSIGNIFICANCE_BY_PERCENTAGE.multiplier;
        let expected_decided_payable_account = ReversiblePayableAccount {
            adjusted_account: PayableAccount {
                balance_wei: 500_000,
                ..payable_account_1
            },
            former_balance: ok_former_balance,
        };
        let bad_former_balance = ok_former_balance + 1;
        let expected_disqualified_account = DisqualifiedPayableAccount {
            wallet: payable_account_2.wallet,
            proposed_adjusted_balance: 500_000,
            original_balance: bad_former_balance,
        };
        assert_eq!(decided_accounts, vec![expected_decided_payable_account]);
        assert_eq!(disqualified_accounts, vec![expected_disqualified_account])
    }

    fn get_extreme_criteria(number_of_accounts: usize) -> Vec<(u128, PayableAccount)> {
        let now = SystemTime::now();
        let account = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: *MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(*FIVE_YEAR_LONG_DEBT_SEC))
                .unwrap(),
            pending_payable_opt: None,
        };
        let accounts = once(account).cycle().take(number_of_accounts).collect();
        let zero_criteria_accounts = PaymentAdjusterReal::initialize_zero_criteria(accounts);
        PaymentAdjusterReal::apply_criteria(zero_criteria_accounts, now)
    }

    #[test]
    fn testing_criteria_on_overflow_safeness() {
        let criteria_and_accounts = get_extreme_criteria(3);
        assert_eq!(criteria_and_accounts.len(), 3);
        //operands in apply_criteria have to be their checked version therefore we passed through without a panic and so no overflow occurred
    }

    #[test]
    fn apply_criteria_returns_accounts_sorted_by_final_weights_in_descending_order() {
        let now = SystemTime::now();
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

        let weights_and_accounts = PaymentAdjusterReal::apply_criteria(zero_criteria_accounts, now);

        let only_accounts = weights_and_accounts
            .iter()
            .map(|(_, account)| account)
            .collect::<Vec<&PayableAccount>>();
        assert_eq!(only_accounts, vec![&account_3, &account_1, &account_2])
    }

    #[test]
    fn small_debt_with_extreme_age_is_paid_outweighed_but_not_with_more_money_than_required() {
        let now = SystemTime::now();
        let collected_setup_data = FinancialAndTechDetails {
            consuming_wallet_balances: ConsumingWalletBalances {
                gas_currency_wei: U256::from(u128::MAX),
                masq_tokens_wei: U256::from(1_500_000_000_000_u64 - 25_000_000),
            },
            desired_gas_price_gwei: 50,
            estimated_gas_limit_per_transaction: 55_000,
        };
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

        let result = PaymentAdjusterReal::run_recursively(
            vec![],
            qualified_payables.clone(),
            collected_setup_data,
            None,
            now,
            &logger,
        );

        //first a presentation of why this test is important
        let total = balance_1 * 10_000 + balance_2 * 10_000;
        let ratio_2_u128 = total / (balance_2 * 10_000);
        let ratio_2 = ratio_2_u128 as f64 / 10_000.0;
        let zero_criteria_accounts =
            PaymentAdjusterReal::initialize_zero_criteria(qualified_payables);
        let criteria = PaymentAdjusterReal::apply_criteria(zero_criteria_accounts, now);
        let account_1_criterion = criteria[0].0 * 10_000;
        let account_2_criterion = criteria[1].0 * 10_000;
        let criteria_total = account_1_criterion + account_2_criterion;
        let criterion_2_ratio = ((criteria_total / account_2_criterion) as f64) / 10_000.0;
        //the next assertion reads as the weight of the second account grew faster and bigger than at the first account;
        //also, the time parameter has a strong impact on the final criteria;
        //consequences are that redistributing the new balances according to the computed weights would've attributed
        //the second account with more tokens to pay than it had when the test started;
        //to prevent it, we've got a rule that any account can never demand more than 100% of the initial amount
        assert!(ratio_2 > criterion_2_ratio);
        assert_eq!(
            result,
            vec![
                account_2, //outweighed accounts take the first places
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance_wei: 1_499_949_995_299,
                    last_paid_timestamp: last_paid_timestamp_1,
                    pending_payable_opt: None,
                },
            ]
        );
    }

    #[test]
    fn try_separating_outweighed_accounts_that_qualify_straight_cuts_back_the_outweighed_account_if_cw_balance_is_smaller(
    ) {
        let consuming_wallet_balance = 1_000_000_000_000_u128 - 1;
        let account_1_made_up_criteria = 18_000_000_000_000;
        let account_1 = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: 1_000_000_000_000 + 333,
            last_paid_timestamp: SystemTime::now()
                .checked_sub(Duration::from_secs(200000))
                .unwrap(),
            pending_payable_opt: None,
        };
        let account_2_made_up_criteria = 5_000_000_000_000;
        let account_2 = PayableAccount {
            wallet: make_wallet("booga"),
            balance_wei: 8_000_000_000_000_000,
            last_paid_timestamp: SystemTime::now()
                .checked_sub(Duration::from_secs(1000))
                .unwrap(),
            pending_payable_opt: None,
        };
        let required_balance_total = 1_000_000_000_000 + 333 + 8_000_000_000_000_000;
        let criteria_total = account_1_made_up_criteria + account_2_made_up_criteria;
        let accounts_with_individual_criteria = vec![
            (account_1_made_up_criteria, account_1.clone()),
            (account_2_made_up_criteria, account_2.clone()),
        ];

        let (outweighed, _) =
            PaymentAdjusterReal::try_separating_outweighed_accounts(
                accounts_with_individual_criteria,
                required_balance_total,
                criteria_total,
                consuming_wallet_balance
            ).right()
            .unwrap();

        let mut expected_account = account_1;
        expected_account.balance_wei = 1_000_000_000_000 - 1;
        assert_eq!(outweighed, vec![expected_account])
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
        let subject = PaymentAdjusterReal::new();
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
        let subject = PaymentAdjusterReal::new();
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
            adjustment: Adjustment::TransactionFeeFirstLaterMaybeMasq {
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
        let subject = PaymentAdjusterReal::new();
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
        TestLogHandler::new().exists_log_containing(&format!("INFO: {test_name}: Recently qualified \
        payable for wallet 0x000000000000000000000000000000000067686b is being ignored as the limited \
        consuming balance implied adjustment of its balance down to 56,554,286 wei, which is not at \
        least half of the debt"));
    }

    fn test_competitive_accounts(
        test_name_with_unique_description: &str,
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
        let subject = PaymentAdjusterReal::new();
        let consuming_wallet_masq_balance_wei = U256::from(100_000_000_000_000_u64 - 1);
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

    #[test]
    fn adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account() {
        // accounts in this test are evenly significant and so one cannot compete another,
        // yet there is not enough balance to pay the minimum required which is a half of each
        // thus we conclude none can be paid
        fn merge_test_name_and_study_description(test_name: &str, description: &str) -> String {
            format!("{}/{}", test_name, description)
        }
        let test_name = "adjust_payments_when_not_enough_masq_to_pay_at_least_half_of_each_account";
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
            &wallet_1,
            &wallet_2,
            balance_account_1,
            balance_account_2,
            age_account_1,
            age_account_2,
        );

        assert_eq!(result, vec![]);
        // scenario B
        const TOLERATED_MAXIMAL_INEFFECTIVE_BALANCE_GAP_HALVED: u128 = 500;
        let second_scenario_name =
            merge_test_name_and_study_description(test_name, "first_heavier_by_balance");

        let result = test_competitive_accounts(
            &second_scenario_name,
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

    //TODO do I really want to delete this test? Why?
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
        let subject = PaymentAdjusterReal::new();
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
            adjustment: Adjustment::TransactionFeeFirstLaterMaybeMasq {
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
                elapsed.pow(AGE_EXPONENT) / (((elapsed as f64).sqrt().ceil()) as u128)
                    * AGE_MULTIPLIER
            })
            .collect();
        let balance_criteria = accounts
            .iter()
            .map(|account| {
                let balance = account.balance_wei;
                let significance = log_2(balance * BALANCE_LOG_2_BASE_MULTIPLIER) as u128;
                let tail_weight = PaymentAdjusterReal::balance_tail_weight(balance);
                balance * (significance * BALANCE_OUTER_MULTIPLIER)
                    + (tail_weight.pow(BALANCE_TAIL_WEIGHT_EXPONENT)
                        * BALANCE_TAIL_WEIGHT_MULTIPLIER)
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
        let multiplication_coeff =
            PaymentAdjusterReal::pick_mul_coeff_for_non_fractional_computation(
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
}
