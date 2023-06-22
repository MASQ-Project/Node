// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::gwei_to_wei;
use crate::accountant::scanners::payable_scan_setup_msgs::{
    FinancialAndTechDetails, PayablePaymentSetup, StageData,
};
use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, OutcomingPaymentsInstructions};
use crate::sub_lib::wallet::Wallet;
use itertools::{Either, Itertools};
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;
use std::collections::HashMap;
use std::iter::{once, successors};
use std::ops::Not;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;

const REFILL_RECOMMENDATION: &str = "\
In order to continue using services of other Nodes and avoid delinquency \
bans you will need to put more funds into your consuming wallet.";

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

        //TODO use question mark later
        let limit_by_gas_opt = match Self::determine_transactions_count_limit_by_gas(
            &this_stage_data,
            qualified_payables.len(),
            logger,
        ) {
            Ok(None) => None,
            Ok(Some(limiting_count)) => Some(limiting_count),
            Err(e) => todo!(),
        };

        //TODO use question mark later
        let required_by_masq_token = match Self::check_need_of_masq_balances_adjustment(
            logger,
            Either::Left(qualified_payables),
            this_stage_data
                .consuming_wallet_balances
                .masq_tokens_wei
                .as_u128(),
        ) {
            Ok(required) => required,
            Err(e) => todo!(),
        };

        match (limit_by_gas_opt, required_by_masq_token) {
            (None, false) => Ok(None),
            (None, true) => Ok(Some(Adjustment::MasqToken)),
            (Some(limited_count_from_gas), false) => Ok(Some(Adjustment::Gas {
                limited_count_from_gas,
            })),
            (Some(limiting_count), true) => todo!(),
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

        let debug_log_printer_opt =
            logger
                .debug_enabled()
                .then_some(Self::before_and_after_debug_msg_formatter(
                    &qualified_payables,
                ));

        let gas_limitation_context_opt = match setup.adjustment {
            Adjustment::Gas {
                limited_count_from_gas,
            } => Some(GasLimitationContext {
                limited_count_from_gas,
                is_masq_token_insufficient: false,
            }),
            Adjustment::Both {
                limited_count_from_gas,
            } => Some(GasLimitationContext {
                limited_count_from_gas,
                is_masq_token_insufficient: true,
            }),
            Adjustment::MasqToken => None,
        };

        let (adjusted_accounts, debug_info_opt) = Self::run_recursively(
            vec![],
            current_stage_data,
            gas_limitation_context_opt,
            qualified_payables,
            now,
            logger,
        );

        debug!(
            logger,
            "{}",
            debug_log_printer_opt.expect("debug message missing")(
                debug_info_opt.expectv("debug info"),
                &adjusted_accounts
            )
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

    fn sum_payable_balances(qualified_accounts: &[PayableAccount]) -> U256 {
        qualified_accounts
            .iter()
            .map(|account| account.balance_wei)
            .sum::<u128>()
            .into()
    }

    fn find_smallest_debt(qualified_accounts: &[&PayableAccount]) -> u128 {
        qualified_accounts
            .iter()
            .sorted_by(|account_a, account_b| {
                Ord::cmp(&account_b.balance_wei, &account_a.balance_wei)
            })
            .last()
            .expect("at least one qualified payable must have been sent here")
            .balance_wei
            .into()
    }

    fn determine_transactions_count_limit_by_gas(
        tech_info: &FinancialAndTechDetails,
        required_transactions_count: usize,
        logger: &Logger,
    ) -> Result<Option<u16>, AnalysisError> {
        let gas_required_per_transaction_gwei =
            u128::try_from(tech_info.estimated_gas_limit_per_transaction)
                .expectv("small number for gas limit")
                * u128::try_from(tech_info.desired_gas_price_gwei)
                    .expectv("small number for gas price");
        let grpt_in_wei: U256 = gwei_to_wei(gas_required_per_transaction_gwei);
        let available_wei = tech_info.consuming_wallet_balances.gas_currency_wei;
        let limiting_max_possible_count = (available_wei / grpt_in_wei).as_u128();
        if limiting_max_possible_count == 0 {
            todo!()
        } else if limiting_max_possible_count >= required_transactions_count as u128 {
            Ok(None)
        } else {
            let limiting_count = u16::try_from(limiting_max_possible_count)
                .expectv("small number for possible tx count");
            Self::log_insufficient_transaction_fee_balance(
                logger,
                required_transactions_count,
                tech_info,
                limiting_count,
            );
            Ok(Some(limiting_count))
        }
    }

    //TODO write a test that tries really big balances...if we can kill the ceiling
    fn find_multiplication_coeff(cw_masq_balance: u128, criteria_sum: u128) -> u128 {
        const EMPIRIC_PRECISION_LEVERAGING_COEFFICIENT: usize = 6;
        let num_len_criteria = log_10(criteria_sum); //TODO make the log_10 fn generic
        let num_len_cw_balance = log_10(cw_masq_balance);
        let smallest_mul_coeff_between = num_len_criteria
            .checked_sub(num_len_cw_balance)
            .unwrap_or(1);
        let safe_mul_coeff = smallest_mul_coeff_between + EMPIRIC_PRECISION_LEVERAGING_COEFFICIENT;
        1_u128 * 10_u128.pow(safe_mul_coeff as u32)
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

    fn recreate_accounts_with_proportioned_balances(
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        proportional_fragment_of_cw_balance: u128,
        multiplication_coeff: u128,
    ) -> (Vec<DecidedPayableAccount>, Vec<DisqualifiedPayableAccount>) {
        accounts_with_individual_criteria.into_iter().fold(
            (vec![], vec![]),
            |(mut decided, mut disqualified), (criteria_sum, mut account)| {
                let original_balance = account.balance_wei;
                let proposed_adjusted_balance =
                    criteria_sum * proportional_fragment_of_cw_balance / multiplication_coeff;
                if ((original_balance * 10) / 2) <= (proposed_adjusted_balance * 10) {
                    account.balance_wei = proposed_adjusted_balance;
                    let decided_account = DecidedPayableAccount::new(account, original_balance);
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
            },
        )
    }

    fn log_info_for_disqualified_accounts(
        logger: &Logger,
        disqualified_accounts: &[DisqualifiedPayableAccount],
    ) {
        disqualified_accounts.iter().for_each(|account| {
            info!(
                logger,
                "Recently qualified payable for wallet {} is being ignored as the limited \
        consuming balance implied adjustment of its balance down to {} wei, which is not at least \
        half of the debt",
                account.wallet,
                account.proposed_adjusted_balance.separate_with_commas()
            )
        });
    }

    fn handle_masq_token_adjustment(
        cw_masq_balance: u128,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> AdjustmentIterationResult {
        let required_balance_total: u128 =
            Self::sum_as(&accounts_with_individual_criteria, |(_, account)| {
                account.balance_wei
            });
        let criteria_sum: u128 =
            Self::sum_as(&accounts_with_individual_criteria, |(criteria, _)| {
                *criteria
            });
        if let Some(prioritized_wallets) =
            Self::check_possible_prioritized_accounts_that_qualify_right_away(
                required_balance_total,
                criteria_sum,
                &accounts_with_individual_criteria,
            )
        {
            let (prioritized, remaining): (Vec<PayableAccount>, Vec<PayableAccount>) =
                accounts_with_individual_criteria
                    .into_iter()
                    .map(|(_, account)| account)
                    .partition(|account| prioritized_wallets.contains(&account.wallet));

            return AdjustmentIterationResult {
                decided_accounts: prioritized,
                remaining_accounts: remaining,
                disqualified_accounts: vec![],
            };
        };
        let multiplication_coeff =
            PaymentAdjusterReal::find_multiplication_coeff(cw_masq_balance, criteria_sum);
        let proportional_fragment_of_cw_balance = cw_masq_balance
            .checked_mul(multiplication_coeff)
            .expect("mul overflow")
            .checked_div(criteria_sum)
            .expect("div overflow");

        let (decided_accounts, disqualified_accounts): (
            Vec<DecidedPayableAccount>,
            Vec<DisqualifiedPayableAccount>,
        ) = Self::recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria,
            proportional_fragment_of_cw_balance,
            multiplication_coeff,
        );
        if disqualified_accounts.is_empty() {
            let decided_accounts = decided_accounts
                .into_iter()
                .map(|decided_account| {
                    PayableAccount::from((
                        decided_account,
                        DecidedPayableAccountResolution::Finalize,
                    ))
                })
                .collect();
            AdjustmentIterationResult {
                decided_accounts,
                remaining_accounts: vec![],
                disqualified_accounts: vec![],
            }
        } else {
            let remaining_accounts = decided_accounts
                .into_iter()
                .map(|decided_account| {
                    PayableAccount::from((decided_account, DecidedPayableAccountResolution::Revert))
                })
                .collect();
            AdjustmentIterationResult {
                decided_accounts: vec![],
                remaining_accounts,
                disqualified_accounts,
            }
        }
    }

    fn apply_criteria(
        accounts_with_zero_criteria: impl Iterator<Item = (u128, PayableAccount)>,
        now: SystemTime,
    ) -> Vec<(u128, PayableAccount)> {
        type CriteriaClosure<'a> =
            Box<dyn FnMut((u128, PayableAccount)) -> (u128, PayableAccount) + 'a>;
        //define individual criteria as closures to be used in a map()

        //caution: always remember to use checked math operations!

        let time_criteria_closure: CriteriaClosure = Box::new(|(criteria_sum, account)| {
            let elapsed_sec: u64 = now
                .duration_since(account.last_paid_timestamp)
                .expect("time traveller")
                .as_secs();
            let divisor = (elapsed_sec as f64).sqrt().ceil() as u128;
            let criterion = (elapsed_sec as u128)
                .pow(4)
                .checked_div(divisor)
                .expect("div overflow");
            (
                criteria_sum.checked_add(criterion).expect("add overflow"),
                account,
            )
        });
        let balance_criteria_closure: CriteriaClosure = Box::new(|(criteria_sum, account)| {
            let digits_weight = log_10(account.balance_wei);
            let multiplier = (digits_weight as u128)
                .checked_pow(3)
                .expect("pow overflow");
            let criterion = account
                .balance_wei
                .checked_mul(multiplier)
                .expect("mul overflow");
            (
                criteria_sum.checked_add(criterion).expect("add overflow"),
                account,
            )
        });

        let weights_and_accounts = accounts_with_zero_criteria
            .map(time_criteria_closure)
            .map(balance_criteria_closure);

        Self::sort_in_descendant_order_by_weights(weights_and_accounts)
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

    fn check_possible_prioritized_accounts_that_qualify_right_away(
        required_balance_total: u128,
        criteria_total: u128,
        accounts_with_individual_criteria: &[(u128, PayableAccount)],
    ) -> Option<Vec<Wallet>> {
        let required_balance_for_safe_math = required_balance_total * 10_000;
        let criteria_total_for_safe_math = criteria_total * 10_000;
        let accounts_to_be_prioritized = accounts_with_individual_criteria
            .iter()
            .filter(|(criterion, account)| {
                //account.balance_wei is still the original balance
                let balance_ratio = required_balance_for_safe_math / (account.balance_wei * 10_000);
                let criterion_ratio = criteria_total_for_safe_math / (criterion * 10_000);
                balance_ratio > criterion_ratio
            })
            .map(|(_, account)| account.wallet.clone())
            .collect::<Vec<Wallet>>();
        if !accounts_to_be_prioritized.is_empty() {
            Some(accounts_to_be_prioritized)
        } else {
            None
        }
    }

    fn adjust_cw_balance_in_setup_data(
        current_data: FinancialAndTechDetails,
        processed_prioritized: &[PayableAccount],
        disqualified_accounts: &[DisqualifiedPayableAccount],
    ) -> FinancialAndTechDetails {
        let subtrahend_total: u128 = if !disqualified_accounts.is_empty() {
            Self::sum_as(disqualified_accounts, |disq_account| {
                disq_account.original_balance
            })
        } else {
            Self::sum_as(processed_prioritized, |account| account.balance_wei)
        };
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

    fn sort_in_descendant_order_by_weights(
        unsorted: impl Iterator<Item = (u128, PayableAccount)>,
    ) -> Vec<(u128, PayableAccount)> {
        unsorted
            .sorted_by(|(weight_a, _), (weight_b, _)| Ord::cmp(weight_b, weight_a))
            .collect()
    }

    fn format_brief_adjustment_summary(
        mut original_accounts: HashMap<Wallet, AccountAdjustmentDebugDetails>,
        adjusted_accounts: impl Iterator<Item = (u128, Wallet, u128)>,
    ) -> String {
        adjusted_accounts.for_each(|(criterion, wallet, adjusted_balance)| {
            let _ = original_accounts.entry(wallet).and_modify(|details| {
                let _ = {
                    details.adjusted_balance_opt.replace(adjusted_balance);
                    details.used_criterion = criterion
                };
            });
        });

        let (adjusted, excluded): (Vec<_>, Vec<_>) = original_accounts
            .into_iter()
            .partition(|(_, details)| details.adjusted_balance_opt.is_some());

        let adjusted_accounts_as_strings = adjusted
            .into_iter()
            .sorted_by(|(_, details_a), (_, details_b)| {
                Ord::cmp(&details_b.used_criterion, &details_a.used_criterion)
            })
            .map(|(wallet, details)| {
                format!(
                    "{} {}\n{:^length$} {}",
                    wallet,
                    details.initial_balance,
                    "",
                    details.adjusted_balance_opt.expectv("adjusted balance"),
                    length = WALLET_ADDRESS_LENGTH
                )
            })
            .join("\n");

        let excluded_accounts_opt = excluded.is_empty().not().then(|| {
            once(format!(
                "\n{:<length$} Original\n",
                "Ignored minor payables",
                length = WALLET_ADDRESS_LENGTH
            ))
            .chain(
                excluded
                    .into_iter()
                    .sorted_by(|(_, debug_details_a), (_, debug_details_b)| {
                        Ord::cmp(
                            &debug_details_b.used_criterion,
                            &debug_details_a.used_criterion,
                        )
                    })
                    .map(|(wallet, debug_details)| {
                        format!("{} {}", wallet, debug_details.initial_balance)
                    }),
            )
            .join("\n")
        });

        vec![Some(adjusted_accounts_as_strings), excluded_accounts_opt]
            .into_iter()
            .flatten()
            .join("\n")
    }

    fn wallets_and_balances_with_criteria_opt<'a>(
        accounts: Either<&'a [PayableAccount], &'a [(u128, &'a PayableAccount)]>,
    ) -> Either<
        impl Iterator<Item = (Wallet, u128)> + 'a,
        impl Iterator<Item = (u128, Wallet, u128)> + 'a,
    > {
        match accounts {
            Either::Left(just_accounts) => Either::Left(
                just_accounts
                    .iter()
                    .map(|account| (account.wallet.clone(), account.balance_wei)),
            ),
            Either::Right(criteria_and_accounts) => {
                Either::Right(criteria_and_accounts.iter().map(|(criterion, account)| {
                    (*criterion, account.wallet.clone(), account.balance_wei)
                }))
            }
        }
    }

    fn before_and_after_debug_msg_formatter(
        original: &[PayableAccount],
    ) -> impl FnOnce(Vec<u128>, &[PayableAccount]) -> String {
        let original_prefabricated =
            Self::wallets_and_balances_with_criteria_opt(Either::Left(original))
                .left()
                .expectv("wallet + balance")
                .map(|(wallet, balance)| (wallet, AccountAdjustmentDebugDetails::new(balance)))
                .collect::<HashMap<Wallet, AccountAdjustmentDebugDetails>>();
        move |criteria: Vec<u128>, adjusted_accounts: &[PayableAccount]| {
            let concise_input = criteria
                .into_iter()
                .zip(adjusted_accounts.iter())
                .collect::<Vec<_>>();
            let prefabricated_adjusted =
                Self::wallets_and_balances_with_criteria_opt(Either::Right(&concise_input))
                    .right()
                    .expectv("criterion + wallet + balance");
            format!(
                "\n\
                {:<length$} {}\n\
                \n\
                {:<length$} {}\n\
                {:<length$} {}\n\
                \n\
                {}",
                "Account wallet",
                "Balance wei",
                "Adjusted payables",
                "Original",
                "",
                "Adjusted",
                Self::format_brief_adjustment_summary(
                    original_prefabricated,
                    prefabricated_adjusted
                ),
                length = WALLET_ADDRESS_LENGTH
            )
        }
    }

    fn log_adjustment_by_masq_required(logger: &Logger, payables_sum: u128, cw_masq_balance: u128) {
        warning!(
            logger,
            "Total of {} wei in MASQ was ordered while the consuming wallet held only {} wei of \
            the MASQ token. Adjustment in their count or the amounts is required.",
            payables_sum.separate_with_commas(),
            cw_masq_balance.separate_with_commas()
        );
        info!(logger, "{}", REFILL_RECOMMENDATION)
    }

    fn rebuild_accounts(criteria_and_accounts: Vec<(u128, PayableAccount)>) -> Vec<PayableAccount> {
        criteria_and_accounts
            .into_iter()
            .map(|(_, account)| account)
            .collect()
    }

    fn run_recursively(
        fully_qualified_accounts: Vec<PayableAccount>,
        collected_setup_data: FinancialAndTechDetails,
        gas_limitation_context_opt: Option<GasLimitationContext>,
        qualified_payables: Vec<PayableAccount>,
        now: SystemTime,
        logger: &Logger,
    ) -> (Vec<PayableAccount>, DebugInfoOpt) {
        let accounts_with_zero_criteria = Self::initialize_zero_criteria(qualified_payables);

        let accounts_with_individual_criteria =
            Self::apply_criteria(accounts_with_zero_criteria, now);

        let debug_info_opt = logger.debug_enabled().then(|| {
            accounts_with_individual_criteria
                .iter()
                .map(|(criterion, _)| *criterion)
                .collect()
        });

        let adjustment_result: AdjustmentIterationResult =
            match Self::give_the_job_to_adjustment_workers(
                gas_limitation_context_opt,
                accounts_with_individual_criteria,
                collected_setup_data
                    .consuming_wallet_balances
                    .masq_tokens_wei
                    .as_u128(),
                logger,
            ) {
                AdjustmentCompletion::Finished(accounts_adjusted) => {
                    return (accounts_adjusted, debug_info_opt)
                }
                AdjustmentCompletion::Continue(iteration_result) => iteration_result,
            };

        Self::log_info_for_disqualified_accounts(logger, &adjustment_result.disqualified_accounts);

        let adjusted_accounts = if adjustment_result.remaining_accounts.is_empty() {
            adjustment_result.decided_accounts
        } else {
            let adjusted_setup_data = Self::adjust_cw_balance_in_setup_data(
                collected_setup_data,
                &adjustment_result.decided_accounts,
                &adjustment_result.disqualified_accounts,
            );
            //TODO what happens if we choose one that will get us into negative when subtracted
            return Self::run_recursively(
                adjustment_result.decided_accounts,
                adjusted_setup_data,
                None,
                adjustment_result.remaining_accounts,
                now,
                logger,
            );
        };

        (
            fully_qualified_accounts
                .into_iter()
                .chain(adjusted_accounts.into_iter())
                .collect(),
            debug_info_opt,
        )
    }

    fn give_the_job_to_adjustment_workers(
        gas_limitation_context_opt: Option<GasLimitationContext>,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
        cw_masq_balance_wei: u128,
        logger: &Logger,
    ) -> AdjustmentCompletion {
        match gas_limitation_context_opt {
            Some(known_limits) => {
                let weighted_accounts_cut_by_gas = Self::cut_back_by_gas_count_limit(
                    accounts_with_individual_criteria,
                    known_limits.limited_count_from_gas,
                );
                match known_limits.is_masq_token_insufficient {
                    true => {
                        match Self::check_need_of_masq_balances_adjustment(
                            logger,
                            Either::Right(&weighted_accounts_cut_by_gas),
                            cw_masq_balance_wei,
                        ) {
                            Ok(is_needed) => match is_needed {
                                true => AdjustmentCompletion::Continue(
                                    Self::handle_masq_token_adjustment(
                                        cw_masq_balance_wei,
                                        weighted_accounts_cut_by_gas,
                                    ),
                                ),
                                false => AdjustmentCompletion::Finished(Self::rebuild_accounts(
                                    weighted_accounts_cut_by_gas,
                                )),
                            },
                            Err(e) => todo!(),
                        }
                    }
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

    fn log_insufficient_transaction_fee_balance(
        logger: &Logger,
        required_transactions_count: usize,
        this_stage_data: &FinancialAndTechDetails,
        limiting_count: u16,
    ) {
        warning!(
            logger,
            "Gas amount {} wei cannot cover anticipated fees from sending {} \
                transactions. Maximum is {}. The payments need to be adjusted in \
                their count.",
            this_stage_data
                .consuming_wallet_balances
                .masq_tokens_wei
                .separate_with_commas(),
            required_transactions_count,
            limiting_count
        );
        info!(logger, "{}", REFILL_RECOMMENDATION)
    }

    fn check_need_of_masq_balances_adjustment(
        logger: &Logger,
        qualified_payables: Either<&[PayableAccount], &[(u128, PayableAccount)]>,
        consuming_wallet_balance_wei: u128,
    ) -> Result<bool, AnalysisError> {
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
            Ok(false)
        } else if Self::find_smallest_debt(&qualified_payables) > consuming_wallet_balance_wei {
            todo!()
        } else {
            Self::log_adjustment_by_masq_required(
                logger,
                required_masq_sum,
                consuming_wallet_balance_wei,
            );
            Ok(true)
        }
    }
}

// replace with `account_1.balance_wei.checked_ilog10().unwrap() + 1`
// which will be introduced by Rust 1.67.0; this was written with 1.63.0
fn log_10(num: u128) -> usize {
    successors(Some(num), |&n| (n >= 10).then(|| n / 10)).count()
}

//saves the computed criteria
type DebugInfoOpt = Option<Vec<u128>>;

#[derive(Debug)]
struct AdjustmentIterationResult {
    decided_accounts: Vec<PayableAccount>,
    remaining_accounts: Vec<PayableAccount>,
    disqualified_accounts: Vec<DisqualifiedPayableAccount>,
}

#[derive(Debug, PartialEq, Eq)]
struct DecidedPayableAccount {
    adjusted_account: PayableAccount,
    former_balance: u128,
}

enum DecidedPayableAccountResolution {
    Finalize,
    Revert,
}

enum AdjustmentCompletion {
    Finished(Vec<PayableAccount>),
    Continue(AdjustmentIterationResult),
}

impl DecidedPayableAccount {
    fn new(adjusted_account: PayableAccount, former_balance: u128) -> Self {
        Self {
            adjusted_account,
            former_balance,
        }
    }
}

impl From<(DecidedPayableAccount, DecidedPayableAccountResolution)> for PayableAccount {
    fn from(
        (decided_account, resolution): (DecidedPayableAccount, DecidedPayableAccountResolution),
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
struct DisqualifiedPayableAccount {
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

#[derive(Debug)]
struct AccountAdjustmentDebugDetails {
    initial_balance: u128,
    adjusted_balance_opt: Option<u128>,
    used_criterion: u128,
}

impl AccountAdjustmentDebugDetails {
    fn new(initial_balance: u128) -> Self {
        AccountAdjustmentDebugDetails {
            initial_balance,
            adjusted_balance_opt: None,
            used_criterion: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Adjustment {
    MasqToken,
    Gas { limited_count_from_gas: u16 },
    Both { limited_count_from_gas: u16 },
}

#[derive(Clone, Copy)]
struct GasLimitationContext {
    limited_count_from_gas: u16,
    is_masq_token_insufficient: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {}

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::{
        log_10, Adjustment, DecidedPayableAccount, DisqualifiedPayableAccount, PaymentAdjuster,
        PaymentAdjusterReal, REFILL_RECOMMENDATION,
    };
    use crate::accountant::scanners::payable_scan_setup_msgs::{
        FinancialAndTechDetails, PayablePaymentSetup, StageData,
    };
    use crate::accountant::scanners::scan_mid_procedures::AwaitedAdjustment;
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, ResponseSkeleton};
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPaymentsInstructions,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use masq_lib::constants::MASQ_TOTAL_SUPPLY;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use std::vec;
    use thousands::Separable;
    use web3::types::U256;

    fn type_definite_conversion(gwei: u64) -> u128 {
        gwei_to_wei(gwei)
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(
            REFILL_RECOMMENDATION,
            "\
In order to continue using services of other Nodes and avoid delinquency \
bans you will need to put more funds into your consuming wallet."
        )
    }

    #[test]
    fn sum_payable_balances_works() {
        let qualified_payables = vec![
            make_payable_account(456),
            make_payable_account(1111),
            make_payable_account(7800),
        ];

        let result = PaymentAdjusterReal::sum_payable_balances(&qualified_payables);

        let expected_result = type_definite_conversion(456)
            + type_definite_conversion(1111)
            + type_definite_conversion(7800);
        assert_eq!(result, U256::from(expected_result))
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
                conditions.consuming_wallet_masq_gwei,
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
        consuming_wallet_masq_gwei: u64,
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
                consuming_wallet_masq_gwei: (111 * 5 * 53_000) + 1,
            }),
        );
        //gas balance = payments
        let msg_4 = make_payable_setup_msg_coming_from_blockchain_bridge(
            None,
            Some(GasTestConditions {
                desired_gas_price_gwei: 100,
                number_of_payments: 6,
                estimated_gas_limit_per_transaction: 53_000,
                consuming_wallet_masq_gwei: 100 * 6 * 53_000,
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
                consuming_wallet_masq_gwei: 100 * 3 * 55_000 - 1,
            }),
        );

        let result = subject.search_for_indispensable_adjustment(&msg, &logger);

        let expected_limiting_count = number_of_payments as u16 - 1;
        assert_eq!(
            result,
            Ok(Some(Adjustment::Gas {
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
    fn find_smallest_debt_works() {
        let mut payable_1 = make_payable_account(111);
        payable_1.balance_wei = 111_111;
        let mut payable_3 = make_payable_account(333);
        payable_3.balance_wei = 111_110;
        let mut payable_2 = make_payable_account(222);
        payable_2.balance_wei = 3_000_000;
        let qualified_payables = vec![payable_1, payable_2, payable_3];
        let referenced_qualified_payables = qualified_payables.iter().collect::<Vec<_>>();

        let min = PaymentAdjusterReal::find_smallest_debt(&referenced_qualified_payables);

        assert_eq!(min, 111_110)
    }

    #[test]
    fn find_smallest_debt_handles_just_one_account() {
        let payable = make_payable_account(111);
        let qualified_payables = vec![payable];
        let referenced_qualified_payables = qualified_payables.iter().collect::<Vec<_>>();

        let min = PaymentAdjusterReal::find_smallest_debt(&referenced_qualified_payables);

        assert_eq!(min, 111_000_000_000)
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
    fn multiplication_coeff_for_integers_to_be_above_one_instead_of_fractional_numbers() {
        let final_criteria_sum = 5_000_000_000_000_u128;
        let consuming_wallet_balances = vec![
            222_222_222_222_u128,
            100_000,
            123_456_789,
            5_555_000_000_000, //the only one bigger than the criteria sum
        ];

        let result = consuming_wallet_balances
            .clone()
            .into_iter()
            .map(|cw_balance| {
                PaymentAdjusterReal::find_multiplication_coeff(cw_balance, final_criteria_sum)
            })
            .collect::<Vec<u128>>();

        assert_eq!(
            result,
            vec![10_000_000, 10_000_000_000_000, 10_000_000_000, 1_000_000]
        )
    }

    #[test]
    fn recreate_accounts_with_proportioned_balances_accepts_exact_adjustment_by_half_but_not_by_more(
    ) {
        let mut payable_account_1 = make_payable_account(1);
        payable_account_1.balance_wei = 1_000_000;
        let mut payable_account_2 = make_payable_account(2);
        payable_account_2.balance_wei = 1_000_001;
        let proportional_fragment_of_cw_balance = 200_000;
        let multiplication_coeff = 10;
        let expected_adjusted_balance = 500_000;
        let criterion =
            expected_adjusted_balance * multiplication_coeff / proportional_fragment_of_cw_balance; // = 25
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

        let expected_decided_payable_account = DecidedPayableAccount {
            adjusted_account: PayableAccount {
                balance_wei: 500_000,
                ..payable_account_1
            },
            former_balance: 1_000_000,
        };
        let expected_disqualified_account = DisqualifiedPayableAccount {
            wallet: payable_account_2.wallet,
            proposed_adjusted_balance: 500_000,
            original_balance: 1_000_001,
        };
        assert_eq!(decided_accounts, vec![expected_decided_payable_account]);
        assert_eq!(disqualified_accounts, vec![expected_disqualified_account])
    }

    #[test]
    fn testing_criteria_on_overflow_safeness() {
        let now = SystemTime::now();
        let extremely_big_balance_wei = MASQ_TOTAL_SUPPLY as u128 * 10u128.pow(18);
        let very_long_period_of_time_sec = 5_u64 * 365 * 24 * 60 * 60; //five years
        let account = PayableAccount {
            wallet: make_wallet("blah"),
            balance_wei: extremely_big_balance_wei,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(very_long_period_of_time_sec))
                .unwrap(),
            pending_payable_opt: None,
        };
        let zero_criteria_accounts = PaymentAdjusterReal::initialize_zero_criteria(vec![account]);
        let criteria_and_accounts =
            PaymentAdjusterReal::apply_criteria(zero_criteria_accounts, now);
        assert_eq!(criteria_and_accounts.len(), 1);
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
    fn log_info_for_disqualified_accounts_can_log_multiple_accounts() {
        init_test_logging();
        let wallet_1 = make_wallet("abc");
        let wallet_2 = make_wallet("efg");
        let balance_1 = 456_789_012_345;
        let balance_2 = 222_444_777;
        let disqualified_accounts = vec![
            DisqualifiedPayableAccount {
                wallet: wallet_1.clone(),
                original_balance: 500_000_000_000,
                proposed_adjusted_balance: balance_1,
            },
            DisqualifiedPayableAccount {
                wallet: wallet_2.clone(),
                original_balance: 300_000_000,
                proposed_adjusted_balance: balance_2,
            },
        ];
        let logger = Logger::new("log_info_for_disqualified_accounts_can_log_multiple_accounts");

        PaymentAdjusterReal::log_info_for_disqualified_accounts(&logger, &disqualified_accounts);

        let make_expected_msg = |wallet: &Wallet, balance: u128| -> String {
            format!("Recently qualified payable for wallet {wallet} is being ignored as the limited consuming \
            balance implied adjustment of its balance down to {} wei, which is not at least half of the debt", balance.separate_with_commas())
        };
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &make_expected_msg(&wallet_1, balance_1),
            &make_expected_msg(&wallet_2, balance_2),
        ]);
    }

    #[test]
    fn small_debt_with_extreme_age_is_paid_prioritized_but_not_with_more_money_than_required() {
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

        let (result, _) = PaymentAdjusterReal::run_recursively(
            vec![],
            collected_setup_data,
            None,
            qualified_payables.clone(),
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
                account_2, //prioritized accounts take the first places
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance_wei: 1_499_949_712_293,
                    last_paid_timestamp: last_paid_timestamp_1,
                    pending_payable_opt: None,
                },
            ]
        );
    }

    #[test]
    fn adjust_payments_when_number_of_accounts_evens_the_final_transaction_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_number_of_accounts_evens_the_final_transaction_count";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 444_444_444_444_444_444,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1_234)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 666_666_666_666_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 22_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(50_000)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let subject = PaymentAdjusterReal::new();
        let accounts_sum: u128 =
            444_444_444_444_444_444 + 666_666_666_666_000_000 + 22_000_000_000_000; //= 1_000_022_000_000_444_444
        let consuming_wallet_masq_balance_wei = U256::from(accounts_sum - 6_000_000_000_000_000);
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
|0x0000000000000000000000000000000000646566 666666666666000000
|                                           663067295999338638
|0x0000000000000000000000000000000000616263 444444444444444444
|                                           442044864010984732
|0x000000000000000000000000000000000067686b 22000000000000
|                                           15053705795285"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
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
        let time_criteria = accounts
            .iter()
            .map(|account| {
                let elapsed = secs_elapsed(account.last_paid_timestamp, now);
                let criterion = elapsed.pow(4) / (((elapsed as f64).sqrt().ceil()) as u128);
                eprintln!("time criterion: {}", criterion.separate_with_commas());
                criterion
            })
            .collect();
        let amount_criteria = accounts
            .iter()
            .map(|account| {
                let significance = log_10(account.balance_wei) as u128;
                account.balance_wei * significance.pow(3)
            } as u128)
            .collect();

        let final_criteria = vec![time_criteria, amount_criteria].into_iter().fold(
            vec![0, 0, 0],
            |acc: Vec<u128>, current: Vec<u128>| {
                acc.into_iter()
                    .zip(current.into_iter())
                    .map(|(partial_acc, partial_current)| partial_acc + partial_current)
                    .collect()
            },
        );

        eprintln!("final criteria {:?}", final_criteria);
        let final_criteria_sum = final_criteria.iter().sum::<u128>();
        let multiplication_coeff = PaymentAdjusterReal::find_multiplication_coeff(
            consuming_wallet_masq_balance_wei,
            final_criteria_sum,
        );
        eprintln!(
            "emul: consuming balance for fragment computation: {}",
            consuming_wallet_masq_balance_wei
        );
        let in_ratio_fragment_of_available_balance = consuming_wallet_masq_balance_wei
            .checked_mul(multiplication_coeff)
            .unwrap()
            .checked_div(final_criteria_sum)
            .unwrap();

        eprintln!(
            "emulated in ration fragment: {}",
            in_ratio_fragment_of_available_balance
        );
        let balanced_portions = final_criteria
            .iter()
            .map(|criterion| {
                in_ratio_fragment_of_available_balance * criterion / multiplication_coeff
            })
            .collect::<Vec<u128>>();
        eprintln!("balanced portions: {:?}", balanced_portions);
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

    #[test]
    fn adjust_payments_when_only_gas_limits_the_final_transaction_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_only_gas_limits_the_final_transaction_count";
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
            adjustment: Adjustment::Gas {
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
        let account_1 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 333_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(12000)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 111_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(5000)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghk");
        let balance_3 = 50_000_000;
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
        assert!(
            account_3_adjusted_balance < (balance_3 / 2),
            "balance for account 3 after \
        adjustment from the first iteration is {} but we need it smaller than {}",
            account_3_adjusted_balance.separate_with_commas(),
            (balance_3 / 2).separate_with_commas()
        );
        let adjusted_cw_balance_after_prioritizing_one_account =
            consuming_wallet_masq_balance_wei.as_u128() - balance_3;
        let expected_accounts = emulation_of_the_actual_adjustment_algorithm(
            account_1,
            account_2,
            None,
            adjusted_cw_balance_after_prioritizing_one_account,
            now,
        );
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
        consuming balance implied adjustment of its balance down to 22,572,576 wei, which is not at \
        least half of the debt"));
    }

    #[test]
    fn adjust_payments_when_both_parameters_must_be_treated_but_masq_doesnt_cut_down_any_account_it_just_adjusts_the_balances(
    ) {
        init_test_logging();
        let test_name = "adjust_payments_when_gas_limits_the_final_transaction_count";
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
        let consuming_wallet_masq_balance = 111_000_000_000_000_u128 + 333_000_000_000_000;
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
            adjustment: Adjustment::Both {
                limited_count_from_gas: 2,
            },
        };

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        let expected_accounts = emulation_of_the_actual_adjustment_algorithm(
            account_2,
            account_3,
            None,
            consuming_wallet_masq_balance,
            now,
        );
        assert_eq!(
            result,
            OutcomingPaymentsInstructions {
                accounts: expected_accounts,
                response_skeleton_opt: None
            }
        );
    }

    #[test]
    fn adjust_payments_when_both_parameters_are_supposed_to_be_treated_but_masq_will_do_after_the_gas_cut(
    ) {
        init_test_logging();
        let test_name = "adjust_payments_when_both_parameters_are_supposed_to_be_treated_but_masq_will_do_after_the_gas_cut";
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
        let consuming_wallet_masq_balance = 333_000_000_000_000_u128 + 222_000_000_000_000 + 1;
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
            adjustment: Adjustment::Both {
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
    }

    #[test]
    fn adjust_payments_when_masq_as_well_as_gas_will_limit_the_count() {
        init_test_logging();
        let test_name = "adjust_payments_when_masq_as_well_as_gas_will_limit_the_count";
        let now = SystemTime::now();
        //thrown away by gas
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 44_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        //thrown away because not enough significant
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 55_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(3333)).unwrap(),
            pending_payable_opt: None,
        };
        let wallet_3 = make_wallet("ghk");
        let last_paid_timestamp_3 = now.checked_sub(Duration::from_secs(4444)).unwrap();
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
            adjustment: Adjustment::Both {
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
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Account wallet                             Balance wei
|
|Adjusted payables                          Original
|                                           Adjusted
|
|0x000000000000000000000000000000000067686b 333000000000000
|                                           299944910012241
|
|Ignored minor payables                     Original
|
|0x0000000000000000000000000000000000616263 44000000000
|0x0000000000000000000000000000000000646566 55000000000"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    fn secs_elapsed(timestamp: SystemTime, now: SystemTime) -> u128 {
        now.duration_since(timestamp).unwrap().as_secs() as u128
    }
}
