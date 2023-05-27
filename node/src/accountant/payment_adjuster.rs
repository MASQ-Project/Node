// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::payable_scan_setup_msgs::inter_actor_communication_for_payable_scanner::{
    ConsumingWalletBalancesAndGasPrice, PayablePaymentSetup,
};
use crate::accountant::{comma_joined_stringifiable, gwei_to_wei};
use crate::sub_lib::blockchain_bridge::OutcomingPayamentsInstructions;
use itertools::Itertools;
use lazy_static::lazy_static;
use masq_lib::logger::Logger;
use std::any::Any;
use std::iter::{once, successors};
use std::time::SystemTime;
use thousands::Separable;
use web3::types::U256;
use crate::accountant::scan_mid_procedures::AwaitingAdjustment;

lazy_static! {
    static ref MULTI_COEFF_BY_100: U256 = U256::from(1000);
}

pub trait PaymentAdjuster {
    fn is_adjustment_required(
        &self,
        msg: &PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError>;

    fn adjust_payments(
        &self,
        setup: AwaitingAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPayamentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn is_adjustment_required(
        &self,
        msg: &PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        let qualified_payables = msg.qualified_payables.as_slice();
        let sum = Self::sum_as_u256(qualified_payables, |payable| payable.balance_wei);
        let cw_masq_balance = msg
            .this_stage_data
            .consuming_wallet_balances
            .masq_tokens_wei;

        let required_by_masq_token = if U256::from(sum) <= cw_masq_balance {
            false
        } else if U256::from(Self::find_smallest_debt(qualified_payables)) > cw_masq_balance {
            todo!()
        } else {
            Self::log_adjustment_required(logger, qualified_payables, sum, cw_masq_balance);

            true
        };

        let total_gas_required = gwei_to_wei::<U256, _>(
            qualified_payables.len() as u64 * msg.this_stage_data.desired_gas_price,
        );
        eprintln!("total gas required {}", total_gas_required);
        eprintln!("cons balance {:?}", msg.this_stage_data.consuming_wallet_balances.gas_currency_wei);
        let required_by_gas = if total_gas_required
            <= msg
                .this_stage_data
                .consuming_wallet_balances
                .gas_currency_wei
        {
            //TODO drive in both < and =
            false
        } else {
            todo!()
        };

        match (required_by_masq_token, required_by_gas){
            (false, false) => Ok(None),
            (true, false) => Ok(Some(Adjustment::MasqToken)),
            (false, true) => todo!(),
            (true, true) => todo!()
        }
    }

    fn adjust_payments(
        &self,
        setup: AwaitingAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutcomingPayamentsInstructions {
        let msg = setup.original_msg;
        let current_stage_data = msg.this_stage_data;
        let qualified_payables: Vec<PayableAccount> = msg.qualified_payables;
        let debug_log_printer_opt =
            logger
                .debug_enabled()
                .then_some(Self::before_and_after_debug_msg_formatter(
                    &qualified_payables,
                ));

        let accounts_with_zero_criteria = Self::initialize_zero_criteria(qualified_payables);
        let accounts_with_individual_criteria =
            Self::apply_criteria(accounts_with_zero_criteria, now);
        let balance_adjusted_accounts = Self::handle_adjustment(
            current_stage_data.consuming_wallet_balances.masq_tokens_wei,
            accounts_with_individual_criteria,
        );

        debug!(
            logger,
            "{}",
            debug_log_printer_opt.expect("debug message missing")(&balance_adjusted_accounts)
        );

        OutcomingPayamentsInstructions {
            accounts: balance_adjusted_accounts,
            response_skeleton_opt: msg.response_skeleton_opt,
        }
    }

    implement_as_any!();
}

impl PaymentAdjusterReal {
    pub fn new() -> Self {
        Self {}
    }

    fn sum_as_u256<T, F>(collection: &[T], arranger: F) -> U256
    where
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

    fn find_smallest_debt(qualified_accounts: &[PayableAccount]) -> U256 {
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

    fn find_multiplication_coeff(cw_masq_balance: U256, criteria_sum: U256) -> u128 {
        ((criteria_sum / cw_masq_balance) * *MULTI_COEFF_BY_100).as_u128()
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
    ) -> Vec<PayableAccount> {
        let rebuild_account = |(criteria_sum, mut account): (u128, PayableAccount)| {
            let proportional_amount_to_pay =
                criteria_sum * proportional_fragment_of_cw_balance / multiplication_coeff;
            account.balance_wei = proportional_amount_to_pay;
            account
        };

        accounts_with_individual_criteria
            .into_iter()
            .map(rebuild_account)
            .collect()
    }

    fn handle_adjustment(
        cw_masq_balance: U256,
        accounts_with_individual_criteria: Vec<(u128, PayableAccount)>,
    ) -> Vec<PayableAccount> {
        let criteria_sum =
            Self::sum_as_u256(&accounts_with_individual_criteria, |(criteria, _)| {
                *criteria
            });
        let multiplication_coeff =
            PaymentAdjusterReal::find_multiplication_coeff(cw_masq_balance, criteria_sum);
        let proportional_fragment_of_cw_balance =
            cw_masq_balance.as_u128() * multiplication_coeff / criteria_sum.as_u128();

        Self::recreate_accounts_with_proportioned_balances(
            accounts_with_individual_criteria,
            proportional_fragment_of_cw_balance,
            multiplication_coeff,
        )
    }

    fn apply_criteria(
        accounts_with_zero_criteria: impl Iterator<Item = (u128, PayableAccount)>,
        now: SystemTime,
    ) -> Vec<(u128, PayableAccount)> {
        type CriteriaClosure<'a> =
            Box<dyn FnMut((u128, PayableAccount)) -> (u128, PayableAccount) + 'a>;
        //define individual criteria as closures to be used in a map()

        let time_criteria_closure: CriteriaClosure = Box::new(|(criteria_sum, account)| {
            let criteria = now
                .duration_since(account.last_paid_timestamp)
                .expect("time traveller")
                .as_secs() as u128;
            (criteria_sum + criteria, account)
        });
        let balance_criteria_closure: CriteriaClosure = Box::new(|(criteria_sum, account)| {
            let digits_weight = log_10(account.balance_wei);
            let additional_criteria = account.balance_wei * digits_weight as u128;
            (criteria_sum + additional_criteria, account)
        });

        accounts_with_zero_criteria
            .map(time_criteria_closure)
            .map(balance_criteria_closure)
            .collect()
    }

    fn format_brief_accounts_summary(
        original_accounts: impl Iterator<Item = String>,
        adjusted_accounts: impl Iterator<Item = String>,
    ) -> String {
        original_accounts
            .zip(adjusted_accounts)
            .map(|(original, adjusted)| format!("{}\n{}", original, adjusted))
            .join("\n")
    }

    fn prefabricated_formatted_accounts<'a>(
        accounts: &'a [PayableAccount],
        display_wallet: bool,
    ) -> impl Iterator<Item = String> + 'a {
        accounts.iter().map(move |account| {
            let wallet_opt = if display_wallet {
                Some(account.wallet.to_string())
            } else {
                None
            };
            format!(
                "{:<42} {}",
                wallet_opt.as_ref().map(|w| w.as_str()).unwrap_or(""),
                account.balance_wei
            )
        })
    }

    fn before_and_after_debug_msg_formatter(
        original: &[PayableAccount],
    ) -> impl FnOnce(&[PayableAccount]) -> String {
        let original_prefabricated =
            Self::prefabricated_formatted_accounts(original, true).collect::<Vec<String>>();
        move |adjusted_accounts: &[PayableAccount]| {
            let prefabricated_adjusted =
                Self::prefabricated_formatted_accounts(adjusted_accounts, false);
            format!(
                "\nAdjusted payables:\n\
                {:<42} {}\n\
                {: <42} {}\n\
                {: <42} {}\n\
                \n\
                {}",
                "Account wallet",
                "Balance wei",
                "",
                "Original",
                "",
                "Adjusted",
                Self::format_brief_accounts_summary(
                    original_prefabricated.into_iter(),
                    prefabricated_adjusted
                )
            )
            //TODO mention accounts that will be excluded completely
        }
    }

    fn log_adjustment_required(
        logger: &Logger,
        payables: &[PayableAccount],
        payables_sum: U256,
        cw_masq_balance: U256,
    ) {
        warning!(
            logger,
            "Payments for wallets {} make total of {} wei while the consuming wallet holds \
            only {} wei. Going to adjust them to fit in the limit, by cutting back the number \
            of payments or their size.",
            comma_joined_stringifiable(payables, |p| p.wallet.to_string()),
            payables_sum.separate_with_commas(),
            cw_masq_balance.separate_with_commas()
        )
    }
}

// replace with `account_1.balance_wei.checked_ilog10().unwrap() + 1`
// which will be introduced by Rust 1.67.0; this was written with 1.63.0
fn log_10(num: u128) -> usize {
    successors(Some(num), |&n| (n >= 10).then(|| n / 10)).count()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Adjustment {
    MasqToken,
    Gas,
    Both,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnalysisError {}

#[cfg(test)]
mod tests {
    use crate::accountant::gwei_to_wei;
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::{log_10, PaymentAdjuster, PaymentAdjusterReal, MULTI_COEFF_BY_100, Adjustment};
    use crate::accountant::test_utils::make_payable_account;
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPayamentsInstructions,
    };
    use crate::test_utils::make_wallet;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::time::{Duration, SystemTime};
    use std::vec;
    use web3::types::U256;
    use crate::accountant::payable_scan_setup_msgs::inter_actor_communication_for_payable_scanner::{ConsumingWalletBalancesAndGasPrice, PayablePaymentSetup};
    use crate::accountant::scan_mid_procedures::AwaitingAdjustment;

    fn type_definite_conversion(gwei: u64) -> u128 {
        gwei_to_wei(gwei)
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

    fn make_msg_with_q_payables_cw_balance_and_gas_price(
        q_payables_gwei_and_cw_balance_gwei_opt: Option<(Vec<u64>, u64)>,
        gas_price_opt: Option<GasTestConditions>,
    ) -> PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice> {
        let (qualified_payables_gwei, consuming_wallet_masq_gwei) =
            q_payables_gwei_and_cw_balance_gwei_opt.unwrap_or((vec![1, 1], u64::MAX));

        let (desired_gas_price, number_of_payments, cw_balance_gas_gwei) = match gas_price_opt {
            Some(conditions) => (
                conditions.desired_gas_price_gwei,
                conditions.number_of_payments,
                conditions.consuming_wallet_masq_gwei,
            ),
            None => (120, qualified_payables_gwei.len(), u64::MAX),
        };

        let qualified_payables = match number_of_payments != qualified_payables_gwei.len() {
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
            this_stage_data: ConsumingWalletBalancesAndGasPrice {
                consuming_wallet_balances: ConsumingWalletBalances {
                    gas_currency_wei: gwei_to_wei(cw_balance_gas_gwei),
                    masq_tokens_wei: gwei_to_wei(consuming_wallet_masq_gwei),
                },
                desired_gas_price,
            },
            response_skeleton_opt: None,
        }
    }

    struct GasTestConditions {
        desired_gas_price_gwei: u64,
        number_of_payments: usize,
        consuming_wallet_masq_gwei: u64,
    }

    #[test]
    fn is_adjustment_required_negative_answer() {
        init_test_logging();
        let test_name = "is_adjustment_required_negative_answer";
        let subject = PaymentAdjusterReal::new();
        let logger = Logger::new(test_name);
        //masq balance > payments
        let msg_1 =
            make_msg_with_q_payables_cw_balance_and_gas_price(Some((vec![85, 14], 100)), None);
        //masq balance = payments
        let msg_2 =
            make_msg_with_q_payables_cw_balance_and_gas_price(Some((vec![85, 15], 100)), None);
        //gas balance > payments
        let msg_3 =
            make_msg_with_q_payables_cw_balance_and_gas_price(None, Some(GasTestConditions{
                desired_gas_price_gwei: 111,
                number_of_payments: 5,
                consuming_wallet_masq_gwei: 556,
            }));
        //gas balance = payments
        let msg_4 =
            make_msg_with_q_payables_cw_balance_and_gas_price(None, Some(GasTestConditions{
                desired_gas_price_gwei: 100,
                number_of_payments: 6,
                consuming_wallet_masq_gwei: 600,
            }));

        [msg_1,msg_2,msg_3,msg_4].into_iter().for_each(|msg| assert_eq!(subject.is_adjustment_required(&msg, &logger), Ok(None), "failed for msg {:?}", msg));

        TestLogHandler::new().exists_no_log_containing(&format!("WARN: {test_name}:"));
    }

    #[test]
    fn is_adjustment_required_positive_for_masq_token() {
        init_test_logging();
        let test_name = "is_adjustment_required_positive_for_masq_token";
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();
        let msg =
            make_msg_with_q_payables_cw_balance_and_gas_price(Some((vec![85, 16], 100)), None);

        let result = subject.is_adjustment_required(&msg, &logger);

        assert_eq!(result, Ok(Some(Adjustment::MasqToken)));
        TestLogHandler::new().exists_log_containing(&format!("WARN: {test_name}: Payments for wallets \
        0x00000000000000000000000077616c6c65743835, 0x00000000000000000000000077616c6c65743136 make \
        total of 101,000,000,000 wei while the consuming wallet holds only 100,000,000,000 wei. \
        Going to adjust them to fit in the limit, by cutting back the number of payments or their \
        size."));
    }

    #[test]
    fn is_adjustment_required_positive_for_gas() {
        init_test_logging();
        let test_name = "is_adjustment_required_positive_for_gas";
        let logger = Logger::new(test_name);
        let subject = PaymentAdjusterReal::new();
        let msg =
            make_msg_with_q_payables_cw_balance_and_gas_price(None, Some(GasTestConditions{
                desired_gas_price_gwei: 100,
                number_of_payments: 3,
                consuming_wallet_masq_gwei: 299,
            }));

        let result = subject.is_adjustment_required(&msg, &logger);

        assert_eq!(result, Ok(Some(Adjustment::MasqToken)));
        TestLogHandler::new().exists_log_containing(&format!("WARN: {test_name}: Payments for wallets \
        0x00000000000000000000000077616c6c65743835, 0x00000000000000000000000077616c6c65743136 would \
        require 100 gwei wei while the consuming wallet holds only 100,000,000,000 wei. \
        Going to adjust them to fit in the limit, by cutting back the number of payments or their \
        size."));
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

        let min = PaymentAdjusterReal::find_smallest_debt(&qualified_payables);

        assert_eq!(min, U256::from(111_110))
    }

    #[test]
    fn find_smallest_debt_handles_just_one_account() {
        let payable = make_payable_account(111);
        let qualified_payables = vec![payable];

        let min = PaymentAdjusterReal::find_smallest_debt(&qualified_payables);

        assert_eq!(min, U256::from(111_000_000_000_u128))
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
    fn multiplication_coeff_to_get_integers_above_one_instead_of_fractional_numbers_works() {
        let final_criteria_sum = U256::from(5_000_000_000_000_u64);
        let consuming_wallet_balances = vec![
            U256::from(222_222_222_222_u64),
            U256::from(100_000),
            U256::from(123_456_789),
        ];

        let result = consuming_wallet_balances
            .clone()
            .into_iter()
            .map(|cw_balance| {
                PaymentAdjusterReal::find_multiplication_coeff(cw_balance, final_criteria_sum)
            })
            .collect::<Vec<u128>>();

        let expected_coefficients = {
            let co_1 = ((final_criteria_sum / consuming_wallet_balances[0]) * *MULTI_COEFF_BY_100)
                .as_u128();
            assert_eq!(co_1, 22_000);
            let co_2 = ((final_criteria_sum / consuming_wallet_balances[1]) * *MULTI_COEFF_BY_100)
                .as_u128();
            assert_eq!(co_2, 50_000_000_000);
            let co_3 = ((final_criteria_sum / consuming_wallet_balances[2]) * *MULTI_COEFF_BY_100)
                .as_u128();
            assert_eq!(co_3, 40_500_000);
            vec![co_1, co_2, co_3]
        };
        assert_eq!(result, expected_coefficients)
    }

    #[test]
    fn adjust_payments_works() {
        init_test_logging();
        let test_name = "adjust_payments_works";
        let now = SystemTime::now();
        let account_1 = PayableAccount {
            wallet: make_wallet("abc"),
            balance_wei: 444_444_444_444_444_444,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(1234)).unwrap(),
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: make_wallet("def"),
            balance_wei: 666_666_666_666_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(100)).unwrap(),
            pending_payable_opt: None,
        };
        let account_3 = PayableAccount {
            wallet: make_wallet("ghk"),
            balance_wei: 22_000_000_000_000,
            last_paid_timestamp: now.checked_sub(Duration::from_secs(78910)).unwrap(),
            pending_payable_opt: None,
        };
        let qualified_payables = vec![account_1.clone(), account_2.clone(), account_3.clone()];
        let subject = PaymentAdjusterReal::new();
        let accounts_sum: u128 =
            444_444_444_444_444_444 + 666_666_666_666_000_000_000_000 + 22_000_000_000_000; //= 666_667_111_132_444_444_444_444
        let consuming_wallet_masq_balance = U256::from(accounts_sum - 600_000_000_000_000_000);
        let setup_msg =  PayablePaymentSetup {
            qualified_payables,
            this_stage_data: ConsumingWalletBalancesAndGasPrice {
                consuming_wallet_balances: ConsumingWalletBalances {
                    gas_currency_wei: U256::from(150),
                    masq_tokens_wei: consuming_wallet_masq_balance,
                },
                desired_gas_price: 222222222222222222,
            },
            response_skeleton_opt: None,
        };
        let adjustment_setup = AwaitingAdjustment{ original_msg: setup_msg, adjustment: Adjustment::MasqToken }; //TODO what to do with the required adjustment?

        let result = subject.adjust_payments(adjustment_setup, now, &Logger::new(test_name));

        let expected_criteria_computation_output = {
            let time_criteria = vec![
                secs_elapsed(account_1.last_paid_timestamp, now),
                secs_elapsed(account_2.last_paid_timestamp, now),
                secs_elapsed(account_3.last_paid_timestamp, now),
            ];
            let amount_criteria = vec![
                account_1.balance_wei * log_10(account_1.balance_wei) as u128,
                account_2.balance_wei * log_10(account_2.balance_wei) as u128,
                account_3.balance_wei * log_10(account_3.balance_wei) as u128,
            ];
            let final_criteria = vec![time_criteria, amount_criteria].into_iter().fold(
                vec![0, 0, 0],
                |acc: Vec<u128>, current| {
                    vec![
                        acc[0] + current[0],
                        acc[1] + current[1],
                        acc[2] + current[2],
                    ]
                },
            );
            let final_criteria_sum = U256::from(final_criteria.iter().sum::<u128>());
            let multiplication_coeff = PaymentAdjusterReal::find_multiplication_coeff(
                consuming_wallet_masq_balance,
                final_criteria_sum,
            );
            let in_ratio_fragment_of_available_balance = (consuming_wallet_masq_balance
                * U256::from(multiplication_coeff)
                / final_criteria_sum)
                .as_u128();
            let balanced_portions = vec![
                in_ratio_fragment_of_available_balance * final_criteria[0] / multiplication_coeff,
                in_ratio_fragment_of_available_balance * final_criteria[1] / multiplication_coeff,
                in_ratio_fragment_of_available_balance * final_criteria[2] / multiplication_coeff,
            ];
            let new_total_amount_to_pay = balanced_portions.iter().sum::<u128>();
            assert!(new_total_amount_to_pay <= consuming_wallet_masq_balance.as_u128());
            assert!(
                new_total_amount_to_pay >= (consuming_wallet_masq_balance.as_u128() * 100) / 102,
                "new total amount to pay: {}, consuming wallet masq balance: {}",
                new_total_amount_to_pay,
                consuming_wallet_masq_balance
            );
            let mut account_1_adjusted = account_1;
            account_1_adjusted.balance_wei = balanced_portions[0];
            let mut account_2_adjusted = account_2;
            account_2_adjusted.balance_wei = balanced_portions[1];
            let mut account_3_adjusted = account_3;
            account_3_adjusted.balance_wei = balanced_portions[2];
            vec![account_1_adjusted, account_2_adjusted, account_3_adjusted]
        };
        assert_eq!(
            result,
            OutcomingPayamentsInstructions {
                accounts: expected_criteria_computation_output,
                response_skeleton_opt: None
            }
        );
        let log_msg = format!(
            "DEBUG: {test_name}: \n\
|Adjusted payables:
|Account wallet                             Balance wei
|                                           Original
|                                           Adjusted
|
|0x0000000000000000000000000000000000616263 444444444444444444
|                                           333000000000000051
|0x0000000000000000000000000000000000646566 666666666666000000000000
|                                           665999999999334000000004
|0x000000000000000000000000000000000067686b 22000000000000
|                                           12820500003284"
        );
        TestLogHandler::new().exists_log_containing(&log_msg.replace("|", ""));
    }

    fn secs_elapsed(timestamp: SystemTime, now: SystemTime) -> u128 {
        now.duration_since(timestamp).unwrap().as_secs() as u128
    }

    #[test]
    fn output_with_response_skeleton_opt_some() {
        todo!("rather include into some other special test??")
    }
}
