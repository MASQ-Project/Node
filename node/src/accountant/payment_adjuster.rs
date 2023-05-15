// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::ConsumingWalletBalancesAndQualifiedPayables;
use crate::sub_lib::blockchain_bridge::OutcomingPayamentsInstructions;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::any::Any;
use std::iter::{once, successors};
use std::time::SystemTime;
use web3::types::U256;

lazy_static! {
    static ref MULTI_COEFF_BY_100: U256 = U256::from(1000);
}

pub trait PaymentAdjuster {
    fn is_adjustment_required(&self, msg: &ConsumingWalletBalancesAndQualifiedPayables) -> bool;

    fn adjust_payments(
        &self,
        msg: ConsumingWalletBalancesAndQualifiedPayables,
        now: SystemTime,
    ) -> OutcomingPayamentsInstructions;

    declare_as_any!();
}

pub struct PaymentAdjusterReal {}

impl PaymentAdjuster for PaymentAdjusterReal {
    fn is_adjustment_required(&self, msg: &ConsumingWalletBalancesAndQualifiedPayables) -> bool {
        let sum = Self::sum_payable_balances(&msg.qualified_payables);
        let consuming_wallet_balance = msg.consuming_wallet_balances.masq_tokens_wei;
        if U256::from(sum) > consuming_wallet_balance {
            true
        } else if U256::from(Self::find_smallest_debt(&msg.qualified_payables))
            > consuming_wallet_balance
        {
            todo!()
        } else {
            false
        }
    }

    fn adjust_payments(
        &self,
        msg: ConsumingWalletBalancesAndQualifiedPayables,
        now: SystemTime,
    ) -> OutcomingPayamentsInstructions {
        //define individual criteria here; write closures to be used in sequence by multiple maps()
        type CriteriaClosure<'a> =
            Box<dyn FnMut((u128, PayableAccount)) -> (u128, PayableAccount) + 'a>;
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

        let qualified_payables = msg.qualified_payables;
        let accounts_count = qualified_payables.len();
        let endless_iter_with_accounts = qualified_payables.into_iter().cycle();
        let criteria_iter = {
            let one_element = once(0_u128);
            let endlessly_repeated = one_element.into_iter().cycle();
            endlessly_repeated.take(accounts_count)
        };

        // add your criteria to chained map() functions here
        let mid_computed_results = criteria_iter
            .zip(endless_iter_with_accounts)
            .map(time_criteria_closure)
            .map(balance_criteria_closure)
            .collect::<Vec<(u128, PayableAccount)>>();

        let criteria_sum: u128 = mid_computed_results
            .iter()
            .map(|(criteria, _)| criteria)
            .sum();
        let multiplication_coeff = PaymentAdjusterReal::find_multiplication_coeff(
            msg.consuming_wallet_balances.masq_tokens_wei,
            U256::from(criteria_sum),
        );
        let proportional_fragment_of_cw_balance =
            msg.consuming_wallet_balances.masq_tokens_wei.as_u128() * multiplication_coeff
                / criteria_sum;

        let rebuild_account = |(criteria_sum, mut account): (u128, PayableAccount)| {
            let proportional_amount_to_pay =
                criteria_sum * proportional_fragment_of_cw_balance / multiplication_coeff;
            account.balance_wei = proportional_amount_to_pay;
            account
        };

        let balance_adjusted_accounts = mid_computed_results
            .into_iter()
            .map(rebuild_account)
            .collect();

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

    fn find_multiplication_coeff(consuming_wallet_balance: U256, final_criteria_sum: U256) -> u128 {
        ((final_criteria_sum / consuming_wallet_balance) * *MULTI_COEFF_BY_100).as_u128()
    }
}

// replace with `account_1.balance_wei.checked_ilog10().unwrap() + 1`
// which will be introduced by Rust 1.67.0; this was written with 1.63.0
fn log_10(num: u128) -> usize {
    successors(Some(num), |&n| (n >= 10).then(|| n / 10)).count()
}

#[cfg(test)]
mod tests {
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::payment_adjuster::{
        log_10, PaymentAdjuster, PaymentAdjusterReal, MULTI_COEFF_BY_100,
    };
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, ConsumingWalletBalancesAndQualifiedPayables};
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, OutcomingPayamentsInstructions,
    };
    use crate::test_utils::make_wallet;
    use itertools::Itertools;
    use std::time::{Duration, SystemTime};
    use std::vec;
    use web3::types::U256;

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

    fn make_cw_balance_and_q_payables_msg(
        qualified_payables_balances_gwei: Vec<u64>,
        masq_balance_gwei: u64,
    ) -> ConsumingWalletBalancesAndQualifiedPayables {
        let qualified_payables = qualified_payables_balances_gwei
            .into_iter()
            .map(|balance| make_payable_account(balance))
            .collect();
        ConsumingWalletBalancesAndQualifiedPayables {
            qualified_payables,
            consuming_wallet_balances: ConsumingWalletBalances {
                gas_currency_wei: U256::zero(),
                masq_tokens_wei: gwei_to_wei(masq_balance_gwei),
            },
            response_skeleton_opt: None,
        }
    }

    #[test]
    fn is_adjustment_required_works_for_non_error_cases() {
        let subject = PaymentAdjusterReal::new();
        let msg_1 = make_cw_balance_and_q_payables_msg(vec![85, 14], 100);
        let msg_2 = make_cw_balance_and_q_payables_msg(vec![85, 15], 100);
        let msg_3 = make_cw_balance_and_q_payables_msg(vec![85, 16], 100);

        assert_eq!(subject.is_adjustment_required(&msg_1), false);
        assert_eq!(subject.is_adjustment_required(&msg_2), false);
        assert_eq!(subject.is_adjustment_required(&msg_3), true)
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
        let msg = ConsumingWalletBalancesAndQualifiedPayables {
            qualified_payables,
            consuming_wallet_balances: ConsumingWalletBalances {
                gas_currency_wei: U256::from(150),
                masq_tokens_wei: consuming_wallet_masq_balance,
            },
            response_skeleton_opt: None,
        };

        let result = subject.adjust_payments(msg, now);

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

        // Example of the current adjustment;
        // printed with `visual_check_balance_before_after(.., ..)`
        //
        // BEFORE
        // AFTER
        //
        // 444444444444444444
        // 333000000000000051
        // ---
        // 666666666666000000000000
        // 665999999999334000000004
        // ---
        // 22000000000000
        // 12820500003284
    }

    fn secs_elapsed(timestamp: SystemTime, now: SystemTime) -> u128 {
        now.duration_since(timestamp).unwrap().as_secs() as u128
    }

    #[test]
    fn output_with_response_skeleton_opt_some() {
        //TODO rather include into some other special test??
    }

    #[allow(dead_code)]
    fn visual_check_balance_before_after(
        accounts_before: &[PayableAccount],
        accounts_after: &[PayableAccount],
    ) {
        let sorting = |a: &&PayableAccount, b: &&PayableAccount| {
            Ord::cmp(&a.wallet.to_string(), &b.wallet.to_string())
        };
        accounts_before
            .into_iter()
            .sorted_by(sorting)
            .zip(accounts_after.into_iter().sorted_by(sorting))
            .for_each(|(original_payable, adjusted_payable)| {
                eprintln!(
                    "{}\n{}\n---",
                    original_payable.balance_wei, adjusted_payable.balance_wei
                )
            })
    }
}
