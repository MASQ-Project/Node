// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::ConsumingWalletBalancesAndQualifiedPayables;
use crate::sub_lib::blockchain_bridge::OutcomingPayamentsInstructions;
use itertools::Itertools;
use web3::types::U256;

pub trait PaymentAdjuster {
    fn is_adjustment_required(&self, msg: &ConsumingWalletBalancesAndQualifiedPayables) -> bool;

    fn adjust_payments(
        &self,
        msg: ConsumingWalletBalancesAndQualifiedPayables,
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
    ) -> OutcomingPayamentsInstructions {
        todo!()
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
}

#[cfg(test)]
mod tests {
    use crate::accountant::payment_adjuster::{PaymentAdjuster, PaymentAdjusterReal};
    use crate::accountant::test_utils::make_payable_account;
    use crate::accountant::{gwei_to_wei, ConsumingWalletBalancesAndQualifiedPayables};
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
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
}
