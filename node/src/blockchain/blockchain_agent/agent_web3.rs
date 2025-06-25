// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scanner_extension::msgs::{
    PricedQualifiedPayables, QualifiedPayablesWithGasPrice, UnpricedQualifiedPayables,
};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use masq_lib::blockchains::chains::Chain;

#[derive(Debug, Clone)]
pub struct BlockchainAgentWeb3 {
    latest_gas_price_wei: u128,
    gas_limit_const_part: u128,
    consuming_wallet: Wallet,
    consuming_wallet_balances: ConsumingWalletBalances,
    chain: Chain,
}

impl BlockchainAgent for BlockchainAgentWeb3 {
    fn price_qualified_payables(
        &self,
        qualified_payables: UnpricedQualifiedPayables,
    ) -> PricedQualifiedPayables {
        let priced_qualified_payables = qualified_payables
            .payables
            .into_iter()
            .map(|payable_without_gas_price| {
                let selected_gas_price_wei =
                    match payable_without_gas_price.previous_attempt_gas_price_minor_opt {
                        None => self.latest_gas_price_wei,
                        Some(previous_price) if self.latest_gas_price_wei < previous_price => {
                            previous_price
                        }
                        Some(_) => self.latest_gas_price_wei,
                    };

                let gas_price_increased_by_margin_wei =
                    increase_gas_price_by_margin(selected_gas_price_wei);

                let price_ceiling = self.chain.rec().gas_price_safe_ceiling_minor;
                let checked_gas_price_wei = if gas_price_increased_by_margin_wei > price_ceiling {
                    price_ceiling
                } else {
                    gas_price_increased_by_margin_wei
                };

                QualifiedPayablesWithGasPrice::new(
                    payable_without_gas_price.payable,
                    checked_gas_price_wei,
                )
            })
            .collect();
        PricedQualifiedPayables {
            payables: priced_qualified_payables,
        }
    }

    fn estimated_transaction_fee_total(
        &self,
        qualified_payables: &PricedQualifiedPayables,
    ) -> u128 {
        let prices_sum: u128 = qualified_payables
            .payables
            .iter()
            .map(|priced_payable| priced_payable.gas_price_minor)
            .sum();
        (self.gas_limit_const_part + WEB3_MAXIMAL_GAS_LIMIT_MARGIN) * prices_sum
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        self.consuming_wallet_balances
    }

    fn consuming_wallet(&self) -> &Wallet {
        &self.consuming_wallet
    }

    fn get_chain(&self) -> Chain {
        self.chain
    }
}

// 64 * (64 - 12) ... std transaction has data of 64 bytes and 12 bytes are never used with us;
// each non-zero byte costs 64 units of gas
pub const WEB3_MAXIMAL_GAS_LIMIT_MARGIN: u128 = 3328;

impl BlockchainAgentWeb3 {
    pub fn new(
        latest_gas_price_wei: u128,
        gas_limit_const_part: u128,
        consuming_wallet: Wallet,
        consuming_wallet_balances: ConsumingWalletBalances,
        chain: Chain,
    ) -> BlockchainAgentWeb3 {
        Self {
            latest_gas_price_wei,
            gas_limit_const_part,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        PricedQualifiedPayables, QualifiedPayablesBeforeGasPriceSelection,
        QualifiedPayablesWithGasPrice, UnpricedQualifiedPayables,
    };
    use crate::accountant::test_utils::{
        make_payable_account, make_unpriced_qualified_payables_for_retry_mode,
    };
    use crate::blockchain::blockchain_agent::agent_web3::{
        BlockchainAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::blockchain::blockchain_agent::BlockchainAgent;
    use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::make_wallet;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3_328)
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_new_payable_scan() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let qualified_payables_without_price =
            UnpricedQualifiedPayables::from(vec![account_1.clone(), account_2.clone()]);
        let rpc_gas_price_wei = 555_666_777;
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let priced_qualified_payables =
            subject.price_qualified_payables(qualified_payables_without_price);

        let gas_price_with_margin_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let expected_result = PricedQualifiedPayables {
            payables: vec![
                QualifiedPayablesWithGasPrice::new(account_1, gas_price_with_margin_wei),
                QualifiedPayablesWithGasPrice::new(account_2, gas_price_with_margin_wei),
            ],
        };
        assert_eq!(priced_qualified_payables, expected_result);
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_retry_payable_scan() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let rpc_gas_price_wei = 444_555_666;
        let chain = TEST_DEFAULT_CHAIN;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let account_3 = make_payable_account(56);
        let account_4 = make_payable_account(78);
        let account_5 = make_payable_account(90);
        let qualified_payables_without_price = UnpricedQualifiedPayables {
            payables: vec![
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_1.clone(),
                    Some(rpc_gas_price_wei - 1),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_2.clone(),
                    Some(rpc_gas_price_wei),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_3.clone(),
                    Some(rpc_gas_price_wei + 1),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_4.clone(),
                    Some(rpc_gas_price_wei - 123_456),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_5.clone(),
                    Some(rpc_gas_price_wei + 456_789),
                ),
            ],
        };
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let priced_qualified_payables =
            subject.price_qualified_payables(qualified_payables_without_price);

        let expected_result = {
            let gas_price_account_wei_1 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_2 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_3 = increase_gas_price_by_margin(rpc_gas_price_wei + 1);
            let gas_price_account_wei_4 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_5 = increase_gas_price_by_margin(rpc_gas_price_wei + 456_789);
            PricedQualifiedPayables {
                payables: vec![
                    QualifiedPayablesWithGasPrice::new(account_1, gas_price_account_wei_1),
                    QualifiedPayablesWithGasPrice::new(account_2, gas_price_account_wei_2),
                    QualifiedPayablesWithGasPrice::new(account_3, gas_price_account_wei_3),
                    QualifiedPayablesWithGasPrice::new(account_4, gas_price_account_wei_4),
                    QualifiedPayablesWithGasPrice::new(account_5, gas_price_account_wei_5),
                ],
            }
        };
        assert_eq!(priced_qualified_payables, expected_result);
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_a_border_value() {
        let chain = TEST_DEFAULT_CHAIN;
        let default_gas_price_margin_percents = chain.rec().gas_price_default_margin_percents;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is
        // applied.
        // Adding just 1 didn't work, therefore 2
        let rpc_gas_price_wei =
            ((ceiling_gas_price_wei * 100) / (default_gas_price_margin_percents as u128 + 100)) + 2;
        let check_value_wei = increase_gas_price_by_margin(rpc_gas_price_wei);

        test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
            chain,
            rpc_gas_price_wei,
        );

        assert!(
            check_value_wei > ceiling_gas_price_wei,
            "should be {} > {} but isn't",
            check_value_wei,
            ceiling_gas_price_wei
        );
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_a_bit_bigger_even_with_no_margin() {
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;

        test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
            chain,
            ceiling_gas_price_wei + 1,
        );
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_just_gigantic() {
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;

        test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
            chain,
            10 * ceiling_gas_price_wei,
        );
    }

    fn test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
        chain: Chain,
        rpc_gas_price_wei: u128,
    ) {
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let qualified_payables =
            UnpricedQualifiedPayables::from(vec![account_1.clone(), account_2.clone()]);
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        let expected_result = PricedQualifiedPayables {
            payables: vec![
                QualifiedPayablesWithGasPrice::new(account_1, ceiling_gas_price_wei),
                QualifiedPayablesWithGasPrice::new(account_2, ceiling_gas_price_wei),
            ],
        };
        assert_eq!(priced_qualified_payables, expected_result);
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_border_value_if_the_latest_fetch_being_bigger() {
        let chain = TEST_DEFAULT_CHAIN;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let default_gas_price_margin_percents = chain.rec().gas_price_default_margin_percents;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is
        // applied.
        // Adding just 1 didn't work, therefore 2
        let rpc_gas_price_wei =
            (ceiling_gas_price_wei * 100) / (default_gas_price_margin_percents as u128 + 100) + 2;
        let check_value_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), rpc_gas_price_wei - 1),
            (account_2.clone(), rpc_gas_price_wei - 2),
        ]);

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            chain,
            rpc_gas_price_wei,
            raw_qualified_payables,
        );

        assert!(
            check_value_wei > ceiling_gas_price_wei,
            "should be {} > {} but isn't",
            check_value_wei,
            ceiling_gas_price_wei
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_border_value_if_the_previous_attempt_being_bigger()
    {
        let chain = TEST_DEFAULT_CHAIN;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let default_gas_price_margin_percents = chain.rec().gas_price_default_margin_percents;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is applied
        let border_gas_price_wei =
            (ceiling_gas_price_wei * 100) / (default_gas_price_margin_percents as u128 + 100) + 2;
        let rpc_gas_price_wei = border_gas_price_wei - 1;
        let check_value_wei = increase_gas_price_by_margin(border_gas_price_wei);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), border_gas_price_wei),
            (account_2.clone(), border_gas_price_wei),
        ]);

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            chain,
            rpc_gas_price_wei,
            raw_qualified_payables,
        );

        assert!(check_value_wei > ceiling_gas_price_wei);
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_big_value_if_the_latest_fetch_being_bigger() {
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let fetched_gas_price_wei = ceiling_gas_price_wei - 1;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), fetched_gas_price_wei - 1),
            (account_2.clone(), fetched_gas_price_wei - 2),
        ]);

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            chain,
            fetched_gas_price_wei,
            raw_qualified_payables,
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_big_value_if_the_previous_attempt_being_bigger() {
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), ceiling_gas_price_wei - 1),
            (account_2.clone(), ceiling_gas_price_wei - 2),
        ]);

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            chain,
            ceiling_gas_price_wei - 3,
            raw_qualified_payables,
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_giant_value_for_the_latest_fetch() {
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let fetched_gas_price_wei = 10 * ceiling_gas_price_wei;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        // The values can never go above the ceiling, therefore, we can assume only values even or
        // smaller than that in the previous attempts
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), ceiling_gas_price_wei),
            (account_2.clone(), ceiling_gas_price_wei),
        ]);

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            chain,
            fetched_gas_price_wei,
            raw_qualified_payables,
        );
    }

    fn test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
        chain: Chain,
        rpc_gas_price_wei: u128,
        qualified_payables: UnpricedQualifiedPayables,
    ) {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let expected_priced_payables = PricedQualifiedPayables {
            payables: qualified_payables
                .payables
                .clone()
                .into_iter()
                .map(|payable| {
                    QualifiedPayablesWithGasPrice::new(payable.payable, ceiling_gas_price_wei)
                })
                .collect(),
        };
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );

        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        assert_eq!(priced_qualified_payables, expected_priced_payables);
    }

    #[test]
    fn returns_correct_non_computed_values() {
        let gas_limit_const_part = 44_000;
        let consuming_wallet = make_wallet("abcde");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::from(456_789),
            masq_token_balance_in_minor_units: U256::from(123_000_000),
        };

        let subject = BlockchainAgentWeb3::new(
            222_333_444,
            gas_limit_const_part,
            consuming_wallet.clone(),
            consuming_wallet_balances,
            TEST_DEFAULT_CHAIN,
        );

        assert_eq!(subject.consuming_wallet(), &consuming_wallet);
        assert_eq!(
            subject.consuming_wallet_balances(),
            consuming_wallet_balances
        );
        assert_eq!(subject.get_chain(), TEST_DEFAULT_CHAIN);
    }

    #[test]
    fn estimated_transaction_fee_works_for_new_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let chain = TEST_DEFAULT_CHAIN;
        let qualified_payables = UnpricedQualifiedPayables::from(vec![account_1, account_2]);
        let subject = BlockchainAgentWeb3::new(
            444_555_666,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        let result = subject.estimated_transaction_fee_total(&priced_qualified_payables);

        assert_eq!(
            result,
            (2 * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN))
                * increase_gas_price_by_margin(444_555_666)
        );
    }

    #[test]
    fn estimated_transaction_fee_works_for_retry_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let rpc_gas_price_wei = 444_555_666;
        let chain = TEST_DEFAULT_CHAIN;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let account_3 = make_payable_account(56);
        let account_4 = make_payable_account(78);
        let account_5 = make_payable_account(90);
        let qualified_payables = UnpricedQualifiedPayables {
            payables: vec![
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_1.clone(),
                    Some(rpc_gas_price_wei - 1),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_2.clone(),
                    Some(rpc_gas_price_wei),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_3.clone(),
                    Some(rpc_gas_price_wei + 1),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_4.clone(),
                    Some(rpc_gas_price_wei - 123_456),
                ),
                QualifiedPayablesBeforeGasPriceSelection::new(
                    account_5.clone(),
                    Some(rpc_gas_price_wei + 456_789),
                ),
            ],
        };
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        let result = subject.estimated_transaction_fee_total(&priced_qualified_payables);

        let gas_price_account_wei_1 = increase_gas_price_by_margin(rpc_gas_price_wei);
        let gas_price_account_wei_2 = increase_gas_price_by_margin(rpc_gas_price_wei);
        let gas_price_account_wei_3 = increase_gas_price_by_margin(rpc_gas_price_wei + 1);
        let gas_price_account_wei_4 = increase_gas_price_by_margin(rpc_gas_price_wei);
        let gas_price_account_wei_5 = increase_gas_price_by_margin(rpc_gas_price_wei + 456_789);
        assert_eq!(
            result,
            (gas_price_account_wei_1
                + gas_price_account_wei_2
                + gas_price_account_wei_3
                + gas_price_account_wei_4
                + gas_price_account_wei_5)
                * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)
        )
    }
}
