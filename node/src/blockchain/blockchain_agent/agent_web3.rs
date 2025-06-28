// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::comma_joined_stringifiable;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    PricedQualifiedPayables, QualifiedPayableWithGasPrice, UnpricedQualifiedPayables,
};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use itertools::{Either, Itertools};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use thousands::Separable;
use web3::types::Address;

#[derive(Debug, Clone)]
pub struct BlockchainAgentWeb3 {
    logger: Logger,
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
        let warning_data_collector_opt =
            self.set_up_warning_data_collector_opt(&qualified_payables);

        let init: (
            Vec<QualifiedPayableWithGasPrice>,
            Option<GasPriceAboveLimitWarningReporter>,
        ) = (vec![], warning_data_collector_opt);
        let (priced_qualified_payables, warning_data_collector_opt) =
            qualified_payables.payables.into_iter().fold(
                init,
                |(mut priced_payables, mut warning_data_collector_opt), unpriced_payable| {
                    let selected_gas_price_wei =
                        match unpriced_payable.previous_attempt_gas_price_minor_opt {
                            None => self.latest_gas_price_wei,
                            Some(previous_price) if self.latest_gas_price_wei < previous_price => {
                                previous_price
                            }
                            Some(_) => self.latest_gas_price_wei,
                        };

                    let gas_price_increased_by_margin_wei =
                        increase_gas_price_by_margin(selected_gas_price_wei);

                    let price_ceiling_wei = self.chain.rec().gas_price_safe_ceiling_minor;
                    let checked_gas_price_wei =
                        if gas_price_increased_by_margin_wei > price_ceiling_wei {
                            warning_data_collector_opt.as_mut().map(|collector| {
                                match collector.data.as_mut() {
                                    Either::Left(new_payable_data) => {
                                        new_payable_data
                                            .addresses
                                            .push(unpriced_payable.payable.wallet.address());
                                        new_payable_data.gas_price_above_limit_wei =
                                            gas_price_increased_by_margin_wei
                                    }
                                    Either::Right(retry_payable_data) => retry_payable_data
                                        .addresses_and_gas_price_value_above_limit_wei
                                        .push((
                                            unpriced_payable.payable.wallet.address(),
                                            gas_price_increased_by_margin_wei,
                                        )),
                                }
                            });
                            price_ceiling_wei
                        } else {
                            gas_price_increased_by_margin_wei
                        };

                    priced_payables.push(QualifiedPayableWithGasPrice::new(
                        unpriced_payable.payable,
                        checked_gas_price_wei,
                    ));

                    (priced_payables, warning_data_collector_opt)
                },
            );

        warning_data_collector_opt
            .map(|collector| collector.log_warning_if_some_reason(&self.logger, self.chain));

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

struct GasPriceAboveLimitWarningReporter {
    data: Either<NewPayableWarningData, RetryPayableWarningData>,
}

impl GasPriceAboveLimitWarningReporter {
    fn log_warning_if_some_reason(self, logger: &Logger, chain: Chain) {
        let ceiling_value_wei = chain.rec().gas_price_safe_ceiling_minor;
        match self.data {
            Either::Left(new_payable_data) => {
                if !new_payable_data.addresses.is_empty() {
                    warning!(
                        logger,
                        "{}",
                        Self::new_payables_warning_msg(new_payable_data, ceiling_value_wei)
                    )
                }
            }
            Either::Right(retry_payable_data) => {
                if !retry_payable_data
                    .addresses_and_gas_price_value_above_limit_wei
                    .is_empty()
                {
                    warning!(
                        logger,
                        "{}",
                        Self::retry_payable_warning_msg(retry_payable_data, ceiling_value_wei)
                    )
                }
            }
        }
    }

    fn new_payables_warning_msg(
        new_payable_warning_data: NewPayableWarningData,
        ceiling_value_wei: u128,
    ) -> String {
        let accounts = comma_joined_stringifiable(&new_payable_warning_data.addresses, |address| {
            format!("{:?}", address)
        });
        format!(
            "Calculated gas price {} wei for txs to {} is over the spend limit {} wei.",
            new_payable_warning_data
                .gas_price_above_limit_wei
                .separate_with_commas(),
            accounts,
            ceiling_value_wei.separate_with_commas()
        )
    }

    fn retry_payable_warning_msg(
        retry_payable_warning_data: RetryPayableWarningData,
        ceiling_value_wei: u128,
    ) -> String {
        let accounts = retry_payable_warning_data
            .addresses_and_gas_price_value_above_limit_wei
            .into_iter()
            .map(|(address, calculated_price_wei)| {
                format!(
                    "{} wei for tx to {:?}",
                    calculated_price_wei.separate_with_commas(),
                    address
                )
            })
            .join(", ");
        format!(
            "Calculated gas price {} surplussed the spend limit {} wei.",
            accounts,
            ceiling_value_wei.separate_with_commas()
        )
    }
}

#[derive(Default)]
struct NewPayableWarningData {
    addresses: Vec<Address>,
    gas_price_above_limit_wei: u128,
}

#[derive(Default)]
struct RetryPayableWarningData {
    addresses_and_gas_price_value_above_limit_wei: Vec<(Address, u128)>,
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
            logger: Logger::new("BlockchainAgentWeb3"),
            latest_gas_price_wei,
            gas_limit_const_part,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        }
    }

    fn set_up_warning_data_collector_opt(
        &self,
        qualified_payables: &UnpricedQualifiedPayables,
    ) -> Option<GasPriceAboveLimitWarningReporter> {
        self.logger.warning_enabled().then(|| {
            let is_retry = Self::is_retry(qualified_payables);
            GasPriceAboveLimitWarningReporter {
                data: if !is_retry {
                    Either::Left(NewPayableWarningData::default())
                } else {
                    Either::Right(RetryPayableWarningData::default())
                },
            }
        })
    }

    fn is_retry(qualified_payables: &UnpricedQualifiedPayables) -> bool {
        qualified_payables
            .payables
            .first()
            .expectv("payable")
            .previous_attempt_gas_price_minor_opt
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        PricedQualifiedPayables, QualifiedPayableWithGasPrice,
        QualifiedPayablesBeforeGasPriceSelection, UnpricedQualifiedPayables,
    };
    use crate::accountant::test_utils::{
        make_payable_account, make_unpriced_qualified_payables_for_retry_mode,
    };
    use crate::blockchain::blockchain_agent::agent_web3::{
        BlockchainAgentWeb3, GasPriceAboveLimitWarningReporter, NewPayableWarningData,
        RetryPayableWarningData, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::blockchain::blockchain_agent::BlockchainAgent;
    use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::make_wallet;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use thousands::Separable;
    use web3::types::U256;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3_328)
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_new_payable_scan() {
        init_test_logging();
        let test_name = "returns_correct_priced_qualified_payables_for_new_payable_scan";
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let address_1 = account_1.wallet.address();
        let address_2 = account_2.wallet.address();
        let unpriced_qualified_payables =
            UnpricedQualifiedPayables::from(vec![account_1.clone(), account_2.clone()]);
        let rpc_gas_price_wei = 555_666_777;
        let chain = TEST_DEFAULT_CHAIN;
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let priced_qualified_payables =
            subject.price_qualified_payables(unpriced_qualified_payables);

        let gas_price_with_margin_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let expected_result = PricedQualifiedPayables {
            payables: vec![
                QualifiedPayableWithGasPrice::new(account_1, gas_price_with_margin_wei),
                QualifiedPayableWithGasPrice::new(account_2, gas_price_with_margin_wei),
            ],
        };
        assert_eq!(priced_qualified_payables, expected_result);
        let msg_that_should_not_occur = {
            let mut new_payable_data = NewPayableWarningData::default();
            new_payable_data.addresses = vec![address_1, address_2];

            GasPriceAboveLimitWarningReporter::new_payables_warning_msg(
                new_payable_data,
                chain.rec().gas_price_safe_ceiling_minor,
            )
        };
        TestLogHandler::new()
            .exists_no_log_containing(&format!("WARN: {test_name}: {msg_that_should_not_occur}"));
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_retry_payable_scan() {
        init_test_logging();
        let test_name = "returns_correct_priced_qualified_payables_for_retry_payable_scan";
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
        let unpriced_qualified_payables = UnpricedQualifiedPayables {
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
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let priced_qualified_payables =
            subject.price_qualified_payables(unpriced_qualified_payables);

        let expected_result = {
            let gas_price_account_wei_1 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_2 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_3 = increase_gas_price_by_margin(rpc_gas_price_wei + 1);
            let gas_price_account_wei_4 = increase_gas_price_by_margin(rpc_gas_price_wei);
            let gas_price_account_wei_5 = increase_gas_price_by_margin(rpc_gas_price_wei + 456_789);
            PricedQualifiedPayables {
                payables: vec![
                    QualifiedPayableWithGasPrice::new(account_1, gas_price_account_wei_1),
                    QualifiedPayableWithGasPrice::new(account_2, gas_price_account_wei_2),
                    QualifiedPayableWithGasPrice::new(account_3, gas_price_account_wei_3),
                    QualifiedPayableWithGasPrice::new(account_4, gas_price_account_wei_4),
                    QualifiedPayableWithGasPrice::new(account_5, gas_price_account_wei_5),
                ],
            }
        };
        assert_eq!(priced_qualified_payables, expected_result);
        let msg_that_should_not_occur = {
            let mut retry_payable_data = RetryPayableWarningData::default();
            retry_payable_data.addresses_and_gas_price_value_above_limit_wei = expected_result
                .payables
                .into_iter()
                .map(|payable_with_gas_price| {
                    (
                        payable_with_gas_price.payable.wallet.address(),
                        payable_with_gas_price.gas_price_minor,
                    )
                })
                .collect();
            GasPriceAboveLimitWarningReporter::retry_payable_warning_msg(
                retry_payable_data,
                chain.rec().gas_price_safe_ceiling_minor,
            )
        };
        TestLogHandler::new()
            .exists_no_log_containing(&format!("WARN: {test_name}: {}", msg_that_should_not_occur));
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_a_border_value() {
        let test_name = "new_payables_gas_price_ceiling_test_if_latest_price_is_a_border_value";
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
            test_name,
            chain,
            rpc_gas_price_wei,
            50_000_000_001,
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
        let test_name = "new_payables_gas_price_ceiling_test_if_latest_price_is_a_bit_bigger_even_with_no_margin";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;

        test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
            test_name,
            chain,
            ceiling_gas_price_wei + 1,
            65_000_000_001,
        );
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_just_gigantic() {
        let test_name = "new_payables_gas_price_ceiling_test_if_latest_price_is_just_gigantic";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;

        test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
            test_name,
            chain,
            10 * ceiling_gas_price_wei,
            650_000_000_000,
        );
    }

    fn test_gas_price_must_not_break_through_ceiling_value_in_the_new_payable_mode(
        test_name: &str,
        chain: Chain,
        rpc_gas_price_wei: u128,
        expected_calculated_surplus_value_wei: u128,
    ) {
        init_test_logging();
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
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        let expected_result = PricedQualifiedPayables {
            payables: vec![
                QualifiedPayableWithGasPrice::new(account_1.clone(), ceiling_gas_price_wei),
                QualifiedPayableWithGasPrice::new(account_2.clone(), ceiling_gas_price_wei),
            ],
        };
        assert_eq!(priced_qualified_payables, expected_result);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Calculated gas price {} wei for txs to {}, {} is over the spend \
            limit {} wei.",
            expected_calculated_surplus_value_wei.separate_with_commas(),
            account_1.wallet,
            account_2.wallet,
            chain
                .rec()
                .gas_price_safe_ceiling_minor
                .separate_with_commas()
        ));
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_border_value_if_the_latest_fetch_being_bigger() {
        let test_name = "retry_payables_gas_price_ceiling_test_of_border_value_if_the_latest_fetch_being_bigger";
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
        let expected_surpluses_wallet_and_wei_as_text = "\
        50,000,000,001 wei for tx to 0x00000000000000000000000077616c6c65743132, 50,000,000,001 \
        wei for tx to 0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            raw_qualified_payables,
            expected_surpluses_wallet_and_wei_as_text,
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
        let test_name = "retry_payables_gas_price_ceiling_test_of_border_value_if_the_previous_attempt_being_bigger";
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
        let expected_surpluses_wallet_and_wei_as_text = "50,000,000,001 wei for tx to \
        0x00000000000000000000000077616c6c65743132, 50,000,000,001 wei for tx to \
        0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            raw_qualified_payables,
            expected_surpluses_wallet_and_wei_as_text,
        );
        assert!(check_value_wei > ceiling_gas_price_wei);
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_big_value_if_the_latest_fetch_being_bigger() {
        let test_name =
            "retry_payables_gas_price_ceiling_test_of_big_value_if_the_latest_fetch_being_bigger";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let fetched_gas_price_wei = ceiling_gas_price_wei - 1;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), fetched_gas_price_wei - 2),
            (account_2.clone(), fetched_gas_price_wei - 3),
        ]);
        let expected_surpluses_wallet_and_wei_as_text = "64,999,999,998 wei for tx to \
        0x00000000000000000000000077616c6c65743132, 64,999,999,998 wei for tx to \
        0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            fetched_gas_price_wei,
            raw_qualified_payables,
            expected_surpluses_wallet_and_wei_as_text,
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_big_value_if_the_previous_attempt_being_bigger() {
        let test_name = "retry_payables_gas_price_ceiling_test_of_big_value_if_the_previous_attempt_being_bigger";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let raw_qualified_payables = make_unpriced_qualified_payables_for_retry_mode(vec![
            (account_1.clone(), ceiling_gas_price_wei - 1),
            (account_2.clone(), ceiling_gas_price_wei - 2),
        ]);
        let expected_surpluses_wallet_and_wei_as_text = "64,999,999,998 wei for tx to \
        0x00000000000000000000000077616c6c65743132, 64,999,999,997 wei for tx to \
        0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            ceiling_gas_price_wei - 3,
            raw_qualified_payables,
            expected_surpluses_wallet_and_wei_as_text,
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_giant_value_for_the_latest_fetch() {
        let test_name = "retry_payables_gas_price_ceiling_test_of_giant_value_for_the_latest_fetch";
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
        let expected_surpluses_wallet_and_wei_as_text =
            "650,000,000,000 wei for tx to 0x00000000000000000000\
            000077616c6c65743132, 650,000,000,000 wei for tx to 0x00000000000000000000000077616c6c6\
            5743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            fetched_gas_price_wei,
            raw_qualified_payables,
            expected_surpluses_wallet_and_wei_as_text,
        );
    }

    fn test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
        test_name: &str,
        chain: Chain,
        rpc_gas_price_wei: u128,
        qualified_payables: UnpricedQualifiedPayables,
        expected_surpluses_wallet_and_wei_as_text: &str,
    ) {
        init_test_logging();
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
                    QualifiedPayableWithGasPrice::new(payable.payable, ceiling_gas_price_wei)
                })
                .collect(),
        };
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let priced_qualified_payables = subject.price_qualified_payables(qualified_payables);

        assert_eq!(priced_qualified_payables, expected_priced_payables);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Calculated gas price {expected_surpluses_wallet_and_wei_as_text} \
                    surplussed the spend limit {} wei.",
            ceiling_gas_price_wei.separate_with_commas()
        ));
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

    #[test]
    fn blockchain_agent_web3_logs_with_right_name() {
        let test_name = "blockchain_agent_web3_logs_with_right_name";
        let subject = BlockchainAgentWeb3::new(
            0,
            0,
            make_wallet("abcde"),
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: U256::from(0),
                masq_token_balance_in_minor_units: U256::from(0),
            },
            TEST_DEFAULT_CHAIN,
        );

        info!(subject.logger, "{}", test_name);

        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: BlockchainAgentWeb3: {}", test_name));
    }
}
