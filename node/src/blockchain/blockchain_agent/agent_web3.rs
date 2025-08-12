// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::PricedNewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::PricedRetryTxTemplates;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use itertools::{Either, Itertools};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use thousands::Separable;

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
        unpriced_tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    ) -> Either<PricedNewTxTemplates, PricedRetryTxTemplates> {
        match unpriced_tx_templates {
            Either::Left(new_tx_templates) => {
                let priced_new_templates = PricedNewTxTemplates::from_initial_with_logging(
                    new_tx_templates,
                    self.latest_gas_price_wei,
                    self.chain.rec().gas_price_safe_ceiling_minor,
                    &self.logger,
                );

                Either::Left(priced_new_templates)
            }
            Either::Right(retry_tx_templates) => {
                let priced_retry_templates = PricedRetryTxTemplates::from_initial_with_logging(
                    retry_tx_templates,
                    self.latest_gas_price_wei,
                    self.chain.rec().gas_price_safe_ceiling_minor,
                    &self.logger,
                );

                Either::Right(priced_retry_templates)
            }
        }
    }

    fn estimate_transaction_fee_total(
        &self,
        priced_tx_templates: &Either<PricedNewTxTemplates, PricedRetryTxTemplates>,
    ) -> u128 {
        let prices_sum = match priced_tx_templates {
            Either::Left(new_tx_templates) => new_tx_templates.total_gas_price(),
            Either::Right(retry_tx_templates) => retry_tx_templates.total_gas_price(),
        };
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
            logger: Logger::new("BlockchainAgentWeb3"),
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
    use crate::accountant::join_with_separator;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::{
        RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::{
        PricedNewTxTemplate, PricedNewTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::priced::retry::{
        PricedRetryTxTemplate, PricedRetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::test_utils::RetryTxTemplateBuilder;
    use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
    use crate::accountant::scanners::test_utils::make_zeroed_consuming_wallet_balances;
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::blockchain_agent::agent_web3::{
        BlockchainAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::blockchain::blockchain_agent::BlockchainAgent;
    use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
    use crate::test_utils::make_wallet;
    use itertools::{Either, Itertools};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::DEFAULT_GAS_PRICE_MARGIN;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use thousands::Separable;

    #[test]
    fn constants_are_correct() {
        assert_eq!(WEB3_MAXIMAL_GAS_LIMIT_MARGIN, 3_328)
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_new_payable_scan() {
        init_test_logging();
        let test_name = "returns_correct_priced_qualified_payables_for_new_payable_scan";
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let new_tx_templates = NewTxTemplates::from(&vec![account_1.clone(), account_2.clone()]);
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

        let result = subject.price_qualified_payables(Either::Left(new_tx_templates.clone()));

        let gas_price_with_margin_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let expected_result = Either::Left(PricedNewTxTemplates::new(
            new_tx_templates,
            gas_price_with_margin_wei,
        ));
        assert_eq!(result, expected_result);
        TestLogHandler::new().exists_no_log_containing(test_name);
    }

    #[test]
    fn returns_correct_priced_qualified_payables_for_retry_payable_scan() {
        init_test_logging();
        let test_name = "returns_correct_priced_qualified_payables_for_retry_payable_scan";
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let rpc_gas_price_wei = 444_555_666;
        let chain = TEST_DEFAULT_CHAIN;
        let retry_tx_templates: Vec<RetryTxTemplate> = {
            vec![
                rpc_gas_price_wei - 1,
                rpc_gas_price_wei,
                rpc_gas_price_wei + 1,
                rpc_gas_price_wei - 123_456,
                rpc_gas_price_wei + 456_789,
            ]
            .into_iter()
            .enumerate()
            .map(|(idx, prev_gas_price_wei)| {
                let account = make_payable_account((idx as u64 + 1) * 3_000);
                RetryTxTemplate {
                    base: BaseTxTemplate::from(&account),
                    prev_gas_price_wei,
                    prev_nonce: idx as u64,
                }
            })
            .collect_vec()
        };
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let result = subject
            .price_qualified_payables(Either::Right(RetryTxTemplates(retry_tx_templates.clone())));

        let expected_result = {
            let price_wei_for_accounts_from_1_to_5 = vec![
                increase_gas_price_by_margin(rpc_gas_price_wei),
                increase_gas_price_by_margin(rpc_gas_price_wei),
                increase_gas_price_by_margin(rpc_gas_price_wei + 1),
                increase_gas_price_by_margin(rpc_gas_price_wei),
                increase_gas_price_by_margin(rpc_gas_price_wei + 456_789),
            ];
            if price_wei_for_accounts_from_1_to_5.len() != retry_tx_templates.len() {
                panic!("Corrupted test")
            }

            Either::Right(PricedRetryTxTemplates(
                retry_tx_templates
                    .iter()
                    .zip(price_wei_for_accounts_from_1_to_5.into_iter())
                    .map(|(retry_tx_template, increased_gas_price)| {
                        PricedRetryTxTemplate::new(retry_tx_template.clone(), increased_gas_price)
                    })
                    .collect_vec(),
            ))
        };
        assert_eq!(result, expected_result);
        TestLogHandler::new().exists_no_log_containing(test_name);
    }

    #[test]
    fn new_payables_gas_price_ceiling_test_if_latest_price_is_a_border_value() {
        let test_name = "new_payables_gas_price_ceiling_test_if_latest_price_is_a_border_value";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is
        // applied.
        // Adding just 1 didn't work, therefore 2
        let rpc_gas_price_wei =
            ((ceiling_gas_price_wei * 100) / (DEFAULT_GAS_PRICE_MARGIN as u128 + 100)) + 2;
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

        eprintln!("ceiling: {}", ceiling_gas_price_wei);

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
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let tx_templates = NewTxTemplates::from(&vec![account_1.clone(), account_2.clone()]);
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let result = subject.price_qualified_payables(Either::Left(tx_templates.clone()));

        let expected_result = Either::Left(PricedNewTxTemplates::new(
            tx_templates,
            ceiling_gas_price_wei,
        ));
        assert_eq!(result, expected_result);
        let addresses_str = join_with_separator(
            &vec![account_1.wallet, account_2.wallet],
            |wallet| format!("{}", wallet),
            "\n",
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: The computed gas price {} wei is above the ceil value of {} wei set by the Node.\n\
            Transaction(s) to following receivers are affected:\n\
            {}",
            expected_calculated_surplus_value_wei.separate_with_commas(),
            ceiling_gas_price_wei.separate_with_commas(),
            addresses_str
        ));
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_border_value_if_the_latest_fetch_being_bigger() {
        let test_name = "retry_payables_gas_price_ceiling_test_of_border_value_if_the_latest_fetch_being_bigger";
        let chain = TEST_DEFAULT_CHAIN;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is
        // applied.
        // Adding just 1 didn't work, therefore 2
        let rpc_gas_price_wei =
            (ceiling_gas_price_wei * 100) / (DEFAULT_GAS_PRICE_MARGIN as u128 + 100) + 2;
        let check_value_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let template_1 = RetryTxTemplateBuilder::new()
            .receiver_address(account_1.wallet.address())
            .amount_in_wei(account_1.balance_wei)
            .prev_gas_price_wei(rpc_gas_price_wei - 1)
            .build();
        let template_2 = RetryTxTemplateBuilder::new()
            .receiver_address(account_2.wallet.address())
            .amount_in_wei(account_2.balance_wei)
            .prev_gas_price_wei(rpc_gas_price_wei - 2)
            .build();
        let retry_tx_templates = vec![template_1, template_2];
        let expected_log_msg = format!(
            "The computed gas price(s) in wei is above the ceil value of 50,000,000,000 wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             0x00000000000000000000000077616c6c65743132 with gas price 50,000,000,001\n\
             0x00000000000000000000000077616c6c65743334 with gas price 50,000,000,001"
        );

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            &expected_log_msg,
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
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        // This should be the value that would surplus the ceiling just slightly if the margin is applied
        let border_gas_price_wei =
            (ceiling_gas_price_wei * 100) / (DEFAULT_GAS_PRICE_MARGIN as u128 + 100) + 2;
        let rpc_gas_price_wei = border_gas_price_wei - 1;
        let check_value_wei = increase_gas_price_by_margin(border_gas_price_wei);
        let template_1 = RetryTxTemplateBuilder::new()
            .receiver_address(account_1.wallet.address())
            .amount_in_wei(account_1.balance_wei)
            .prev_gas_price_wei(border_gas_price_wei)
            .build();
        let template_2 = RetryTxTemplateBuilder::new()
            .receiver_address(account_2.wallet.address())
            .amount_in_wei(account_2.balance_wei)
            .prev_gas_price_wei(border_gas_price_wei)
            .build();
        let retry_tx_templates = vec![template_1, template_2];
        let expected_log_msg = format!(
            "The computed gas price(s) in wei is above the ceil value of 50,000,000,000 wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             0x00000000000000000000000077616c6c65743132 with gas price 50,000,000,001\n\
             0x00000000000000000000000077616c6c65743334 with gas price 50,000,000,001"
        );

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            &expected_log_msg,
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
        let template_1 = RetryTxTemplateBuilder::new()
            .receiver_address(account_1.wallet.address())
            .amount_in_wei(account_1.balance_wei)
            .prev_gas_price_wei(fetched_gas_price_wei - 2)
            .build();
        let template_2 = RetryTxTemplateBuilder::new()
            .receiver_address(account_2.wallet.address())
            .amount_in_wei(account_2.balance_wei)
            .prev_gas_price_wei(fetched_gas_price_wei - 3)
            .build();
        let retry_tx_templates = vec![template_1, template_2];
        let expected_log_msg = format!(
            "The computed gas price(s) in wei is above the ceil value of 50,000,000,000 wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             0x00000000000000000000000077616c6c65743132 with gas price 64,999,999,998\n\
             0x00000000000000000000000077616c6c65743334 with gas price 64,999,999,998"
        );

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            fetched_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            &expected_log_msg,
        );
    }

    #[test]
    fn retry_payables_gas_price_ceiling_test_of_big_value_if_the_previous_attempt_being_bigger() {
        let test_name = "retry_payables_gas_price_ceiling_test_of_big_value_if_the_previous_attempt_being_bigger";
        let chain = TEST_DEFAULT_CHAIN;
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let template_1 = RetryTxTemplateBuilder::new()
            .receiver_address(account_1.wallet.address())
            .amount_in_wei(account_1.balance_wei)
            .prev_gas_price_wei(ceiling_gas_price_wei - 1)
            .build();
        let template_2 = RetryTxTemplateBuilder::new()
            .receiver_address(account_2.wallet.address())
            .amount_in_wei(account_2.balance_wei)
            .prev_gas_price_wei(ceiling_gas_price_wei - 2)
            .build();
        let retry_tx_templates = vec![template_1, template_2];
        let expected_log_msg = format!(
            "The computed gas price(s) in wei is above the ceil value of 50,000,000,000 wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             0x00000000000000000000000077616c6c65743132 with gas price 64,999,999,998\n\
             0x00000000000000000000000077616c6c65743334 with gas price 64,999,999,997"
        );

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            ceiling_gas_price_wei - 3,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            &expected_log_msg,
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
        let template_1 = RetryTxTemplateBuilder::new()
            .receiver_address(account_1.wallet.address())
            .amount_in_wei(account_1.balance_wei)
            .prev_gas_price_wei(ceiling_gas_price_wei)
            .build();
        let template_2 = RetryTxTemplateBuilder::new()
            .receiver_address(account_2.wallet.address())
            .amount_in_wei(account_2.balance_wei)
            .prev_gas_price_wei(ceiling_gas_price_wei)
            .build();
        let retry_tx_templates = vec![template_1, template_2];
        let expected_log_msg = format!(
            "The computed gas price(s) in wei is above the ceil value of 50,000,000,000 wei set by the Node.\n\
             Transaction(s) to following receivers are affected:\n\
             0x00000000000000000000000077616c6c65743132 with gas price 650,000,000,000\n\
             0x00000000000000000000000077616c6c65743334 with gas price 650,000,000,000"
        );

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            fetched_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            &expected_log_msg,
        );
    }

    fn test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
        test_name: &str,
        chain: Chain,
        rpc_gas_price_wei: u128,
        tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
        expected_log_msg: &str,
    ) {
        init_test_logging();
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let ceiling_gas_price_wei = chain.rec().gas_price_safe_ceiling_minor;
        let expected_result = match tx_templates.clone() {
            Either::Left(new_tx_templates) => Either::Left(PricedNewTxTemplates(
                new_tx_templates
                    .iter()
                    .map(|tx_template| {
                        PricedNewTxTemplate::new(tx_template.clone(), ceiling_gas_price_wei)
                    })
                    .collect(),
            )),
            Either::Right(retry_tx_templates) => Either::Right(PricedRetryTxTemplates(
                retry_tx_templates
                    .iter()
                    .map(|tx_template| {
                        PricedRetryTxTemplate::new(tx_template.clone(), ceiling_gas_price_wei)
                    })
                    .collect(),
            )),
        };
        let mut subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        subject.logger = Logger::new(test_name);

        let result = subject.price_qualified_payables(tx_templates);

        assert_eq!(result, expected_result);
        TestLogHandler::new()
            .exists_log_containing(&format!("WARN: {test_name}: {expected_log_msg}"));
    }

    #[test]
    fn returns_correct_non_computed_values() {
        let gas_limit_const_part = 44_000;
        let consuming_wallet = make_wallet("abcde");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();

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
    fn estimate_transaction_fee_total_works_for_new_payable() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let account_1 = make_payable_account(12);
        let account_2 = make_payable_account(34);
        let chain = TEST_DEFAULT_CHAIN;
        let tx_templates = NewTxTemplates::from(&vec![account_1, account_2]);
        let subject = BlockchainAgentWeb3::new(
            444_555_666,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        let new_tx_templates = subject.price_qualified_payables(Either::Left(tx_templates));

        let result = subject.estimate_transaction_fee_total(&new_tx_templates);

        assert_eq!(
            result,
            (2 * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN))
                * increase_gas_price_by_margin(444_555_666)
        );
    }

    #[test]
    fn estimate_transaction_fee_total_works_for_retry_txs() {
        let consuming_wallet = make_wallet("efg");
        let consuming_wallet_balances = make_zeroed_consuming_wallet_balances();
        let rpc_gas_price_wei = 444_555_666;
        let chain = TEST_DEFAULT_CHAIN;
        let retry_tx_templates: Vec<RetryTxTemplate> = {
            vec![
                rpc_gas_price_wei - 1,
                rpc_gas_price_wei,
                rpc_gas_price_wei + 1,
                rpc_gas_price_wei - 123_456,
                rpc_gas_price_wei + 456_789,
            ]
            .into_iter()
            .enumerate()
            .map(|(idx, prev_gas_price_wei)| {
                let account = make_payable_account((idx as u64 + 1) * 3_000);
                RetryTxTemplate {
                    base: BaseTxTemplate::from(&account),
                    prev_gas_price_wei,
                    prev_nonce: idx as u64,
                }
            })
            .collect()
        };
        let subject = BlockchainAgentWeb3::new(
            rpc_gas_price_wei,
            77_777,
            consuming_wallet,
            consuming_wallet_balances,
            chain,
        );
        let priced_qualified_payables =
            subject.price_qualified_payables(Either::Right(RetryTxTemplates(retry_tx_templates)));

        let result = subject.estimate_transaction_fee_total(&priced_qualified_payables);

        let gas_prices_for_accounts_from_1_to_5 = vec![
            increase_gas_price_by_margin(rpc_gas_price_wei),
            increase_gas_price_by_margin(rpc_gas_price_wei),
            increase_gas_price_by_margin(rpc_gas_price_wei + 1),
            increase_gas_price_by_margin(rpc_gas_price_wei),
            increase_gas_price_by_margin(rpc_gas_price_wei + 456_789),
        ];
        let expected_result = gas_prices_for_accounts_from_1_to_5
            .into_iter()
            .sum::<u128>()
            * (77_777 + WEB3_MAXIMAL_GAS_LIMIT_MARGIN);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn blockchain_agent_web3_logs_with_right_name() {
        let test_name = "blockchain_agent_web3_logs_with_right_name";
        let subject = BlockchainAgentWeb3::new(
            0,
            0,
            make_wallet("abcde"),
            make_zeroed_consuming_wallet_balances(),
            TEST_DEFAULT_CHAIN,
        );

        info!(subject.logger, "{}", test_name);

        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: BlockchainAgentWeb3: {}", test_name));
    }
}
