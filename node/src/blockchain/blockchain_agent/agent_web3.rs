// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::payable_scanner::data_structures::{
    NewTxTemplate, NewTxTemplates, RetryTxTemplate, RetryTxTemplates,
};
use crate::accountant::scanners::payable_scanner_extension::msgs::PricedQualifiedPayables;
use crate::accountant::{comma_joined_stringifiable, join_with_separator};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::increase_gas_price_by_margin;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use itertools::{Either, Itertools};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use std::collections::{BTreeSet, HashMap};
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
        tx_templates: Either<NewTxTemplates, RetryTxTemplates>,
    ) -> Either<NewTxTemplates, RetryTxTemplates> {
        match tx_templates {
            Either::Left(new_tx_templates) => {
                let updated_new_tx_templates =
                    self.update_gas_price_for_new_tx_templates(new_tx_templates);

                Either::Left(updated_new_tx_templates)
            }
            Either::Right(retry_tx_templates) => {
                let updated_retry_tx_templates =
                    self.update_gas_price_for_retry_tx_templates(retry_tx_templates);

                Either::Right(updated_retry_tx_templates)
            }
        }
    }

    fn estimate_transaction_fee_total(
        &self,
        tx_templates_with_gas_price: &Either<NewTxTemplates, RetryTxTemplates>,
    ) -> u128 {
        let prices_sum = match tx_templates_with_gas_price {
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
        tx_templates: &Either<NewTxTemplates, RetryTxTemplates>,
    ) -> Option<GasPriceAboveLimitWarningReporter> {
        self.logger.warning_enabled().then(|| {
            let data = if tx_templates.is_left() {
                Either::Left(NewPayableWarningData::default())
            } else {
                Either::Right(RetryPayableWarningData::default())
            };

            GasPriceAboveLimitWarningReporter { data }
        })
    }

    fn compute_gas_price(&self, prev_gas_price_wei_opt: Option<u128>) -> u128 {
        let evaluated_gas_price_wei = match prev_gas_price_wei_opt {
            Some(prev_gas_price_wei) => prev_gas_price_wei.max(self.latest_gas_price_wei),
            None => self.latest_gas_price_wei,
        };

        increase_gas_price_by_margin(evaluated_gas_price_wei)
    }

    fn update_gas_price_for_new_tx_templates(
        &self,
        mut new_tx_templates: NewTxTemplates,
    ) -> NewTxTemplates {
        let all_receivers: Vec<Address> = new_tx_templates
            .iter()
            .map(|tx_template| tx_template.base.receiver_address)
            .collect();
        let mut computed_gas_price_wei = self.compute_gas_price(None);
        let ceil = self.chain.rec().gas_price_safe_ceiling_minor;

        if computed_gas_price_wei > ceil {
            warning!(
                self.logger,
                "The computed gas price {} wei is \
                 above the ceil value of {} wei set by the Node.\n\
                 Transaction(s) to following receivers are affected:\n\
                 {}",
                computed_gas_price_wei.separate_with_commas(),
                ceil.separate_with_commas(),
                join_with_separator(&all_receivers, |address| format!("{:?}", address), "\n")
            );

            computed_gas_price_wei = ceil;
        }

        let updated_tx_templates = new_tx_templates
            .iter_mut()
            .map(|new_tx_template| {
                new_tx_template.computed_gas_price_wei = Some(computed_gas_price_wei);
                new_tx_template.clone()
            })
            .collect();

        NewTxTemplates(updated_tx_templates)
    }

    fn update_gas_price_for_retry_tx_templates(
        &self,
        mut retry_tx_templates: RetryTxTemplates,
    ) -> RetryTxTemplates {
        let mut log_data: Vec<(Address, u128)> = Vec::with_capacity(retry_tx_templates.len());

        let ceil = self.chain.rec().gas_price_safe_ceiling_minor;

        let updated_tx_templates = retry_tx_templates
            .iter_mut()
            .map(|retry_tx_template| {
                let receiver = retry_tx_template.base.receiver_address;
                let computed_gas_price_wei =
                    self.compute_gas_price(Some(retry_tx_template.prev_gas_price_wei));

                if computed_gas_price_wei > ceil {
                    log_data.push((receiver, computed_gas_price_wei));
                    retry_tx_template.computed_gas_price_wei = Some(ceil);
                } else {
                    retry_tx_template.computed_gas_price_wei = Some(computed_gas_price_wei);
                }

                retry_tx_template.clone()
            })
            .collect();

        warning!(
            self.logger,
            "The computed gas price(s) in wei is \
                 above the ceil value of {} wei set by the Node.\n\
                 Transaction(s) to following receivers are affected:\n\
                 {}",
            ceil.separate_with_commas(),
            join_with_separator(
                &log_data,
                |(address, gas_price)| format!(
                    "{:?} with gas price {}",
                    address,
                    gas_price.separate_with_commas()
                ),
                "\n"
            )
        );

        RetryTxTemplates(updated_tx_templates)
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::join_with_separator;
    use crate::accountant::scanners::payable_scanner::data_structures::{
        BaseTxTemplate, NewTxTemplate, NewTxTemplates, RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::test_utils::RetryTxTemplateBuilder;
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        PricedQualifiedPayables, QualifiedPayableWithGasPrice,
    };
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::create_new_tx_templates;
    use crate::accountant::scanners::test_utils::make_zeroed_consuming_wallet_balances;
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::blockchain_agent::agent_web3::{
        BlockchainAgentWeb3, GasPriceAboveLimitWarningReporter, NewPayableWarningData,
        RetryPayableWarningData, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
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
    use std::collections::BTreeSet;
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
        let address_1 = account_1.wallet.address();
        let address_2 = account_2.wallet.address();
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

        let result = subject.price_qualified_payables(Either::Left(new_tx_templates));

        let gas_price_with_margin_wei = increase_gas_price_by_margin(rpc_gas_price_wei);
        let expected_result = Either::Left(NewTxTemplates(vec![
            make_new_tx_template_with_gas_price(&account_1, gas_price_with_margin_wei),
            make_new_tx_template_with_gas_price(&account_2, gas_price_with_margin_wei),
        ]));
        assert_eq!(result, expected_result);
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
            .map(|(idx, previous_attempt_gas_price_wei)| {
                let account = make_payable_account((idx as u64 + 1) * 3_000);
                make_retry_tx_template_with_prev_gas_price(&account, previous_attempt_gas_price_wei)
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

            Either::Right(RetryTxTemplates(
                retry_tx_templates
                    .iter()
                    .zip(price_wei_for_accounts_from_1_to_5.into_iter())
                    .map(|(retry_tx_template, increased_gas_price)| {
                        let mut updated_tx_template = retry_tx_template.clone();
                        updated_tx_template.computed_gas_price_wei = Some(increased_gas_price);

                        updated_tx_template
                    })
                    .collect_vec(),
            ))
        };
        assert_eq!(result, expected_result);
        // TODO: GH-605: Work on fixing the log
        // let msg_that_should_not_occur = {
        //     let mut retry_payable_data = RetryPayableWarningData::default();
        //     retry_payable_data.addresses_and_gas_price_value_above_limit_wei = expected_result
        //         .payables
        //         .into_iter()
        //         .map(|payable_with_gas_price| {
        //             (
        //                 payable_with_gas_price.payable.wallet.address(),
        //                 payable_with_gas_price.gas_price_minor,
        //             )
        //         })
        //         .collect();
        //     GasPriceAboveLimitWarningReporter::retry_payable_warning_msg(
        //         retry_payable_data,
        //         chain.rec().gas_price_safe_ceiling_minor,
        //     )
        // };
        // TestLogHandler::new()
        //     .exists_no_log_containing(&format!("WARN: {test_name}: {}", msg_that_should_not_occur));
    }

    fn make_retry_tx_template_with_prev_gas_price(
        payable: &PayableAccount,
        gas_price_wei: u128,
    ) -> RetryTxTemplate {
        let base = BaseTxTemplate::from(payable);
        RetryTxTemplate {
            base,
            prev_gas_price_wei: gas_price_wei,
            prev_nonce: 0,
            computed_gas_price_wei: None,
        }
    }

    fn make_retry_tx_template_with_computed_gas_price(
        payable: &PayableAccount,
        gas_price_wei: u128,
    ) -> RetryTxTemplate {
        let base = BaseTxTemplate::from(payable);
        RetryTxTemplate {
            base,
            prev_gas_price_wei: 0,
            prev_nonce: 0,
            computed_gas_price_wei: Some(gas_price_wei),
        }
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

    pub fn make_new_tx_template_with_gas_price(
        payable: &PayableAccount,
        gas_price_wei: u128,
    ) -> NewTxTemplate {
        let mut tx_template = NewTxTemplate::from(payable);
        tx_template.computed_gas_price_wei = Some(gas_price_wei);

        tx_template
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

        let result = subject.price_qualified_payables(Either::Left(tx_templates));

        let expected_result = Either::Left(NewTxTemplates(vec![
            make_new_tx_template_with_gas_price(&account_1, ceiling_gas_price_wei),
            make_new_tx_template_with_gas_price(&account_2, ceiling_gas_price_wei),
        ]));
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
        let expected_surpluses_wallet_and_wei_as_text = "\
        50,000,000,001 wei for tx to 0x00000000000000000000000077616c6c65743132, 50,000,000,001 \
        wei for tx to 0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
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
        let expected_surpluses_wallet_and_wei_as_text = "50,000,000,001 wei for tx to \
        0x00000000000000000000000077616c6c65743132, 50,000,000,001 wei for tx to \
        0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            rpc_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
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
        let expected_surpluses_wallet_and_wei_as_text =
            "650,000,000,000 wei for tx to 0x00000000000000000000\
            000077616c6c65743132, 650,000,000,000 wei for tx to 0x00000000000000000000000077616c6c65743334";

        test_gas_price_must_not_break_through_ceiling_value_in_the_retry_payable_mode(
            test_name,
            chain,
            fetched_gas_price_wei,
            Either::Right(RetryTxTemplates(retry_tx_templates)),
            expected_surpluses_wallet_and_wei_as_text,
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
            Either::Left(mut new_tx_templates) => Either::Left(NewTxTemplates(
                new_tx_templates
                    .iter_mut()
                    .map(|tx_template| {
                        tx_template.computed_gas_price_wei = Some(ceiling_gas_price_wei);
                        tx_template.clone()
                    })
                    .collect(),
            )),
            Either::Right(retry_tx_templates) => Either::Right(RetryTxTemplates(
                retry_tx_templates
                    .clone()
                    .iter_mut()
                    .map(|tx_template| {
                        tx_template.computed_gas_price_wei = Some(ceiling_gas_price_wei);
                        tx_template.clone()
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
            .map(|(idx, previous_attempt_gas_price_wei)| {
                let account = make_payable_account((idx as u64 + 1) * 3_000);
                make_retry_tx_template_with_prev_gas_price(&account, previous_attempt_gas_price_wei)
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
