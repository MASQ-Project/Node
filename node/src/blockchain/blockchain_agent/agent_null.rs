// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, QualifiedPayableGasPriceSetup};
use crate::sub_lib::wallet::Wallet;
use ethereum_types::U256;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;

#[derive(Clone)]
pub struct BlockchainAgentNull {
    wallet: Wallet,
    logger: Logger,
}

impl BlockchainAgent for BlockchainAgentNull {
    fn estimated_transaction_fee_total(&self) -> u128 {
        self.log_function_call("estimated_transaction_fee_total()");
        0
    }

    fn consuming_wallet_balances(&self) -> ConsumingWalletBalances {
        self.log_function_call("consuming_wallet_balances()");
        ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: U256::zero(),
            masq_token_balance_in_minor_units: U256::zero(),
        }
    }

    // fn finalize_gas_price_per_payable(&self, qualified_payables: QualifiedPayablesRawPack) -> QualifiedPayablesRipePack {
    //     self.log_function_call("finalize_gas_price_per_payable()");
    //     let payables = qualified_payables.payables.into_iter().map(|preconfiguration| {
    //         QualifiedPayablesWithGasPrice{ payable: preconfiguration.payable, gas_price_minor: 0 }
    //     }).collect();
    //     QualifiedPayablesRipePack{ payables }
    // }

    fn consuming_wallet(&self) -> &Wallet {
        self.log_function_call("consuming_wallet()");
        &self.wallet
    }

    fn get_chain(&self) -> Chain {
        self.log_function_call("get_chain()");
        TEST_DEFAULT_CHAIN
    }

    #[cfg(test)]
    fn dup(&self) -> Box<dyn BlockchainAgent> {
        intentionally_blank!()
    }

    #[cfg(test)]
    as_any_ref_in_trait_impl!();
}

impl BlockchainAgentNull {
    pub fn new() -> Self {
        Self {
            wallet: Wallet::null(),
            logger: Logger::new("BlockchainAgentNull"),
        }
    }

    fn log_function_call(&self, function_call: &str) {
        error!(
            self.logger,
            "calling null version of {function_call} for BlockchainAgentNull will be without effect",
        );
    }
}

impl Default for BlockchainAgentNull {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, QualifiedPayableGasPriceSetup,
    };
    use crate::sub_lib::wallet::Wallet;

    use crate::blockchain::blockchain_agent::agent_null::BlockchainAgentNull;
    use crate::blockchain::blockchain_agent::BlockchainAgent;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use web3::types::U256;

    fn blockchain_agent_null_constructor_works<C>(constructor: C)
    where
        C: Fn() -> BlockchainAgentNull,
    {
        init_test_logging();

        let result = constructor();

        assert_eq!(result.wallet, Wallet::null());
        warning!(result.logger, "blockchain_agent_null_constructor_works");
        TestLogHandler::default().exists_log_containing(
            "WARN: BlockchainAgentNull: \
        blockchain_agent_null_constructor_works",
        );
    }

    #[test]
    fn blockchain_agent_null_constructor_works_for_new() {
        blockchain_agent_null_constructor_works(BlockchainAgentNull::new)
    }

    #[test]
    fn blockchain_agent_null_constructor_works_for_default() {
        blockchain_agent_null_constructor_works(BlockchainAgentNull::default)
    }

    fn assert_error_log(test_name: &str, expected_operation: &str) {
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling \
            null version of {expected_operation}() for BlockchainAgentNull \
            will be without effect"
        ));
    }

    #[test]
    fn null_agent_estimated_transaction_fee_total() {
        init_test_logging();
        let test_name = "null_agent_estimated_transaction_fee_total";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.estimated_transaction_fee_total();

        assert_eq!(result, 0);
        assert_error_log(test_name, "estimated_transaction_fee_total");
    }

    #[test]
    fn null_agent_consuming_wallet_balances() {
        init_test_logging();
        let test_name = "null_agent_consuming_wallet_balances";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consuming_wallet_balances();

        assert_eq!(
            result,
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: U256::zero(),
                masq_token_balance_in_minor_units: U256::zero()
            }
        );
        assert_error_log(test_name, "consuming_wallet_balances")
    }

    #[test]
    fn null_agent_consuming_wallet() {
        init_test_logging();
        let test_name = "null_agent_consuming_wallet";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consuming_wallet();

        assert_eq!(result, &Wallet::null());
        assert_error_log(test_name, "consuming_wallet")
    }

    #[test]
    fn null_agent_get_chain() {
        init_test_logging();
        let test_name = "null_agent_get_chain";
        let mut subject = BlockchainAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.get_chain();

        assert_eq!(result, TEST_DEFAULT_CHAIN);
        assert_error_log(test_name, "get_chain")
    }
}
