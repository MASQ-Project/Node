// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent::{
    AgentDigest, PayablePaymentsAgent,
};
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
use crate::db_config::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::U256;
use masq_lib::logger::Logger;
#[cfg(test)]
use std::any::Any;

trait LoggingNullObject<'a> {
    fn logger(&'a self) -> &'a Logger;

    fn name(&self) -> &'static str;

    fn log_function_call(&'a self, function_call: &str) {
        error!(
            self.logger(),
            "calling null version of {function_call} for {} will be without effect",
            self.name()
        );
    }
}

pub struct PayablePaymentsAgentNull {
    logger: Logger,
}

impl<'a> LoggingNullObject<'a> for PayablePaymentsAgentNull {
    fn logger(&'a self) -> &'a Logger {
        &self.logger
    }

    fn name(&self) -> &'static str {
        "PayablePaymentsAgentNull"
    }
}

impl PayablePaymentsAgent for PayablePaymentsAgentNull {
    fn set_agreed_fee_per_computation_unit(
        &mut self,
        _persistent_config: &dyn PersistentConfiguration,
    ) -> Result<(), PersistentConfigError> {
        self.log_function_call("set_agreed_fee_per_computation_unit()");
        Ok(())
    }

    fn set_consuming_wallet_balances(&mut self, _balances: ConsumingWalletBalances) {
        self.log_function_call("set_consuming_wallet_balances()")
    }

    fn estimated_transaction_fee_total(&self, _number_of_transactions: usize) -> u128 {
        self.log_function_call("estimated_transaction_fee_total()");
        0
    }

    fn consuming_wallet_balances(&self) -> Option<ConsumingWalletBalances> {
        self.log_function_call("consuming_wallet_balances()");
        None
    }

    fn make_agent_digest(
        &self,
        _blockchain_interface: &dyn BlockchainInterface,
        _wallet: &Wallet,
    ) -> Result<Box<dyn AgentDigest>, BlockchainError> {
        self.log_function_call("make_agent_digest()");
        Ok(Box::new(AgentDigestNull::new()))
    }
}

impl PayablePaymentsAgentNull {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("PayablePaymentsAgentNull"),
        }
    }
}

impl Default for PayablePaymentsAgentNull {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AgentDigestNull {
    logger: Logger,
}

impl<'a> LoggingNullObject<'a> for AgentDigestNull {
    fn logger(&'a self) -> &'a Logger {
        &self.logger
    }

    fn name(&self) -> &'static str {
        "AgentDigestNull"
    }
}

impl AgentDigest for AgentDigestNull {
    fn agreed_fee_per_computation_unit(&self) -> u64 {
        self.log_function_call("agreed_fee_per_computation_unit()");
        0
    }

    fn pending_transaction_id(&self) -> U256 {
        self.log_function_call("pending_transaction_id()");
        U256::zero()
    }

    implement_as_any!();
}

impl AgentDigestNull {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("AgentDigestNull"),
        }
    }
}

impl Default for AgentDigestNull {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent::{
        AgentDigest, PayablePaymentsAgent,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::{
        AgentDigestNull, PayablePaymentsAgentNull,
    };
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use web3::types::U256;

    fn payable_payments_agent_null_constructor_works<C>(constructor: C)
    where
        C: Fn() -> PayablePaymentsAgentNull,
    {
        init_test_logging();

        let result = constructor();

        warning!(
            result.logger,
            "payable_payments_agent_null_constructor_works"
        );
        TestLogHandler::default().exists_log_containing(
            "WARN: PayablePaymentsAgentNull: \
        payable_payments_agent_null_constructor_works",
        );
    }

    #[test]
    fn payable_payments_agent_null_constructor_works_for_new() {
        payable_payments_agent_null_constructor_works(PayablePaymentsAgentNull::new)
    }

    #[test]
    fn payable_payments_agent_null_constructor_works_for_default() {
        payable_payments_agent_null_constructor_works(PayablePaymentsAgentNull::default)
    }

    #[test]
    fn null_agent_set_agreed_fee_per_computation_unit() {
        init_test_logging();
        let test_name = "null_agent_set_agreed_fee_per_computation_unit";
        let mut subject = PayablePaymentsAgentNull::new();
        subject.logger = Logger::new(test_name);
        let persistent_config = PersistentConfigurationMock::new();

        let result = subject.set_agreed_fee_per_computation_unit(&persistent_config);

        assert_eq!(result, Ok(()));
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling null \
        version of set_agreed_fee_per_computation_unit() for PayablePaymentsAgentNull \
        will be without effect"
        ));
    }

    #[test]
    fn null_agent_set_consuming_wallet_balances() {
        init_test_logging();
        let test_name = "null_agent_set_consuming_wallet_balances";
        let mut subject = PayablePaymentsAgentNull::new();
        subject.logger = Logger::new(test_name);
        let balances = ConsumingWalletBalances::new(U256::from(45678), U256::from(12345));

        subject.set_consuming_wallet_balances(balances);

        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling \
            null version of set_consuming_wallet_balances() for PayablePaymentsAgentNull will \
            be without effect"
        ));
    }

    #[test]
    fn null_agent_estimated_transaction_fee_total() {
        init_test_logging();
        let test_name = "null_agent_estimated_transaction_fee_total";
        let mut subject = PayablePaymentsAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.estimated_transaction_fee_total(4);

        assert_eq!(result, 0);
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling \
            null version of estimated_transaction_fee_total() for PayablePaymentsAgentNull \
            will be without effect"
        ));
    }

    #[test]
    fn null_agent_consuming_wallet_balances() {
        init_test_logging();
        let test_name = "null_agent_consuming_wallet_balances";
        let mut subject = PayablePaymentsAgentNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.consuming_wallet_balances();

        assert_eq!(result, None);
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling null version of consuming_wallet_balances() \
            for PayablePaymentsAgentNull will be without effect"
        ));
    }

    #[test]
    fn null_agent_make_agent_digest() {
        init_test_logging();
        let test_name = "null_agent_make_agent_digest";
        let mut subject = PayablePaymentsAgentNull::new();
        subject.logger = Logger::new(test_name);
        let blockchain_interface = BlockchainInterfaceMock::default();
        let wallet = make_wallet("abc");

        let result = subject
            .make_agent_digest(&blockchain_interface, &wallet)
            .unwrap();

        result.as_any().downcast_ref::<AgentDigestNull>().unwrap();
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling \
            null version of make_agent_digest() for PayablePaymentsAgentNull \
            will be without effect"
        ));
    }

    fn null_agent_digest_constructor_works<C>(constructor: C)
    where
        C: Fn() -> AgentDigestNull,
    {
        init_test_logging();

        let result = constructor();

        warning!(result.logger, "null_agent_digest_constructor_works");
        TestLogHandler::default().exists_log_containing(
            "WARN: AgentDigestNull: \
        null_agent_digest_constructor_works",
        );
    }

    #[test]
    fn null_agent_digest_constructor_works_for_new() {
        null_agent_digest_constructor_works(AgentDigestNull::new)
    }

    #[test]
    fn null_agent_digest_constructor_works_for_default() {
        null_agent_digest_constructor_works(AgentDigestNull::default)
    }

    #[test]
    fn null_agent_digest_agreed_fee_per_computation_unit() {
        init_test_logging();
        let test_name = "null_agent_digest_agreed_fee_per_computation_unit";
        let mut subject = AgentDigestNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.agreed_fee_per_computation_unit();

        assert_eq!(result, 0);
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling null version of agreed_fee_per_computation_unit() \
            for AgentDigestNull will be without effect"
        ));
    }

    #[test]
    fn null_agent_digest_pending_transaction_id() {
        init_test_logging();
        let test_name = "null_agent_digest_pending_transaction_id";
        let mut subject = AgentDigestNull::new();
        subject.logger = Logger::new(test_name);

        let result = subject.pending_transaction_id();

        assert_eq!(result, U256::zero());
        TestLogHandler::default().exists_log_containing(&format!(
            "ERROR: {test_name}: calling null version of pending_transaction_id() \
            for AgentDigestNull will be without effect"
        ));
    }
}
