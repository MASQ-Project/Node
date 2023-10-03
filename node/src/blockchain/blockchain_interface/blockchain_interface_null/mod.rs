// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod lower_level_interface_null;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::BlockchainAgentNull;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_null::lower_level_interface_null::LowerBCINull;
use crate::blockchain::blockchain_interface::lower_level_interface::LowerBCI;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, PayableTransactionError, ProcessedPayableFallible,
    ResultForReceipt, RetrievedBlockchainTransactions,
};
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use masq_lib::logger::Logger;
use web3::types::{Address, BlockNumber, H160, H256};

pub struct BlockchainInterfaceNull {
    logger: Logger,
    helper: Box<dyn LowerBCI>,
}

impl BlockchainInterface for BlockchainInterfaceNull {
    fn contract_address(&self) -> Address {
        self.log_uninitialized_for_operation("get contract address");
        H160::zero()
    }

    fn retrieve_transactions(
        &self,
        _start_block: BlockNumber,
        _end_block: BlockNumber,
        _wallet: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        self.handle_uninitialized_interface("retrieve transactions")
    }

    fn build_blockchain_agent(
        &self,
        _consuming_wallet: &Wallet,
        _persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, String> {
        error!(self.logger, "Builds a null blockchain agent only");
        Ok(Box::new(BlockchainAgentNull::new()))
    }

    fn send_batch_of_payables(
        &self,
        _agent: Box<dyn BlockchainAgent>,
        _new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        _accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
        self.handle_uninitialized_interface("pay for payables")
    }

    fn get_transaction_receipt(&self, _hash: H256) -> ResultForReceipt {
        self.handle_uninitialized_interface("get transaction receipt")
    }

    fn lower_interface(&self) -> &dyn LowerBCI {
        error!(self.logger, "Provides null RPC helpers only");
        &*self.helper
    }

    as_any_in_trait_impl!();
}

impl Default for BlockchainInterfaceNull {
    fn default() -> Self {
        Self::new()
    }
}

trait BlockchainInterfaceUninitializedError {
    fn error() -> Self;
}

impl BlockchainInterfaceUninitializedError for PayableTransactionError {
    fn error() -> Self {
        Self::UninitializedBlockchainInterface
    }
}

impl BlockchainInterfaceUninitializedError for BlockchainError {
    fn error() -> Self {
        Self::UninitializedBlockchainInterface
    }
}

impl BlockchainInterfaceNull {
    pub fn new() -> Self {
        let logger = Logger::new("BlockchainInterface");
        let helper = Box::new(LowerBCINull::new(&logger));
        BlockchainInterfaceNull { logger, helper }
    }

    fn handle_uninitialized_interface<Irrelevant, E>(
        &self,
        operation: &str,
    ) -> Result<Irrelevant, E>
    where
        E: BlockchainInterfaceUninitializedError,
    {
        self.log_uninitialized_for_operation(operation);
        let err = E::error();
        Err(err)
    }

    fn log_uninitialized_for_operation(&self, operation: &str) {
        error!(
            self.logger,
            "Failed to {} with uninitialized blockchain \
            interface. Parameter blockchain-service-url is missing.",
            operation
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::BlockchainAgentNull;
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::lower_level_interface_null::LowerBCINull;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::{
        BlockchainInterfaceNull, BlockchainInterfaceUninitializedError,
    };
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainInterface, PayableTransactionError,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use actix::Actor;
    use ethereum_types::U64;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use web3::types::{BlockNumber, H160};

    fn make_subject(test_name: &str) -> BlockchainInterfaceNull {
        let logger = Logger::new(test_name);
        let helper = Box::new(LowerBCINull::new(&logger));
        BlockchainInterfaceNull { logger, helper }
    }

    #[test]
    fn blockchain_interface_null_returns_contract_address() {
        let result = make_subject("irrelevant").contract_address();

        assert_eq!(result, H160::zero())
    }

    #[test]
    fn blockchain_interface_null_retrieves_no_transactions() {
        init_test_logging();
        let test_name = "blockchain_interface_null_retrieves_no_transactions";
        let wallet = make_wallet("blah");

        let result = make_subject(test_name).retrieve_transactions(
            BlockNumber::Number(U64::zero()),
            BlockNumber::Latest,
            &wallet,
        );

        assert_eq!(
            result,
            Err(BlockchainError::UninitializedBlockchainInterface)
        );
        let expected_msg = "Failed to retrieve transactions with uninitialized blockchain \
            interface. Parameter blockchain-service-url is missing.";
        let expected_log_msg = format!("ERROR: {test_name}: {}", expected_msg);
        TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
    }

    #[test]
    fn blockchain_interface_null_builds_null_agent() {
        init_test_logging();
        let test_name = "blockchain_interface_null_builds_null_agent";
        let wallet = make_wallet("blah");
        let persistent_config = PersistentConfigurationMock::new();

        let result = make_subject(test_name)
            .build_blockchain_agent(&wallet, &persistent_config)
            .unwrap();

        result
            .as_any()
            .downcast_ref::<BlockchainAgentNull>()
            .unwrap();
        let expected_log_msg = format!("ERROR: {test_name}: Builds a null blockchain agent only");
        TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
    }

    #[test]
    fn blockchain_interface_null_cannot_send_batch_of_payables() {
        init_test_logging();
        let test_name = "blockchain_interface_null_cannot_send_batch_of_payables";
        let (recorder, _, _) = make_recorder();
        let recipient = recorder.start().recipient();
        let accounts = vec![make_payable_account(111)];
        let agent = Box::new(BlockchainAgentNull::new());

        let result = make_subject(test_name).send_batch_of_payables(agent, &recipient, &accounts);

        assert_eq!(
            result,
            Err(PayableTransactionError::UninitializedBlockchainInterface)
        );
        let expected_log_msg = format!(
            "ERROR: {test_name}: Failed to pay for payables with uninitialized blockchain \
            interface. Parameter blockchain-service-url is missing."
        );
        TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
    }

    #[test]
    fn blockchain_interface_null_gets_no_transaction_receipt() {
        init_test_logging();
        let test_name = "blockchain_interface_null_gets_no_transaction_receipt";
        let tx_hash = make_tx_hash(123);

        let result = make_subject(test_name).get_transaction_receipt(tx_hash);

        assert_eq!(
            result,
            Err(BlockchainError::UninitializedBlockchainInterface)
        );
        let expected_log_msg = format!(
            "ERROR: {test_name}: Failed to get transaction receipt with uninitialized \
            blockchain interface. Parameter blockchain-service-url is missing."
        );
        TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
    }

    #[test]
    fn blockchain_interface_null_gives_null_helper() {
        init_test_logging();
        let test_name = "blockchain_interface_null_gives_null_helper";
        let wallet = make_wallet("abc");

        let _ = make_subject(test_name)
            .lower_interface()
            .get_transaction_id(&wallet);

        let expected_log_msg_from_helpers_call =
            format!("ERROR: {test_name}: Provides null RPC helpers only");
        let expected_log_msg_from_rcp_call =
            format!("ERROR: {test_name}: Null version can't fetch transaction id");
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            expected_log_msg_from_helpers_call.as_str(),
            expected_log_msg_from_rcp_call.as_str(),
        ]);
    }

    #[test]
    fn blockchain_interface_null_error_is_implemented_for_blockchain_error() {
        assert_eq!(
            BlockchainError::error(),
            BlockchainError::UninitializedBlockchainInterface
        )
    }

    #[test]
    fn blockchain_interface_null_error_is_implemented_for_payable_transaction_error() {
        assert_eq!(
            PayableTransactionError::error(),
            PayableTransactionError::UninitializedBlockchainInterface
        )
    }
}
