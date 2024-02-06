// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod lower_level_interface_null;

use ethereum_types::U256;
use futures::Future;
use futures::future::result;
use web3::transports::{Batch, Http};
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::blockchain_interface_null::lower_level_interface_null::LowBlockChainIntNull;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use web3::types::{Address, BlockNumber, H160, H256};
use web3::Web3;
use masq_lib::blockchains::chains::Chain;
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainAgentBuildError, BlockchainError, PayableTransactionError, ResultForReceipt};
use crate::blockchain::blockchain_interface::data_structures::{RetrievedBlockchainTransactions};

pub struct BlockchainInterfaceNull {
    logger: Logger,
    lower_level_interface: Box<dyn LowBlockchainInt>,
}

impl BlockchainInterface for BlockchainInterfaceNull {
    fn contract_address(&self) -> Address {
        self.log_uninitialized_for_operation("get contract address");
        H160::zero()
    }

    fn get_chain(&self) -> Chain {
        todo!()
    }

    fn get_batch_web3(&self) -> Web3<Batch<Http>> {
        todo!()
    }

    fn retrieve_transactions(
        &self,
        _start_block: BlockNumber,
        _end_block: BlockNumber,
        _recipient: &Wallet,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        Box::new(result(
            self.handle_uninitialized_interface("retrieve transactions"),
        ))
    }

    fn build_blockchain_agent(
        &self,
        _consuming_wallet: &Wallet,
        _persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, BlockchainAgentBuildError> {
        self.handle_uninitialized_interface("build blockchain agent")
    }

    fn get_transaction_fee_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        todo!()
    }

    fn get_token_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        todo!()
    }

    fn get_transaction_count(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        todo!()
    }

    // fn send_batch_of_payables(
    //     &self,
    //     _agent: Box<dyn BlockchainAgent>,
    //     _new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
    //     _accounts: &[PayableAccount],
    // ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
    //     self.handle_uninitialized_interface("pay for payables")
    // }

    fn get_transaction_receipt(&self, _hash: H256) -> ResultForReceipt {
        self.handle_uninitialized_interface("get transaction receipt")
    }

    fn lower_interface(&self) -> &dyn LowBlockchainInt {
        error!(
            self.logger,
            "Provides the null version of lower blockchain interface only"
        );
        &*self.lower_level_interface
    }

    as_any_ref_in_trait_impl!();
}

impl Default for BlockchainInterfaceNull {
    fn default() -> Self {
        Self::new()
    }
}

pub trait BlockchainInterfaceUninitializedError {
    fn error() -> Self;
}

macro_rules! impl_bci_uninitialized {
    ($($error_type: ty),+) => {
        $(
            impl BlockchainInterfaceUninitializedError for $error_type {
                fn error() -> Self {
                    Self::UninitializedBlockchainInterface
                }
            }
        )+
    }
}

impl_bci_uninitialized!(
    PayableTransactionError,
    BlockchainError,
    BlockchainAgentBuildError
);

impl BlockchainInterfaceNull {
    pub fn new() -> Self {
        let logger = Logger::new("BlockchainInterface");
        let lower_level_interface = Box::new(LowBlockChainIntNull::new(&logger));
        BlockchainInterfaceNull {
            logger,
            lower_level_interface,
        }
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
    use crate::blockchain::blockchain_interface::blockchain_interface_null::lower_level_interface_null::LowBlockChainIntNull;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::{
        BlockchainInterfaceNull, BlockchainInterfaceUninitializedError,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use ethereum_types::U64;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use web3::types::{BlockNumber, H160};
    use crate::blockchain::blockchain_interface::BlockchainInterface;
    use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainAgentBuildError, BlockchainError, PayableTransactionError};
    use futures::Future;
    fn make_subject(test_name: &str) -> BlockchainInterfaceNull {
        let logger = Logger::new(test_name);
        let lower_level_interface = Box::new(LowBlockChainIntNull::new(&logger));
        BlockchainInterfaceNull {
            logger,
            lower_level_interface,
        }
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

        let result = make_subject(test_name)
            .retrieve_transactions(
                BlockNumber::Number(U64::zero()),
                BlockNumber::Latest,
                &wallet,
            )
            .wait();

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
        let subject = make_subject(test_name);

        let result = subject.build_blockchain_agent(&wallet, &persistent_config);

        let err = match result {
            Ok(_) => panic!("we expected an error but got ok"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            BlockchainAgentBuildError::UninitializedBlockchainInterface
        );
        let expected_log_msg = format!(
            "ERROR: {test_name}: Failed to build blockchain agent with uninitialized blockchain \
            interface. Parameter blockchain-service-url is missing."
        );
        TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
    }

    #[test]
    fn blockchain_interface_null_cannot_send_batch_of_payables() {
        todo!("GH-744: send_batch_of_payables was removed");
        // init_test_logging();
        // let test_name = "blockchain_interface_null_cannot_send_batch_of_payables";
        // let (recorder, _, _) = make_recorder();
        // let recipient = recorder.start().recipient();
        // let accounts = vec![make_payable_account(111)];
        // let agent = Box::new(BlockchainAgentNull::new());
        //
        // let result = make_subject(test_name).send_batch_of_payables(agent, &recipient, &accounts);
        //
        // assert_eq!(
        //     result,
        //     Err(PayableTransactionError::UninitializedBlockchainInterface)
        // );
        // let expected_log_msg = format!(
        //     "ERROR: {test_name}: Failed to pay for payables with uninitialized blockchain \
        //     interface. Parameter blockchain-service-url is missing."
        // );
        // TestLogHandler::new().exists_log_containing(expected_log_msg.as_str());
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
    fn blockchain_interface_null_gives_null_lower_interface() {
        init_test_logging();
        let test_name = "blockchain_interface_null_gives_null_lower_interface";
        let wallet = make_wallet("abc");

        let _ = make_subject(test_name)
            .lower_interface()
            .get_transaction_id(&wallet);

        let expected_log_msg_from_low_level_interface_call = format!(
            "ERROR: {test_name}: Provides the null version of lower blockchain interface only"
        );
        let expected_log_msg_from_rcp_call =
            format!("ERROR: {test_name}: Null version can't fetch transaction id");
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            expected_log_msg_from_low_level_interface_call.as_str(),
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
