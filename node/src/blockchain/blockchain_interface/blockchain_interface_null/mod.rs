// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod rpc_helpers_null;

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::rpc_helpers::RPCHelpers;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, PayableTransactionError, ProcessedPayableFallible,
    ResultForReceipt, RetrievedBlockchainTransactions,
};
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use masq_lib::blockchains::chains::Chain;

use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::BlockchainAgentNull;
use crate::blockchain::blockchain_interface::blockchain_interface_null::rpc_helpers_null::RPCHelpersNull;
use masq_lib::logger::Logger;
use web3::types::{Address, H256};

// TODO: This probably should go away
pub struct BlockchainInterfaceClandestine {
    logger: Logger,
    helper: Box<dyn RPCHelpers>,
    chain: Chain,
}

impl BlockchainInterfaceClandestine {
    pub fn new(chain: Chain) -> Self {
        let logger = Logger::new("BlockchainInterface");
        let helper = Box::new(RPCHelpersNull::new(&logger));
        BlockchainInterfaceClandestine {
            logger,
            helper,
            chain,
        }
    }
}

impl BlockchainInterface for BlockchainInterfaceClandestine {
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn retrieve_transactions(
        &self,
        _start_block: u64,
        _recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        let msg = "Can't retrieve transactions clandestinely yet".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::QueryFailed(msg))
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
        error!(self.logger, "Can't send transactions out clandestinely yet",);
        Err(PayableTransactionError::Sending {
            msg: "invalid attempt to send txs clandestinely".to_string(),
            hashes: vec![],
        })
    }

    fn get_transaction_receipt(&self, _hash: H256) -> ResultForReceipt {
        error!(
            self.logger,
            "Can't get transaction receipt clandestinely yet",
        );
        Ok(None)
    }

    fn helpers(&self) -> &dyn RPCHelpers {
        error!(self.logger, "Can provide only RPC helpers null");
        &*self.helper
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_null::BlockchainAgentNull;
    use crate::accountant::test_utils::make_payable_account;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::rpc_helpers_null::RPCHelpersNull;
    use crate::blockchain::blockchain_interface::blockchain_interface_null::BlockchainInterfaceClandestine;
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainInterface, PayableTransactionError,
    };
    use crate::blockchain::test_utils::{all_chains, make_tx_hash};
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use actix::Actor;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

    fn make_clandestine_subject(test_name: &str, chain: Chain) -> BlockchainInterfaceClandestine {
        let logger = Logger::new(test_name);
        let helper = Box::new(RPCHelpersNull::new(&logger));
        BlockchainInterfaceClandestine {
            logger,
            helper,
            chain,
        }
    }

    #[test]
    fn blockchain_interface_clandestine_returns_contract_address() {
        all_chains().into_iter().for_each(|chain| {
            assert_eq!(
                make_clandestine_subject("irrelevant", chain).contract_address(),
                chain.rec().contract
            )
        })
    }

    #[test]
    fn blockchain_interface_clandestine_retrieves_no_transactions() {
        init_test_logging();
        let test_name = "blockchain_interface_clandestine_retrieves_no_transactions";
        let expected_msg = "Can't retrieve transactions clandestinely yet";
        let wallet = make_wallet("blah");
        let chains = all_chains();

        chains.into_iter().for_each(|chain| {
            assert_eq!(
                make_clandestine_subject(test_name, chain).retrieve_transactions(0, &wallet),
                Err(BlockchainError::QueryFailed(expected_msg.to_string()))
            )
        });

        let expected_log_msg = format!("ERROR: {test_name}: {}", expected_msg);
        TestLogHandler::new()
            .assert_logs_contain_in_order(vec![expected_log_msg.as_str()].repeat(chains.len()));
    }

    #[test]
    fn blockchain_interface_clandestine_builds_null_agent() {
        init_test_logging();
        let test_name = "blockchain_interface_clandestine_builds_null_agent";
        let wallet = make_wallet("blah");
        let persistent_config = PersistentConfigurationMock::new();
        let chains = all_chains();

        chains.into_iter().for_each(|chain| {
            let result = make_clandestine_subject(test_name, chain)
                .build_blockchain_agent(&wallet, &persistent_config)
                .unwrap();
            result
                .as_any()
                .downcast_ref::<BlockchainAgentNull>()
                .unwrap();
        });

        let expected_log_msg = format!("ERROR: {test_name}: Builds a null blockchain agent only");
        TestLogHandler::new()
            .assert_logs_contain_in_order(vec![expected_log_msg.as_str()].repeat(chains.len()));
    }

    #[test]
    fn blockchain_interface_clandestine_cannot_send_batch_of_payables() {
        init_test_logging();
        let test_name = "blockchain_interface_clandestine_cannot_send_batch_of_payables";
        let chains = all_chains();
        let (recorder, _, _) = make_recorder();
        let recipient = recorder.start().recipient();
        let accounts = vec![make_payable_account(111)];

        chains.into_iter().for_each(|chain| {
            let agent_digest = Box::new(BlockchainAgentNull::new());
            assert_eq!(
                make_clandestine_subject(test_name, chain).send_batch_of_payables(
                    agent_digest,
                    &recipient,
                    &accounts
                ),
                Err(PayableTransactionError::Sending {
                    msg: "invalid attempt to send txs clandestinely".to_string(),
                    hashes: vec![],
                })
            )
        });

        let expected_log_msg =
            format!("ERROR: {test_name}: Can't send transactions out clandestinely yet");
        TestLogHandler::new()
            .assert_logs_contain_in_order(vec![expected_log_msg.as_str()].repeat(chains.len()));
    }

    #[test]
    fn blockchain_interface_clandestine_gets_no_transaction_receipt() {
        init_test_logging();
        let test_name = "blockchain_interface_clandestine_gets_no_transaction_receipt";
        let tx_hash = make_tx_hash(123);
        let chains = all_chains();

        chains.into_iter().for_each(|chain| {
            assert_eq!(
                make_clandestine_subject(test_name, chain).get_transaction_receipt(tx_hash),
                Ok(None)
            )
        });

        let expected_log_msg =
            format!("ERROR: {test_name}: Can't get transaction receipt clandestinely yet");
        TestLogHandler::new()
            .assert_logs_contain_in_order(vec![expected_log_msg.as_str()].repeat(chains.len()));
    }

    #[test]
    fn blockchain_interface_clandestine_gives_null_helper() {
        init_test_logging();
        let test_name = "blockchain_interface_clandestine_gives_null_helper";
        let wallet = make_wallet("abc");
        let chains = all_chains();

        chains.into_iter().for_each(|chain| {
            let _ = make_clandestine_subject(test_name, chain)
                .helpers()
                .get_transaction_id(&wallet);
        });

        let expected_log_msg = format!("ERROR: {test_name}: Can provide only RPC helpers null");
        TestLogHandler::new()
            .assert_logs_contain_in_order(vec![expected_log_msg.as_str()].repeat(chains.len()));
    }
}
