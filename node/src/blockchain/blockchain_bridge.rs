// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface, Transaction};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::Wallet;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};
use futures::Future;

pub struct BlockchainBridge {
    config: BlockchainBridgeConfig,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
}

#[allow(dead_code)] // Not utilized by SC-702, but should be in future.
struct RetrieveTransactions {
    start_block: u64,
    recipient: Wallet,
}

impl Message for RetrieveTransactions {
    type Result = Box<Future<Item = Vec<Transaction>, Error = BlockchainError> + Send>;
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        match self.config.consuming_private_key.as_ref() {
            Some(key) => {
                // This is hashing the UTF-8 bytes of the string, not the actual bytes encoded as hex
                let hash = CryptDENull::new().hash(&PlainData::new(key.as_bytes()));
                self.logger.debug(format!(
                    "Received BindMessage; consuming private key that hashes to {:?}",
                    hash
                ));
            }
            None => {
                self.logger
                    .debug("Received BindMessage; no consuming private key specified".to_string());
            }
        }
    }
}

impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = MessageResult<RetrieveTransactions>;

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        MessageResult(
            self.blockchain_interface
                .retrieve_transactions(msg.start_block, &msg.recipient),
        )
    }
}

impl Handler<ReportAccountsPayable> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, _msg: ReportAccountsPayable, _ctx: &mut Self::Context) -> Self::Result {
        self.logger
            .debug("Received ReportAccountsPayable message".to_string());
    }
}

impl BlockchainBridge {
    pub fn new(
        config: BlockchainBridgeConfig,
        blockchain_interface: Box<dyn BlockchainInterface>,
    ) -> BlockchainBridge {
        BlockchainBridge {
            config,
            blockchain_interface,
            logger: Logger::new("BlockchainBridge"),
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            report_accounts_payable: addr.clone().recipient::<ReportAccountsPayable>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::{
        BlockchainError, Transaction, TESTNET_CONTRACT_ADDRESS,
    };
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::test_utils::cryptde;
    use actix::Addr;
    use actix::System;
    use futures::future::ok;
    use futures::Future;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use web3::types::U256;

    fn stub_bi() -> Box<BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();

        let consuming_private_key =
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9".to_string();
        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_private_key: Some(consuming_private_key.clone()),
            },
            stub_bi(),
        );

        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        let hash = cryptde().hash(&PlainData::new(consuming_private_key.as_bytes()));
        TestLogHandler::new()
            .exists_log_containing(&format!("DEBUG: BlockchainBridge: Received BindMessage; consuming private key that hashes to {:?}", hash));
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_without_consuming_private_key() {
        init_test_logging();

        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_private_key: None,
            },
            stub_bi(),
        );

        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Received BindMessage; no consuming private key specified",
        );
    }

    #[test]
    fn blockchain_bridge_receives_report_accounts_payable_message_and_logs() {
        init_test_logging();

        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_private_key: None,
            },
            stub_bi(),
        );

        let system = System::new("blockchain_bridge_receives_report_accounts_payable_message");
        let addr: Addr<BlockchainBridge> = subject.start();

        addr.try_send(ReportAccountsPayable { accounts: vec![] })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Received ReportAccountsPayable message",
        );
    }

    #[derive(Default)]
    struct BlockchainInterfaceMock {
        pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
        pub retrieve_transactions_results:
            RefCell<Vec<Box<dyn Future<Item = Vec<Transaction>, Error = BlockchainError> + Send>>>,
    }

    impl BlockchainInterfaceMock {
        fn retrieve_transactions_result(
            self,
            result: Box<dyn Future<Item = Vec<Transaction>, Error = BlockchainError> + Send>,
        ) -> Self {
            self.retrieve_transactions_results.borrow_mut().push(result);
            self
        }
    }

    impl BlockchainInterface for BlockchainInterfaceMock {
        fn retrieve_transactions(
            &self,
            start_block: u64,
            recipient: &Wallet,
        ) -> Box<dyn Future<Item = Vec<Transaction>, Error = BlockchainError> + Send> {
            self.retrieve_transactions_parameters
                .lock()
                .unwrap()
                .push((start_block.clone(), recipient.clone()));
            self.retrieve_transactions_results.borrow_mut().remove(0)
        }
    }

    #[test]
    fn ask_me_about_my_transactions() {
        let system = System::new("ask_me_about_my_transactions");
        let block_no = 37;
        let expected_results = vec![Transaction {
            block_number: U256::from(42),
            from: Wallet::new("some_address"),
            amount: U256::from(21),
        }];
        let result = Box::new(ok(expected_results.clone()));
        let wallet = Wallet {
            address: "smelly".to_string(),
        };
        let blockchain_interface_mock =
            BlockchainInterfaceMock::default().retrieve_transactions_result(result);
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_private_key: None,
            },
            Box::new(blockchain_interface_mock),
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(RetrieveTransactions {
            start_block: block_no,
            recipient: wallet.clone(),
        });
        System::current().stop();
        system.run();

        let retrieve_transactions_parameters = retrieve_transactions_parameters.lock().unwrap();
        assert_eq!((block_no, wallet), retrieve_transactions_parameters[0]);

        let result = request.wait().unwrap().wait().unwrap();
        assert_eq!(expected_results, result);
    }
}
