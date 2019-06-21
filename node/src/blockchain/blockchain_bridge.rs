// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface, Transaction};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::Wallet;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};

pub struct BlockchainBridge {
    config: BlockchainBridgeConfig,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        match self.config.consuming_wallet.as_ref() {
            Some(wallet) => {
                self.logger.debug(format!(
                    "Received BindMessage; consuming wallet address {}",
                    wallet
                ));
            }
            None => {
                self.logger.debug(
                    "Received BindMessage; no consuming wallet address specified".to_string(),
                );
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RetrieveTransactions {
    pub start_block: u64,
    pub recipient: Wallet,
}

impl Message for RetrieveTransactions {
    type Result = Result<Vec<Transaction>, BlockchainError>;
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
            retrieve_transactions: addr.clone().recipient::<RetrieveTransactions>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::{
        Balance, BlockchainError, Transaction, Transactions, TESTNET_CONTRACT_ADDRESS,
    };
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::test_utils::make_wallet;
    use actix::Addr;
    use actix::System;
    use ethsign::SecretKey;
    use futures::future::Future;
    use rustc_hex::FromHex;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    fn stub_bi() -> Box<BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();
        let secret: Vec<u8> = "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            .from_hex()
            .unwrap();
        let consuming_private_key = SecretKey::from_raw(&secret).unwrap();

        let consuming_wallet = Wallet::from(Bip32ECKeyPair::from(consuming_private_key));
        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_wallet: Some(consuming_wallet.clone()),
                mnemonic_seed: Some(String::from("cc43146a8987a33d2ef331dd6fde88b0656a1c288e00546ccf12ad333560ba6e5bff098071a3c5a9d24a79f78f40ce07614c2e70ff111e52441f1360fea44127")),
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
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: BlockchainBridge: Received BindMessage; consuming wallet address {}",
            consuming_wallet
        ));
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_without_consuming_private_key() {
        init_test_logging();

        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_wallet: None,
                mnemonic_seed: None,
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
            "DEBUG: BlockchainBridge: Received BindMessage; no consuming wallet address specified",
        );
    }

    #[test]
    fn blockchain_bridge_receives_report_accounts_payable_message_and_logs() {
        init_test_logging();

        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_wallet: None,
                mnemonic_seed: None,
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
        pub retrieve_transactions_results: RefCell<Vec<Result<Vec<Transaction>, BlockchainError>>>,
    }

    impl BlockchainInterfaceMock {
        fn retrieve_transactions_result(
            self,
            result: Result<Vec<Transaction>, BlockchainError>,
        ) -> Self {
            self.retrieve_transactions_results.borrow_mut().push(result);
            self
        }
    }

    impl BlockchainInterface for BlockchainInterfaceMock {
        fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
            self.retrieve_transactions_parameters
                .lock()
                .unwrap()
                .push((start_block, recipient.clone()));
            self.retrieve_transactions_results.borrow_mut().remove(0)
        }

        fn get_eth_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_token_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }
    }

    #[test]
    fn ask_me_about_my_transactions() {
        let system = System::new("ask_me_about_my_transactions");
        let block_no = 37;
        let expected_results = vec![Transaction {
            block_number: 42u64,
            from: make_wallet("some_address"),
            gwei_amount: 21,
        }];
        let result = Ok(expected_results.clone());
        let wallet = make_wallet("smelly");
        let blockchain_interface_mock =
            BlockchainInterfaceMock::default().retrieve_transactions_result(result);
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_wallet: None,
                mnemonic_seed: None,
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

        let result = request.wait().unwrap().unwrap();
        assert_eq!(expected_results, result);
    }
}
