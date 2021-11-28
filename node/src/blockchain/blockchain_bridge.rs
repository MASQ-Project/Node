// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainResult, Transaction,
};
use crate::database::db_initializer::{DbInitializer, DATABASE_FILE};
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::utils::handle_ui_crash_request;
use crate::sub_lib::wallet::Wallet;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Actor, MessageResult};
use actix::{Addr, Recipient};
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::convert::TryFrom;
use std::path::PathBuf;
use web3::transports::Http;

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

pub struct BlockchainBridge {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    crashable: bool,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.set_consuming_wallet_subs_opt = Some(vec![
            msg.peer_actors
                .neighborhood
                .set_consuming_wallet_sub
                .clone(),
            msg.peer_actors.proxy_server.set_consuming_wallet_sub,
        ]);
        match self.consuming_wallet_opt.as_ref() {
            Some(wallet) => debug!(
                self.logger,
                "Received BindMessage; consuming wallet address {}", wallet
            ),
            None => debug!(
                self.logger,
                "Received BindMessage; no consuming wallet address specified"
            ),
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
    type Result = MessageResult<ReportAccountsPayable>;

    fn handle(
        &mut self,
        msg: ReportAccountsPayable,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<ReportAccountsPayable>>::Result {
        self.handle_report_accounts_payable(msg)
    }
}

impl Handler<NodeFromUiMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl BlockchainBridge {
    pub fn new(
        blockchain_interface: Box<dyn BlockchainInterface>,
        persistent_config: Box<dyn PersistentConfiguration>,
        crashable: bool,
        consuming_wallet_opt: Option<Wallet>,
    ) -> BlockchainBridge {
        BlockchainBridge {
            consuming_wallet_opt,
            blockchain_interface,
            persistent_config,
            set_consuming_wallet_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
        }
    }

    pub fn make_connections(
        blockchain_service_url: Option<String>,
        db_initializer: &dyn DbInitializer,
        data_directory: PathBuf,
        chain: Chain,
    ) -> (
        Box<dyn BlockchainInterface>,
        Box<dyn PersistentConfiguration>,
    ) {
        let blockchain_interface: Box<dyn BlockchainInterface> = {
            match blockchain_service_url {
                Some(url) => match Http::new(&url) {
                    Ok((event_loop_handle, transport)) => Box::new(
                        BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain),
                    ),
                    Err(e) => panic!("Invalid blockchain node URL: {:?}", e),
                },
                None => Box::new(BlockchainInterfaceClandestine::new(chain)),
            }
        };
        let config_dao = Box::new(ConfigDaoReal::new(
            db_initializer
                .initialize(&data_directory, true, MigratorConfig::panic_on_migration())
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to connect to database at {:?}",
                        &data_directory.join(DATABASE_FILE)
                    )
                }),
        ));
        (
            blockchain_interface,
            Box::new(PersistentConfigurationReal::new(config_dao)),
        )
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            report_accounts_payable: recipient!(addr, ReportAccountsPayable),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    fn handle_report_accounts_payable(
        &self,
        creditors_msg: ReportAccountsPayable,
    ) -> MessageResult<ReportAccountsPayable> {
        MessageResult(match self.consuming_wallet_opt.as_ref() {
            Some(consuming_wallet) => {
                let gas_price = match self.persistent_config.gas_price() {
                    Ok(num) => num,
                    Err(err) => {
                        return MessageResult(Err(format!(
                            "ReportAccountPayable: gas-price: {:?}",
                            err
                        )))
                    }
                };
                Ok(self.process_payments(creditors_msg, gas_price, consuming_wallet))
            }
            None => Err(String::from("No consuming wallet specified")),
        })
    }

    fn process_payments(
        &self,
        creditors_msg: ReportAccountsPayable,
        gas_price: u64,
        consuming_wallet: &Wallet,
    ) -> Vec<BlockchainResult<Payment>> {
        creditors_msg
            .accounts
            .iter()
            .map(|payable| {
                match self
                    .blockchain_interface
                    .get_transaction_count(consuming_wallet)
                {
                    Ok(nonce) => {
                        let amount = u64::try_from(payable.balance).unwrap_or_else(|_| {
                            panic!("Lost payable amount precision: {}", payable.balance)
                        });
                        match self.blockchain_interface.send_transaction(
                            consuming_wallet,
                            &payable.wallet,
                            amount,
                            nonce,
                            gas_price,
                        ) {
                            Ok(hash) => Ok(Payment::new(payable.wallet.clone(), amount, hash)),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .collect::<Vec<BlockchainResult<Payment>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableAccount;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_interface::{
        Balance, BlockchainError, BlockchainResult, Nonce, Transaction, Transactions,
    };
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        make_default_persistent_configuration, prove_that_crash_request_handler_is_hooked_up,
    };
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::Addr;
    use actix::System;
    use ethsign::SecretKey;
    use ethsign_crypto::Keccak256;
    use futures::future::Future;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use rustc_hex::FromHex;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{Address, H256, U256};

    fn stub_bi() -> Box<dyn BlockchainInterface> {
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
            stub_bi(),
            Box::new(make_default_persistent_configuration()),
            false,
            Some(consuming_wallet.clone()),
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
            stub_bi(),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
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

    #[derive(Debug, Default)]
    struct BlockchainInterfaceMock {
        pub retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
        pub retrieve_transactions_results: RefCell<Vec<BlockchainResult<Vec<Transaction>>>>,
        pub send_transaction_parameters: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
        pub send_transaction_results: RefCell<Vec<BlockchainResult<H256>>>,
        pub contract_address_results: RefCell<Vec<Address>>,
        pub get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
        pub get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
    }

    impl BlockchainInterfaceMock {
        fn retrieve_transactions_result(
            self,
            result: Result<Vec<Transaction>, BlockchainError>,
        ) -> Self {
            self.retrieve_transactions_results.borrow_mut().push(result);
            self
        }

        fn send_transaction_result(self, result: BlockchainResult<H256>) -> Self {
            self.send_transaction_results.borrow_mut().push(result);
            self
        }

        fn contract_address_result(self, address: Address) -> Self {
            self.contract_address_results.borrow_mut().push(address);
            self
        }

        fn get_transaction_count_result(self, result: BlockchainResult<U256>) -> Self {
            self.get_transaction_count_results.borrow_mut().push(result);
            self
        }
    }

    impl BlockchainInterface for BlockchainInterfaceMock {
        fn contract_address(&self) -> Address {
            self.contract_address_results.borrow_mut().remove(0)
        }

        fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
            self.retrieve_transactions_parameters
                .lock()
                .unwrap()
                .push((start_block, recipient.clone()));
            self.retrieve_transactions_results.borrow_mut().remove(0)
        }

        fn send_transaction(
            &self,
            consuming_wallet: &Wallet,
            recipient: &Wallet,
            amount: u64,
            nonce: U256,
            gas_price: u64,
        ) -> BlockchainResult<H256> {
            self.send_transaction_parameters.lock().unwrap().push((
                consuming_wallet.clone(),
                recipient.clone(),
                amount,
                nonce,
                gas_price,
            ));
            self.send_transaction_results.borrow_mut().remove(0)
        }

        fn get_eth_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_token_balance(&self, _address: &Wallet) -> Balance {
            unimplemented!()
        }

        fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
            self.get_transaction_count_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());
            self.get_transaction_count_results.borrow_mut().remove(0)
        }
    }

    #[test]
    #[should_panic(expected = "Invalid blockchain node URL")]
    fn invalid_blockchain_url_produces_panic() {
        let data_directory = PathBuf::new(); //never reached
        let blockchain_service_url = Some("http://λ:8545".to_string());
        let _ = BlockchainBridge::make_connections(
            blockchain_service_url,
            &DbInitializerMock::default(),
            data_directory,
            DEFAULT_CHAIN,
        );
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
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_result(result)
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
        let retrieve_transactions_parameters = blockchain_interface_mock
            .retrieve_transactions_parameters
            .clone();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
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

    #[test]
    fn report_accounts_payable_sends_transactions_to_blockchain_interface() {
        let system =
            System::new("report_accounts_payable_sends_transactions_to_blockchain_interface");
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(U256::from(1)))
            .get_transaction_count_result(Ok(U256::from(2)))
            .send_transaction_result(Ok(H256::from("sometransactionhash".keccak256())))
            .send_transaction_result(Ok(H256::from("someothertransactionhash".keccak256())))
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
        let send_parameters = blockchain_interface_mock
            .send_transaction_parameters
            .clone();
        let transaction_count_parameters = blockchain_interface_mock
            .get_transaction_count_parameters
            .clone();
        let expected_gas_price = 5u64;
        let persistent_configuration_mock =
            PersistentConfigurationMock::default().gas_price_result(Ok(expected_gas_price));

        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet.clone()),
        );
        let addr: Addr<BlockchainBridge> = subject.start();

        let request = addr.send(ReportAccountsPayable {
            accounts: vec![
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance: 42,
                    last_paid_timestamp: SystemTime::now(),
                    pending_payment_transaction: None,
                },
                PayableAccount {
                    wallet: make_wallet("foo"),
                    balance: 21,
                    last_paid_timestamp: SystemTime::now(),
                    pending_payment_transaction: None,
                },
            ],
        });
        System::current().stop();
        system.run();

        assert_eq!(
            send_parameters.lock().unwrap()[0],
            (
                consuming_wallet.clone(),
                make_wallet("blah"),
                42,
                U256::from(1),
                expected_gas_price
            )
        );
        assert_eq!(
            send_parameters.lock().unwrap()[1],
            (
                consuming_wallet.clone(),
                make_wallet("foo"),
                21,
                U256::from(2),
                expected_gas_price
            )
        );

        let result = request.wait().unwrap().unwrap();
        let mut expected_payment_0 = Payment::new(
            make_wallet("blah"),
            42,
            H256::from("sometransactionhash".keccak256()),
        );

        if let Ok(zero) = result.clone().get(0).unwrap().clone() {
            assert!(
                zero.timestamp
                    <= expected_payment_0
                        .timestamp
                        .checked_add(Duration::from_secs(2))
                        .unwrap()
            );
            assert!(
                zero.timestamp
                    >= expected_payment_0
                        .timestamp
                        .checked_sub(Duration::from_secs(2))
                        .unwrap()
            );
            expected_payment_0.timestamp = zero.timestamp
        }

        let mut expected_payment_1 = Payment::new(
            make_wallet("foo"),
            21,
            H256::from("someothertransactionhash".keccak256()),
        );

        if let Ok(one) = result.clone().get(1).unwrap().clone() {
            assert!(
                one.timestamp
                    <= expected_payment_1
                        .timestamp
                        .checked_add(Duration::from_secs(2))
                        .unwrap()
            );
            assert!(
                one.timestamp
                    >= expected_payment_1
                        .timestamp
                        .checked_sub(Duration::from_secs(2))
                        .unwrap()
            );
            expected_payment_1.timestamp = one.timestamp
        }

        assert_eq!(result[1], Ok(expected_payment_1));

        assert_eq!(
            transaction_count_parameters.lock().unwrap()[0],
            consuming_wallet.clone(),
        );
        assert_eq!(
            transaction_count_parameters.lock().unwrap()[1],
            consuming_wallet.clone(),
        );
    }

    #[test]
    fn report_accounts_payable_returns_error_for_blockchain_error() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_result(Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure",
            ))));
        let transaction_count_parameters = blockchain_interface_mock
            .get_transaction_count_parameters
            .clone();
        let consuming_wallet = make_wallet("somewallet");
        let persistent_configuration_mock =
            PersistentConfigurationMock::new().gas_price_result(Ok(3u64));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet.clone()),
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        assert_eq!(
            result.0,
            Ok(vec![Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure"
            )))])
        );
        let actual_wallet = transaction_count_parameters.lock().unwrap().remove(0);
        assert_eq!(actual_wallet, consuming_wallet);
    }

    #[test]
    fn report_accounts_payable_returns_error_when_there_is_no_consuming_wallet_configured() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default();
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            None,
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        assert_eq!(result.0, Err("No consuming wallet specified".to_string()));
    }

    #[test]
    fn handle_report_account_payable_manages_gas_price_error() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)));
        let persistent_configuration_mock = PersistentConfigurationMock::new()
            .gas_price_result(Err(PersistentConfigError::TransactionError));
        let consuming_wallet = make_wallet("somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet),
        );
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payment_transaction: None,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        assert_eq!(
            result.0,
            Err(String::from(
                "ReportAccountPayable: gas-price: TransactionError"
            ))
        )
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let actor = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            crashable,
            None,
        );

        prove_that_crash_request_handler_is_hooked_up(actor, CRASH_KEY);
    }
}
