// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::accountant::{ReceivedPayments, SentPayments};
use crate::blockchain::blockchain_interface::{
    BlockchainInterface, BlockchainInterfaceClandestine, BlockchainInterfaceNonClandestine,
    BlockchainResult,
};
use crate::database::db_initializer::{DbInitializer, DATABASE_FILE};
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::utils::handle_ui_crash_request;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Addr, Recipient};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
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
    sent_payments_subs_opt: Option<Recipient<SentPayments>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
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
        self.sent_payments_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.received_payments_subs_opt = Some(msg.peer_actors.accountant.report_new_payments);
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

#[derive(Debug, Eq, PartialEq, Message, Clone)]
pub struct RetrieveTransactions {
    pub start_block: u64,
    pub recipient: Wallet,
}
impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = ();

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        self.handle_retrieve_transactions(msg)
    }
}

impl Handler<ReportAccountsPayable> for BlockchainBridge {
    type Result = ();

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
            sent_payments_subs_opt: None,
            received_payments_subs_opt: None,
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

    fn handle_report_accounts_payable(&self, creditors_msg: ReportAccountsPayable) {
        let processed_payments = self.handle_report_accounts_payable_inner(creditors_msg);
        match processed_payments {
            Ok(payments) => {
                self.sent_payments_subs_opt
                    .as_ref()
                    .expect("Accountant is unbound")
                    .try_send(SentPayments { payments })
                    .expect("Accountant is dead");
            }
            Err(e) => warning!(self.logger, "{}", e),
        }
    }

    fn handle_report_accounts_payable_inner(
        &self,
        creditors_msg: ReportAccountsPayable,
    ) -> Result<Vec<BlockchainResult<Payment>>, String> {
        match self.consuming_wallet_opt.as_ref() {
            Some(consuming_wallet) => match self.persistent_config.gas_price() {
                Ok(gas_price) => {
                    Ok(self.process_payments(creditors_msg, gas_price, consuming_wallet))
                }
                Err(err) => Err(format!("ReportAccountPayable: gas-price: {:?}", err)),
            },
            None => Err(String::from("No consuming wallet specified")),
        }
    }

    fn handle_retrieve_transactions(&self, msg: RetrieveTransactions) {
        let retrieved_transactions = self
            .blockchain_interface
            .retrieve_transactions(msg.start_block, &msg.recipient);
        match retrieved_transactions {
            Ok(transactions) if transactions.is_empty() => {
                debug!(self.logger, "No new receivable detected")
            }
            Ok(transactions) => self
                .received_payments_subs_opt
                .as_ref()
                .expect("Accountant is unbound")
                .try_send(ReceivedPayments {
                    payments: transactions,
                })
                .expect("Accountant is dead."),
            Err(e) => warning!(
                self.logger,
                "Attempted to retrieve received payments but failed: {:?}",
                e
            ),
        }
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
                            self.blockchain_interface.send_transaction_tools().as_ref(),
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
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::{
        configure_default_persistent_config, prove_that_crash_request_handler_is_hooked_up,
    };
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethsign_crypto::Keccak256;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use rustc_hex::FromHex;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use web3::types::{H256, U256};

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(BlockchainInterfaceMock::default())
    }

    #[test]
    fn blockchain_bridge_receives_bind_message_with_consuming_private_key() {
        init_test_logging();
        let secret: Vec<u8> = "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            .from_hex()
            .unwrap();
        let consuming_wallet = Wallet::from(Bip32ECKeyProvider::from_raw_secret(&secret).unwrap());
        let subject = BlockchainBridge::new(
            stub_bi(),
            Box::new(configure_default_persistent_config(
                0b0000_0001
            )),
            false,
            Some(consuming_wallet.clone()),
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();

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
        let addr = subject.start();

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
    fn report_accounts_payable_returns_error_for_blockchain_error() {
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_result(Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure",
            ))));
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

        let result = subject.handle_report_accounts_payable_inner(request);

        assert_eq!(
            result,
            Ok(vec![Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure"
            )))])
        );
        let actual_wallet = get_transaction_count_params_arc.lock().unwrap().remove(0);
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

        let result = subject.handle_report_accounts_payable_inner(request);

        assert_eq!(result, Err("No consuming wallet specified".to_string()));
    }

    #[test]
    fn handle_report_accounts_payable_transacts_and_sends_finished_payments_back_to_accountant() {
        let system =
            System::new("report_accounts_payable_sends_transactions_to_blockchain_interface");
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let send_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(U256::from(1)))
            .get_transaction_count_result(Ok(U256::from(2)))
            .send_transaction_params(&send_transaction_params_arc)
            .send_transaction_result(Ok(H256::from("sometransactionhash".keccak256())))
            .send_transaction_result(Ok(H256::from("someothertransactionhash".keccak256())));
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
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(ReportAccountsPayable {
                accounts: vec![
                    PayableAccount {
                        wallet: make_wallet("blah"),
                        balance: 420,
                        last_paid_timestamp: from_time_t(150_000_000),
                        pending_payment_transaction: None,
                    },
                    PayableAccount {
                        wallet: make_wallet("foo"),
                        balance: 210,
                        last_paid_timestamp: from_time_t(120_000_000),
                        pending_payment_transaction: None,
                    },
                ],
            })
            .unwrap();

        System::current().stop();
        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        let send_transaction_params = send_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *send_transaction_params,
            vec![
                (
                    consuming_wallet.clone(),
                    make_wallet("blah"),
                    420,
                    U256::from(1),
                    expected_gas_price
                ),
                (
                    consuming_wallet.clone(),
                    make_wallet("foo"),
                    210,
                    U256::from(2),
                    expected_gas_price
                )
            ]
        );
        let get_transaction_count_params = get_transaction_count_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_count_params,
            vec![consuming_wallet.clone(), consuming_wallet.clone()]
        );
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let sent_payment_msg = accountant_received_payment.get_record::<SentPayments>(0);
        let mut sent_payments_cloned = sent_payment_msg.payments.clone();
        let mut list_of_timestamps = vec![];
        sent_payments_cloned
            .iter_mut()
            .for_each(|payment_in_result| {
                let payment = payment_in_result.as_mut().unwrap();
                list_of_timestamps.push(payment.timestamp);
                payment.timestamp = from_time_t(0)
            });
        assert_eq!(
            sent_payments_cloned,
            vec![
                Ok(Payment {
                    to: make_wallet("blah"),
                    amount: 420,
                    timestamp: from_time_t(0), //cannot be asserted directly, this field is just a sentinel
                    transaction: H256::from("sometransactionhash".keccak256())
                }),
                Ok(Payment {
                    to: make_wallet("foo"),
                    amount: 210,
                    timestamp: from_time_t(0), //cannot be asserted directly, this field is just a sentinel
                    transaction: H256::from("someothertransactionhash".keccak256())
                })
            ]
        );
        list_of_timestamps.iter().for_each(|stamp| {
            assert!(
                before < *stamp && *stamp < after,
                "before: {:?}, actual: {:?}, after: {:?}",
                before,
                stamp,
                after
            )
        })
    }

    #[test]
    fn handle_report_account_payable_manages_gas_price_error() {
        init_test_logging();
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

        let _ = subject.handle_report_accounts_payable(request);

        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: ReportAccountPayable: gas-price: TransactionError",
        );
    }

    #[test]
    fn blockchain_bridge_logs_error_from_retrieving_received_payments() {
        init_test_logging();
        let blockchain_interface = BlockchainInterfaceMock::default().retrieve_transactions_result(
            Err(BlockchainError::QueryFailed("we have no luck".to_string())),
        );
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        let msg = RetrieveTransactions {
            start_block: 5,
            recipient: make_wallet("blah"),
        };

        let _ = subject.handle_retrieve_transactions(msg);

        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: Attempted to retrieve \
         received payments but failed: QueryFailed(\"we have no luck\")",
        );
    }

    #[test]
    fn handle_retrieve_transactions_sends_received_payments_back_to_accountant() {
        let retrieve_transactions_params_arc = Arc::new(Mutex::new(vec![]));
        let system =
            System::new("handle_retrieve_transactions_sends_received_payments_back_to_accountant");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let earning_wallet = make_wallet("somewallet");
        let amount = 42;
        let amount2 = 55;
        let expected_transactions = vec![
            Transaction {
                block_number: 7,
                from: earning_wallet.clone(),
                gwei_amount: amount,
            },
            Transaction {
                block_number: 9,
                from: earning_wallet.clone(),
                gwei_amount: amount2,
            },
        ];
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_params(&retrieve_transactions_params_arc)
            .retrieve_transactions_result(Ok(expected_transactions.clone()));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            Some(make_wallet("consuming")),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            start_block: 6,
            recipient: earning_wallet.clone(),
        };

        let _ = addr.try_send(retrieve_transactions).unwrap();

        System::current().stop();
        system.run();
        let retrieve_transactions_params = retrieve_transactions_params_arc.lock().unwrap();
        assert_eq!(*retrieve_transactions_params, vec![(6, earning_wallet)]);
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                payments: expected_transactions
            }
        );
    }

    #[test]
    fn processing_of_received_payments_does_not_continue_if_no_payments_detected() {
        init_test_logging();
        let blockchain_interface_mock =
            BlockchainInterfaceMock::default().retrieve_transactions_result(Ok(vec![]));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None, //not needed in this test
        );
        let retrieve_transactions = RetrieveTransactions {
            start_block: 6,
            recipient: make_wallet("somewallet"),
        };

        let _ = subject.handle_retrieve_transactions(retrieve_transactions);

        TestLogHandler::new()
            .exists_log_containing("DEBUG: BlockchainBridge: No new receivable detected");
        //the test did not panic, meaning we did not try to send the actor message
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
