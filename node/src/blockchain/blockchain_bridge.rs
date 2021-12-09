// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::accountant::RequestTransactionReceipts;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainResult, Transaction, TxReceipt,
};
use crate::blockchain::tool_wrappers::PaymentBackupRecipientWrapperReal;
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
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::convert::TryFrom;
use std::default::Default;
use std::path::PathBuf;
use std::time::SystemTime;
use web3::transports::Http;
use web3::types::H256;

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

pub struct BlockchainBridge {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    #[allow(dead_code)]
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    crashable: bool,
    payment_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    transaction_backup_tx_subs_opt: Option<Recipient<PendingPaymentBackup>>,
    report_transaction_receipts_sub_opt: Option<Recipient<ReportTransactionReceipts>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        //TODO is this dead code?
        // self.set_consuming_wallet_subs_opt = Some(vec![
        //     msg.peer_actors.neighborhood.set_consuming_wallet_sub,
        //     msg.peer_actors.proxy_server.set_consuming_wallet_sub,
        // ]);
        self.payment_confirmation.transaction_backup_tx_subs_opt =
            Some(msg.peer_actors.accountant.transaction_backup);
        self.payment_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
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

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        let results: Vec<(TxReceipt, Payment)> = msg
            .pending_payments
            .iter()
            .map(|pending_payment| {
                self.blockchain_interface
                    .get_transaction_receipt(pending_payment.transaction)
            })
            .zip(msg.pending_payments.iter().cloned())
            .collect_vec();
        self.payment_confirmation
            .report_transaction_receipts_sub_opt
            .as_ref()
            .expect("Accountant is unbound")
            .try_send(ReportTransactionReceipts {
                payments_with_tx_receipts: results,
                receipt_failure_count: 0,
                attempt: msg.attempt,
            })
            .expect("Accountant is dead")
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub payments_with_tx_receipts: Vec<(TxReceipt, Payment)>,
    pub attempt: u16,
}

#[derive(Debug, PartialEq, Message, Clone, Copy)]
pub struct PendingPaymentBackup {
    pub rowid: u16,
    pub payment_timestamp: SystemTime,
    pub amount: u64,
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
            payment_confirmation: TransactionConfirmationTools {
                transaction_backup_tx_subs_opt: None,
                report_transaction_receipts_sub_opt: None,
            },
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
            request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
        }
    }

    fn handle_report_accounts_payable(
        &self,
        creditors_msg: ReportAccountsPayable,
    ) -> MessageResult<ReportAccountsPayable> {
        let result = match self.consuming_wallet_opt.as_ref() {
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
        };
        MessageResult(result)
    }

    //TODO delete this
    // fn collect_hashes_and_payments_from_sent_payments(
    //     result: &Result<Vec<BlockchainResult<Payment>>, String>,
    // ) -> (Vec<H256>, Vec<Payment>) {
    //     let mut hashes_of_pending_tx = vec![];
    //     let mut payments = vec![];
    //     let _ = result.as_ref().map(|collection| {
    //         collection.iter().for_each(|result| {
    //             let _ = result.as_ref().map(|payment| {
    //                 hashes_of_pending_tx.push(payment.transaction);
    //                 payments.push(payment.clone())
    //             });
    //         })
    //     });
    //     (hashes_of_pending_tx, payments)
    // }

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
                            unimplemented!() //   panic!("Lost payable amount precision: {}", payable.balance)
                        });
                        //TODO this needs to go inside send_transaction()
                        // Ok(()) => match self.pending_payments_dao.as_mut().insert_record(PendingPaymentRecord::new(&payment,rowid)){
                        //     Ok(_) => Ok((payment.transaction,rowid)),
                        //     Err(e) => Err(PaymentError::PostTransaction(PaymentErrorKind::RusqliteError(format!("Failed to finish a record insertion of pending transaction: {}; rowid: {}",payment.transaction,rowid)),payment.transaction))
                        // },
                        match self.blockchain_interface.send_transaction(
                            consuming_wallet,
                            &payable.wallet,
                            amount,
                            nonce,
                            gas_price,
                            payable.rowid,
                            self.blockchain_interface
                                .send_transaction_tools(&PaymentBackupRecipientWrapperReal::new(
                                    self.payment_confirmation
                                        .transaction_backup_tx_subs_opt
                                        .as_ref()
                                        .expect("Accountant is unbound"),
                                ))
                                .as_ref(),
                        ) {
                            Ok((hash, timestamp)) => Ok(Payment::new(
                                payable.wallet.clone(),
                                amount,
                                hash,
                                timestamp,
                                payable.last_paid_timestamp,
                                payable.rowid,
                            )),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            })
            .collect::<Vec<BlockchainResult<Payment>>>()
    }
}

#[derive(Debug, PartialEq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::test_utils::{earlier_in_seconds, BlockchainInterfaceMock};
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::blockchain_bridge::Payment;
    use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
    use crate::blockchain::tool_wrappers::SendTransactionToolWrapperNull;
    use crate::database::dao_utils::{from_time_t, to_time_t};
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
    use ethsign_crypto::Keccak256;
    use futures::future::Future;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use rustc_hex::FromHex;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
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
        let consuming_wallet = Wallet::from(Bip32ECKeyPair::from_raw_secret(&secret).unwrap());
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
        let retrieve_transactions_parameters_arc = Arc::new(Mutex::new(vec![]));
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
            .retrieve_transactions_params(&retrieve_transactions_parameters_arc)
            .retrieve_transactions_result(result)
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
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

        let retrieve_transactions_parameters = retrieve_transactions_parameters_arc.lock().unwrap();
        assert_eq!((block_no, wallet), retrieve_transactions_parameters[0]);

        let result = request.wait().unwrap().unwrap();
        assert_eq!(expected_results, result);
    }

    #[test]
    fn report_accounts_payable_sends_transactions_to_blockchain_interface() {
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let send_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let payment_timestamp_0 = from_time_t(to_time_t(SystemTime::now()) - 2);
        let payment_timestamp_1 = SystemTime::now();
        let system =
            System::new("report_accounts_payable_sends_transactions_to_blockchain_interface");
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(U256::from(1)))
            .get_transaction_count_result(Ok(U256::from(2)))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_params(&send_transaction_params_arc)
            .send_transaction_result(Ok((
                H256::from("sometransactionhash".keccak256()),
                payment_timestamp_0,
            )))
            .send_transaction_result(Ok((
                H256::from("someothertransactionhash".keccak256()),
                payment_timestamp_1,
            )))
            .contract_address_result(TEST_DEFAULT_CHAIN.rec().contract);
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
        let now = SystemTime::now();

        let request = addr.send(ReportAccountsPayable {
            accounts: vec![
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance: 42,
                    last_paid_timestamp: now,
                    pending_payment_transaction: None,
                    rowid: 1,
                },
                PayableAccount {
                    wallet: make_wallet("foo"),
                    balance: 21,
                    last_paid_timestamp: now,
                    pending_payment_transaction: None,
                    rowid: 2,
                },
            ],
        });
        System::current().stop();
        system.run();

        let result = request.wait().unwrap().unwrap();

        let send_transaction_params = send_transaction_params_arc.lock().unwrap();
        assert_eq!(
            send_transaction_params[0],
            (
                consuming_wallet.clone(),
                make_wallet("blah"),
                42,
                U256::from(1),
                expected_gas_price
            )
        );
        assert_eq!(
            send_transaction_params[1],
            (
                consuming_wallet.clone(),
                make_wallet("foo"),
                21,
                U256::from(2),
                expected_gas_price
            )
        );
        assert_eq!(send_transaction_params.len(), 2);
        let mut expected_payment_0 = Payment::new(
            make_wallet("blah"),
            42,
            H256::from("sometransactionhash".keccak256()),
            payment_timestamp_0,
            earlier_in_seconds(1000),
            1,
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
            payment_timestamp_1,
            earlier_in_seconds(1000),
            2,
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
        let get_transaction_count_params = get_transaction_count_params_arc.lock().unwrap();
        assert_eq!(get_transaction_count_params[0], consuming_wallet.clone(),);
        assert_eq!(get_transaction_count_params[1], consuming_wallet.clone(),);
        assert_eq!(get_transaction_count_params.len(), 2)
    }

    #[test]
    fn report_accounts_payable_returns_error_for_blockchain_error() {
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
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
                rowid: 1,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        assert_eq!(
            result.0,
            Ok(vec![Err(BlockchainError::TransactionFailed(String::from(
                "mock payment failure"
            )))])
        );
        let get_transaction_count_params = get_transaction_count_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_count_params, vec![consuming_wallet]);
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
                rowid: 1,
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
                rowid: 1,
            }],
        };

        let result = subject.handle_report_accounts_payable(request);

        assert_eq!(
            result.0,
            Err(String::from(
                "ReportAccountPayable: gas-price: TransactionError"
            ))
        );
    }

    //TODO remove this
    // #[test]
    // fn blockchain_bridge_lists_hashes_of_active_pending_txs() {
    //     let tx_hash1 = H256::from_uint(&U256::from(456));
    //     let tx_hash2 = H256::from_uint(&U256::from(123));
    //     let blockchain_interface_mock = BlockchainInterfaceMock::default()
    //         .get_transaction_count_result(Ok(web3::types::U256::from(1)))
    //         .get_transaction_count_result(Ok(web3::types::U256::from(2)))
    //         .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
    //         .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
    //         .send_transaction_result(Ok(tx_hash1))
    //         .send_transaction_result(Ok(tx_hash2));
    //     //injecting results is quite specific...they come in with "send_transaction_tool_wrapper_factory"
    //     let persistent_configuration_mock =
    //         PersistentConfigurationMock::new().gas_price_result(Ok(150));
    //     let subject = BlockchainBridge::new(
    //         Box::new(blockchain_interface_mock),
    //         Box::new(persistent_configuration_mock),
    //         false,
    //         Some(make_wallet("ourWallet"))
    //     );
    //     let wallet1 = make_wallet("blah");
    //     let timestamp1 = from_time_t(456000);
    //     let balance1 = 45_000;
    //     let wallet2 = make_wallet("hurrah");
    //     let timestamp2 = from_time_t(300000);
    //     let balance2 = 111;
    //     let account1 = PayableAccount {
    //         wallet: wallet1.clone(),
    //         balance: balance1,
    //         last_paid_timestamp: timestamp1,
    //         pending_payment_transaction: None,
    //     };
    //     let account2 = PayableAccount {
    //         wallet: wallet2.clone(),
    //         balance: balance2,
    //         last_paid_timestamp: timestamp2,
    //         pending_payment_transaction: None,
    //     };
    //     let request = ReportAccountsPayable {
    //         accounts: vec![account1, account2],
    //     };
    //
    //     let result = subject.handle_report_accounts_payable(request);
    //
    //     let (result, hashes) = result;
    //     let mut vec_of_payments = result.0.unwrap();
    //     let processed_payment_1 = vec_of_payments.remove(0).unwrap();
    //     assert_eq!(processed_payment_1.amount, balance1 as u64);
    //     assert_eq!(processed_payment_1.to, wallet1);
    //     assert_eq!(processed_payment_1.transaction, tx_hash1);
    //     assert!(to_time_t(processed_payment_1.timestamp) > (to_time_t(SystemTime::now()) - 10));
    //     let processed_payment_2 = vec_of_payments.remove(0).unwrap();
    //     assert_eq!(processed_payment_2.amount, balance2 as u64);
    //     assert_eq!(processed_payment_2.to, wallet2);
    //     assert_eq!(processed_payment_2.transaction, tx_hash2);
    //     assert!(to_time_t(processed_payment_2.timestamp) > (to_time_t(SystemTime::now()) - 10));
    //     assert_eq!(hashes.len(), 2);
    //     assert!(vec_of_payments.is_empty());
    //     assert_eq!(
    //         subject.payment_confirmation.list_of_pending_txs.borrow().len(),
    //         2
    //     );
    //     assert!(subject
    //         .payment_confirmation
    //         .list_of_pending_txs
    //         .borrow()
    //         .contains_key(&tx_hash1));
    //     assert!(subject
    //         .payment_confirmation
    //         .list_of_pending_txs
    //         .borrow()
    //         .contains_key(&tx_hash2));
    // }

    // #[test]
    // fn add_new_pending_transaction_on_list_returns_error_on_double_insertion() {
    //     let pending_tx_hash = H256::from_uint(&U256::from(123));
    //     let blockchain_interface_mock = BlockchainInterfaceMock::default()
    //         .get_transaction_count_result(Ok(web3::types::U256::from(1)))
    //         .send_transaction_result(Ok(pending_tx_hash))
    //         .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull));
    //     let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(150));
    //     let subject = BlockchainBridge::new(
    //         Box::new(blockchain_interface_mock),
    //         Box::new(persistent_config),
    //         false,
    //         Some(make_wallet("blahBlah"))
    //     );
    //     let wallet = make_wallet("blah");
    //     let timestamp = from_time_t(456000);
    //     let balance = 45_000;
    //     let account = PayableAccount {
    //         wallet: wallet.clone(),
    //         balance,
    //         last_paid_timestamp: timestamp,
    //         pending_payment_transaction: None,
    //     };
    //     let request = ReportAccountsPayable {
    //         accounts: vec![account],
    //     };
    //     let payment = Payment {
    //         to: wallet,
    //         amount: balance as u64,
    //         timestamp,
    //         previous_timestamp: earlier_in_seconds(5000),
    //         transaction: pending_tx_hash,
    //     };
    //     assert!(subject
    //         .payment_confirmation
    //         .list_of_pending_txs
    //         .borrow_mut()
    //         .insert(pending_tx_hash, payment)
    //         .is_none());
    //
    //     let result = subject.handle_report_accounts_payable(request);
    //
    //     let (result, hashes) = result;
    //     assert!(hashes.is_empty());
    //     assert_eq!(result.0,Err("ReportAccountPayable: Repeated attempt for an insertion of the same hash of a pending transaction: 0x0000…007b".to_string()))
    // }

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
