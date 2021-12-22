// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{PayableAccount, Payment};
use crate::accountant::SentPayments;
use crate::accountant::{PaymentError, RequestTransactionReceipts};
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainResult, SendTransactionInputs, Transaction
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
use std::path::PathBuf;
use std::time::SystemTime;
use web3::transports::Http;
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

pub struct BlockchainBridge {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    #[allow(dead_code)]
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    sent_payments_subs_opt: Option<Recipient<SentPayments>>,
    crashable: bool,
    payment_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    transaction_backup_subs_opt: Option<Recipient<PaymentBackupRecord>>,
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
        self.payment_confirmation.transaction_backup_subs_opt =
            Some(msg.peer_actors.accountant.payment_backup);
        self.payment_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
        self.sent_payments_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
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

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_request_transaction_receipts(msg)
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub payment_backups_with_receipts: Vec<(Option<TransactionReceipt>, PaymentBackupRecord)>,
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct PaymentBackupRecord {
    pub rowid: u64,
    pub timestamp: SystemTime,
    pub hash: H256,
    pub attempt: u16,
    pub amount: u64,
    pub process_error: Option<String>,
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
            crashable,
            logger: Logger::new("BlockchainBridge"),
            payment_confirmation: TransactionConfirmationTools {
                transaction_backup_subs_opt: None,
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

    fn handle_report_accounts_payable(&self, creditors_msg: ReportAccountsPayable) {
        let processed_payments = self.handle_report_accounts_payable_inner(creditors_msg);
        match processed_payments {
            Ok(payments) => {
                let payments_with_payment_errors = payments
                    .into_iter()
                    .map(|item| item.map_err(PaymentError::from))
                    .collect();
                //TODO test that this error transformation is test-followed
                self.sent_payments_subs_opt
                    .as_ref()
                    .expect("Accountant is unbound")
                    .try_send(SentPayments {
                        payments: payments_with_payment_errors,
                    })
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

    fn handle_request_transaction_receipts(&self, msg: RequestTransactionReceipts) {
        let short_circuit_result: Result<Vec<Option<TransactionReceipt>>, BlockchainError> = msg
            .pending_payments
            .iter()
            .map(|backup| {
                self.blockchain_interface
                    .get_transaction_receipt(backup.hash)
            })
            .collect();
        match short_circuit_result{
            Ok(vector_of_receipts) => {
                let pairs = vector_of_receipts.into_iter().zip(msg.pending_payments.into_iter())
                    .collect_vec();
                self.payment_confirmation
                    .report_transaction_receipts_sub_opt
                    .as_ref()
                    .expect("Accountant is unbound")
                    .try_send(ReportTransactionReceipts {
                        payment_backups_with_receipts: pairs,
                    })
                    .expect("Accountant is dead")
            },
            Err(e) => warning!(self.logger,"WARN: BlockchainBridge: Aborting scanning; request of a transaction receipt failed due to '{:?}'",e)
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
            .map(|payable| self.process_payments_inner_body(payable, gas_price, consuming_wallet))
            .collect::<Vec<BlockchainResult<Payment>>>()
    }

    fn process_payments_inner_body(
        &self,
        payable: &PayableAccount,
        gas_price: u64,
        consuming_wallet: &Wallet,
    ) -> BlockchainResult<Payment> {
        let nonce = self
            .blockchain_interface
            .get_transaction_count(consuming_wallet)?;
        let unsigned_amount = u64::try_from(payable.balance)
            .expect("negative balance accounts should never be seen here");
        let pending_payment_rowid = payable
            .pending_payment_rowid_opt
            .expect("accounts failing to fetch a relevant rowid should've been left out");
        match self.blockchain_interface.send_transaction(
            SendTransactionInputs::new(payable, consuming_wallet, nonce, gas_price)?,
            self.blockchain_interface
                .send_transaction_tools(&PaymentBackupRecipientWrapperReal::new(
                    self.payment_confirmation
                        .transaction_backup_subs_opt
                        .as_ref()
                        .expect("Accountant is unbound"),
                ))
                .as_ref(),
        ) {
            Ok((hash, timestamp)) => Ok(Payment::new(
                payable.wallet.clone(),
                unsigned_amount,
                hash,
                timestamp,
                pending_payment_rowid,
            )),
            Err(e) => Err(e),
        }
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
    use crate::accountant::test_utils::make_payment_backup;
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_bridge::Payment;
    use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        make_default_persistent_configuration, prove_that_crash_request_handler_is_hooked_up,
    };
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::Addr;
    use actix::System;
    use ethereum_types::BigEndianHash;
    use ethsign_crypto::Keccak256;
    use futures::future::Future;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use rustc_hex::FromHex;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use web3::types::{TransactionReceipt, H256, U256};

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
        let mut subject = BlockchainBridge::new(
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
                pending_payment_rowid_opt: Some(789),
            }],
        };
        let (accountat, _, _) = make_recorder();
        let backup_recipient = accountat.start().recipient();
        subject.payment_confirmation.transaction_backup_subs_opt = Some(backup_recipient);

        let result = subject.handle_report_accounts_payable_inner(request);

        assert_eq!(
            result,
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
                pending_payment_rowid_opt: Some(123),
            }],
        };

        let result = subject.handle_report_accounts_payable_inner(request);

        assert_eq!(result, Err("No consuming wallet specified".to_string()));
    }

    #[test]
    fn report_accounts_payable_sends_transactions_to_blockchain_interface() {
        let system =
            System::new("report_accounts_payable_sends_transactions_to_blockchain_interface");
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let send_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let timestamp_transaction_1 = from_time_t(200_000_000);
        let timestamp_transaction_2 = from_time_t(200_000_001);
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(U256::from(1)))
            .get_transaction_count_result(Ok(U256::from(2)))
            .send_transaction_params(&send_transaction_params_arc)
            .send_transaction_result(Ok((
                H256::from("sometransactionhash".keccak256()),
                timestamp_transaction_1,
            )))
            .send_transaction_result(Ok((
                H256::from("someothertransactionhash".keccak256()),
                timestamp_transaction_2,
            )))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull));
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
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr.try_send(ReportAccountsPayable {
            accounts: vec![
                PayableAccount {
                    wallet: make_wallet("blah"),
                    balance: 420,
                    last_paid_timestamp: from_time_t(150_000_000),
                    pending_payment_rowid_opt: Some(789),
                },
                PayableAccount {
                    wallet: make_wallet("foo"),
                    balance: 210,
                    last_paid_timestamp: from_time_t(120_000_000),
                    pending_payment_rowid_opt: Some(790),
                },
            ],
        });
        System::current().stop();
        system.run();

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
        sent_payments_cloned
            .iter_mut()
            .for_each(|payment_in_result| {
                if let Ok(payment) = payment_in_result {
                    payment.timestamp = from_time_t(0)
                }
            });
        assert_eq!(
            sent_payments_cloned,
            vec![
                Ok(Payment {
                    to: make_wallet("blah"),
                    amount: 420,
                    timestamp: from_time_t(0), //cannot be asserted directly, this field is just a sentinel
                    transaction: H256::from("sometransactionhash".keccak256()),
                    rowid: 789
                }),
                Ok(Payment {
                    to: make_wallet("foo"),
                    amount: 210,
                    timestamp: from_time_t(0), //cannot be asserted directly, this field is just a sentinel
                    transaction: H256::from("someothertransactionhash".keccak256()),
                    rowid: 790
                })
            ]
        )
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
                pending_payment_rowid_opt: None,
            }],
        };

        let _ = subject.handle_report_accounts_payable(request);

        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: ReportAccountPayable: gas-price: TransactionError",
        );
    }

    #[test]
    fn blockchain_bridge_processes_requests_for_transaction_receipts_when_all_were_ok() {
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let payment_backup_1 = make_payment_backup();
        let hash_1 = payment_backup_1.hash;
        let hash_2 = H256::from_uint(&U256::from(78989));
        let payment_backup_2 = PaymentBackupRecord {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(Some(TransactionReceipt::default())))
            .get_transaction_receipt_result(Ok(None));
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let msg = RequestTransactionReceipts {
            pending_payments: vec![payment_backup_1.clone(), payment_backup_2.clone()],
        };

        let _ = addr.try_send(msg).unwrap();

        let system = System::new("transaction receipts");
        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let received_message = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            received_message,
            &ReportTransactionReceipts {
                payment_backups_with_receipts: vec![
                    (Some(TransactionReceipt::default()), payment_backup_1),
                    (None, payment_backup_2),
                ]
            }
        );
        let get_transaction_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_params, vec![hash_1, hash_2])
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_for_a_failure_within_remote_process_and_logs_the_abort(
    ) {
        init_test_logging();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant.start();
        let accountant_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.recipient();
        let hash_1 = H256::from_uint(&U256::from(111334));
        let hash_2 = H256::from_uint(&U256::from(78989));
        let hash_3 = H256::from_uint(&U256::from(11111));
        let mut payment_backup_1 = make_payment_backup();
        payment_backup_1.hash = hash_1;
        let payment_backup_2 = PaymentBackupRecord {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let payment_backup_3 = PaymentBackupRecord {
            rowid: 450,
            timestamp: from_time_t(230_000_000),
            hash: hash_3,
            attempt: 1,
            amount: 7879,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(Some(TransactionReceipt::default())))
            .get_transaction_receipt_result(Err(BlockchainError::TransactionFailed(
                "bad bad bad".to_string(),
            )))
            .get_transaction_receipt_result(Ok(None));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        subject
            .payment_confirmation
            .report_transaction_receipts_sub_opt = Some(accountant_recipient);
        let msg = RequestTransactionReceipts {
            pending_payments: vec![
                payment_backup_1.clone(),
                payment_backup_2.clone(),
                payment_backup_3.clone(),
            ],
        };

        let _ = subject.handle_request_transaction_receipts(msg);

        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_receipts_params, vec![hash_1, hash_2]);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction receipt failed due to 'TransactionFailed(\"bad bad bad\")'");
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            crashable,
            None,
        );

        prove_that_crash_request_handler_is_hooked_up(subject, CRASH_KEY);
    }
}
