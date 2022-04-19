// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{Payable, PayableAccount};
use crate::accountant::{ReceivedPayments, SentPayable};
use crate::accountant::{ReportTransactionReceipts, RequestTransactionReceipts};
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainResult, SendTransactionInputs,
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
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::plus;
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
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    sent_payable_subs_opt: Option<Recipient<SentPayable>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
    crashable: bool,
    payment_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    transaction_backup_subs_opt: Option<Recipient<PendingPayableFingerprint>>,
    report_transaction_receipts_sub_opt: Option<Recipient<ReportTransactionReceipts>>,
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.set_consuming_wallet_subs_opt = Some(vec![
            msg.peer_actors.neighborhood.set_consuming_wallet_sub,
            msg.peer_actors.proxy_server.set_consuming_wallet_sub,
        ]);
        self.payment_confirmation.transaction_backup_subs_opt =
            Some(msg.peer_actors.accountant.pending_payable_fingerprint);
        self.payment_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
        self.sent_payable_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
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

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_request_transaction_receipts(msg)
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct PendingPayableFingerprint {
    pub rowid_opt: Option<u64>, //None when initialized
    pub timestamp: SystemTime,
    pub hash: H256,
    pub attempt_opt: Option<u16>, //None when initialized
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
            sent_payable_subs_opt: None,
            received_payments_subs_opt: None,
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
                self.sent_payable_subs_opt
                    .as_ref()
                    .expect("Accountant is unbound")
                    .try_send(SentPayable { payable: payments })
                    .expect("Accountant is dead");
            }
            Err(e) => warning!(self.logger, "{}", e),
        }
    }

    fn handle_report_accounts_payable_inner(
        &self,
        creditors_msg: ReportAccountsPayable,
    ) -> Result<Vec<BlockchainResult<Payable>>, String> {
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

    fn handle_request_transaction_receipts(&self, msg: RequestTransactionReceipts) {
        let short_circuit_result: (
            Vec<Option<TransactionReceipt>>,
            Option<(BlockchainError, H256)>,
        ) = msg
            .pending_payable
            .iter()
            .fold((vec![], None), |so_far, current_fingerprint| match so_far {
                (_, None) => match self
                    .blockchain_interface
                    .get_transaction_receipt(current_fingerprint.hash)
                {
                    Ok(receipt_opt) => (plus(so_far.0, receipt_opt), None),
                    Err(e) => (so_far.0, Some((e, current_fingerprint.hash))),
                },
                _ => so_far,
            });
        let (vector_of_results, error_opt) = short_circuit_result;
        if !vector_of_results.is_empty() {
            let pairs = vector_of_results
                .into_iter()
                .zip(msg.pending_payable.into_iter())
                .collect_vec();
            self.payment_confirmation
                .report_transaction_receipts_sub_opt
                .as_ref()
                .expect("Accountant is unbound")
                .try_send(ReportTransactionReceipts {
                    fingerprints_with_receipts: pairs,
                })
                .expect("Accountant is dead");
        }
        if let Some((e, hash)) = error_opt {
            warning!(
                self.logger,
                "Aborting scanning; request of a transaction receipt for '{:?}' failed due to '{:?}'",
                hash,
                e
            )
        }
    }

    fn process_payments(
        &self,
        creditors_msg: ReportAccountsPayable,
        gas_price: u64,
        consuming_wallet: &Wallet,
    ) -> Vec<BlockchainResult<Payable>> {
        creditors_msg
            .accounts
            .iter()
            .map(|payable| self.process_payments_inner_body(payable, gas_price, consuming_wallet))
            .collect::<Vec<BlockchainResult<Payable>>>()
    }

    fn process_payments_inner_body(
        &self,
        payable: &PayableAccount,
        gas_price: u64,
        consuming_wallet: &Wallet,
    ) -> BlockchainResult<Payable> {
        let nonce = self
            .blockchain_interface
            .get_transaction_count(consuming_wallet)?;
        let unsigned_amount = u64::try_from(payable.balance)
            .expect("negative balance for qualified payable is nonsense");
        let send_tools = self.blockchain_interface.send_transaction_tools(
            self.payment_confirmation
                .transaction_backup_subs_opt
                .as_ref()
                .expect("Accountant is unbound"),
        );
        match self
            .blockchain_interface
            .send_transaction(SendTransactionInputs::new(
                payable,
                consuming_wallet,
                nonce,
                gas_price,
                send_tools.as_ref(),
            )?) {
            Ok((hash, timestamp)) => Ok(Payable::new(
                payable.wallet.clone(),
                unsigned_amount,
                hash,
                timestamp,
            )),
            Err(e) => Err(e.into()),
            //if you're adding more code here that can fail don't forget to provide
            //the transaction hash together with the error
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
    use crate::accountant::test_utils::make_pending_payable_fingerprint;
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_bridge::Payable;
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainTransactionError, Transaction,
    };
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolsWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::unshared_test_utils::{
        configure_default_persistent_config, prove_that_crash_request_handler_is_hooked_up, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use rustc_hex::FromHex;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use web3::types::{TransactionReceipt, H160, H256, U256};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "BLOCKCHAINBRIDGE");
    }

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
            Box::new(configure_default_persistent_config(ZERO)),
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
        let transaction_hash = H256::from_uint(&U256::from(789));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_transaction_tools_result(Box::new(SendTransactionToolsWrapperNull))
            .send_transaction_result(Err(BlockchainTransactionError::Sending(
                String::from("mock payment failure"),
                transaction_hash,
            )));
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
                pending_payable_opt: None,
            }],
        };
        let (accountant, _, _) = make_recorder();
        let backup_recipient = accountant.start().recipient();
        subject.payment_confirmation.transaction_backup_subs_opt = Some(backup_recipient);

        let result = subject.handle_report_accounts_payable_inner(request);

        assert_eq!(
            result,
            Ok(vec![Err(BlockchainError::TransactionFailed {
                msg: String::from("Sending: mock payment failure"),
                hash_opt: Some(transaction_hash)
            })])
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
                pending_payable_opt: None,
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
            .send_transaction_tools_result(Box::new(SendTransactionToolsWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolsWrapperNull))
            .send_transaction_params(&send_transaction_params_arc)
            .send_transaction_result(Ok((
                H256::from("sometransactionhash".keccak256()),
                from_time_t(150_000_000),
            )))
            .send_transaction_result(Ok((
                H256::from("someothertransactionhash".keccak256()),
                from_time_t(160_000_000),
            )));
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
                        pending_payable_opt: None,
                    },
                    PayableAccount {
                        wallet: make_wallet("foo"),
                        balance: 210,
                        last_paid_timestamp: from_time_t(160_000_000),
                        pending_payable_opt: None,
                    },
                ],
            })
            .unwrap();

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
        let sent_payments_msg = accountant_received_payment.get_record::<SentPayable>(0);
        assert_eq!(
            sent_payments_msg.payable,
            vec![
                Ok(Payable {
                    to: make_wallet("blah"),
                    amount: 420,
                    timestamp: from_time_t(150_000_000),
                    tx_hash: H256::from("sometransactionhash".keccak256())
                }),
                Ok(Payable {
                    to: make_wallet("foo"),
                    amount: 210,
                    timestamp: from_time_t(160_000_000),
                    tx_hash: H256::from("someothertransactionhash".keccak256())
                })
            ]
        );
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
                pending_payable_opt: None,
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
        let pending_payable_fingerprint_1 = make_pending_payable_fingerprint();
        let hash_1 = pending_payable_fingerprint_1.hash;
        let hash_2 = H256::from_uint(&U256::from(78989));
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(456),
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt_opt: Some(3),
            amount: 4565,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(Some(TransactionReceipt::default())))
            .get_transaction_receipt_result(Ok(None));
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
            pending_payable: vec![
                pending_payable_fingerprint_1.clone(),
                pending_payable_fingerprint_2.clone(),
            ],
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
                fingerprints_with_receipts: vec![
                    (
                        Some(TransactionReceipt::default()),
                        pending_payable_fingerprint_1
                    ),
                    (None, pending_payable_fingerprint_2),
                ]
            }
        );
        let get_transaction_receipt_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_receipt_params, vec![hash_1, hash_2])
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
    fn handle_request_transaction_receipts_short_circuits_on_failure_from_remote_process_sends_back_all_good_results_and_logs_abort(
    ) {
        init_test_logging();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant.start();
        let accountant_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.recipient();
        let hash_1 = H256::from_uint(&U256::from(111334));
        let hash_2 = H256::from_uint(&U256::from(100000));
        let hash_3 = H256::from_uint(&U256::from(78989));
        let hash_4 = H256::from_uint(&U256::from(11111));
        let mut fingerprint_1 = make_pending_payable_fingerprint();
        fingerprint_1.hash = hash_1;
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(454),
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt_opt: Some(3),
            amount: 3333,
            process_error: None,
        };
        let fingerprint_3 = PendingPayableFingerprint {
            rowid_opt: Some(456),
            timestamp: SystemTime::now(),
            hash: hash_3,
            attempt_opt: Some(3),
            amount: 4565,
            process_error: None,
        };
        let fingerprint_4 = PendingPayableFingerprint {
            rowid_opt: Some(450),
            timestamp: from_time_t(230_000_000),
            hash: hash_4,
            attempt_opt: Some(1),
            amount: 7879,
            process_error: None,
        };
        let mut transaction_receipt = TransactionReceipt::default();
        transaction_receipt.block_number = Some(U64::from(4545454));
        transaction_receipt.contract_address = Some(H160::from_low_u64_be(887766));
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(None))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt.clone())))
            .get_transaction_receipt_result(Err(BlockchainError::QueryFailed(
                "bad bad bad".to_string(),
            )));
        let system = System::new("test_transaction_receipts");
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
            pending_payable: vec![
                fingerprint_1.clone(),
                fingerprint_2.clone(),
                fingerprint_3,
                fingerprint_4,
            ],
        };

        let _ = subject.handle_request_transaction_receipts(msg);

        System::current().stop();
        assert_eq!(system.run(), 0);
        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_receipts_params,
            vec![hash_1, hash_2, hash_3]
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let report_receipts_msg = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            report_receipts_msg.fingerprints_with_receipts,
            vec![
                (None, fingerprint_1),
                (Some(transaction_receipt), fingerprint_2)
            ]
        );
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction receipt \
         for '0x000000000000000000000000000000000000000000000000000000000001348d' failed due to 'QueryFailed(\"bad bad bad\")'");
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_of_the_first_payment_and_it_does_not_send_any_message_just_aborts_and_logs(
    ) {
        init_test_logging();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = H256::from_uint(&U256::from(111334));
        let fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(454),
            timestamp: SystemTime::now(),
            hash: hash_1,
            attempt_opt: Some(3),
            amount: 3333,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(456),
            timestamp: SystemTime::now(),
            hash: H256::from_uint(&U256::from(222444)),
            attempt_opt: Some(3),
            amount: 4565,
            process_error: None,
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Err(BlockchainError::QueryFailed("booga".to_string())));
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(PersistentConfigurationMock::default()),
            false,
            None,
        );
        subject
            .payment_confirmation
            //due to this None we would've panicked if we tried to send a msg
            .report_transaction_receipts_sub_opt = None;
        let msg = RequestTransactionReceipts {
            pending_payable: vec![fingerprint_1, fingerprint_2],
        };

        let _ = subject.handle_request_transaction_receipts(msg);

        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_receipts_params, vec![hash_1]);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction \
         receipt for '0x000000000000000000000000000000000000000000000000000000000001b2e6' failed due to 'QueryFailed(\"booga\")'");
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
        let subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::default()),
            crashable,
            None,
        );

        prove_that_crash_request_handler_is_hooked_up(subject, CRASH_KEY);
    }
}
