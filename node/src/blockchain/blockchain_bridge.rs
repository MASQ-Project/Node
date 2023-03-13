// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::dao_utils::DaoFactoryReal;
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::{
    ReceivedPayments, ResponseSkeleton, ScanError, SentPayables, SkeletonOptHolder,
};
use crate::accountant::{ReportTransactionReceipts, RequestTransactionReceipts};
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainInterfaceClandestine,
    BlockchainInterfaceNonClandestine, BlockchainResult, ProcessedPayableFallible,
};
use crate::database::db_initializer::DbInitializationConfig;
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
use masq_lib::messages::ScanType;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::plus;
use std::path::PathBuf;
use std::time::SystemTime;
use web3::transports::Http;
use web3::types::{TransactionReceipt, H256};
use web3::Transport;

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";

pub struct BlockchainBridge<T: Transport = Http> {
    consuming_wallet_opt: Option<Wallet>,
    blockchain_interface: Box<dyn BlockchainInterface<T>>,
    logger: Logger,
    persistent_config: Box<dyn PersistentConfiguration>,
    set_consuming_wallet_subs_opt: Option<Vec<Recipient<SetConsumingWalletMessage>>>,
    sent_payable_subs_opt: Option<Recipient<SentPayables>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
    scan_error_subs_opt: Option<Recipient<ScanError>>,
    crashable: bool,
    paid_payable_confirmation: TransactionConfirmationTools,
}

struct TransactionConfirmationTools {
    new_pp_fingerprints_sub_opt: Option<Recipient<PendingPayableFingerprintSeeds>>,
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
        self.paid_payable_confirmation.new_pp_fingerprints_sub_opt =
            Some(msg.peer_actors.accountant.init_pending_payable_fingerprints);
        self.paid_payable_confirmation
            .report_transaction_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_receipts);
        self.sent_payable_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.received_payments_subs_opt = Some(msg.peer_actors.accountant.report_inbound_payments);
        self.scan_error_subs_opt = Some(msg.peer_actors.accountant.scan_errors);
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

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct RetrieveTransactions {
    pub recipient: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RetrieveTransactions {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

impl Handler<RetrieveTransactions> for BlockchainBridge {
    type Result = ();

    fn handle(
        &mut self,
        msg: RetrieveTransactions,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RetrieveTransactions>>::Result {
        self.handle_scan(
            Self::handle_retrieve_transactions,
            ScanType::Receivables,
            &msg,
        )
    }
}

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_scan(
            Self::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            &msg,
        )
    }
}

impl Handler<ReportAccountsPayable> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: ReportAccountsPayable, _ctx: &mut Self::Context) {
        self.handle_scan(
            Self::handle_report_accounts_payable,
            ScanType::Payables,
            &msg,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub struct PendingPayableFingerprintSeeds {
    pub batch_wide_timestamp: SystemTime,
    pub hashes_and_balances: Vec<(H256, u128)>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PendingPayableFingerprint {
    pub rowid: u64,
    pub timestamp: SystemTime,
    pub hash: H256,
    //TODO make sure this starts with 1 and is right at all places
    pub attempt: u16,
    pub amount: u128,
    pub process_error: Option<String>,
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
            scan_error_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
            paid_payable_confirmation: TransactionConfirmationTools {
                new_pp_fingerprints_sub_opt: None,
                report_transaction_receipts_sub_opt: None,
            },
        }
    }

    pub fn make_connections(
        blockchain_service_url: Option<String>,
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
            DaoFactoryReal::new(
                &data_directory,
                DbInitializationConfig::panic_on_migration(),
            )
            .make_connection(),
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
        &mut self,
        msg: &ReportAccountsPayable,
    ) -> Result<(), String> {
        let result = self.start_processing_payments(msg)?;

        let local_processing_result = match &result {
            Err(e) => Err(format!("ReportAccountsPayable: {}", e)),
            Ok(_) => Ok(()),
        };

        let skeleton = msg.response_skeleton_opt;
        self.sent_payable_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .try_send(SentPayables {
                payment_procedure_result: result,
                response_skeleton_opt: skeleton,
            })
            .expect("Accountant is dead");

        local_processing_result
    }

    fn start_processing_payments(
        &self,
        msg: &ReportAccountsPayable,
    ) -> Result<BlockchainResult<Vec<ProcessedPayableFallible>>, String> {
        match self.consuming_wallet_opt.as_ref() {
            Some(consuming_wallet) => match self.persistent_config.gas_price() {
                Ok(gas_price) => Ok(self.process_payments(msg, consuming_wallet, gas_price)),
                Err(e) => Err(format!("ReportAccountsPayable: gas-price: {:?}", e)),
            },
            None => Err(String::from("No consuming wallet specified")),
        }
    }

    fn handle_retrieve_transactions(&mut self, msg: &RetrieveTransactions) -> Result<(), String> {
        let start_block = match self.persistent_config.start_block() {
            Ok (sb) => sb,
            Err (e) => panic! ("Cannot retrieve start block from database; payments to you may not be processed: {:?}", e)
        };
        let retrieved_transactions = self
            .blockchain_interface
            .retrieve_transactions(start_block, &msg.recipient);

        match retrieved_transactions {
            Ok(transactions) => {
                if let Err(e) = self
                    .persistent_config
                    .set_start_block(transactions.new_start_block)
                {
                    panic! ("Cannot set start block in database; payments to you may not be processed: {:?}", e)
                };
                if transactions.transactions.is_empty() {
                    debug!(self.logger, "No new receivable detected");
                }
                self.received_payments_subs_opt
                    .as_ref()
                    .expect("Accountant is unbound")
                    .try_send(ReceivedPayments {
                        timestamp: SystemTime::now(),
                        payments: transactions.transactions,
                        response_skeleton_opt: msg.response_skeleton_opt,
                    })
                    .expect("Accountant is dead.");
                Ok(())
            }
            Err(e) => Err(format!(
                "Tried to retrieve received payments but failed: {:?}",
                e
            )),
        }
    }

    fn handle_request_transaction_receipts(
        &mut self,
        msg: &RequestTransactionReceipts,
    ) -> Result<(), String> {
        let init: (
            Vec<Option<TransactionReceipt>>,
            Option<(BlockchainError, H256)>,
        ) = (vec![], None);
        let short_circuit_result =
            msg.pending_payable
                .iter()
                .fold(init, |so_far, current_fingerprint| match so_far {
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
        let pairs = vector_of_results
            .into_iter()
            .zip(msg.pending_payable.iter().cloned())
            .collect_vec();
        self.paid_payable_confirmation
            .report_transaction_receipts_sub_opt
            .as_ref()
            .expect("Accountant is unbound")
            .try_send(ReportTransactionReceipts {
                fingerprints_with_receipts: pairs,
                response_skeleton_opt: msg.response_skeleton_opt,
            })
            .expect("Accountant is dead");
        if let Some((e, hash)) = error_opt {
            return Err (format! (
                "Aborting scanning; request of a transaction receipt for '{:?}' failed due to '{:?}'",
                hash,
                e
            ));
        }
        Ok(())
    }

    fn handle_scan<M, F>(&mut self, handler: F, scan_type: ScanType, msg: &M)
    where
        F: FnOnce(&mut BlockchainBridge, &M) -> Result<(), String>,
        M: SkeletonOptHolder,
    {
        let skeleton_opt = msg.skeleton_opt();
        match handler(self, msg) {
            Ok(_r) => (),
            Err(e) => {
                warning!(self.logger, "{}", e);
                self.scan_error_subs_opt
                    .as_ref()
                    .expect("Accountant not bound")
                    .try_send(ScanError {
                        scan_type,
                        response_skeleton_opt: skeleton_opt,
                        msg: e,
                    })
                    .expect("Accountant is dead");
            }
        }
    }

    fn process_payments(
        &self,
        msg: &ReportAccountsPayable,
        consuming_wallet: &Wallet,
        gas_price: u64,
    ) -> BlockchainResult<Vec<ProcessedPayableFallible>> {
        let executable_payments = match self.check_our_capability_to_pay(&msg.accounts)
        {
            Ok(accounts) => accounts,
            Err(_e) => todo!("Will be completed by driving in either GH-554 or GH-555, then transform this match into a simple question mark"),
        };

        let pending_nonce = self
            .blockchain_interface
            .get_transaction_count(consuming_wallet)?;

        let new_fingerprints_recipient = self
            .paid_payable_confirmation
            .new_pp_fingerprints_sub_opt
            .as_ref()
            .expect("Accountant unbound");

        self.blockchain_interface.send_payables_within_batch(
            consuming_wallet,
            gas_price,
            pending_nonce,
            new_fingerprints_recipient,
            executable_payments,
        )
    }

    fn check_our_capability_to_pay<'a>(
        &self,
        payable_accounts: &'a [PayableAccount],
    ) -> Result<&'a [PayableAccount], BlockchainError> {
        //TODO: implement GH-554 and GH-555 at this place
        // also check if the resulting amount of filtered-out accounts is the same as the original...
        // if not, log the inability to pay it all at the moment
        Ok(payable_accounts)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::dao_utils::from_time_t;
    use crate::accountant::payable_dao::{PayableAccount, PendingPayable};
    use crate::accountant::test_utils::make_pending_payable_fingerprint;
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::Correct;
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainTransaction, RetrievedBlockchainTransactions,
    };
    use crate::blockchain::test_utils::{make_tx_hash, BlockchainInterfaceMock};
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::match_every_type_id;
    use crate::node_test_utils::check_timestamp;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::recorder_stop_conditions::StopCondition;
    use crate::test_utils::recorder_stop_conditions::StopConditions;
    use crate::test_utils::unshared_test_utils::{
        configure_default_persistent_config, prove_that_crash_request_handler_is_hooked_up, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use rustc_hex::FromHex;
    use std::any::TypeId;
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
            data_directory,
            DEFAULT_CHAIN,
        );
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
                balance_wei: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }],
            response_skeleton_opt: None,
        };

        let result = subject.start_processing_payments(&request);

        assert_eq!(result, Err("No consuming wallet specified".to_string()));
    }

    #[test]
    fn handle_report_accounts_payable_transacts_and_sends_finished_payments_back_to_accountant() {
        let system =
            System::new("handle_report_accounts_payable_transacts_and_sends_finished_payments_back_to_accountant");
        let get_transaction_count_params_arc = Arc::new(Mutex::new(vec![]));
        let send_payables_within_batch_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant =
            accountant.system_stop_conditions(match_every_type_id!(PendingPayableFingerprintSeeds));
        let wallet_account_1 = make_wallet("blah");
        let wallet_account_2 = make_wallet("foo");
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_params(&get_transaction_count_params_arc)
            .get_transaction_count_result(Ok(U256::from(1u64)))
            .send_payables_within_batch_params(&send_payables_within_batch_params_arc)
            .send_payables_within_batch_result(Ok(vec![
                Correct(PendingPayable {
                    recipient_wallet: wallet_account_1.clone(),
                    hash: H256::from("sometransactionhash".keccak256()),
                }),
                Correct(PendingPayable {
                    recipient_wallet: wallet_account_2.clone(),
                    hash: H256::from("someothertransactionhash".keccak256()),
                }),
            ]));
        let expected_gas_price = 145u64;
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
        let accounts = vec![
            PayableAccount {
                wallet: wallet_account_1.clone(),
                balance_wei: 420,
                last_paid_timestamp: from_time_t(150_000_000),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: wallet_account_2.clone(),
                balance_wei: 210,
                last_paid_timestamp: from_time_t(160_000_000),
                pending_payable_opt: None,
            },
        ];
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(ReportAccountsPayable {
                accounts: accounts.clone(),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let mut send_payables_within_batch_params =
            send_payables_within_batch_params_arc.lock().unwrap();
        //cannot assert on the captured recipient as it its actor is gone after the System stops spinning
        let (
            consuming_wallet_actual,
            gas_price_actual,
            nonce_actual,
            _recipient_actual,
            accounts_actual,
        ) = send_payables_within_batch_params.remove(0);
        assert!(send_payables_within_batch_params.is_empty());
        assert_eq!(consuming_wallet_actual, consuming_wallet.clone());
        assert_eq!(gas_price_actual, expected_gas_price);
        assert_eq!(nonce_actual, U256::from(1u64));
        assert_eq!(accounts_actual, accounts);
        let get_transaction_count_params = get_transaction_count_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_count_params, vec![consuming_wallet]);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let sent_payments_msg = accountant_recording.get_record::<SentPayables>(0);
        assert_eq!(
            *sent_payments_msg,
            SentPayables {
                payment_procedure_result: Ok(vec![
                    Correct(PendingPayable {
                        recipient_wallet: wallet_account_1,
                        hash: H256::from("sometransactionhash".keccak256())
                    }),
                    Correct(PendingPayable {
                        recipient_wallet: wallet_account_2,
                        hash: H256::from("someothertransactionhash".keccak256())
                    })
                ]),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                })
            }
        );
    }

    #[test]
    fn handle_report_accounts_payable_transacts_eleventh_hour_error_back_to_accountant() {
        let system = System::new(
            "handle_report_accounts_payable_transacts_eleventh_hour_error_back_to_accountant",
        );
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let hash = make_tx_hash(222);
        let wallet_account = make_wallet("blah");
        let expected_error_msg = "We were so close but we stumbled and smashed our face against \
         the ground just a moment after the signing";
        let expected_error = Err(BlockchainError::PayableTransactionFailed {
            msg: expected_error_msg.to_string(),
            signed_and_hashed_txs_opt: Some(vec![hash]),
        });
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(U256::from(1u64)))
            .send_payables_within_batch_result(expected_error.clone());
        let persistent_configuration_mock =
            PersistentConfigurationMock::default().gas_price_result(Ok(123));
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        let accounts = vec![PayableAccount {
            wallet: wallet_account,
            balance_wei: 111_420_204,
            last_paid_timestamp: from_time_t(150_000_000),
            pending_payable_opt: None,
        }];
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(ReportAccountsPayable {
                accounts,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 2);
        let sent_payments_msg = accountant_recording.get_record::<SentPayables>(0);
        assert_eq!(
            *sent_payments_msg,
            SentPayables {
                payment_procedure_result: expected_error,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                })
            }
        );
        let scan_error_msg = accountant_recording.get_record::<ScanError>(1);
        assert_eq!(
            *scan_error_msg,
            ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: format!(
                    "ReportAccountsPayable: Blockchain error: Occurred at the final batch \
            processing: \"{}\". Successfully signed and hashed these transactions: \
            0x00000000000000000000000000000000000000000000000000000000000000de.",
                    expected_error_msg
                )
            }
        )
    }

    #[test]
    fn report_accounts_payable_returns_error_fetching_pending_nonce() {
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Err(BlockchainError::QueryFailed(
                "What the hack...??".to_string(),
            )));
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
                balance_wei: 123_456,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }],
            response_skeleton_opt: None,
        };

        let result = subject.process_payments(&request, &consuming_wallet, 123);

        assert_eq!(
            result,
            Err(BlockchainError::QueryFailed(
                "What the hack...??".to_string()
            ))
        );
    }

    #[test]
    fn report_accounts_payable_returns_error_from_sending_batch() {
        let transaction_hash = make_tx_hash(789);
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .send_payables_within_batch_result(Err(BlockchainError::PayableTransactionFailed {
                msg: "failure from exhaustion".to_string(),
                signed_and_hashed_txs_opt: Some(vec![transaction_hash]),
            }));
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
                balance_wei: 424_454,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }],
            response_skeleton_opt: None,
        };
        let (accountant, _, _) = make_recorder();
        let fingerprint_recipient = accountant.start().recipient();
        subject
            .paid_payable_confirmation
            .new_pp_fingerprints_sub_opt = Some(fingerprint_recipient);

        let result = subject.start_processing_payments(&request);

        assert_eq!(
            result,
            Ok(Err(BlockchainError::PayableTransactionFailed {
                msg: "failure from exhaustion".to_string(),
                signed_and_hashed_txs_opt: Some(vec![transaction_hash])
            }))
        );
    }

    #[test]
    fn handle_report_accounts_payable_manages_gas_price_error() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let scan_error_recipient: Recipient<ScanError> = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start()
            .recipient();
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)));
        let persistent_configuration_mock = PersistentConfigurationMock::new()
            .gas_price_result(Err(PersistentConfigError::TransactionError));
        let consuming_wallet = make_wallet("somewallet");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_configuration_mock),
            false,
            Some(consuming_wallet),
        );
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let request = ReportAccountsPayable {
            accounts: vec![PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: 42,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }],
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(request).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let message = recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: None,
                msg: "ReportAccountsPayable: gas-price: TransactionError".to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: ReportAccountsPayable: gas-price: TransactionError",
        );
    }

    #[test]
    fn blockchain_bridge_processes_requests_for_transaction_receipts_when_all_were_ok() {
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let pending_payable_fingerprint_1 = make_pending_payable_fingerprint();
        let hash_1 = pending_payable_fingerprint_1.hash;
        let hash_2 = make_tx_hash(78989);
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
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
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
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
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        let get_transaction_receipt_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_receipt_params, vec![hash_1, hash_2])
    }

    #[test]
    fn blockchain_bridge_logs_error_from_retrieving_received_payments() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let scan_error_recipient: Recipient<ScanError> = accountant
            .system_stop_conditions(match_every_type_id!(ScanError))
            .start()
            .recipient();
        let blockchain_interface = BlockchainInterfaceMock::default().retrieve_transactions_result(
            Err(BlockchainError::QueryFailed("we have no luck".to_string())),
        );
        let persistent_config = PersistentConfigurationMock::new().start_block_result(Ok(5)); // no set_start_block_result: set_start_block() must not be called
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            None,
        );
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RetrieveTransactions {
            recipient: make_wallet("blah"),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(msg).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let message = recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: None,
                msg: "Tried to retrieve received payments but failed: QueryFailed(\"we have no luck\")".to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: Tried to retrieve \
         received payments but failed: QueryFailed(\"we have no luck\")",
        );
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_from_remote_process_sends_back_all_good_results_and_logs_abort(
    ) {
        init_test_logging();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_every_type_id!(ReportTransactionReceipts, ScanError))
            .start();
        let report_transaction_receipt_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.clone().recipient();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.recipient();
        let hash_1 = make_tx_hash(111334);
        let hash_2 = make_tx_hash(100000);
        let hash_3 = make_tx_hash(78989);
        let hash_4 = make_tx_hash(11111);
        let mut fingerprint_1 = make_pending_payable_fingerprint();
        fingerprint_1.hash = hash_1;
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_2,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_3 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: hash_3,
            attempt: 3,
            amount: 4565,
            process_error: None,
        };
        let fingerprint_4 = PendingPayableFingerprint {
            rowid: 450,
            timestamp: from_time_t(230_000_000),
            hash: hash_4,
            attempt: 1,
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
            .paid_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(report_transaction_receipt_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![
                fingerprint_1.clone(),
                fingerprint_2.clone(),
                fingerprint_3,
                fingerprint_4,
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg).unwrap();

        assert_eq!(system.run(), 0);
        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_receipts_params,
            vec![hash_1, hash_2, hash_3]
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 2);
        let report_receipts_msg = accountant_recording.get_record::<ReportTransactionReceipts>(0);
        assert_eq!(
            *report_receipts_msg,
            ReportTransactionReceipts {
                fingerprints_with_receipts: vec![
                    (None, fingerprint_1),
                    (Some(transaction_receipt), fingerprint_2)
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        let scan_error_msg = accountant_recording.get_record::<ScanError>(1);
        assert_eq!(*scan_error_msg, ScanError {
            scan_type: ScanType::PendingPayables,
            response_skeleton_opt: Some(ResponseSkeleton { client_id: 1234, context_id: 4321 }),
            msg: "Aborting scanning; request of a transaction receipt \
         for '0x000000000000000000000000000000000000000000000000000000000001348d' failed due to 'QueryFailed(\"bad bad bad\")'".to_string()
        });
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Aborting scanning; request of a transaction receipt \
         for '0x000000000000000000000000000000000000000000000000000000000001348d' failed due to 'QueryFailed(\"bad bad bad\")'");
    }

    #[test]
    fn blockchain_bridge_can_return_report_transaction_receipts_with_an_empty_vector() {
        let (accountant, _, accountant_recording) = make_recorder();
        let recipient = accountant.start().recipient();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceClandestine::new(Chain::Dev)),
            Box::new(PersistentConfigurationMock::default()),
            false,
            Some(Wallet::new("mine")),
        );
        subject
            .paid_payable_confirmation
            .report_transaction_receipts_sub_opt = Some(recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![],
            response_skeleton_opt: None,
        };
        let system = System::new(
            "blockchain_bridge_can_return_report_transaction_receipts_with_an_empty_vector",
        );

        let _ = subject.handle_request_transaction_receipts(&msg);

        System::current().stop();
        system.run();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(
            recording.get_record::<ReportTransactionReceipts>(0),
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![],
                response_skeleton_opt: None
            }
        )
    }

    #[test]
    fn handle_request_transaction_receipts_short_circuits_on_failure_of_the_first_payment_and_it_sends_a_message_with_empty_vector_and_logs(
    ) {
        init_test_logging();
        let (accountant, _, accountant_recording) = make_recorder();
        let accountant_addr = accountant.start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let report_transaction_recipient: Recipient<ReportTransactionReceipts> =
            accountant_addr.recipient();
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(111334);
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 454,
            timestamp: SystemTime::now(),
            hash: hash_1,
            attempt: 3,
            amount: 3333,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 456,
            timestamp: SystemTime::now(),
            hash: make_tx_hash(222444),
            attempt: 3,
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
            .paid_payable_confirmation
            //due to this None we would've panicked if we tried to send a msg
            .report_transaction_receipts_sub_opt = Some(report_transaction_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            pending_payable: vec![fingerprint_1, fingerprint_2],
            response_skeleton_opt: None,
        };
        let system = System::new("test");

        let _ = subject.handle_scan(
            BlockchainBridge::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            &msg,
        );

        System::current().stop();
        system.run();
        let get_transaction_receipts_params = get_transaction_receipt_params_arc.lock().unwrap();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(*get_transaction_receipts_params, vec![hash_1]);
        assert_eq!(
            recording.get_record::<ReportTransactionReceipts>(0),
            &ReportTransactionReceipts {
                fingerprints_with_receipts: vec![],
                response_skeleton_opt: None
            }
        );
        assert_eq!(
            recording.get_record::<ScanError>(1),
            &ScanError {
                scan_type: ScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: "Aborting scanning; request of a transaction receipt for '0x000000000000000000000000000000000000000000000000000000000001b2e6' failed due to 'QueryFailed(\"booga\")'".to_string()
            }
        );
        assert_eq!(recording.len(), 2);
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
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: 1234,
            transactions: vec![
                BlockchainTransaction {
                    block_number: 7,
                    from: earning_wallet.clone(),
                    wei_amount: amount,
                },
                BlockchainTransaction {
                    block_number: 9,
                    from: earning_wallet.clone(),
                    wei_amount: amount2,
                },
            ],
        };
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_params(&retrieve_transactions_params_arc)
            .retrieve_transactions_result(Ok(expected_transactions.clone()));
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_config),
            false,
            Some(make_wallet("consuming")),
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        let _ = addr.try_send(retrieve_transactions).unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let set_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*set_start_block_params, vec![1234]);
        let retrieve_transactions_params = retrieve_transactions_params_arc.lock().unwrap();
        assert_eq!(*retrieve_transactions_params, vec![(6, earning_wallet)]);
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                payments: expected_transactions.transactions,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn processing_of_received_payments_continues_even_if_no_payments_are_detected() {
        init_test_logging();
        let blockchain_interface_mock = BlockchainInterfaceMock::default()
            .retrieve_transactions_result(Ok(RetrievedBlockchainTransactions {
                new_start_block: 7,
                transactions: vec![],
            }));
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(6))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new(
            "processing_of_received_payments_continues_even_if_no_payments_are_detected",
        );
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface_mock),
            Box::new(persistent_config),
            false,
            None, //not needed in this test
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        let _ = addr.try_send(retrieve_transactions).unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let set_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*set_start_block_params, vec![7]);
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                payments: vec![],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        TestLogHandler::new()
            .exists_log_containing("DEBUG: BlockchainBridge: No new receivable detected");
    }

    #[test]
    #[should_panic(
        expected = "Cannot retrieve start block from database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_read() {
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::TransactionError));
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(persistent_config),
            false,
            None, //not needed in this test
        );
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        let _ = subject.handle_retrieve_transactions(&retrieve_transactions);
    }

    #[test]
    #[should_panic(
        expected = "Cannot set start block in database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_written() {
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(1234))
            .set_start_block_result(Err(PersistentConfigError::TransactionError));
        let blockchain_interface = BlockchainInterfaceMock::default().retrieve_transactions_result(
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 1234,
                transactions: vec![BlockchainTransaction {
                    block_number: 1000,
                    from: make_wallet("somewallet"),
                    wei_amount: 2345,
                }],
            }),
        );
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            None, //not needed in this test
        );
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        let _ = subject.handle_retrieve_transactions(&retrieve_transactions);
    }

    fn success_handler(
        _bcb: &mut BlockchainBridge,
        _msg: &RetrieveTransactions,
    ) -> Result<(), String> {
        Ok(())
    }

    fn failure_handler(
        _bcb: &mut BlockchainBridge,
        _msg: &RetrieveTransactions,
    ) -> Result<(), String> {
        Err("My tummy hurts".to_string())
    }

    #[test]
    fn handle_scan_handles_success() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject.handle_scan(
            success_handler,
            ScanType::Receivables,
            &retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
    }

    #[test]
    fn handle_scan_handles_failure_without_skeleton() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        subject.handle_scan(
            failure_handler,
            ScanType::Receivables,
            &retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: None,
                msg: "My tummy hurts".to_string()
            }
        );
        assert_eq!(accountant_recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: My tummy hurts");
    }

    #[test]
    fn handle_scan_handles_failure_with_skeleton() {
        init_test_logging();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut subject = BlockchainBridge::new(
            Box::new(BlockchainInterfaceMock::default()),
            Box::new(PersistentConfigurationMock::new()),
            false,
            None, //not needed in this test
        );
        let system = System::new("test");
        subject.scan_error_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject.handle_scan(
            failure_handler,
            ScanType::Receivables,
            &retrieve_transactions,
        );

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(
            accountant_recording.get_record::<ScanError>(0),
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "My tummy hurts".to_string()
            }
        );
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: My tummy hurts");
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
