// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    BlockchainAgentWithContextMessage, PricedQualifiedPayables, QualifiedPayablesMessage,
};
use crate::accountant::{
    ReceivedPayments, ResponseSkeleton, ScanError, SentPayables, SkeletonOptHolder,
};
use crate::accountant::{RequestTransactionReceipts, TxReceiptsMessage};
use crate::actor_system_factory::SubsFactory;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
use crate::blockchain::blockchain_interface::data_structures::errors::{
    BlockchainInterfaceError, PayableTransactionError,
};
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, StatusReadFromReceiptCheck, TxReceiptResult,
};
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::blockchain::blockchain_interface_initializer::BlockchainInterfaceInitializer;
use crate::database::db_initializer::{DbInitializationConfig, DbInitializer, DbInitializerReal};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::blockchain_bridge::{BlockchainBridgeSubs, OutboundPaymentsInstructions};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::{db_connection_launch_panic, handle_ui_crash_request};
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::{Addr, Recipient};
use ethabi::Hash;
use futures::Future;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::DEFAULT_GAS_PRICE_MARGIN;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use masq_lib::ui_gateway::NodeFromUiMessage;
use regex::Regex;
use std::path::Path;
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use web3::types::H256;

pub const CRASH_KEY: &str = "BLOCKCHAINBRIDGE";
pub const DEFAULT_BLOCKCHAIN_SERVICE_URL: &str = "https://0.0.0.0";

pub struct BlockchainBridge {
    blockchain_interface: Box<dyn BlockchainInterface>,
    logger: Logger,
    persistent_config_arc: Arc<Mutex<dyn PersistentConfiguration>>,
    sent_payable_subs_opt: Option<Recipient<SentPayables>>,
    payable_payments_setup_subs_opt: Option<Recipient<BlockchainAgentWithContextMessage>>,
    received_payments_subs_opt: Option<Recipient<ReceivedPayments>>,
    scan_error_subs_opt: Option<Recipient<ScanError>>,
    crashable: bool,
    pending_payable_confirmation: TxConfirmationTools,
}

struct TxConfirmationTools {
    register_new_pending_payables_sub_opt: Option<Recipient<RegisterNewPendingPayables>>,
    report_tx_receipts_sub_opt: Option<Recipient<TxReceiptsMessage>>,
}

#[derive(PartialEq, Eq)]
pub enum BlockScanRange {
    NoLimit,
    Range(u64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BlockMarker {
    Uninitialized,
    Value(u64),
}

impl Actor for BlockchainBridge {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.pending_payable_confirmation
            .register_new_pending_payables_sub_opt =
            Some(msg.peer_actors.accountant.register_new_pending_payables);
        self.pending_payable_confirmation.report_tx_receipts_sub_opt =
            Some(msg.peer_actors.accountant.report_transaction_status);
        self.payable_payments_setup_subs_opt =
            Some(msg.peer_actors.accountant.report_payable_payments_setup);
        self.sent_payable_subs_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.received_payments_subs_opt = Some(msg.peer_actors.accountant.report_inbound_payments);
        self.scan_error_subs_opt = Some(msg.peer_actors.accountant.scan_errors);
        // There's a multinode integration test looking for this message
        debug!(self.logger, "Received BindMessage");
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
        self.handle_scan_future(
            Self::handle_retrieve_transactions,
            ScanType::Receivables,
            msg,
        )
    }
}

impl Handler<RequestTransactionReceipts> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: RequestTransactionReceipts, _ctx: &mut Self::Context) {
        self.handle_scan_future(
            Self::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        )
    }
}

impl Handler<QualifiedPayablesMessage> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: QualifiedPayablesMessage, _ctx: &mut Self::Context) {
        self.handle_scan_future(Self::handle_qualified_payable_msg, ScanType::Payables, msg);
    }
}

impl Handler<OutboundPaymentsInstructions> for BlockchainBridge {
    type Result = ();

    fn handle(&mut self, msg: OutboundPaymentsInstructions, _ctx: &mut Self::Context) {
        self.handle_scan_future(
            Self::handle_outbound_payments_instructions,
            ScanType::Payables,
            msg,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Message)]
pub struct RegisterNewPendingPayables {
    pub new_sent_txs: Vec<SentTx>,
}

impl RegisterNewPendingPayables {
    pub fn new(new_sent_txs: Vec<SentTx>) -> Self {
        Self { new_sent_txs }
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
        persistent_config: Arc<Mutex<dyn PersistentConfiguration>>,
        crashable: bool,
    ) -> BlockchainBridge {
        BlockchainBridge {
            blockchain_interface,
            persistent_config_arc: persistent_config,
            sent_payable_subs_opt: None,
            payable_payments_setup_subs_opt: None,
            received_payments_subs_opt: None,
            scan_error_subs_opt: None,
            crashable,
            logger: Logger::new("BlockchainBridge"),
            pending_payable_confirmation: TxConfirmationTools {
                register_new_pending_payables_sub_opt: None,
                report_tx_receipts_sub_opt: None,
            },
        }
    }

    pub fn initialize_persistent_configuration(
        data_directory: &Path,
    ) -> Arc<Mutex<dyn PersistentConfiguration>> {
        let config_dao = Box::new(ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(data_directory, DbInitializationConfig::panic_on_migration())
                .unwrap_or_else(|err| db_connection_launch_panic(err, data_directory)),
        ));
        Arc::new(Mutex::new(PersistentConfigurationReal::new(config_dao)))
    }

    pub fn initialize_blockchain_interface(
        blockchain_service_url_opt: Option<String>,
        chain: Chain,
        logger: Logger,
    ) -> Box<dyn BlockchainInterface> {
        match blockchain_service_url_opt {
            Some(url) => {
                // TODO if we decided to have interchangeably runtime switchable or simultaneously usable interfaces we will
                // probably want to make BlockchainInterfaceInitializer a collaborator that's a part of the actor
                info!(logger, "Blockchain service url has been set to {}", url);
                BlockchainInterfaceInitializer {}.initialize_interface(&url, chain)
            }
            None => {
                info!(logger, "The Blockchain service url is not set yet. its been defaulted to a wild card IP");
                BlockchainInterfaceInitializer {}
                    .initialize_interface(DEFAULT_BLOCKCHAIN_SERVICE_URL, chain)
            }
        }
    }

    pub fn make_subs_from(addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridgeSubs {
            bind: recipient!(addr, BindMessage),
            outbound_payments_instructions: recipient!(addr, OutboundPaymentsInstructions),
            qualified_payables: recipient!(addr, QualifiedPayablesMessage),
            retrieve_transactions: recipient!(addr, RetrieveTransactions),
            ui_sub: recipient!(addr, NodeFromUiMessage),
            request_transaction_receipts: recipient!(addr, RequestTransactionReceipts),
        }
    }

    fn handle_qualified_payable_msg(
        &mut self,
        incoming_message: QualifiedPayablesMessage,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        // TODO rewrite this into a batch call as soon as GH-629 gets into master
        let accountant_recipient = self.payable_payments_setup_subs_opt.clone();
        Box::new(
            self.blockchain_interface
                .introduce_blockchain_agent(incoming_message.consuming_wallet)
                .map_err(|e| format!("Blockchain agent build error: {:?}", e))
                .and_then(move |agent| {
                    let priced_qualified_payables =
                        agent.price_qualified_payables(incoming_message.qualified_payables);
                    let outgoing_message = BlockchainAgentWithContextMessage::new(
                        priced_qualified_payables,
                        agent,
                        incoming_message.response_skeleton_opt,
                    );
                    accountant_recipient
                        .expect("Accountant is unbound")
                        .try_send(outgoing_message)
                        .expect("Accountant is dead");
                    Ok(())
                }),
        )
    }

    fn handle_outbound_payments_instructions(
        &mut self,
        msg: OutboundPaymentsInstructions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let skeleton_opt = msg.response_skeleton_opt;
        let sent_payable_subs = self
            .sent_payable_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();

        let send_message_if_failure = move |msg: SentPayables| {
            sent_payable_subs.try_send(msg).expect("Accountant is dead");
        };
        let send_message_if_successful = send_message_if_failure.clone();

        Box::new(
            self.process_payments(msg.agent, msg.affordable_accounts)
                .map_err(move |e: PayableTransactionError| {
                    send_message_if_failure(SentPayables {
                        payment_procedure_result: Err(e.clone()),
                        response_skeleton_opt: skeleton_opt,
                    });
                    format!("ReportAccountsPayable: {}", e)
                })
                .and_then(move |payment_result| {
                    send_message_if_successful(SentPayables {
                        payment_procedure_result: Ok(payment_result),
                        response_skeleton_opt: skeleton_opt,
                    });
                    Ok(())
                }),
        )
    }

    fn handle_retrieve_transactions(
        &mut self,
        msg: RetrieveTransactions,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let (start_block, block_scan_range) = {
            let persistent_config_lock = self
                .persistent_config_arc
                .lock()
                .expect("Unable to lock persistent config in BlockchainBridge");
            let start_block_value = match persistent_config_lock.start_block() {
                    Ok(Some(block)) => BlockMarker::Value(block),
                    Ok(None) => BlockMarker::Uninitialized,
                    Err(e) => panic!("Cannot retrieve start block from database; payments to you may not be processed: {:?}", e)
                };
            // TODO: Rename this field to block_scan_range but it'll require changes in database and UI communication
            let block_scan_range_value = match persistent_config_lock.max_block_count() {
                    Ok(Some(range)) => BlockScanRange::Range(range),
                    Ok(None) => BlockScanRange::NoLimit,
                    Err(e) => panic!("Cannot retrieve block scan range from database; payments to you may not be processed: {:?}", e)
                };
            (start_block_value, block_scan_range_value)
        };

        let logger = self.logger.clone();
        let received_payments_subs = self
            .received_payments_subs_opt
            .as_ref()
            .expect("Accountant is unbound")
            .clone();
        let persistent_config_arc = self.persistent_config_arc.clone();

        Box::new(
            self.blockchain_interface
                .retrieve_transactions(
                    start_block,
                    block_scan_range,
                    msg.recipient.address(),
                )
                .map_err(move |e| {
                    if let Some(max_block_count) =
                        BlockchainBridge::extract_max_block_count(e.clone())
                    {
                        match persistent_config_arc
                            .lock()
                            .expect("Mutex with persistent configuration in BlockchainBridge was poisoned")
                            .set_max_block_count(Some(max_block_count))
                        {
                            Ok(()) => {
                                debug!(
                                    logger,
                                    "Updated max_block_count to {} in database.", max_block_count
                                );
                            }
                            Err(e) => {
                                panic!(
                                    "Attempt to set new max block to {} failed due to: {:?}",
                                    max_block_count, e
                                )
                            }
                        }
                    }
                    format!("Error while retrieving transactions: {:?}", e)
                })
                .and_then(move |retrieved_blockchain_transactions| {
                    received_payments_subs
                        .try_send(ReceivedPayments {
                            timestamp: SystemTime::now(),
                            new_start_block: retrieved_blockchain_transactions.new_start_block,
                            response_skeleton_opt: msg.response_skeleton_opt,
                            transactions: retrieved_blockchain_transactions.transactions,
                        })
                        .expect("Accountant is dead.");
                    Ok(())
                }),
        )
    }

    fn log_status_of_tx_receipts(
        logger: &Logger,
        transaction_receipts_results: &[TxReceiptResult],
    ) {
        logger.debug(|| {
            let (successful_count, failed_count, pending_count) =
                transaction_receipts_results.iter().fold(
                    (0, 0, 0),
                    |(success, fail, pending), transaction_receipt| match transaction_receipt {
                        TxReceiptResult(Ok(tx_receipt)) => match tx_receipt.status {
                            StatusReadFromReceiptCheck::Failed(_) => (success, fail + 1, pending),
                            StatusReadFromReceiptCheck::Succeeded(_) => {
                                (success + 1, fail, pending)
                            }
                            StatusReadFromReceiptCheck::Pending => (success, fail, pending + 1),
                        },
                        TxReceiptResult(Err(_)) => (success, fail, pending + 1),
                    },
                );
            format!(
                "Scan results: Successful: {}, Pending: {}, Failed: {}",
                successful_count, pending_count, failed_count
            )
        });
    }

    fn handle_request_transaction_receipts(
        &mut self,
        msg: RequestTransactionReceipts,
    ) -> Box<dyn Future<Item = (), Error = String>> {
        let logger = self.logger.clone();
        let accountant_recipient = self
            .pending_payable_confirmation
            .report_tx_receipts_sub_opt
            .clone()
            .expect("Accountant is unbound");
        Box::new(
            self.blockchain_interface
                .process_transaction_receipts(msg.tx_hashes)
                .map_err(move |e| e.to_string())
                .and_then(move |tx_receipt_results| {
                    Self::log_status_of_tx_receipts(&logger, tx_receipt_results.as_slice());
                    accountant_recipient
                        .try_send(TxReceiptsMessage {
                            results: tx_receipt_results,
                            response_skeleton_opt: msg.response_skeleton_opt,
                        })
                        .expect("Accountant is dead");

                    Ok(())
                }),
        )
    }

    fn handle_scan_future<M, F>(&mut self, handler: F, scan_type: ScanType, msg: M)
    where
        F: FnOnce(&mut BlockchainBridge, M) -> Box<dyn Future<Item = (), Error = String>>,
        M: SkeletonOptHolder,
    {
        let skeleton_opt = msg.skeleton_opt();
        let logger = self.logger.clone();
        let scan_error_subs_opt = self.scan_error_subs_opt.clone();
        let future = handler(self, msg).map_err(move |e| {
            warning!(logger, "{}", e);
            scan_error_subs_opt
                .as_ref()
                .expect("Accountant not bound")
                .try_send(ScanError {
                    scan_type,
                    response_skeleton_opt: skeleton_opt,
                    msg: e,
                })
                .expect("Accountant is dead");
        });

        actix::spawn(future);
    }

    fn process_payments(
        &self,
        agent: Box<dyn BlockchainAgent>,
        affordable_accounts: PricedQualifiedPayables,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>
    {
        let recipient = self.new_pending_payables_recipient();
        let logger = self.logger.clone();
        self.blockchain_interface.submit_payables_in_batch(
            logger,
            agent,
            recipient,
            affordable_accounts,
        )
    }

    fn new_pending_payables_recipient(&self) -> Recipient<RegisterNewPendingPayables> {
        self.pending_payable_confirmation
            .register_new_pending_payables_sub_opt
            .clone()
            .expect("Accountant unbound")
    }

    pub fn extract_max_block_count(error: BlockchainInterfaceError) -> Option<u64> {
        let regex_result =
            Regex::new(r".* (max: |allowed for your plan: |is limited to |block range limit \(|exceeds max block range )(?P<max_block_count>\d+).*")
                .expect("Invalid regex");
        let max_block_count = match error {
            BlockchainInterfaceError::QueryFailed(msg) => match regex_result.captures(msg.as_str())
            {
                Some(captures) => match captures.name("max_block_count") {
                    Some(m) => match m.as_str().parse::<u64>() {
                        Ok(value) => Some(value),
                        Err(_) => None,
                    },
                    _ => None,
                },
                None => match msg.as_str() {
                    "Got invalid response: Expected batch, got single." => Some(1000),
                    _ => None,
                },
            },
            _ => None,
        };
        max_block_count
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct PendingTxInfo {
    hash: H256,
    when_sent: SystemTime,
}

pub fn increase_gas_price_by_margin(gas_price: u128) -> u128 {
    (gas_price * (100 + DEFAULT_GAS_PRICE_MARGIN as u128)) / 100
}

pub struct BlockchainBridgeSubsFactoryReal {}

impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs> for BlockchainBridgeSubsFactoryReal {
    fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
        BlockchainBridge::make_subs_from(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::db_access_objects::sent_payable_dao::TxStatus;
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        QualifiedPayableWithGasPrice, UnpricedQualifiedPayables,
    };
    use crate::accountant::scanners::payable_scanner_extension::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::pending_payable_scanner::utils::TxHashByTable;
    use crate::accountant::test_utils::make_priced_qualified_payables;
    use crate::accountant::test_utils::{make_payable_account, make_sent_tx};
    use crate::accountant::PendingPayable;
    use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError::TransactionID;
    use crate::blockchain::blockchain_interface::data_structures::errors::{
        BlockchainAgentBuildError, PayableTransactionError,
    };
    use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible::Correct;
    use crate::blockchain::blockchain_interface::data_structures::{
        BlockchainTransaction, RetrievedBlockchainTransactions, RetrievedTxStatus, TxBlock,
        TxReceiptError,
    };
    use crate::blockchain::test_utils::{
        make_blockchain_interface_web3, make_tx_hash, ReceiptResponseBuilder,
    };
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::match_lazily_every_type_id;
    use crate::node_test_utils::check_timestamp;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{
        make_accountant_subs_from_recorder, make_recorder, peer_actors_builder,
    };
    use crate::test_utils::recorder_stop_conditions::StopConditions;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, configure_default_persistent_config,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage, ZERO,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use ethereum_types::U64;
    use masq_lib::constants::DEFAULT_MAX_BLOCK_COUNT;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::{
        ensure_node_home_directory_exists, LogObject, TEST_DEFAULT_CHAIN,
    };
    use masq_lib::utils::find_free_port;
    use std::any::TypeId;
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H160};
    use crate::blockchain::errors::blockchain_loggable_error::app_rpc_web3_error::{AppRpcWeb3Error, RemoteError};
    use crate::blockchain::errors::validation_status::ValidationStatus;

    impl Handler<AssertionsMessage<Self>> for BlockchainBridge {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<Self>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "BLOCKCHAINBRIDGE");
        assert_eq!(DEFAULT_BLOCKCHAIN_SERVICE_URL, "https://0.0.0.0");
    }

    fn stub_bi() -> Box<dyn BlockchainInterface> {
        Box::new(make_blockchain_interface_web3(find_free_port()))
    }

    #[test]
    fn blockchain_bridge_receives_bind_message() {
        init_test_logging();
        let subject = BlockchainBridge::new(
            stub_bi(),
            Arc::new(Mutex::new(configure_default_persistent_config(ZERO))),
            false,
        );
        let system = System::new("blockchain_bridge_receives_bind_message");
        let addr = subject.start();

        addr.try_send(BindMessage {
            peer_actors: peer_actors_builder().build(),
        })
        .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new()
            .exists_log_containing("DEBUG: BlockchainBridge: Received BindMessage");
    }

    #[test]
    fn blockchain_interface_is_constructed_with_missing_blockchain_service_url() {
        init_test_logging();
        let subject = BlockchainBridge::initialize_blockchain_interface(
            None,
            TEST_DEFAULT_CHAIN,
            Logger::new("test"),
        );

        let chain = subject.get_chain();

        assert_eq!(chain, TEST_DEFAULT_CHAIN);
        TestLogHandler::new().exists_log_containing("INFO: test: The Blockchain service url is not set yet. its been defaulted to a wild card IP");
    }

    #[test]
    fn blockchain_interface_is_constructed_with_a_blockchain_service_url() {
        init_test_logging();
        let blockchain_service_url = "https://example.com";
        let subject = BlockchainBridge::initialize_blockchain_interface(
            Some(blockchain_service_url.to_string()),
            TEST_DEFAULT_CHAIN,
            Logger::new("test"),
        );

        let chain = subject.get_chain();

        assert_eq!(chain, TEST_DEFAULT_CHAIN);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: test: Blockchain service url has been set to {}",
            blockchain_service_url
        ));
    }

    #[test]
    fn handles_qualified_payables_msg_in_new_payables_mode_and_sends_response_back_to_accountant() {
        let system = System::new(
            "handles_qualified_payables_msg_in_new_payables_mode_and_sends_response_back_to_accountant");
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            // Fetching a recommended gas price
            .ok_response("0x230000000".to_string(), 1)
            .ok_response("0xAAAA".to_string(), 1)
            .ok_response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_recipient = accountant.start().recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let persistent_configuration = PersistentConfigurationMock::default();
        let wallet_1 = make_wallet("booga");
        let wallet_2 = make_wallet("gulp");
        let qualified_payables = vec![
            PayableAccount {
                wallet: wallet_1.clone(),
                balance_wei: 78_654_321_124,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(1000))
                    .unwrap(),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: wallet_2.clone(),
                balance_wei: 60_457_111_003,
                last_paid_timestamp: SystemTime::now()
                    .checked_sub(Duration::from_secs(500))
                    .unwrap(),
                pending_payable_opt: None,
            },
        ];
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration)),
            false,
        );
        subject.payable_payments_setup_subs_opt = Some(accountant_recipient);
        let unpriced_qualified_payables =
            UnpricedQualifiedPayables::from(qualified_payables.clone());
        let qualified_payables_msg = QualifiedPayablesMessage {
            qualified_payables: unpriced_qualified_payables.clone(),
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444,
            }),
        };

        subject
            .handle_qualified_payable_msg(qualified_payables_msg)
            .wait()
            .unwrap();

        System::current().stop();
        system.run();
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        let blockchain_agent_with_context_msg_actual: &BlockchainAgentWithContextMessage =
            accountant_received_payment.get_record(0);
        let expected_priced_qualified_payables = PricedQualifiedPayables {
            payables: qualified_payables
                .into_iter()
                .map(|payable| QualifiedPayableWithGasPrice {
                    payable,
                    gas_price_minor: increase_gas_price_by_margin(0x230000000),
                })
                .collect(),
        };
        assert_eq!(
            blockchain_agent_with_context_msg_actual.qualified_payables,
            expected_priced_qualified_payables
        );
        let actual_agent = blockchain_agent_with_context_msg_actual.agent.as_ref();
        assert_eq!(actual_agent.consuming_wallet(), &consuming_wallet);
        assert_eq!(
            actual_agent.consuming_wallet_balances(),
            ConsumingWalletBalances::new(0xAAAA.into(), 0xFFFF.into())
        );
        assert_eq!(
            actual_agent.estimate_transaction_fee_total(
                &actual_agent.price_qualified_payables(unpriced_qualified_payables)
            ),
            1_791_228_995_698_688
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444
            })
        );
        assert_eq!(accountant_received_payment.len(), 1);
    }

    #[test]
    fn qualified_payables_msg_is_handled_but_fails_on_introduce_blockchain_agent() {
        let system = System::new(
            "qualified_payables_msg_is_handled_but_fails_on_introduce_blockchain_agent",
        );
        let port = find_free_port();
        // build blockchain agent fails by not providing the third response.
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x23".to_string(), 1)
            .ok_response("0x23".to_string(), 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_recipient = accountant.start().recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"somewallet");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject.payable_payments_setup_subs_opt = Some(accountant_recipient);
        let qualified_payables = UnpricedQualifiedPayables::from(vec![make_payable_account(123)]);
        let qualified_payables_msg = QualifiedPayablesMessage {
            qualified_payables,
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 11122,
                context_id: 444,
            }),
        };

        let error_msg = subject
            .handle_qualified_payable_msg(qualified_payables_msg)
            .wait()
            .unwrap_err();

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        let service_fee_balance_error = BlockchainAgentBuildError::ServiceFeeBalance(
            consuming_wallet.address(),
            BlockchainInterfaceError::QueryFailed(
                "Api error: Transport error: Error(IncompleteMessage)".to_string(),
            ),
        );
        assert_eq!(
            error_msg,
            format!(
                "Blockchain agent build error: {:?}",
                service_fee_balance_error
            )
        )
    }

    #[test]
    fn handle_outbound_payments_instructions_sees_payment_happen_and_sends_payment_results_back_to_accountant(
    ) {
        let system = System::new(
            "handle_outbound_payments_instructions_sees_payment_happen_and_sends_payment_results_back_to_accountant",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x20".to_string(), 1)
            .begin_batch()
            .ok_response("rpc result".to_string(), 1)
            .end_batch()
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(SentPayables))
            .start();
        let wallet_account = make_wallet("blah");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration_mock)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        let account = PayableAccount {
            wallet: wallet_account,
            balance_wei: 111_420_204,
            last_paid_timestamp: from_unix_timestamp(150_000_000),
            pending_payable_opt: None,
        };
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default()
            .set_arbitrary_id_stamp(agent_id_stamp)
            .consuming_wallet_result(consuming_wallet)
            .get_chain_result(Chain::PolyMainnet);

        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(OutboundPaymentsInstructions {
                affordable_accounts: make_priced_qualified_payables(vec![(
                    account.clone(),
                    111_222_333,
                )]),
                agent: Box::new(agent),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        let time_before = SystemTime::now();
        system.run();
        let time_after = SystemTime::now();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let register_new_pending_sent_tx_msg =
            accountant_recording.get_record::<RegisterNewPendingPayables>(0);
        let sent_payables_msg = accountant_recording.get_record::<SentPayables>(1);
        let expected_hash =
            H256::from_str("81d20df32920161727cd20e375e53c2f9df40fd80256a236fb39e444c999fb6c")
                .unwrap();
        assert_eq!(
            sent_payables_msg,
            &SentPayables {
                payment_procedure_result: Ok(vec![Correct(PendingPayable {
                    recipient_wallet: account.wallet.clone(),
                    hash: expected_hash
                })]),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                })
            }
        );
        let first_actual_sent_tx = &register_new_pending_sent_tx_msg.new_sent_txs[0];
        assert_eq!(
            first_actual_sent_tx.receiver_address,
            account.wallet.address()
        );
        assert_eq!(first_actual_sent_tx.hash, expected_hash);
        assert_eq!(first_actual_sent_tx.amount_minor, account.balance_wei);
        assert_eq!(first_actual_sent_tx.gas_price_minor, 111_222_333);
        assert_eq!(first_actual_sent_tx.nonce, 0x20);
        assert_eq!(
            first_actual_sent_tx.status,
            TxStatus::Pending(ValidationStatus::Waiting)
        );
        assert!(
            to_unix_timestamp(time_before) <= first_actual_sent_tx.timestamp
                && first_actual_sent_tx.timestamp <= to_unix_timestamp(time_after),
            "We thought the timestamp was between {:?} and {:?}, but it was {:?}",
            time_before,
            time_after,
            from_unix_timestamp(first_actual_sent_tx.timestamp)
        );
        assert_eq!(accountant_recording.len(), 2);
    }

    #[test]
    fn handle_outbound_payments_instructions_sends_error_when_failing_on_submit_batch() {
        let system = System::new(
            "handle_outbound_payments_instructions_sends_error_when_failing_on_submit_batch",
        );
        let port = find_free_port();
        // To make submit_batch failed we didn't provide any responses for batch calls
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x20".to_string(), 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(SentPayables))
            .start();
        let account_wallet = make_wallet("blah");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_configuration_mock = PersistentConfigurationMock::default();
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_configuration_mock)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = make_accountant_subs_from_recorder(&accountant_addr);
        let account = PayableAccount {
            wallet: account_wallet.clone(),
            balance_wei: 111_420_204,
            last_paid_timestamp: from_unix_timestamp(150_000_000),
            pending_payable_opt: None,
        };
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let agent = BlockchainAgentMock::default()
            .consuming_wallet_result(consuming_wallet)
            .gas_price_result(123)
            .get_chain_result(Chain::PolyMainnet);
        send_bind_message!(subject_subs, peer_actors);

        let _ = addr
            .try_send(OutboundPaymentsInstructions {
                affordable_accounts: make_priced_qualified_payables(vec![(
                    account.clone(),
                    111_222_333,
                )]),
                agent: Box::new(agent),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            })
            .unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let actual_register_new_pending_payables_msg =
            accountant_recording.get_record::<RegisterNewPendingPayables>(0);
        let sent_payables_msg = accountant_recording.get_record::<SentPayables>(1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(2);
        assert_sending_error(
            sent_payables_msg
                .payment_procedure_result
                .as_ref()
                .unwrap_err(),
            "Transport error: Error(IncompleteMessage)",
        );
        assert_eq!(
            actual_register_new_pending_payables_msg.new_sent_txs[0].receiver_address,
            account_wallet.address()
        );
        assert_eq!(
            actual_register_new_pending_payables_msg.new_sent_txs[0].hash,
            H256::from_str("81d20df32920161727cd20e375e53c2f9df40fd80256a236fb39e444c999fb6c")
                .unwrap()
        );
        assert_eq!(
            actual_register_new_pending_payables_msg.new_sent_txs[0].amount_minor,
            account.balance_wei
        );
        let number_of_requested_txs = actual_register_new_pending_payables_msg.new_sent_txs.len();
        assert_eq!(
            number_of_requested_txs, 1,
            "We expected only one sent tx, but got {}",
            number_of_requested_txs
        );
        assert_eq!(
            *scan_error_msg,
            ScanError {
                scan_type: ScanType::Payables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: format!(
                    "ReportAccountsPayable: Sending phase: \"Transport error: Error(IncompleteMessage)\". \
                    Signed and hashed txs: 0x81d20df32920161727cd20e375e53c2f9df40fd80256a236fb39e444c999fb6c"
                )
            }
        );
        assert_eq!(accountant_recording.len(), 3);
    }

    #[test]
    fn process_payments_works() {
        let test_name = "process_payments_works";
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x01".to_string(), 1)
            .begin_batch()
            .ok_response("rpc_result".to_string(), 7)
            .ok_response("rpc_result_2".to_string(), 7)
            .end_batch()
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let accounts_1 = make_payable_account(1);
        let accounts_2 = make_payable_account(2);
        let affordable_qualified_payables = make_priced_qualified_payables(vec![
            (accounts_1.clone(), 777_777_777),
            (accounts_2.clone(), 999_999_999),
        ]);
        let system = System::new(test_name);
        let agent = BlockchainAgentMock::default()
            .consuming_wallet_result(consuming_wallet)
            .gas_price_result(1)
            .get_chain_result(Chain::PolyMainnet);
        let msg =
            OutboundPaymentsInstructions::new(affordable_qualified_payables, Box::new(agent), None);
        let persistent_config = PersistentConfigurationMock::new();
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_web3),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let (accountant, _, accountant_recording) = make_recorder();
        subject
            .pending_payable_confirmation
            .register_new_pending_payables_sub_opt = Some(accountant.start().recipient());

        let result = subject
            .process_payments(msg.agent, msg.affordable_accounts)
            .wait();

        System::current().stop();
        system.run();
        let processed_payments = result.unwrap();
        assert_eq!(
            processed_payments[0],
            Correct(PendingPayable {
                recipient_wallet: accounts_1.wallet,
                hash: H256::from_str(
                    "c0756e8da662cee896ed979456c77931668b7f8456b9f978fc3305671f8f82ad"
                )
                .unwrap()
            })
        );
        assert_eq!(
            processed_payments[1],
            Correct(PendingPayable {
                recipient_wallet: accounts_2.wallet,
                hash: H256::from_str(
                    "9ba19f88ce43297d700b1f57ed8bc6274d01a5c366b78dd05167f9874c867ba0"
                )
                .unwrap()
            })
        );
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(recording.len(), 1);
    }

    #[test]
    fn process_payments_fails_on_get_transaction_count() {
        let test_name = "process_payments_fails_on_get_transaction_count";
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("trash transaction id".to_string(), 1)
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(port);
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let system = System::new(test_name);
        let agent = BlockchainAgentMock::default()
            .get_chain_result(TEST_DEFAULT_CHAIN)
            .consuming_wallet_result(consuming_wallet)
            .gas_price_result(123);
        let msg = OutboundPaymentsInstructions::new(
            make_priced_qualified_payables(vec![(make_payable_account(111), 111_000_000)]),
            Box::new(agent),
            None,
        );
        let persistent_config = configure_default_persistent_config(ZERO);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface_web3),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let (accountant, _, accountant_recording) = make_recorder();
        subject
            .pending_payable_confirmation
            .register_new_pending_payables_sub_opt = Some(accountant.start().recipient());

        let result = subject
            .process_payments(msg.agent, msg.affordable_accounts)
            .wait();

        System::current().stop();
        system.run();
        let error_result = result.unwrap_err();
        assert_eq!(
            error_result,
            TransactionID(BlockchainInterfaceError::QueryFailed(
                "Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0) for wallet 0x2581…7849".to_string()
            ))
        );
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    fn assert_sending_error(error: &PayableTransactionError, error_msg: &str) {
        if let PayableTransactionError::Sending { msg, .. } = error {
            assert!(
                msg.contains(error_msg),
                "Actual Error message: {} does not contain this fragment {}",
                msg,
                error_msg
            );
        } else {
            panic!("Received wrong error: {:?}", error);
        }
    }

    #[test]
    fn blockchain_bridge_processes_requests_for_a_complete_and_null_transaction_receipt() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant =
            accountant.system_stop_conditions(match_lazily_every_type_id!(TxReceiptsMessage));
        let tx_hash_1 = make_tx_hash(123);
        let tx_hash_2 = make_tx_hash(456);
        let first_response = ReceiptResponseBuilder::default()
            .status(U64::from(1))
            .transaction_hash(tx_hash_1)
            .build();
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .raw_response(first_response)
            // A transaction receipt is null when the transaction is not available
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .end_batch()
            .start();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant).build();
        send_bind_message!(subject_subs, peer_actors);
        let msg = RequestTransactionReceipts {
            tx_hashes: vec![
                TxHashByTable::SentPayable(tx_hash_1),
                TxHashByTable::FailedPayable(tx_hash_2),
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(msg).unwrap();

        let system = System::new("transaction receipts");
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let tx_receipts_message = accountant_recording.get_record::<TxReceiptsMessage>(0);
        let mut expected_receipt = TransactionReceipt::default();
        expected_receipt.transaction_hash = tx_hash_1;
        expected_receipt.status = Some(U64::from(1));
        assert_eq!(
            tx_receipts_message,
            &TxReceiptsMessage {
                results: vec![
                    TxReceiptResult(Ok(RetrievedTxStatus::new(
                        TxHashByTable::SentPayable(tx_hash_1),
                        expected_receipt.into()
                    ))),
                    TxReceiptResult(Ok(RetrievedTxStatus::new(
                        TxHashByTable::FailedPayable(tx_hash_2),
                        StatusReadFromReceiptCheck::Pending
                    )))
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn blockchain_bridge_logs_error_from_retrieving_received_payments() {
        init_test_logging();
        let port = find_free_port();
        // We have intentionally left out responses to cause this error
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(ScanError))
            .start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let received_payments_subs: Recipient<ReceivedPayments> = accountant_addr.recipient();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(DEFAULT_MAX_BLOCK_COUNT)))
            .start_block_result(Ok(Some(5))); // no set_start_block_result: set_start_block() must not be called
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        subject.received_payments_subs_opt = Some(received_payments_subs);
        let msg = RetrieveTransactions {
            recipient: make_wallet("blah"),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(msg).unwrap();

        system.run();
        let recording = accountant_recording_arc.lock().unwrap();
        let scan_error = recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: None,
                msg: "Error while retrieving transactions: QueryFailed(\"Transport error: Error(IncompleteMessage)\")".to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing(
            "WARN: BlockchainBridge: Error while retrieving transactions: QueryFailed(\"Transport error: Error(IncompleteMessage)\")",
        );
    }

    #[test]
    fn handle_request_transaction_receipts_sends_back_results() {
        init_test_logging();
        let port = find_free_port();
        let block_number = U64::from(4545454);
        let contract_address = H160::from_low_u64_be(887766);
        let tx_receipt_response = ReceiptResponseBuilder::default()
            .block_number(block_number)
            .block_hash(Default::default())
            .status(U64::from(1))
            .contract_address(contract_address)
            .build();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .raw_response(tx_receipt_response)
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .end_batch()
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(TxReceiptsMessage))
            .start();
        let report_transaction_receipt_recipient: Recipient<TxReceiptsMessage> =
            accountant_addr.clone().recipient();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.recipient();
        let tx_hash_1 = make_tx_hash(1334);
        let tx_hash_2 = make_tx_hash(1000);
        let tx_hash_3 = make_tx_hash(1212);
        let tx_hash_4 = make_tx_hash(1111);
        let blockchain_interface = make_blockchain_interface_web3(port);
        let system = System::new("test_transaction_receipts");
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject
            .pending_payable_confirmation
            .report_tx_receipts_sub_opt = Some(report_transaction_receipt_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            tx_hashes: vec![
                TxHashByTable::SentPayable(tx_hash_1),
                TxHashByTable::SentPayable(tx_hash_2),
                TxHashByTable::SentPayable(tx_hash_3),
                TxHashByTable::SentPayable(tx_hash_4),
            ],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg).unwrap();

        assert_eq!(system.run(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let report_receipts_msg = accountant_recording.get_record::<TxReceiptsMessage>(0);
        assert_eq!(
            *report_receipts_msg,
            TxReceiptsMessage {
                results: vec![
                    TxReceiptResult(Ok(RetrievedTxStatus::new(TxHashByTable::SentPayable(tx_hash_1), StatusReadFromReceiptCheck::Pending))),
                    TxReceiptResult(Ok(RetrievedTxStatus::new(TxHashByTable::SentPayable(tx_hash_2),  StatusReadFromReceiptCheck::Succeeded(TxBlock {
                        block_hash: Default::default(),
                        block_number,
                    })))),
                    TxReceiptResult(Err(
                        TxReceiptError::new(
                            TxHashByTable::SentPayable(tx_hash_3),
                        AppRpcWeb3Error:: Remote(RemoteError::Web3RpcError { code: 429, message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string()})))),
                    TxReceiptResult(Ok(RetrievedTxStatus::new(TxHashByTable::SentPayable(tx_hash_1), StatusReadFromReceiptCheck::Pending))),
                ],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: BlockchainBridge: Scan results: Successful: 1, Pending: 3, Failed: 0",
        );
    }

    #[test]
    fn handle_request_transaction_receipts_failing_submit_the_batch() {
        init_test_logging();
        let (accountant, _, accountant_recording) = make_recorder();
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(ScanError))
            .start();
        let scan_error_recipient: Recipient<ScanError> = accountant_addr.clone().recipient();
        let report_transaction_recipient: Recipient<TxReceiptsMessage> =
            accountant_addr.recipient();
        let tx_hash_1 = make_tx_hash(10101);
        let tx_hash_2 = make_tx_hash(10102);
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let blockchain_interface = make_blockchain_interface_web3(port);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            false,
        );
        subject
            .pending_payable_confirmation
            .report_tx_receipts_sub_opt = Some(report_transaction_recipient);
        subject.scan_error_subs_opt = Some(scan_error_recipient);
        let msg = RequestTransactionReceipts {
            tx_hashes: vec![
                TxHashByTable::SentPayable(tx_hash_1),
                TxHashByTable::FailedPayable(tx_hash_2),
            ],
            response_skeleton_opt: None,
        };
        let system = System::new("test");

        let _ = subject.handle_scan_future(
            BlockchainBridge::handle_request_transaction_receipts,
            ScanType::PendingPayables,
            msg,
        );

        system.run();
        let recording = accountant_recording.lock().unwrap();
        assert_eq!(
            recording.get_record::<ScanError>(0),
            &ScanError {
                scan_type: ScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: "Blockchain error: Query failed: Transport error: Error(IncompleteMessage)"
                    .to_string()
            }
        );
        assert_eq!(recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Blockchain error: Query failed: Transport error: Error(IncompleteMessage)");
    }

    #[test]
    fn handle_retrieve_transactions_uses_default_max_block_count_for_ending_block_number_upon_get_block_number_error(
    ) {
        init_test_logging();
        let system = System::new(
            "handle_retrieve_transactions_uses_default_max_block_count_for_ending_block_number_upon_get_block_number_error",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)// 1,000,000,000
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000000000002a",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000000066697273745f77616c6c6574"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fc",
                  "data": "0x00000000000000000000000000000037",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000007365636f6e645f77616c6c6574"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let earning_wallet = make_wallet("somewallet");
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(Some(9_000_000u64)))
            .start_block_result(Ok(Some(42)));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.received_payments_subs_opt = Some(accountant.start().recipient());
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        subject
            .handle_retrieve_transactions(retrieve_transactions)
            .wait()
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: BlockMarker::Value(42 + 9_000_000 + 1),
            transactions: vec![
                BlockchainTransaction {
                    block_number: 6040059,
                    // Wallet represented in the RPC response by the first 'topic' as: 0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80
                    from: make_wallet("first_wallet"),
                    // Paid amount read out from the field 'data' in the RPC
                    wei_amount: 42,
                },
                BlockchainTransaction {
                    block_number: 6040060,
                    // Wallet represented in the RPC response by the first 'topic' as: 0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80
                    from: make_wallet("second_wallet"),
                    // Paid amount read out from the field 'data' in the RPC
                    wei_amount: 55,
                },
            ],
        };
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                new_start_block: expected_transactions.new_start_block,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                transactions: expected_transactions.transactions,
            }
        );
    }

    #[test]
    fn handle_retrieve_transactions_when_start_block_number_starts_undefined_in_a_brand_new_database(
    ) {
        let system = System::new(
            "handle_retrieve_transactions_when_start_block_number_starts_undefined_in_a_brand_new_database",
        );
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x845FED".to_string(), 0)
            .ok_response(
                vec![LogObject {
                    removed: false,
                    log_index: Some("0x20".to_string()),
                    transaction_index: Some("0x30".to_string()),
                    transaction_hash: Some(
                        "0x2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    block_hash: Some(
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    block_number: Some("0x845FEC".to_string()),
                    address: "0x3333333333333333333333333333333333333334".to_string(),
                    data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                        .to_string(),
                    topics: vec![
                        "0xddf252ad1be2c89b69c2b06800000000000000000000736f6d6577616c6c6574"
                            .to_string(),
                        "0xddf252ad1be2c89b69c2b06900000000000000000000736f6d6577616c6c6574"
                            .to_string(),
                    ],
                }],
                1,
            )
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr =
            accountant.system_stop_conditions(match_lazily_every_type_id!(ReceivedPayments));
        let some_wallet = make_wallet("somewallet");
        let recipient_wallet = make_wallet("recipient_wallet");
        let amount = 996000000;
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: BlockMarker::Value(8675309u64),
            transactions: vec![BlockchainTransaction {
                block_number: 8675308u64,
                from: some_wallet.clone(),
                wei_amount: amount,
            }],
        };
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .max_block_count_result(Ok(None))
            .start_block_result(Ok(None));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant_addr).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: recipient_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let before = SystemTime::now();

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let after = SystemTime::now();
        let accountant_received_payment = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_received_payment.len(), 1);
        let received_payments = accountant_received_payment.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments.timestamp, after);
        assert_eq!(
            received_payments,
            &ReceivedPayments {
                timestamp: received_payments.timestamp,
                new_start_block: BlockMarker::Value(8675309u64 + 1),
                transactions: expected_transactions.transactions,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn handle_retrieve_transactions_sends_received_payments_back_to_accountant() {
        let system =
            System::new("handle_retrieve_transactions_sends_received_payments_back_to_accountant");
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0) // 1,000,000,000
            .ok_response(
                vec![LogObject {
                    removed: false,
                    log_index: Some("0x20".to_string()),
                    transaction_index: Some("0x30".to_string()),
                    transaction_hash: Some(
                        "0x2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    block_hash: Some(
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    block_number: Some("0x7D0".to_string()), // 2000 decimal
                    address: "0x3333333333333333333333333333333333333334".to_string(),
                    data: "0x000000000000000000000000000000000000000000000000000000003b5dc100"
                        .to_string(),
                    topics: vec![
                        "0xddf252ad1be2c89b69c2b0680000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                        "0xddf252ad1be2c89b69c2b0690000000000006561726e696e675f77616c6c6574"
                            .to_string(),
                    ],
                }],
                1,
            )
            .start();

        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr =
            accountant.system_stop_conditions(match_lazily_every_type_id!(ReceivedPayments));
        let earning_wallet = make_wallet("earning_wallet");
        let amount = 996000000;
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(Some(6)))
            .max_block_count_result(Ok(Some(5000)));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant_addr).build();
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

        system.run();
        let after = SystemTime::now();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let received_payments_message = accountant_recording.get_record::<ReceivedPayments>(0);
        check_timestamp(before, received_payments_message.timestamp, after);
        let expected_transactions = RetrievedBlockchainTransactions {
            new_start_block: BlockMarker::Value(6 + 5000 + 1),
            transactions: vec![BlockchainTransaction {
                block_number: 2000,
                from: earning_wallet.clone(),
                wei_amount: amount,
            }],
        };
        assert_eq!(
            received_payments_message,
            &ReceivedPayments {
                timestamp: received_payments_message.timestamp,
                new_start_block: expected_transactions.new_start_block,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                transactions: expected_transactions.transactions,
            }
        );
    }

    #[test]
    fn handle_retrieve_transactions_receives_invalid_topics() {
        init_test_logging();
        let test_name = "handle_retrieve_transactions_receives_invalid_topics";
        let system = System::new(test_name);
        let logger = Logger::new(test_name);
        let port = find_free_port();
        let expected_response_logs = vec![LogObject {
            removed: false,
            log_index: Some("0x20".to_string()),
            transaction_index: Some("0x30".to_string()),
            transaction_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            ),
            block_hash: Some(
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            ),
            block_number: Some("0x7D0".to_string()), // 2000 decimal
            address: "0x3333333333333333333333333333333333333334".to_string(),
            data: "0x000000000000000000000000000000000000000000000000000000003b5dc100".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b0680000000000006561726e696e675f77616c6c6574".to_string(),
            ],
        }];
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .ok_response(expected_response_logs, 1)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant_addr =
            accountant.system_stop_conditions(match_lazily_every_type_id!(ScanError));
        let earning_wallet = make_wallet("earning_wallet");
        let mut blockchain_interface = make_blockchain_interface_web3(port);
        blockchain_interface.logger = logger;
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(Some(6)))
            .max_block_count_result(Ok(Some(1000)));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let addr = subject.start();
        let subject_subs = BlockchainBridge::make_subs_from(&addr);
        let peer_actors = peer_actors_builder().accountant(accountant_addr).build();
        send_bind_message!(subject_subs, peer_actors);
        let retrieve_transactions = RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error_msg,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "Error while retrieving transactions: InvalidResponse".to_string(),
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Invalid response from blockchain server:"
        ));
    }

    #[test]
    fn handle_retrieve_transactions_receives_query_failed_and_updates_max_block() {
        init_test_logging();
        let test_name = "handle_retrieve_transactions_receives_query_failed_and_updates_max_block";
        let system = System::new(test_name);
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .err_response(-32005, "Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000", 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let accountant = accountant.system_stop_conditions(match_lazily_every_type_id!(ScanError));
        let earning_wallet = make_wallet("earning_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let set_max_block_count_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(Some(6)))
            .max_block_count_result(Ok(None))
            .set_max_block_count_result(Ok(()))
            .set_max_block_count_params(&set_max_block_count_params_arc);
        let mut subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        subject.logger = Logger::new(test_name);
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

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let scan_error_msg = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            scan_error_msg,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321
                }),
                msg: "Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000\\\", data: None }\")".to_string(),
            }
        );
        let max_block_count_params = set_max_block_count_params_arc.lock().unwrap();
        assert_eq!(*max_block_count_params, vec![Some(1000)]);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Updated max_block_count to 1000 in database"
        ));
    }

    #[test]
    #[should_panic(
        expected = "Attempt to set new max block to 1000 failed due to: DatabaseError(\"my brain hurts\")"
    )]
    fn handle_retrieve_transactions_receives_panics_when_it_receives_persistent_config_error_while_setting_value(
    ) {
        let system = System::new("test");
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .err_response(-32005, "Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000", 0)
            .start();
        let (accountant, _, _) = make_recorder();
        let earning_wallet = make_wallet("earning_wallet");
        let blockchain_interface = make_blockchain_interface_web3(port);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(Some(6)))
            .max_block_count_result(Ok(Some(1000)))
            .set_max_block_count_result(Err(PersistentConfigError::DatabaseError(
                "my brain hurts".to_string(),
            )));
        let subject = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Arc::new(Mutex::new(persistent_config)),
            false,
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

        let _ = addr.try_send(retrieve_transactions).unwrap();

        system.run();
    }

    #[test]
    #[should_panic(
        expected = "Cannot retrieve start block from database; payments to you may not be processed: TransactionError"
    )]
    fn handle_retrieve_transactions_panics_if_start_block_cannot_be_read() {
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::TransactionError));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(find_free_port())),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let retrieve_transactions = RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        };

        let _ = subject.handle_retrieve_transactions(retrieve_transactions);
    }

    // TODO: GH-555: Remove system_stop_conditions while also confirming the ScanError msg wasn't sent.
    #[test]
    fn handle_scan_future_handles_success() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0xC8".to_string(), 0)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000000000002a",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000000066697273745f77616c6c6574"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fc",
                  "data": "0x00000000000000000000000000000037",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80",
                    "0x000000000000000000000000000000000000007365636f6e645f77616c6c6574"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let start_block = Some(2000);
        let wallet = make_wallet("somewallet");
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_result(Ok(start_block))
            .max_block_count_result(Ok(None));
        let retrieve_transactions = RetrieveTransactions {
            recipient: wallet.clone(),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let system = System::new("test");
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(ReceivedPayments))
            .start();
        subject.received_payments_subs_opt = Some(accountant_addr.clone().recipient());
        subject.scan_error_subs_opt = Some(accountant_addr.recipient());

        subject.handle_scan_future(
            BlockchainBridge::handle_retrieve_transactions,
            ScanType::Receivables,
            retrieve_transactions,
        );

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let received_msg = accountant_recording.get_record::<ReceivedPayments>(0);
        assert_eq!(received_msg.new_start_block, BlockMarker::Value(0xc8 + 1));
        let msg_opt = accountant_recording.get_record_opt::<ScanError>(1);
        assert_eq!(msg_opt, None, "We didnt expect a scan error: {:?}", msg_opt);
    }

    #[test]
    fn handle_scan_future_handles_failure() {
        assert_handle_scan_future_handles_failure(RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        });

        assert_handle_scan_future_handles_failure(RetrieveTransactions {
            recipient: make_wallet("somewallet"),
            response_skeleton_opt: None,
        });
    }

    fn assert_handle_scan_future_handles_failure(msg: RetrieveTransactions) {
        init_test_logging();
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0xC8".to_string(), 0)
            .err_response(-32005, "My tummy hurts", 0)
            .start();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let start_block = Some(2000);
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_result(Ok(start_block))
            .max_block_count_result(Ok(None));
        let mut subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(port)),
            Arc::new(Mutex::new(persistent_config)),
            false,
        );
        let system = System::new("test");
        let accountant_addr = accountant
            .system_stop_conditions(match_lazily_every_type_id!(ScanError))
            .start();
        subject.received_payments_subs_opt = Some(accountant_addr.clone().recipient());
        subject.scan_error_subs_opt = Some(accountant_addr.recipient());

        subject.handle_scan_future(
            BlockchainBridge::handle_retrieve_transactions,
            ScanType::Receivables,
            msg.clone(),
        );

        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ScanError>(0);
        assert_eq!(
            message,
            &ScanError {
                scan_type: ScanType::Receivables,
                response_skeleton_opt: msg.response_skeleton_opt,
                msg: "Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"My tummy hurts\\\", data: None }\")"
                    .to_string()
            }
        );
        assert_eq!(accountant_recording.len(), 1);
        TestLogHandler::new().exists_log_containing("WARN: BlockchainBridge: Error while retrieving transactions: QueryFailed(\"RPC error: Error { code: ServerError(-32005), message: \\\"My tummy hurts\\\", data: None }\")");
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn blockchain_bridge_can_be_crashed_properly_but_not_improperly() {
        let crashable = true;
        let subject = BlockchainBridge::new(
            Box::new(make_blockchain_interface_web3(find_free_port())),
            Arc::new(Mutex::new(PersistentConfigurationMock::default())),
            crashable,
        );

        prove_that_crash_request_handler_is_hooked_up(subject, CRASH_KEY);
    }

    #[test]
    fn extract_max_block_range_from_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs block range too large, range: 33636, max: 3500\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(3500u64), max_block_count);
    }

    #[test]
    fn extract_max_block_range_from_pokt_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("Rpc(Error { code: ServerError(-32001), message: \"Relay request failed validation: invalid relay request: eth_getLogs block range limit (100000 blocks) exceeded\", data: None })".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(100000u64), max_block_count);
    }
    /*
        POKT (Polygon mainnet and amoy)
        {"jsonrpc":"2.0","id":7,"error":{"message":"You cannot query logs for more than 100000 blocks at once.","code":-32064}}
    */
    /*
        Ankr
        {"jsonrpc":"2.0","error":{"code":-32600,"message":"block range is too wide"},"id":null}%
    */
    #[test]
    fn extract_max_block_range_for_ankr_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: ServerError(-32600), message: \"block range is too wide\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    /*
    MaticVigil
    [{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":7},{"error":{"message":"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000","code":-32005},"jsonrpc":"2.0","id":8}]%
    */
    #[test]
    fn extract_max_block_range_for_matic_vigil_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"Blockheight too far in the past. Check params passed to eth_getLogs or eth_call requests.Range of blocks allowed for your plan: 1000\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    /*
    Blockpi
    [{"jsonrpc":"2.0","id":7,"result":"0x21db466"},{"jsonrpc":"2.0","id":8,"error":{"code":-32602,"message":"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference"}}]
    */
    #[test]
    fn extract_max_block_range_for_blockpi_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: ServerError(-32005), message: \"eth_getLogs is limited to 1024 block range. Please check the parameter requirements at  https://docs.blockpi.io/documentations/api-reference\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1024), max_block_count);
    }

    /*
    blastapi - completely rejected call on Public endpoint as won't handle eth_getLogs method on public API
    [{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found","data":{"method":""}}},{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request","data":{"message":"Cancelled due to validation app_rpc_web3_error_kind in batch request"}}}] (edited)
    [8:50 AM]
    */

    #[test]
    fn extract_max_block_range_for_blastapi_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: ServerError(-32601), message: \"Method not found\", data: \"'eth_getLogs' is not available on our public API. Head over to https://docs.blastapi.io/blast-documentation/tutorials-and-guides/using-blast-to-get-a-blockchain-endpoint for more information\" }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(None, max_block_count);
    }

    #[test]
    fn extract_max_block_range_for_nodies_error_response() {
        let result = BlockchainInterfaceError::QueryFailed("RPC error: Error { code: InvalidParams, message: \"query exceeds max block range 100000\", data: None }".to_string());

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(100000), max_block_count);
    }

    #[test]
    fn extract_max_block_range_for_expected_batch_got_single_error_response() {
        let result = BlockchainInterfaceError::QueryFailed(
            "Got invalid response: Expected batch, got single.".to_string(),
        );

        let max_block_count = BlockchainBridge::extract_max_block_count(result);

        assert_eq!(Some(1000), max_block_count);
    }

    #[test]
    fn make_connections_implements_panic_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "blockchain_bridge",
            "make_connections_with_panic_on_migration",
        );

        let act = |data_dir: &Path| {
            BlockchainBridge::initialize_persistent_configuration(data_dir);
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    #[test]
    fn increase_gas_price_by_margin_works() {
        assert_eq!(increase_gas_price_by_margin(1_000_000_000), 1_300_000_000);
        assert_eq!(increase_gas_price_by_margin(9_000_000_000), 11_700_000_000);
    }
}

#[cfg(test)]
pub mod exportable_test_parts {
    use super::*;
    use crate::test_utils::recorder::make_blockchain_bridge_subs_from_recorder;
    use crate::test_utils::unshared_test_utils::SubsFactoryTestAddrLeaker;

    impl SubsFactory<BlockchainBridge, BlockchainBridgeSubs>
        for SubsFactoryTestAddrLeaker<BlockchainBridge>
    {
        fn make(&self, addr: &Addr<BlockchainBridge>) -> BlockchainBridgeSubs {
            self.send_leaker_msg_and_return_meaningless_subs(
                addr,
                make_blockchain_bridge_subs_from_recorder,
            )
        }
    }
}
