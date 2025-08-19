// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod db_access_objects;
pub mod db_big_integer;
pub mod financials;
pub mod payment_adjuster;
pub mod scanners;

#[cfg(test)]
pub mod test_utils;

use core::fmt::Debug;
use masq_lib::constants::{SCAN_ERROR, WEIS_IN_GWEI};
use std::cell::{Ref, RefCell};

use crate::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoError};
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDao;
use crate::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoError};
use crate::accountant::db_access_objects::utils::{
    remap_payable_accounts, remap_receivable_accounts, CustomQuery, DaoFactoryReal,
};
use crate::accountant::financials::visibility_restricted_module::{
    check_query_is_within_tech_limits, financials_entry_check,
};
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    BlockchainAgentWithContextMessage, QualifiedPayablesMessage,
};
use crate::accountant::scanners::{StartScanError, Scanners};
use crate::blockchain::blockchain_bridge::{BlockMarker, PendingPayableFingerprint, PendingPayableFingerprintSeeds, RetrieveTransactions};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError;
use crate::blockchain::blockchain_interface::data_structures::{
    BlockchainTransaction, ProcessedPayableFallible,
};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::DbInitializationConfig;
use crate::sub_lib::accountant::{AccountantSubs, DetailedScanType};
use crate::sub_lib::accountant::DaoFactories;
use crate::sub_lib::accountant::FinancialStatistics;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::ReportServicesConsumedMessage;
use crate::sub_lib::accountant::{MessageIdGenerator, MessageIdGeneratorReal};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::neighborhood::{ConfigChange, ConfigChangeMsg};
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::AsyncContext;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Recipient;
use itertools::Either;
use itertools::Itertools;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, UiFinancialsResponse, UiScanResponse};
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::messages::{
    QueryResults, UiFinancialStatistics, UiPayableAccount, UiReceivableAccount,
    UiScanRequest,
};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use std::any::type_name;
#[cfg(test)]
use std::default::Default;
use std::fmt::Display;
use std::ops::{Div, Mul};
use std::path::Path;
use std::rc::Rc;
use std::time::SystemTime;
use web3::types::H256;
use crate::accountant::scanners::pending_payable_scanner::utils::PendingPayableScanResult;
use crate::accountant::scanners::scan_schedulers::{PayableSequenceScanner, ScanRescheduleAfterEarlyStop, ScanSchedulers};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::OperationOutcome;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;

pub const CRASH_KEY: &str = "ACCOUNTANT";
pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

pub struct Accountant {
    consuming_wallet_opt: Option<Wallet>,
    earning_wallet: Wallet,
    payable_dao: Box<dyn PayableDao>,
    receivable_dao: Box<dyn ReceivableDao>,
    pending_payable_dao: Box<dyn PendingPayableDao>,
    crashable: bool,
    scanners: Scanners,
    scan_schedulers: ScanSchedulers,
    financial_statistics: Rc<RefCell<FinancialStatistics>>,
    outbound_payments_instructions_sub_opt: Option<Recipient<OutboundPaymentsInstructions>>,
    qualified_payables_sub_opt: Option<Recipient<QualifiedPayablesMessage>>,
    retrieve_transactions_sub_opt: Option<Recipient<RetrieveTransactions>>,
    request_transaction_receipts_sub_opt: Option<Recipient<RequestTransactionReceipts>>,
    report_inbound_payments_sub_opt: Option<Recipient<ReceivedPayments>>,
    report_sent_payables_sub_opt: Option<Recipient<SentPayables>>,
    ui_message_sub_opt: Option<Recipient<NodeToUiMessage>>,
    message_id_generator: Box<dyn MessageIdGenerator>,
    logger: Logger,
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct ResponseSkeleton {
    pub client_id: u64,
    pub context_id: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ReceivedPaymentsError {
    ExceededBlockScanLimit(u64),
    OtherRPCError(String),
}

#[derive(Debug, Message, PartialEq, Eq)]
pub struct ReceivedPayments {
    //TODO When we decide whether to delinquency-ban a debtor, we do so based on the age
    // of his debt. That age is calculated from the last time he made a payment. It would
    // be most accurate to draw that timestamp from the time the block containing the
    // payment was placed on the blockchain; however, we're actually drawing the timestamp
    // from the moment we discovered and accepted the payment, which is less accurate and
    // detects any upcoming delinquency later than the more accurate version would. Is this
    // a problem? Do we want to correct the timestamp? Discuss.
    pub timestamp: SystemTime,
    pub new_start_block: BlockMarker,
    pub transactions: Vec<BlockchainTransaction>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub fingerprints_with_receipts: Vec<(TransactionReceiptResult, PendingPayableFingerprint)>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, PartialEq, Clone)]
pub struct SentPayables {
    pub payment_procedure_result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, Default, PartialEq, Eq, Clone, Copy)]
pub struct ScanForPendingPayables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, Default, PartialEq, Eq, Clone, Copy)]
pub struct ScanForNewPayables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, Default, PartialEq, Eq, Clone, Copy)]
pub struct ScanForRetryPayables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, Default, PartialEq, Eq, Clone, Copy)]
pub struct ScanForReceivables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Clone, Message, PartialEq, Eq)]
pub struct ScanError {
    pub scan_type: DetailedScanType,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
    pub msg: String,
}

impl Handler<BindMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        self.handle_bind_message(msg);
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
    }
}

impl Handler<ConfigChangeMsg> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ConfigChangeMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_config_change_msg(msg);
    }
}

impl Handler<StartMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: StartMessage, ctx: &mut Self::Context) -> Self::Result {
        if self.scan_schedulers.automatic_scans_enabled {
            debug!(
                &self.logger,
                "Started with --scans on; starting database and blockchain scans"
            );
            ctx.notify(ScanForPendingPayables {
                response_skeleton_opt: None,
            });
            ctx.notify(ScanForReceivables {
                response_skeleton_opt: None,
            });
        } else {
            info!(
                &self.logger,
                "Started with --scans off; declining to begin database and blockchain scans"
            );
        }
    }
}

impl Handler<ScanForPendingPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPendingPayables, ctx: &mut Self::Context) -> Self::Result {
        // By now we know this is an automatic scan process. The scan may be or may not be
        // rescheduled. It depends on the findings. Any failed transaction will lead to the launch
        // of the RetryPayableScanner, which finishes, and the PendingPayablesScanner is scheduled
        // to run again. However, not from here.
        let response_skeleton_opt = msg.response_skeleton_opt;

        let scheduling_hint =
            self.handle_request_of_scan_for_pending_payable(response_skeleton_opt);

        match scheduling_hint {
            ScanRescheduleAfterEarlyStop::Schedule(ScanType::Payables) => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            ScanRescheduleAfterEarlyStop::Schedule(ScanType::PendingPayables) => self
                .scan_schedulers
                .pending_payable
                .schedule(ctx, &self.logger),
            ScanRescheduleAfterEarlyStop::Schedule(scan_type) => unreachable!(
                "Early stopped pending payable scan was suggested to be followed up \
                by the scan for {:?}, which is not supported though",
                scan_type
            ),
            ScanRescheduleAfterEarlyStop::DoNotSchedule => {
                trace!(
                    self.logger,
                    "No early rescheduling, as the pending payable scan did find results"
                );
            }
        }
    }
}

impl Handler<ScanForNewPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForNewPayables, ctx: &mut Self::Context) -> Self::Result {
        // We know this must be a scheduled scan, but are yet clueless where it's going to be
        // rescheduled. If no payable qualifies for a payment, we do it here right away. If some
        // transactions made it out, the next scheduling of this scanner is going to be decided by
        // the PendingPayableScanner whose job is to evaluate if it has seen every pending payable
        // complete. That's the moment when another run of the NewPayableScanner makes sense again.
        let response_skeleton = msg.response_skeleton_opt;

        let scheduling_hint = self.handle_request_of_scan_for_new_payable(response_skeleton);

        match scheduling_hint {
            ScanRescheduleAfterEarlyStop::Schedule(ScanType::Payables) => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            ScanRescheduleAfterEarlyStop::Schedule(other_scan_type) => unreachable!(
                "Early stopped new payable scan was suggested to be followed up by the scan \
                for {:?}, which is not supported though",
                other_scan_type
            ),
            ScanRescheduleAfterEarlyStop::DoNotSchedule => {
                trace!(
                    self.logger,
                    "No early rescheduling, as the new payable scan did find results"
                )
            }
        }
    }
}

impl Handler<ScanForRetryPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForRetryPayables, _ctx: &mut Self::Context) -> Self::Result {
        // RetryPayableScanner is scheduled only when the PendingPayableScanner finishes discovering
        // that there have been some failed payables. No place for that here.
        let response_skeleton = msg.response_skeleton_opt;
        self.handle_request_of_scan_for_retry_payable(response_skeleton);
    }
}

impl Handler<ScanForReceivables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForReceivables, ctx: &mut Self::Context) -> Self::Result {
        // By now we know it is an automatic scan. The ReceivableScanner is independent of other
        // scanners and rescheduled regularly, just here.
        self.handle_request_of_scan_for_receivable(msg.response_skeleton_opt);
        self.scan_schedulers.receivable.schedule(ctx, &self.logger);
    }
}

impl Handler<ReportTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReportTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        let response_skeleton_opt = msg.response_skeleton_opt;
        match self.scanners.finish_pending_payable_scan(msg, &self.logger) {
            PendingPayableScanResult::NoPendingPayablesLeft(ui_msg_opt) => {
                if let Some(node_to_ui_msg) = ui_msg_opt {
                    self.ui_message_sub_opt
                        .as_ref()
                        .expect("UIGateway is not bound")
                        .try_send(node_to_ui_msg)
                        .expect("UIGateway is dead");
                    // Externally triggered scan should never be allowed to spark a procedure that
                    // would bring over payables with fresh nonces. The job's done.
                } else {
                    self.scan_schedulers
                        .payable
                        .schedule_new_payable_scan(ctx, &self.logger)
                }
            }
            PendingPayableScanResult::PaymentRetryRequired => self
                .scan_schedulers
                .payable
                .schedule_retry_payable_scan(ctx, response_skeleton_opt, &self.logger),
        };
    }
}

impl Handler<BlockchainAgentWithContextMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: BlockchainAgentWithContextMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_payable_payment_setup(msg)
    }
}

impl Handler<SentPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: SentPayables, ctx: &mut Self::Context) -> Self::Result {
        let scan_result = self.scanners.finish_payable_scan(msg, &self.logger);

        match scan_result.ui_response_opt {
            None => match scan_result.result {
                OperationOutcome::NewPendingPayable => self
                    .scan_schedulers
                    .pending_payable
                    .schedule(ctx, &self.logger),
                OperationOutcome::Failure => self
                    .scan_schedulers
                    .payable
                    .schedule_new_payable_scan(ctx, &self.logger),
            },
            Some(node_to_ui_msg) => {
                self.ui_message_sub_opt
                    .as_ref()
                    .expect("UIGateway is not bound")
                    .try_send(node_to_ui_msg)
                    .expect("UIGateway is dead");

                // Externally triggered scans are not allowed to provoke an unwinding scan sequence
                // with intervals. The only exception is the PendingPayableScanner and retry-
                // payable scanner, which are ever meant to run in a tight tandem.
            }
        }
    }
}

impl Handler<ReceivedPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReceivedPayments, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(node_to_ui_msg) = self.scanners.finish_receivable_scan(msg, &self.logger) {
            self.ui_message_sub_opt
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(node_to_ui_msg)
                .expect("UIGateway is dead");
        }
    }
}

impl Handler<ScanError> for Accountant {
    type Result = ();

    fn handle(&mut self, scan_error: ScanError, ctx: &mut Self::Context) -> Self::Result {
        error!(self.logger, "Received ScanError: {:?}", scan_error);
        self.scanners
            .acknowledge_scan_error(&scan_error, &self.logger);

        match scan_error.scan_type {
            DetailedScanType::NewPayables => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            DetailedScanType::RetryPayables => self
                .scan_schedulers
                .payable
                .schedule_retry_payable_scan(ctx, None, &self.logger),
            DetailedScanType::PendingPayables => self
                .scan_schedulers
                .pending_payable
                .schedule(ctx, &self.logger),
            DetailedScanType::Receivables => {
                self.scan_schedulers.receivable.schedule(ctx, &self.logger)
            }
        }

        if let Some(response_skeleton) = scan_error.response_skeleton_opt {
            let error_msg = NodeToUiMessage {
                target: ClientId(response_skeleton.client_id),
                body: MessageBody {
                    opcode: "scan".to_string(),
                    path: MessagePath::Conversation(response_skeleton.context_id),
                    payload: Err((
                        SCAN_ERROR,
                        format!(
                            "{:?} scan failed: '{}'",
                            scan_error.scan_type, scan_error.msg
                        ),
                    )),
                },
            };
            error!(self.logger, "Sending UiScanResponse: {:?}", error_msg);
            self.ui_message_sub_opt
                .as_ref()
                .expect("UIGateway not bound")
                .try_send(error_msg)
                .expect("UiGateway is dead");
        }
    }
}

impl Handler<ReportRoutingServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_routing_service_provided_message(msg);
    }
}

impl Handler<ReportExitServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_exit_service_provided_message(msg);
    }
}

impl Handler<ReportServicesConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportServicesConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_services_consumed_message(msg);
    }
}

pub trait SkeletonOptHolder {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton>;
}

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct RequestTransactionReceipts {
    pub pending_payable_fingerprints: Vec<PendingPayableFingerprint>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RequestTransactionReceipts {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

impl Handler<PendingPayableFingerprintSeeds> for Accountant {
    type Result = ();
    fn handle(
        &mut self,
        msg: PendingPayableFingerprintSeeds,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_new_pending_payable_fingerprints(msg)
    }
}

impl Handler<NodeFromUiMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        if let Ok((request, context_id)) = UiFinancialsRequest::fmb(msg.body.clone()) {
            self.handle_financials(&request, client_id, context_id)
        } else if let Ok((body, context_id)) = UiScanRequest::fmb(msg.body.clone()) {
            self.handle_externally_triggered_scan(
                ctx,
                body.scan_type,
                ResponseSkeleton {
                    client_id,
                    context_id,
                },
            )
        } else {
            handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
        }
    }
}

impl Accountant {
    pub fn new(config: BootstrapperConfig, dao_factories: DaoFactories) -> Accountant {
        let payment_thresholds = config.payment_thresholds_opt.expectv("Payment thresholds");
        let scan_intervals = config.scan_intervals_opt.expectv("Scan Intervals");
        let earning_wallet = config.earning_wallet.clone();
        let financial_statistics = Rc::new(RefCell::new(FinancialStatistics::default()));
        let payable_dao = dao_factories.payable_dao_factory.make();
        let pending_payable_dao = dao_factories.pending_payable_dao_factory.make();
        let receivable_dao = dao_factories.receivable_dao_factory.make();
        let scan_schedulers = ScanSchedulers::new(scan_intervals, config.automatic_scans_enabled);
        let scanners = Scanners::new(
            dao_factories,
            Rc::new(payment_thresholds),
            config.when_pending_too_long_sec,
            Rc::clone(&financial_statistics),
        );

        Accountant {
            consuming_wallet_opt: config.consuming_wallet_opt.clone(),
            earning_wallet,
            payable_dao,
            receivable_dao,
            pending_payable_dao,
            scanners,
            crashable: config.crash_point == CrashPoint::Message,
            scan_schedulers,
            financial_statistics: Rc::clone(&financial_statistics),
            outbound_payments_instructions_sub_opt: None,
            qualified_payables_sub_opt: None,
            report_sent_payables_sub_opt: None,
            retrieve_transactions_sub_opt: None,
            report_inbound_payments_sub_opt: None,
            request_transaction_receipts_sub_opt: None,
            ui_message_sub_opt: None,
            message_id_generator: Box::new(MessageIdGeneratorReal::default()),
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: recipient!(addr, BindMessage),
            config_change_msg_sub: recipient!(addr, ConfigChangeMsg),
            start: recipient!(addr, StartMessage),
            report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
            report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
            report_services_consumed: recipient!(addr, ReportServicesConsumedMessage),
            report_payable_payments_setup: recipient!(addr, BlockchainAgentWithContextMessage),
            report_inbound_payments: recipient!(addr, ReceivedPayments),
            init_pending_payable_fingerprints: recipient!(addr, PendingPayableFingerprintSeeds),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayables),
            scan_errors: recipient!(addr, ScanError),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, DbInitializationConfig::panic_on_migration())
    }

    fn record_service_provided(
        &self,
        service_rate: u64,
        byte_rate: u64,
        timestamp: SystemTime,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate as u128 * (payload_size as u128);
        let total_charge = service_rate as u128 + byte_charge;
        if !self.our_wallet(wallet) {
            match self.receivable_dao
                .as_ref()
                .more_money_receivable(timestamp, wallet, total_charge) {
                Ok(_) => (),
                Err(ReceivableDaoError::SignConversion(_)) => error!(
                    self.logger,
                    "Overflow error recording service provided for {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(e) => panic!("Recording services provided for {} but has hit fatal database error: {:?}", wallet, e)
            };
        } else {
            warning!(
                self.logger,
                "Declining to record a receivable against our wallet {} for service we provided",
                wallet
            );
        }
    }

    fn record_service_consumed(
        &self,
        service_rate: u64,
        byte_rate: u64,
        timestamp: SystemTime,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate as u128 * (payload_size as u128);
        let total_charge = service_rate as u128 + byte_charge;
        if !self.our_wallet(wallet) {
            match self.payable_dao
                .as_ref()
                .more_money_payable(timestamp, wallet, total_charge) {
                Ok(_) => (),
                Err(PayableDaoError::SignConversion(_)) => error!(
                    self.logger,
                    "Overflow error recording consumed services from {}: total charge {}, service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    total_charge,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(e) => panic!("Recording services consumed from {} but has hit fatal database error: {:?}", wallet, e)
            };
        } else {
            warning!(
                self.logger,
                "Declining to record a payable against our wallet {} for service we provided",
                wallet
            );
        }
    }

    fn our_wallet(&self, wallet: &Wallet) -> bool {
        match &self.consuming_wallet_opt {
            Some(ref consuming) if consuming.address() == wallet.address() => true,
            _ => wallet.address() == self.earning_wallet.address(),
        }
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        self.outbound_payments_instructions_sub_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .outbound_payments_instructions,
        );
        self.retrieve_transactions_sub_opt =
            Some(msg.peer_actors.blockchain_bridge.retrieve_transactions);
        self.report_inbound_payments_sub_opt =
            Some(msg.peer_actors.accountant.report_inbound_payments);
        self.qualified_payables_sub_opt =
            Some(msg.peer_actors.blockchain_bridge.qualified_payables);
        self.report_sent_payables_sub_opt = Some(msg.peer_actors.accountant.report_sent_payments);
        self.ui_message_sub_opt = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
        self.request_transaction_receipts_sub_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .request_transaction_receipts,
        );
        info!(self.logger, "Accountant bound");
    }

    fn handle_config_change_msg(&mut self, msg: ConfigChangeMsg) {
        if let ConfigChange::UpdateWallets(wallet_pair) = msg.change {
            if self.earning_wallet != wallet_pair.earning_wallet {
                info!(
                    self.logger,
                    "Earning Wallet has been updated: {}", wallet_pair.earning_wallet
                );
                self.earning_wallet = wallet_pair.earning_wallet;
            }
            if self.consuming_wallet_opt != Some(wallet_pair.consuming_wallet.clone()) {
                info!(
                    self.logger,
                    "Consuming Wallet has been updated: {}", wallet_pair.consuming_wallet
                );
                self.consuming_wallet_opt = Some(wallet_pair.consuming_wallet);
            }
        } else {
            trace!(self.logger, "Ignored irrelevant message: {:?}", msg);
        }
    }

    fn handle_report_routing_service_provided_message(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
    ) {
        debug!(
            self.logger,
            "Charging routing of {} bytes to wallet {}", msg.payload_size, msg.paying_wallet
        );
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.timestamp,
            msg.payload_size,
            &msg.paying_wallet,
        );
    }

    fn handle_report_exit_service_provided_message(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
    ) {
        debug!(
            self.logger,
            "Charging exit service for {} bytes to wallet {} at {} per service and {} per byte",
            msg.payload_size,
            msg.paying_wallet,
            msg.service_rate,
            msg.byte_rate
        );
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.timestamp,
            msg.payload_size,
            &msg.paying_wallet,
        );
    }

    fn msg_id(&self) -> u32 {
        if self.logger.debug_enabled() {
            self.message_id_generator.id()
        } else {
            0
        }
    }

    fn handle_report_services_consumed_message(&mut self, msg: ReportServicesConsumedMessage) {
        let msg_id = self.msg_id();
        debug!(
            self.logger,
            "MsgId {}: Accruing debt to {} for consuming {} exited bytes",
            msg_id,
            msg.exit.earning_wallet,
            msg.exit.payload_size
        );
        self.record_service_consumed(
            msg.exit.service_rate,
            msg.exit.byte_rate,
            msg.timestamp,
            msg.exit.payload_size,
            &msg.exit.earning_wallet,
        );
        msg.routing.iter().for_each(|routing_service| {
            debug!(
                self.logger,
                "MsgId {}: Accruing debt to {} for consuming {} routed bytes",
                msg_id,
                routing_service.earning_wallet,
                msg.routing_payload_size
            );
            self.record_service_consumed(
                routing_service.service_rate,
                routing_service.byte_rate,
                msg.timestamp,
                msg.routing_payload_size,
                &routing_service.earning_wallet,
            );
        })
    }

    fn handle_payable_payment_setup(&mut self, msg: BlockchainAgentWithContextMessage) {
        let blockchain_bridge_instructions = match self
            .scanners
            .try_skipping_payable_adjustment(msg, &self.logger)
        {
            Ok(Either::Left(finalized_msg)) => finalized_msg,
            Ok(Either::Right(unaccepted_msg)) => {
                //TODO we will eventually query info from Neighborhood before the adjustment, according to GH-699
                self.scanners
                    .perform_payable_adjustment(unaccepted_msg, &self.logger)
            }
            Err(_e) => todo!("be completed by GH-711"),
        };
        self.outbound_payments_instructions_sub_opt
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .try_send(blockchain_bridge_instructions)
            .expect("BlockchainBridge is dead")
        //TODO implement send point for ScanError; be completed by GH-711
    }

    fn handle_financials(&self, msg: &UiFinancialsRequest, client_id: u64, context_id: u64) {
        let body: MessageBody = self.compute_financials(msg, context_id);
        self.ui_message_sub_opt
            .as_ref()
            .expect("UiGateway not bound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body,
            })
            .expect("UiGateway is dead");
    }

    fn compute_financials(&self, msg: &UiFinancialsRequest, context_id: u64) -> MessageBody {
        if let Err(message_body) = financials_entry_check(msg, context_id) {
            return message_body;
        };
        let stats_opt = self.process_stats(msg);
        let query_results_opt = match self.process_queries_of_records(msg, context_id) {
            Ok(results_opt) => results_opt,
            Err(message_body) => return message_body,
        };
        UiFinancialsResponse {
            stats_opt,
            query_results_opt,
        }
        .tmb(context_id)
    }

    fn request_payable_accounts_by_specific_mode(
        &self,
        mode: CustomQuery<u64>,
    ) -> Option<Vec<UiPayableAccount>> {
        self.payable_dao
            .custom_query(mode)
            .map(remap_payable_accounts)
    }

    fn request_receivable_accounts_by_specific_mode(
        &self,
        mode: CustomQuery<i64>,
    ) -> Option<Vec<UiReceivableAccount>> {
        self.receivable_dao
            .custom_query(mode)
            .map(remap_receivable_accounts)
    }

    fn process_stats(&self, msg: &UiFinancialsRequest) -> Option<UiFinancialStatistics> {
        if msg.stats_required {
            let financial_statistics = self.financial_statistics();
            Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: wei_to_gwei(self.payable_dao.total()),
                total_paid_payable_gwei: wei_to_gwei(financial_statistics.total_paid_payable_wei),
                total_unpaid_receivable_gwei: wei_to_gwei(self.receivable_dao.total()),
                total_paid_receivable_gwei: wei_to_gwei(
                    financial_statistics.total_paid_receivable_wei,
                ),
            })
        } else {
            None
        }
    }

    fn process_top_records_query(&self, msg: &UiFinancialsRequest) -> Option<QueryResults> {
        msg.top_records_opt.map(|config| {
            let payable = self
                .request_payable_accounts_by_specific_mode(config.into())
                .unwrap_or_default();
            let receivable = self
                .request_receivable_accounts_by_specific_mode(config.into())
                .unwrap_or_default();

            QueryResults {
                payable_opt: Some(payable),
                receivable_opt: Some(receivable),
            }
        })
    }

    fn process_custom_queries(
        &self,
        msg: &UiFinancialsRequest,
        context_id: u64,
    ) -> Result<Option<QueryResults>, MessageBody> {
        Ok(match msg.custom_queries_opt.as_ref() {
            Some(specs) => {
                let payable_opt = if let Some(query_specs) = specs.payable_opt.as_ref() {
                    let query = CustomQuery::from(query_specs);
                    check_query_is_within_tech_limits(&query, "payable", context_id)?;
                    self.request_payable_accounts_by_specific_mode(query)
                } else {
                    None
                };
                let receivable_opt = if let Some(query_specs) = specs.receivable_opt.as_ref() {
                    let query = CustomQuery::from(query_specs);
                    check_query_is_within_tech_limits(&query, "receivable", context_id)?;
                    self.request_receivable_accounts_by_specific_mode(query)
                } else {
                    None
                };

                Some(QueryResults {
                    payable_opt,
                    receivable_opt,
                })
            }
            None => None,
        })
    }

    fn process_queries_of_records(
        &self,
        msg: &UiFinancialsRequest,
        context_id: u64,
    ) -> Result<Option<QueryResults>, MessageBody> {
        let top_records_opt = self.process_top_records_query(msg);
        let custom_query_records_opt = match self.process_custom_queries(msg, context_id) {
            Ok(query_results) => query_results,
            Err(message_body) => return Err(message_body),
        };
        match vec![top_records_opt, custom_query_records_opt]
            .into_iter()
            .find(|results| results.is_some())
        {
            Some(results) => Ok(results),
            None => Ok(None),
        }
    }

    fn handle_request_of_scan_for_new_payable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> ScanRescheduleAfterEarlyStop {
        let result: Result<QualifiedPayablesMessage, StartScanError> =
            match self.consuming_wallet_opt.as_ref() {
                Some(consuming_wallet) => self.scanners.start_new_payable_scan_guarded(
                    consuming_wallet,
                    SystemTime::now(),
                    response_skeleton_opt,
                    &self.logger,
                    self.scan_schedulers.automatic_scans_enabled,
                ),
                None => Err(StartScanError::NoConsumingWalletFound),
            };

        match result {
            Ok(scan_message) => {
                self.qualified_payables_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message)
                    .expect("BlockchainBridge is dead");
                ScanRescheduleAfterEarlyStop::DoNotSchedule
            }
            Err(e) => self.handle_start_scan_error_and_prevent_scan_stall_point(
                PayableSequenceScanner::NewPayables,
                e,
                response_skeleton_opt,
            ),
        }
    }

    fn handle_request_of_scan_for_retry_payable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        let result: Result<QualifiedPayablesMessage, StartScanError> =
            match self.consuming_wallet_opt.as_ref() {
                Some(consuming_wallet) => self.scanners.start_retry_payable_scan_guarded(
                    consuming_wallet,
                    SystemTime::now(),
                    response_skeleton_opt,
                    &self.logger,
                ),
                None => Err(StartScanError::NoConsumingWalletFound),
            };

        match result {
            Ok(scan_message) => {
                self.qualified_payables_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message)
                    .expect("BlockchainBridge is dead");
            }
            Err(e) => {
                let _ = self.handle_start_scan_error_and_prevent_scan_stall_point(
                    PayableSequenceScanner::RetryPayables,
                    e,
                    response_skeleton_opt,
                );
            }
        }
    }

    fn handle_request_of_scan_for_pending_payable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> ScanRescheduleAfterEarlyStop {
        let result: Result<RequestTransactionReceipts, StartScanError> =
            match self.consuming_wallet_opt.as_ref() {
                Some(consuming_wallet) => self.scanners.start_pending_payable_scan_guarded(
                    consuming_wallet, // This argument is not used and is therefore irrelevant
                    SystemTime::now(),
                    response_skeleton_opt,
                    &self.logger,
                    self.scan_schedulers.automatic_scans_enabled,
                ),
                None => Err(StartScanError::NoConsumingWalletFound),
            };

        let hint: ScanRescheduleAfterEarlyStop = match result {
            Ok(scan_message) => {
                self.request_transaction_receipts_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message)
                    .expect("BlockchainBridge is dead");
                ScanRescheduleAfterEarlyStop::DoNotSchedule
            }
            Err(e) => {
                let initial_pending_payable_scan = self.scanners.initial_pending_payable_scan();
                self.handle_start_scan_error_and_prevent_scan_stall_point(
                    PayableSequenceScanner::PendingPayables {
                        initial_pending_payable_scan,
                    },
                    e,
                    response_skeleton_opt,
                )
            }
        };

        if self.scanners.initial_pending_payable_scan() {
            self.scanners.unset_initial_pending_payable_scan()
        }

        hint
    }

    fn handle_start_scan_error_and_prevent_scan_stall_point(
        &self,
        scanner: PayableSequenceScanner,
        e: StartScanError,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> ScanRescheduleAfterEarlyStop {
        let is_externally_triggered = response_skeleton_opt.is_some();

        e.log_error(&self.logger, scanner.into(), is_externally_triggered);

        if let Some(skeleton) = response_skeleton_opt {
            self.ui_message_sub_opt
                .as_ref()
                .expect("UiGateway is unbound")
                .try_send(NodeToUiMessage {
                    target: MessageTarget::ClientId(skeleton.client_id),
                    body: UiScanResponse {}.tmb(skeleton.context_id),
                })
                .expect("UiGateway is dead");
        };

        self.scan_schedulers
            .reschedule_on_error_resolver
            .resolve_rescheduling_on_error(scanner, &e, is_externally_triggered, &self.logger)
    }

    fn handle_request_of_scan_for_receivable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        let result: Result<RetrieveTransactions, StartScanError> =
            self.scanners.start_receivable_scan_guarded(
                &self.earning_wallet,
                SystemTime::now(),
                response_skeleton_opt,
                &self.logger,
                self.scan_schedulers.automatic_scans_enabled,
            );

        match result {
            Ok(scan_message) => self
                .retrieve_transactions_sub_opt
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(scan_message)
                .expect("BlockchainBridge is dead"),
            Err(e) => {
                e.log_error(
                    &self.logger,
                    ScanType::Receivables,
                    response_skeleton_opt.is_some(),
                );

                if let Some(skeleton) = response_skeleton_opt {
                    self.ui_message_sub_opt
                        .as_ref()
                        .expect("UiGateway is unbound")
                        .try_send(NodeToUiMessage {
                            target: MessageTarget::ClientId(skeleton.client_id),
                            body: UiScanResponse {}.tmb(skeleton.context_id),
                        })
                        .expect("UiGateway is dead");
                };
            }
        }
    }

    fn handle_externally_triggered_scan(
        &mut self,
        _ctx: &mut Context<Accountant>,
        scan_type: ScanType,
        response_skeleton: ResponseSkeleton,
    ) {
        // Each of these scans runs only once per request, they do not go on into a sequence under
        // any circumstances
        match scan_type {
            ScanType::Payables => {
                self.handle_request_of_scan_for_new_payable(Some(response_skeleton));
            }
            ScanType::PendingPayables => {
                self.handle_request_of_scan_for_pending_payable(Some(response_skeleton));
            }
            ScanType::Receivables => {
                self.handle_request_of_scan_for_receivable(Some(response_skeleton));
            }
        }
    }

    fn handle_new_pending_payable_fingerprints(&self, msg: PendingPayableFingerprintSeeds) {
        fn serialize_hashes(fingerprints_data: &[HashAndAmount]) -> String {
            comma_joined_stringifiable(fingerprints_data, |hash_and_amount| {
                format!("{:?}", hash_and_amount.hash)
            })
        }
        match self
            .pending_payable_dao
            .insert_new_fingerprints(&msg.hashes_and_balances, msg.batch_wide_timestamp)
        {
            Ok(_) => debug!(
                self.logger,
                "Saved new pending payable fingerprints for: {}",
                serialize_hashes(&msg.hashes_and_balances)
            ),
            Err(e) => error!(
                self.logger,
                "Failed to process new pending payable fingerprints due to '{:?}', \
                 disabling the automated confirmation for all these transactions: {}",
                e,
                serialize_hashes(&msg.hashes_and_balances)
            ),
        }
    }

    fn financial_statistics(&self) -> Ref<'_, FinancialStatistics> {
        self.financial_statistics.borrow()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PendingPayableId {
    pub rowid: u64,
    pub hash: H256,
}

impl PendingPayableId {
    pub fn new(rowid: u64, hash: H256) -> Self {
        Self { rowid, hash }
    }

    fn rowids(ids: &[Self]) -> Vec<u64> {
        ids.iter().map(|id| id.rowid).collect()
    }

    fn serialize_hashes_to_string(ids: &[Self]) -> String {
        comma_joined_stringifiable(ids, |id| format!("{:?}", id.hash))
    }
}

impl From<PendingPayableFingerprint> for PendingPayableId {
    fn from(pending_payable_fingerprint: PendingPayableFingerprint) -> Self {
        Self {
            hash: pending_payable_fingerprint.hash,
            rowid: pending_payable_fingerprint.rowid,
        }
    }
}

pub fn comma_joined_stringifiable<T, F>(collection: &[T], stringify: F) -> String
where
    F: FnMut(&T) -> String,
{
    collection.iter().map(stringify).join(", ")
}

pub fn sign_conversion<T: Copy, S: TryFrom<T>>(num: T) -> Result<S, T> {
    S::try_from(num).map_err(|_| num)
}

pub fn politely_checked_conversion<T: Copy + Display, S: TryFrom<T>>(num: T) -> Result<S, String> {
    sign_conversion(num).map_err(|num| {
        format!(
            "Overflow detected with {}: cannot be converted from {} to {}",
            num,
            type_name::<T>(),
            type_name::<S>()
        )
    })
}

#[track_caller]
pub fn checked_conversion<T: Copy + Display, S: TryFrom<T>>(num: T) -> S {
    politely_checked_conversion(num).unwrap_or_else(|msg| panic!("{}", msg))
}

pub fn gwei_to_wei<T: Mul<Output = T> + From<u32> + From<S>, S>(gwei: S) -> T {
    (T::from(gwei)).mul(T::from(WEIS_IN_GWEI as u32))
}

pub fn wei_to_gwei<T: TryFrom<S>, S: Display + Copy + Div<Output = S> + From<u32>>(wei: S) -> T {
    checked_conversion::<S, T>(wei.div(S::from(WEIS_IN_GWEI as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::payable_dao::{
        PayableAccount, PayableDaoError, PayableDaoFactory,
    };
    use crate::accountant::db_access_objects::pending_payable_dao::{
        PendingPayable, PendingPayableDaoError, TransactionHashes,
    };
    use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp, CustomQuery};
    use crate::accountant::payment_adjuster::Adjustment;
    use crate::accountant::scanners::payable_scanner_extension::test_utils::BlockchainAgentMock;
    use crate::accountant::scanners::test_utils::{MarkScanner, NewPayableScanDynIntervalComputerMock, ReplacementType, RescheduleScanOnErrorResolverMock, ScannerMock, ScannerReplacement};
    use crate::accountant::scanners::{StartScanError};
    use crate::accountant::test_utils::DaoWithDestination::{
        ForAccountantBody, ForPayableScanner, ForPendingPayableScanner, ForReceivableScanner,
    };
    use crate::accountant::test_utils::{bc_from_earning_wallet, bc_from_wallets, make_payable_account, make_pending_payable_fingerprint, make_qualified_and_unqualified_payables, make_unpriced_qualified_payables_for_retry_mode, make_priced_qualified_payables, BannedDaoFactoryMock, ConfigDaoFactoryMock, MessageIdGeneratorMock, PayableDaoFactoryMock, PayableDaoMock, PayableScannerBuilder, PaymentAdjusterMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock, ReceivableDaoFactoryMock, ReceivableDaoMock};
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::Accountant;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
    use crate::blockchain::test_utils::{
        make_tx_hash
    };
    use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::db_config::config_dao::ConfigDaoRecord;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::{match_lazily_every_type_id, setup_for_counter_msg_triggered_via_type_id};
    use crate::sub_lib::accountant::{
        ExitServiceConsumed, PaymentThresholds, RoutingServiceConsumed, ScanIntervals,
        DEFAULT_EARNING_WALLET, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
    use crate::sub_lib::neighborhood::ConfigChange;
    use crate::sub_lib::neighborhood::{Hops, WalletPair};
    use crate::test_utils::recorder::{make_recorder, PeerActorsBuilder, SetUpCounterMsgs};
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder_stop_conditions::{MsgIdentification, StopConditions};
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::notify_handlers::{NotifyHandleMock, NotifyLaterHandleMock};
    use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, make_bc_with_defaults,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::{System};
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use log::{Level};
    use masq_lib::constants::{
        REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS, REQUEST_WITH_NO_VALUES, SCAN_ERROR,
        VALUE_EXCEEDS_ALLOWED_LIMIT,
    };
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::messages::{
        CustomQueries, RangeQuery, TopRecordsConfig, UiFinancialStatistics,
        UiMessageError, UiPayableAccount, UiReceivableAccount, UiScanRequest, UiScanResponse,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};
    use std::any::{TypeId};
    use std::ops::{Sub};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};
    use std::vec;
    use crate::accountant::scanners::payable_scanner_extension::msgs::UnpricedQualifiedPayables;
    use crate::accountant::scanners::scan_schedulers::{NewPayableScanDynIntervalComputer, NewPayableScanDynIntervalComputerReal};
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{OperationOutcome, PayableScanResult};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock, TxReceipt, TxStatus};
    use crate::test_utils::recorder_counter_msgs::SingleTypeCounterMsgSetup;

    impl Handler<AssertionsMessage<Accountant>> for Accountant {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<Accountant>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "ACCOUNTANT");
        assert_eq!(DEFAULT_PENDING_TOO_LONG_SEC, 21_600);
    }

    #[test]
    fn new_calls_factories_properly() {
        let config = make_bc_with_defaults();
        let payable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_params(&payable_dao_factory_params_arc)
            .make_result(PayableDaoMock::new()) // For Accountant
            .make_result(PayableDaoMock::new()) // For Payable Scanner
            .make_result(PayableDaoMock::new()); // For PendingPayable Scanner
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new()
            .make_params(&pending_payable_dao_factory_params_arc)
            .make_result(PendingPayableDaoMock::new()) // For Accountant
            .make_result(PendingPayableDaoMock::new()) // For Payable Scanner
            .make_result(PendingPayableDaoMock::new()); // For PendingPayable Scanner
        let receivable_dao_factory = ReceivableDaoFactoryMock::new()
            .make_params(&receivable_dao_factory_params_arc)
            .make_result(ReceivableDaoMock::new()) // For Accountant
            .make_result(ReceivableDaoMock::new()); // For Receivable Scanner
        let banned_dao_factory = BannedDaoFactoryMock::new()
            .make_params(&banned_dao_factory_params_arc)
            .make_result(BannedDaoMock::new()); // For Receivable Scanner
        let config_dao_factory = ConfigDaoFactoryMock::new()
            .make_params(&config_dao_factory_params_arc)
            .make_result(ConfigDaoMock::new()); // For receivable scanner

        let _ = Accountant::new(
            config,
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
                config_dao_factory: Box::new(config_dao_factory),
            },
        );

        assert_eq!(
            *payable_dao_factory_params_arc.lock().unwrap(),
            vec![(), (), ()]
        );
        assert_eq!(
            *pending_payable_dao_factory_params_arc.lock().unwrap(),
            vec![(), (), ()]
        );
        assert_eq!(
            *receivable_dao_factory_params_arc.lock().unwrap(),
            vec![(), ()]
        );
        assert_eq!(*banned_dao_factory_params_arc.lock().unwrap(), vec![()]);
        assert_eq!(*config_dao_factory_params_arc.lock().unwrap(), vec![()]);
    }

    #[test]
    fn accountant_have_proper_defaulted_values() {
        let bootstrapper_config = make_bc_with_defaults();
        let payable_dao_factory = Box::new(
            PayableDaoFactoryMock::new()
                .make_result(PayableDaoMock::new()) // For Accountant
                .make_result(PayableDaoMock::new()) // For Payable Scanner
                .make_result(PayableDaoMock::new()), // For PendingPayable Scanner
        );
        let pending_payable_dao_factory = Box::new(
            PendingPayableDaoFactoryMock::new()
                .make_result(PendingPayableDaoMock::new()) // For Accountant
                .make_result(PendingPayableDaoMock::new()) // For Payable Scanner
                .make_result(PendingPayableDaoMock::new()), // For PendingPayable Scanner
        );
        let receivable_dao_factory = Box::new(
            ReceivableDaoFactoryMock::new()
                .make_result(ReceivableDaoMock::new()) // For Accountant
                .make_result(ReceivableDaoMock::new()), // For Scanner
        );
        let banned_dao_factory =
            Box::new(BannedDaoFactoryMock::new().make_result(BannedDaoMock::new()));
        let config_dao_factory =
            Box::new(ConfigDaoFactoryMock::new().make_result(ConfigDaoMock::new()));

        let result = Accountant::new(
            bootstrapper_config,
            DaoFactories {
                payable_dao_factory,
                pending_payable_dao_factory,
                receivable_dao_factory,
                banned_dao_factory,
                config_dao_factory,
            },
        );

        let financial_statistics = result.financial_statistics().clone();
        let default_scan_intervals = ScanIntervals::default();
        assert_eq!(
            result.scan_schedulers.payable.new_payable_interval,
            default_scan_intervals.payable_scan_interval
        );
        assert_eq!(
            result.scan_schedulers.pending_payable.interval,
            default_scan_intervals.pending_payable_scan_interval,
        );
        assert_eq!(
            result.scan_schedulers.receivable.interval,
            default_scan_intervals.receivable_scan_interval,
        );
        assert_eq!(result.scan_schedulers.automatic_scans_enabled, true);
        assert_eq!(
            result.scanners.aware_of_unresolved_pending_payables(),
            false
        );
        assert_eq!(result.consuming_wallet_opt, None);
        assert_eq!(result.earning_wallet, *DEFAULT_EARNING_WALLET);
        result
            .message_id_generator
            .as_any()
            .downcast_ref::<MessageIdGeneratorReal>()
            .unwrap();
        assert_eq!(result.crashable, false);
        assert_eq!(financial_statistics.total_paid_receivable_wei, 0);
        assert_eq!(financial_statistics.total_paid_payable_wei, 0);
    }

    #[test]
    fn accountant_handles_config_change_msg() {
        assert_handling_of_config_change_msg(
            ConfigChangeMsg {
                change: ConfigChange::UpdateWallets(WalletPair {
                    consuming_wallet: make_paying_wallet(b"new_consuming_wallet"),
                    earning_wallet: make_wallet("new_earning_wallet"),
                }),
            },
            |subject: &Accountant| {
                assert_eq!(
                    subject.consuming_wallet_opt,
                    Some(make_paying_wallet(b"new_consuming_wallet"))
                );
                assert_eq!(subject.earning_wallet, make_wallet("new_earning_wallet"));
                let _ = TestLogHandler::new().assert_logs_contain_in_order(
                    vec![
                        "INFO: ConfigChange: Earning Wallet has been updated: 0x00006e65775f6561726e696e675f77616c6c6574",
                        "INFO: ConfigChange: Consuming Wallet has been updated: 0xfa133bbf90bce093fa2e7caa6da68054af66793e",
                    ]
                );
            },
        );
        assert_handling_of_config_change_msg(
            ConfigChangeMsg {
                change: ConfigChange::UpdatePassword("new password".to_string()),
            },
            |_subject: &Accountant| {
                let _ = TestLogHandler::new().exists_log_containing(
                    "TRACE: ConfigChange: Ignored irrelevant message: \
                    ConfigChangeMsg { change: UpdatePassword(\"new password\") }",
                );
            },
        );
        assert_handling_of_config_change_msg(
            ConfigChangeMsg {
                change: ConfigChange::UpdateMinHops(Hops::FourHops),
            },
            |_subject: &Accountant| {
                let _ = TestLogHandler::new().exists_log_containing(
                    "TRACE: ConfigChange: Ignored irrelevant message: \
                    ConfigChangeMsg { change: UpdateMinHops(FourHops) }",
                );
            },
        );
    }

    fn assert_handling_of_config_change_msg<A>(msg: ConfigChangeMsg, assertions: A)
    where
        A: FnOnce(&Accountant),
    {
        init_test_logging();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(make_bc_with_defaults())
            .build();
        subject.logger = Logger::new("ConfigChange");

        subject.handle_config_change_msg(msg);

        assertions(&subject);
    }

    #[test]
    fn externally_triggered_scan_payables_request() {
        let config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        let consuming_wallet = make_paying_wallet(b"consuming");
        let payable_account = PayableAccount {
            wallet: make_wallet("wallet"),
            balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1),
            last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(
                (DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 1) as u64,
            )),
            pending_payable_opt: None,
        };
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(vec![payable_account.clone()]);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .bootstrapper_config(config)
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(QualifiedPayablesMessage));
        let blockchain_bridge_addr = blockchain_bridge.start();
        // Important
        subject.scan_schedulers.automatic_scans_enabled = false;
        subject.qualified_payables_sub_opt = Some(blockchain_bridge_addr.recipient());
        // Making sure we would get a panic if another scan was scheduled
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_interval = Duration::from_secs(100);
        let subject_addr = subject.start();
        let system = System::new("test");
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::Payables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recording.get_record::<QualifiedPayablesMessage>(0),
            &QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables::from(vec![payable_account]),
                consuming_wallet,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                })
            }
        );
    }

    #[test]
    fn sent_payable_with_response_skeleton_sends_scan_response_to_ui_gateway() {
        let config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(1, make_tx_hash(123))],
                no_rowid_results: vec![],
            });
        let payable_dao = PayableDaoMock::default().mark_pending_payables_rowids_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .pending_payable_daos(vec![ForPayableScanner(pending_payable_dao)])
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .bootstrapper_config(config)
            .build();
        // Making sure we would get a panic if another scan was scheduled
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![ProcessedPayableFallible::Correct(PendingPayable {
                recipient_wallet: make_wallet("blah"),
                hash: make_tx_hash(123),
            })]),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(sent_payable).unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: ClientId(1234),
                body: UiScanResponse {}.tmb(4321),
            }
        );
    }

    #[test]
    fn qualified_payables_under_our_money_limit_are_forwarded_to_blockchain_bridge_right_away() {
        // The numbers in balances don't do real math, they don't need to match either the condition for
        // the payment adjustment or the actual values that come from the payable size reducing algorithm;
        // all that is mocked in this test
        init_test_logging();
        let test_name = "qualified_payables_under_our_money_limit_are_forwarded_to_blockchain_bridge_right_away";
        let is_adjustment_required_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let instructions_recipient = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(OutboundPaymentsInstructions))
            .start()
            .recipient();
        let mut subject = AccountantBuilder::default().build();
        let payment_adjuster = PaymentAdjusterMock::default()
            .is_adjustment_required_params(&is_adjustment_required_params_arc)
            .is_adjustment_required_result(Ok(None));
        let payable_scanner = PayableScannerBuilder::new()
            .payment_adjuster(payment_adjuster)
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Real(
                payable_scanner,
            )));
        subject.outbound_payments_instructions_sub_opt = Some(instructions_recipient);
        subject.logger = Logger::new(test_name);
        let subject_addr = subject.start();
        let account_1 = make_payable_account(44_444);
        let account_2 = make_payable_account(333_333);
        let system = System::new("test");
        let agent_id_stamp = ArbitraryIdStamp::new();
        let agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp);
        let qualified_payables = make_priced_qualified_payables(vec![
            (account_1, 1_000_000_001),
            (account_2, 1_000_000_002),
        ]);
        let msg = BlockchainAgentWithContextMessage {
            qualified_payables: qualified_payables.clone(),
            agent: Box::new(agent),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject_addr.try_send(msg).unwrap();

        system.run();
        let mut is_adjustment_required_params = is_adjustment_required_params_arc.lock().unwrap();
        let (blockchain_agent_with_context_msg_actual, logger_clone) =
            is_adjustment_required_params.remove(0);
        assert_eq!(
            blockchain_agent_with_context_msg_actual.qualified_payables,
            qualified_payables.clone()
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            })
        );
        assert_eq!(
            blockchain_agent_with_context_msg_actual
                .agent
                .arbitrary_id_stamp(),
            agent_id_stamp
        );
        assert!(is_adjustment_required_params.is_empty());
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let payments_instructions =
            blockchain_bridge_recording.get_record::<OutboundPaymentsInstructions>(0);
        assert_eq!(
            payments_instructions.affordable_accounts,
            qualified_payables
        );
        assert_eq!(
            payments_instructions.response_skeleton_opt,
            Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            })
        );
        assert_eq!(
            payments_instructions.agent.arbitrary_id_stamp(),
            agent_id_stamp
        );
        assert_eq!(blockchain_bridge_recording.len(), 1);
        assert_using_the_same_logger(&logger_clone, test_name, None)
        // The adjust_payments() function doesn't require prepared results, indicating it shouldn't
        // have been reached during the test, or it would have caused a panic.
    }

    fn assert_using_the_same_logger(
        logger_clone: &Logger,
        test_name: &str,
        differentiation_opt: Option<&str>,
    ) {
        let log_handler = TestLogHandler::default();
        let experiment_msg = format!("DEBUG: {test_name}: hello world: {:?}", differentiation_opt);
        log_handler.exists_no_log_containing(&experiment_msg);

        debug!(logger_clone, "hello world: {:?}", differentiation_opt);

        log_handler.exists_log_containing(&experiment_msg);
    }

    #[test]
    fn qualified_payables_over_masq_balance_are_adjusted_before_sending_to_blockchain_bridge() {
        // The numbers in balances don't do real math, they don't need to match either the condition for
        // the payment adjustment or the actual values that come from the payable size reducing algorithm;
        // all that is mocked in this test
        init_test_logging();
        let test_name =
            "qualified_payables_over_masq_balance_are_adjusted_before_sending_to_blockchain_bridge";
        let adjust_payments_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let report_recipient = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(OutboundPaymentsInstructions))
            .start()
            .recipient();
        let mut subject = AccountantBuilder::default().build();
        let unadjusted_account_1 = make_payable_account(111_111);
        let unadjusted_account_2 = make_payable_account(222_222);
        let adjusted_account_1 = PayableAccount {
            balance_wei: gwei_to_wei(55_550_u64),
            ..unadjusted_account_1.clone()
        };
        let adjusted_account_2 = PayableAccount {
            balance_wei: gwei_to_wei(100_000_u64),
            ..unadjusted_account_2.clone()
        };
        let response_skeleton = ResponseSkeleton {
            client_id: 12,
            context_id: 55,
        };
        let agent_id_stamp_first_phase = ArbitraryIdStamp::new();
        let agent =
            BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp_first_phase);
        let initial_unadjusted_accounts = make_priced_qualified_payables(vec![
            (unadjusted_account_1.clone(), 111_222_333),
            (unadjusted_account_2.clone(), 222_333_444),
        ]);
        let msg = BlockchainAgentWithContextMessage {
            qualified_payables: initial_unadjusted_accounts.clone(),
            agent: Box::new(agent),
            response_skeleton_opt: Some(response_skeleton),
        };
        // In the real world the agents are identical, here they bear different ids
        // so that we can watch their journey better
        let agent_id_stamp_second_phase = ArbitraryIdStamp::new();
        let agent =
            BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp_second_phase);
        let affordable_accounts = make_priced_qualified_payables(vec![
            (adjusted_account_1.clone(), 111_222_333),
            (adjusted_account_2.clone(), 222_333_444),
        ]);
        let payments_instructions = OutboundPaymentsInstructions {
            affordable_accounts: affordable_accounts.clone(),
            agent: Box::new(agent),
            response_skeleton_opt: Some(response_skeleton),
        };
        let payment_adjuster = PaymentAdjusterMock::default()
            .is_adjustment_required_result(Ok(Some(Adjustment::MasqToken)))
            .adjust_payments_params(&adjust_payments_params_arc)
            .adjust_payments_result(payments_instructions);
        let payable_scanner = PayableScannerBuilder::new()
            .payment_adjuster(payment_adjuster)
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Real(
                payable_scanner,
            )));
        subject.outbound_payments_instructions_sub_opt = Some(report_recipient);
        subject.logger = Logger::new(test_name);
        let subject_addr = subject.start();
        let system = System::new("test");

        subject_addr.try_send(msg).unwrap();

        let before = SystemTime::now();
        assert_eq!(system.run(), 0);
        let after = SystemTime::now();
        let mut adjust_payments_params = adjust_payments_params_arc.lock().unwrap();
        let (actual_prepared_adjustment, captured_now, logger_clone) =
            adjust_payments_params.remove(0);
        assert_eq!(actual_prepared_adjustment.adjustment, Adjustment::MasqToken);
        assert_eq!(
            actual_prepared_adjustment
                .original_setup_msg
                .qualified_payables,
            initial_unadjusted_accounts
        );
        assert_eq!(
            actual_prepared_adjustment
                .original_setup_msg
                .agent
                .arbitrary_id_stamp(),
            agent_id_stamp_first_phase
        );
        assert!(
            before <= captured_now && captured_now <= after,
            "timestamp should be between {:?} and {:?} but was {:?}",
            before,
            after,
            captured_now
        );
        assert!(adjust_payments_params.is_empty());
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let payments_instructions =
            blockchain_bridge_recording.get_record::<OutboundPaymentsInstructions>(0);
        assert_eq!(
            payments_instructions.agent.arbitrary_id_stamp(),
            agent_id_stamp_second_phase
        );
        assert_eq!(
            payments_instructions.affordable_accounts,
            affordable_accounts
        );
        assert_eq!(
            payments_instructions.response_skeleton_opt,
            Some(response_skeleton)
        );
        assert_eq!(blockchain_bridge_recording.len(), 1);
        assert_using_the_same_logger(&logger_clone, test_name, None)
    }

    #[test]
    fn externally_triggered_scan_pending_payables_request() {
        let mut config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let fingerprint = PendingPayableFingerprint {
            rowid: 1234,
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt: 1,
            amount: 1_000_000,
            process_error: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_errorless_fingerprints_result(vec![fingerprint.clone()]);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .bootstrapper_config(config)
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(RequestTransactionReceipts));
        let blockchain_bridge_addr = blockchain_bridge.start();
        let system = System::new("test");
        // Important
        subject.scan_schedulers.automatic_scans_enabled = false;
        subject.request_transaction_receipts_sub_opt = Some(blockchain_bridge_addr.recipient());
        // Making sure we would get a panic if another scan was scheduled
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_interval = Duration::from_secs(100);
        let subject_addr = subject.start();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::PendingPayables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0),
            &RequestTransactionReceipts {
                pending_payable_fingerprints: vec![fingerprint],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            }
        );
    }

    #[test]
    fn externally_triggered_scan_identifies_all_pending_payables_as_complete() {
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 565,
            context_id: 112233,
        });
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transaction_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .payable_daos(vec![ForPendingPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_gateway =
            ui_gateway.system_stop_conditions(match_lazily_every_type_id!(NodeToUiMessage));
        let ui_gateway_addr = ui_gateway.start();
        let system = System::new("test");
        subject.scan_schedulers.automatic_scans_enabled = false;
        // Making sure we would kill the test if any sort of scan was scheduled
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.ui_message_sub_opt = Some(ui_gateway_addr.recipient());
        let subject_addr = subject.start();
        let tx_fingerprint = make_pending_payable_fingerprint();
        let report_tx_receipts = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(
                TransactionReceiptResult::RpcResponse(TxReceipt {
                    transaction_hash: make_tx_hash(777),
                    status: TxStatus::Succeeded(TransactionBlock {
                        block_hash: make_tx_hash(456),
                        block_number: 78901234.into(),
                    }),
                }),
                tx_fingerprint.clone(),
            )],
            response_skeleton_opt,
        };

        subject_addr.try_send(report_tx_receipts).unwrap();

        system.run();
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transaction_confirmed_params, vec![vec![tx_fingerprint]]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton_opt.unwrap().client_id),
                body: UiScanResponse {}.tmb(response_skeleton_opt.unwrap().context_id),
            }
        );
        assert_eq!(ui_gateway_recording.len(), 1);
    }

    #[test]
    fn externally_triggered_scan_is_not_handled_in_case_the_scan_is_already_running() {
        init_test_logging();
        let test_name =
            "externally_triggered_scan_is_not_handled_in_case_the_scan_is_already_running";
        let mut config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        config.automatic_scans_enabled = false;
        let now_unix = to_unix_timestamp(SystemTime::now());
        let payment_thresholds = PaymentThresholds::default();
        let past_timestamp_unix = now_unix
            - (payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec) as i64;
        let mut payable_account = make_payable_account(123);
        payable_account.balance_wei = gwei_to_wei(payment_thresholds.debt_threshold_gwei);
        payable_account.last_paid_timestamp = from_unix_timestamp(past_timestamp_unix);
        let payable_dao =
            PayableDaoMock::default().non_pending_payables_result(vec![payable_account]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .logger(Logger::new(test_name))
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new(test_name);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .ui_gateway(ui_gateway)
            .build();
        let first_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::Payables,
            }
            .tmb(4321),
        };
        let second_message = first_message.clone();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr.try_send(first_message).unwrap();

        subject_addr.try_send(second_message).unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {}: Payables scan was already initiated",
            test_name
        ));
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let msg = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(msg.body, UiScanResponse {}.tmb(4321));
    }

    fn test_externally_triggered_scan_is_prevented_if_automatic_scans_are_enabled(
        test_name: &str,
        scan_type: ScanType,
    ) {
        let expected_log_msg = format!(
            "WARN: {test_name}: User requested {:?} scan was denied. Automatic mode \
            prevents manual triggers.",
            scan_type
        );

        test_externally_triggered_scan_is_prevented_if(
            true,
            true,
            test_name,
            scan_type,
            &expected_log_msg,
        )
    }

    fn test_externally_triggered_scan_is_prevented_if(
        automatic_scans_enabled: bool,
        aware_of_unresolved_pending_payables: bool,
        test_name: &str,
        scan_type: ScanType,
        expected_log_message: &str,
    ) {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recorder_arc) = make_recorder();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_gateway =
            ui_gateway.system_stop_conditions(match_lazily_every_type_id!(NodeToUiMessage));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .consuming_wallet(make_wallet("abc"))
            .build();
        subject.scan_schedulers.automatic_scans_enabled = automatic_scans_enabled;
        subject
            .scanners
            .set_aware_of_unresolved_pending_payables(aware_of_unresolved_pending_payables);
        subject.scanners.unset_initial_pending_payable_scan();
        let subject_addr = subject.start();
        let system = System::new(test_name);
        let peer_actors = PeerActorsBuilder::default()
            .ui_gateway(ui_gateway)
            .blockchain_bridge(blockchain_bridge)
            .build();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest { scan_type }.tmb(6789),
        };
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(ui_message).unwrap();

        assert_eq!(system.run(), 0);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let msg = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(msg.body, UiScanResponse {}.tmb(6789));
        assert_eq!(ui_gateway_recording.len(), 1);
        let blockchain_bridge_recorder = blockchain_bridge_recorder_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 0);
        TestLogHandler::new().exists_log_containing(expected_log_message);
    }

    #[test]
    fn externally_triggered_scan_for_new_payables_is_prevented_if_automatic_scans_are_enabled() {
        test_externally_triggered_scan_is_prevented_if_automatic_scans_are_enabled("externally_triggered_scan_for_new_payables_is_prevented_if_automatic_scans_are_enabled", ScanType::Payables)
    }

    #[test]
    fn externally_triggered_scan_for_pending_payables_is_prevented_if_automatic_scans_are_enabled()
    {
        test_externally_triggered_scan_is_prevented_if_automatic_scans_are_enabled("externally_triggered_scan_for_pending_payables_is_prevented_if_automatic_scans_are_enabled", ScanType::PendingPayables)
    }

    #[test]
    fn externally_triggered_scan_for_receivables_is_prevented_if_automatic_scans_are_enabled() {
        test_externally_triggered_scan_is_prevented_if_automatic_scans_are_enabled(
            "externally_triggered_scan_for_receivables_is_prevented_if_automatic_scans_are_enabled",
            ScanType::Receivables,
        )
    }

    #[test]
    fn externally_triggered_scan_for_pending_payables_is_prevented_if_all_payments_already_complete(
    ) {
        let test_name = "externally_triggered_scan_for_pending_payables_is_prevented_if_all_payments_already_complete";
        let expected_log_msg = format!(
            "INFO: {test_name}: User requested PendingPayables scan was denied expecting zero \
            findings. Run the Payable scanner first."
        );

        test_externally_triggered_scan_is_prevented_if(
            false,
            false,
            test_name,
            ScanType::PendingPayables,
            &expected_log_msg,
        )
    }

    #[test]
    fn pending_payable_scan_response_is_sent_to_ui_gateway_when_both_participating_scanners_have_completed(
    ) {
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 4555,
            context_id: 5566,
        });
        // TODO when we have more logic in place with the other cards taken in, we'll need to configure these
        // accordingly
        let payable_dao = PayableDaoMock::default().transactions_confirmed_result(Ok(()));
        let pending_payable = PendingPayableDaoMock::default()
            .return_all_errorless_fingerprints_result(vec![make_pending_payable_fingerprint()])
            .mark_failures_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .payable_daos(vec![ForPendingPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable)])
            .build();
        subject.scan_schedulers.automatic_scans_enabled = false;
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_gateway =
            ui_gateway.system_stop_conditions(match_lazily_every_type_id!(NodeToUiMessage));
        let (peer_actors, peer_addresses) = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .ui_gateway(ui_gateway)
            .build_and_provide_addresses();
        let subject_addr = subject.start();
        let system = System::new("test");
        let first_counter_msg_setup = setup_for_counter_msg_triggered_via_type_id!(
            RequestTransactionReceipts,
            ReportTransactionReceipts {
                fingerprints_with_receipts: vec![(
                    TransactionReceiptResult::RpcResponse(TxReceipt {
                        transaction_hash: make_tx_hash(234),
                        status: TxStatus::Failed
                    }),
                    make_pending_payable_fingerprint()
                )],
                response_skeleton_opt
            },
            &subject_addr
        );
        let second_counter_msg_setup = setup_for_counter_msg_triggered_via_type_id!(
            QualifiedPayablesMessage,
            SentPayables {
                payment_procedure_result: Ok(vec![ProcessedPayableFallible::Correct(
                    PendingPayable {
                        recipient_wallet: make_wallet("abc"),
                        hash: make_tx_hash(789)
                    }
                )]),
                response_skeleton_opt
            },
            &subject_addr
        );
        peer_addresses
            .blockchain_bridge_addr
            .try_send(SetUpCounterMsgs::new(vec![
                first_counter_msg_setup,
                second_counter_msg_setup,
            ]))
            .unwrap();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let pending_payable_request = ScanForPendingPayables {
            response_skeleton_opt,
        };

        subject_addr.try_send(pending_payable_request).unwrap();

        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: ClientId(4555),
                body: UiScanResponse {}.tmb(5566),
            }
        );
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recording.len(), 2);
    }

    #[test]
    fn accountant_sends_qualified_payable_msg_when_qualified_payable_found() {
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let (qualified_payables, _, all_non_pending_payables) =
            make_qualified_and_unqualified_payables(now, &payment_thresholds);
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let system =
            System::new("accountant_sends_qualified_payable_msg_when_qualified_payable_found");
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .consuming_wallet(consuming_wallet.clone())
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null));
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        accountant_addr
            .try_send(ScanForNewPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let message = blockchain_bridge_recorder.get_record::<QualifiedPayablesMessage>(0);
        assert_eq!(
            message,
            &QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables::from(qualified_payables),
                consuming_wallet,
                response_skeleton_opt: None,
            }
        );
    }

    #[test]
    fn automatic_scan_for_new_payables_schedules_another_one_immediately_if_no_qualified_payables_found(
    ) {
        let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let system =
            System::new("automatic_scan_for_new_payables_schedules_another_one_immediately_if_no_qualified_payables_found");
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(consuming_wallet)
            .build();
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
        );
        subject.scan_schedulers.payable.dyn_interval_computer = Box::new(
            NewPayableScanDynIntervalComputerMock::default()
                .compute_interval_result(Some(Duration::from_secs(500))),
        );
        let payable_scanner = ScannerMock::default()
            .scan_started_at_result(None)
            .scan_started_at_result(None)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                payable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null));
        let accountant_addr = subject.start();

        accountant_addr
            .try_send(ScanForNewPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        System::current().stop();
        assert_eq!(system.run(), 0);
        let mut notify_later_params = notify_later_params_arc.lock().unwrap();
        let (msg, interval) = notify_later_params.remove(0);
        assert_eq!(
            msg,
            ScanForNewPayables {
                response_skeleton_opt: None
            }
        );
        assert_eq!(interval, Duration::from_secs(500));
        assert_eq!(notify_later_params.len(), 0);
        // Accountant is unbound; therefore, it is guaranteed that sending a message to
        // the BlockchainBridge wasn't attempted. It would've panicked otherwise.
    }

    #[test]
    fn accountant_handles_scan_for_retry_payables() {
        init_test_logging();
        let test_name = "accountant_handles_scan_for_retry_payables";
        let start_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system = System::new(test_name);
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let consuming_wallet = make_wallet("abc");
        subject.consuming_wallet_opt = Some(consuming_wallet.clone());
        let qualified_payables_msg = QualifiedPayablesMessage {
            qualified_payables: make_unpriced_qualified_payables_for_retry_mode(vec![
                (make_payable_account(789), 111_222_333),
                (make_payable_account(888), 222_333_444),
            ]),
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: None,
        };
        let payable_scanner_mock = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&start_scan_params_arc)
            .start_scan_result(Ok(qualified_payables_msg.clone()));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                payable_scanner_mock,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null));
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        accountant_addr
            .try_send(ScanForRetryPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        System::current().stop();
        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        let mut start_scan_params = start_scan_params_arc.lock().unwrap();
        let (actual_wallet, actual_now, actual_response_skeleton_opt, actual_logger, _) =
            start_scan_params.remove(0);
        assert_eq!(actual_wallet, consuming_wallet);
        assert_eq!(actual_response_skeleton_opt, None);
        assert!(before <= actual_now && actual_now <= after);
        assert!(
            start_scan_params.is_empty(),
            "should be empty but was {:?}",
            start_scan_params
        );
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        let message = blockchain_bridge_recorder.get_record::<QualifiedPayablesMessage>(0);
        assert_eq!(message, &qualified_payables_msg);
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        assert_using_the_same_logger(&actual_logger, test_name, None)
    }

    #[test]
    fn scan_for_retry_payables_if_consuming_wallet_is_not_present() {
        init_test_logging();
        let test_name = "scan_for_retry_payables_if_consuming_wallet_is_not_present";
        let system = System::new(test_name);
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_gateway =
            ui_gateway.system_stop_conditions(match_lazily_every_type_id!(NodeToUiMessage));
        let ui_gateway_addr = ui_gateway.start();
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let payable_scanner_mock = ScannerMock::new();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                payable_scanner_mock,
            )));
        subject.ui_message_sub_opt = Some(ui_gateway_addr.recipient());
        // It must be populated because no errors are tolerated at the RetryPayableScanner
        // if automatic scans are on
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 789,
            context_id: 111,
        });
        let accountant_addr = subject.start();

        accountant_addr
            .try_send(ScanForRetryPayables {
                response_skeleton_opt,
            })
            .unwrap();

        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let message = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(
            message,
            &NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton_opt.unwrap().client_id),
                body: UiScanResponse {}.tmb(response_skeleton_opt.unwrap().context_id)
            }
        );
        TestLogHandler::new().exists_log_containing(&format!("WARN: {test_name}: Cannot initiate Payables scan because no consuming wallet was found"));
    }

    #[test]
    fn accountant_requests_blockchain_bridge_to_scan_for_received_payments() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(RetrieveTransactions));
        let earning_wallet = make_wallet("someearningwallet");
        let system =
            System::new("accountant_requests_blockchain_bridge_to_scan_for_received_payments");
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(earning_wallet.clone()))
            .receivable_daos(vec![ForReceivableScanner(receivable_dao)])
            .build();
        // Important. Preventing the possibly endless sequence of
        // PendingPayableScanner -> NewPayableScanner -> NewPayableScanner...
        subject.scan_schedulers.payable.new_payable_notify = Box::new(NotifyHandleMock::default());
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        let retrieve_transactions_msg =
            blockchain_bridge_recorder.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            retrieve_transactions_msg,
            &RetrieveTransactions {
                recipient: earning_wallet.clone(),
                response_skeleton_opt: None,
            }
        );
        assert_eq!(blockchain_bridge_recorder.len(), 1);
    }

    #[test]
    fn externally_triggered_scan_receivables_request() {
        let mut config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_millis(2_000),
            receivable_scan_interval: Duration::from_millis(10_000),
        });
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_daos(vec![ForReceivableScanner(receivable_dao)])
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(RetrieveTransactions));
        let blockchain_bridge_addr = blockchain_bridge.start();
        // Important
        subject.scan_schedulers.automatic_scans_enabled = false;
        subject.retrieve_transactions_sub_opt = Some(blockchain_bridge_addr.recipient());
        let subject_addr = subject.start();
        let system = System::new("test");
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::Receivables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recording.get_record::<RetrieveTransactions>(0),
            &RetrieveTransactions {
                recipient: make_wallet("earning_wallet"),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            }
        );
    }

    #[test]
    fn received_payments_with_response_skeleton_sends_response_to_ui_gateway() {
        let mut config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_millis(2_000),
            receivable_scan_interval: Duration::from_millis(10_000),
        });
        config.automatic_scans_enabled = false;
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .config_dao(
                ConfigDaoMock::new()
                    .get_result(Ok(ConfigDaoRecord::new("start_block", None, false)))
                    .set_result(Ok(())),
            )
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let received_payments = ReceivedPayments {
            timestamp: SystemTime::now(),
            new_start_block: BlockMarker::Value(0),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
            transactions: vec![],
        };

        subject_addr.try_send(received_payments).unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: ClientId(1234),
                body: UiScanResponse {}.tmb(4321),
            }
        );
    }

    #[test]
    fn accountant_processes_msg_with_received_payments_using_receivables_dao_and_then_updates_start_block(
    ) {
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_by_guest_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let now = SystemTime::now();
        let earning_wallet = make_wallet("earner3000");
        let expected_receivable_1 = BlockchainTransaction {
            block_number: 7,
            from: make_wallet("wallet0"),
            wei_amount: 456,
        };
        let expected_receivable_2 = BlockchainTransaction {
            block_number: 13,
            from: make_wallet("wallet1"),
            wei_amount: 10000,
        };
        let transaction_id = ArbitraryIdStamp::new();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default()
            .commit_params(&commit_params_arc)
            .commit_result(Ok(()))
            .set_arbitrary_id_stamp(transaction_id);
        let wrapped_transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_params(&more_money_received_params_arc)
            .more_money_received_result(wrapped_transaction);
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new("start_block", None, false)))
            .set_by_guest_transaction_params(&set_by_guest_transaction_params_arc)
            .set_by_guest_transaction_result(Ok(()));
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(earning_wallet.clone()))
            .receivable_daos(vec![ForReceivableScanner(receivable_dao)])
            .config_dao(config_dao)
            .build();
        let system = System::new("accountant_uses_receivables_dao_to_process_received_payments");
        let subject = accountant.start();
        subject
            .try_send(ReceivedPayments {
                timestamp: now,
                new_start_block: BlockMarker::Value(123456789u64),
                response_skeleton_opt: None,
                transactions: vec![expected_receivable_1.clone(), expected_receivable_2.clone()],
            })
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(
            *more_money_received_params,
            vec![(now, vec![expected_receivable_1, expected_receivable_2])]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
        let set_by_guest_transaction_params = set_by_guest_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *set_by_guest_transaction_params,
            vec![(
                transaction_id,
                "start_block".to_string(),
                Some("123456789".to_string())
            )]
        )
    }

    #[test]
    fn accountant_scans_after_startup_and_does_not_detect_any_pending_payables() {
        // We will want to prove that the PendingPayableScanner runs before the NewPayableScanner.
        // Their relationship towards the ReceivableScanner isn't important.
        init_test_logging();
        let test_name = "accountant_scans_after_startup_and_does_not_detect_any_pending_payables";
        let scan_params = ScanParams::default();
        let notify_and_notify_later_params = NotifyAndNotifyLaterParams::default();
        let compute_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = make_wallet("consuming");
        let system = System::new(test_name);
        let _ = SystemKillerActor::new(Duration::from_secs(10)).start();
        let config = bc_from_wallets(consuming_wallet.clone(), earning_wallet.clone());
        let payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.payable_start_scan)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        let pending_payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.pending_payable_start_scan)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        let receivable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.receivable_start_scan)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        let (subject, new_payable_expected_computed_interval, receivable_scan_interval) =
            set_up_subject_for_no_pending_payables_found_startup_test(
                test_name,
                &notify_and_notify_later_params,
                &compute_interval_params_arc,
                config,
                pending_payable_scanner,
                receivable_scanner,
                payable_scanner,
            );
        let peer_actors = peer_actors_builder().build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        // The system is stopped by the NotifyLaterHandleMock for the Receivable scanner
        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        assert_pending_payable_scanner_for_no_pending_payable_found(
            test_name,
            consuming_wallet,
            &scan_params.pending_payable_start_scan,
            &notify_and_notify_later_params.pending_payables_notify_later,
            before,
            after,
        );
        assert_payable_scanner_for_no_pending_payable_found(
            &notify_and_notify_later_params,
            compute_interval_params_arc,
            new_payable_expected_computed_interval,
            before,
            after,
        );
        assert_receivable_scanner(
            test_name,
            earning_wallet,
            &scan_params.receivable_start_scan,
            &notify_and_notify_later_params.receivables_notify_later,
            receivable_scan_interval,
        );
        // The test lays down evidences that the NewPayableScanner couldn't run before
        // the PendingPayableScanner, which is an intention.
        // To interpret the evidence, we have to notice that the PendingPayableScanner ran
        // certainly, while it wasn't attempted to schedule in the whole test. That points out that
        // the scanning sequence started spontaneously, not requiring any prior scheduling. Most
        // importantly, regarding the payable scanner, it ran not even once. We know, though,
        // that its scheduling did take place, specifically an urgent call of the new payable mode.
        // That totally corresponds with the expected behavior where the PendingPayableScanner
        // should first search for any stray pending payables; if no findings, the NewPayableScanner
        // is supposed to go next, and it shouldn't have to undertake the standard new-payable
        //  interval, but here, at the beginning, it comes immediately.
    }

    #[test]
    fn accountant_scans_after_startup_and_detects_pending_payable_from_before() {
        // We do ensure the PendingPayableScanner runs before the NewPayableScanner. Not interested
        // in an exact placing of the ReceivableScanner so much.
        init_test_logging();
        let test_name = "accountant_scans_after_startup_and_detects_pending_payable_from_before";
        let scan_params = ScanParams::default();
        let notify_and_notify_later_params = NotifyAndNotifyLaterParams::default();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = make_wallet("consuming");
        let system = System::new(test_name);
        let _ = SystemKillerActor::new(Duration::from_secs(10)).start();
        let config = bc_from_wallets(consuming_wallet.clone(), earning_wallet.clone());
        let pp_fingerprint = make_pending_payable_fingerprint();
        let payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .scan_started_at_result(None)
            // These values belong to the RetryPayableScanner
            .start_scan_params(&scan_params.payable_start_scan)
            .start_scan_result(Ok(QualifiedPayablesMessage {
                qualified_payables: make_unpriced_qualified_payables_for_retry_mode(vec![(
                    make_payable_account(123),
                    555_666_777,
                )]),
                consuming_wallet: consuming_wallet.clone(),
                response_skeleton_opt: None,
            }))
            .finish_scan_params(&scan_params.payable_finish_scan)
            // Important
            .finish_scan_result(PayableScanResult {
                ui_response_opt: None,
                result: OperationOutcome::NewPendingPayable,
            });
        let pending_payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.pending_payable_start_scan)
            .start_scan_result(Ok(RequestTransactionReceipts {
                pending_payable_fingerprints: vec![pp_fingerprint],
                response_skeleton_opt: None,
            }))
            .finish_scan_params(&scan_params.pending_payable_finish_scan)
            .finish_scan_result(PendingPayableScanResult::PaymentRetryRequired);
        let receivable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.receivable_start_scan)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        let (subject, pending_payable_expected_notify_later_interval, receivable_scan_interval) =
            set_up_subject_for_some_pending_payable_found_startup_test(
                test_name,
                &notify_and_notify_later_params,
                config,
                payable_scanner,
                pending_payable_scanner,
                receivable_scanner,
            );
        let (peer_actors, addresses) = peer_actors_builder().build_and_provide_addresses();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        let expected_report_transaction_receipts = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(
                TransactionReceiptResult::RpcResponse(TxReceipt {
                    transaction_hash: make_tx_hash(789),
                    status: TxStatus::Failed,
                }),
                make_pending_payable_fingerprint(),
            )],
            response_skeleton_opt: None,
        };
        let expected_sent_payables = SentPayables {
            payment_procedure_result: Ok(vec![ProcessedPayableFallible::Correct(PendingPayable {
                recipient_wallet: make_wallet("bcd"),
                hash: make_tx_hash(890),
            })]),
            response_skeleton_opt: None,
        };
        let blockchain_bridge_counter_msg_setup_for_pending_payable_scanner = setup_for_counter_msg_triggered_via_type_id!(
            RequestTransactionReceipts,
            expected_report_transaction_receipts.clone(),
            &subject_addr
        );
        let blockchain_bridge_counter_msg_setup_for_payable_scanner = setup_for_counter_msg_triggered_via_type_id!(
            QualifiedPayablesMessage,
            expected_sent_payables.clone(),
            &subject_addr
        );
        send_bind_message!(subject_subs, peer_actors);
        addresses
            .blockchain_bridge_addr
            .try_send(SetUpCounterMsgs::new(vec![
                blockchain_bridge_counter_msg_setup_for_pending_payable_scanner,
                blockchain_bridge_counter_msg_setup_for_payable_scanner,
            ]))
            .unwrap();

        send_start_message!(subject_subs);

        // The system is stopped by the NotifyHandleLaterMock for the PendingPayable scanner
        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        assert_pending_payable_scanner_for_some_pending_payable_found(
            test_name,
            consuming_wallet.clone(),
            &scan_params,
            &notify_and_notify_later_params.pending_payables_notify_later,
            pending_payable_expected_notify_later_interval,
            expected_report_transaction_receipts,
            before,
            after,
        );
        assert_payable_scanner_for_some_pending_payable_found(
            test_name,
            consuming_wallet,
            &scan_params,
            &notify_and_notify_later_params,
            expected_sent_payables,
        );
        assert_receivable_scanner(
            test_name,
            earning_wallet,
            &scan_params.receivable_start_scan,
            &notify_and_notify_later_params.receivables_notify_later,
            receivable_scan_interval,
        );
        // Given the assertions prove that the pending payable scanner has run multiple times
        // before the new payable scanner started or was scheduled, the front position belongs to
        // the one first mentioned, no doubts.
    }

    #[derive(Default)]
    struct ScanParams {
        payable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
        payable_finish_scan: Arc<Mutex<Vec<(SentPayables, Logger)>>>,
        pending_payable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
        pending_payable_finish_scan: Arc<Mutex<Vec<(ReportTransactionReceipts, Logger)>>>,
        receivable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
        // receivable_finish_scan ... not needed
    }

    #[derive(Default)]
    struct NotifyAndNotifyLaterParams {
        new_payables_notify_later: Arc<Mutex<Vec<(ScanForNewPayables, Duration)>>>,
        new_payables_notify: Arc<Mutex<Vec<ScanForNewPayables>>>,
        retry_payables_notify: Arc<Mutex<Vec<ScanForRetryPayables>>>,
        pending_payables_notify_later: Arc<Mutex<Vec<(ScanForPendingPayables, Duration)>>>,
        receivables_notify_later: Arc<Mutex<Vec<(ScanForReceivables, Duration)>>>,
    }

    fn set_up_subject_for_no_pending_payables_found_startup_test(
        test_name: &str,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        compute_interval_params_arc: &Arc<Mutex<Vec<(SystemTime, SystemTime, Duration)>>>,
        config: BootstrapperConfig,
        pending_payable_scanner: ScannerMock<
            RequestTransactionReceipts,
            ReportTransactionReceipts,
            PendingPayableScanResult,
        >,
        receivable_scanner: ScannerMock<
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
        payable_scanner: ScannerMock<QualifiedPayablesMessage, SentPayables, PayableScanResult>,
    ) -> (Accountant, Duration, Duration) {
        let mut subject = make_subject_and_inject_scanners(
            test_name,
            config,
            pending_payable_scanner,
            receivable_scanner,
            payable_scanner,
        );
        let new_payable_expected_computed_interval = Duration::from_secs(3600);
        // Important that this is made short because the test relies on it with the system stop.
        let receivable_scan_interval = Duration::from_millis(50);
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_and_notify_later_params.pending_payables_notify_later),
        );
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_and_notify_later_params.new_payables_notify_later),
        );
        subject.scan_schedulers.payable.retry_payable_notify = Box::new(
            NotifyHandleMock::default()
                .notify_params(&notify_and_notify_later_params.retry_payables_notify),
        );
        subject.scan_schedulers.payable.new_payable_notify = Box::new(
            NotifyHandleMock::default()
                .notify_params(&notify_and_notify_later_params.new_payables_notify),
        );
        let receivable_notify_later_handle_mock = NotifyLaterHandleMock::default()
            .notify_later_params(&notify_and_notify_later_params.receivables_notify_later)
            .stop_system_on_count_received(1);
        subject.scan_schedulers.receivable.handle = Box::new(receivable_notify_later_handle_mock);
        subject.scan_schedulers.receivable.interval = receivable_scan_interval;
        let dyn_interval_computer = NewPayableScanDynIntervalComputerMock::default()
            .compute_interval_params(&compute_interval_params_arc)
            .compute_interval_result(Some(new_payable_expected_computed_interval));
        subject.scan_schedulers.payable.dyn_interval_computer = Box::new(dyn_interval_computer);
        (
            subject,
            new_payable_expected_computed_interval,
            receivable_scan_interval,
        )
    }

    fn set_up_subject_for_some_pending_payable_found_startup_test(
        test_name: &str,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        config: BootstrapperConfig,
        payable_scanner: ScannerMock<QualifiedPayablesMessage, SentPayables, PayableScanResult>,
        pending_payable_scanner: ScannerMock<
            RequestTransactionReceipts,
            ReportTransactionReceipts,
            PendingPayableScanResult,
        >,
        receivable_scanner: ScannerMock<
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
    ) -> (Accountant, Duration, Duration) {
        let mut subject = make_subject_and_inject_scanners(
            test_name,
            config,
            pending_payable_scanner,
            receivable_scanner,
            payable_scanner,
        );
        let pending_payable_scan_interval = Duration::from_secs(3600);
        let receivable_scan_interval = Duration::from_secs(3600);
        let pending_payable_notify_later_handle_mock = NotifyLaterHandleMock::default()
            .notify_later_params(&notify_and_notify_later_params.pending_payables_notify_later)
            // This should stop the system
            .stop_system_on_count_received(1);
        subject.scan_schedulers.pending_payable.handle =
            Box::new(pending_payable_notify_later_handle_mock);
        subject.scan_schedulers.pending_payable.interval = pending_payable_scan_interval;
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_and_notify_later_params.new_payables_notify_later),
        );
        subject.scan_schedulers.payable.retry_payable_notify = Box::new(
            NotifyHandleMock::default()
                .notify_params(&notify_and_notify_later_params.retry_payables_notify)
                .capture_msg_and_let_it_fly_on(),
        );
        subject.scan_schedulers.payable.new_payable_notify = Box::new(
            NotifyHandleMock::default()
                .notify_params(&notify_and_notify_later_params.new_payables_notify),
        );
        let receivable_notify_later_handle_mock = NotifyLaterHandleMock::default()
            .notify_later_params(&notify_and_notify_later_params.receivables_notify_later);
        subject.scan_schedulers.receivable.interval = receivable_scan_interval;
        subject.scan_schedulers.receivable.handle = Box::new(receivable_notify_later_handle_mock);
        (
            subject,
            pending_payable_scan_interval,
            receivable_scan_interval,
        )
    }

    fn make_subject_and_inject_scanners(
        test_name: &str,
        config: BootstrapperConfig,
        pending_payable_scanner: ScannerMock<
            RequestTransactionReceipts,
            ReportTransactionReceipts,
            PendingPayableScanResult,
        >,
        receivable_scanner: ScannerMock<
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
        payable_scanner: ScannerMock<QualifiedPayablesMessage, SentPayables, PayableScanResult>,
    ) -> Accountant {
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .bootstrapper_config(config)
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Mock(
                receivable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                payable_scanner,
            )));
        subject
    }

    fn assert_pending_payable_scanner_for_no_pending_payable_found(
        test_name: &str,
        consuming_wallet: Wallet,
        pending_payable_start_scan_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        scan_for_pending_payables_notify_later_params_arc: &Arc<
            Mutex<Vec<(ScanForPendingPayables, Duration)>>,
        >,
        act_started_at: SystemTime,
        act_finished_at: SystemTime,
    ) {
        let pp_logger = pending_payable_common(
            consuming_wallet,
            pending_payable_start_scan_params_arc,
            act_started_at,
            act_finished_at,
        );
        let scan_for_pending_payables_notify_later_params =
            scan_for_pending_payables_notify_later_params_arc
                .lock()
                .unwrap();
        // PendingPayableScanner can only start after NewPayableScanner finishes and makes at least
        // one transaction. The test stops before running NewPayableScanner, missing both
        // the second PendingPayableScanner run and its scheduling event.
        assert!(
            scan_for_pending_payables_notify_later_params.is_empty(),
            "We did not expect to see another schedule for pending payables, but it happened {:?}",
            scan_for_pending_payables_notify_later_params
        );
        assert_using_the_same_logger(&pp_logger, test_name, Some("pp"));
    }

    fn assert_pending_payable_scanner_for_some_pending_payable_found(
        test_name: &str,
        consuming_wallet: Wallet,
        scan_params: &ScanParams,
        scan_for_pending_payables_notify_later_params_arc: &Arc<
            Mutex<Vec<(ScanForPendingPayables, Duration)>>,
        >,
        pending_payable_expected_notify_later_interval: Duration,
        expected_report_tx_receipts_msg: ReportTransactionReceipts,
        act_started_at: SystemTime,
        act_finished_at: SystemTime,
    ) {
        let pp_start_scan_logger = pending_payable_common(
            consuming_wallet,
            &scan_params.pending_payable_start_scan,
            act_started_at,
            act_finished_at,
        );
        assert_using_the_same_logger(&pp_start_scan_logger, test_name, Some("pp start scan"));
        let mut pending_payable_finish_scan_params =
            scan_params.pending_payable_finish_scan.lock().unwrap();
        let (actual_report_tx_receipts_msg, pp_finish_scan_logger) =
            pending_payable_finish_scan_params.remove(0);
        assert_eq!(
            actual_report_tx_receipts_msg,
            expected_report_tx_receipts_msg
        );
        assert_using_the_same_logger(&pp_finish_scan_logger, test_name, Some("pp finish scan"));
        let scan_for_pending_payables_notify_later_params =
            scan_for_pending_payables_notify_later_params_arc
                .lock()
                .unwrap();
        // This is the moment when the test ends. It says that we went the way of the pending payable
        // sequence, instead of calling the NewPayableScan just after the initial pending payable
        // scan.
        assert_eq!(
            *scan_for_pending_payables_notify_later_params,
            vec![(
                ScanForPendingPayables {
                    response_skeleton_opt: None
                },
                pending_payable_expected_notify_later_interval
            )],
        );
    }

    fn pending_payable_common(
        consuming_wallet: Wallet,
        pending_payable_start_scan_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        act_started_at: SystemTime,
        act_finished_at: SystemTime,
    ) -> Logger {
        let mut pending_payable_params = pending_payable_start_scan_params_arc.lock().unwrap();
        let (
            pp_wallet,
            pp_scan_started_at,
            pp_response_skeleton_opt,
            pp_logger,
            pp_trigger_msg_type_str,
        ) = pending_payable_params.remove(0);
        assert_eq!(pp_wallet, consuming_wallet);
        assert_eq!(pp_response_skeleton_opt, None);
        assert!(
            pp_trigger_msg_type_str.contains("PendingPayable"),
            "Should contain PendingPayable but {}",
            pp_trigger_msg_type_str
        );
        assert!(
            pending_payable_params.is_empty(),
            "Should be empty but was {:?}",
            pending_payable_params
        );
        assert!(
            act_started_at <= pp_scan_started_at && pp_scan_started_at <= act_finished_at,
            "The scanner was supposed to run between {:?} and {:?} but it was {:?}",
            act_started_at,
            act_finished_at,
            pp_scan_started_at
        );
        pp_logger
    }

    fn assert_payable_scanner_for_no_pending_payable_found(
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        compute_interval_params_arc: Arc<Mutex<Vec<(SystemTime, SystemTime, Duration)>>>,
        new_payable_expected_computed_interval: Duration,
        act_started_at: SystemTime,
        act_finished_at: SystemTime,
    ) {
        // Note that there is no functionality from the payable scanner actually running.
        // We only witness it to be scheduled.
        let scan_for_new_payables_notify_later_params = notify_and_notify_later_params
            .new_payables_notify_later
            .lock()
            .unwrap();
        assert_eq!(
            *scan_for_new_payables_notify_later_params,
            vec![(
                ScanForNewPayables {
                    response_skeleton_opt: None
                },
                new_payable_expected_computed_interval
            )]
        );
        let mut compute_interval_params = compute_interval_params_arc.lock().unwrap();
        let (p_scheduling_now, last_new_payable_scan_timestamp, _) =
            compute_interval_params.remove(0);
        assert_eq!(last_new_payable_scan_timestamp, UNIX_EPOCH);
        let scan_for_new_payables_notify_params = notify_and_notify_later_params
            .new_payables_notify
            .lock()
            .unwrap();
        assert!(
            scan_for_new_payables_notify_params.is_empty(),
            "We did not expect any immediate scheduling of new payables, but it happened {:?}",
            scan_for_new_payables_notify_params
        );
        let scan_for_retry_payables_notify_params = notify_and_notify_later_params
            .retry_payables_notify
            .lock()
            .unwrap();
        assert!(
            scan_for_retry_payables_notify_params.is_empty(),
            "We did not expect any scheduling of retry payables, but it happened {:?}",
            scan_for_retry_payables_notify_params
        );
        assert!(
            act_started_at <= p_scheduling_now && p_scheduling_now <= act_finished_at,
            "The payable scan scheduling was supposed to take place between {:?} and {:?} \
            but it was {:?}",
            act_started_at,
            act_finished_at,
            p_scheduling_now
        );
    }

    fn assert_payable_scanner_for_some_pending_payable_found(
        test_name: &str,
        consuming_wallet: Wallet,
        scan_params: &ScanParams,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        expected_sent_payables: SentPayables,
    ) {
        let mut payable_start_scan_params = scan_params.payable_start_scan.lock().unwrap();
        let (p_wallet, _, p_response_skeleton_opt, p_start_scan_logger, p_trigger_msg_type_str) =
            payable_start_scan_params.remove(0);
        assert_eq!(p_wallet, consuming_wallet);
        assert_eq!(p_response_skeleton_opt, None);
        // Important: it's the proof that we're dealing with the RetryPayableScanner not NewPayableScanner
        assert!(
            p_trigger_msg_type_str.contains("RetryPayable"),
            "Should contain RetryPayable but {}",
            p_trigger_msg_type_str
        );
        assert!(
            payable_start_scan_params.is_empty(),
            "Should be empty but was {:?}",
            payable_start_scan_params
        );
        assert_using_the_same_logger(&p_start_scan_logger, test_name, Some("retry payable start"));
        let mut payable_finish_scan_params = scan_params.payable_finish_scan.lock().unwrap();
        let (actual_sent_payable, p_finish_scan_logger) = payable_finish_scan_params.remove(0);
        assert_eq!(actual_sent_payable, expected_sent_payables,);
        assert!(
            payable_finish_scan_params.is_empty(),
            "Should be empty but was {:?}",
            payable_finish_scan_params
        );
        assert_using_the_same_logger(
            &p_finish_scan_logger,
            test_name,
            Some("retry payable finish"),
        );
        let scan_for_new_payables_notify_later_params = notify_and_notify_later_params
            .new_payables_notify_later
            .lock()
            .unwrap();
        assert!(
            scan_for_new_payables_notify_later_params.is_empty(),
            "We did not expect any later scheduling of new payables, but it happened {:?}",
            scan_for_new_payables_notify_later_params
        );
        let scan_for_new_payables_notify_params = notify_and_notify_later_params
            .new_payables_notify
            .lock()
            .unwrap();
        assert!(
            scan_for_new_payables_notify_params.is_empty(),
            "We did not expect any immediate scheduling of new payables, but it happened {:?}",
            scan_for_new_payables_notify_params
        );
        let scan_for_retry_payables_notify_params = notify_and_notify_later_params
            .retry_payables_notify
            .lock()
            .unwrap();
        assert_eq!(
            *scan_for_retry_payables_notify_params,
            vec![ScanForRetryPayables {
                response_skeleton_opt: None
            }],
        );
    }

    fn assert_receivable_scanner(
        test_name: &str,
        earning_wallet: Wallet,
        receivable_start_scan_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        scan_for_receivables_notify_later_params_arc: &Arc<
            Mutex<Vec<(ScanForReceivables, Duration)>>,
        >,
        receivable_scan_interval: Duration,
    ) {
        let mut receivable_start_scan_params = receivable_start_scan_params_arc.lock().unwrap();
        let (r_wallet, _r_started_at, r_response_skeleton_opt, r_logger, r_trigger_msg_name_str) =
            receivable_start_scan_params.remove(0);
        assert_eq!(r_wallet, earning_wallet);
        assert_eq!(r_response_skeleton_opt, None);
        assert!(
            r_trigger_msg_name_str.contains("Receivable"),
            "Should contain Receivable but {}",
            r_trigger_msg_name_str
        );
        assert!(
            receivable_start_scan_params.is_empty(),
            "Should be already empty but was {:?}",
            receivable_start_scan_params
        );
        assert_using_the_same_logger(&r_logger, test_name, Some("r"));
        let scan_for_receivables_notify_later_params =
            scan_for_receivables_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *scan_for_receivables_notify_later_params,
            vec![(
                ScanForReceivables {
                    response_skeleton_opt: None
                },
                receivable_scan_interval
            )]
        );
    }

    #[test]
    fn initial_pending_payable_scan_if_some_payables_found() {
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_errorless_fingerprints_result(vec![make_pending_payable_fingerprint()]);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let system = System::new("test");
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge.start();
        subject.request_transaction_receipts_sub_opt = Some(blockchain_bridge_addr.recipient());
        let flag_before = subject.scanners.initial_pending_payable_scan();

        let hint = subject.handle_request_of_scan_for_pending_payable(None);

        System::current().stop();
        system.run();
        let flag_after = subject.scanners.initial_pending_payable_scan();
        assert_eq!(hint, ScanRescheduleAfterEarlyStop::DoNotSchedule);
        assert_eq!(flag_before, true);
        assert_eq!(flag_after, false);
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let _ = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
    }

    #[test]
    fn initial_pending_payable_scan_if_no_payables_found() {
        let pending_payable_dao =
            PendingPayableDaoMock::default().return_all_errorless_fingerprints_result(vec![]);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let flag_before = subject.scanners.initial_pending_payable_scan();

        let hint = subject.handle_request_of_scan_for_pending_payable(None);

        let flag_after = subject.scanners.initial_pending_payable_scan();
        assert_eq!(
            hint,
            ScanRescheduleAfterEarlyStop::Schedule(ScanType::Payables)
        );
        assert_eq!(flag_before, true);
        assert_eq!(flag_after, false);
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: ScanAlreadyRunning { \
        cross_scan_cause_opt: None, started_at: SystemTime { tv_sec: 0, tv_nsec: 0 } } \
        should be impossible with PendingPayableScanner in automatic mode"
    )]
    fn initial_pending_payable_scan_hits_unexpected_error() {
        init_test_logging();
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("abc"))
            .build();
        let pending_payable_scanner =
            ScannerMock::default().scan_started_at_result(Some(UNIX_EPOCH));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));

        let _ = subject.handle_request_of_scan_for_pending_payable(None);
    }

    #[test]
    fn periodical_scanning_for_receivables_and_delinquencies_works() {
        init_test_logging();
        let test_name = "periodical_scanning_for_receivables_and_delinquencies_works";
        let start_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_receivable_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        SystemKillerActor::new(Duration::from_secs(10)).start(); // a safety net for GitHub Actions
        let receivable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .scan_started_at_result(None)
            .start_scan_params(&start_scan_params_arc)
            .start_scan_result(Err(StartScanError::NothingToProcess))
            .start_scan_result(Ok(RetrieveTransactions {
                recipient: make_wallet("some_recipient"),
                response_skeleton_opt: None,
            }))
            .stop_the_system_after_last_msg();
        let earning_wallet = make_wallet("earning");
        let mut config = bc_from_earning_wallet(earning_wallet.clone());
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_secs(100),
            pending_payable_scan_interval: Duration::from_secs(10),
            receivable_scan_interval: Duration::from_millis(99),
        });
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .logger(Logger::new(test_name))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Mock(
                receivable_scanner,
            )));
        subject.scan_schedulers.receivable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_receivable_params_arc)
                .capture_msg_and_let_it_fly_on(),
        );
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        let peer_actors = peer_actors_builder().build();
        send_bind_message!(subject_subs, peer_actors);

        subject_addr
            .try_send(ScanForReceivables {
                response_skeleton_opt: None,
            })
            .unwrap();

        let time_before = SystemTime::now();
        system.run();
        let time_after = SystemTime::now();
        let notify_later_receivable_params = notify_later_receivable_params_arc.lock().unwrap();
        let tlh = TestLogHandler::new();
        let mut start_scan_params = start_scan_params_arc.lock().unwrap();
        let (
            first_attempt_wallet,
            first_attempt_timestamp,
            first_attempt_response_skeleton_opt,
            first_attempt_logger,
            _,
        ) = start_scan_params.remove(0);
        let (
            second_attempt_wallet,
            second_attempt_timestamp,
            second_attempt_response_skeleton_opt,
            second_attempt_logger,
            _,
        ) = start_scan_params.remove(0);
        assert_eq!(first_attempt_wallet, earning_wallet);
        assert_eq!(second_attempt_wallet, earning_wallet);
        assert!(time_before <= first_attempt_timestamp);
        assert!(first_attempt_timestamp <= second_attempt_timestamp);
        assert!(second_attempt_timestamp <= time_after);
        assert_eq!(first_attempt_response_skeleton_opt, None);
        assert_eq!(second_attempt_response_skeleton_opt, None);
        assert!(start_scan_params.is_empty());
        debug!(
            first_attempt_logger,
            "first attempt verifying receivable scanner"
        );
        debug!(
            second_attempt_logger,
            "second attempt verifying receivable scanner"
        );
        assert_eq!(
            *notify_later_receivable_params,
            vec![
                (
                    ScanForReceivables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(99)
                ),
                (
                    ScanForReceivables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(99)
                ),
            ]
        );
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: There was nothing to process during Receivables scan."
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: first attempt verifying receivable scanner",
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: second attempt verifying receivable scanner",
        ));
    }

    // This test begins with the new payable scan, continues over the retry payable scan and ends
    // with another attempt for new payables which proves one complete cycle.
    #[test]
    fn periodical_scanning_for_payables_works() {
        init_test_logging();
        let test_name = "periodical_scanning_for_payables_works";
        let start_scan_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let start_scan_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let payable_account = make_payable_account(123);
        let unpriced_qualified_payables =
            UnpricedQualifiedPayables::from(vec![payable_account.clone()]);
        let priced_qualified_payables =
            make_priced_qualified_payables(vec![(payable_account, 123_456_789)]);
        let consuming_wallet = make_paying_wallet(b"consuming");
        let counter_msg_1 = BlockchainAgentWithContextMessage {
            qualified_payables: priced_qualified_payables.clone(),
            agent: Box::new(BlockchainAgentMock::default()),
            response_skeleton_opt: None,
        };
        let transaction_hash = make_tx_hash(789);
        let creditor_wallet = make_wallet("blah");
        let counter_msg_2 = SentPayables {
            payment_procedure_result: Ok(vec![ProcessedPayableFallible::Correct(
                PendingPayable::new(creditor_wallet, transaction_hash),
            )]),
            response_skeleton_opt: None,
        };
        let tx_receipt = TxReceipt {
            transaction_hash,
            status: TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(369369),
                block_number: 4444444444u64.into(),
            }),
        };
        let pending_payable_fingerprint = make_pending_payable_fingerprint();
        let counter_msg_3 = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(
                TransactionReceiptResult::RpcResponse(tx_receipt),
                pending_payable_fingerprint.clone(),
            )],
            response_skeleton_opt: None,
        };
        let request_transaction_receipts_msg = RequestTransactionReceipts {
            pending_payable_fingerprints: vec![pending_payable_fingerprint],
            response_skeleton_opt: None,
        };
        let qualified_payables_msg = QualifiedPayablesMessage {
            qualified_payables: unpriced_qualified_payables,
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt: None,
        };
        let subject = set_up_subject_to_prove_periodical_payable_scan(
            test_name,
            &blockchain_bridge_addr,
            &consuming_wallet,
            &qualified_payables_msg,
            &request_transaction_receipts_msg,
            &start_scan_pending_payable_params_arc,
            &start_scan_payable_params_arc,
            &notify_later_pending_payables_params_arc,
            &notify_payable_params_arc,
        );
        let subject_addr = subject.start();
        let set_up_counter_msgs = SetUpCounterMsgs::new(vec![
            setup_for_counter_msg_triggered_via_type_id!(
                QualifiedPayablesMessage,
                counter_msg_1,
                &subject_addr
            ),
            setup_for_counter_msg_triggered_via_type_id!(
                OutboundPaymentsInstructions,
                counter_msg_2,
                &subject_addr
            ),
            setup_for_counter_msg_triggered_via_type_id!(
                RequestTransactionReceipts,
                counter_msg_3,
                &subject_addr
            ),
        ]);
        blockchain_bridge_addr
            .try_send(set_up_counter_msgs)
            .unwrap();

        subject_addr
            .try_send(ScanForNewPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        let time_before = SystemTime::now();
        system.run();
        let time_after = SystemTime::now();
        let mut start_scan_payable_params = start_scan_payable_params_arc.lock().unwrap();
        let (wallet, timestamp, response_skeleton_opt, logger, _) =
            start_scan_payable_params.remove(0);
        assert_eq!(wallet, consuming_wallet);
        assert!(time_before <= timestamp && timestamp <= time_after);
        assert_eq!(response_skeleton_opt, None);
        assert!(start_scan_payable_params.is_empty());
        assert_using_the_same_logger(&logger, test_name, Some("start scan payable"));
        let mut start_scan_pending_payable_params =
            start_scan_pending_payable_params_arc.lock().unwrap();
        let (wallet, timestamp, response_skeleton_opt, logger, _) =
            start_scan_pending_payable_params.remove(0);
        assert_eq!(wallet, consuming_wallet);
        assert!(time_before <= timestamp && timestamp <= time_after);
        assert_eq!(response_skeleton_opt, None);
        assert!(start_scan_pending_payable_params.is_empty());
        assert_using_the_same_logger(&logger, test_name, Some("start scan pending payable"));
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let actual_qualified_payables_msg =
            blockchain_bridge_recording.get_record::<QualifiedPayablesMessage>(0);
        assert_eq!(actual_qualified_payables_msg, &qualified_payables_msg);
        let actual_outbound_payment_instructions_msg =
            blockchain_bridge_recording.get_record::<OutboundPaymentsInstructions>(1);
        assert_eq!(
            actual_outbound_payment_instructions_msg.affordable_accounts,
            priced_qualified_payables
        );
        let actual_requested_receipts_1 =
            blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(2);
        assert_eq!(
            actual_requested_receipts_1,
            &request_transaction_receipts_msg
        );
        let notify_later_pending_payables_params =
            notify_later_pending_payables_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_pending_payables_params,
            vec![(
                ScanForPendingPayables {
                    response_skeleton_opt: None
                },
                Duration::from_millis(50)
            ),]
        );
        let notify_payables_params = notify_payable_params_arc.lock().unwrap();
        assert_eq!(
            *notify_payables_params,
            vec![ScanForNewPayables {
                response_skeleton_opt: None
            },]
        );
    }

    fn set_up_subject_to_prove_periodical_payable_scan(
        test_name: &str,
        blockchain_bridge_addr: &Addr<Recorder>,
        consuming_wallet: &Wallet,
        qualified_payables_msg: &QualifiedPayablesMessage,
        request_transaction_receipts: &RequestTransactionReceipts,
        start_scan_pending_payable_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        start_scan_payable_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        notify_later_pending_payables_params_arc: &Arc<
            Mutex<Vec<(ScanForPendingPayables, Duration)>>,
        >,
        notify_payable_params_arc: &Arc<Mutex<Vec<ScanForNewPayables>>>,
    ) -> Accountant {
        let pending_payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&start_scan_pending_payable_params_arc)
            .start_scan_result(Ok(request_transaction_receipts.clone()))
            .finish_scan_result(PendingPayableScanResult::NoPendingPayablesLeft(None));
        let payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            // Always checking also on the payable scanner when handling ScanForPendingPayable
            .scan_started_at_result(None)
            .start_scan_params(&start_scan_payable_params_arc)
            .start_scan_result(Ok(qualified_payables_msg.clone()))
            .finish_scan_result(PayableScanResult {
                ui_response_opt: None,
                result: OperationOutcome::NewPendingPayable,
            });
        let mut config = bc_from_earning_wallet(make_wallet("hi"));
        config.scan_intervals_opt = Some(ScanIntervals {
            // This simply means that we're gonna surplus this value (it abides by how many pending
            // payable cycles have to go in between before the lastly submitted txs are confirmed),
            payable_scan_interval: Duration::from_millis(10),
            pending_payable_scan_interval: Duration::from_millis(50),
            receivable_scan_interval: Duration::from_secs(100), // We'll never run this scanner
        });
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .consuming_wallet(consuming_wallet.clone())
            .logger(Logger::new(test_name))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                payable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null)); //skipping
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::<ScanForPendingPayables>::default()
                .notify_later_params(&notify_later_pending_payables_params_arc)
                .capture_msg_and_let_it_fly_on(),
        );
        subject.scan_schedulers.payable.new_payable_notify = Box::new(
            NotifyHandleMock::<ScanForNewPayables>::default()
                .notify_params(&notify_payable_params_arc)
                // This should stop the system. If anything goes wrong, the SystemKillerActor will.
                .stop_system_on_count_received(1),
        );
        subject.qualified_payables_sub_opt = Some(blockchain_bridge_addr.clone().recipient());
        subject.outbound_payments_instructions_sub_opt =
            Some(blockchain_bridge_addr.clone().recipient());
        subject.request_transaction_receipts_sub_opt =
            Some(blockchain_bridge_addr.clone().recipient());
        subject
    }

    #[test]
    fn payable_scan_is_not_initiated_if_consuming_wallet_is_not_found() {
        init_test_logging();
        let test_name = "payable_scan_is_not_initiated_if_consuming_wallet_is_not_found";
        let mut subject = AccountantBuilder::default().build();
        subject.consuming_wallet_opt = None;
        subject.logger = Logger::new(test_name);

        subject.handle_request_of_scan_for_new_payable(None);

        let has_scan_started = subject
            .scanners
            .scan_started_at(ScanType::Payables)
            .is_some();
        assert_eq!(has_scan_started, false);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Cannot initiate Payables scan because no consuming wallet was found."
        ));
    }

    #[test]
    fn pending_payable_scan_is_not_initiated_if_consuming_wallet_is_not_found() {
        init_test_logging();
        let test_name = "pending_payable_scan_is_not_initiated_if_consuming_wallet_is_not_found";
        let mut subject = AccountantBuilder::default().build();
        subject.consuming_wallet_opt = None;
        subject.logger = Logger::new(test_name);

        subject.handle_request_of_scan_for_pending_payable(None);

        let has_scan_started = subject
            .scanners
            .scan_started_at(ScanType::PendingPayables)
            .is_some();
        assert_eq!(has_scan_started, false);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Cannot initiate PendingPayables scan because no consuming wallet was found."
        ));
    }

    #[test]
    fn start_message_triggers_no_scans_in_suppress_mode() {
        init_test_logging();
        let test_name = "start_message_triggers_no_scans_in_suppress_mode";
        let system = System::new(test_name);
        let mut config = bc_from_earning_wallet(make_wallet("hi"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(100),
            pending_payable_scan_interval: Duration::from_millis(50),
            receivable_scan_interval: Duration::from_millis(100),
        });
        config.automatic_scans_enabled = false;
        let peer_actors = peer_actors_builder().build();
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .logger(Logger::new(test_name))
            .build();
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        System::current().stop();
        assert_eq!(system.run(), 0);
        // No panics because of recalcitrant DAOs; therefore DAOs were not called; therefore test passes
        TestLogHandler::new().exists_log_containing(
            &format!("{test_name}: Started with --scans off; declining to begin database and blockchain scans"),
        );
    }

    #[test]
    fn scan_for_new_payables_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let config = bc_from_earning_wallet(make_wallet("mine"));
        let now = to_unix_timestamp(SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei - 1),
                last_paid_timestamp: from_unix_timestamp(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.maturity_threshold_sec
                            + payment_thresholds.threshold_interval_sec,
                    ),
                ),
                pending_payable_opt: None,
            },
            // above balance intersection, to the left of minimum time (outside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: gwei_to_wei(payment_thresholds.debt_threshold_gwei + 1),
                last_paid_timestamp: from_unix_timestamp(
                    now - checked_conversion::<u64, i64>(payment_thresholds.maturity_threshold_sec)
                        + 1,
                ),
                pending_payable_opt: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance_wei: gwei_to_wei::<u128, u64>(
                    payment_thresholds.permanent_debt_allowed_gwei,
                ) + 1,
                last_paid_timestamp: from_unix_timestamp(
                    now - checked_conversion::<u64, i64>(payment_thresholds.threshold_interval_sec)
                        + 1,
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_new_payables_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .consuming_wallet(consuming_wallet.clone())
            .build();
        let payable_scanner = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .payable_dao(payable_dao)
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Real(
                payable_scanner,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null));
        subject.qualified_payables_sub_opt = Some(blockchain_bridge_addr.recipient());
        bind_ui_gateway_unasserted(&mut subject);

        let result = subject.handle_request_of_scan_for_new_payable(None);

        System::current().stop();
        system.run();
        assert_eq!(
            result,
            ScanRescheduleAfterEarlyStop::Schedule(ScanType::Payables)
        );
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_new_payables_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let mut config = bc_from_earning_wallet(make_wallet("mine"));
        let consuming_wallet = make_paying_wallet(b"consuming");
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_secs(50_000),
            pending_payable_scan_interval: Duration::from_secs(10_000),
            receivable_scan_interval: Duration::from_secs(50_000),
        });
        let now = to_unix_timestamp(SystemTime::now());
        let qualified_payables = vec![
            // Slightly above the minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance_wei: gwei_to_wei(
                    DEFAULT_PAYMENT_THRESHOLDS.permanent_debt_allowed_gwei + 1,
                ),
                last_paid_timestamp: from_unix_timestamp(
                    now - checked_conversion::<u64, i64>(
                        DEFAULT_PAYMENT_THRESHOLDS.threshold_interval_sec
                            + DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
                            + 10,
                    ),
                ),
                pending_payable_opt: None,
            },
            // Slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1),
                last_paid_timestamp: from_unix_timestamp(
                    now - checked_conversion::<u64, i64>(
                        DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 10,
                    ),
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao =
            PayableDaoMock::default().non_pending_payables_result(qualified_payables.clone());
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let system =
            System::new("scan_for_payable_message_triggers_payment_for_balances_over_the_curve");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .consuming_wallet(consuming_wallet.clone())
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Null));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Receivable(ReplacementType::Null));
        subject.qualified_payables_sub_opt = Some(blockchain_bridge_addr.recipient());
        bind_ui_gateway_unasserted(&mut subject);

        subject.handle_request_of_scan_for_new_payable(None);

        System::current().stop();
        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        let message = blockchain_bridge_recordings.get_record::<QualifiedPayablesMessage>(0);
        assert_eq!(
            message,
            &QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables::from(qualified_payables),
                consuming_wallet,
                response_skeleton_opt: None,
            }
        );
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Early stopped new payable scan \
        was suggested to be followed up by the scan for Receivables, which is not supported though"
    )]
    fn start_scan_error_in_new_payables_and_unexpected_reaction_by_receivable_scan_scheduling() {
        let mut subject = AccountantBuilder::default().build();
        let reschedule_on_error_resolver = RescheduleScanOnErrorResolverMock::default()
            .resolve_rescheduling_on_error_result(ScanRescheduleAfterEarlyStop::Schedule(
                ScanType::Receivables,
            ));
        subject.scan_schedulers.reschedule_on_error_resolver =
            Box::new(reschedule_on_error_resolver);
        let system = System::new("test");
        let subject_addr = subject.start();

        subject_addr
            .try_send(ScanForNewPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        system.run();
    }

    #[test]
    fn accountant_does_not_initiate_another_scan_if_one_is_already_running() {
        init_test_logging();
        let test_name = "accountant_does_not_initiate_another_scan_if_one_is_already_running";
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let (blockchain_bridge, _, blockchain_bridge_recording) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(
                QualifiedPayablesMessage,
                QualifiedPayablesMessage
            ))
            .start();
        let qualified_payables_sub = blockchain_bridge_addr.clone().recipient();
        let (mut qualified_payables, _, _) =
            make_qualified_and_unqualified_payables(now, &payment_thresholds);
        let payable_1 = qualified_payables.remove(0);
        let payable_2 = qualified_payables.remove(0);
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(vec![payable_1.clone()])
            .non_pending_payables_result(vec![payable_2.clone()]);
        let mut config = bc_from_earning_wallet(make_wallet("mine"));
        config.payment_thresholds_opt = Some(payment_thresholds);
        let system = System::new(test_name);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .logger(Logger::new(test_name))
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .bootstrapper_config(config)
            .build();
        let message_before = ScanForNewPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 111,
                context_id: 222,
            }),
        };
        let message_simultaneous = ScanForNewPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 999,
                context_id: 888,
            }),
        };
        let message_after = ScanForNewPayables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 333,
                context_id: 444,
            }),
        };
        subject.qualified_payables_sub_opt = Some(qualified_payables_sub);
        bind_ui_gateway_unasserted(&mut subject);
        // important
        subject.scan_schedulers.automatic_scans_enabled = false;
        let addr = subject.start();
        addr.try_send(message_before.clone()).unwrap();

        addr.try_send(message_simultaneous).unwrap();

        // We ignored the second ScanForNewPayables message as there was already in progress from
        // the first message. Now we reset the state by ending the first scan by a failure and see
        // that the third scan request is going to be accepted willingly again.
        addr.try_send(SentPayables {
            payment_procedure_result: Err(PayableTransactionError::Signing("bluh".to_string())),
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1122,
                context_id: 7788,
            }),
        })
        .unwrap();
        addr.try_send(message_after.clone()).unwrap();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording.lock().unwrap();
        let first_message_actual: &QualifiedPayablesMessage =
            blockchain_bridge_recording.get_record(0);
        assert_eq!(
            first_message_actual.response_skeleton_opt,
            message_before.response_skeleton_opt
        );
        let second_message_actual: &QualifiedPayablesMessage =
            blockchain_bridge_recording.get_record(1);
        assert_eq!(
            second_message_actual.response_skeleton_opt,
            message_after.response_skeleton_opt
        );
        let messages_received = blockchain_bridge_recording.len();
        assert_eq!(messages_received, 2);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {}: Payables scan was already initiated",
            test_name
        ));
    }

    #[test]
    fn scan_for_pending_payables_finds_still_pending_payables() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(RequestTransactionReceipts))
            .start();
        let payable_fingerprint_1 = PendingPayableFingerprint {
            rowid: 555,
            timestamp: from_unix_timestamp(210_000_000),
            hash: make_tx_hash(45678),
            attempt: 1,
            amount: 4444,
            process_error: None,
        };
        let payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: 550,
            timestamp: from_unix_timestamp(210_000_100),
            hash: make_tx_hash(112233),
            attempt: 2,
            amount: 7999,
            process_error: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_errorless_fingerprints_result(vec![
                payable_fingerprint_1.clone(),
                payable_fingerprint_2.clone(),
            ]);
        let config = bc_from_earning_wallet(make_wallet("mine"));
        let system = System::new("pending payable scan");
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .bootstrapper_config(config)
            .build();

        subject.request_transaction_receipts_sub_opt = Some(blockchain_bridge_addr.recipient());
        let account_addr = subject.start();

        let _ = account_addr
            .try_send(ScanForPendingPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let received_msg = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            received_msg,
            &RequestTransactionReceipts {
                pending_payable_fingerprints: vec![payable_fingerprint_1, payable_fingerprint_2],
                response_skeleton_opt: None,
            }
        );
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Found 2 pending payables to process");
    }

    #[test]
    fn start_scan_error_in_pending_payables_if_initial_scan_is_true_and_no_consuming_wallet_found()
    {
        let pending_payables_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payables_notify_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default().build();
        subject.consuming_wallet_opt = None;
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&pending_payables_notify_later_params_arc)
                .stop_system_on_count_received(1),
        );
        subject.scan_schedulers.pending_payable.interval = Duration::from_secs(60);
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&new_payables_notify_params_arc));
        let system = System::new("test");
        let subject_addr = subject.start();

        subject_addr
            .try_send(ScanForPendingPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        system.run();
        let pending_payables_notify_later_params =
            pending_payables_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payables_notify_later_params,
            vec![(
                ScanForPendingPayables {
                    response_skeleton_opt: None
                },
                Duration::from_secs(60)
            )]
        );
        let new_payables_notify_params = new_payables_notify_params_arc.lock().unwrap();
        assert_eq!(
            new_payables_notify_params.len(),
            0,
            "Did not expect the new payables request"
        );
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Early stopped pending payable scan \
        was suggested to be followed up by the scan for Receivables, which is not supported though"
    )]
    fn start_scan_error_in_pending_payables_and_unexpected_reaction_by_receivable_scan_scheduling()
    {
        let mut subject = AccountantBuilder::default().build();
        let reschedule_on_error_resolver = RescheduleScanOnErrorResolverMock::default()
            .resolve_rescheduling_on_error_result(ScanRescheduleAfterEarlyStop::Schedule(
                ScanType::Receivables,
            ));
        subject.scan_schedulers.reschedule_on_error_resolver =
            Box::new(reschedule_on_error_resolver);
        let system = System::new("test");
        let subject_addr = subject.start();

        subject_addr
            .try_send(ScanForPendingPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        system.run();
    }

    #[test]
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let bootstrapper_config = bc_from_earning_wallet(make_wallet("hi"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bootstrapper_config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let paying_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                timestamp: now,
                paying_wallet: paying_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (now, make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Charging routing of 1234 bytes to wallet {}",
            paying_wallet
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("our consuming wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("our earning wallet"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                timestamp: SystemTime::now(),
                paying_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("our earning wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                timestamp: SystemTime::now(),
                paying_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            earning_wallet,
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let config = bc_from_earning_wallet(make_wallet("hi"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let paying_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                timestamp: now,
                paying_wallet: paying_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (now, make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Charging exit service for 1234 bytes to wallet {}",
            paying_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("my consuming wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("my earning wallet"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                timestamp: SystemTime::now(),
                paying_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("my earning wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao_mock)])
            .build();
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                timestamp: SystemTime::now(),
                paying_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop();
        system.run();
        assert!(more_money_receivable_parameters_arc
            .lock()
            .unwrap()
            .is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            earning_wallet,
        ));
    }

    #[test]
    fn report_services_consumed_message_is_received() {
        init_test_logging();
        let config = make_bc_with_defaults();
        let more_money_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .more_money_payable_params(more_money_payable_params_arc.clone())
            .more_money_payable_result(Ok(()))
            .more_money_payable_result(Ok(()))
            .more_money_payable_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .build();
        subject.message_id_generator = Box::new(MessageIdGeneratorMock::default().id_result(123));
        let system = System::new("report_services_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();
        let earning_wallet_exit = make_wallet("exit");
        let earning_wallet_routing_1 = make_wallet("routing 1");
        let earning_wallet_routing_2 = make_wallet("routing 2");
        let timestamp = SystemTime::now();

        subject_addr
            .try_send(ReportServicesConsumedMessage {
                timestamp,
                exit: ExitServiceConsumed {
                    earning_wallet: earning_wallet_exit.clone(),
                    payload_size: 1200,
                    service_rate: 120,
                    byte_rate: 30,
                },
                routing_payload_size: 3456,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: earning_wallet_routing_1.clone(),
                        service_rate: 42,
                        byte_rate: 24,
                    },
                    RoutingServiceConsumed {
                        earning_wallet: earning_wallet_routing_2.clone(),
                        service_rate: 52,
                        byte_rate: 33,
                    },
                ],
            })
            .unwrap();

        System::current().stop();
        system.run();
        let more_money_payable_params = more_money_payable_params_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_params
                .iter()
                .map(|(timestamp, wallet, amount)| (timestamp, wallet, amount))
                .collect::<Vec<_>>(),
            vec![
                (&timestamp, &earning_wallet_exit, &((1 * 120) + (1200 * 30))),
                (
                    &timestamp,
                    &earning_wallet_routing_1,
                    &((1 * 42) + (3456 * 24))
                ),
                (
                    &timestamp,
                    &earning_wallet_routing_2,
                    &((1 * 52) + (3456 * 33))
                )
            ]
        );
        let test_log_handler = TestLogHandler::new();

        test_log_handler.exists_log_containing(&format!(
            "DEBUG: Accountant: MsgId 123: Accruing debt to {} for consuming 1200 exited bytes",
            earning_wallet_exit
        ));
        test_log_handler.exists_log_containing(&format!(
            "DEBUG: Accountant: MsgId 123: Accruing debt to {} for consuming 3456 routed bytes",
            earning_wallet_routing_1
        ));
        test_log_handler.exists_log_containing(&format!(
            "DEBUG: Accountant: MsgId 123: Accruing debt to {} for consuming 3456 routed bytes",
            earning_wallet_routing_2
        ));
    }

    fn assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
        config: BootstrapperConfig,
        message: ReportServicesConsumedMessage,
    ) -> Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>> {
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_result(Ok(()))
            .more_money_payable_params(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_daos(vec![ForAccountantBody(payable_dao_mock)])
            .build();
        let system = System::new("test");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr.try_send(message).unwrap();

        System::current().stop();
        system.run();
        more_money_payable_parameters_arc
    }

    #[test]
    fn routing_service_consumed_is_reported_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("the consuming wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("the earning wallet"));
        let foreign_wallet = make_wallet("exit wallet");
        let timestamp = SystemTime::now();
        let report_message = ReportServicesConsumedMessage {
            timestamp,
            exit: ExitServiceConsumed {
                earning_wallet: foreign_wallet.clone(),
                payload_size: 1234,
                service_rate: 45,
                byte_rate: 10,
            },
            routing_payload_size: 3333,
            routing: vec![RoutingServiceConsumed {
                earning_wallet: consuming_wallet.clone(),
                service_rate: 42,
                byte_rate: 6,
            }],
        };

        let more_money_payable_params_arc =
            assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
                config,
                report_message,
            );

        let more_money_payable_params = more_money_payable_params_arc.lock().unwrap();
        assert_eq!(
            *more_money_payable_params,
            //except processing the exit service there was no change in payables
            vec![(timestamp, foreign_wallet, (45 + 10 * 1234))]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a payable against our wallet {} for service we provided",
            consuming_wallet
        ));
    }

    #[test]
    fn routing_service_consumed_is_reported_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet =
            make_wallet("routing_service_consumed_is_reported_for_our_earning_wallet");
        let foreign_wallet = make_wallet("exit wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let timestamp = SystemTime::now();
        let report_message = ReportServicesConsumedMessage {
            timestamp,
            exit: ExitServiceConsumed {
                earning_wallet: foreign_wallet.clone(),
                payload_size: 1234,
                service_rate: 45,
                byte_rate: 10,
            },
            routing_payload_size: 3333,
            routing: vec![RoutingServiceConsumed {
                earning_wallet: earning_wallet.clone(),
                service_rate: 42,
                byte_rate: 6,
            }],
        };

        let more_money_payable_params_arc =
            assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
                config,
                report_message,
            );

        let more_money_payable_params = more_money_payable_params_arc.lock().unwrap();
        assert_eq!(
            *more_money_payable_params,
            //except processing the exit service there was no change in payables
            vec![(timestamp, foreign_wallet, (45 + 10 * 1234))]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a payable against our wallet {} for service we provided",
            earning_wallet
        ));
    }

    #[test]
    fn exit_service_consumed_is_reported_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet =
            make_wallet("exit_service_consumed_is_reported_for_our_consuming_wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("own earning wallet"));
        let report_message = ReportServicesConsumedMessage {
            timestamp: SystemTime::now(),
            exit: ExitServiceConsumed {
                earning_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            },
            routing_payload_size: 3333,
            routing: vec![],
        };

        let more_money_payable_params_arc =
            assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
                config,
                report_message,
            );

        assert!(more_money_payable_params_arc.lock().unwrap().is_empty());
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a payable against our wallet {} for service we provided",
            consuming_wallet
        ));
    }

    #[test]
    fn exit_service_consumed_is_reported_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("own earning wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let report_message = ReportServicesConsumedMessage {
            timestamp: SystemTime::now(),
            exit: ExitServiceConsumed {
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            },
            routing_payload_size: 3333,
            routing: vec![],
        };

        let more_money_payable_params_arc =
            assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
                config,
                report_message,
            );

        assert!(more_money_payable_params_arc.lock().unwrap().is_empty());
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: Accountant: Declining to record a payable against our wallet {} for service we provided",
            earning_wallet
        ));
    }

    #[test]
    #[should_panic(
        expected = "Recording services provided for 0x000000000000000000000000000000626f6f6761 \
    but has hit fatal database error: RusqliteError(\"we cannot help ourselves; this is baaad\")"
    )]
    fn record_service_provided_panics_on_fatal_errors() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let receivable_dao = ReceivableDaoMock::new().more_money_receivable_result(Err(
            ReceivableDaoError::RusqliteError(
                "we cannot help ourselves; this is baaad".to_string(),
            ),
        ));
        let subject = AccountantBuilder::default()
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();

        let _ = subject.record_service_provided(i64::MAX as u64, 1, SystemTime::now(), 2, &wallet);
    }

    #[test]
    fn record_service_provided_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_receivable_result(Err(ReceivableDaoError::SignConversion(1234)));
        let subject = AccountantBuilder::default()
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();

        subject.record_service_provided(i64::MAX as u64, 1, SystemTime::now(), 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error recording service provided for {}: service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            i64::MAX as u64
        ));
    }

    #[test]
    fn record_service_consumed_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let payable_dao = PayableDaoMock::new()
            .more_money_payable_result(Err(PayableDaoError::SignConversion(1234)));
        let subject = AccountantBuilder::default()
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .build();
        let service_rate = i64::MAX as u64;

        subject.record_service_consumed(service_rate, 1, SystemTime::now(), 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error recording consumed services from {}: total charge {}, service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            i64::MAX as u64 + 1 * 2,
            i64::MAX as u64
        ));
    }

    #[test]
    #[should_panic(
        expected = "Recording services consumed from 0x000000000000000000000000000000626f6f6761 but \
     has hit fatal database error: RusqliteError(\"we cannot help ourselves; this is baaad\")"
    )]
    fn record_service_consumed_panics_on_fatal_errors() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let payable_dao = PayableDaoMock::new().more_money_payable_result(Err(
            PayableDaoError::RusqliteError("we cannot help ourselves; this is baaad".to_string()),
        ));
        let subject = AccountantBuilder::default()
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .build();

        let _ = subject.record_service_consumed(i64::MAX as u64, 1, SystemTime::now(), 2, &wallet);
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn accountant_can_be_crashed_properly_but_not_improperly() {
        let mut config = make_bc_with_defaults();
        config.crash_point = CrashPoint::Message;
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();

        prove_that_crash_request_handler_is_hooked_up(accountant, CRASH_KEY);
    }

    #[test]
    fn accountant_processes_sent_payables_and_schedules_pending_payable_scanner() {
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payables_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_wallet = make_wallet("paying_you");
        let expected_hash = H256::from("transaction_hash".keccak256());
        let expected_rowid = 45623;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(expected_rowid, expected_hash)],
                no_rowid_results: vec![],
            });
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payables_rowids_params(&mark_pending_payables_rowids_params_arc)
            .mark_pending_payables_rowids_result(Ok(()));
        let system =
            System::new("accountant_processes_sent_payables_and_schedules_pending_payable_scanner");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPayableScanner(pending_payable_dao)])
            .build();
        let pending_payable_interval = Duration::from_millis(55);
        subject.scan_schedulers.pending_payable.interval = pending_payable_interval;
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&pending_payable_notify_later_params_arc),
        );
        let expected_payable = PendingPayable::new(expected_wallet.clone(), expected_hash.clone());
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![ProcessedPayableFallible::Correct(
                expected_payable.clone(),
            )]),
            response_skeleton_opt: None,
        };
        let addr = subject.start();

        addr.try_send(sent_payable).expect("unexpected actix error");

        System::current().stop();
        system.run();
        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(*fingerprints_rowids_params, vec![vec![expected_hash]]);
        let mark_pending_payables_rowids_params =
            mark_pending_payables_rowids_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payables_rowids_params,
            vec![vec![(expected_wallet, expected_rowid)]]
        );
        let pending_payable_notify_later_params =
            pending_payable_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payable_notify_later_params,
            vec![(ScanForPendingPayables::default(), pending_payable_interval)]
        );
        // The accountant is unbound here. We don't use the bind message. It means we can prove
        // none of those other scan requests could have been sent (especially ScanForNewPayables,
        // ScanForRetryPayables)
    }

    #[test]
    fn no_payables_left_the_node_so_payable_scan_is_rescheduled_as_pending_payable_scan_was_omitted(
    ) {
        init_test_logging();
        let test_name = "no_payables_left_the_node_so_payable_scan_is_rescheduled_as_pending_payable_scan_was_omitted";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                ScannerMock::default()
                    .finish_scan_params(&finish_scan_params_arc)
                    .finish_scan_result(PayableScanResult {
                        ui_response_opt: None,
                        result: OperationOutcome::Failure,
                    }),
            )));
        // Important. Otherwise, the scan would've been handled through a different endpoint and
        // gone for a very long time
        subject
            .scan_schedulers
            .payable
            .inner
            .lock()
            .unwrap()
            .last_new_payable_scan_timestamp = SystemTime::now();
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&payable_notify_later_params_arc),
        );
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let sent_payable = SentPayables {
            payment_procedure_result: Err(PayableTransactionError::Sending {
                msg: "booga".to_string(),
                hashes: vec![make_tx_hash(456)],
            }),
            response_skeleton_opt: None,
        };
        let addr = subject.start();

        addr.try_send(sent_payable.clone())
            .expect("unexpected actix error");

        System::current().stop();
        assert_eq!(system.run(), 0);
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (actual_sent_payable, logger) = finish_scan_params.remove(0);
        assert_eq!(actual_sent_payable, sent_payable,);
        assert_using_the_same_logger(&logger, test_name, None);
        let mut payable_notify_later_params = payable_notify_later_params_arc.lock().unwrap();
        let (scheduled_msg, _interval) = payable_notify_later_params.remove(0);
        assert_eq!(scheduled_msg, ScanForNewPayables::default());
        assert!(
            payable_notify_later_params.is_empty(),
            "Should be empty but {:?}",
            payable_notify_later_params
        );
    }

    #[test]
    fn accountant_schedule_retry_payable_scanner_because_not_all_pending_payables_completed() {
        init_test_logging();
        let test_name =
            "accountant_schedule_retry_payable_scanner_because_not_all_pending_payables_completed";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let retry_payable_notify_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::PaymentRetryRequired);
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&retry_payable_notify_params_arc));
        let system = System::new(test_name);
        let (mut msg, _) =
            make_report_transaction_receipts_msg(vec![TxStatus::Pending, TxStatus::Failed]);
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 45,
            context_id: 7,
        });
        msg.response_skeleton_opt = response_skeleton_opt;
        let subject_addr = subject.start();

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (msg_actual, logger) = finish_scan_params.remove(0);
        assert_eq!(msg_actual, msg);
        let retry_payable_notify_params = retry_payable_notify_params_arc.lock().unwrap();
        assert_eq!(
            *retry_payable_notify_params,
            vec![ScanForRetryPayables {
                response_skeleton_opt
            }]
        );
        assert_using_the_same_logger(&logger, test_name, None)
    }

    #[test]
    fn accountant_confirms_payable_txs_and_schedules_the_new_payable_scanner_timely() {
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let compute_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let system = System::new("new_payable_scanner_timely");
        let mut subject = AccountantBuilder::default()
            .payable_daos(vec![ForPendingPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let last_new_payable_scan_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(3))
            .unwrap();
        let nominal_interval = Duration::from_secs(6);
        let expected_computed_interval = Duration::from_secs(3);
        let dyn_interval_computer = NewPayableScanDynIntervalComputerMock::default()
            .compute_interval_params(&compute_interval_params_arc)
            .compute_interval_result(Some(expected_computed_interval));
        subject.scan_schedulers.payable.new_payable_interval = nominal_interval;
        subject.scan_schedulers.payable.dyn_interval_computer = Box::new(dyn_interval_computer);
        subject
            .scan_schedulers
            .payable
            .inner
            .lock()
            .unwrap()
            .last_new_payable_scan_timestamp = last_new_payable_scan_timestamp;
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&new_payable_notify_arc));
        let subject_addr = subject.start();
        let (msg, two_fingerprints) = make_report_transaction_receipts_msg(vec![
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(123),
                block_number: U64::from(100),
            }),
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(234),
                block_number: U64::from(200),
            }),
        ]);

        subject_addr.try_send(msg).unwrap();

        System::current().stop();
        system.run();
        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transactions_confirmed_params, vec![two_fingerprints]);
        let mut compute_interval_params = compute_interval_params_arc.lock().unwrap();
        let (_, last_new_payable_timestamp_actual, scan_interval_actual) =
            compute_interval_params.remove(0);
        assert_eq!(
            last_new_payable_timestamp_actual,
            last_new_payable_scan_timestamp
        );
        assert_eq!(scan_interval_actual, nominal_interval);
        assert!(compute_interval_params.is_empty());
        let new_payable_notify_later = new_payable_notify_later_arc.lock().unwrap();
        assert_eq!(
            *new_payable_notify_later,
            vec![(ScanForNewPayables::default(), expected_computed_interval)]
        );
        let new_payable_notify = new_payable_notify_arc.lock().unwrap();
        assert!(
            new_payable_notify.is_empty(),
            "should be empty but was: {:?}",
            new_payable_notify
        )
    }

    #[test]
    fn accountant_confirms_payable_txs_and_schedules_the_delayed_new_payable_scanner_asap() {
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let compute_interval_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .payable_daos(vec![ForPendingPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let last_new_payable_scan_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(8))
            .unwrap();
        let nominal_interval = Duration::from_secs(6);
        let dyn_interval_computer = NewPayableScanDynIntervalComputerMock::default()
            .compute_interval_params(&compute_interval_params_arc)
            .compute_interval_result(None);
        subject.scan_schedulers.payable.new_payable_interval = nominal_interval;
        subject.scan_schedulers.payable.dyn_interval_computer = Box::new(dyn_interval_computer);
        subject
            .scan_schedulers
            .payable
            .inner
            .lock()
            .unwrap()
            .last_new_payable_scan_timestamp = last_new_payable_scan_timestamp;
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&new_payable_notify_arc));
        let subject_addr = subject.start();
        let (msg, two_fingerprints) = make_report_transaction_receipts_msg(vec![
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(123),
                block_number: U64::from(100),
            }),
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(234),
                block_number: U64::from(200),
            }),
        ]);

        subject_addr.try_send(msg).unwrap();

        let system = System::new("new_payable_scanner_asap");
        System::current().stop();
        system.run();
        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transactions_confirmed_params, vec![two_fingerprints]);
        let mut compute_interval_params = compute_interval_params_arc.lock().unwrap();
        let (_, last_new_payable_timestamp_actual, scan_interval_actual) =
            compute_interval_params.remove(0);
        assert_eq!(
            last_new_payable_timestamp_actual,
            last_new_payable_scan_timestamp
        );
        assert_eq!(scan_interval_actual, nominal_interval);
        assert!(compute_interval_params.is_empty());
        let new_payable_notify_later = new_payable_notify_later_arc.lock().unwrap();
        assert!(
            new_payable_notify_later.is_empty(),
            "should be empty but was: {:?}",
            new_payable_notify_later
        );
        let new_payable_notify = new_payable_notify_arc.lock().unwrap();
        assert_eq!(*new_payable_notify, vec![ScanForNewPayables::default()])
    }

    #[test]
    fn scheduler_for_new_payables_operates_with_proper_now_timestamp() {
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default().transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let system = System::new("scheduler_for_new_payables_operates_with_proper_now_timestamp");
        let mut subject = AccountantBuilder::default()
            .payable_daos(vec![ForPendingPayableScanner(payable_dao)])
            .pending_payable_daos(vec![ForPendingPayableScanner(pending_payable_dao)])
            .build();
        let last_new_payable_scan_timestamp = SystemTime::now()
            .checked_sub(Duration::from_millis(3500))
            .unwrap();
        let new_payable_interval = Duration::from_secs(6);
        subject.scan_schedulers.payable.new_payable_interval = new_payable_interval;
        subject
            .scan_schedulers
            .payable
            .inner
            .lock()
            .unwrap()
            .last_new_payable_scan_timestamp = last_new_payable_scan_timestamp;
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        let subject_addr = subject.start();
        let (msg, _) = make_report_transaction_receipts_msg(vec![
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(123),
                block_number: U64::from(100),
            }),
            TxStatus::Succeeded(TransactionBlock {
                block_hash: make_tx_hash(234),
                block_number: U64::from(200),
            }),
        ]);

        subject_addr.try_send(msg).unwrap();

        let before = SystemTime::now();
        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let new_payable_notify_later = new_payable_notify_later_arc.lock().unwrap();
        let (_, actual_interval) = new_payable_notify_later[0];
        let interval_computer = NewPayableScanDynIntervalComputerReal::default();
        let left_side_bound = interval_computer
            .compute_interval(
                before,
                last_new_payable_scan_timestamp,
                new_payable_interval,
            )
            .unwrap();
        let right_side_bound = interval_computer
            .compute_interval(after, last_new_payable_scan_timestamp, new_payable_interval)
            .unwrap();
        assert!(
            left_side_bound >= actual_interval && actual_interval >= right_side_bound,
            "expected actual {:?} to be between {:?} and {:?}",
            actual_interval,
            left_side_bound,
            right_side_bound
        );
    }

    fn make_report_transaction_receipts_msg(
        status_txs: Vec<TxStatus>,
    ) -> (ReportTransactionReceipts, Vec<PendingPayableFingerprint>) {
        let (receipt_result_fingerprint_pairs, fingerprints): (Vec<_>, Vec<_>) = status_txs
            .into_iter()
            .enumerate()
            .map(|(idx, status)| {
                let transaction_hash = make_tx_hash(idx as u32);
                let transaction_receipt_result = TransactionReceiptResult::RpcResponse(TxReceipt {
                    transaction_hash,
                    status,
                });
                let fingerprint = PendingPayableFingerprint {
                    rowid: idx as u64,
                    timestamp: from_unix_timestamp(1_000_000_000 * idx as i64),
                    hash: transaction_hash,
                    attempt: 2,
                    amount: 1_000_000 * idx as u128 * idx as u128,
                    process_error: None,
                };
                (
                    (transaction_receipt_result, fingerprint.clone()),
                    fingerprint,
                )
            })
            .unzip();

        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: receipt_result_fingerprint_pairs,
            response_skeleton_opt: None,
        };

        (msg, fingerprints)
    }

    #[test]
    fn accountant_handles_inserting_new_fingerprints() {
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .insert_fingerprints_params(&insert_fingerprint_params_arc)
            .insert_fingerprints_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_daos(vec![ForAccountantBody(pending_payable_dao)])
            .build();
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let timestamp = SystemTime::now();
        let hash_1 = make_tx_hash(0x6c81c);
        let amount_1 = 12345;
        let hash_2 = make_tx_hash(0x1b207);
        let amount_2 = 87654;
        let hash_and_amount_1 = HashAndAmount {
            hash: hash_1,
            amount: amount_1,
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: hash_2,
            amount: amount_2,
        };
        let init_params = vec![hash_and_amount_1, hash_and_amount_2];
        let init_fingerprints_msg = PendingPayableFingerprintSeeds {
            batch_wide_timestamp: timestamp,
            hashes_and_balances: init_params.clone(),
        };

        let _ = accountant_subs
            .init_pending_payable_fingerprints
            .try_send(init_fingerprints_msg)
            .unwrap();

        let system = System::new("ordering payment fingerprint test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let insert_fingerprint_params = insert_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *insert_fingerprint_params,
            vec![(vec![hash_and_amount_1, hash_and_amount_2], timestamp)]
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Saved new pending payable fingerprints for: \
             0x000000000000000000000000000000000000000000000000000000000006c81c, \
             0x000000000000000000000000000000000000000000000000000000000001b207",
        );
    }

    #[test]
    fn payable_fingerprint_insertion_clearly_failed_and_we_log_it_at_least() {
        //despite it doesn't end so here this event would be a cause of a later panic
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .insert_fingerprints_params(&insert_fingerprint_params_arc)
            .insert_fingerprints_result(Err(PendingPayableDaoError::InsertionFailed(
                "Crashed".to_string(),
            )));
        let amount = 2345;
        let transaction_hash = make_tx_hash(0x1c8);
        let hash_and_amount = HashAndAmount {
            hash: transaction_hash,
            amount,
        };
        let subject = AccountantBuilder::default()
            .pending_payable_daos(vec![ForAccountantBody(pending_payable_dao)])
            .build();
        let timestamp = SystemTime::now();
        let report_new_fingerprints = PendingPayableFingerprintSeeds {
            batch_wide_timestamp: timestamp,
            hashes_and_balances: vec![hash_and_amount],
        };

        let _ = subject.handle_new_pending_payable_fingerprints(report_new_fingerprints);

        let insert_fingerprint_params = insert_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *insert_fingerprint_params,
            vec![(vec![hash_and_amount], timestamp)]
        );
        TestLogHandler::new().exists_log_containing("ERROR: Accountant: Failed to process \
         new pending payable fingerprints due to 'InsertionFailed(\"Crashed\")', disabling the automated \
          confirmation for all these transactions: \
          0x00000000000000000000000000000000000000000000000000000000000001c8");
    }

    const EXAMPLE_RESPONSE_SKELETON: ResponseSkeleton = ResponseSkeleton {
        client_id: 1234,
        context_id: 4321,
    };

    const EXAMPLE_ERROR_MSG: &str = "My tummy hurts";

    fn setup_and_prepare_assertions_for_new_payables(
    ) -> Box<dyn FnOnce(&mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(|scan_schedulers: &mut ScanSchedulers| {
            // Setup
            let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
            scan_schedulers
                .payable
                .inner
                .lock()
                .unwrap()
                .last_new_payable_scan_timestamp = SystemTime::now();
            scan_schedulers.payable.dyn_interval_computer = Box::new(
                NewPayableScanDynIntervalComputerMock::default()
                    .compute_interval_result(Some(Duration::from_secs(152))),
            );
            scan_schedulers.payable.new_payable_notify_later = Box::new(
                NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
            );

            // Assertions
            Box::new(move || {
                let notify_later_params = notify_later_params_arc.lock().unwrap();
                assert_eq!(
                    *notify_later_params,
                    vec![(ScanForNewPayables::default(), Duration::from_secs(152))]
                );
            })
        })
    }

    fn setup_and_prepare_assertions_for_retry_payables(
    ) -> Box<dyn FnOnce(&mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(|scan_schedulers: &mut ScanSchedulers| {
            // Setup
            let retry_payable_notify_params_arc = Arc::new(Mutex::new(vec![]));
            scan_schedulers.payable.retry_payable_notify = Box::new(
                NotifyHandleMock::default().notify_params(&retry_payable_notify_params_arc),
            );

            // Assertions
            Box::new(move || {
                let retry_payable_notify_params = retry_payable_notify_params_arc.lock().unwrap();
                // Response skeleton must be None
                assert_eq!(
                    *retry_payable_notify_params,
                    vec![ScanForRetryPayables {
                        response_skeleton_opt: None
                    }]
                );
            })
        })
    }

    fn setup_and_prepare_assertions_for_pending_payables(
    ) -> Box<dyn FnOnce(&mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(|scan_schedulers: &mut ScanSchedulers| {
            // Setup
            let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
            scan_schedulers.pending_payable.interval = Duration::from_secs(600);
            scan_schedulers.pending_payable.handle = Box::new(
                NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
            );

            // Assertions
            Box::new(move || {
                let notify_later_params = notify_later_params_arc.lock().unwrap();
                assert_eq!(
                    *notify_later_params,
                    vec![(ScanForPendingPayables::default(), Duration::from_secs(600))]
                );
            })
        })
    }

    fn setup_and_prepare_assertions_for_receivables(
    ) -> Box<dyn FnOnce(&mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(|scan_schedulers: &mut ScanSchedulers| {
            // Setup
            let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
            scan_schedulers.receivable.interval = Duration::from_secs(600);
            scan_schedulers.receivable.handle = Box::new(
                NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
            );

            // Assertions
            Box::new(move || {
                let notify_later_params = notify_later_params_arc.lock().unwrap();
                assert_eq!(
                    *notify_later_params,
                    vec![(ScanForReceivables::default(), Duration::from_secs(600))]
                );
            })
        })
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_new_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_new_payables",
            ScanError {
                scan_type: DetailedScanType::NewPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_new_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_retry_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_retry_payables",
            ScanError {
                scan_type: DetailedScanType::RetryPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_retry_payables(),
        )
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_pending_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_pending_payables",
            ScanError {
                scan_type: DetailedScanType::PendingPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_pending_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_receivables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_receivables",
            ScanError {
                scan_type: DetailedScanType::Receivables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_receivables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_new_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_new_payables",
            ScanError {
                scan_type: DetailedScanType::NewPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_new_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_retry_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_retry_payables",
            ScanError {
                scan_type: DetailedScanType::RetryPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_retry_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_pending_payables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_pending_payables",
            ScanError {
                scan_type: DetailedScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_pending_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_receivables() {
        assert_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_receivables",
            ScanError {
                scan_type: DetailedScanType::Receivables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            setup_and_prepare_assertions_for_receivables(),
        );
    }

    #[test]
    fn financials_request_with_nothing_to_respond_to_is_refused() {
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiFinancialsRequest {
                stats_required: false,
                top_records_opt: None,
                custom_queries_opt: None,
            }
            .tmb(2222),
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(response.target, ClientId(1234));
        let error = UiFinancialsResponse::fmb(response.body.clone()).unwrap_err();
        let err_message_body = match error {
            UiMessageError::PayloadError(payload) => payload,
            x => panic!("we expected error message in the payload but got: {:?}", x),
        };
        let (err_code, err_message) = err_message_body.payload.unwrap_err();
        assert_eq!(err_code, REQUEST_WITH_NO_VALUES);
        assert_eq!(
            err_message,
            "Empty requests with missing queries not to be processed"
        );
        assert!(matches!(err_message_body.path, Conversation(2222)));
    }

    #[test]
    fn financials_request_allows_only_one_kind_of_view_into_books_at_a_time() {
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .build();
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: Some(TopRecordsConfig {
                count: 13,
                ordered_by: Age,
            }),
            custom_queries_opt: Some(CustomQueries {
                payable_opt: Some(RangeQuery {
                    min_age_s: 5000,
                    max_age_s: 11000,
                    min_amount_gwei: 1_454_050_000,
                    max_amount_gwei: 555_000_000_000,
                }),
                receivable_opt: None,
            }),
        };

        let result = subject.compute_financials(&request, 4567);

        assert_eq!(
            result,
            MessageBody {
                opcode: "financials".to_string(),
                path: Conversation(4567),
                payload: Err((
                    REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS,
                    "Requesting top records and the more customized subset of \
             records is not allowed both at the same time"
                        .to_string()
                ))
            }
        );
    }

    #[test]
    fn financials_request_produces_financials_response() {
        let payable_dao = PayableDaoMock::new().total_result(264_567_894_578);
        let receivable_dao = ReceivableDaoMock::new().total_result(987_654_328_996);
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .bootstrapper_config(make_bc_with_defaults())
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiFinancialsRequest {
                stats_required: true,
                top_records_opt: None,
                custom_queries_opt: None,
            }
            .tmb(2222),
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(response.target, ClientId(1234));
        let (body, context_id) = UiFinancialsResponse::fmb(response.body.clone()).unwrap();
        assert_eq!(context_id, 2222);
        assert_eq!(
            body,
            UiFinancialsResponse {
                stats_opt: Some(UiFinancialStatistics {
                    total_unpaid_and_pending_payable_gwei: 264,
                    total_paid_payable_gwei: 0,
                    total_unpaid_receivable_gwei: 987,
                    total_paid_receivable_gwei: 0,
                }),
                query_results_opt: None,
            }
        )
    }

    #[test]
    fn compute_financials_processes_defaulted_request() {
        let payable_dao = PayableDaoMock::new().total_result(u64::MAX as u128 + 123456);
        let receivable_dao = ReceivableDaoMock::new().total_result((i64::MAX as i128) * 3);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        subject
            .financial_statistics
            .borrow_mut()
            .total_paid_payable_wei = 172_345_602_235_454_454;
        subject
            .financial_statistics
            .borrow_mut()
            .total_paid_receivable_wei = 4_455_656_989_415_777_555;
        let context_id = 1234;
        let request = UiFinancialsRequest {
            stats_required: true,
            top_records_opt: None,
            custom_queries_opt: None,
        };

        let result = subject.compute_financials(&request, context_id);

        assert_eq!(
            result,
            UiFinancialsResponse {
                stats_opt: Some(UiFinancialStatistics {
                    total_unpaid_and_pending_payable_gwei: 18446744073,
                    total_paid_payable_gwei: 172345602,
                    total_unpaid_receivable_gwei: 27670116110,
                    total_paid_receivable_gwei: 4455656989
                }),
                query_results_opt: None
            }
            .tmb(context_id)
        )
    }

    macro_rules! extract_ages_from_accounts {
        ($main_structure: expr, $account_specific_field_opt: ident) => {{
            let accounts_collection = &$main_structure
                .query_results_opt
                .as_ref()
                .unwrap()
                .$account_specific_field_opt
                .as_ref()
                .unwrap();
            accounts_collection
                .iter()
                .map(|account| account.age_s)
                .collect::<Vec<u64>>()
        }};
    }

    #[test]
    fn compute_financials_processes_request_with_top_records_only_and_balance_ordering() {
        //take that the tested logic doesn't contain anything about an actual process of ordering,
        //that part is in the responsibility of the database manager, answering the specific SQL query
        let payable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_accounts_retrieved = vec![PayableAccount {
            wallet: make_wallet("abcd123"),
            balance_wei: 58_568_686_005,
            last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(5000)),
            pending_payable_opt: None,
        }];
        let payable_dao = PayableDaoMock::new()
            .custom_query_params(&payable_custom_query_params_arc)
            .custom_query_result(Some(payable_accounts_retrieved));
        let receivable_accounts_retrieved = vec![ReceivableAccount {
            wallet: make_wallet("efe4848"),
            balance_wei: 3_788_455_600_556_898,
            last_received_timestamp: SystemTime::now().sub(Duration::from_secs(6500)),
        }];
        let receivable_dao = ReceivableDaoMock::new()
            .custom_query_params(&receivable_custom_query_params_arc)
            .custom_query_result(Some(receivable_accounts_retrieved));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: Some(TopRecordsConfig {
                count: 6,
                ordered_by: Balance,
            }),
            custom_queries_opt: None,
        };
        let before = SystemTime::now();

        let result = subject.compute_financials(&request, context_id_expected);

        let after = SystemTime::now();
        let (computed_response, context_id) = UiFinancialsResponse::fmb(result).unwrap();
        let extracted_payable_ages = extract_ages_from_accounts!(computed_response, payable_opt);
        let extracted_receivable_ages =
            extract_ages_from_accounts!(computed_response, receivable_opt);
        assert_eq!(context_id, context_id_expected);
        assert_eq!(
            computed_response,
            UiFinancialsResponse {
                stats_opt: None,
                query_results_opt: Some(QueryResults {
                    payable_opt: Some(vec![UiPayableAccount {
                        wallet: make_wallet("abcd123").to_string(),
                        age_s: extracted_payable_ages[0],
                        balance_gwei: 58,
                        pending_payable_hash_opt: None
                    },]),
                    receivable_opt: Some(vec![UiReceivableAccount {
                        wallet: make_wallet("efe4848").to_string(),
                        age_s: extracted_receivable_ages[0],
                        balance_gwei: 3_788_455
                    },])
                }),
            }
        );
        let time_needed_for_the_act_in_full_sec =
            (after.duration_since(before).unwrap().as_millis() / 1000 + 1) as u64;
        assert!(
            extracted_payable_ages[0] >= 5000
                && extracted_payable_ages[0] <= 5000 + time_needed_for_the_act_in_full_sec
        );
        assert!(
            extracted_receivable_ages[0] >= 6500
                && extracted_receivable_ages[0] <= 6500 + time_needed_for_the_act_in_full_sec
        );
        let payable_custom_query_params = payable_custom_query_params_arc.lock().unwrap();
        assert_eq!(
            *payable_custom_query_params,
            vec![CustomQuery::TopRecords {
                count: 6,
                ordered_by: Balance
            }]
        );
        let receivable_custom_query_params = receivable_custom_query_params_arc.lock().unwrap();
        assert_eq!(
            *receivable_custom_query_params,
            vec![CustomQuery::TopRecords {
                count: 6,
                ordered_by: Balance
            }]
        )
    }

    #[test]
    fn compute_financials_processes_request_with_top_records_only_and_age_ordering() {
        let payable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .custom_query_params(&payable_custom_query_params_arc)
            .custom_query_result(None);
        let receivable_dao = ReceivableDaoMock::new()
            .custom_query_params(&receivable_custom_query_params_arc)
            .custom_query_result(None);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: Some(TopRecordsConfig {
                count: 80,
                ordered_by: Age,
            }),
            custom_queries_opt: None,
        };

        let result = subject.compute_financials(&request, context_id_expected);

        let (response, context_id) = UiFinancialsResponse::fmb(result).unwrap();
        assert_eq!(context_id, context_id_expected);
        assert_eq!(
            response,
            UiFinancialsResponse {
                stats_opt: None,
                query_results_opt: Some(QueryResults {
                    payable_opt: Some(vec![]),
                    receivable_opt: Some(vec![])
                })
            }
        );
        let payable_custom_query_params = payable_custom_query_params_arc.lock().unwrap();
        assert_eq!(
            *payable_custom_query_params,
            vec![CustomQuery::TopRecords {
                count: 80,
                ordered_by: Age
            }]
        );
        let receivable_custom_query_params = receivable_custom_query_params_arc.lock().unwrap();
        assert_eq!(
            *receivable_custom_query_params,
            vec![CustomQuery::TopRecords {
                count: 80,
                ordered_by: Age
            }]
        )
    }

    #[test]
    fn compute_financials_processes_request_with_range_queries_only() {
        let payable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_accounts_retrieved = vec![PayableAccount {
            wallet: make_wallet("abcd123"),
            balance_wei: 5_686_860_056,
            last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(7580)),
            pending_payable_opt: None,
        }];
        let payable_dao = PayableDaoMock::new()
            .custom_query_params(&payable_custom_query_params_arc)
            .custom_query_result(Some(payable_accounts_retrieved));
        let receivable_accounts_retrieved = vec![
            ReceivableAccount {
                wallet: make_wallet("efe4848"),
                balance_wei: 20_456_056_055_600_789,
                last_received_timestamp: SystemTime::now().sub(Duration::from_secs(3333)),
            },
            ReceivableAccount {
                wallet: make_wallet("bb123aa"),
                balance_wei: 550_555_565_233,
                last_received_timestamp: SystemTime::now().sub(Duration::from_secs(87000)),
            },
        ];
        let receivable_dao = ReceivableDaoMock::new()
            .custom_query_params(&receivable_custom_query_params_arc)
            .custom_query_result(Some(receivable_accounts_retrieved));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: Some(RangeQuery {
                    min_age_s: 0,
                    max_age_s: 8000,
                    min_amount_gwei: 0,
                    max_amount_gwei: 50_000_000,
                }),
                receivable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: 200000,
                    min_amount_gwei: 0,
                    max_amount_gwei: 60_000_000,
                }),
            }),
        };
        let before = SystemTime::now();

        let result = subject.compute_financials(&request, context_id_expected);

        let after = SystemTime::now();
        let (computed_response, context_id) = UiFinancialsResponse::fmb(result).unwrap();
        let extracted_payable_ages = extract_ages_from_accounts!(computed_response, payable_opt);
        let extracted_receivable_ages =
            extract_ages_from_accounts!(computed_response, receivable_opt);
        assert_eq!(context_id, context_id_expected);
        assert_eq!(
            computed_response,
            UiFinancialsResponse {
                stats_opt: None,
                query_results_opt: Some(QueryResults {
                    payable_opt: Some(vec![UiPayableAccount {
                        wallet: make_wallet("abcd123").to_string(),
                        age_s: extracted_payable_ages[0],
                        balance_gwei: 5,
                        pending_payable_hash_opt: None
                    },]),
                    receivable_opt: Some(vec![
                        UiReceivableAccount {
                            wallet: make_wallet("efe4848").to_string(),
                            age_s: extracted_receivable_ages[0],
                            balance_gwei: 20_456_056
                        },
                        UiReceivableAccount {
                            wallet: make_wallet("bb123aa").to_string(),
                            age_s: extracted_receivable_ages[1],
                            balance_gwei: 550,
                        }
                    ])
                })
            }
        );
        let time_needed_for_the_act_in_full_sec =
            (after.duration_since(before).unwrap().as_millis() / 1000 + 1) as u64;
        assert!(
            7580 <= extracted_payable_ages[0]
                && extracted_payable_ages[0] <= 7580 + time_needed_for_the_act_in_full_sec
        );
        assert!(
            3333 <= extracted_receivable_ages[0]
                && extracted_receivable_ages[0] <= 3333 + time_needed_for_the_act_in_full_sec
        );
        assert!(
            87000 <= extracted_receivable_ages[1]
                && extracted_receivable_ages[1] <= 87000 + time_needed_for_the_act_in_full_sec
        );
        let payable_custom_query_params = payable_custom_query_params_arc.lock().unwrap();
        let actual_timestamp = extract_timestamp_from_custom_query(&payable_custom_query_params[0]);
        assert_eq!(
            *payable_custom_query_params,
            vec![CustomQuery::RangeQuery {
                min_age_s: 0,
                max_age_s: 8000,
                min_amount_gwei: 0,
                max_amount_gwei: 50000000,
                timestamp: actual_timestamp
            }]
        );
        assert!(
            before <= actual_timestamp && actual_timestamp <= after,
            "before: {:?}, actual: {:?}, after: {:?}",
            before,
            actual_timestamp,
            after
        );
        let receivable_custom_query_params = receivable_custom_query_params_arc.lock().unwrap();
        let actual_timestamp =
            extract_timestamp_from_custom_query(&receivable_custom_query_params[0]);
        assert_eq!(
            *receivable_custom_query_params,
            vec![CustomQuery::RangeQuery {
                min_age_s: 2000,
                max_age_s: 200000,
                min_amount_gwei: 0,
                max_amount_gwei: 60000000,
                timestamp: actual_timestamp
            }]
        );
        assert!(
            before <= actual_timestamp && actual_timestamp <= after,
            "before: {:?}, actual: {:?}, after: {:?}",
            before,
            actual_timestamp,
            after
        )
    }

    fn extract_timestamp_from_custom_query<T>(captured_input: &CustomQuery<T>) -> SystemTime {
        if let CustomQuery::RangeQuery { timestamp, .. } = captured_input {
            *timestamp
        } else {
            panic!("we expected range query whose part is also a timestamp")
        }
    }

    #[test]
    fn compute_financials_allows_range_query_to_be_aimed_only_at_one_table() {
        let receivable_custom_query_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_accounts_retrieved = vec![ReceivableAccount {
            wallet: make_wallet("efe4848"),
            balance_wei: 60055600789,
            last_received_timestamp: SystemTime::now().sub(Duration::from_secs(3333)),
        }];
        let receivable_dao = ReceivableDaoMock::new()
            .custom_query_params(&receivable_custom_query_params_arc)
            .custom_query_result(Some(receivable_accounts_retrieved));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: None,
                receivable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: 200000,
                    min_amount_gwei: 0,
                    max_amount_gwei: 150000000000,
                }),
            }),
        };

        let result = subject.compute_financials(&request, context_id_expected);

        let (response, _) = UiFinancialsResponse::fmb(result).unwrap();
        let response_guts = response.query_results_opt.unwrap();
        assert_eq!(response_guts.payable_opt.is_some(), false);
        assert_eq!(response_guts.receivable_opt.is_some(), true);
    }

    fn assert_compute_financials_tests_range_query_on_too_big_values_in_input(
        request: UiFinancialsRequest,
        err_msg: &str,
    ) {
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .build();
        let context_id_expected = 1234;

        let result = subject.compute_financials(&request, context_id_expected);

        assert_eq!(
            result,
            MessageBody {
                opcode: "financials".to_string(),
                path: Conversation(context_id_expected),
                payload: Err((VALUE_EXCEEDS_ALLOWED_LIMIT, err_msg.to_string()))
            }
        );
    }

    #[test]
    fn compute_financials_tests_range_query_of_payables_on_too_big_values_in_input() {
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: 50000,
                    min_amount_gwei: 0,
                    max_amount_gwei: u64::MAX,
                }),
                receivable_opt: None,
            }),
        };

        assert_compute_financials_tests_range_query_on_too_big_values_in_input(
            request,
            "Range query for payable: Max amount requested too big. \
             Should be less than or equal to 9223372036854775807, not: 18446744073709551615",
        )
    }

    #[test]
    fn compute_financials_tests_range_query_of_receivables_on_too_big_values_in_input() {
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: None,
                receivable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: u64::MAX,
                    min_amount_gwei: -55,
                    max_amount_gwei: 6666,
                }),
            }),
        };

        assert_compute_financials_tests_range_query_on_too_big_values_in_input(
            request,
            "Range query for receivable: Max age requested too big. \
             Should be less than or equal to 9223372036854775807, not: 18446744073709551615",
        )
    }

    #[test]
    #[should_panic(
        expected = "Broken code: PayableAccount with less than 1 gwei passed through db query \
     constraints; wallet: 0x0000000000000000000000000061626364313233, balance: 8686005"
    )]
    fn compute_financials_blows_up_on_screwed_sql_query_for_payables_returning_balance_smaller_than_one_gwei(
    ) {
        let payable_accounts_retrieved = vec![PayableAccount {
            wallet: make_wallet("abcd123"),
            balance_wei: 8_686_005,
            last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(5000)),
            pending_payable_opt: None,
        }];
        let payable_dao =
            PayableDaoMock::new().custom_query_result(Some(payable_accounts_retrieved));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForAccountantBody(payable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: 200000,
                    min_amount_gwei: 0,
                    max_amount_gwei: 150000000000,
                }),
                receivable_opt: None,
            }),
        };

        subject.compute_financials(&request, context_id_expected);
    }

    #[test]
    #[should_panic(
        expected = "Broken code: ReceivableAccount with balance between 1 and 0 gwei passed through \
     db query constraints; wallet: 0x0000000000000000000000000061626364313233, balance: 7686005"
    )]
    fn compute_financials_blows_up_on_screwed_sql_query_for_receivables_returning_balance_smaller_than_one_gwei(
    ) {
        let receivable_accounts_retrieved = vec![ReceivableAccount {
            wallet: make_wallet("abcd123"),
            balance_wei: 7_686_005,
            last_received_timestamp: SystemTime::now().sub(Duration::from_secs(5000)),
        }];
        let receivable_dao =
            ReceivableDaoMock::new().custom_query_result(Some(receivable_accounts_retrieved));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .receivable_daos(vec![ForAccountantBody(receivable_dao)])
            .build();
        let context_id_expected = 1234;
        let request = UiFinancialsRequest {
            stats_required: false,
            top_records_opt: None,
            custom_queries_opt: Some(CustomQueries {
                payable_opt: None,
                receivable_opt: Some(RangeQuery {
                    min_age_s: 2000,
                    max_age_s: 200000,
                    min_amount_gwei: 0,
                    max_amount_gwei: 150000000000,
                }),
            }),
        };

        subject.compute_financials(&request, context_id_expected);
    }

    #[test]
    #[cfg(not(feature = "no_test_share"))]
    fn msg_id_generates_numbers_only_if_debug_log_enabled() {
        let mut logger1 = Logger::new("msg_id_generator_off");
        logger1.set_level_for_test(Level::Info);
        let mut subject = AccountantBuilder::default().build();
        let msg_id_generator = MessageIdGeneratorMock::default().id_result(789); //we prepared a result just for one call
        subject.message_id_generator = Box::new(msg_id_generator);
        subject.logger = logger1;

        let id1 = subject.msg_id();

        let mut logger2 = Logger::new("msg_id_generator_on");
        logger2.set_level_for_test(Level::Debug);
        subject.logger = logger2;

        let id2 = subject.msg_id();

        assert_eq!(id1, 0);
        assert_eq!(id2, 789);
    }

    #[test]
    fn unsigned_to_signed_handles_zero() {
        let result = sign_conversion::<u64, i64>(0);

        assert_eq!(result, Ok(0i64));
    }

    #[test]
    fn unsigned_to_signed_handles_max_allowable() {
        let result = sign_conversion::<u64, i64>(i64::MAX as u64);

        assert_eq!(result, Ok(i64::MAX));
    }

    #[test]
    fn unsigned_to_signed_handles_max_plus_one() {
        let attempt = (i64::MAX as u64) + 1;
        let result = sign_conversion::<u64, i64>((i64::MAX as u64) + 1);

        assert_eq!(result, Err(attempt));
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 170141183460469231731687303715884105728: cannot be converted from u128 to i128"
    )]
    fn checked_conversion_works_for_overflow() {
        checked_conversion::<u128, i128>(i128::MAX as u128 + 1);
    }

    #[test]
    fn checked_conversion_without_panic() {
        let result = politely_checked_conversion::<u128, i128>(u128::MAX);

        assert_eq!(result, Err("Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128".to_string()))
    }

    #[test]
    fn gwei_to_wei_works() {
        let result: u128 = gwei_to_wei(12_546_u64);

        assert_eq!(result, 12_546_000_000_000)
    }

    #[test]
    fn wei_to_gwei_works() {
        let result: u64 = wei_to_gwei(127_800_050_500_u128);

        assert_eq!(result, 127)
    }

    #[test]
    #[should_panic(
        expected = "Overflow detected with 340282366920938463463374607431: cannot be converted from u128 to u64"
    )]
    fn wei_to_gwei_blows_up_on_overflow() {
        let _: u64 = wei_to_gwei(u128::MAX);
    }

    type RunSchedulersAssertions = Box<dyn Fn()>;

    fn assert_scan_error_is_handled_properly(
        test_name: &str,
        message: ScanError,
        set_up_schedulers_and_prepare_assertions: Box<
            dyn FnOnce(&mut ScanSchedulers) -> RunSchedulersAssertions,
        >,
    ) {
        init_test_logging();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("blah"))
            .logger(Logger::new(test_name))
            .build();
        subject.scanners.reset_scan_started(
            message.scan_type.into(),
            MarkScanner::Started(SystemTime::now()),
        );
        let run_schedulers_assertions =
            set_up_schedulers_and_prepare_assertions(&mut subject.scan_schedulers);
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(message.clone()).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |actor: &mut Accountant| {
                    let scan_started_at_opt =
                        actor.scanners.scan_started_at(message.scan_type.into());
                    assert_eq!(scan_started_at_opt, None);
                }),
            })
            .unwrap();
        System::current().stop();
        assert_eq!(system.run(), 0);
        run_schedulers_assertions();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        match message.response_skeleton_opt {
            Some(response_skeleton) => {
                let expected_message_sent_to_ui = NodeToUiMessage {
                    target: ClientId(response_skeleton.client_id),
                    body: MessageBody {
                        opcode: "scan".to_string(),
                        path: MessagePath::Conversation(response_skeleton.context_id),
                        payload: Err((
                            SCAN_ERROR,
                            format!("{:?} scan failed: '{}'", message.scan_type, message.msg),
                        )),
                    },
                };
                assert_eq!(
                    ui_gateway_recording.get_record::<NodeToUiMessage>(0),
                    &expected_message_sent_to_ui
                );
                TestLogHandler::new().assert_logs_contain_in_order(vec![
                    &format!("ERROR: {}: Received ScanError: {:?}", test_name, message),
                    &format!(
                        "ERROR: {}: Sending UiScanResponse: {:?}",
                        test_name, expected_message_sent_to_ui
                    ),
                ]);
            }
            None => {
                assert_eq!(ui_gateway_recording.len(), 0);
                let tlh = TestLogHandler::new();
                tlh.exists_log_containing(&format!(
                    "ERROR: {}: Received ScanError: {:?}",
                    test_name, message
                ));
                tlh.exists_no_log_containing(&format!(
                    "ERROR: {}: Sending UiScanResponse",
                    test_name
                ));
            }
        }
    }

    #[test]
    fn make_dao_factory_uses_panic_on_migration() {
        let data_dir = ensure_node_home_directory_exists(
            "accountant",
            "make_dao_factory_uses_panic_on_migration",
        );

        let act = |data_dir: &Path| {
            let factory = Accountant::dao_factory(data_dir);
            factory.make();
        };

        assert_on_initialization_with_panic_on_migration(&data_dir, &act);
    }

    fn bind_ui_gateway_unasserted(accountant: &mut Accountant) {
        accountant.ui_message_sub_opt = Some(make_recorder().0.start().recipient());
    }
}

#[cfg(test)]
pub mod exportable_test_parts {
    use super::*;
    use crate::accountant::test_utils::bc_from_earning_wallet;
    use crate::actor_system_factory::SubsFactory;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use crate::test_utils::actor_system_factory::BannedCacheLoaderMock;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_accountant_subs_from_recorder;
    use crate::test_utils::unshared_test_utils::{AssertionsMessage, SubsFactoryTestAddrLeaker};
    use actix::System;
    use crossbeam_channel::bounded;
    use masq_lib::test_utils::utils::ShouldWeRunTheTest::{GoAhead, Skip};
    use masq_lib::test_utils::utils::{
        check_if_source_code_is_attached, ensure_node_home_directory_exists, ShouldWeRunTheTest,
    };
    use regex::Regex;
    use std::env::current_dir;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;

    impl SubsFactory<Accountant, AccountantSubs> for SubsFactoryTestAddrLeaker<Accountant> {
        fn make(&self, addr: &Addr<Accountant>) -> AccountantSubs {
            self.send_leaker_msg_and_return_meaningless_subs(
                addr,
                make_accountant_subs_from_recorder,
            )
        }
    }

    fn verify_presence_of_user_defined_sqlite_fns_in_new_delinquencies_for_receivable_dao(
    ) -> ShouldWeRunTheTest {
        fn skip_down_to_first_line_saying_new_delinquencies(
            previous: impl Iterator<Item = String>,
        ) -> impl Iterator<Item = String> {
            previous
                .skip_while(|line| {
                    let adjusted_line: String = line
                        .chars()
                        .skip_while(|char| char.is_whitespace())
                        .collect();
                    !adjusted_line.starts_with("fn new_delinquencies(")
                })
                .skip(1)
        }
        fn assert_is_not_trait_definition(body_lines: impl Iterator<Item = String>) -> String {
            fn yield_if_contains_semicolon(line: &str) -> Option<String> {
                line.contains(';').then(|| line.to_string())
            }
            let mut semicolon_line_opt = None;
            let line_undivided_fn_body = body_lines
                .map(|line| {
                    if semicolon_line_opt.is_none() {
                        if let Some(result) = yield_if_contains_semicolon(&line) {
                            semicolon_line_opt = Some(result)
                        }
                    }
                    line
                })
                .collect::<String>();
            if let Some(line) = semicolon_line_opt {
                let regex = Regex::new(r"Vec<\w+>;").unwrap();
                if regex.is_match(&line) {
                    // The important part of the regex is the semicolon at the end. Trait
                    // implementations don't use it. They go on with an opening bracket of
                    // the function body. Its presence therefore signifies we have to do
                    // with a trait definition
                    panic!(
                        "The second parsed chunk of code is a trait definition \
                    and the implementation lies before it. Conventions say the opposite. Simply \
                    change the placement order in the production code."
                    )
                }
            }
            line_undivided_fn_body
        }
        fn scope_fn_new_delinquency_alone(reader: BufReader<File>) -> String {
            let all_lines_in_the_file = reader.lines().flatten();
            let lines_with_cut_fn_trait_definition =
                skip_down_to_first_line_saying_new_delinquencies(all_lines_in_the_file);
            let assumed_implemented_function_body =
                skip_down_to_first_line_saying_new_delinquencies(
                    lines_with_cut_fn_trait_definition,
                )
                .take_while(|line| {
                    let adjusted_line: String = line
                        .chars()
                        .skip_while(|char| char.is_whitespace())
                        .collect();
                    !adjusted_line.starts_with("fn")
                });
            assert_is_not_trait_definition(assumed_implemented_function_body)
        }
        fn user_defined_functions_detected(line_undivided_fn_body: &str) -> bool {
            line_undivided_fn_body.contains(" slope_drop_high_bytes(")
                && line_undivided_fn_body.contains(" slope_drop_low_bytes(")
        }

        let current_dir = current_dir().unwrap();
        let file_path = current_dir.join(PathBuf::from_iter([
            "src",
            "accountant",
            "db_access_objects",
            "receivable_dao.rs",
        ]));
        let file = match File::open(file_path) {
            Ok(file) => file,
            Err(_) => match check_if_source_code_is_attached(&current_dir) {
                Skip => return Skip,
                _ => panic!(
                    "if panics, the file receivable_dao.rs probably doesn't exist or \
                has moved to an unexpected location"
                ),
            },
        };
        let reader = BufReader::new(file);
        let function_body_ready_for_final_check = scope_fn_new_delinquency_alone(reader);
        if user_defined_functions_detected(&function_body_ready_for_final_check) {
            GoAhead
        } else {
            panic!(
                "was about to test user-defined SQLite functions (slope_drop_high_bytes and
            slope_drop_low_bytes) in new_delinquencies() but found out those are absent at the
            expected place and would leave falsely positive results"
            )
        }
    }

    pub fn test_accountant_is_constructed_with_upgraded_db_connection_recognizing_our_extra_sqlite_functions<
        A,
    >(
        test_module: &str,
        test_name: &str,
        act: A,
    ) where
        A: FnOnce(
            BootstrapperConfig,
            DbInitializerReal,
            BannedCacheLoaderMock,
            SubsFactoryTestAddrLeaker<Accountant>,
        ) -> AccountantSubs,
    {
        // precondition: .new_delinquencies() still encompasses the considered functions, otherwise
        // the test is false-positive
        if let Skip =
            verify_presence_of_user_defined_sqlite_fns_in_new_delinquencies_for_receivable_dao()
        {
            eprintln!(
                "skipping test {test_name} due to having been unable to find receivable_dao.rs"
            );
            return;
        };
        let data_dir = ensure_node_home_directory_exists(test_module, test_name);
        let _ = DbInitializerReal::default()
            .initialize(data_dir.as_ref(), DbInitializationConfig::test_default())
            .unwrap();
        let mut bootstrapper_config = bc_from_earning_wallet(make_wallet("mine"));
        bootstrapper_config.data_directory = data_dir;
        let db_initializer = DbInitializerReal::default();
        let banned_cache_loader = BannedCacheLoaderMock::default();
        let (tx, accountant_addr_rv) = bounded(1);
        let address_leaker = SubsFactoryTestAddrLeaker { address_leaker: tx };
        let system = System::new(test_name);

        act(
            bootstrapper_config,
            db_initializer,
            banned_cache_loader,
            address_leaker,
        );

        let accountant_addr = accountant_addr_rv.try_recv().unwrap();
        let assertion_msg = AssertionsMessage {
            assertions: Box::new(|accountant: &mut Accountant| {
                // Will crash a test if our user-defined SQLite fns have been unreachable;
                // We cannot rely on failures in the DAO tests, because Account's database connection
                // has to be set up specially first (we teach it about the extra functions) as we're
                // creating the actor

                accountant
                    .receivable_dao
                    .new_delinquencies(SystemTime::now(), &DEFAULT_PAYMENT_THRESHOLDS);
                // Don't move this to the main test, it could produce a deceiving result.
                // It wouldn't actually process this message. I don't know why exactly
                System::current().stop();
            }),
        };
        accountant_addr.try_send(assertion_msg).unwrap();
        assert_eq!(system.run(), 0);
        // We didn't blow up, it recognized the functions.
        // This is an example of the error: "no such function: slope_drop_high_bytes"
    }
}
