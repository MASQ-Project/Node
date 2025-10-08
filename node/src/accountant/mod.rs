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
use crate::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoError};
use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDao, SentTx};
use crate::accountant::db_access_objects::utils::{
    remap_payable_accounts, remap_receivable_accounts, CustomQuery, DaoFactoryReal, TxHash,
};
use crate::accountant::financials::visibility_restricted_module::{
    check_query_is_within_tech_limits, financials_entry_check,
};
use crate::accountant::scanners::payable_scanner::msgs::{
    InitialTemplatesMessage, PricedTemplatesMessage,
};
use crate::accountant::scanners::payable_scanner::utils::NextScanToRun;
use crate::accountant::scanners::pending_payable_scanner::utils::{
    PendingPayableScanResult, TxHashByTable,
};
use crate::accountant::scanners::scan_schedulers::{
    PayableSequenceScanner, ScanReschedulingAfterEarlyStop, ScanSchedulers,
};
use crate::accountant::scanners::{Scanners, StartScanError};
use crate::blockchain::blockchain_bridge::{
    BlockMarker, RegisterNewPendingPayables, RetrieveTransactions,
};
use crate::blockchain::blockchain_interface::data_structures::{
    BatchResults, BlockchainTransaction, StatusReadFromReceiptCheck,
};
use crate::blockchain::errors::rpc_errors::AppRpcError;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::DbInitializationConfig;
use crate::sub_lib::accountant::DaoFactories;
use crate::sub_lib::accountant::FinancialStatistics;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::ReportServicesConsumedMessage;
use crate::sub_lib::accountant::{AccountantSubs, DetailedScanType};
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
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::messages::{
    QueryResults, UiFinancialStatistics, UiPayableAccount, UiReceivableAccount, UiScanRequest,
};
use masq_lib::messages::{ScanType, UiFinancialsResponse, UiScanResponse};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{MessageBody, MessagePath, MessageTarget};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use std::any::type_name;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::default::Default;
use std::fmt::Display;
use std::ops::{Div, Mul};
use std::path::Path;
use std::rc::Rc;
use std::time::SystemTime;

pub const CRASH_KEY: &str = "ACCOUNTANT";
pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

pub struct Accountant {
    consuming_wallet_opt: Option<Wallet>,
    earning_wallet: Wallet,
    payable_dao: Box<dyn PayableDao>,
    receivable_dao: Box<dyn ReceivableDao>,
    sent_payable_dao: Box<dyn SentPayableDao>,
    crashable: bool,
    scanners: Scanners,
    scan_schedulers: ScanSchedulers,
    financial_statistics: Rc<RefCell<FinancialStatistics>>,
    outbound_payments_instructions_sub_opt: Option<Recipient<OutboundPaymentsInstructions>>,
    qualified_payables_sub_opt: Option<Recipient<InitialTemplatesMessage>>,
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

pub type TxReceiptResult = Result<StatusReadFromReceiptCheck, AppRpcError>;

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct TxReceiptsMessage {
    pub results: BTreeMap<TxHashByTable, TxReceiptResult>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PayableScanType {
    New,
    Retry,
}

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct SentPayables {
    pub payment_procedure_result: Result<BatchResults, String>,
    pub payable_scan_type: PayableScanType,
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
            ScanReschedulingAfterEarlyStop::Schedule(ScanType::Payables) => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            ScanReschedulingAfterEarlyStop::Schedule(ScanType::PendingPayables) => self
                .scan_schedulers
                .pending_payable
                .schedule(ctx, &self.logger),
            ScanReschedulingAfterEarlyStop::Schedule(scan_type) => unreachable!(
                "Early stopped pending payable scan was suggested to be followed up \
                by the scan for {:?}, which is not supported though",
                scan_type
            ),
            ScanReschedulingAfterEarlyStop::DoNotSchedule => {
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
            ScanReschedulingAfterEarlyStop::Schedule(ScanType::Payables) => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            ScanReschedulingAfterEarlyStop::Schedule(other_scan_type) => unreachable!(
                "Early stopped new payable scan was suggested to be followed up by the scan \
                for {:?}, which is not supported though",
                other_scan_type
            ),
            ScanReschedulingAfterEarlyStop::DoNotSchedule => {
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

impl Handler<TxReceiptsMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: TxReceiptsMessage, ctx: &mut Self::Context) -> Self::Result {
        match self.scanners.finish_pending_payable_scan(msg, &self.logger) {
            PendingPayableScanResult::NoPendingPayablesLeft(ui_msg_opt) => {
                if let Some(node_to_ui_msg) = ui_msg_opt {
                    self.ui_message_sub_opt
                        .as_ref()
                        .expect("UIGateway is not bound")
                        .try_send(node_to_ui_msg)
                        .expect("UIGateway is dead");
                    // Non-automatic scan for pending payables is not permitted to spark a payable
                    // scan bringing over new payables with fresh nonces. The job's done here.
                } else {
                    self.scan_schedulers
                        .payable
                        .schedule_new_payable_scan(ctx, &self.logger)
                }
            }
            PendingPayableScanResult::PaymentRetryRequired(response_skeleton_opt) => self
                .scan_schedulers
                .payable
                .schedule_retry_payable_scan(ctx, response_skeleton_opt, &self.logger),
            PendingPayableScanResult::ProcedureShouldBeRepeated(ui_msg_opt) => {
                if let Some(node_to_ui_msg) = ui_msg_opt {
                    info!(
                        self.logger,
                        "Re-running the pending payable scan is recommended, as some parts \
                        did not finish last time."
                    );
                    self.ui_message_sub_opt
                        .as_ref()
                        .expect("UIGateway is not bound")
                        .try_send(node_to_ui_msg)
                        .expect("UIGateway is dead");
                    // The repetition must be triggered by an external impulse
                } else {
                    self.scan_schedulers
                        .pending_payable
                        .schedule(ctx, &self.logger)
                }
            }
        };
    }
}

impl Handler<PricedTemplatesMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: PricedTemplatesMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_payable_payment_setup(msg)
    }
}

impl Handler<SentPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: SentPayables, ctx: &mut Self::Context) -> Self::Result {
        let scan_result = self.scanners.finish_payable_scan(msg, &self.logger);

        match scan_result.ui_response_opt {
            None => self.schedule_next_automatic_scan(scan_result.result, ctx),
            Some(node_to_ui_msg) => {
                self.ui_message_sub_opt
                    .as_ref()
                    .expect("UIGateway is not bound")
                    .try_send(node_to_ui_msg)
                    .expect("UIGateway is dead");

                // Externally triggered scans are not allowed to provoke an unwinding scan sequence
                // with intervals. The only exception is the PendingPayableScanner that is always
                // followed by the retry-payable scanner in a tight tandem.
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

        match scan_error.response_skeleton_opt {
            None => {
                debug!(
                    self.logger,
                    "Trying to restore the scan train after a crash"
                );
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
            }
            Some(response_skeleton) => {
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
    pub tx_hashes: Vec<TxHashByTable>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RequestTransactionReceipts {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

impl Handler<RegisterNewPendingPayables> for Accountant {
    type Result = ();
    fn handle(
        &mut self,
        msg: RegisterNewPendingPayables,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.register_new_pending_sent_tx(msg)
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
        let sent_payable_dao = dao_factories.sent_payable_dao_factory.make();
        let receivable_dao = dao_factories.receivable_dao_factory.make();
        let scan_schedulers = ScanSchedulers::new(scan_intervals, config.automatic_scans_enabled);
        let scanners = Scanners::new(
            dao_factories,
            Rc::new(payment_thresholds),
            Rc::clone(&financial_statistics),
        );

        Accountant {
            consuming_wallet_opt: config.consuming_wallet_opt.clone(),
            earning_wallet,
            payable_dao,
            receivable_dao,
            sent_payable_dao,
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
            report_payable_payments_setup: recipient!(addr, PricedTemplatesMessage),
            report_inbound_payments: recipient!(addr, ReceivedPayments),
            register_new_pending_payables: recipient!(addr, RegisterNewPendingPayables),
            report_transaction_status: recipient!(addr, TxReceiptsMessage),
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
                Err(e) => panic!("Was recording services provided for {} but hit a fatal database error: {:?}", wallet, e)
            };
        } else {
            warning!(
                self.logger,
                "Declining to record a receivable against our wallet {} for services we provided",
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
        trace!(
            self.logger,
            "Charging routing of {} bytes to wallet {}",
            msg.payload_size,
            msg.paying_wallet
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
        trace!(
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
        trace!(
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
            trace!(
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

    fn handle_payable_payment_setup(&mut self, msg: PricedTemplatesMessage) {
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
    ) -> ScanReschedulingAfterEarlyStop {
        let result: Result<InitialTemplatesMessage, StartScanError> =
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

        self.scan_schedulers.payable.reset_scan_timer(&self.logger);

        match result {
            Ok(scan_message) => {
                self.qualified_payables_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message)
                    .expect("BlockchainBridge is dead");
                ScanReschedulingAfterEarlyStop::DoNotSchedule
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
        let result: Result<InitialTemplatesMessage, StartScanError> =
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
                // It is thrown away and there is no rescheduling downstream because every error
                // happening here on the start resolves into a panic by the current design
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
    ) -> ScanReschedulingAfterEarlyStop {
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

        let hint: ScanReschedulingAfterEarlyStop = match result {
            Ok(scan_message) => {
                self.request_transaction_receipts_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message)
                    .expect("BlockchainBridge is dead");
                ScanReschedulingAfterEarlyStop::DoNotSchedule
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
    ) -> ScanReschedulingAfterEarlyStop {
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

    fn schedule_next_automatic_scan(
        &self,
        next_scan_to_run: NextScanToRun,
        ctx: &mut Context<Accountant>,
    ) {
        match next_scan_to_run {
            NextScanToRun::PendingPayableScan => self
                .scan_schedulers
                .pending_payable
                .schedule(ctx, &self.logger),
            NextScanToRun::NewPayableScan => self
                .scan_schedulers
                .payable
                .schedule_new_payable_scan(ctx, &self.logger),
            NextScanToRun::RetryPayableScan => self
                .scan_schedulers
                .payable
                .schedule_retry_payable_scan(ctx, None, &self.logger),
        }
    }

    fn register_new_pending_sent_tx(&self, msg: RegisterNewPendingPayables) {
        fn serialize_hashes(tx_hashes: &[SentTx]) -> String {
            join_with_commas(tx_hashes, |sent_tx| format!("{:?}", sent_tx.hash))
        }

        let sent_txs: BTreeSet<SentTx> = msg.new_sent_txs.iter().cloned().collect();

        match self.sent_payable_dao.insert_new_records(&sent_txs) {
            Ok(_) => debug!(
                self.logger,
                "Registered new pending payables for: {}",
                serialize_hashes(&msg.new_sent_txs)
            ),
            Err(e) => error!(
                self.logger,
                "Failed to save new pending payable records for {} due to '{:?}' which is integral \
                to the function of the automated tx confirmation",
                serialize_hashes(&msg.new_sent_txs),
                e
            ),
        }
    }

    fn financial_statistics(&self) -> Ref<'_, FinancialStatistics> {
        self.financial_statistics.borrow()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPayable {
    pub recipient_wallet: Wallet,
    pub hash: TxHash,
}

impl PendingPayable {
    pub fn new(recipient_wallet: Wallet, hash: TxHash) -> Self {
        Self {
            recipient_wallet,
            hash,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PendingPayableId {
    pub rowid: u64,
    pub hash: TxHash,
}

impl PendingPayableId {
    pub fn new(rowid: u64, hash: TxHash) -> Self {
        Self { rowid, hash }
    }
}

pub fn join_with_separator<T, F, I>(collection: I, stringify: F, separator: &str) -> String
where
    F: Fn(&T) -> String,
    I: IntoIterator<Item = T>,
{
    collection
        .into_iter()
        .map(|item| stringify(&item))
        .join(separator)
}

pub fn join_with_commas<T, F, I>(collection: I, stringify: F) -> String
where
    F: Fn(&T) -> String,
    I: IntoIterator<Item = T>,
{
    join_with_separator(collection, stringify, ", ")
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
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason};
    use crate::accountant::db_access_objects::payable_dao::{
        PayableAccount, PayableDaoError, PayableDaoFactory,
    };
    use crate::accountant::db_access_objects::receivable_dao::ReceivableAccount;
    use crate::accountant::db_access_objects::sent_payable_dao::{
        Detection, SentPayableDaoError, TxStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, TxBuilder,
    };
    use crate::accountant::db_access_objects::utils::{
        from_unix_timestamp, to_unix_timestamp, CustomQuery,
    };
    use crate::accountant::payment_adjuster::Adjustment;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::test_utils::{
        make_priced_new_tx_templates, make_retry_tx_template,
    };
    use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
    use crate::accountant::scanners::pending_payable_scanner::utils::TxByTable;
    use crate::accountant::scanners::scan_schedulers::{
        NewPayableScanIntervalComputer, NewPayableScanIntervalComputerReal, ScanTiming,
    };
    use crate::accountant::scanners::test_utils::{
        MarkScanner, NewPayableScanIntervalComputerMock, PendingPayableCacheMock, ReplacementType,
        RescheduleScanOnErrorResolverMock, ScannerMock, ScannerReplacement,
    };
    use crate::accountant::scanners::StartScanError;
    use crate::accountant::test_utils::DaoWithDestination::{
        ForAccountantBody, ForPayableScanner, ForPendingPayableScanner, ForReceivableScanner,
    };
    use crate::accountant::test_utils::{
        bc_from_earning_wallet, bc_from_wallets, make_payable_account,
        make_qualified_and_unqualified_payables, make_transaction_block, BannedDaoFactoryMock,
        ConfigDaoFactoryMock, DaoWithDestination, FailedPayableDaoFactoryMock,
        FailedPayableDaoMock, MessageIdGeneratorMock, PayableDaoFactoryMock, PayableDaoMock,
        PaymentAdjusterMock, PendingPayableScannerBuilder, ReceivableDaoFactoryMock,
        ReceivableDaoMock, SentPayableDaoFactoryMock, SentPayableDaoMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::Accountant;
    use crate::blockchain::blockchain_agent::test_utils::BlockchainAgentMock;
    use crate::blockchain::blockchain_interface::data_structures::{
        StatusReadFromReceiptCheck, TxBlock,
    };
    use crate::blockchain::errors::rpc_errors::RemoteError;
    use crate::blockchain::errors::validation_status::ValidationStatus;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::db_config::config_dao::ConfigDaoRecord;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::sub_lib::accountant::{
        ExitServiceConsumed, PaymentThresholds, RoutingServiceConsumed, ScanIntervals,
        DEFAULT_EARNING_WALLET, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
    use crate::sub_lib::neighborhood::ConfigChange;
    use crate::sub_lib::neighborhood::{Hops, WalletPair};
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::{make_recorder, PeerActorsBuilder, SetUpCounterMsgs};
    use crate::test_utils::recorder_counter_msgs::SingleTypeCounterMsgSetup;
    use crate::test_utils::recorder_stop_conditions::{MsgIdentification, StopConditions};
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::unshared_test_utils::notify_handlers::{
        NotifyHandleMock, NotifyLaterHandleMock,
    };
    use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
    use crate::test_utils::unshared_test_utils::{
        assert_on_initialization_with_panic_on_migration, make_bc_with_defaults,
        prove_that_crash_request_handler_is_hooked_up, AssertionsMessage,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use crate::{match_lazily_every_type_id, setup_for_counter_msg_triggered_via_type_id};
    use actix::System;
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use log::Level;
    use masq_lib::constants::{
        DEFAULT_CHAIN, REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS, REQUEST_WITH_NO_VALUES, SCAN_ERROR,
        VALUE_EXCEEDS_ALLOWED_LIMIT,
    };
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::messages::{
        CustomQueries, RangeQuery, TopRecordsConfig, UiFinancialStatistics, UiMessageError,
        UiPayableAccount, UiReceivableAccount, UiScanRequest, UiScanResponse,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};
    use std::any::TypeId;
    use std::collections::BTreeSet;
    use std::ops::Sub;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};
    use std::vec;
    use web3::types::H256;

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
        let config = make_bc_with_defaults(DEFAULT_CHAIN);
        let payable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao_factory_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_params(&payable_dao_factory_params_arc)
            .make_result(PayableDaoMock::new()) // For Accountant
            .make_result(PayableDaoMock::new()) // For Payable Scanner
            .make_result(PayableDaoMock::new()); // For PendingPayable Scanner
        let sent_payable_dao_factory = SentPayableDaoFactoryMock::new()
            .make_params(&sent_payable_dao_factory_params_arc)
            .make_result(SentPayableDaoMock::new()) // For Accountant
            .make_result(SentPayableDaoMock::new()) // For Payable Scanner
            .make_result(SentPayableDaoMock::new()); // For PendingPayable Scanner
        let failed_payable_dao_factory = FailedPayableDaoFactoryMock::new()
            .make_params(&failed_payable_dao_factory_params_arc)
            .make_result(FailedPayableDaoMock::new()) // For Payable Scanner
            .make_result(FailedPayableDaoMock::new().retrieve_txs_result(BTreeSet::new())); // For PendingPayableScanner;
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
                sent_payable_dao_factory: Box::new(sent_payable_dao_factory),
                failed_payable_dao_factory: Box::new(failed_payable_dao_factory),
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
            *sent_payable_dao_factory_params_arc.lock().unwrap(),
            vec![(), (), ()]
        );
        assert_eq!(
            *failed_payable_dao_factory_params_arc.lock().unwrap(),
            vec![(), ()]
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
        let chain = TEST_DEFAULT_CHAIN;
        let bootstrapper_config = make_bc_with_defaults(chain);
        let payable_dao_factory = Box::new(
            PayableDaoFactoryMock::new()
                .make_result(PayableDaoMock::new()) // For Accountant
                .make_result(PayableDaoMock::new()) // For Payable Scanner
                .make_result(PayableDaoMock::new()), // For PendingPayable Scanner
        );
        let failed_payable_dao_factory = Box::new(
            FailedPayableDaoFactoryMock::new()
                .make_result(FailedPayableDaoMock::new()) // For Payable Scanner
                .make_result(FailedPayableDaoMock::new()),
        ); // For PendingPayable Scanner
        let sent_payable_dao_factory = Box::new(
            SentPayableDaoFactoryMock::new()
                .make_result(SentPayableDaoMock::new()) // For Accountant
                .make_result(SentPayableDaoMock::new()) // For Payable Scanner
                .make_result(SentPayableDaoMock::new()),
        ); // For PendingPayable Scanner
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
                sent_payable_dao_factory,
                failed_payable_dao_factory,
                receivable_dao_factory,
                banned_dao_factory,
                config_dao_factory,
            },
        );

        let financial_statistics = result.financial_statistics().clone();
        let default_scan_intervals = ScanIntervals::compute_default(chain);
        result
            .scan_schedulers
            .payable
            .interval_computer
            .as_any()
            .downcast_ref::<NewPayableScanIntervalComputerReal>()
            .unwrap();
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
            .bootstrapper_config(make_bc_with_defaults(TEST_DEFAULT_CHAIN))
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
            PayableDaoMock::new().retrieve_payables_result(vec![payable_account.clone()]);
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .bootstrapper_config(config)
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(InitialTemplatesMessage));
        let blockchain_bridge_addr = blockchain_bridge.start();
        // Important
        subject.scan_schedulers.automatic_scans_enabled = false;
        subject.qualified_payables_sub_opt = Some(blockchain_bridge_addr.recipient());
        // Making sure we would get a panic if another scan was scheduled
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
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
        let expected_new_tx_templates = NewTxTemplates::from(&vec![payable_account]);
        assert_eq!(
            blockchain_bridge_recording.get_record::<InitialTemplatesMessage>(0),
            &InitialTemplatesMessage {
                initial_templates: Either::Left(expected_new_tx_templates),
                consuming_wallet,
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                })
            }
        );
    }

    #[test]
    fn sent_payables_with_response_skeleton_results_in_scan_response_to_ui_gateway() {
        let config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        let payable_dao = PayableDaoMock::default().mark_pending_payables_rowids_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let subject = AccountantBuilder::default()
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .sent_payable_daos(vec![DaoWithDestination::ForPayableScanner(
                sent_payable_dao,
            )])
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        let sent_payables = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![make_sent_tx(1)],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(sent_payables).unwrap();

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
        let priced_new_templates = make_priced_new_tx_templates(vec![
            (account_1, 1_000_000_001),
            (account_2, 1_000_000_002),
        ]);
        let msg = PricedTemplatesMessage {
            priced_templates: Either::Left(priced_new_templates.clone()),
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
            blockchain_agent_with_context_msg_actual.priced_templates,
            Either::Left(priced_new_templates.clone())
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
            payments_instructions.priced_templates,
            Either::Left(priced_new_templates.clone())
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
        let initial_unadjusted_accounts = make_priced_new_tx_templates(vec![
            (unadjusted_account_1.clone(), 111_222_333),
            (unadjusted_account_2.clone(), 222_333_444),
        ]);
        let msg = PricedTemplatesMessage {
            priced_templates: Either::Left(initial_unadjusted_accounts.clone()),
            agent: Box::new(agent),
            response_skeleton_opt: Some(response_skeleton),
        };
        // In the real world the agents are identical, here they bear different ids
        // so that we can watch their journey better
        let agent_id_stamp_second_phase = ArbitraryIdStamp::new();
        let agent =
            BlockchainAgentMock::default().set_arbitrary_id_stamp(agent_id_stamp_second_phase);
        let affordable_accounts = make_priced_new_tx_templates(vec![
            (adjusted_account_1.clone(), 111_222_333),
            (adjusted_account_2.clone(), 222_333_444),
        ]);
        let payments_instructions = OutboundPaymentsInstructions {
            priced_templates: Either::Left(affordable_accounts.clone()),
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
                .priced_templates,
            Either::Left(initial_unadjusted_accounts)
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
            payments_instructions.priced_templates,
            Either::Left(affordable_accounts)
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
        let sent_tx = make_sent_tx(555);
        let tx_hash = sent_tx.hash;
        let sent_payable_dao =
            SentPayableDaoMock::default().retrieve_txs_result(BTreeSet::from([sent_tx]));
        let failed_payable_dao =
            FailedPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_paying_wallet(b"consuming"))
            .bootstrapper_config(config)
            .sent_payable_daos(vec![ForPendingPayableScanner(sent_payable_dao)])
            .failed_payable_daos(vec![ForPendingPayableScanner(failed_payable_dao)])
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
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
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
                tx_hashes: vec![TxHashByTable::SentPayable(tx_hash)],
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
        let sent_payable_dao = SentPayableDaoMock::default().confirm_tx_result(Ok(()));
        let mut subject = AccountantBuilder::default().build();
        let mut sent_tx = make_sent_tx(123);
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);
        let sent_payable_cache =
            PendingPayableCacheMock::default().get_record_by_hash_result(Some(sent_tx.clone()));
        let pending_payable_scanner = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .sent_payable_cache(Box::new(sent_payable_cache))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Real(
                pending_payable_scanner,
            )));
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
        let tx_block = TxBlock {
            block_hash: make_tx_hash(456),
            block_number: 78901234.into(),
        };
        let tx_receipts_msg = TxReceiptsMessage {
            results: btreemap![TxHashByTable::SentPayable(sent_tx.hash) => Ok(
                StatusReadFromReceiptCheck::Succeeded(tx_block),
            )],
            response_skeleton_opt,
        };

        subject_addr.try_send(tx_receipts_msg).unwrap();

        system.run();
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        sent_tx.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block.block_hash),
            block_number: tx_block.block_number.as_u64(),
            detection: Detection::Normal,
        };
        assert_eq!(*transaction_confirmed_params, vec![vec![sent_tx]]);
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
        let payable_dao = PayableDaoMock::default().retrieve_payables_result(vec![payable_account]);
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
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_for_payable_scanner =
            PayableDaoMock::default().retrieve_payables_result(vec![]);
        let payable_dao_for_pending_payable_scanner =
            PayableDaoMock::default().transactions_confirmed_result(Ok(()));
        let sent_tx = make_sent_tx(123);
        let tx_hash = sent_tx.hash;
        let sent_payable_dao_for_payable_scanner = SentPayableDaoMock::default()
            // TODO should be removed with GH-701
            .insert_new_records_result(Ok(()));
        let sent_payable_dao_for_pending_payable_scanner = SentPayableDaoMock::default()
            .retrieve_txs_result(BTreeSet::from([sent_tx.clone()]))
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let failed_tx = make_failed_tx(123);
        let failed_payable_dao_for_payable_scanner =
            FailedPayableDaoMock::default().retrieve_txs_result(btreeset!(failed_tx));
        let failed_payable_dao_for_pending_payable_scanner = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .payable_daos(vec![
                ForPayableScanner(payable_dao_for_payable_scanner),
                ForPendingPayableScanner(payable_dao_for_pending_payable_scanner),
            ])
            .sent_payable_daos(vec![
                ForPayableScanner(sent_payable_dao_for_payable_scanner),
                ForPendingPayableScanner(sent_payable_dao_for_pending_payable_scanner),
            ])
            .failed_payable_daos(vec![
                ForPayableScanner(failed_payable_dao_for_payable_scanner),
                ForPendingPayableScanner(failed_payable_dao_for_pending_payable_scanner),
            ])
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
        let response_skeleton_opt = Some(ResponseSkeleton {
            client_id: 4555,
            context_id: 5566,
        });
        let first_counter_msg_setup = setup_for_counter_msg_triggered_via_type_id!(
            RequestTransactionReceipts,
            TxReceiptsMessage {
                results: btreemap![TxHashByTable::SentPayable(sent_tx.hash) => Ok(
                    StatusReadFromReceiptCheck::Reverted
                ),],
                response_skeleton_opt
            },
            &subject_addr
        );
        let sent_payables = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![make_sent_tx(1)],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt,
        };
        let second_counter_msg_setup = setup_for_counter_msg_triggered_via_type_id!(
            InitialTemplatesMessage,
            sent_payables,
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
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        let expected_failed_tx = FailedTx::from((sent_tx, FailureReason::Reverted));
        assert_eq!(
            *insert_new_records_params,
            vec![BTreeSet::from([expected_failed_tx])]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![BTreeSet::from([tx_hash])]);
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
    fn accountant_sends_qualified_payable_msg_for_new_payable_scan_when_qualified_payable_found() {
        let new_payable_templates = NewTxTemplates::from(&vec![make_payable_account(123)]);
        accountant_sends_qualified_payable_msg_when_qualified_payable_found(
            ScanForNewPayables {
                response_skeleton_opt: None,
            },
            Either::Left(new_payable_templates),
            vec![()],
        )
    }

    #[test]
    fn accountant_sends_qualified_payable_msg_for_retry_payable_scan_when_qualified_payable_found()
    {
        let retry_payable_templates = RetryTxTemplates(vec![make_retry_tx_template(123)]);
        accountant_sends_qualified_payable_msg_when_qualified_payable_found(
            ScanForRetryPayables {
                response_skeleton_opt: None,
            },
            Either::Right(retry_payable_templates),
            vec![],
        )
    }

    fn accountant_sends_qualified_payable_msg_when_qualified_payable_found<ActorMessage>(
        act_msg: ActorMessage,
        initial_templates: Either<NewTxTemplates, RetryTxTemplates>,
        reset_last_scan_timestamp_params_expected: Vec<()>,
    ) where
        ActorMessage: Message + Send + 'static,
        ActorMessage::Result: Send,
        Accountant: Handler<ActorMessage>,
    {
        let reset_last_scan_timestamp_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system =
            System::new("accountant_sends_qualified_payable_msg_when_qualified_payable_found");
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .consuming_wallet(consuming_wallet.clone())
            .build();
        let initial_template_msg = InitialTemplatesMessage {
            initial_templates,
            consuming_wallet,
            response_skeleton_opt: None,
        };
        let payable_scanner = ScannerMock::default()
            .scan_started_at_result(None)
            .start_scan_result(Ok(initial_template_msg.clone()));
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
        subject.scan_schedulers.payable.interval_computer = Box::new(
            NewPayableScanIntervalComputerMock::default()
                .reset_last_scan_timestamp_params(&reset_last_scan_timestamp_params_arc),
        );
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        accountant_addr.try_send(act_msg).unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let message = blockchain_bridge_recorder.get_record::<InitialTemplatesMessage>(0);
        assert_eq!(message, &initial_template_msg);
        let reset_last_scan_timestamp_params = reset_last_scan_timestamp_params_arc.lock().unwrap();
        assert_eq!(
            *reset_last_scan_timestamp_params,
            reset_last_scan_timestamp_params_expected
        )
    }

    #[test]
    fn automatic_scan_for_new_payables_schedules_another_one_immediately_if_no_qualified_payables_found(
    ) {
        let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let system =
            System::new("automatic_scan_for_new_payables_schedules_another_one_immediately_if_no_qualified_payables_found");
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(make_bc_with_defaults(TEST_DEFAULT_CHAIN))
            .consuming_wallet(consuming_wallet)
            .build();
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
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
        // As obvious, the next scan is scheduled for the future and should not run immediately.
        let (msg, actual_interval) = notify_later_params.remove(0);
        assert_eq!(
            msg,
            ScanForNewPayables {
                response_skeleton_opt: None
            }
        );
        // The initial last_new_payable_scan_timestamp is UNIX_EPOCH by this design. Such a value
        // would've driven an immediate scan without an interval. Therefore, the performed interval
        // implies that the last_new_payable_scan_timestamp must have been updated to the current
        // time. (As the result of running into StartScanError::NothingToProcess)
        let default_interval =
            ScanIntervals::compute_default(TEST_DEFAULT_CHAIN).payable_scan_interval;
        let tolerance = Duration::from_secs(5);
        let min_interval = default_interval.checked_sub(tolerance).unwrap();
        let max_interval = default_interval.checked_add(tolerance).unwrap();
        // The divergence should be only a few milliseconds, definitely not seconds; the tested
        // interval should be safe for slower machines too.
        assert!(
            min_interval <= actual_interval && actual_interval <= max_interval,
            "Expected interval between {:?} and {:?}, got {:?}",
            min_interval,
            max_interval,
            actual_interval
        );
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
        let retry_tx_templates =
            RetryTxTemplates(vec![make_retry_tx_template(1), make_retry_tx_template(2)]);
        let qualified_payables_msg = InitialTemplatesMessage {
            initial_templates: Either::Right(retry_tx_templates),
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
        let message = blockchain_bridge_recorder.get_record::<InitialTemplatesMessage>(0);
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
        let time_until_next_scan_params_arc = Arc::new(Mutex::new(vec![]));
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
            configure_accountant_for_startup_with_preexisting_pending_payables(
                test_name,
                &notify_and_notify_later_params,
                &time_until_next_scan_params_arc,
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
            &scan_params.payable_start_scan,
            &notify_and_notify_later_params,
            time_until_next_scan_params_arc,
            new_payable_expected_computed_interval,
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
        let tx_hash = make_tx_hash(456);
        let retry_tx_templates = RetryTxTemplates(vec![make_retry_tx_template(1)]);
        let payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .scan_started_at_result(None)
            // These values belong to the RetryPayableScanner
            .start_scan_params(&scan_params.payable_start_scan)
            .start_scan_result(Ok(InitialTemplatesMessage {
                initial_templates: Either::Right(retry_tx_templates),
                consuming_wallet: consuming_wallet.clone(),
                response_skeleton_opt: None,
            }))
            .finish_scan_params(&scan_params.payable_finish_scan)
            // Important
            .finish_scan_result(PayableScanResult {
                ui_response_opt: None,
                result: NextScanToRun::PendingPayableScan,
            });
        let pending_payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.pending_payable_start_scan)
            .start_scan_result(Ok(RequestTransactionReceipts {
                tx_hashes: vec![TxHashByTable::SentPayable(tx_hash)],
                response_skeleton_opt: None,
            }))
            .finish_scan_params(&scan_params.pending_payable_finish_scan)
            .finish_scan_result(PendingPayableScanResult::PaymentRetryRequired(None));
        let receivable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&scan_params.receivable_start_scan)
            .start_scan_result(Err(StartScanError::NothingToProcess));
        let (subject, expected_pending_payable_notify_later_interval, receivable_scan_interval) =
            configure_accountant_for_startup_with_no_preexisting_pending_payables(
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
        let expected_tx_receipts_msg = TxReceiptsMessage {
            results: btreemap![TxHashByTable::SentPayable(tx_hash) => Ok(
                StatusReadFromReceiptCheck::Reverted,
            )],
            response_skeleton_opt: None,
        };
        let sent_tx = TxBuilder::default()
            .hash(make_tx_hash(890))
            .receiver_address(make_wallet("bcd").address())
            .build();
        let expected_sent_payables = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![sent_tx],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: None,
        };
        let blockchain_bridge_counter_msg_setup_for_pending_payable_scanner = setup_for_counter_msg_triggered_via_type_id!(
            RequestTransactionReceipts,
            expected_tx_receipts_msg.clone(),
            &subject_addr
        );
        let blockchain_bridge_counter_msg_setup_for_payable_scanner = setup_for_counter_msg_triggered_via_type_id!(
            InitialTemplatesMessage,
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
            expected_pending_payable_notify_later_interval,
            expected_tx_receipts_msg,
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
        // Since the assertions proved that the pending payable scanner had run multiple times
        // before the new payable scanner started or was scheduled, the front position definitely
        // belonged to the one first mentioned.
    }

    #[derive(Default)]
    struct ScanParams {
        payable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
        payable_finish_scan: Arc<Mutex<Vec<(SentPayables, Logger)>>>,
        pending_payable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
        pending_payable_finish_scan: Arc<Mutex<Vec<(TxReceiptsMessage, Logger)>>>,
        receivable_start_scan:
            Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
    }

    #[derive(Default)]
    struct NotifyAndNotifyLaterParams {
        new_payables_notify_later: Arc<Mutex<Vec<(ScanForNewPayables, Duration)>>>,
        new_payables_notify: Arc<Mutex<Vec<ScanForNewPayables>>>,
        retry_payables_notify: Arc<Mutex<Vec<ScanForRetryPayables>>>,
        pending_payables_notify_later: Arc<Mutex<Vec<(ScanForPendingPayables, Duration)>>>,
        receivables_notify_later: Arc<Mutex<Vec<(ScanForReceivables, Duration)>>>,
    }

    fn configure_accountant_for_startup_with_preexisting_pending_payables(
        test_name: &str,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        time_until_next_scan_params_arc: &Arc<Mutex<Vec<()>>>,
        config: BootstrapperConfig,
        pending_payable_scanner: ScannerMock<
            RequestTransactionReceipts,
            TxReceiptsMessage,
            PendingPayableScanResult,
        >,
        receivable_scanner: ScannerMock<
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
        payable_scanner: ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>,
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
        let interval_computer = NewPayableScanIntervalComputerMock::default()
            .time_until_next_scan_params(&time_until_next_scan_params_arc)
            .time_until_next_scan_result(ScanTiming::WaitFor(
                new_payable_expected_computed_interval,
            ));
        subject.scan_schedulers.payable.interval_computer = Box::new(interval_computer);
        (
            subject,
            new_payable_expected_computed_interval,
            receivable_scan_interval,
        )
    }

    fn configure_accountant_for_startup_with_no_preexisting_pending_payables(
        test_name: &str,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        config: BootstrapperConfig,
        payable_scanner: ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>,
        pending_payable_scanner: ScannerMock<
            RequestTransactionReceipts,
            TxReceiptsMessage,
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
            TxReceiptsMessage,
            PendingPayableScanResult,
        >,
        receivable_scanner: ScannerMock<
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
        payable_scanner: ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>,
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
        let pp_logger = assert_pending_payable_scanner_ran(
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
        expected_tx_receipts_msg: TxReceiptsMessage,
        act_started_at: SystemTime,
        act_finished_at: SystemTime,
    ) {
        let pp_start_scan_logger = assert_pending_payable_scanner_ran(
            consuming_wallet,
            &scan_params.pending_payable_start_scan,
            act_started_at,
            act_finished_at,
        );
        assert_using_the_same_logger(&pp_start_scan_logger, test_name, Some("pp start scan"));
        let mut pending_payable_finish_scan_params =
            scan_params.pending_payable_finish_scan.lock().unwrap();
        let (actual_tx_receipts_msg, pp_finish_scan_logger) =
            pending_payable_finish_scan_params.remove(0);
        assert_eq!(actual_tx_receipts_msg, expected_tx_receipts_msg);
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

    fn assert_pending_payable_scanner_ran(
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
        payable_scanner_start_scan_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        time_until_next_scan_until_next_new_payable_scan_params_arc: Arc<Mutex<Vec<()>>>,
        new_payable_expected_computed_interval: Duration,
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
        let time_until_next_scan_until_next_new_payable_scan_params =
            time_until_next_scan_until_next_new_payable_scan_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *time_until_next_scan_until_next_new_payable_scan_params,
            vec![()]
        );
        let payable_scanner_start_scan = payable_scanner_start_scan_arc.lock().unwrap();
        assert!(
            payable_scanner_start_scan.is_empty(),
            "We expected the payable scanner not to run in this test, but it did"
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
        assert!(
            scan_for_retry_payables_notify_params.is_empty(),
            "We did not expect any scheduling of retry payables, but it happened {:?}",
            scan_for_retry_payables_notify_params
        );
    }

    fn assert_payable_scanner_for_some_pending_payable_found(
        test_name: &str,
        consuming_wallet: Wallet,
        scan_params: &ScanParams,
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
        expected_sent_payables: SentPayables,
    ) {
        assert_payable_scanner_ran_for_some_pending_payable_found(
            test_name,
            consuming_wallet,
            scan_params,
            expected_sent_payables,
        );
        assert_scan_scheduling_for_some_pending_payable_found(notify_and_notify_later_params);
    }

    fn assert_payable_scanner_ran_for_some_pending_payable_found(
        test_name: &str,
        consuming_wallet: Wallet,
        scan_params: &ScanParams,
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
    }

    fn assert_scan_scheduling_for_some_pending_payable_found(
        notify_and_notify_later_params: &NotifyAndNotifyLaterParams,
    ) {
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
        assert_receivable_scan_ran(test_name, receivable_start_scan_params_arc, earning_wallet);
        assert_another_receivable_scan_scheduled(
            scan_for_receivables_notify_later_params_arc,
            receivable_scan_interval,
        )
    }

    fn assert_receivable_scan_ran(
        test_name: &str,
        receivable_start_scan_params_arc: &Arc<
            Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>,
        >,
        earning_wallet: Wallet,
    ) {
        let mut receivable_start_scan_params = receivable_start_scan_params_arc.lock().unwrap();
        let (r_wallet, _r_started_at, r_response_skeleton_opt, r_logger, r_trigger_msg_name_str) =
            receivable_start_scan_params.remove(0);
        assert_eq!(r_wallet, earning_wallet);
        assert_eq!(r_response_skeleton_opt, None);
        assert!(
            r_trigger_msg_name_str.contains("Receivable"),
            "Should contain 'Receivable' but {}",
            r_trigger_msg_name_str
        );
        assert!(
            receivable_start_scan_params.is_empty(),
            "Should be empty by now but was {:?}",
            receivable_start_scan_params
        );
        assert_using_the_same_logger(&r_logger, test_name, Some("r"));
    }

    fn assert_another_receivable_scan_scheduled(
        scan_for_receivables_notify_later_params_arc: &Arc<
            Mutex<Vec<(ScanForReceivables, Duration)>>,
        >,
        receivable_scan_interval: Duration,
    ) {
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
        let sent_payable_dao =
            SentPayableDaoMock::default().retrieve_txs_result(BTreeSet::from([make_sent_tx(789)]));
        let failed_payable_dao =
            FailedPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .sent_payable_daos(vec![ForPendingPayableScanner(sent_payable_dao)])
            .failed_payable_daos(vec![ForPendingPayableScanner(failed_payable_dao)])
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
        assert_eq!(hint, ScanReschedulingAfterEarlyStop::DoNotSchedule);
        assert_eq!(flag_before, true);
        assert_eq!(flag_after, false);
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let _ = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
    }

    #[test]
    fn initial_pending_payable_scan_if_no_payables_found() {
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let failed_payable_dao =
            FailedPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(make_wallet("consuming"))
            .sent_payable_daos(vec![ForPendingPayableScanner(sent_payable_dao)])
            .failed_payable_daos(vec![ForPendingPayableScanner(failed_payable_dao)])
            .build();
        let flag_before = subject.scanners.initial_pending_payable_scan();

        let hint = subject.handle_request_of_scan_for_pending_payable(None);

        let flag_after = subject.scanners.initial_pending_payable_scan();
        assert_eq!(
            hint,
            ScanReschedulingAfterEarlyStop::Schedule(ScanType::Payables)
        );
        assert_eq!(flag_before, true);
        assert_eq!(flag_after, false);
    }

    #[test]
    #[cfg(windows)]
    #[should_panic(
        expected = "internal error: entered unreachable code: ScanAlreadyRunning { \
        cross_scan_cause_opt: None, started_at: SystemTime { intervals: 116444736000000000 } } \
        should be impossible with PendingPayableScanner in automatic mode"
    )]
    fn initial_pending_payable_scan_hits_unexpected_error() {
        test_initial_pending_payable_scan_hits_unexpected_error()
    }

    #[test]
    #[cfg(not(windows))]
    #[should_panic(
        expected = "internal error: entered unreachable code: ScanAlreadyRunning { \
        cross_scan_cause_opt: None, started_at: SystemTime { tv_sec: 0, tv_nsec: 0 } } \
        should be impossible with PendingPayableScanner in automatic mode"
    )]
    fn initial_pending_payable_scan_hits_unexpected_error() {
        test_initial_pending_payable_scan_hits_unexpected_error()
    }

    fn test_initial_pending_payable_scan_hits_unexpected_error() {
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
        let new_tx_templates = NewTxTemplates::from(&vec![payable_account.clone()]);
        let priced_new_tx_templates =
            make_priced_new_tx_templates(vec![(payable_account, 123_456_789)]);
        let consuming_wallet = make_paying_wallet(b"consuming");
        let counter_msg_1 = PricedTemplatesMessage {
            priced_templates: Either::Left(priced_new_tx_templates.clone()),
            agent: Box::new(BlockchainAgentMock::default()),
            response_skeleton_opt: None,
        };
        let transaction_hash = make_tx_hash(789);
        let tx_hash = make_tx_hash(456);
        let creditor_wallet = make_wallet("blah");
        let sent_tx = TxBuilder::default()
            .hash(transaction_hash)
            .receiver_address(creditor_wallet.address())
            .build();
        let counter_msg_2 = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![sent_tx],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: None,
        };
        let tx_status = StatusReadFromReceiptCheck::Succeeded(TxBlock {
            block_hash: make_tx_hash(369369),
            block_number: 4444444444u64.into(),
        });
        let counter_msg_3 = TxReceiptsMessage {
            results: btreemap![TxHashByTable::SentPayable(tx_hash) => Ok(tx_status)],
            response_skeleton_opt: None,
        };
        let request_transaction_receipts_msg = RequestTransactionReceipts {
            tx_hashes: vec![TxHashByTable::SentPayable(tx_hash)],
            response_skeleton_opt: None,
        };
        let qualified_payables_msg = InitialTemplatesMessage {
            initial_templates: Either::Left(new_tx_templates),
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
                InitialTemplatesMessage,
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
            blockchain_bridge_recording.get_record::<InitialTemplatesMessage>(0);
        assert_eq!(actual_qualified_payables_msg, &qualified_payables_msg);
        let actual_outbound_payment_instructions_msg =
            blockchain_bridge_recording.get_record::<OutboundPaymentsInstructions>(1);
        assert_eq!(
            actual_outbound_payment_instructions_msg.priced_templates,
            Either::Left(priced_new_tx_templates)
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
        qualified_payables_msg: &InitialTemplatesMessage,
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
                result: NextScanToRun::PendingPayableScan,
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
            .retrieve_payables_result(accounts.clone())
            .retrieve_payables_result(vec![]);
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
            ScanReschedulingAfterEarlyStop::Schedule(ScanType::Payables)
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
            PayableDaoMock::default().retrieve_payables_result(qualified_payables.clone());
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
        let message = blockchain_bridge_recordings.get_record::<InitialTemplatesMessage>(0);
        let new_tx_templates = NewTxTemplates::from(&qualified_payables);
        assert_eq!(
            message,
            &InitialTemplatesMessage {
                initial_templates: Either::Left(new_tx_templates),
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
            .resolve_rescheduling_on_error_result(ScanReschedulingAfterEarlyStop::Schedule(
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
                InitialTemplatesMessage,
                InitialTemplatesMessage
            ))
            .start();
        let qualified_payables_sub = blockchain_bridge_addr.clone().recipient();
        let (mut qualified_payables, _, _) =
            make_qualified_and_unqualified_payables(now, &payment_thresholds);
        let payable_1 = qualified_payables.remove(0);
        let payable_2 = qualified_payables.remove(0);
        let payable_dao = PayableDaoMock::new()
            .retrieve_payables_result(vec![payable_1.clone()])
            .retrieve_payables_result(vec![payable_2.clone()]);
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
            payment_procedure_result: Err("blah".to_string()),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1122,
                context_id: 7788,
            }),
        })
        .unwrap();
        addr.try_send(message_after.clone()).unwrap();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording.lock().unwrap();
        let first_message_actual: &InitialTemplatesMessage =
            blockchain_bridge_recording.get_record(0);
        assert_eq!(
            first_message_actual.response_skeleton_opt,
            message_before.response_skeleton_opt
        );
        let second_message_actual: &InitialTemplatesMessage =
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
    fn scan_for_pending_payables_finds_various_payables() {
        init_test_logging();
        let test_name = "scan_for_pending_payables_finds_various_payables";
        let start_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let blockchain_bridge_addr = blockchain_bridge
            .system_stop_conditions(match_lazily_every_type_id!(RequestTransactionReceipts))
            .start();
        let tx_hash_1 = make_tx_hash(456);
        let tx_hash_2 = make_tx_hash(789);
        let tx_hash_3 = make_tx_hash(123);
        let expected_composed_msg_for_blockchain_bridge = RequestTransactionReceipts {
            tx_hashes: vec![
                TxHashByTable::SentPayable(tx_hash_1),
                TxHashByTable::FailedPayable(tx_hash_2),
                TxHashByTable::FailedPayable(tx_hash_3),
            ],
            response_skeleton_opt: None,
        };
        let pending_payable_scanner = ScannerMock::new()
            .scan_started_at_result(None)
            .start_scan_params(&start_scan_params_arc)
            .start_scan_result(Ok(expected_composed_msg_for_blockchain_bridge.clone()));
        let consuming_wallet = make_wallet("consuming");
        let system = System::new("pending payable scan");
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(consuming_wallet.clone())
            .logger(Logger::new(test_name))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.request_transaction_receipts_sub_opt = Some(blockchain_bridge_addr.recipient());
        let account_addr = subject.start();

        let _ = account_addr
            .try_send(ScanForPendingPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        let mut start_scan_params = start_scan_params_arc.lock().unwrap();
        let (wallet, timestamp, response_skeleton_opt, logger, _) = start_scan_params.remove(0);
        assert_eq!(wallet, consuming_wallet);
        assert!(before <= timestamp && timestamp <= after);
        assert_eq!(response_skeleton_opt, None);
        assert!(
            start_scan_params.is_empty(),
            "Should be empty but {:?}",
            start_scan_params
        );
        assert_using_the_same_logger(&logger, test_name, Some("start scan payable"));
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        let received_msg = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(received_msg, &expected_composed_msg_for_blockchain_bridge);
        assert_eq!(blockchain_bridge_recording.len(), 1);
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
            .resolve_rescheduling_on_error_result(ScanReschedulingAfterEarlyStop::Schedule(
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
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("our consuming wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("our earning wallet"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for services we provided",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("our earning wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for services we provided",
            earning_wallet,
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let config = bc_from_earning_wallet(make_wallet("hi"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("my consuming wallet");
        let config = bc_from_wallets(consuming_wallet.clone(), make_wallet("my earning wallet"));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for services we provided",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("my earning wallet");
        let config = bc_from_earning_wallet(earning_wallet.clone());
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().retrieve_payables_result(vec![]);
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for services we provided",
            earning_wallet,
        ));
    }

    #[test]
    fn report_services_consumed_message_is_received() {
        init_test_logging();
        let config = make_bc_with_defaults(TEST_DEFAULT_CHAIN);
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
    }

    fn assert_that_we_do_not_charge_our_own_wallet_for_consumed_services(
        config: BootstrapperConfig,
        message: ReportServicesConsumedMessage,
    ) -> Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>> {
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .retrieve_payables_result(vec![])
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
        expected = "Was recording services provided for 0x000000000000000000000000000000626f6f6761 \
    but hit a fatal database error: RusqliteError(\"we cannot help ourselves; this is baaad\")"
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
        let mut config = make_bc_with_defaults(TEST_DEFAULT_CHAIN);
        config.crash_point = CrashPoint::Message;
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();

        prove_that_crash_request_handler_is_hooked_up(accountant, CRASH_KEY);
    }

    #[test]
    fn accountant_processes_sent_payables_and_schedules_pending_payable_scanner() {
        // let get_tx_identifiers_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let inserted_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_hash = H256::from("transaction_hash".keccak256());
        let payable_dao = PayableDaoMock::new();
        let sent_payable_dao = SentPayableDaoMock::new()
            .insert_new_records_params(&inserted_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        // let expected_rowid = 45623;
        // let sent_payable_dao = SentPayableDaoMock::default()
        //     .get_tx_identifiers_params(&get_tx_identifiers_params_arc)
        //     .get_tx_identifiers_result(hashmap! (expected_hash => expected_rowid));
        let system =
            System::new("accountant_processes_sent_payables_and_schedules_pending_payable_scanner");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .sent_payable_daos(vec![ForPayableScanner(sent_payable_dao)])
            .build();
        let pending_payable_interval = Duration::from_millis(55);
        subject.scan_schedulers.pending_payable.interval = pending_payable_interval;
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&pending_payable_notify_later_params_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        let expected_tx = TxBuilder::default().hash(expected_hash.clone()).build();
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![expected_tx.clone()],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: None,
        };
        let addr = subject.start();

        addr.try_send(sent_payable).expect("unexpected actix error");

        System::current().stop();
        system.run();
        let inserted_new_records_params = inserted_new_records_params_arc.lock().unwrap();
        assert_eq!(
            inserted_new_records_params[0],
            BTreeSet::from([expected_tx])
        );
        let pending_payable_notify_later_params =
            pending_payable_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payable_notify_later_params,
            vec![(ScanForPendingPayables::default(), pending_payable_interval)]
        );
    }

    #[test]
    fn accountant_finishes_processing_of_retry_payables_and_schedules_pending_payable_scanner() {
        let pending_payable_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let inserted_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_hash = H256::from("transaction_hash".keccak256());
        let payable_dao = PayableDaoMock::new();
        let sent_payable_dao = SentPayableDaoMock::new()
            .insert_new_records_params(&inserted_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let failed_payble_dao = FailedPayableDaoMock::new().retrieve_txs_result(BTreeSet::new());
        let system = System::new(
            "accountant_finishes_processing_of_retry_payables_and_schedules_pending_payable_scanner",
        );
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_daos(vec![ForPayableScanner(payable_dao)])
            .failed_payable_daos(vec![ForPayableScanner(failed_payble_dao)])
            .sent_payable_daos(vec![ForPayableScanner(sent_payable_dao)])
            .build();
        let pending_payable_interval = Duration::from_millis(55);
        subject.scan_schedulers.pending_payable.interval = pending_payable_interval;
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&pending_payable_notify_later_params_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        let expected_tx = TxBuilder::default().hash(expected_hash.clone()).build();
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![expected_tx.clone()],
                failed_txs: vec![],
            }),
            payable_scan_type: PayableScanType::Retry,
            response_skeleton_opt: None,
        };
        let addr = subject.start();

        addr.try_send(sent_payable).expect("unexpected actix error");

        System::current().stop();
        system.run();
        let inserted_new_records_params = inserted_new_records_params_arc.lock().unwrap();
        assert_eq!(
            inserted_new_records_params[0],
            BTreeSet::from([expected_tx])
        );
        let pending_payable_notify_later_params =
            pending_payable_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payable_notify_later_params,
            vec![(ScanForPendingPayables::default(), pending_payable_interval)]
        );
    }

    #[test]
    fn retry_payable_scan_is_requested_to_be_repeated() {
        init_test_logging();
        let test_name = "retry_payable_scan_is_requested_to_be_repeated";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let retry_payable_notify_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        let consuming_wallet = make_paying_wallet(b"paying wallet");
        let mut subject = AccountantBuilder::default()
            .consuming_wallet(consuming_wallet.clone())
            .logger(Logger::new(test_name))
            .build();
        subject
            .scanners
            .replace_scanner(ScannerReplacement::Payable(ReplacementType::Mock(
                ScannerMock::default()
                    .finish_scan_params(&finish_scan_params_arc)
                    .finish_scan_result(PayableScanResult {
                        ui_response_opt: None,
                        result: NextScanToRun::RetryPayableScan,
                    }),
            )));
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&retry_payable_notify_params_arc));
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(BatchResults {
                sent_txs: vec![],
                failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
            }),
            payable_scan_type: PayableScanType::New,
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
        let mut payable_notify_params = retry_payable_notify_params_arc.lock().unwrap();
        let scheduled_msg = payable_notify_params.remove(0);
        assert_eq!(scheduled_msg, ScanForRetryPayables::default());
        assert!(
            payable_notify_params.is_empty(),
            "Should be empty but {:?}",
            payable_notify_params
        );
    }

    #[test]
    fn accountant_in_automatic_mode_schedules_tx_retry_as_some_pending_payables_have_not_completed()
    {
        init_test_logging();
        let test_name =
            "accountant_in_automatic_mode_schedules_tx_retry_as_some_pending_payables_have_not_completed";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let retry_payable_notify_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::PaymentRetryRequired(None));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&retry_payable_notify_params_arc));
        let system = System::new(test_name);
        let (mut msg, _) = make_tx_receipts_msg(vec![
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::SentPayable(make_tx_hash(123)),
                status: StatusReadFromReceiptCheck::Pending,
            },
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::FailedPayable(make_tx_hash(456)),
                status: StatusReadFromReceiptCheck::Reverted,
            },
        ]);
        msg.response_skeleton_opt = None;
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
                response_skeleton_opt: None
            }]
        );
        assert_using_the_same_logger(&logger, test_name, None)
    }

    #[test]
    fn accountant_reschedules_pending_p_scanner_in_automatic_mode_after_receipt_fetching_failed() {
        init_test_logging();
        let test_name =
            "accountant_reschedules_pending_p_scanner_in_automatic_mode_after_receipt_fetching_failed";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::ProcedureShouldBeRepeated(None));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let interval = Duration::from_secs(20);
        subject.scan_schedulers.pending_payable.interval = interval;
        subject.scan_schedulers.pending_payable.handle = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&pending_payable_notify_later_params_arc),
        );
        let system = System::new(test_name);
        let msg = TxReceiptsMessage {
            results: btreemap!(TxHashByTable::SentPayable(make_tx_hash(123)) => Err(AppRpcError::Remote(RemoteError::Unreachable))),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (msg_actual, logger) = finish_scan_params.remove(0);
        assert_eq!(msg_actual, msg);
        let pending_payable_notify_later_params =
            pending_payable_notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payable_notify_later_params,
            vec![(
                ScanForPendingPayables {
                    response_skeleton_opt: None
                },
                interval
            )]
        );
        assert_using_the_same_logger(&logger, test_name, None)
    }

    #[test]
    fn accountant_reschedules_pending_p_scanner_in_manual_mode_after_receipt_fetching_failed() {
        init_test_logging();
        let test_name =
            "accountant_reschedules_pending_p_scanner_in_manual_mode_after_receipt_fetching_failed";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let ui_gateway =
            ui_gateway.system_stop_conditions(match_lazily_every_type_id!(NodeToUiMessage));
        let expected_node_to_ui_msg = NodeToUiMessage {
            target: MessageTarget::ClientId(1234),
            body: UiScanResponse {}.tmb(54),
        };
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::ProcedureShouldBeRepeated(Some(
                expected_node_to_ui_msg.clone(),
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let interval = Duration::from_secs(20);
        subject.scan_schedulers.pending_payable.interval = interval;
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.ui_message_sub_opt = Some(ui_gateway.start().recipient());
        let system = System::new(test_name);
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 54,
        };
        let msg = TxReceiptsMessage {
            results: btreemap!(TxHashByTable::SentPayable(make_tx_hash(123)) => Err(AppRpcError::Remote(RemoteError::Unreachable))),
            response_skeleton_opt: Some(response_skeleton),
        };
        let subject_addr = subject.start();

        subject_addr.try_send(msg.clone()).unwrap();

        system.run();
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (msg_actual, logger) = finish_scan_params.remove(0);
        assert_eq!(msg_actual, msg);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let node_to_ui_msg = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(node_to_ui_msg, &expected_node_to_ui_msg);
        assert_eq!(ui_gateway_recording.len(), 1);
        assert_using_the_same_logger(&logger, test_name, None);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Re-running the pending payable scan is recommended, as some parts \
            did not finish last time."
        ));
    }

    #[test]
    fn accountant_in_manual_mode_schedules_tx_retry_as_some_pending_payables_have_not_completed() {
        init_test_logging();
        let test_name =
            "accountant_in_manual_mode_schedules_tx_retry_as_some_pending_payables_have_not_completed";
        let retry_payable_notify_params_arc = Arc::new(Mutex::new(vec![]));
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let response_skeleton = ResponseSkeleton {
            client_id: 123,
            context_id: 333,
        };
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::PaymentRetryRequired(Some(
                response_skeleton,
            )));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.retry_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&retry_payable_notify_params_arc));
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.payable.new_payable_notify_later =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        subject.scan_schedulers.pending_payable.handle =
            Box::new(NotifyLaterHandleMock::default().panic_on_schedule_attempt());
        let system = System::new(test_name);
        let msg = TxReceiptsMessage {
            results: btreemap!(TxHashByTable::SentPayable(make_tx_hash(123)) => Err(AppRpcError::Remote(RemoteError::Unreachable))),
            response_skeleton_opt: Some(response_skeleton),
        };
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
                response_skeleton_opt: Some(response_skeleton)
            }]
        );
        assert_using_the_same_logger(&logger, test_name, None)
    }

    #[test]
    fn accountant_confirms_all_pending_txs_and_schedules_new_payable_scanner_timely() {
        init_test_logging();
        let test_name =
            "accountant_confirms_all_pending_txs_and_schedules_new_payable_scanner_timely";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let time_until_next_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new("new_payable_scanner_timely");
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::NoPendingPayablesLeft(None));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        let expected_computed_interval = Duration::from_secs(3);
        let interval_computer = NewPayableScanIntervalComputerMock::default()
            .time_until_next_scan_params(&time_until_next_scan_params_arc)
            // This determines the test
            .time_until_next_scan_result(ScanTiming::WaitFor(expected_computed_interval));
        subject.scan_schedulers.payable.interval_computer = Box::new(interval_computer);
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&new_payable_notify_arc));
        let subject_addr = subject.start();
        let (msg, _) = make_tx_receipts_msg(vec![
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::SentPayable(make_tx_hash(123)),
                status: StatusReadFromReceiptCheck::Succeeded(TxBlock {
                    block_hash: make_tx_hash(123),
                    block_number: U64::from(100),
                }),
            },
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::FailedPayable(make_tx_hash(555)),
                status: StatusReadFromReceiptCheck::Succeeded(TxBlock {
                    block_hash: make_tx_hash(234),
                    block_number: U64::from(200),
                }),
            },
        ]);

        subject_addr.try_send(msg.clone()).unwrap();

        System::current().stop();
        system.run();
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (captured_msg, logger) = finish_scan_params.remove(0);
        assert_eq!(captured_msg, msg);
        assert_using_the_same_logger(&logger, test_name, None);
        assert!(
            finish_scan_params.is_empty(),
            "Should be empty but {:?}",
            finish_scan_params
        );
        // Here, we see that the next payable scan is scheduled for the future, in the expected interval.
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
        init_test_logging();
        let test_name =
            "accountant_confirms_payable_txs_and_schedules_the_delayed_new_payable_scanner_asap";
        let finish_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let time_until_next_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_notify_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default()
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_params(&finish_scan_params_arc)
            .finish_scan_result(PendingPayableScanResult::NoPendingPayablesLeft(None));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        let interval_computer = NewPayableScanIntervalComputerMock::default()
            .time_until_next_scan_params(&time_until_next_scan_params_arc)
            // This determines the test
            .time_until_next_scan_result(ScanTiming::ReadyNow);
        subject.scan_schedulers.payable.interval_computer = Box::new(interval_computer);
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        subject.scan_schedulers.payable.new_payable_notify =
            Box::new(NotifyHandleMock::default().notify_params(&new_payable_notify_arc));
        let tx_block_1 = make_transaction_block(4567);
        let tx_block_2 = make_transaction_block(1234);
        let subject_addr = subject.start();
        let (msg, _) = make_tx_receipts_msg(vec![
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::SentPayable(make_tx_hash(123)),
                status: StatusReadFromReceiptCheck::Succeeded(tx_block_1),
            },
            SeedsToMakeUpPayableWithStatus {
                tx_hash: TxHashByTable::FailedPayable(make_tx_hash(456)),
                status: StatusReadFromReceiptCheck::Succeeded(tx_block_2),
            },
        ]);

        subject_addr.try_send(msg.clone()).unwrap();

        let system = System::new(test_name);
        System::current().stop();
        system.run();
        let mut finish_scan_params = finish_scan_params_arc.lock().unwrap();
        let (captured_msg, logger) = finish_scan_params.remove(0);
        assert_eq!(captured_msg, msg);
        assert_using_the_same_logger(&logger, test_name, None);
        assert!(
            finish_scan_params.is_empty(),
            "Should be empty but {:?}",
            finish_scan_params
        );
        let time_until_next_scan_params = time_until_next_scan_params_arc.lock().unwrap();
        assert_eq!(*time_until_next_scan_params, vec![()]);
        let new_payable_notify_later = new_payable_notify_later_arc.lock().unwrap();
        assert!(
            new_payable_notify_later.is_empty(),
            "should be empty but was: {:?}",
            new_payable_notify_later
        );
        // As a proof, the handle for an immediate launch of the new payable scanner was used
        let new_payable_notify = new_payable_notify_arc.lock().unwrap();
        assert_eq!(*new_payable_notify, vec![ScanForNewPayables::default()]);
    }

    #[test]
    fn scheduler_for_new_payables_operates_with_proper_now_timestamp() {
        let new_payable_notify_later_arc = Arc::new(Mutex::new(vec![]));
        let test_name = "scheduler_for_new_payables_operates_with_proper_now_timestamp";
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(make_bc_with_defaults(TEST_DEFAULT_CHAIN))
            .logger(Logger::new(test_name))
            .build();
        let pending_payable_scanner = ScannerMock::new()
            .finish_scan_result(PendingPayableScanResult::NoPendingPayablesLeft(None));
        subject
            .scanners
            .replace_scanner(ScannerReplacement::PendingPayable(ReplacementType::Mock(
                pending_payable_scanner,
            )));
        subject.scan_schedulers.payable.new_payable_notify_later = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&new_payable_notify_later_arc),
        );
        let default_scan_intervals = ScanIntervals::compute_default(TEST_DEFAULT_CHAIN);
        let mut assertion_interval_computer =
            NewPayableScanIntervalComputerReal::new(default_scan_intervals.payable_scan_interval);
        {
            subject
                .scan_schedulers
                .payable
                .interval_computer
                .reset_last_scan_timestamp();
            assertion_interval_computer.reset_last_scan_timestamp();
        }
        let system = System::new(test_name);
        let subject_addr = subject.start();
        let (msg, _) = make_tx_receipts_msg(vec![SeedsToMakeUpPayableWithStatus {
            tx_hash: TxHashByTable::SentPayable(make_tx_hash(123)),
            status: StatusReadFromReceiptCheck::Succeeded(TxBlock {
                block_hash: make_tx_hash(123),
                block_number: U64::from(100),
            }),
        }]);
        let left_side_bound = if let ScanTiming::WaitFor(interval) =
            assertion_interval_computer.time_until_next_scan()
        {
            interval
        } else {
            panic!("expected an interval")
        };

        subject_addr.try_send(msg).unwrap();

        System::current().stop();
        system.run();
        let new_payable_notify_later = new_payable_notify_later_arc.lock().unwrap();
        let (_, actual_interval) = new_payable_notify_later[0];
        let right_side_bound = if let ScanTiming::WaitFor(interval) =
            assertion_interval_computer.time_until_next_scan()
        {
            interval
        } else {
            panic!("expected an interval")
        };
        assert!(
            left_side_bound >= actual_interval && actual_interval >= right_side_bound,
            "expected actual {:?} to be between {:?} and {:?}",
            actual_interval,
            left_side_bound,
            right_side_bound
        );
    }

    pub struct SeedsToMakeUpPayableWithStatus {
        tx_hash: TxHashByTable,
        status: StatusReadFromReceiptCheck,
    }

    fn make_tx_receipts_msg(
        seeds: Vec<SeedsToMakeUpPayableWithStatus>,
    ) -> (TxReceiptsMessage, Vec<TxByTable>) {
        let (tx_receipt_results, tx_record_vec) = seeds.into_iter().enumerate().fold(
            (btreemap![], vec![]),
            |(mut tx_receipt_results, mut record_by_table_vec), (idx, seed_params)| {
                let tx_hash = seed_params.tx_hash;
                let status = seed_params.status;
                let (key, value, record) =
                    make_receipt_check_result_and_record(tx_hash, status, idx as u64);
                tx_receipt_results.insert(key, value);
                record_by_table_vec.push(record);
                (tx_receipt_results, record_by_table_vec)
            },
        );

        let msg = TxReceiptsMessage {
            results: tx_receipt_results,
            response_skeleton_opt: None,
        };

        (msg, tx_record_vec)
    }

    fn make_receipt_check_result_and_record(
        tx_hash: TxHashByTable,
        status: StatusReadFromReceiptCheck,
        idx: u64,
    ) -> (TxHashByTable, TxReceiptResult, TxByTable) {
        match tx_hash {
            TxHashByTable::SentPayable(hash) => {
                let mut sent_tx = make_sent_tx((1 + idx) as u32);
                sent_tx.hash = hash;

                if let StatusReadFromReceiptCheck::Succeeded(block) = &status {
                    sent_tx.status = TxStatus::Confirmed {
                        block_hash: format!("{:?}", block.block_hash),
                        block_number: block.block_number.as_u64(),
                        detection: Detection::Normal,
                    }
                }

                let result = Ok(status);
                let record_by_table = TxByTable::SentPayable(sent_tx);
                (tx_hash, result, record_by_table)
            }
            TxHashByTable::FailedPayable(hash) => {
                let mut failed_tx = make_failed_tx(1 + idx as u32);
                failed_tx.hash = hash;

                let result = Ok(status);
                let record_by_table = TxByTable::FailedPayable(failed_tx);
                (tx_hash, result, record_by_table)
            }
        }
    }

    #[test]
    fn accountant_handles_registering_new_pending_payables() {
        init_test_logging();
        let test_name = "accountant_handles_registering_new_pending_payables";
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let subject = AccountantBuilder::default()
            .sent_payable_daos(vec![ForAccountantBody(sent_payable_dao)])
            .logger(Logger::new(test_name))
            .build();
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let mut sent_tx_1 = make_sent_tx(456);
        let hash_1 = make_tx_hash(0x6c81c);
        sent_tx_1.hash = hash_1;
        let mut sent_tx_2 = make_sent_tx(789);
        let hash_2 = make_tx_hash(0x1b207);
        sent_tx_2.hash = hash_2;
        let new_sent_txs = vec![sent_tx_1.clone(), sent_tx_2.clone()];
        let msg = RegisterNewPendingPayables { new_sent_txs };

        let _ = accountant_subs
            .register_new_pending_payables
            .try_send(msg)
            .unwrap();

        let system = System::new("ordering payment sent tx record test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_records_params,
            vec![BTreeSet::from([sent_tx_1, sent_tx_2])]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Registered new pending payables for: \
             0x000000000000000000000000000000000000000000000000000000000006c81c, \
             0x000000000000000000000000000000000000000000000000000000000001b207",
        ));
    }

    #[test]
    fn sent_payable_insertion_clearly_failed_and_we_log_at_least() {
        // Even though it's factually a filed db operation, which is treated by an instant panic
        // due to the broken db reliance, this is an exception. We give out some time to complete
        // the actual paying and panic soon after when we figure out, from a different place
        // that some sent tx records are missing. This should eventually be eliminated by GH-655
        init_test_logging();
        let test_name = "sent_payable_insertion_clearly_failed_and_we_log_at_least";
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Err(SentPayableDaoError::SqlExecutionFailed(
                "Crashed".to_string(),
            )));
        let tx_hash_1 = make_tx_hash(0x1c8);
        let mut sent_tx_1 = make_sent_tx(456);
        sent_tx_1.hash = tx_hash_1;
        let tx_hash_2 = make_tx_hash(0x1b2);
        let mut sent_tx_2 = make_sent_tx(789);
        sent_tx_2.hash = tx_hash_2;
        let subject = AccountantBuilder::default()
            .sent_payable_daos(vec![ForAccountantBody(sent_payable_dao)])
            .logger(Logger::new(test_name))
            .build();
        let msg = RegisterNewPendingPayables {
            new_sent_txs: vec![sent_tx_1.clone(), sent_tx_2.clone()],
        };

        let _ = subject.register_new_pending_sent_tx(msg);

        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_records_params,
            vec![BTreeSet::from([sent_tx_1, sent_tx_2])]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Failed to save new pending payable records for \
            0x00000000000000000000000000000000000000000000000000000000000001c8, \
            0x00000000000000000000000000000000000000000000000000000000000001b2 \
            due to 'SqlExecutionFailed(\"Crashed\")' which is integral to the function \
            of the automated tx confirmation"
        ));
    }

    const EXAMPLE_RESPONSE_SKELETON: ResponseSkeleton = ResponseSkeleton {
        client_id: 1234,
        context_id: 4321,
    };

    const EXAMPLE_ERROR_MSG: &str = "My tummy hurts";

    fn do_setup_and_prepare_assertions_for_new_payables(
    ) -> Box<dyn FnOnce(&mut Scanners, &mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(
            |_scanners: &mut Scanners, scan_schedulers: &mut ScanSchedulers| {
                // Setup
                let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
                scan_schedulers.payable.interval_computer = Box::new(
                    NewPayableScanIntervalComputerMock::default()
                        .time_until_next_scan_result(ScanTiming::WaitFor(Duration::from_secs(152))),
                );
                scan_schedulers.payable.new_payable_notify_later = Box::new(
                    NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
                );

                // Assertions
                Box::new(move |response_skeleton_opt| {
                    let notify_later_params = notify_later_params_arc.lock().unwrap();
                    match response_skeleton_opt {
                        None => assert_eq!(
                            *notify_later_params,
                            vec![(ScanForNewPayables::default(), Duration::from_secs(152))]
                        ),
                        Some(_) => {
                            assert!(
                                notify_later_params.is_empty(),
                                "Should be empty but contained {:?}",
                                notify_later_params
                            )
                        }
                    }
                })
            },
        )
    }

    fn do_setup_and_prepare_assertions_for_retry_payables(
    ) -> Box<dyn FnOnce(&mut Scanners, &mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(
            |_scanners: &mut Scanners, scan_schedulers: &mut ScanSchedulers| {
                // Setup
                let notify_params_arc = Arc::new(Mutex::new(vec![]));
                scan_schedulers.payable.retry_payable_notify =
                    Box::new(NotifyHandleMock::default().notify_params(&notify_params_arc));

                // Assertions
                Box::new(move |response_skeleton_opt| {
                    let notify_params = notify_params_arc.lock().unwrap();
                    match response_skeleton_opt {
                        None => {
                            // Response skeleton must be None
                            assert_eq!(
                                *notify_params,
                                vec![ScanForRetryPayables {
                                    response_skeleton_opt: None
                                }]
                            )
                        }
                        Some(_) => {
                            assert!(
                                notify_params.is_empty(),
                                "Should be empty but contained {:?}",
                                notify_params
                            )
                        }
                    }
                })
            },
        )
    }

    fn do_setup_and_prepare_assertions_for_pending_payables(
    ) -> Box<dyn FnOnce(&mut Scanners, &mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(
            |scanners: &mut Scanners, scan_schedulers: &mut ScanSchedulers| {
                // Setup
                let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
                let ensure_empty_cache_sent_tx_params_arc = Arc::new(Mutex::new(vec![]));
                let ensure_empty_cache_failed_tx_params_arc = Arc::new(Mutex::new(vec![]));
                scan_schedulers.pending_payable.interval = Duration::from_secs(600);
                scan_schedulers.pending_payable.handle = Box::new(
                    NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
                );
                let sent_payable_cache = PendingPayableCacheMock::default()
                    .ensure_empty_cache_params(&ensure_empty_cache_sent_tx_params_arc);
                let failed_payable_cache = PendingPayableCacheMock::default()
                    .ensure_empty_cache_params(&ensure_empty_cache_failed_tx_params_arc);
                let scanner = PendingPayableScannerBuilder::new()
                    .sent_payable_cache(Box::new(sent_payable_cache))
                    .failed_payable_cache(Box::new(failed_payable_cache))
                    .build();
                scanners.replace_scanner(ScannerReplacement::PendingPayable(
                    ReplacementType::Real(scanner),
                ));

                // Assertions
                Box::new(move |response_skeleton_opt| {
                    let notify_later_params = notify_later_params_arc.lock().unwrap();
                    match response_skeleton_opt {
                        None => {
                            assert_eq!(
                                *notify_later_params,
                                vec![(ScanForPendingPayables::default(), Duration::from_secs(600))]
                            )
                        }
                        Some(_) => {
                            assert!(
                                notify_later_params.is_empty(),
                                "Should be empty but contained {:?}",
                                notify_later_params
                            )
                        }
                    }
                    let ensure_empty_cache_sent_tx_params =
                        ensure_empty_cache_sent_tx_params_arc.lock().unwrap();
                    assert_eq!(*ensure_empty_cache_sent_tx_params, vec![()]);
                    let ensure_empty_cache_failed_tx_params =
                        ensure_empty_cache_failed_tx_params_arc.lock().unwrap();
                    assert_eq!(*ensure_empty_cache_failed_tx_params, vec![()]);
                })
            },
        )
    }

    fn do_setup_and_prepare_assertions_for_receivables(
    ) -> Box<dyn FnOnce(&mut Scanners, &mut ScanSchedulers) -> RunSchedulersAssertions> {
        Box::new(
            |_scanners: &mut Scanners, scan_schedulers: &mut ScanSchedulers| {
                // Setup
                let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
                scan_schedulers.receivable.interval = Duration::from_secs(600);
                scan_schedulers.receivable.handle = Box::new(
                    NotifyLaterHandleMock::default().notify_later_params(&notify_later_params_arc),
                );

                // Assertions
                Box::new(move |response_skeleton_opt| {
                    let notify_later_params = notify_later_params_arc.lock().unwrap();
                    match response_skeleton_opt {
                        None => {
                            assert_eq!(
                                *notify_later_params,
                                vec![(ScanForReceivables::default(), Duration::from_secs(600))]
                            )
                        }
                        Some(_) => {
                            assert!(
                                notify_later_params.is_empty(),
                                "Should be empty but contained {:?}",
                                notify_later_params
                            )
                        }
                    }
                })
            },
        )
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_new_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_new_payables",
            ScanError {
                scan_type: DetailedScanType::NewPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_new_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_retry_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_retry_payables",
            ScanError {
                scan_type: DetailedScanType::RetryPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_retry_payables(),
        )
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_pending_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_pending_payables",
            ScanError {
                scan_type: DetailedScanType::PendingPayables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_pending_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_externally_triggered_receivables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_externally_triggered_receivables",
            ScanError {
                scan_type: DetailedScanType::Receivables,
                response_skeleton_opt: Some(EXAMPLE_RESPONSE_SKELETON),
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_receivables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_new_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_new_payables",
            ScanError {
                scan_type: DetailedScanType::NewPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_new_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_retry_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_retry_payables",
            ScanError {
                scan_type: DetailedScanType::RetryPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_retry_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_pending_payables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_pending_payables",
            ScanError {
                scan_type: DetailedScanType::PendingPayables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_pending_payables(),
        );
    }

    #[test]
    fn handling_scan_error_for_internally_triggered_receivables() {
        test_scan_error_is_handled_properly(
            "handling_scan_error_for_internally_triggered_receivables",
            ScanError {
                scan_type: DetailedScanType::Receivables,
                response_skeleton_opt: None,
                msg: EXAMPLE_ERROR_MSG.to_string(),
            },
            do_setup_and_prepare_assertions_for_receivables(),
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
            .bootstrapper_config(make_bc_with_defaults(TEST_DEFAULT_CHAIN))
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

    type RunSchedulersAssertions = Box<dyn Fn(Option<ResponseSkeleton>)>;

    fn test_scan_error_is_handled_properly(
        test_name: &str,
        message: ScanError,
        set_up_schedulers_and_prepare_assertions: Box<
            dyn FnOnce(&mut Scanners, &mut ScanSchedulers) -> RunSchedulersAssertions,
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
        let run_schedulers_assertions = set_up_schedulers_and_prepare_assertions(
            &mut subject.scanners,
            &mut subject.scan_schedulers,
        );
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
        run_schedulers_assertions(message.response_skeleton_opt);
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
    use std::collections::BTreeSet;
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

    #[test]
    fn join_with_separator_works() {
        // With a Vec
        let vec = vec![1, 2, 3];
        let result_vec = join_with_separator(vec, |&num| num.to_string(), ", ");
        assert_eq!(result_vec, "1, 2, 3".to_string());

        // With a HashSet
        let set = BTreeSet::from([1, 2, 3]);
        let result_set = join_with_separator(set, |&num| num.to_string(), ", ");
        assert_eq!(result_set, "1, 2, 3".to_string());

        // With a slice
        let slice = &[1, 2, 3];
        let result_slice = join_with_separator(slice.to_vec(), |&num| num.to_string(), ", ");
        assert_eq!(result_slice, "1, 2, 3".to_string());

        // With an array
        let array = [1, 2, 3];
        let result_array = join_with_separator(array.to_vec(), |&num| num.to_string(), ", ");
        assert_eq!(result_array, "1, 2, 3".to_string());
    }
}
