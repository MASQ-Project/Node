// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
pub mod payable_dao;
pub mod pending_payable_dao;
pub mod receivable_dao;
pub mod scanners;
pub mod scanners_tools;

#[cfg(test)]
pub mod test_utils;

use masq_lib::constants::SCAN_ERROR;
use std::cell::{Ref, RefCell};

use masq_lib::messages::{ScanType, UiScanRequest};
use masq_lib::ui_gateway::{MessageBody, MessagePath};

use crate::accountant::payable_dao::{Payable, PayableDaoError};
use crate::accountant::pending_payable_dao::PendingPayableDao;
use crate::accountant::receivable_dao::ReceivableDaoError;
use crate::accountant::scanners::{NotifyLaterForScanners, Scanners};
use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainTransaction};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::DaoFactoryReal;
use crate::database::db_migrations::MigratorConfig;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::ReportServicesConsumedMessage;
use crate::sub_lib::accountant::{AccountantSubs, ScanIntervals};
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics};
use crate::sub_lib::accountant::{MessageIdGenerator, MessageIdGeneratorReal};
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
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
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::messages::UiFinancialsResponse;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use payable_dao::PayableDao;
use receivable_dao::ReceivableDao;
use std::default::Default;
use std::path::Path;
use std::rc::Rc;
use std::time::SystemTime;
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "ACCOUNTANT";

pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

pub struct Accountant {
    scan_intervals: ScanIntervals,
    suppress_initial_scans: bool,
    consuming_wallet: Option<Wallet>,
    earning_wallet: Rc<Wallet>,
    payable_dao: Box<dyn PayableDao>,
    receivable_dao: Box<dyn ReceivableDao>,
    pending_payable_dao: Box<dyn PendingPayableDao>,
    crashable: bool,
    scanners: Scanners,
    notify_later: NotifyLaterForScanners,
    financial_statistics: Rc<RefCell<FinancialStatistics>>,
    report_accounts_payable_sub_opt: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayable>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
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

#[derive(Debug, Message, PartialEq, Eq)]
pub struct ReceivedPayments {
    pub timestamp: SystemTime,
    pub payments: Vec<BlockchainTransaction>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, PartialEq, Eq)]
pub struct SentPayable {
    pub timestamp: SystemTime,
    pub payable: Vec<Result<Payable, BlockchainError>>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Eq, Message, PartialEq, Clone, Copy)]
pub struct ScanForPayables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Message, PartialEq, Eq, Clone, Copy)]
pub struct ScanForReceivables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Clone, Copy, Message, PartialEq, Eq)]
pub struct ScanForPendingPayables {
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, Clone, Message, PartialEq, Eq)]
pub struct ScanError {
    pub scan_type: ScanType,
    pub response_skeleton: ResponseSkeleton,
    pub msg: String,
}

impl Handler<BindMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        self.handle_bind_message(msg);
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
    }
}

impl Handler<StartMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: StartMessage, ctx: &mut Self::Context) -> Self::Result {
        if self.suppress_initial_scans {
            info!(
                &self.logger,
                "Started with --scans off; declining to begin database and blockchain scans"
            );
        } else {
            debug!(
                &self.logger,
                "Started with --scans on; starting database and blockchain scans"
            );
            ctx.notify(ScanForPendingPayables {
                response_skeleton_opt: None,
            });
            ctx.notify(ScanForPayables {
                response_skeleton_opt: None,
            });
            ctx.notify(ScanForReceivables {
                response_skeleton_opt: None,
            });
        }
    }
}

impl Handler<ReceivedPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReceivedPayments, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(node_to_ui_msg) = self.scanners.receivable.finish_scan(msg, &self.logger) {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(node_to_ui_msg)
                .expect("UIGateway is dead");
        }
    }
}

impl Handler<SentPayable> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: SentPayable, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(node_to_ui_msg) = self.scanners.payable.finish_scan(msg, &self.logger) {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(node_to_ui_msg)
                .expect("UIGateway is dead");
        }
    }
}

impl Handler<ScanForPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPayables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_request_of_scan_for_payable(msg.response_skeleton_opt);
        let _ = self.notify_later.scan_for_payable.notify_later(
            ScanForPayables {
                response_skeleton_opt: None,
            },
            self.scan_intervals.payable_scan_interval,
            ctx,
        );
    }
}

impl Handler<ScanForPendingPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPendingPayables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_request_of_scan_for_pending_payable(msg.response_skeleton_opt);
        let _ = self.notify_later.scan_for_pending_payable.notify_later(
            ScanForPendingPayables {
                response_skeleton_opt: None, // because scheduled scans don't respond
            },
            self.scan_intervals.pending_payable_scan_interval,
            ctx,
        );
    }
}

impl Handler<ScanForReceivables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForReceivables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_request_of_scan_for_receivable(msg.response_skeleton_opt);
        let _ = self.notify_later.scan_for_receivable.notify_later(
            ScanForReceivables {
                response_skeleton_opt: None, // because scheduled scans don't respond
            },
            self.scan_intervals.receivable_scan_interval,
            ctx,
        );
    }
}

impl Handler<ScanError> for Accountant {
    type Result = ();

    fn handle(&mut self, scan_error: ScanError, _ctx: &mut Self::Context) -> Self::Result {
        error!(self.logger, "Received ScanError: {:?}", scan_error);
        let error_msg = NodeToUiMessage {
            target: ClientId(scan_error.response_skeleton.client_id),
            body: MessageBody {
                opcode: "scan".to_string(),
                path: MessagePath::Conversation(scan_error.response_skeleton.context_id),
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
        self.ui_message_sub
            .as_ref()
            .expect("UIGateway not bound")
            .try_send(error_msg)
            .expect("UiGateway is dead");
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
    pub pending_payable: Vec<PendingPayableFingerprint>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for RequestTransactionReceipts {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub fingerprints_with_receipts: Vec<(Option<TransactionReceipt>, PendingPayableFingerprint)>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl Handler<ReportTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReportTransactionReceipts, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(node_to_ui_msg) = self.scanners.pending_payable.finish_scan(msg, &self.logger) {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(node_to_ui_msg)
                .expect("UIGateway is dead");
        }
    }
}

impl Handler<PendingPayableFingerprint> for Accountant {
    type Result = ();
    fn handle(&mut self, msg: PendingPayableFingerprint, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_new_pending_payable_fingerprint(msg)
    }
}

impl Handler<NodeFromUiMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        if let Ok((_, context_id)) = UiFinancialsRequest::fmb(msg.body.clone()) {
            self.handle_financials(client_id, context_id);
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
        let earning_wallet = Rc::new(config.earning_wallet);
        let financial_statistics = Rc::new(RefCell::new(FinancialStatistics::default()));
        let payable_dao = dao_factories.payable_dao_factory.make();
        let pending_payable_dao = dao_factories.pending_payable_dao_factory.make();
        let receivable_dao = dao_factories.receivable_dao_factory.make();
        let scanners = Scanners::new(
            dao_factories,
            Rc::new(payment_thresholds),
            Rc::clone(&earning_wallet),
            config.when_pending_too_long_sec,
            Rc::clone(&financial_statistics),
        );

        Accountant {
            scan_intervals,
            suppress_initial_scans: config.suppress_initial_scans,
            consuming_wallet: config.consuming_wallet_opt.clone(),
            earning_wallet: Rc::clone(&earning_wallet),
            payable_dao,
            receivable_dao,
            pending_payable_dao,
            scanners,
            crashable: config.crash_point == CrashPoint::Message,
            notify_later: NotifyLaterForScanners::default(),
            financial_statistics: Rc::clone(&financial_statistics),
            report_accounts_payable_sub_opt: None,
            retrieve_transactions_sub: None,
            request_transaction_receipts_subs_opt: None,
            report_new_payments_sub: None,
            report_sent_payments_sub: None,
            ui_message_sub: None,
            message_id_generator: Box::new(MessageIdGeneratorReal::default()),
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: recipient!(addr, BindMessage),
            start: recipient!(addr, StartMessage),
            report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
            report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
            report_services_consumed: recipient!(addr, ReportServicesConsumedMessage),
            report_new_payments: recipient!(addr, ReceivedPayments),
            pending_payable_fingerprint: recipient!(addr, PendingPayableFingerprint),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayable),
            scan_errors: recipient!(addr, ScanError),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, false, MigratorConfig::panic_on_migration())
    }

    fn record_service_provided(
        &self,
        service_rate: u64,
        byte_rate: u64,
        timestamp: SystemTime,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.receivable_dao
                .as_ref()
                .more_money_receivable(timestamp,wallet, total_charge) {
                Ok(_) => (),
                Err(ReceivableDaoError::SignConversion(_)) => error! (
                    self.logger,
                    "Overflow error recording service provided for {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(e)=> panic!("Recording services provided for {} but has hit fatal database error: {:?}", wallet, e)
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
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.payable_dao
                .as_ref()
                .more_money_payable(timestamp, wallet, total_charge) {
                Ok(_) => (),
                Err(PayableDaoError::SignConversion(_)) => error! (
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
        match &self.consuming_wallet {
            Some(ref consuming) if consuming.address() == wallet.address() => true,
            _ => wallet.address() == self.earning_wallet.address(),
        }
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        self.report_accounts_payable_sub_opt =
            Some(msg.peer_actors.blockchain_bridge.report_accounts_payable);
        self.retrieve_transactions_sub =
            Some(msg.peer_actors.blockchain_bridge.retrieve_transactions);
        self.report_new_payments_sub = Some(msg.peer_actors.accountant.report_new_payments);
        self.report_sent_payments_sub = Some(msg.peer_actors.accountant.report_sent_payments);
        self.ui_message_sub = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
        self.request_transaction_receipts_subs_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .request_transaction_receipts,
        );
        info!(self.logger, "Accountant bound");
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

    fn handle_financials(&mut self, client_id: u64, context_id: u64) {
        let financial_statistics = self.financial_statistics();
        let total_unpaid_and_pending_payable = self.payable_dao.total();
        let total_paid_payable = financial_statistics.total_paid_payable;
        let total_unpaid_receivable = self.receivable_dao.total();
        let total_paid_receivable = financial_statistics.total_paid_receivable;
        let body = UiFinancialsResponse {
            total_unpaid_and_pending_payable,
            total_paid_payable,
            total_unpaid_receivable,
            total_paid_receivable,
        }
        .tmb(context_id);
        self.ui_message_sub
            .as_ref()
            .expect("UiGateway not bound")
            .try_send(NodeToUiMessage {
                target: ClientId(client_id),
                body,
            })
            .expect("UiGateway is dead");
    }

    fn handle_request_of_scan_for_payable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        match self.scanners.payable.begin_scan(
            SystemTime::now(),
            response_skeleton_opt,
            &self.logger,
        ) {
            Ok(scan_message) => {
                self.report_accounts_payable_sub_opt
                    .as_ref()
                    .expect("BlockchainBridge is unbound")
                    .try_send(scan_message.clone())
                    .expect("BlockchainBridge is dead");
            }
            Err(e) => e.handle_error(
                &self.logger,
                ScanType::Payables,
                response_skeleton_opt.is_some(),
            ),
        }
    }

    fn handle_request_of_scan_for_pending_payable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        match self.scanners.pending_payable.begin_scan(
            SystemTime::now(),
            response_skeleton_opt,
            &self.logger,
        ) {
            Ok(scan_message) => self
                .request_transaction_receipts_subs_opt
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(scan_message)
                .expect("BlockchainBridge is dead"),
            Err(e) => e.handle_error(
                &self.logger,
                ScanType::PendingPayables,
                response_skeleton_opt.is_some(),
            ),
        }
    }

    fn handle_request_of_scan_for_receivable(
        &mut self,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        match self.scanners.receivable.begin_scan(
            SystemTime::now(),
            response_skeleton_opt,
            &self.logger,
        ) {
            Ok(scan_message) => self
                .retrieve_transactions_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(scan_message)
                .expect("BlockchainBridge is dead"),
            Err(e) => e.handle_error(
                &self.logger,
                ScanType::Receivables,
                response_skeleton_opt.is_some(),
            ),
        };
    }

    fn handle_externally_triggered_scan(
        &mut self,
        _ctx: &mut Context<Accountant>,
        scan_type: ScanType,
        response_skeleton: ResponseSkeleton,
    ) {
        match scan_type {
            ScanType::Payables => self.handle_request_of_scan_for_payable(Some(response_skeleton)),
            ScanType::PendingPayables => {
                self.handle_request_of_scan_for_pending_payable(Some(response_skeleton));
            }
            ScanType::Receivables => {
                self.handle_request_of_scan_for_receivable(Some(response_skeleton))
            }
        }
    }

    fn handle_new_pending_payable_fingerprint(&self, msg: PendingPayableFingerprint) {
        match self
            .pending_payable_dao
            .insert_new_fingerprint(msg.hash, msg.amount, msg.timestamp)
        {
            Ok(_) => debug!(
                self.logger,
                "Processed a pending payable fingerprint for '{:?}'", msg.hash
            ),
            Err(e) => error!(
                self.logger,
                "Failed to make a fingerprint for pending payable '{:?}' due to '{:?}'",
                msg.hash,
                e
            ),
        }
    }

    fn financial_statistics(&self) -> Ref<'_, FinancialStatistics> {
        self.financial_statistics.borrow()
    }
}

pub fn unsigned_to_signed(unsigned: u64) -> Result<i64, u64> {
    i64::try_from(unsigned).map_err(|_| unsigned)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PendingTransactionStatus {
    StillPending(PendingPayableId), //updates slightly the record, waits an interval and starts a new round
    Failure(PendingPayableId),      //official tx failure
    Confirmed(PendingPayableFingerprint), //tx was fully processed and successful
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PendingPayableId {
    pub rowid: u64,
    pub hash: H256,
}

impl From<&PendingPayableFingerprint> for PendingPayableId {
    fn from(pending_payable_fingerprint: &PendingPayableFingerprint) -> Self {
        Self {
            hash: pending_payable_fingerprint.hash,
            rowid: pending_payable_fingerprint
                .rowid_opt
                .expectv("initialized rowid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::ops::{Add, Sub};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use actix::{Arbiter, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use itertools::Itertools;
    use log::Level;
    use masq_lib::constants::SCAN_ERROR;
    use web3::types::U256;

    use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};

    use crate::accountant::payable_dao::{PayableAccount, PayableDaoError};
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::scanners::{BeginScanError, NullScanner, ScannerMock};
    use crate::accountant::test_utils::{
        bc_from_earning_wallet, bc_from_wallets, make_payables, BannedDaoFactoryMock,
        MessageIdGeneratorMock, PayableDaoFactoryMock, PayableDaoMock,
        PendingPayableDaoFactoryMock, PendingPayableDaoMock, ReceivableDaoFactoryMock,
        ReceivableDaoMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::Accountant;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::BlockchainTransaction;
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolsWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::sub_lib::accountant::{
        ExitServiceConsumed, PaymentThresholds, RoutingServiceConsumed, ScanIntervals,
        DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::utils::NotifyLaterHandleReal;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::unshared_test_utils::{
        make_bc_with_defaults, prove_that_crash_request_handler_is_hooked_up,
        NotifyLaterHandleMock, SystemKillerActor,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use web3::types::{TransactionReceipt, H256};

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

        let _ = Accountant::new(
            config,
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
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

        let result = Accountant::new(
            bootstrapper_config,
            DaoFactories {
                payable_dao_factory,
                pending_payable_dao_factory,
                receivable_dao_factory,
                banned_dao_factory,
            },
        );

        let financial_statistics = result.financial_statistics().clone();
        let notify_later = result.notify_later;
        notify_later
            .scan_for_pending_payable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForPendingPayables>>()
            .unwrap();
        notify_later
            .scan_for_payable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForPayables>>()
            .unwrap();
        notify_later
            .scan_for_receivable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForReceivables>>();
        result
            .message_id_generator
            .as_any()
            .downcast_ref::<MessageIdGeneratorReal>()
            .unwrap();
        assert_eq!(result.crashable, false);
        assert_eq!(financial_statistics.total_paid_receivable, 0);
        assert_eq!(financial_statistics.total_paid_payable, 0);
    }

    #[test]
    fn scan_receivables_request() {
        let mut config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_dao(ReceivableDaoMock::new())
            .receivable_dao(receivable_dao)
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::Receivables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
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
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        config.suppress_initial_scans = true;
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let received_payments = ReceivedPayments {
            timestamp: SystemTime::now(),
            payments: vec![],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
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
    fn scan_payables_request() {
        let config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        let payable_account = PayableAccount {
            wallet: make_wallet("wallet"),
            balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1,
            last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(
                (DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 1) as u64,
            )),
            pending_payable_opt: None,
        };
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(vec![payable_account.clone()]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::Payables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recording.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable {
                accounts: vec![payable_account],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            }
        );
    }

    #[test]
    fn sent_payable_with_response_skeleton_sends_scan_response_to_ui_gateway() {
        let config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

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
    fn scan_pending_payables_request() {
        let mut config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        config.suppress_initial_scans = true;
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(1234),
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt_opt: Some(1),
            amount: 1_000_000,
            process_error: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_fingerprints_result(vec![fingerprint.clone()]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Payable Scanner
            .pending_payable_dao(pending_payable_dao) // For PendingPayable Scanner
            .build();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::PendingPayables,
            }
            .tmb(4321),
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0),
            &RequestTransactionReceipts {
                pending_payable: vec![fingerprint],
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                }),
            }
        );
    }

    #[test]
    fn scan_request_from_ui_is_handled_in_case_the_scan_is_already_running() {
        init_test_logging();
        let test_name = "scan_request_from_ui_is_handled_in_case_the_scan_is_already_running";
        let mut config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        config.suppress_initial_scans = true;
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(1234),
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt_opt: Some(1),
            amount: 1_000_000,
            process_error: None,
        };
        let pending_payable_dao =
            PendingPayableDaoMock::default().return_all_fingerprints_result(vec![fingerprint]);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Payable Scanner
            .pending_payable_dao(pending_payable_dao) // For PendingPayable Scanner
            .build();
        subject.logger = Logger::new(test_name);
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let first_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiScanRequest {
                scan_type: ScanType::PendingPayables,
            }
            .tmb(4321),
        };
        let second_message = first_message.clone();
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr.try_send(first_message).unwrap();

        subject_addr.try_send(second_message).unwrap();

        System::current().stop();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {}: PendingPayables scan was already initiated",
            test_name
        ));
        assert_eq!(blockchain_bridge_recording.len(), 1);
    }

    #[test]
    fn report_transaction_receipts_with_response_skeleton_sends_scan_response_to_ui_gateway() {
        let mut config = bc_from_earning_wallet(make_wallet("earning_wallet"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(10_000),
            receivable_scan_interval: Duration::from_millis(10_000),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let report_transaction_receipts = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![],
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 4321,
            }),
        };

        subject_addr.try_send(report_transaction_receipts).unwrap();

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
    fn accountant_calls_payable_dao_to_mark_pending_payable() {
        let fingerprint_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payable_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_wallet = make_wallet("paying_you");
        let expected_amount = 12;
        let expected_hash = H256::from("transaction_hash".keccak256());
        let expected_timestamp = SystemTime::now();
        let expected_rowid = 45623;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(expected_rowid));
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_params(&mark_pending_payable_rowid_params_arc)
            .mark_pending_payable_rowid_result(Ok(()));
        let system = System::new("accountant_calls_payable_dao_to_mark_pending_payable");
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(pending_payable_dao) // For Payable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        let expected_payable = Payable::new(
            expected_wallet.clone(),
            expected_amount,
            expected_hash.clone(),
            expected_timestamp,
        );
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![Ok(expected_payable.clone())],
            response_skeleton_opt: None,
        };
        let subject = accountant.start();

        subject
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(*fingerprint_rowid_params, vec![expected_hash]);
        let mark_pending_payable_rowid_params =
            mark_pending_payable_rowid_params_arc.lock().unwrap();
        let actual = mark_pending_payable_rowid_params.get(0).unwrap();
        assert_eq!(actual, &(expected_wallet, expected_rowid));
    }

    #[test]
    fn accountant_logs_and_aborts_when_handle_sent_payable_finds_an_error_from_post_hash_time_and_the_pending_payable_fingerprint_does_not_exist(
    ) {
        init_test_logging();
        let system = System::new("sent payable failure without backup");
        let pending_payable_dao = PendingPayableDaoMock::default().fingerprint_rowid_result(None);
        let accountant = AccountantBuilder::default()
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(pending_payable_dao) // For Payable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        let hash = H256::from_uint(&U256::from(12345));
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![Err(BlockchainError::TransactionFailed {
                msg: "SQLite migraine".to_string(),
                hash_opt: Some(hash),
            })],
            response_skeleton_opt: None,
        };
        let subject = accountant.start();

        subject
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let log_handler = TestLogHandler::new();
        log_handler.exists_no_log_containing(&format!(
            "DEBUG: Accountant: Deleting an existing backup for a failed transaction {:?}",
            hash
        ));
        log_handler.exists_log_containing(&format!(
            "WARN: Accountant: Encountered transaction error at this end: 'TransactionFailed \
         {{ msg: \"SQLite migraine\", hash_opt: Some({:?}) }}'",
            hash
        ));
        log_handler.exists_log_containing(
            r#"WARN: Accountant: Failed transaction with a hash '0x0000000000000000000000000000000000000000000000000000000000003039' but without the record - thrown out"#,
        );
    }

    #[test]
    fn handle_sent_payable_discovers_failed_transaction_and_pending_payable_fingerprint_was_really_created(
    ) {
        init_test_logging();
        let fingerprint_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payable_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let good_transaction_rowid = 3;
        let failed_transaction_rowid = 5;
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_params(&mark_pending_payable_rowid_params_arc)
            .mark_pending_payable_rowid_result(Ok(()));
        let system = System::new("accountant_calls_payable_dao_payment_sent_when_sent_payments");
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(good_transaction_rowid)) //for the correct transaction before mark_pending_payment
            .fingerprint_rowid_result(Some(failed_transaction_rowid)) //err, to find out if the backup has been created or if the error occurred before that
            .delete_fingerprint_params(&delete_fingerprint_params_arc)
            .delete_fingerprint_result(Ok(()));
        let subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(pending_payable_dao) // For Payable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Scanner
            .build();
        let wallet = make_wallet("blah");
        let hash_tx_1 = H256::from_uint(&U256::from(5555));
        let hash_tx_2 = H256::from_uint(&U256::from(12345));
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![
                Ok(Payable {
                    to: wallet.clone(),
                    amount: 5656,
                    timestamp: SystemTime::now(),
                    tx_hash: hash_tx_1,
                }),
                Err(BlockchainError::TransactionFailed {
                    msg: "Attempt failed".to_string(),
                    hash_opt: Some(hash_tx_2),
                }),
            ],
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();

        subject_addr
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let pending_payable_fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(
            *pending_payable_fingerprint_rowid_params,
            vec![hash_tx_1, hash_tx_2]
        );
        let mark_pending_payable_params = mark_pending_payable_rowid_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payable_params,
            vec![(wallet, good_transaction_rowid)]
        );
        let delete_pending_payable_fingerprint_params =
            delete_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *delete_pending_payable_fingerprint_params,
            vec![failed_transaction_rowid]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error at this end: \
         'TransactionFailed { msg: \"Attempt failed\", hash_opt: Some(0x0000000000000000000000000000000000000000000000000000000000003039)");
        log_handler.exists_log_containing(
            "DEBUG: Accountant: Deleting an existing fingerprint for a failed transaction 0x0000000000000000000000000000000000000000000000000000000000003039",
        );
    }

    #[test]
    fn accountant_sends_report_accounts_payable_to_blockchain_bridge_when_qualified_payable_found()
    {
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let (qualified_payables, _, all_non_pending_payables) =
            make_payables(now, &payment_thresholds);
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let system = System::new("report_accounts_payable forwarded to blockchain_bridge");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(make_wallet("some_wallet_address")))
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner::new());
        subject.scanners.receivable = Box::new(NullScanner::new());
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        System::current().stop();
        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let message = blockchain_bridge_recorder.get_record::<ReportAccountsPayable>(0);
        assert_eq!(
            message,
            &ReportAccountsPayable {
                accounts: qualified_payables,
                response_skeleton_opt: None,
            }
        );
    }

    #[test]
    fn accountant_sends_a_request_to_blockchain_bridge_to_scan_for_received_payments() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let earning_wallet = make_wallet("someearningwallet");
        let system = System::new(
            "accountant_sends_a_request_to_blockchain_bridge_to_scan_for_received_payments",
        );
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(earning_wallet.clone()))
            .receivable_dao(ReceivableDaoMock::new()) // For Accountant
            .receivable_dao(receivable_dao) // For Scanner
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner::new());
        subject.scanners.payable = Box::new(NullScanner::new());
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        System::current().stop();
        system.run();
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let retrieve_transactions_msg =
            blockchain_bridge_recorder.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            retrieve_transactions_msg,
            &RetrieveTransactions {
                recipient: earning_wallet.clone(),
                response_skeleton_opt: None,
            }
        );
    }

    #[test]
    fn accountant_receives_new_payments_to_the_receivables_dao() {
        let now = SystemTime::now();
        let earning_wallet = make_wallet("earner3000");
        let expected_receivable_1 = BlockchainTransaction {
            block_number: 7,
            from: make_wallet("wallet0"),
            gwei_amount: 456,
        };
        let expected_receivable_2 = BlockchainTransaction {
            block_number: 13,
            from: make_wallet("wallet1"),
            gwei_amount: 10000,
        };
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_parameters(&more_money_received_params_arc)
            .more_money_received_result(Ok(()));
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(bc_from_earning_wallet(earning_wallet.clone()))
            .receivable_dao(ReceivableDaoMock::new())
            .receivable_dao(receivable_dao)
            .build();
        let system = System::new("accountant_receives_new_payments_to_the_receivables_dao");
        let subject = accountant.start();

        subject
            .try_send(ReceivedPayments {
                timestamp: now,
                payments: vec![expected_receivable_1.clone(), expected_receivable_2.clone()],
                response_skeleton_opt: None,
            })
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(
            *more_money_received_params,
            vec![(now, vec![expected_receivable_1, expected_receivable_2])]
        )
    }

    #[test]
    fn accountant_scans_after_startup() {
        init_test_logging();
        let pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_params_arc = Arc::new(Mutex::new(vec![]));
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, _) = make_recorder();
        let earning_wallet = make_wallet("earning");
        let system = System::new("accountant_scans_after_startup");
        let config = bc_from_wallets(make_wallet("buy"), earning_wallet.clone());
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&payable_params_arc)
            .non_pending_payables_result(vec![]);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_fingerprints_params(&pending_payable_params_arc)
            .return_all_fingerprints_result(vec![]);
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_params_arc)
            .new_delinquencies_result(vec![])
            .paid_delinquencies_parameters(&paid_delinquencies_params_arc)
            .paid_delinquencies_result(vec![]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Payable Scanner
            .pending_payable_dao(pending_payable_dao) // For PendingPayable Scanner
            .receivable_dao(ReceivableDaoMock::new()) // For Accountant
            .receivable_dao(receivable_dao) // For Scanner
            .build();
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        System::current().stop();
        system.run();
        let payable_params = payable_params_arc.lock().unwrap();
        let pending_payable_params = pending_payable_params_arc.lock().unwrap();
        //proof of calling pieces of scan_for_delinquencies()
        let mut new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        let (captured_timestamp, captured_curves) = new_delinquencies_params.remove(0);
        let paid_delinquencies_params = paid_delinquencies_params_arc.lock().unwrap();
        assert_eq!(*payable_params, vec![()]);
        assert_eq!(*pending_payable_params, vec![()]);
        assert!(new_delinquencies_params.is_empty());
        assert!(
            captured_timestamp < SystemTime::now()
                && captured_timestamp >= from_time_t(to_time_t(SystemTime::now()) - 5)
        );
        assert_eq!(captured_curves, PaymentThresholds::default());
        assert_eq!(paid_delinquencies_params.len(), 1);
        assert_eq!(paid_delinquencies_params[0], PaymentThresholds::default());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("INFO: Accountant: Scanning for payables");
        tlh.exists_log_containing("INFO: Accountant: Scanning for pending payable");
        tlh.exists_log_containing(&format!(
            "INFO: Accountant: Scanning for receivables to {}",
            earning_wallet
        ));
        tlh.exists_log_containing("INFO: Accountant: Scanning for delinquencies");
    }

    #[test]
    fn periodical_scanning_for_receivables_and_delinquencies_works() {
        init_test_logging();
        let test_name = "periodical_scanning_for_receivables_and_delinquencies_works";
        let begin_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_receivable_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        SystemKillerActor::new(Duration::from_secs(10)).start(); // a safety net for GitHub Actions
        let receivable_scanner = ScannerMock::new()
            .begin_scan_params(&begin_scan_params_arc)
            .begin_scan_result(Err(BeginScanError::NothingToProcess))
            .begin_scan_result(Ok(RetrieveTransactions {
                recipient: make_wallet("some_recipient"),
                response_skeleton_opt: None,
            }))
            .stop_the_system();
        let mut config = make_bc_with_defaults();
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_secs(100),
            receivable_scan_interval: Duration::from_millis(99),
            pending_payable_scan_interval: Duration::from_secs(100),
        });
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        subject.logger = Logger::new(test_name);
        subject.scanners.payable = Box::new(NullScanner::new()); // Skipping
        subject.scanners.pending_payable = Box::new(NullScanner::new()); // Skipping
        subject.scanners.receivable = Box::new(receivable_scanner);
        subject.notify_later.scan_for_receivable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_receivable_params_arc)
                .permit_to_send_out(),
        );
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        let peer_actors = peer_actors_builder().build();
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let begin_scan_params = begin_scan_params_arc.lock().unwrap();
        let notify_later_receivable_params = notify_later_receivable_params_arc.lock().unwrap();
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: There was nothing to process during Receivables scan."
        ));
        assert_eq!(begin_scan_params.len(), 2);
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
        )
    }

    #[test]
    fn periodical_scanning_for_pending_payable_works() {
        init_test_logging();
        let test_name = "periodical_scanning_for_pending_payable_works";
        let begin_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        SystemKillerActor::new(Duration::from_secs(10)).start(); // a safety net for GitHub Actions
        let pending_payable_scanner = ScannerMock::new()
            .begin_scan_params(&begin_scan_params_arc)
            .begin_scan_result(Err(BeginScanError::NothingToProcess))
            .begin_scan_result(Ok(RequestTransactionReceipts {
                pending_payable: vec![],
                response_skeleton_opt: None,
            }))
            .stop_the_system();
        let mut config = make_bc_with_defaults();
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_secs(100),
            receivable_scan_interval: Duration::from_secs(100),
            pending_payable_scan_interval: Duration::from_millis(98),
        });
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        subject.logger = Logger::new(test_name);
        subject.scanners.payable = Box::new(NullScanner::new()); //skipping
        subject.scanners.pending_payable = Box::new(pending_payable_scanner);
        subject.scanners.receivable = Box::new(NullScanner::new()); //skipping
        subject.notify_later.scan_for_pending_payable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_pending_payable_params_arc)
                .permit_to_send_out(),
        );
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        let peer_actors = peer_actors_builder().build();
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let begin_scan_params = begin_scan_params_arc.lock().unwrap();
        let notify_later_pending_payable_params =
            notify_later_pending_payable_params_arc.lock().unwrap();
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: There was nothing to process during PendingPayables scan."
        ));
        assert_eq!(begin_scan_params.len(), 2);
        assert_eq!(
            *notify_later_pending_payable_params,
            vec![
                (
                    ScanForPendingPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(98)
                ),
                (
                    ScanForPendingPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(98)
                ),
            ]
        )
    }

    #[test]
    fn periodical_scanning_for_payable_works() {
        init_test_logging();
        let test_name = "periodical_scanning_for_payable_works";
        let begin_scan_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        SystemKillerActor::new(Duration::from_secs(10)).start(); // a safety net for GitHub Actions
        let payable_scanner = ScannerMock::new()
            .begin_scan_params(&begin_scan_params_arc)
            .begin_scan_result(Err(BeginScanError::NothingToProcess))
            .begin_scan_result(Ok(ReportAccountsPayable {
                accounts: vec![],
                response_skeleton_opt: None,
            }))
            .stop_the_system();
        let mut config = bc_from_earning_wallet(make_wallet("hi"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(97),
            receivable_scan_interval: Duration::from_secs(100), // We'll never run this scanner
            pending_payable_scan_interval: Duration::from_secs(100), // We'll never run this scanner
        });
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        subject.logger = Logger::new(test_name);
        subject.scanners.payable = Box::new(payable_scanner);
        subject.scanners.pending_payable = Box::new(NullScanner::new()); //skipping
        subject.scanners.receivable = Box::new(NullScanner::new()); //skipping
        subject.notify_later.scan_for_payable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_payables_params_arc)
                .permit_to_send_out(),
        );
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        let peer_actors = peer_actors_builder().build();
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        //the second attempt is the one where the queue is empty and System::current.stop() ends the cycle
        let begin_scan_params = begin_scan_params_arc.lock().unwrap();
        let notify_later_payables_params = notify_later_payables_params_arc.lock().unwrap();
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: There was nothing to process during Payables scan."
        ));
        assert_eq!(begin_scan_params.len(), 2);
        assert_eq!(
            *notify_later_payables_params,
            vec![
                (
                    ScanForPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(97)
                ),
                (
                    ScanForPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(97)
                ),
            ]
        )
    }

    #[test]
    fn start_message_triggers_no_scans_in_suppress_mode() {
        init_test_logging();
        let test_name = "start_message_triggers_no_scans_in_suppress_mode";
        let system = System::new(test_name);
        let mut config = bc_from_earning_wallet(make_wallet("hi"));
        config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_millis(100),
            receivable_scan_interval: Duration::from_millis(100),
            pending_payable_scan_interval: Duration::from_millis(100),
        });
        config.suppress_initial_scans = true;
        let peer_actors = peer_actors_builder().build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        subject.logger = Logger::new(test_name);
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        System::current().stop();
        assert_eq!(system.run(), 0);
        // no panics because of recalcitrant DAOs; therefore DAOs were not called; therefore test passes
        TestLogHandler::new().exists_log_containing(
            &format!("{test_name}: Started with --scans off; declining to begin database and blockchain scans"),
        );
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let config = bc_from_earning_wallet(make_wallet("mine"));
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: payment_thresholds.permanent_debt_allowed_gwei - 1,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 10,
                ),
                pending_payable_opt: None,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: payment_thresholds.debt_threshold_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.maturity_threshold_sec + 10,
                ),
                pending_payable_opt: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: payment_thresholds.debt_threshold_gwei - 1000,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.maturity_threshold_sec - 1,
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_payable_message_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub =
            blockchain_bridge_addr.recipient::<ReportAccountsPayable>();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        subject.report_accounts_payable_sub_opt = Some(report_accounts_payable_sub);

        let _result = subject
            .scanners
            .payable
            .begin_scan(SystemTime::now(), None, &subject.logger);

        System::current().stop_with_code(0);
        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_payable_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let mut config = bc_from_earning_wallet(make_wallet("mine"));
        config.scan_intervals_opt = Some(ScanIntervals {
            pending_payable_scan_interval: Duration::from_secs(50_000),
            payable_scan_interval: Duration::from_secs(50_000),
            receivable_scan_interval: Duration::from_secs(50_000),
        });
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // slightly above minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: DEFAULT_PAYMENT_THRESHOLDS.permanent_debt_allowed_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - DEFAULT_PAYMENT_THRESHOLDS.threshold_interval_sec - 10,
                ),
                pending_payable_opt: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec - 10,
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::default().non_pending_payables_result(accounts.clone());
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let mut expected_messages_by_type = HashMap::new();
        expected_messages_by_type.insert(TypeId::of::<ReportAccountsPayable>(), 1);
        let blockchain_bridge = blockchain_bridge
            .stop_after_messages_and_start_system_killer(expected_messages_by_type);
        let system =
            System::new("scan_for_payable_message_triggers_payment_for_balances_over_the_curve");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner::new());
        subject.scanners.receivable = Box::new(NullScanner::new());
        let subject_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        let message = blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0);
        assert_eq!(
            message,
            &ReportAccountsPayable {
                accounts,
                response_skeleton_opt: None,
            }
        );
    }

    #[test]
    fn accountant_does_not_initiate_another_scan_in_case_it_receives_the_message_and_the_scanner_is_running(
    ) {
        init_test_logging();
        let test_name = "accountant_does_not_initiate_another_scan_in_case_it_receives_the_message_and_the_scanner_is_running";
        let payable_dao = PayableDaoMock::default();
        let (blockchain_bridge, _, blockchain_bridge_recording) = make_recorder();
        let report_accounts_payable_sub = blockchain_bridge.start().recipient();
        let last_paid_timestamp =
            to_time_t(SystemTime::now()) - DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec - 1;
        let payable_account = PayableAccount {
            wallet: make_wallet("scan_for_payables"),
            balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1,
            last_paid_timestamp: from_time_t(last_paid_timestamp),
            pending_payable_opt: None,
        };
        let mut payable_dao =
            payable_dao.non_pending_payables_result(vec![payable_account.clone()]);
        payable_dao.have_non_pending_payables_shut_down_the_system = true;
        let config = bc_from_earning_wallet(make_wallet("mine"));
        let system = System::new(test_name);
        let mut subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new()) // For Accountant
            .payable_dao(payable_dao) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .bootstrapper_config(config)
            .build();
        subject.report_accounts_payable_sub_opt = Some(report_accounts_payable_sub);
        subject.logger = Logger::new(test_name);
        let addr = subject.start();
        addr.try_send(ScanForPayables {
            response_skeleton_opt: None,
        })
        .unwrap();

        addr.try_send(ScanForPayables {
            response_skeleton_opt: None,
        })
        .unwrap();

        System::current().stop();
        system.run();
        let recording = blockchain_bridge_recording.lock().unwrap();
        let messages_received = recording.len();
        assert_eq!(messages_received, 0);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: Payables scan was already initiated",
            test_name
        ));
    }

    #[test]
    fn scan_for_pending_payable_found_unresolved_pending_payable_and_urges_their_processing() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let payable_fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(555),
            timestamp: from_time_t(210_000_000),
            hash: H256::from_uint(&U256::from(45678)),
            attempt_opt: Some(0),
            amount: 4444,
            process_error: None,
        };
        let payable_fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(550),
            timestamp: from_time_t(210_000_100),
            hash: H256::from_uint(&U256::from(112233)),
            attempt_opt: Some(0),
            amount: 7999,
            process_error: None,
        };
        let pending_payable_dao =
            PendingPayableDaoMock::default().return_all_fingerprints_result(vec![
                payable_fingerprint_1.clone(),
                payable_fingerprint_2.clone(),
            ]);
        let config = bc_from_earning_wallet(make_wallet("mine"));
        let system = System::new("pending payable scan");
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Payable Scanner
            .pending_payable_dao(pending_payable_dao) // For PendiingPayable Scanner
            .bootstrapper_config(config)
            .build();
        let blockchain_bridge_addr = blockchain_bridge.start();
        subject.request_transaction_receipts_subs_opt = Some(blockchain_bridge_addr.recipient());
        let account_addr = subject.start();

        let _ = account_addr
            .try_send(ScanForPendingPayables {
                response_skeleton_opt: None,
            })
            .unwrap();

        let killer = SystemKillerActor::new(Duration::from_millis(10));
        killer.start();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let received_msg = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            received_msg,
            &RequestTransactionReceipts {
                pending_payable: vec![payable_fingerprint_1, payable_fingerprint_2],
                response_skeleton_opt: None,
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Found 2 pending payables to process");
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .receivable_dao(receivable_dao_mock)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .receivable_dao(receivable_dao_mock)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .receivable_dao(receivable_dao_mock)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .receivable_dao(receivable_dao_mock)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .receivable_dao(receivable_dao_mock)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao_mock) // For Accountant
            .payable_dao(PayableDaoMock::new()) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .receivable_dao(receivable_dao_mock) // For Accountant
            .receivable_dao(ReceivableDaoMock::new()) // For Scanner
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
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
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
    ) -> Arc<Mutex<Vec<(SystemTime, Wallet, u64)>>> {
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_result(Ok(()))
            .more_money_payable_params(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
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
            .receivable_dao(receivable_dao)
            .receivable_dao(ReceivableDaoMock::new())
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
            .receivable_dao(receivable_dao)
            .receivable_dao(ReceivableDaoMock::new())
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
            .payable_dao(payable_dao)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
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
            .payable_dao(payable_dao)
            .payable_dao(PayableDaoMock::new())
            .payable_dao(PayableDaoMock::new())
            .build();

        let _ = subject.record_service_consumed(i64::MAX as u64, 1, SystemTime::now(), 2, &wallet);
    }

    #[test]
    #[should_panic(
        expected = "Database unmaintainable; payable fingerprint deletion for transaction 0x000000000000000000000000000000000000000000000000000000000000007b \
        has stayed undone due to RecordDeletion(\"we slept over, sorry\")"
    )]
    fn accountant_panics_in_case_it_receives_an_error_from_scanner_while_handling_sent_payable_msg()
    {
        let rowid = 4;
        let hash = H256::from_uint(&U256::from(123));
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![Err(BlockchainError::TransactionFailed {
                msg: "blah".to_string(),
                hash_opt: Some(hash),
            })],
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_result(Some(rowid))
            .delete_fingerprint_result(Err(PendingPayableDaoError::RecordDeletion(
                "we slept over, sorry".to_string(),
            )));
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Accountant
            .pending_payable_dao(pending_payable_dao) // For Payable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        let addr = subject.start();

        let _ = addr.try_send(sent_payable);

        System::current().stop();
        assert_eq!(system.run(), 0);
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
    fn pending_transaction_is_registered_and_monitored_until_it_gets_confirmed_or_canceled() {
        init_test_logging();
        let mark_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let return_all_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let update_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_record_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_scan_for_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_scan_for_pending_payable_arc_cloned =
            notify_later_scan_for_pending_payable_params_arc.clone(); //because it moves into a closure
        let pending_tx_hash_1 = H256::from_uint(&U256::from(123));
        let pending_tx_hash_2 = H256::from_uint(&U256::from(567));
        let rowid_for_account_1 = 3;
        let rowid_for_account_2 = 5;
        let now = SystemTime::now();
        let past_payable_timestamp_1 = now.sub(Duration::from_secs(
            (DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 555) as u64,
        ));
        let past_payable_timestamp_2 = now.sub(Duration::from_secs(
            (DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 50) as u64,
        ));
        let this_payable_timestamp_1 = now;
        let this_payable_timestamp_2 = now.add(Duration::from_millis(50));
        let payable_account_balance_1 = DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 10;
        let payable_account_balance_2 = DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 666;
        let transaction_receipt_tx_2_first_round = TransactionReceipt::default();
        let transaction_receipt_tx_1_second_round = TransactionReceipt::default();
        let transaction_receipt_tx_2_second_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_1_third_round = TransactionReceipt::default();
        transaction_receipt_tx_1_third_round.status = Some(U64::from(0)); //failure
        let transaction_receipt_tx_2_third_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_2_fourth_round = TransactionReceipt::default();
        transaction_receipt_tx_2_fourth_round.status = Some(U64::from(1)); // confirmed
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .get_transaction_count_result(Ok(web3::types::U256::from(2)))
            //because we cannot have both, resolution on the high level and also of what's inside blockchain interface,
            //there is one component missing in this wholesome test - the part where we send a request for
            //a fingerprint of that payable in the DB - this happens inside send_raw_transaction()
            .send_transaction_tools_result(Box::new(SendTransactionToolsWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolsWrapperNull))
            .send_transaction_result(Ok((pending_tx_hash_1, past_payable_timestamp_1)))
            .send_transaction_result(Ok((pending_tx_hash_2, past_payable_timestamp_2)))
            .get_transaction_receipt_params(&get_transaction_receipt_params_arc)
            .get_transaction_receipt_result(Ok(None))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_first_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_1_second_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_second_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_1_third_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_third_round)))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt_tx_2_fourth_round)));
        let consuming_wallet = make_paying_wallet(b"wallet");
        let system = System::new("pending_transaction");
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(130));
        let blockchain_bridge = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            Some(consuming_wallet),
        );
        let wallet_account_1 = make_wallet("creditor1");
        let account_1 = PayableAccount {
            wallet: wallet_account_1.clone(),
            balance: payable_account_balance_1,
            last_paid_timestamp: past_payable_timestamp_1,
            pending_payable_opt: None,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: payable_account_balance_2,
            last_paid_timestamp: past_payable_timestamp_2,
            pending_payable_opt: None,
        };
        let pending_payable_scan_interval = 200; //should be slightly less than 1/5 of the time until shutting the system
        let payable_dao_for_accountant = PayableDaoMock::new();
        let payable_dao_for_payable_scanner = PayableDaoMock::new()
            .mark_pending_payable_rowid_params(&mark_pending_payable_params_arc)
            .mark_pending_payable_rowid_result(Ok(()))
            .mark_pending_payable_rowid_result(Ok(()))
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![account_1, account_2]);
        let payable_dao_for_pending_payable_scanner = PayableDaoMock::new()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));

        let mut bootstrapper_config = bc_from_earning_wallet(make_wallet("some_wallet_address"));
        bootstrapper_config.scan_intervals_opt = Some(ScanIntervals {
            payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
            receivable_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
            pending_payable_scan_interval: Duration::from_millis(pending_payable_scan_interval),
        });
        let fingerprint_1_first_round = PendingPayableFingerprint {
            rowid_opt: Some(rowid_for_account_1),
            timestamp: this_payable_timestamp_1,
            hash: pending_tx_hash_1,
            attempt_opt: Some(1),
            amount: payable_account_balance_1 as u64,
            process_error: None,
        };
        let fingerprint_2_first_round = PendingPayableFingerprint {
            rowid_opt: Some(rowid_for_account_2),
            timestamp: this_payable_timestamp_2,
            hash: pending_tx_hash_2,
            attempt_opt: Some(1),
            amount: payable_account_balance_2 as u64,
            process_error: None,
        };
        let fingerprint_1_second_round = PendingPayableFingerprint {
            attempt_opt: Some(2),
            ..fingerprint_1_first_round.clone()
        };
        let fingerprint_2_second_round = PendingPayableFingerprint {
            attempt_opt: Some(2),
            ..fingerprint_2_first_round.clone()
        };
        let fingerprint_1_third_round = PendingPayableFingerprint {
            attempt_opt: Some(3),
            ..fingerprint_1_first_round.clone()
        };
        let fingerprint_2_third_round = PendingPayableFingerprint {
            attempt_opt: Some(3),
            ..fingerprint_2_first_round.clone()
        };
        let fingerprint_2_fourth_round = PendingPayableFingerprint {
            attempt_opt: Some(4),
            ..fingerprint_2_first_round.clone()
        };
        let pending_payable_dao_for_accountant = PendingPayableDaoMock::default();
        let pending_payable_dao_for_payable_scanner = PendingPayableDaoMock::default()
            .fingerprint_rowid_result(Some(rowid_for_account_1))
            .fingerprint_rowid_result(Some(rowid_for_account_2))
            .insert_fingerprint_params(&insert_fingerprint_params_arc)
            .insert_fingerprint_result(Ok(()))
            .insert_fingerprint_result(Ok(()));
        let mut pending_payable_dao_for_pending_payable_scanner = PendingPayableDaoMock::new()
            .return_all_fingerprints_params(&return_all_fingerprints_params_arc)
            .return_all_fingerprints_result(vec![])
            .return_all_fingerprints_result(vec![
                fingerprint_1_first_round,
                fingerprint_2_first_round,
            ])
            .return_all_fingerprints_result(vec![
                fingerprint_1_second_round,
                fingerprint_2_second_round,
            ])
            .return_all_fingerprints_result(vec![
                fingerprint_1_third_round,
                fingerprint_2_third_round,
            ])
            .return_all_fingerprints_result(vec![fingerprint_2_fourth_round.clone()])
            .update_fingerprint_params(&update_fingerprint_params_arc)
            .update_fingerprint_results(Ok(()))
            .update_fingerprint_results(Ok(()))
            .update_fingerprint_results(Ok(()))
            .update_fingerprint_results(Ok(()))
            .update_fingerprint_results(Ok(()))
            .mark_failure_params(&mark_failure_params_arc)
            //we don't have a better solution yet, so we mark this down
            .mark_failure_result(Ok(()))
            .mark_failure_result(Ok(()))
            .delete_fingerprint_params(&delete_record_params_arc)
            //this is used during confirmation of the successful one
            .delete_fingerprint_result(Ok(()));
        pending_payable_dao_for_pending_payable_scanner
            .have_return_all_fingerprints_shut_down_the_system = true;
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let mut subject = AccountantBuilder::default()
                    .bootstrapper_config(bootstrapper_config)
                    .payable_dao(payable_dao_for_accountant)
                    .payable_dao(payable_dao_for_payable_scanner)
                    .payable_dao(payable_dao_for_pending_payable_scanner)
                    .pending_payable_dao(pending_payable_dao_for_accountant)
                    .pending_payable_dao(pending_payable_dao_for_payable_scanner)
                    .pending_payable_dao(pending_payable_dao_for_pending_payable_scanner)
                    .build();
                subject.scanners.receivable = Box::new(NullScanner::new());
                let notify_later_half_mock = NotifyLaterHandleMock::default()
                    .notify_later_params(&notify_later_scan_for_pending_payable_arc_cloned)
                    .permit_to_send_out();
                subject.notify_later.scan_for_pending_payable = Box::new(notify_later_half_mock);
                subject
            });
        let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        peer_actors.accountant = accountant_subs.clone();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);

        send_start_message!(accountant_subs);

        assert_eq!(system.run(), 0);
        let mut mark_pending_payable_params = mark_pending_payable_params_arc.lock().unwrap();
        let first_payable = mark_pending_payable_params.remove(0);
        assert_eq!(first_payable.0, wallet_account_1);
        assert_eq!(first_payable.1, rowid_for_account_1);
        let second_payable = mark_pending_payable_params.remove(0);
        assert!(
            mark_pending_payable_params.is_empty(),
            "{:?}",
            mark_pending_payable_params
        );
        assert_eq!(second_payable.0, wallet_account_2);
        assert_eq!(second_payable.1, rowid_for_account_2);
        let return_all_fingerprints_params = return_all_fingerprints_params_arc.lock().unwrap();
        //it varies with machines and sometimes we manage more cycles than necessary
        assert!(return_all_fingerprints_params.len() >= 5);
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![()]); //because we disabled further scanning for payables
        let get_transaction_receipt_params = get_transaction_receipt_params_arc.lock().unwrap();
        assert_eq!(
            *get_transaction_receipt_params,
            vec![
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_1,
                pending_tx_hash_2,
                pending_tx_hash_2,
            ]
        );
        let update_backup_after_cycle_params = update_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *update_backup_after_cycle_params,
            vec![
                rowid_for_account_1,
                rowid_for_account_2,
                rowid_for_account_1,
                rowid_for_account_2,
                rowid_for_account_2,
            ]
        );
        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![rowid_for_account_1]);
        let delete_record_params = delete_record_params_arc.lock().unwrap();
        assert_eq!(*delete_record_params, vec![rowid_for_account_2]);
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![fingerprint_2_fourth_round.clone()]
        );
        let expected_scan_pending_payable_msg_and_interval = (
            ScanForPendingPayables {
                response_skeleton_opt: None,
            },
            Duration::from_millis(pending_payable_scan_interval),
        );
        let mut notify_later_check_for_confirmation =
            notify_later_scan_for_pending_payable_params_arc
                .lock()
                .unwrap();
        //it varies with machines and sometimes we manage more cycles than necessary
        let vector_of_first_five_cycles = notify_later_check_for_confirmation
            .drain(0..=4)
            .collect_vec();
        assert_eq!(
            vector_of_first_five_cycles,
            vec![
                expected_scan_pending_payable_msg_and_interval.clone(),
                expected_scan_pending_payable_msg_and_interval.clone(),
                expected_scan_pending_payable_msg_and_interval.clone(),
                expected_scan_pending_payable_msg_and_interval.clone(),
                expected_scan_pending_payable_msg_and_interval,
            ]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            "WARN: Accountant: Broken transaction 0x000000000000000000000000000000000000000000000000000000000000007b left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there \
             is no automated process that can fix this without you");
        log_handler.exists_log_matching("INFO: Accountant: Transaction '0x0000000000000000000000000000000000000000000000000000000000000237' has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x0000000000000000000000000000000000000000000000000000000000000237 has gone through the whole confirmation process succeeding");
    }

    #[test]
    fn accountant_handles_pending_payable_fingerprint() {
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao = PendingPayableDaoMock::default()
            .insert_fingerprint_params(&insert_fingerprint_params_arc)
            .insert_fingerprint_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payment_dao) // For Accountant
            .pending_payable_dao(PendingPayableDaoMock::new()) // For Payable Scanner
            .pending_payable_dao(PendingPayableDaoMock::new()) // For PendingPayable Scanner
            .build();
        let accountant_addr = subject.start();
        let tx_hash = H256::from_uint(&U256::from(55));
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let amount = 4055;
        let timestamp = SystemTime::now();
        let backup_message = PendingPayableFingerprint {
            rowid_opt: None,
            timestamp,
            hash: tx_hash,
            attempt_opt: None,
            amount,
            process_error: None,
        };

        let _ = accountant_subs
            .pending_payable_fingerprint
            .try_send(backup_message.clone())
            .unwrap();

        let system = System::new("ordering payment fingerprint test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let insert_fingerprint_params = insert_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *insert_fingerprint_params,
            vec![(tx_hash, amount, timestamp)]
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Processed a pending payable fingerprint for '0x0000000000000000000000000000000000000000000000000000000000000037'",
        );
    }

    #[test]
    fn payable_fingerprint_insertion_clearly_failed_and_we_log_it_at_least() {
        //despite it doesn't happen here this event would cause a panic later
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .insert_fingerprint_params(&insert_fingerprint_params_arc)
            .insert_fingerprint_result(Err(PendingPayableDaoError::InsertionFailed(
                "Crashed".to_string(),
            )));
        let amount = 2345;
        let transaction_hash = H256::from_uint(&U256::from(456));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .pending_payable_dao(PendingPayableDaoMock::new())
            .pending_payable_dao(PendingPayableDaoMock::new())
            .build();
        let timestamp_secs = 150_000_000;
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: None,
            timestamp: from_time_t(timestamp_secs),
            hash: transaction_hash,
            attempt_opt: None,
            amount,
            process_error: None,
        };

        let _ = subject.handle_new_pending_payable_fingerprint(fingerprint);

        let insert_fingerprint_params = insert_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *insert_fingerprint_params,
            vec![(transaction_hash, amount, from_time_t(timestamp_secs))]
        );
        TestLogHandler::new().exists_log_containing("ERROR: Accountant: Failed to make a fingerprint for pending payable '0x00000000000000000000000000000000000000000000000000000000000001c8' due to 'InsertionFailed(\"Crashed\")'");
    }

    #[test]
    fn handles_scan_error() {
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject = AccountantBuilder::default().build();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(ScanError {
                scan_type: ScanType::Payables,
                response_skeleton: ResponseSkeleton {
                    client_id: 1234,
                    context_id: 4321,
                },
                msg: "My tummy hurts".to_string(),
            })
            .unwrap();

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<NodeToUiMessage>(0),
            &NodeToUiMessage {
                target: ClientId(1234),
                body: MessageBody {
                    opcode: "scan".to_string(),
                    path: MessagePath::Conversation(4321),
                    payload: Err((
                        SCAN_ERROR,
                        "Payables scan failed: 'My tummy hurts'".to_string()
                    )),
                },
            }
        );
    }

    #[test]
    fn financials_request_produces_financials_response() {
        let payable_dao = PayableDaoMock::new().total_result(23456789);
        let receivable_dao = ReceivableDaoMock::new().total_result(98765432);
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .bootstrapper_config(make_bc_with_defaults())
            .payable_dao(payable_dao) // For Accountant
            .payable_dao(PayableDaoMock::new()) // For Payable Scanner
            .payable_dao(PayableDaoMock::new()) // For PendingPayable Scanner
            .receivable_dao(receivable_dao) // For Accountant
            .receivable_dao(ReceivableDaoMock::new()) // For Scanner
            .build();
        let mut financial_statistics = subject.financial_statistics().clone();
        financial_statistics.total_paid_payable += 123456;
        financial_statistics.total_paid_receivable += 334455;
        subject.financial_statistics.replace(financial_statistics);
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let ui_message = NodeFromUiMessage {
            client_id: 1234,
            body: UiFinancialsRequest {}.tmb(2222),
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
                total_unpaid_and_pending_payable: 23456789,
                total_paid_payable: 123456,
                total_unpaid_receivable: 98765432,
                total_paid_receivable: 334455,
            }
        );
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
        let result = unsigned_to_signed(0);

        assert_eq!(result, Ok(0i64));
    }

    #[test]
    fn unsigned_to_signed_handles_max_allowable() {
        let result = unsigned_to_signed(i64::MAX as u64);

        assert_eq!(result, Ok(i64::MAX));
    }

    #[test]
    fn unsigned_to_signed_handles_max_plus_one() {
        let attempt = (i64::MAX as u64) + 1;
        let result = unsigned_to_signed((i64::MAX as u64) + 1);

        assert_eq!(result, Err(attempt));
    }
}
