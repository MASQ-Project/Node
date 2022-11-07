// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
pub mod payable_dao;
pub mod pending_payable_dao;
pub mod receivable_dao;
pub mod tools;

#[cfg(test)]
pub mod test_utils;

use masq_lib::constants::SCAN_ERROR;

use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
use masq_lib::ui_gateway::{MessageBody, MessagePath};

use crate::accountant::payable_dao::{
    PayableAccount, PayableDaoError, PayableDaoFactory, PendingPayable,
};
use crate::accountant::pending_payable_dao::{PendingPayableDao, PendingPayableDaoFactory};
use crate::accountant::receivable_dao::{
    ReceivableAccount, ReceivableDaoError, ReceivableDaoFactory,
};
use crate::accountant::tools::accountant_tools::{Scanner, Scanners, TransactionConfirmationTools};
use crate::accountant::PayableTransactingErrorEnum::{LocalError, RemoteErrors};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::{
    PendingPayableFingerprint, ReportNewPendingPayableFingerprints, RetrieveTransactions,
};
use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failure};
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainTransaction, ProcessedPayableFallible, RpcPayableFailure,
};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::DaoFactoryReal;
use crate::database::db_migrations::MigratorConfig;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::accountant::{AccountantConfig, FinancialStatistics, PaymentThresholds};
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
use itertools::Itertools;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::messages::UiFinancialsResponse;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::{plus, ExpectValue};
use payable_dao::PayableDao;
use receivable_dao::ReceivableDao;
#[cfg(test)]
use std::any::Any;
use std::default::Default;
use std::ops::Add;
use std::path::Path;
use std::time::{Duration, SystemTime};
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "ACCOUNTANT";

pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

pub struct Accountant {
    config: AccountantConfig,
    consuming_wallet: Option<Wallet>,
    earning_wallet: Wallet,
    payable_dao: Box<dyn PayableDao>,
    receivable_dao: Box<dyn ReceivableDao>,
    pending_payable_dao: Box<dyn PendingPayableDao>,
    banned_dao: Box<dyn BannedDao>,
    crashable: bool,
    scanners: Scanners,
    tools: TransactionConfirmationTools,
    financial_statistics: FinancialStatistics,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayable>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
    payable_threshold_tools: Box<dyn PayableExceedThresholdTools>,
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

#[derive(Debug, Message, PartialEq)]
pub struct SentPayable {
    pub timestamp: SystemTime,
    pub payable_outcomes: Result<Vec<ProcessedPayableFallible>, BlockchainError>,
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
        if self.config.suppress_initial_scans {
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
        self.handle_received_payments(msg);
    }
}

impl Handler<SentPayable> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: SentPayable, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_sent_payable(msg);
    }
}

impl Handler<ScanForPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPayables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_scan_message(
            self.scanners.payables.as_ref(),
            msg.response_skeleton_opt,
            ctx,
        )
    }
}

impl Handler<ScanForPendingPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForPendingPayables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_scan_message(
            self.scanners.pending_payables.as_ref(),
            msg.response_skeleton_opt,
            ctx,
        )
    }
}

impl Handler<ScanForReceivables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ScanForReceivables, ctx: &mut Self::Context) -> Self::Result {
        self.handle_scan_message(
            self.scanners.receivables.as_ref(),
            msg.response_skeleton_opt,
            ctx,
        )
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

impl Handler<ReportRoutingServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_routing_service_consumed_message(msg);
    }
}

impl Handler<ReportExitServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_report_exit_service_consumed_message(msg);
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
        debug!(
            self.logger,
            "Processing receipts for {} transactions",
            msg.fingerprints_with_receipts.len()
        );
        let scan_summary = self.handle_pending_transaction_with_its_receipt(&msg);
        self.process_transaction_by_status(scan_summary);
        if let Some(response_skeleton) = &msg.response_skeleton_opt {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway not bound")
                .try_send(NodeToUiMessage {
                    target: ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                })
                .expect("UIGateway is dead");
        }
    }
}

impl Handler<ReportNewPendingPayableFingerprints> for Accountant {
    type Result = ();
    fn handle(
        &mut self,
        msg: ReportNewPendingPayableFingerprints,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_new_pending_payable_fingerprints(msg)
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
            );
        } else {
            handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
        }
    }
}

impl Accountant {
    pub fn new(
        config: &BootstrapperConfig,
        payable_dao_factory: Box<dyn PayableDaoFactory>,
        receivable_dao_factory: Box<dyn ReceivableDaoFactory>,
        pending_payable_dao_factory: Box<dyn PendingPayableDaoFactory>,
        banned_dao_factory: Box<dyn BannedDaoFactory>,
    ) -> Accountant {
        Accountant {
            config: *config
                .accountant_config_opt
                .as_ref()
                .expectv("Accountant config"),
            consuming_wallet: config.consuming_wallet_opt.clone(),
            earning_wallet: config.earning_wallet.clone(),
            payable_dao: payable_dao_factory.make(),
            receivable_dao: receivable_dao_factory.make(),
            pending_payable_dao: pending_payable_dao_factory.make(),
            banned_dao: banned_dao_factory.make(),
            crashable: config.crash_point == CrashPoint::Message,
            scanners: Scanners::default(),
            tools: TransactionConfirmationTools::default(),
            financial_statistics: FinancialStatistics::default(),
            report_accounts_payable_sub: None,
            retrieve_transactions_sub: None,
            report_new_payments_sub: None,
            report_sent_payments_sub: None,
            ui_message_sub: None,
            payable_threshold_tools: Box::new(PayableExceedThresholdToolsReal::default()),
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: recipient!(addr, BindMessage),
            start: recipient!(addr, StartMessage),
            report_routing_service_provided: recipient!(addr, ReportRoutingServiceProvidedMessage),
            report_exit_service_provided: recipient!(addr, ReportExitServiceProvidedMessage),
            report_routing_service_consumed: recipient!(addr, ReportRoutingServiceConsumedMessage),
            report_exit_service_consumed: recipient!(addr, ReportExitServiceConsumedMessage),
            report_new_payments: recipient!(addr, ReceivedPayments),
            init_pending_payable_fingerprints: recipient!(
                addr,
                ReportNewPendingPayableFingerprints
            ),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayable),
            scan_errors: recipient!(addr, ScanError),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, false, MigratorConfig::panic_on_migration())
    }

    fn handle_scan_message(
        &self,
        scanner: &dyn Scanner,
        response_skeleton_opt: Option<ResponseSkeleton>,
        ctx: &mut Context<Accountant>,
    ) {
        scanner.scan(self, response_skeleton_opt);
        scanner.notify_later_assertable(self, ctx)
    }

    fn scan_for_payables(&self, response_skeleton_opt: Option<ResponseSkeleton>) {
        info!(self.logger, "Scanning for payables");

        let all_non_pending_payables = self.payable_dao.non_pending_payables();
        debug!(
            self.logger,
            "{}",
            Self::investigate_debt_extremes(&all_non_pending_payables)
        );
        let qualified_payables = all_non_pending_payables
            .into_iter()
            .filter(|account| self.should_pay(account))
            .collect::<Vec<PayableAccount>>();
        info!(
            self.logger,
            "Chose {} qualified debts to pay",
            qualified_payables.len()
        );
        debug!(
            self.logger,
            "{}",
            self.payables_debug_summary(&qualified_payables)
        );
        if !qualified_payables.is_empty() {
            self.report_accounts_payable_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(ReportAccountsPayable {
                    accounts: qualified_payables,
                    response_skeleton_opt,
                })
                .expect("BlockchainBridge is dead")
        }
    }

    fn scan_for_delinquencies(&self) {
        info!(self.logger, "Scanning for delinquencies");
        let now = SystemTime::now();
        self.receivable_dao
            .new_delinquencies(now, &self.config.payment_thresholds)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet);
                let (balance, age) = Self::balance_and_age(&account);
                info!(
                    self.logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) banned for delinquency",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });
        self.receivable_dao
            .paid_delinquencies(&self.config.payment_thresholds)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet);
                let (balance, age) = Self::balance_and_age(&account);
                info!(
                    self.logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });
    }

    fn scan_for_received_payments(&self, response_skeleton_opt: Option<ResponseSkeleton>) {
        info!(
            self.logger,
            "Scanning for receivables to {}", self.earning_wallet
        );
        self.retrieve_transactions_sub
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .try_send(RetrieveTransactions {
                recipient: self.earning_wallet.clone(),
                response_skeleton_opt,
            })
            .expect("BlockchainBridge is dead");
    }

    fn scan_for_pending_payable(&self, response_skeleton_opt: Option<ResponseSkeleton>) {
        info!(self.logger, "Scanning for pending payable");
        let filtered_pending_payable = self.pending_payable_dao.return_all_fingerprints();
        if filtered_pending_payable.is_empty() {
            debug!(self.logger, "No pending payable found during last scan")
        } else {
            debug!(
                self.logger,
                "Found {} pending payables to process",
                filtered_pending_payable.len()
            );
            self.tools
                .request_transaction_receipts_subs_opt
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(RequestTransactionReceipts {
                    pending_payable: filtered_pending_payable,
                    response_skeleton_opt,
                })
                .expect("BlockchainBridge is dead");
        }
    }

    fn balance_and_age(account: &ReceivableAccount) -> (String, Duration) {
        let balance = format!("{}", (account.balance as f64) / 1_000_000_000.0);
        let age = account
            .last_received_timestamp
            .elapsed()
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }

    fn should_pay(&self, payable: &PayableAccount) -> bool {
        self.payable_exceeded_threshold(payable).is_some()
    }

    fn payable_exceeded_threshold(&self, payable: &PayableAccount) -> Option<u64> {
        // TODO: This calculation should be done in the database, if possible
        let time_since_last_paid = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if self.payable_threshold_tools.is_innocent_age(
            time_since_last_paid,
            self.config.payment_thresholds.maturity_threshold_sec as u64,
        ) {
            return None;
        }

        if self.payable_threshold_tools.is_innocent_balance(
            payable.balance,
            self.config.payment_thresholds.permanent_debt_allowed_gwei,
        ) {
            return None;
        }

        let threshold = self
            .payable_threshold_tools
            .calculate_payout_threshold(self.config.payment_thresholds, time_since_last_paid);
        if payable.balance as f64 > threshold {
            Some(threshold as u64)
        } else {
            None
        }
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
            info!(
                self.logger,
                "Not recording service provided for our wallet {}", wallet
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
            info!(
                self.logger,
                "Not recording service consumed to our wallet {}", wallet
            );
        }
    }

    fn our_wallet(&self, wallet: &Wallet) -> bool {
        match &self.consuming_wallet {
            Some(ref consuming) if consuming.address() == wallet.address() => true,
            _ => wallet.address() == self.earning_wallet.address(),
        }
    }

    //for debugging only
    fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
        if all_non_pending_payables.is_empty() {
            "Payable scan found no debts".to_string()
        } else {
            struct PayableInfo {
                balance: i64,
                age: Duration,
            }
            let now = SystemTime::now();
            let init = (
                PayableInfo {
                    balance: 0,
                    age: Duration::ZERO,
                },
                PayableInfo {
                    balance: 0,
                    age: Duration::ZERO,
                },
            );
            let (biggest, oldest) = all_non_pending_payables.iter().fold(init, |sofar, p| {
                let (mut biggest, mut oldest) = sofar;
                let p_age = now
                    .duration_since(p.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                {
                    //look at a test if not understandable
                    let check_age_parameter_if_the_first_is_the_same =
                        || -> bool { p.balance == biggest.balance && p_age > biggest.age };

                    if p.balance > biggest.balance || check_age_parameter_if_the_first_is_the_same()
                    {
                        biggest = PayableInfo {
                            balance: p.balance,
                            age: p_age,
                        }
                    }

                    let check_balance_parameter_if_the_first_is_the_same =
                        || -> bool { p_age == oldest.age && p.balance > oldest.balance };

                    if p_age > oldest.age || check_balance_parameter_if_the_first_is_the_same() {
                        oldest = PayableInfo {
                            balance: p.balance,
                            age: p_age,
                        }
                    }
                }
                (biggest, oldest)
            });
            format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                    all_non_pending_payables.len(), biggest.balance, biggest.age.as_secs(),
                    oldest.balance, oldest.age.as_secs())
        }
    }

    fn payables_debug_summary(&self, qualified_payables: &[PayableAccount]) -> String {
        let now = SystemTime::now();
        let list = qualified_payables
            .iter()
            .map(|payable| {
                let p_age = now
                    .duration_since(payable.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                let threshold = self
                    .payable_exceeded_threshold(payable)
                    .expect("Threshold suddenly changed!");
                format!(
                    "{} owed for {}sec exceeds threshold: {}; creditor: {}",
                    payable.balance,
                    p_age.as_secs(),
                    threshold,
                    payable.wallet
                )
            })
            .join("\n");
        String::from("Paying qualified debts:\n").add(&list)
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        self.report_accounts_payable_sub =
            Some(msg.peer_actors.blockchain_bridge.report_accounts_payable);
        self.retrieve_transactions_sub =
            Some(msg.peer_actors.blockchain_bridge.retrieve_transactions);
        self.report_new_payments_sub = Some(msg.peer_actors.accountant.report_new_payments);
        self.report_sent_payments_sub = Some(msg.peer_actors.accountant.report_sent_payments);
        self.ui_message_sub = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
        self.tools.request_transaction_receipts_subs_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .request_transaction_receipts,
        );
        info!(self.logger, "Accountant bound");
    }

    fn handle_received_payments(&mut self, msg: ReceivedPayments) {
        if !msg.payments.is_empty() {
            let total_newly_paid_receivable = msg
                .payments
                .iter()
                .fold(0, |so_far, now| so_far + now.gwei_amount);
            self.receivable_dao
                .as_mut()
                .more_money_received(msg.timestamp, msg.payments);
            self.financial_statistics.total_paid_receivable += total_newly_paid_receivable;
        }
        if let Some(response_skeleton) = msg.response_skeleton_opt {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(NodeToUiMessage {
                    target: ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                })
                .expect("UIGateway is dead");
        }
    }

    fn handle_sent_payable(&self, sent_payable: SentPayable) {
        if let Ok(vec) = &sent_payable.payable_outcomes {
            if vec.is_empty() {
                todo!("panic here")
            }
        }
        let (ok, err_opt) = Self::separate_errors(&sent_payable, &self.logger);

        self.logger
            .debug(|| Self::debugging_summary_after_error_separation(&ok, err_opt.as_ref()));

        if !ok.is_empty() {
            self.mark_pending_payable(ok);
        }
        if let Some(err) = err_opt {
            match err {
                RemoteErrors(hashes)
                | LocalError(PayableTransactionFailed {
                    signed_and_saved_txs_opt: Some(hashes),
                    ..
                }) => self.discard_incomplete_transactions_with_failures(hashes),
                _ => todo!(), //debug!(self.logger,"Forgetting a transaction attempt that even did not reach the signing stage")
            }
        }

        if let Some(response_skeleton) = &sent_payable.response_skeleton_opt {
            self.ui_message_sub
                .as_ref()
                .expect("UIGateway is not bound")
                .try_send(NodeToUiMessage {
                    target: ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                })
                .expect("UIGateway is dead");
        }
    }

    fn discard_incomplete_transactions_with_failures(&self, hashes: Vec<H256>) {
        fn serialized_hashes(hashes: &[H256]) -> String {
            hashes.iter().map(|hash| format!("{:?}", hash)).join(", ")
        }

        let (existent, nonexistent): (Vec<(Option<u64>, H256)>, Vec<(Option<u64>, H256)>) = self
            .pending_payable_dao
            .fingerprints_rowids(&hashes)
            .into_iter()
            .partition(|(rowid_opt, _hash)| rowid_opt.is_some());

        if !nonexistent.is_empty() {
            let hashes_of_nonexistent = nonexistent
                .into_iter()
                .map(|(_, hash)| hash)
                .collect::<Vec<H256>>();
            warning!(
                self.logger,
                "Throwing out failed transactions {} but with a missing record",
                serialized_hashes(&hashes_of_nonexistent),
            )
        }

        if !existent.is_empty() {
            let (ids, hashes): (Vec<u64>, Vec<H256>) = existent
                .into_iter()
                .map(|(ever_some_rowid, hash)| (ever_some_rowid.expectv("validated rowid"), hash))
                .unzip();
            debug!(
                self.logger,
                "Deleting existing fingerprints for failed transactions {}",
                serialized_hashes(&hashes)
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprints(&ids) {
                panic!("Database corrupt: payable fingerprint deletion for transactions {} has stayed undone due to {:?}", serialized_hashes(&hashes), e)
            }
        }
    }

    fn debugging_summary_after_error_separation(
        oks: &[&PendingPayable],
        errs_opt: Option<&PayableTransactingErrorEnum>,
    ) -> String {
        format!(
            "Received {} properly sent payables of {} attempts",
            oks.len(),
            Self::count_total_errors(errs_opt)
                .map(|err_count| (err_count + oks.len()).to_string())
                .unwrap_or("undetermined number of".to_string())
        )
    }

    fn count_total_errors(
        full_set_of_errors: Option<&PayableTransactingErrorEnum>,
    ) -> Option<usize> {
        match full_set_of_errors {
            Some(errors) => match errors {
                LocalError(blockchain_error) => match blockchain_error {
                    PayableTransactionFailed {
                        signed_and_saved_txs_opt,
                        ..
                    } => signed_and_saved_txs_opt.as_ref().map(|hashes| hashes.len()),
                    _ => None,
                },
                RemoteErrors(b_e) => Some(b_e.len()),
            },
            None => Some(0),
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

    fn handle_report_routing_service_consumed_message(
        &mut self,
        msg: ReportRoutingServiceConsumedMessage,
    ) {
        debug!(
            self.logger,
            "Accruing debt to wallet {} for consuming routing service {} bytes",
            msg.earning_wallet,
            msg.payload_size
        );
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.timestamp,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }

    fn handle_report_exit_service_consumed_message(
        &mut self,
        msg: ReportExitServiceConsumedMessage,
    ) {
        debug!(
            self.logger,
            "Accruing debt to wallet {} for consuming exit service {} bytes",
            msg.earning_wallet,
            msg.payload_size
        );
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.timestamp,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }

    fn handle_financials(&mut self, client_id: u64, context_id: u64) {
        let total_unpaid_and_pending_payable = self.payable_dao.total();
        let total_paid_payable = self.financial_statistics.total_paid_payable;
        let total_unpaid_receivable = self.receivable_dao.total();
        let total_paid_receivable = self.financial_statistics.total_paid_receivable;
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

    fn handle_externally_triggered_scan(
        &self,
        _ctx: &mut Context<Accountant>,
        scan_type: ScanType,
        response_skeleton: ResponseSkeleton,
    ) {
        match scan_type {
            ScanType::Payables => self.scanners.payables.scan(self, Some(response_skeleton)),
            ScanType::Receivables => self
                .scanners
                .receivables
                .scan(self, Some(response_skeleton)),
            ScanType::PendingPayables => self
                .scanners
                .pending_payables
                .scan(self, Some(response_skeleton)),
        }
    }

    fn separate_errors<'a, 'b>(
        sent_payments: &'a SentPayable,
        logger: &'b Logger,
    ) -> (Vec<&'a PendingPayable>, Option<PayableTransactingErrorEnum>) {
        match &sent_payments.payable_outcomes {
            Ok(batch_responses) => {
                let (ok, err) = Self::separate_rpc_results(&batch_responses, logger);
                let err_opt = if !err.is_empty() {
                    Some(RemoteErrors(err))
                } else {
                    None
                };
                (ok, err_opt)
            }
            Err(e) => {
                warning!(logger, "Encountered transaction error at our end: {}", e);
                (vec![], Some(LocalError(e.clone())))
            }
        }
    }

    fn separate_rpc_results<'a, 'b>(
        batch_individual_responses: &'a [ProcessedPayableFallible],
        logger: &'b Logger,
    ) -> (Vec<&'a PendingPayable>, Vec<H256>) {
        batch_individual_responses
            .iter()
            .fold(
                (vec![], vec![]),
                |so_far, given_request_result| match given_request_result {
                    Correct(payment_sent) => (plus(so_far.0, payment_sent), so_far.1),
                    Failure(RpcPayableFailure{rpc_error,recipient_wallet,hash }) => {
                        warning!(logger, "Remote transaction failure: {}, for payment to {} and transaction hash {:?}. Please check your blockchain service URL configuration.", rpc_error, recipient_wallet,hash);
                        (so_far.0, plus(so_far.1, *hash))
                    }
                },
            )
    }

    fn mark_pending_payable(&self, sent_payments: Vec<&PendingPayable>) {
        fn missing_fingerprints_msg(nonexistent: &[(TupleOfWalletRefAndRowidOpt, H256)]) -> String {
            format!(
                "Payable fingerprints for {} not found but should exist by now; system unreliable",
                nonexistent
                    .iter()
                    .map(|((wallet, _), hash)| format!("(tx: {:?}, to wallet: {})", hash, wallet))
                    .join(", ")
            )
        }

        let hashes = sent_payments
            .iter()
            .map(|pending_payable| pending_payable.hash)
            .collect::<Vec<H256>>();

        let (existent, nonexistent): (
            Vec<(TupleOfWalletRefAndRowidOpt, H256)>,
            Vec<(TupleOfWalletRefAndRowidOpt, H256)>,
        ) = self
            .pending_payable_dao
            .fingerprints_rowids(&hashes)
            .into_iter()
            .zip(sent_payments.iter())
            .map(|((rowid_opt, hash), pending_payable)| {
                ((&pending_payable.recipient_wallet, rowid_opt), hash)
            })
            .partition(|((_, rowid_opt), _)| rowid_opt.is_some());

        let appropriate_data_for_mppr = existent
            .iter()
            .map(|((wallet, ever_some_rowid), _)| (*wallet, ever_some_rowid.expectv("rowid")))
            .collect::<Vec<(&Wallet, u64)>>();

        if !appropriate_data_for_mppr.is_empty() {
            match self
                .payable_dao
                .as_ref()
                .mark_pending_payables_rowids(&appropriate_data_for_mppr)
            {
                Ok(()) => (),
                Err(e) => {
                    if !nonexistent.is_empty() {
                        error!(self.logger, "{}", missing_fingerprints_msg(&nonexistent))
                    }
                    panic!(
                        "Was unable to create a mark in payables due to {:?} for new pending payables {}",
                        e,
                        sent_payments
                            .iter()
                            .map(|pending_payable| pending_payable.recipient_wallet.to_string())
                            .join(", ")
                    )
                }
            }
            debug!(
                self.logger,
                "Payables {} have been marked as pending in the payable table",
                sent_payments
                    .iter()
                    .map(|pending_payable_dao| format!("{:?}", pending_payable_dao.hash))
                    .join(", ")
            )
        }
        if !nonexistent.is_empty() {
            panic!("{}", missing_fingerprints_msg(&nonexistent))
        }
    }

    fn handle_pending_transaction_with_its_receipt(
        &self,
        msg: &ReportTransactionReceipts,
    ) -> PendingPayableScanSummary {
        fn handle_none_receipt(
            scan_summary: &mut PendingPayableScanSummary,
            payable: &PendingPayableFingerprint,
            logger: &Logger,
        ) {
            debug!(logger,
                "DEBUG: Accountant: Interpreting a receipt for transaction {:?} but none was given; attempt {}, {}ms since sending",
                payable.hash, payable.attempt_opt.expectv("initialized attempt"),elapsed_in_ms(payable.timestamp)
            );

            scan_summary.still_pending.push(PendingPayableId {
                hash: payable.hash,
                rowid: payable.rowid_opt.expectv("initialized rowid"),
            })
        }

        let mut scan_summary = PendingPayableScanSummary::default();
        msg.fingerprints_with_receipts
            .iter()
            .for_each(|(receipt_opt, fingerprint)| match receipt_opt {
                Some(receipt) => self.interpret_transaction_receipt(
                    &mut scan_summary,
                    receipt,
                    fingerprint,
                    &self.logger,
                ),
                None => handle_none_receipt(&mut scan_summary, fingerprint, &self.logger),
            });
        scan_summary
    }

    fn interpret_transaction_receipt(
        &self,
        scan_summary: &mut PendingPayableScanSummary,
        receipt: &TransactionReceipt,
        fingerprint: &PendingPayableFingerprint,
        logger: &Logger,
    ) {
        fn handle_none_status(
            scan_summary: &mut PendingPayableScanSummary,
            fingerprint: &PendingPayableFingerprint,
            max_pending_interval: u64,
            logger: &Logger,
        ) {
            info!(logger,"Pending transaction {:?} couldn't be confirmed at attempt {} at {}ms after its sending",
                fingerprint.hash, fingerprint.attempt_opt.expectv("initialized attempt"), elapsed_in_ms(fingerprint.timestamp)
            );

            let elapsed = fingerprint
                .timestamp
                .elapsed()
                .expect("we should be older now");

            if max_pending_interval <= elapsed.as_secs() {
                error!(logger,"Pending transaction {:?} has exceeded the maximum pending time ({}sec) and the confirmation process is going to be aborted now at the final attempt {}; \
                 manual resolution is required from the user to complete the transaction.", fingerprint.hash, max_pending_interval, fingerprint.attempt_opt.expectv("initialized attempt"));
                scan_summary.failures.push(fingerprint.into())
            } else {
                scan_summary.still_pending.push(fingerprint.into())
            }
        }

        fn handle_status_with_success(
            scan_summary: &mut PendingPayableScanSummary,
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) {
            info!(
                logger,
                "Transaction {:?} has been added to the blockchain; detected locally at attempt {} at {}ms after its sending",
                fingerprint.hash,
                fingerprint.attempt_opt.expectv("initialized attempt"),
                elapsed_in_ms(fingerprint.timestamp)
            );
            scan_summary.confirmed.push(fingerprint.clone())
        }

        fn handle_status_with_failure(
            scan_summary: &mut PendingPayableScanSummary,
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) {
            error!(logger,"Pending transaction {:?} announced as a failure, interpreting attempt {} after {}ms from the sending",
                fingerprint.hash,fingerprint.attempt_opt.expectv("initialized attempt"),elapsed_in_ms(fingerprint.timestamp)
            );
            scan_summary.failures.push(fingerprint.into())
        }

        match receipt.status{
                None => handle_none_status(scan_summary,fingerprint, self.config.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64(){
                    0 => handle_status_with_failure(scan_summary, fingerprint, logger),
                    1 => handle_status_with_success(scan_summary, fingerprint, logger),
                    other => unreachable!("tx receipt for pending {:?} - tx status: code other than 0 or 1 shouldn't be possible, but was {}", fingerprint.hash, other)
                }
            }
    }

    fn process_transaction_by_status(&mut self, scan_summary: PendingPayableScanSummary) {
        self.confirm_transactions(scan_summary.confirmed);
        self.cancel_transactions(scan_summary.failures);
        self.update_fingerprints(scan_summary.still_pending)
    }

    fn confirm_transactions(&mut self, fingerprints: Vec<PendingPayableFingerprint>) {
        fn serialized_hashes(fingerprints: &[PendingPayableFingerprint]) -> String {
            fingerprints
                .iter()
                .map(|fgp| format!("{:?}", fgp.hash))
                .join(", ")
        }

        if !fingerprints.is_empty() {
            if let Err(e) = self.payable_dao.transactions_confirmed(&fingerprints) {
                panic!(
                    "Was unable to uncheck pending payables {} during their confirmation due to {:?}",
                    serialized_hashes(&fingerprints),
                    e
                )
            } else {
                self.add_to_the_total_of_paid_payable(&fingerprints, serialized_hashes);
                let rowids = fingerprints
                    .iter()
                    .map(|fingerprint| fingerprint.rowid_opt.expectv("initialized rowid"))
                    .collect::<Vec<u64>>();
                if let Err(e) = self.pending_payable_dao.delete_fingerprints(&rowids) {
                    panic!("Was unable to delete payable fingerprints {} for successful transactions due to {:?}",
                        serialized_hashes(&fingerprints), e)
                } else {
                    info!(
                        self.logger,
                        "Transactions {} went through the whole confirmation process succeeding",
                        serialized_hashes(&fingerprints)
                    )
                }
            }
        }
    }

    fn add_to_the_total_of_paid_payable(
        &mut self,
        fingerprints: &[PendingPayableFingerprint],
        serialized_hashes: fn(&[PendingPayableFingerprint]) -> String,
    ) {
        fingerprints.iter().for_each(|fingerprint| {
            self.financial_statistics.total_paid_payable += fingerprint.amount
        });
        debug!(
            self.logger,
            "Confirmation of transactions {}; record for total paid payable was modified",
            serialized_hashes(fingerprints)
        );
    }

    fn cancel_transactions(&self, ids: Vec<PendingPayableId>) {
        if !ids.is_empty() {
            //TODO we should have a function clearing these failures out from the pending_payable table after a certain long time period passes
            let rowids = PendingPayableId::rowids(&ids);
            match self
                    .pending_payable_dao
                    .mark_failures(&rowids)
                {
                    Ok(_) => warning!(
                self.logger, "Broken transactions {} marked as an error. You should take over the care of those \
                 to make sure your debts are going to be settled properly. At the moment, there is no automated process fixing that without your assistance",
                PendingPayableId::hashes_as_single_string(&ids)),
                    Err(e) => panic!("Unsuccessful attempt for transactions {} to mark fatal error \
                     at payable fingerprint due to {:?}; database unreliable", PendingPayableId::hashes_as_single_string(&ids), e),
                }
            //TODO I think it should also remove the mark at the payable table
        }
    }

    fn update_fingerprints(&self, ids: Vec<PendingPayableId>) {
        if !ids.is_empty() {
            let rowids = PendingPayableId::rowids(&ids);
            match self.pending_payable_dao.update_fingerprints(&rowids) {
                Ok(_) => trace!(
                    self.logger,
                    "Updated records for rowids: {} ",
                    stringify_rowids(&rowids)
                ),
                Err(e) => panic!(
                    "Failure on updating payable fingerprints {} due to {:?}",
                    PendingPayableId::hashes_as_single_string(&ids),
                    e
                ),
            }
        }
    }

    fn handle_new_pending_payable_fingerprints(&self, msg: ReportNewPendingPayableFingerprints) {
        fn serialized_hashes(fingerprints_data: &[(H256, u64)]) -> String {
            fingerprints_data
                .iter()
                .map(|(hash, _)| format!("{:?}", hash))
                .join(", ")
        }

        match self
            .pending_payable_dao
            .insert_new_fingerprints(&msg.init_params, msg.batch_wide_timestamp)
        {
            Ok(_) => debug!(
                self.logger,
                "Saved new pending payable fingerprints for: {}",
                serialized_hashes(&msg.init_params)
            ),
            Err(e) => error!(
                self.logger,
                "Failed to process new pending payable fingerprints due to '{:?}', \
                 disabling the automated confirmation for all these transactions: {}",
                e,
                serialized_hashes(&msg.init_params)
            ),
        }
    }
}

#[derive(Debug, PartialEq)]
enum PayableTransactingErrorEnum {
    LocalError(BlockchainError),
    RemoteErrors(Vec<H256>),
}

pub fn unsigned_to_signed(unsigned: u64) -> Result<i64, u64> {
    i64::try_from(unsigned).map_err(|_| unsigned)
}

pub fn stringify_rowids(ids: &[u64]) -> String {
    ids.iter().map(|id| id.to_string()).join(", ")
}

fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct PendingPayableScanSummary {
    pub still_pending: Vec<PendingPayableId>,
    pub failures: Vec<PendingPayableId>,
    pub confirmed: Vec<PendingPayableFingerprint>,
}

type TupleOfWalletRefAndRowidOpt<'a> = (&'a Wallet, Option<u64>);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PendingPayableId {
    pub rowid: u64,
    pub hash: H256,
}

impl PendingPayableId {
    fn rowids(ids: &[Self]) -> Vec<u64> {
        ids.iter().map(|id| id.rowid).collect()
    }

    fn hashes_as_single_string(ids: &[Self]) -> String {
        ids.iter().map(|id| format!("{:?}", id.hash)).join(", ")
    }
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

trait PayableExceedThresholdTools {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
    fn is_innocent_balance(&self, balance: i64, limit: i64) -> bool;
    fn calculate_payout_threshold(&self, payment_thresholds: PaymentThresholds, x: u64) -> f64;
    as_any_dcl!();
}

#[derive(Default)]
struct PayableExceedThresholdToolsReal {}

impl PayableExceedThresholdTools for PayableExceedThresholdToolsReal {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
        age <= limit
    }

    fn is_innocent_balance(&self, balance: i64, limit: i64) -> bool {
        balance <= limit
    }

    fn calculate_payout_threshold(&self, payment_thresholds: PaymentThresholds, x: u64) -> f64 {
        let m = -((payment_thresholds.debt_threshold_gwei as f64
            - payment_thresholds.permanent_debt_allowed_gwei as f64)
            / (payment_thresholds.threshold_interval_sec as f64
                - payment_thresholds.maturity_threshold_sec as f64));
        let b = payment_thresholds.debt_threshold_gwei as f64
            - m * payment_thresholds.maturity_threshold_sec as f64;
        m * x as f64 + b
    }
    as_any_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::time::Duration;
    use std::time::SystemTime;

    use actix::{Arbiter, System};
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use masq_lib::constants::SCAN_ERROR;
    use web3::Error;

    use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};

    use crate::accountant::payable_dao::PayableDaoError;
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::{
        bc_from_ac_plus_earning_wallet, bc_from_ac_plus_wallets, make_pending_payable_fingerprint,
        make_receivable_account, BannedDaoFactoryMock, PayableDaoFactoryMock, PayableDaoMock,
        PendingPayableDaoFactoryMock, PendingPayableDaoMock, ReceivableDaoFactoryMock,
        ReceivableDaoMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::tools::accountant_tools::{NullScanner, ReceivablesScanner};
    use crate::accountant::Accountant;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
    use crate::blockchain::blockchain_interface::BlockchainTransaction;
    use crate::blockchain::test_utils::{make_tx_hash, BlockchainInterfaceMock};
    use crate::bootstrapper::BootstrapperConfig;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::sub_lib::accountant::{
        ReportRoutingServiceConsumedMessage, ScanIntervals, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::utils::NotifyLaterHandleReal;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::unshared_test_utils::{
        make_accountant_config_null, make_populated_accountant_config_with_defaults,
        prove_that_crash_request_handler_is_hooked_up, NotifyLaterHandleMock, SystemKillerActor,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use web3::types::{TransactionReceipt, H256};

    #[derive(Default)]
    struct PayableThresholdToolsMock {
        is_innocent_age_params: Arc<Mutex<Vec<(u64, u64)>>>,
        is_innocent_age_results: RefCell<Vec<bool>>,
        is_innocent_balance_params: Arc<Mutex<Vec<(i64, i64)>>>,
        is_innocent_balance_results: RefCell<Vec<bool>>,
        calculate_payout_threshold_params: Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
        calculate_payout_threshold_results: RefCell<Vec<f64>>,
    }

    impl PayableExceedThresholdTools for PayableThresholdToolsMock {
        fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
            self.is_innocent_age_params
                .lock()
                .unwrap()
                .push((age, limit));
            self.is_innocent_age_results.borrow_mut().remove(0)
        }

        fn is_innocent_balance(&self, balance: i64, limit: i64) -> bool {
            self.is_innocent_balance_params
                .lock()
                .unwrap()
                .push((balance, limit));
            self.is_innocent_balance_results.borrow_mut().remove(0)
        }

        fn calculate_payout_threshold(&self, payment_thresholds: PaymentThresholds, x: u64) -> f64 {
            self.calculate_payout_threshold_params
                .lock()
                .unwrap()
                .push((payment_thresholds, x));
            self.calculate_payout_threshold_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl PayableThresholdToolsMock {
        fn is_innocent_age_params(mut self, params: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.is_innocent_age_params = params.clone();
            self
        }

        fn is_innocent_age_result(self, result: bool) -> Self {
            self.is_innocent_age_results.borrow_mut().push(result);
            self
        }

        fn is_innocent_balance_params(mut self, params: &Arc<Mutex<Vec<(i64, i64)>>>) -> Self {
            self.is_innocent_balance_params = params.clone();
            self
        }

        fn is_innocent_balance_result(self, result: bool) -> Self {
            self.is_innocent_balance_results.borrow_mut().push(result);
            self
        }

        fn calculate_payout_threshold_params(
            mut self,
            params: &Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
        ) -> Self {
            self.calculate_payout_threshold_params = params.clone();
            self
        }

        fn calculate_payout_threshold_result(self, result: f64) -> Self {
            self.calculate_payout_threshold_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "ACCOUNTANT");
        assert_eq!(DEFAULT_PENDING_TOO_LONG_SEC, 21_600);
    }

    #[test]
    fn new_calls_factories_properly() {
        let mut config = BootstrapperConfig::new();
        config.accountant_config_opt = Some(make_accountant_config_null());
        let payable_dao_factory_called = Rc::new(RefCell::new(false));
        let payable_dao = PayableDaoMock::new();
        let payable_dao_factory =
            PayableDaoFactoryMock::new(payable_dao).called(&payable_dao_factory_called);
        let receivable_dao_factory_called = Rc::new(RefCell::new(false));
        let receivable_dao = ReceivableDaoMock::new();
        let receivable_dao_factory =
            ReceivableDaoFactoryMock::new(receivable_dao).called(&receivable_dao_factory_called);
        let pending_payable_dao_factory_called = Rc::new(RefCell::new(false));
        let pending_payable_dao = PendingPayableDaoMock::default();
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new(pending_payable_dao)
            .called(&pending_payable_dao_factory_called);
        let banned_dao_factory_called = Rc::new(RefCell::new(false));
        let banned_dao = BannedDaoMock::new();
        let banned_dao_factory =
            BannedDaoFactoryMock::new(banned_dao).called(&banned_dao_factory_called);

        let _ = Accountant::new(
            &config,
            Box::new(payable_dao_factory),
            Box::new(receivable_dao_factory),
            Box::new(pending_payable_dao_factory),
            Box::new(banned_dao_factory),
        );

        assert_eq!(payable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(receivable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(
            pending_payable_dao_factory_called.as_ref(),
            &RefCell::new(true)
        );
        assert_eq!(banned_dao_factory_called.as_ref(), &RefCell::new(true));
    }

    #[test]
    fn accountant_have_proper_defaulted_values() {
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.accountant_config_opt =
            Some(make_populated_accountant_config_with_defaults());
        let payable_dao_factory = Box::new(PayableDaoFactoryMock::new(PayableDaoMock::new()));
        let receivable_dao_factory =
            Box::new(ReceivableDaoFactoryMock::new(ReceivableDaoMock::new()));
        let pending_payable_dao_factory = Box::new(PendingPayableDaoFactoryMock::new(
            PendingPayableDaoMock::default(),
        ));
        let banned_dao_factory = Box::new(BannedDaoFactoryMock::new(BannedDaoMock::new()));

        let result = Accountant::new(
            &bootstrapper_config,
            payable_dao_factory,
            receivable_dao_factory,
            pending_payable_dao_factory,
            banned_dao_factory,
        );

        let transaction_confirmation_tools = result.tools;
        transaction_confirmation_tools
            .notify_later_scan_for_pending_payable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForPendingPayables>>()
            .unwrap();
        transaction_confirmation_tools
            .notify_later_scan_for_payable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForPayables>>()
            .unwrap();
        transaction_confirmation_tools
            .notify_later_scan_for_receivable
            .as_any()
            .downcast_ref::<NotifyLaterHandleReal<ScanForReceivables>>()
            .unwrap();
        //testing presence of real scanners, there is a different test covering them all
        result
            .scanners
            .receivables
            .as_any()
            .downcast_ref::<ReceivablesScanner>()
            .unwrap();
        result
            .payable_threshold_tools
            .as_any()
            .downcast_ref::<PayableExceedThresholdToolsReal>()
            .unwrap();
        assert_eq!(result.crashable, false);
        assert_eq!(result.financial_statistics.total_paid_receivable, 0);
        assert_eq!(result.financial_statistics.total_paid_payable, 0);
    }

    #[test]
    fn scan_receivables_request() {
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: Default::default(),
            },
            make_wallet("earning_wallet"),
        );
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
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
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn received_payments_with_response_skeleton_sends_response_to_ui_gateway() {
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("earning_wallet"),
        );
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("some_wallet_address"),
        );
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
            .payable_dao(payable_dao)
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
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn sent_payable_with_response_skeleton_sends_scan_response_to_ui_gateway() {
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("earning_wallet"),
        );
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(1), Default::default())]);
        let payable_dao = PayableDaoMock::default().mark_pending_payable_rowid_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .payable_dao(payable_dao)
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Ok(vec![Correct(PendingPayable {
                recipient_wallet: make_wallet("blah"),
                hash: Default::default(),
            })]),
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("some_wallet_address"),
        );
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
            .pending_payable_dao(pending_payable_dao)
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
                    context_id: 4321
                }),
            }
        );
    }

    #[test]
    fn report_transaction_receipts_with_response_skeleton_sends_scan_response_to_ui_gateway() {
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(10_000),
                    receivable_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("earning_wallet"),
        );
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
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payable_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_wallet = make_wallet("paying_you");
        let expected_hash = H256::from("transaction_hash".keccak256());
        let expected_rowid = 45623;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(vec![(Some(expected_rowid), expected_hash)]);
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_params(&mark_pending_payable_rowid_params_arc)
            .mark_pending_payable_rowid_result(Ok(()));
        let system = System::new("accountant_calls_payable_dao_to_mark_pending_payable");
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let expected_payable = PendingPayable::new(expected_wallet.clone(), expected_hash.clone());
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Ok(vec![Correct(expected_payable.clone())]),
            response_skeleton_opt: None,
        };
        let subject = accountant.start();

        subject
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(*fingerprints_rowids_params, vec![vec![expected_hash]]);
        let mark_pending_payable_rowid_params =
            mark_pending_payable_rowid_params_arc.lock().unwrap();
        let actual = mark_pending_payable_rowid_params.get(0).unwrap();
        assert_eq!(actual, &[(expected_wallet, expected_rowid)]);
    }

    #[test]
    fn accountant_logs_and_aborts_when_handle_sent_payable_finds_errors_from_post_hash_time_and_some_fingerprints_do_not_exist(
    ) {
        init_test_logging();
        let system = System::new("sent payable failure without backup");
        let hash_1 = make_tx_hash(112233);
        let hash_2 = make_tx_hash(12345);
        let hash_3 = make_tx_hash(8765);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(333), hash_1), (None, hash_2), (None, hash_3)])
            .delete_fingerprints_result(Ok(()));
        let accountant = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Err(BlockchainError::PayableTransactionFailed {
                msg: "SQLite migraine".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_1, hash_2, hash_3]),
            }),
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
            hash_1
        ));
        log_handler.exists_log_containing(
            "WARN: Accountant: Encountered transaction error at our end: Blockchain error: \
             Processing batch requests: SQLite migraine. With fully prepared transactions, \
              each registered. Those are: 0x000000000000000000000000000000000000000000000000000000000001b669, \
              0x0000000000000000000000000000000000000000000000000000000000003039, \
               0x000000000000000000000000000000000000000000000000000000000000223d.");
        log_handler.exists_log_containing(
            "WARN: Accountant: Throwing out failed transactions 0x0000000000000000000000000000000000000000000000000000000000003039, \
             0x000000000000000000000000000000000000000000000000000000000000223d but with a missing record",
        );
    }

    #[test]
    fn handle_sent_payable_discovers_failed_transactions_and_pending_payable_fingerprints_were_really_created(
    ) {
        init_test_logging();
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_tx_1 = make_tx_hash(5555);
        let hash_tx_2 = make_tx_hash(12345);
        let first_incomplete_transaction_rowid = 3;
        let second_incomplete_transaction_rowid = 5;
        let system = System::new("handle_sent_payable_discovers_failed_transactions_and_pending_payable_fingerprints_were_really_created");
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(vec![
                (Some(first_incomplete_transaction_rowid), hash_tx_1),
                (Some(second_incomplete_transaction_rowid), hash_tx_2),
            ])
            .delete_fingerprint_params(&delete_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()))
            .delete_fingerprints_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        subject.logger = Logger::new("handle_sent_payable_discovers_failed_transactions_and_pending_payable_fingerprints_were_really_created");
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Err(BlockchainError::PayableTransactionFailed {
                msg: "Attempt failed".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_tx_1, hash_tx_2]),
            }),
            response_skeleton_opt: None,
        };
        let subject_addr = subject.start();

        subject_addr
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(
            *fingerprints_rowids_params,
            vec![vec![hash_tx_1, hash_tx_2]]
        );
        let delete_fingerprints_params = delete_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *delete_fingerprints_params,
            vec![vec![
                first_incomplete_transaction_rowid,
                second_incomplete_transaction_rowid
            ]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: handle_sent_payable_discovers_failed_transactions_and_pending_payable_fingerprints_were_really_created: \
         Encountered transaction error at our end: Blockchain error: Processing batch requests: Attempt failed. With fully prepared transactions, each registered. Those are: \
           0x00000000000000000000000000000000000000000000000000000000000015b3, 0x0000000000000000000000000000000000000000000000000000000000003039.");
        log_handler.exists_log_containing(
            "DEBUG: handle_sent_payable_discovers_failed_transactions_and_pending_payable_fingerprints_were_really_created: \
            Deleting existing fingerprints for failed transactions 0x00000000000000000000000000000000000000000000000000000000000015b3, \
            0x0000000000000000000000000000000000000000000000000000000000003039",
        );
        //we haven't supplied any result for mark_pending_payable() and so it's proved as uncalled
    }

    #[test]
    fn discard_incomplete_transactions_with_failures_logs_missing_rowids_before_definite_panic_from_fingerprint_deletion(
    ) {
        init_test_logging();
        let existent_record_hash = make_tx_hash(45678);
        let nonexistent_record_hash = make_tx_hash(1234);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![
                (Some(45), existent_record_hash),
                (None, nonexistent_record_hash),
            ])
            .delete_fingerprints_result(Err(PendingPayableDaoError::RecordDeletion(
                "Another failure. Really ???".to_string(),
            )));
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        subject.logger = Logger::new("discard_incomplete_transactions_with_failures_logs_missing_rowids_before_definite_panic_from_fingerprint_deletion");

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.discard_incomplete_transactions_with_failures(vec![])
        }))
        .unwrap_err();

        let panic_message = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(panic_message, "Database corrupt: payable fingerprint deletion for transactions 0x000000000000000000000000000000000000000000000000000000000000b26e has stayed \
        undone due to RecordDeletion(\"Another failure. Really ???\")");
        TestLogHandler::new().exists_log_containing("WARN: discard_incomplete_transactions_with_failures_logs_missing_rowids_before_definite_panic_from_fingerprint_deletion: \
        Throwing out failed transactions 0x00000000000000000000000000000000000000000000000000000000000004d2 but with a missing record");
    }

    #[test]
    fn accountant_sends_report_accounts_payable_to_blockchain_bridge_when_qualified_payable_found()
    {
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("blah"),
                balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 55,
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now())
                        - DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
                        - 5,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("foo"),
                balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 66,
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now())
                        - DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
                        - 500,
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(accounts.clone());
        let system = System::new("report_accounts_payable forwarded to blockchain_bridge");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .payable_dao(payable_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner);
        subject.scanners.receivables = Box::new(NullScanner);
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
        let report_accounts_payables_msgs: Vec<&ReportAccountsPayable> = (0
            ..blockchain_bridge_recorder.len())
            .flat_map(|index| {
                blockchain_bridge_recorder.get_record_opt::<ReportAccountsPayable>(index)
            })
            .collect();
        assert_eq!(
            report_accounts_payables_msgs,
            vec![&ReportAccountsPayable {
                accounts,
                response_skeleton_opt: None
            }]
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
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                earning_wallet.clone(),
            ))
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner);
        subject.scanners.payables = Box::new(NullScanner);
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                earning_wallet.clone(),
            ))
            .payable_dao(PayableDaoMock::new().non_pending_payables_result(vec![]))
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
        let return_all_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, _) = make_recorder();
        let system = System::new("accountant_scans_after_startup");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_secs(100), //making sure we cannot enter the first repeated scanning
                    receivable_scan_interval: Duration::from_secs(100),
                    pending_payable_scan_interval: Duration::from_millis(100), //except here, where we use it to stop the system
                },
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: false,
            },
            make_wallet("buy"),
            make_wallet("hi"),
        );
        let mut pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_fingerprints_params(&return_all_fingerprints_params_arc)
            .return_all_fingerprints_result(vec![]);
        pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_params_arc)
            .new_delinquencies_result(vec![])
            .paid_delinquencies_parameters(&paid_delinquencies_params_arc)
            .paid_delinquencies_result(vec![]);
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![]);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let tlh = TestLogHandler::new();
        tlh.await_log_containing("INFO: Accountant: Scanning for payables", 1000);
        tlh.exists_log_containing(&format!(
            "INFO: Accountant: Scanning for receivables to {}",
            make_wallet("hi")
        ));
        tlh.exists_log_containing("INFO: Accountant: Scanning for delinquencies");
        tlh.exists_log_containing("INFO: Accountant: Scanning for pending payable");
        //some more weak proofs but still good enough
        //proof of calling a piece of scan_for_pending_payable
        let return_all_fingerprints_params = return_all_fingerprints_params_arc.lock().unwrap();
        //the last ends this test calling System::current.stop()
        assert_eq!(*return_all_fingerprints_params, vec![(), ()]);
        //proof of calling a piece of scan_for_payable()
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![()]);
        //proof of calling pieces of scan_for_delinquencies()
        let mut new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        let (captured_timestamp, captured_curves) = new_delinquencies_params.remove(0);
        assert!(new_delinquencies_params.is_empty());
        assert!(
            captured_timestamp < SystemTime::now()
                && captured_timestamp >= from_time_t(to_time_t(SystemTime::now()) - 5)
        );
        assert_eq!(captured_curves, *DEFAULT_PAYMENT_THRESHOLDS);
        let paid_delinquencies_params = paid_delinquencies_params_arc.lock().unwrap();
        assert_eq!(paid_delinquencies_params.len(), 1);
        assert_eq!(paid_delinquencies_params[0], *DEFAULT_PAYMENT_THRESHOLDS);
    }

    #[test]
    fn periodical_scanning_for_receivables_and_delinquencies_works() {
        init_test_logging();
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let ban_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_receivable_params_arc = Arc::new(Mutex::new(vec![]));
        let earning_wallet = make_wallet("earner3000");
        let wallet_to_be_banned = make_wallet("bad_luck");
        let (blockchain_bridge, _, blockchain_bridge_recording) = make_recorder();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_secs(100),
                    receivable_scan_interval: Duration::from_millis(99),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: false,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            earning_wallet.clone(),
        );
        let new_delinquent_account = ReceivableAccount {
            wallet: wallet_to_be_banned.clone(),
            balance: 4567,
            last_received_timestamp: from_time_t(200_000_000),
        };
        let system = System::new("periodical_scanning_for_receivables_and_delinquencies_works");
        let banned_dao = BannedDaoMock::new().ban_parameters(&ban_params_arc);
        let mut receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_params_arc)
            //this is the immediate try, not with our interval
            .new_delinquencies_result(vec![])
            //after the interval we actually process data
            .new_delinquencies_result(vec![new_delinquent_account])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        receivable_dao.have_new_delinquencies_shutdown_the_system = true;
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner);
        subject.scanners.payables = Box::new(NullScanner);
        subject.tools.notify_later_scan_for_receivable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_receivable_params_arc)
                .permit_to_send_out(),
        );
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        assert_eq!(retrieve_transactions_recording.len(), 3);
        let retrieve_transactions_msgs: Vec<&RetrieveTransactions> = (0
            ..retrieve_transactions_recording.len())
            .map(|index| retrieve_transactions_recording.get_record::<RetrieveTransactions>(index))
            .collect();
        assert_eq!(
            *retrieve_transactions_msgs,
            vec![
                &RetrieveTransactions {
                    recipient: earning_wallet.clone(),
                    response_skeleton_opt: None,
                },
                &RetrieveTransactions {
                    recipient: earning_wallet.clone(),
                    response_skeleton_opt: None,
                },
                &RetrieveTransactions {
                    recipient: earning_wallet.clone(),
                    response_skeleton_opt: None,
                }
            ]
        );
        //sadly I cannot effectively assert on the exact params
        //they are a) real timestamp of now, b) constant payment_thresholds
        //the Rust type system gives me enough support to be okay with counting occurrences
        let new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        assert_eq!(new_delinquencies_params.len(), 3); //the third one is the signal to shut the system down
        let ban_params = ban_params_arc.lock().unwrap();
        assert_eq!(*ban_params, vec![wallet_to_be_banned]);
        let notify_later_receivable_params = notify_later_receivable_params_arc.lock().unwrap();
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
                (
                    ScanForReceivables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(99)
                )
            ]
        )
    }

    #[test]
    fn periodical_scanning_for_pending_payable_works() {
        //in the very first round we scan without waiting but we cannot find any pending payable
        init_test_logging();
        let return_all_pending_payable_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system =
            System::new("accountant_payable_scan_timer_triggers_scanning_for_pending_payable");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_secs(100),
                    receivable_scan_interval: Duration::from_secs(100),
                    pending_payable_scan_interval: Duration::from_millis(98),
                },
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: false,
            },
            make_wallet("hi"),
        );
        // slightly above minimum balance, to the right of the curve (time intersection)
        let pending_payable_fingerprint_record = PendingPayableFingerprint {
            rowid_opt: Some(45454),
            timestamp: SystemTime::now(),
            hash: make_tx_hash(565),
            attempt_opt: Some(1),
            amount: 4589,
            process_error: None,
        };
        let mut pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_fingerprints_params(&return_all_pending_payable_fingerprints_params_arc)
            .return_all_fingerprints_result(vec![])
            .return_all_fingerprints_result(vec![pending_payable_fingerprint_record.clone()]);
        pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .pending_payable_dao(pending_payable_dao)
            .build();
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.scanners.payables = Box::new(NullScanner); //skipping
        subject.tools.notify_later_scan_for_pending_payable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_pending_payable_params_arc)
                .permit_to_send_out(),
        );
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let return_all_pending_payable_fingerprints =
            return_all_pending_payable_fingerprints_params_arc
                .lock()
                .unwrap();
        //the third attempt is the one where the queue is empty and System::current.stop() ends the cycle
        assert_eq!(*return_all_pending_payable_fingerprints, vec![(), (), ()]);
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let request_transaction_receipt_msg =
            blockchain_bridge_recorder.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            request_transaction_receipt_msg,
            &RequestTransactionReceipts {
                pending_payable: vec![pending_payable_fingerprint_record],
                response_skeleton_opt: None,
            }
        );
        let notify_later_pending_payable_params =
            notify_later_pending_payable_params_arc.lock().unwrap();
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
                (
                    ScanForPendingPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(98)
                )
            ]
        )
    }

    #[test]
    fn accountant_payable_scan_timer_triggers_periodical_scanning_for_payables() {
        //in the very first round we scan without waiting but we cannot find any payable records
        init_test_logging();
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let system = System::new("accountant_payable_scan_timer_triggers_scanning_for_payables");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(97),
                    receivable_scan_interval: Duration::from_secs(100),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: false,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("hi"),
        );
        let now = to_time_t(SystemTime::now());
        // slightly above minimum balance, to the right of the curve (time intersection)
        let account = PayableAccount {
            wallet: make_wallet("wallet"),
            balance: DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 5,
            last_paid_timestamp: from_time_t(
                now - DEFAULT_PAYMENT_THRESHOLDS.threshold_interval_sec - 10,
            ),
            pending_payable_opt: None,
        };
        let mut payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![])
            .non_pending_payables_result(vec![account.clone()]);
        payable_dao.have_non_pending_payables_shut_down_the_system = true;
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner); //skipping
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.tools.notify_later_scan_for_payable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_payables_params_arc)
                .permit_to_send_out(),
        );
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        system.run();
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        //the third attempt is the one where the queue is empty and System::current.stop() ends the cycle
        assert_eq!(*non_pending_payables_params, vec![(), (), ()]);
        let blockchain_bridge_recorder = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recorder.len(), 1);
        let report_accounts_payables_msg =
            blockchain_bridge_recorder.get_record::<ReportAccountsPayable>(0);
        assert_eq!(
            report_accounts_payables_msg,
            &ReportAccountsPayable {
                accounts: vec![account],
                response_skeleton_opt: None,
            }
        );
        let notify_later_payables_params = notify_later_payables_params_arc.lock().unwrap();
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
                (
                    ScanForPayables {
                        response_skeleton_opt: None
                    },
                    Duration::from_millis(97)
                )
            ]
        )
    }

    #[test]
    fn start_message_triggers_no_scans_in_suppress_mode() {
        init_test_logging();
        let system = System::new("start_message_triggers_no_scans_in_suppress_mode");
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_millis(1),
                    receivable_scan_interval: Duration::from_millis(1),
                    pending_payable_scan_interval: Duration::from_secs(100),
                },
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: true,
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
            },
            make_wallet("hi"),
        );
        let payable_dao = PayableDaoMock::new(); // No payables: demanding one would cause a panic
        let receivable_dao = ReceivableDaoMock::new(); // No delinquencies: demanding one would cause a panic
        let peer_actors = peer_actors_builder().build();
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .build();
        let subject_addr = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(subject_subs, peer_actors);

        send_start_message!(subject_subs);

        System::current().stop();
        assert_eq!(system.run(), 0);
        // no panics because of recalcitrant DAOs; therefore DAOs were not called; therefore test passes
        TestLogHandler::new().exists_log_containing(
            "Started with --scans off; declining to begin database and blockchain scans",
        );
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let accountant_config = make_populated_accountant_config_with_defaults();
        let config = bc_from_ac_plus_earning_wallet(accountant_config, make_wallet("mine"));
        let now = to_time_t(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
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
            .payable_dao(payable_dao)
            .build();
        subject.report_accounts_payable_sub = Some(report_accounts_payable_sub);
        subject.config.payment_thresholds = payment_thresholds;

        subject.scan_for_payables(None);

        System::current().stop_with_code(0);
        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_payable_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    pending_payable_scan_interval: Duration::from_secs(50_000),
                    payable_scan_interval: Duration::from_millis(100),
                    receivable_scan_interval: Duration::from_secs(50_000),
                },
                payment_thresholds: DEFAULT_PAYMENT_THRESHOLDS.clone(),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                suppress_initial_scans: false,
            },
            make_wallet("mine"),
        );
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
        let mut payable_dao = PayableDaoMock::default()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        payable_dao.have_non_pending_payables_shut_down_the_system = true;
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system =
            System::new("scan_for_payable_message_triggers_payment_for_balances_over_the_curve");
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner);
        subject.scanners.receivables = Box::new(NullScanner);
        let subject_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable {
                accounts,
                response_skeleton_opt: None
            }
        );
    }

    #[test]
    fn scan_for_delinquencies_triggers_bans_and_unbans() {
        init_test_logging();
        let accountant_config = make_populated_accountant_config_with_defaults();
        let config = bc_from_ac_plus_earning_wallet(accountant_config, make_wallet("mine"));
        let newly_banned_1 = make_receivable_account(1234, true);
        let newly_banned_2 = make_receivable_account(2345, true);
        let newly_unbanned_1 = make_receivable_account(3456, false);
        let newly_unbanned_2 = make_receivable_account(4567, false);
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let new_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_parameters_arc)
            .new_delinquencies_result(vec![newly_banned_1.clone(), newly_banned_2.clone()])
            .paid_delinquencies_parameters(&paid_delinquencies_parameters_arc)
            .paid_delinquencies_result(vec![newly_unbanned_1.clone(), newly_unbanned_2.clone()]);
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .build();

        subject.scan_for_delinquencies();

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentThresholds)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(
            DEFAULT_PAYMENT_THRESHOLDS.clone(),
            new_delinquencies_parameters[0].1
        );
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentThresholds>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(
            DEFAULT_PAYMENT_THRESHOLDS.clone(),
            paid_delinquencies_parameters[0]
        );
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet));
        assert!(ban_parameters.contains(&newly_banned_2.wallet));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c65743132333464 \\(balance: 1234 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c65743233343564 \\(balance: 2345 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c6574333435366e \\(balance: 3456 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
        tlh.exists_log_matching("INFO: Accountant: Wallet 0x00000000000000000077616c6c6574343536376e \\(balance: 4567 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
    }

    #[test]
    fn scan_for_pending_payable_found_no_pending_payable() {
        init_test_logging();
        let return_all_backup_records_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .return_all_fingerprints_params(&return_all_backup_records_params_arc)
            .return_all_fingerprints_result(vec![]);
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.scan_for_pending_payable(None);

        let return_all_backup_records_params = return_all_backup_records_params_arc.lock().unwrap();
        assert_eq!(*return_all_backup_records_params, vec![()]);
        TestLogHandler::new()
            .exists_log_containing("DEBUG: Accountant: No pending payable found during last scan");
    }

    #[test]
    fn scan_for_pending_payable_found_unresolved_pending_payable_and_urges_their_processing() {
        init_test_logging();
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let payable_fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(555),
            timestamp: from_time_t(210_000_000),
            hash: make_tx_hash(45678),
            attempt_opt: Some(0),
            amount: 4444,
            process_error: None,
        };
        let payable_fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(550),
            timestamp: from_time_t(210_000_100),
            hash: make_tx_hash(112233),
            attempt_opt: Some(0),
            amount: 7999,
            process_error: None,
        };
        let pending_payable_dao =
            PendingPayableDaoMock::default().return_all_fingerprints_result(vec![
                payable_fingerprint_1.clone(),
                payable_fingerprint_2.clone(),
            ]);
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            make_wallet("mine"),
        );
        let system = System::new("pending payable scan");
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .bootstrapper_config(config)
            .build();
        let blockchain_bridge_addr = blockchain_bridge.start();
        subject.tools.request_transaction_receipts_subs_opt =
            Some(blockchain_bridge_addr.recipient());
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
        let mut bootstrapper_config = BootstrapperConfig::default();
        bootstrapper_config.accountant_config_opt = Some(make_accountant_config_null());
        bootstrapper_config.earning_wallet = make_wallet("hi");
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bootstrapper_config)
            .payable_dao(payable_dao_mock)
            .receivable_dao(receivable_dao_mock)
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
        let config = bc_from_ac_plus_wallets(
            make_populated_accountant_config_with_defaults(),
            consuming_wallet.clone(),
            make_wallet("our earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_dao(receivable_dao_mock)
            .payable_dao(payable_dao_mock)
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
            "INFO: Accountant: Not recording service provided for our wallet {}",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("our earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            earning_wallet.clone(),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .receivable_dao(receivable_dao_mock)
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
            "INFO: Accountant: Not recording service provided for our wallet {}",
            earning_wallet,
        ));
    }

    #[test]
    fn report_routing_service_consumed_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            make_wallet("hi"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let earning_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                timestamp: now,
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (now, make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            &format!("DEBUG: Accountant: Accruing debt to wallet {} for consuming routing service 1234 bytes", earning_wallet),
        );
    }

    #[test]
    fn report_routing_service_consumed_message_is_received_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("the consuming wallet");
        let config = bc_from_ac_plus_wallets(
            make_populated_accountant_config_with_defaults(),
            consuming_wallet.clone(),
            make_wallet("the earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                timestamp: SystemTime::now(),
                earning_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            consuming_wallet,
        ));
    }

    #[test]
    fn report_routing_service_consumed_message_is_received_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("the earning wallet");
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            earning_wallet.clone(),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                timestamp: SystemTime::now(),
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            earning_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_dao(receivable_dao_mock)
            .payable_dao(payable_dao_mock)
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
        let config = bc_from_ac_plus_wallets(
            make_accountant_config_null(),
            consuming_wallet.clone(),
            make_wallet("my earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .receivable_dao(receivable_dao_mock)
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
            "INFO: Accountant: Not recording service provided for our wallet {}",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_provided_message_is_received_from_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("my earning wallet");
        let config =
            bc_from_ac_plus_earning_wallet(make_accountant_config_null(), earning_wallet.clone());
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .receivable_dao(receivable_dao_mock)
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
            "INFO: Accountant: Not recording service provided for our wallet {}",
            earning_wallet,
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received() {
        init_test_logging();
        let now = SystemTime::now();
        let config =
            bc_from_ac_plus_earning_wallet(make_accountant_config_null(), make_wallet("hi"));
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        let earning_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                timestamp: now,
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (now, make_wallet("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Accountant: Accruing debt to wallet {} for consuming exit service 1234 bytes",
            earning_wallet
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received_for_our_consuming_wallet() {
        init_test_logging();
        let consuming_wallet = make_wallet("own consuming wallet");
        let config = bc_from_ac_plus_wallets(
            make_accountant_config_null(),
            consuming_wallet.clone(),
            make_wallet("own earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                timestamp: SystemTime::now(),
                earning_wallet: consuming_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
            consuming_wallet
        ));
    }

    #[test]
    fn report_exit_service_consumed_message_is_received_for_our_earning_wallet() {
        init_test_logging();
        let earning_wallet = make_wallet("own earning wallet");
        let config =
            bc_from_ac_plus_earning_wallet(make_accountant_config_null(), earning_wallet.clone());
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
            .build();
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                timestamp: SystemTime::now(),
                earning_wallet: earning_wallet.clone(),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        assert!(more_money_payable_parameters_arc.lock().unwrap().is_empty());

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: Accountant: Not recording service consumed to our wallet {}",
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
            .build();
        let service_rate = i64::MAX as u64;

        subject.record_service_consumed(service_rate, 1, SystemTime::now(), 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error recording consumed services from {}: total charge {}, service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            i64::MAX as u64 +1*2,
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
            .build();

        let _ = subject.record_service_consumed(i64::MAX as u64, 1, SystemTime::now(), 2, &wallet);
    }

    fn common_body_for_failing_to_mark_rowids_tests(
        test_name: &str,
        pending_payable_dao: PendingPayableDaoMock,
        hash_1: H256,
        hash_2: H256,
    ) {
        let payable_1 = PendingPayable::new(make_wallet("blah111"), hash_1);
        let payable_2 = PendingPayable::new(make_wallet("blah222"), hash_2);
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_result(Err(PayableDaoError::SignConversion(9999999999999)));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        subject.logger = Logger::new(test_name);

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.mark_pending_payable(vec![&payable_1, &payable_2])
        }))
        .unwrap_err();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(panic_msg, "Was unable to create a mark in payables due to SignConversion(9999999999999) for new pending payables \
         0x00000000000000000000000000626c6168313131, 0x00000000000000000000000000626c6168323232");
    }

    #[test]
    fn handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_nonexistent_fingerprints_to_report_about(
    ) {
        init_test_logging();
        let hash_1 = make_tx_hash(248);
        let hash_2 = make_tx_hash(139);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(7879), hash_1), (Some(7881), hash_2)]);
        common_body_for_failing_to_mark_rowids_tests("handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_wrongs_from_fetching_rowids_to_report_about",pending_payable_dao, hash_1, hash_2);
        TestLogHandler::new().exists_no_log_matching("ERROR: handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_wrongs_from_fetching_rowids_to_report_about: Payable fingerprints for (\
         .*) not found but should exist by now; system unreliable");
    }

    #[test]
    fn handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_nonexistent_fingerprints(
    ) {
        init_test_logging();
        let hash_1 = make_tx_hash(248);
        let hash_2 = make_tx_hash(139);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(None, hash_1), (Some(7881), hash_2)]);
        common_body_for_failing_to_mark_rowids_tests("handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_wrongs_from_fetching_rowids",pending_payable_dao, hash_1, hash_2);
        TestLogHandler::new().exists_log_containing("ERROR: handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_wrongs_from_fetching_rowids: Payable fingerprints for \
         (tx: 0x00000000000000000000000000000000000000000000000000000000000000f8, to wallet: 0x00000000000000000000000000626c6168313131) not found but should exist by now; system unreliable");
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: payable fingerprint deletion for transactions 0x000000000000000000000000000000000000000000000000000000000000007b, \
        0x0000000000000000000000000000000000000000000000000000000000000315 has stayed undone due to RecordDeletion(\"we slept over without an alarm set\")"
    )]
    fn handle_sent_payable_dealing_with_failed_payment_fails_to_delete_the_existing_pending_payable_fingerprint_and_panics(
    ) {
        let rowid_1 = 4;
        let hash_1 = make_tx_hash(123);
        let rowid_2 = 6;
        let hash_2 = make_tx_hash(789);
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Err(BlockchainError::PayableTransactionFailed {
                msg: "blah".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_1, hash_2]),
            }),
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(rowid_1), hash_1), (Some(rowid_2), hash_2)])
            .delete_fingerprints_result(Err(PendingPayableDaoError::RecordDeletion(
                "we slept over without an alarm set".to_string(),
            )));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.handle_sent_payable(sent_payable);
    }

    #[test]
    fn handle_sent_payable_process_two_correct_payments_and_one_incorrect_rpc_call() {
        //the two failures differ in the logged messages
        init_test_logging();
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let now_system = SystemTime::now();
        let payable_hash_1 = make_tx_hash(111);
        let payable_rowid_1 = 125;
        let wallet_1 = make_wallet("tralala");
        let pending_payable_1 = PendingPayable::new(wallet_1.clone(), payable_hash_1);
        let error_payable_hash_2 = make_tx_hash(222);
        let error_payable_rowid_2 = 126;
        let error_wallet_2 = make_wallet("hohoho");
        let error_payable_2 = RpcPayableFailure {
            rpc_error: Error::InvalidResponse(
                "Learn how to write before you send your garbage!".to_string(),
            ),
            recipient_wallet: error_wallet_2,
            hash: error_payable_hash_2,
        };
        let payable_hash_3 = make_tx_hash(333);
        let payable_rowid_3 = 127;
        let wallet_3 = make_wallet("booga");
        let pending_payable_3 = PendingPayable::new(wallet_3.clone(), payable_hash_3);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(vec![
                (Some(payable_rowid_1), payable_hash_1),
                (Some(payable_rowid_3), payable_hash_3),
            ])
            .fingerprints_rowids_result(vec![(Some(error_payable_rowid_2), error_payable_hash_2)])
            .delete_fingerprint_params(&delete_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()));
        let subject = AccountantBuilder::default()
            .payable_dao(
                PayableDaoMock::new()
                    .mark_pending_payable_rowid_params(&mark_pending_payables_params_arc)
                    .mark_pending_payable_rowid_result(Ok(()))
                    .mark_pending_payable_rowid_result(Ok(())),
            )
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayable {
            timestamp: now_system,
            payable_outcomes: Ok(vec![
                Correct(pending_payable_1),
                Failure(error_payable_2),
                Correct(pending_payable_3),
            ]),
            response_skeleton_opt: None,
        };

        subject.handle_sent_payable(sent_payable);

        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(
            *fingerprints_rowids_params,
            vec![
                vec![payable_hash_1, payable_hash_3],
                vec![error_payable_hash_2]
            ]
        );
        let mark_pending_payables_params = mark_pending_payables_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payables_params,
            vec![vec![
                (wallet_1, payable_rowid_1),
                (wallet_3, payable_rowid_3)
            ]]
        );
        let delete_fingerprint_params = delete_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *delete_fingerprint_params,
            vec![vec![error_payable_rowid_2]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Remote transaction failure: \
         Got invalid response: Learn how to write before you send your garbage!, for payment to 0x0000000000000000000000000000686f686f686f \
          and transaction hash 0x00000000000000000000000000000000000000000000000000000000000000de. \
           Please check your blockchain service URL configuration");
        log_handler.exists_log_containing("DEBUG: Accountant: Payables 0x000000000000000000000000000000000000000000000000000000000000006f, \
         0x000000000000000000000000000000000000000000000000000000000000014d have been marked as pending in the payable table");
        log_handler.exists_log_containing("DEBUG: Accountant: Deleting existing fingerprints for failed transactions 0x00000000000000000000000000000000000000000000000000000000000000de");
    }

    #[test]
    #[should_panic(
        expected = "Payable fingerprints for (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, to wallet: 0x000000000000000000000000000000626f6f6761), \
         (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, to wallet: 0x00000000000000000000000000000061676f6f62) not found but should exist by now; system unreliable"
    )]
    fn handle_sent_payable_receives_proper_payment_but_fingerprint_not_found_so_it_panics() {
        init_test_logging();
        let hash_1 = make_tx_hash(789);
        let payment_1 = PendingPayable::new(make_wallet("booga"), hash_1);
        let hash_2 = make_tx_hash(789);
        let payment_2 = PendingPayable::new(make_wallet("agoob"), hash_2);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(None, hash_1), (None, hash_2)]);
        let subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(())))
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.mark_pending_payable(vec![&payment_1, &payment_2]);
    }

    #[test]
    fn confirm_transactions_works() {
        init_test_logging();
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transaction_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .delete_fingerprint_params(&delete_pending_payable_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid_1 = 2;
        let pending_payable_fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(rowid_1),
            timestamp: from_time_t(199_000_000),
            hash: H256::from("some_hash".keccak256()),
            attempt_opt: Some(1),
            amount: 4567,
            process_error: None,
        };
        let rowid_2 = 5;
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(rowid_2),
            timestamp: from_time_t(200_000_000),
            hash: H256::from("different_hash".keccak256()),
            attempt_opt: Some(1),
            amount: 5555,
            process_error: None,
        };

        subject.confirm_transactions(vec![
            pending_payable_fingerprint_1.clone(),
            pending_payable_fingerprint_2.clone(),
        ]);

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![vec![
                pending_payable_fingerprint_1,
                pending_payable_fingerprint_2
            ]]
        );
        let delete_pending_payable_fingerprint_params =
            delete_pending_payable_fingerprint_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *delete_pending_payable_fingerprint_params,
            vec![vec![rowid_1, rowid_2]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Confirmation of transactions 0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
         0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7; record for total paid payable was modified");
        log_handler.exists_log_containing("INFO: Accountant: Transactions 0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
         0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7 went through the whole confirmation process succeeding");
    }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payables 0x0000000000000000000000000000000000000000000000000000000000000315 \
         during their confirmation due to RusqliteError(\"record change not successful\")"
    )]
    fn confirm_transactions_panics_on_unchecking_payable_table() {
        init_test_logging();
        let hash = make_tx_hash(789);
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .build();
        let mut payment = make_pending_payable_fingerprint();
        payment.rowid_opt = Some(rowid);
        payment.hash = hash;

        subject.confirm_transactions(vec![payment]);
    }

    #[test]
    #[should_panic(
        expected = "Was unable to delete payable fingerprints 0x0000000000000000000000000000000000000000000000000000000000000315 \
         for successful transactions due to RecordDeletion(\"the database likes fooling around with us\")"
    )]
    fn confirm_transactions_panics_on_deleting_pending_payable_fingerprint() {
        init_test_logging();
        let hash = make_tx_hash(789);
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().delete_fingerprints_result(Err(
            PendingPayableDaoError::RecordDeletion(
                "the database likes fooling around with us".to_string(),
            ),
        ));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.hash = hash;

        subject.confirm_transactions(vec![pending_payable_fingerprint]);
    }

    #[test]
    fn cancel_transactions_does_nothing_if_no_tx_failures_detected() {
        let subject = AccountantBuilder::default().build();

        subject.cancel_transactions(vec![])

        //pending payable DAO didn't cause a panic which means we skipped the actual process
    }

    #[test]
    fn cancel_transactions_works() {
        init_test_logging();
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failures_params(&mark_failure_params_arc)
            .mark_failures_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let id_1 = PendingPayableId {
            hash: H256::from("sometransactionhash".keccak256()),
            rowid: 2,
        };
        let id_2 = PendingPayableId {
            hash: H256::from("anothertransactionhash".keccak256()),
            rowid: 3,
        };

        let _ = subject.cancel_transactions(vec![id_1, id_2]);

        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![vec![2, 3]]);
        TestLogHandler::new().exists_log_containing(
            "WARN: Accountant: Broken transactions 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19, \
             0x06c979a34cca4fb22247b14a7b60bef387a550c255a8d708f81f19dd4c4a1c51 marked as an error. You should take over \
             the care of those to make sure your debts are going to be settled properly. At the moment, there is no automated \
              process fixing that without your assistance",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transactions 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 \
         to mark fatal error at payable fingerprint due to UpdateFailed(\"I'm gonna tell you last time. No!\")"
    )]
    fn handle_cancel_pending_transaction_panics_on_its_inability_to_mark_failure() {
        let payable_dao = PayableDaoMock::default().transaction_canceled_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failures_result(Err(
            PendingPayableDaoError::UpdateFailed("I'm gonna tell you last time. No!".to_string()),
        ));
        let subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());
        let id = PendingPayableId { rowid, hash };

        subject.cancel_transactions(vec![id]);
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn accountant_can_be_crashed_properly_but_not_improperly() {
        let mut config = BootstrapperConfig::default();
        config.crash_point = CrashPoint::Message;
        config.accountant_config_opt = Some(make_accountant_config_null());
        let accountant = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();

        prove_that_crash_request_handler_is_hooked_up(accountant, CRASH_KEY);
    }

    #[test]
    fn investigate_debt_extremes_picks_the_most_relevant_records() {
        let now = to_time_t(SystemTime::now());
        let same_amount_significance = 2_000_000;
        let same_age_significance = from_time_t(now - 30000);
        let payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 10000),
                pending_payable_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance: 100,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: 330,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
        ];

        let result = Accountant::investigate_debt_extremes(payables);

        assert_eq!(result,"Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        let now = to_time_t(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1000,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1234,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1,
                ),
                pending_payable_opt: None,
            },
        ];
        let mut config = BootstrapperConfig::default();
        config.accountant_config_opt = Some(make_populated_accountant_config_with_defaults());
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        subject.config.payment_thresholds = payment_thresholds;

        let result = subject.payables_debug_summary(qualified_payables);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
    }

    #[test]
    fn threshold_calculation_depends_on_user_defined_payment_thresholds() {
        let safe_age_params_arc = Arc::new(Mutex::new(vec![]));
        let safe_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let calculate_payable_threshold_params_arc = Arc::new(Mutex::new(vec![]));
        let balance = 5555;
        let how_far_in_past = Duration::from_secs(1111 + 1);
        let last_paid_timestamp = SystemTime::now().sub(how_far_in_past);
        let payable_account = PayableAccount {
            wallet: make_wallet("hi"),
            balance,
            last_paid_timestamp,
            pending_payable_opt: None,
        };
        let custom_payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1111,
            payment_grace_period_sec: 2222,
            permanent_debt_allowed_gwei: 3333,
            debt_threshold_gwei: 4444,
            threshold_interval_sec: 5555,
            unban_below_gwei: 3333,
        };
        let mut bootstrapper_config = BootstrapperConfig::default();
        bootstrapper_config.accountant_config_opt = Some(AccountantConfig {
            scan_intervals: Default::default(),
            payment_thresholds: custom_payment_thresholds,
            suppress_initial_scans: false,
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
        });
        let payable_thresholds_tools = PayableThresholdToolsMock::default()
            .is_innocent_age_params(&safe_age_params_arc)
            .is_innocent_age_result(
                how_far_in_past.as_secs()
                    <= custom_payment_thresholds.maturity_threshold_sec as u64,
            )
            .is_innocent_balance_params(&safe_balance_params_arc)
            .is_innocent_balance_result(
                balance <= custom_payment_thresholds.permanent_debt_allowed_gwei,
            )
            .calculate_payout_threshold_params(&calculate_payable_threshold_params_arc)
            .calculate_payout_threshold_result(4567.0); //made up value
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bootstrapper_config)
            .build();
        subject.payable_threshold_tools = Box::new(payable_thresholds_tools);

        let result = subject.payable_exceeded_threshold(&payable_account);

        assert_eq!(result, Some(4567));
        let mut safe_age_params = safe_age_params_arc.lock().unwrap();
        let safe_age_single_params = safe_age_params.remove(0);
        assert_eq!(*safe_age_params, vec![]);
        let (time_elapsed, curve_derived_time) = safe_age_single_params;
        assert!(
            (how_far_in_past.as_secs() - 3) < time_elapsed
                && time_elapsed < (how_far_in_past.as_secs() + 3)
        );
        assert_eq!(
            curve_derived_time,
            custom_payment_thresholds.maturity_threshold_sec as u64
        );
        let safe_balance_params = safe_balance_params_arc.lock().unwrap();
        assert_eq!(
            *safe_balance_params,
            vec![(
                payable_account.balance,
                custom_payment_thresholds.permanent_debt_allowed_gwei
            )]
        );
        let mut calculate_payable_curves_params =
            calculate_payable_threshold_params_arc.lock().unwrap();
        let calculate_payable_curves_single_params = calculate_payable_curves_params.remove(0);
        assert_eq!(*calculate_payable_curves_params, vec![]);
        let (payment_thresholds, time_elapsed) = calculate_payable_curves_single_params;
        assert!(
            (how_far_in_past.as_secs() - 3) < time_elapsed
                && time_elapsed < (how_far_in_past.as_secs() + 3)
        );
        assert_eq!(payment_thresholds, custom_payment_thresholds)
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
        let pending_tx_hash_1 = make_tx_hash(123);
        let pending_tx_hash_2 = make_tx_hash(567);
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
        let wallet_account_1 = make_wallet("creditor1");
        let wallet_account_2 = make_wallet("creditor2");
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
            .send_payables_within_batch_result(Ok(vec![
                Correct(PendingPayable {
                    recipient_wallet: wallet_account_1.clone(),
                    hash: pending_tx_hash_1,
                }),
                Correct(PendingPayable {
                    recipient_wallet: wallet_account_2.clone(),
                    hash: pending_tx_hash_2,
                }),
            ]))
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
        let account_1 = PayableAccount {
            wallet: wallet_account_1.clone(),
            balance: payable_account_balance_1,
            last_paid_timestamp: past_payable_timestamp_1,
            pending_payable_opt: None,
        };
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: payable_account_balance_2,
            last_paid_timestamp: past_payable_timestamp_2,
            pending_payable_opt: None,
        };
        let pending_payable_scan_interval = 200; //should be slightly less than 1/5 of the time until shutting the system
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![account_1, account_2])
            .mark_pending_payable_rowid_params(&mark_pending_payable_params_arc)
            .mark_pending_payable_rowid_result(Ok(()))
            .mark_pending_payable_rowid_result(Ok(()))
            .transactions_confirmed_params(&transaction_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                scan_intervals: ScanIntervals {
                    payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                    receivable_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                    pending_payable_scan_interval: Duration::from_millis(
                        pending_payable_scan_interval,
                    ),
                },
                payment_thresholds: *DEFAULT_PAYMENT_THRESHOLDS,
                suppress_initial_scans: false,
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("some_wallet_address"),
        );
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
        let mut pending_payable_dao = PendingPayableDaoMock::default()
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
            .insert_fingerprints_params(&insert_fingerprint_params_arc)
            .insert_fingerprints_result(Ok(()))
            .insert_fingerprints_result(Ok(()))
            .fingerprints_rowids_result(vec![
                (Some(rowid_for_account_1), pending_tx_hash_1),
                (Some(rowid_for_account_2), pending_tx_hash_2),
            ])
            .update_fingerprints_params(&update_fingerprint_params_arc)
            .update_fingerprints_results(Ok(()))
            .update_fingerprints_results(Ok(()))
            .update_fingerprints_results(Ok(()))
            .update_fingerprints_results(Ok(()))
            .update_fingerprints_results(Ok(()))
            .mark_failures_params(&mark_failure_params_arc)
            //we don't have a better solution yet, so we mark this down
            .mark_failures_result(Ok(()))
            .mark_failures_result(Ok(()))
            .delete_fingerprint_params(&delete_record_params_arc)
            //this is used during confirmation of the successful one
            .delete_fingerprints_result(Ok(()));
        pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let mut subject = AccountantBuilder::default()
                    .bootstrapper_config(bootstrapper_config)
                    .payable_dao(payable_dao)
                    .pending_payable_dao(pending_payable_dao)
                    .build();
                subject.scanners.receivables = Box::new(NullScanner);
                let notify_later_half_mock = NotifyLaterHandleMock::default()
                    .notify_later_params(&notify_later_scan_for_pending_payable_arc_cloned)
                    .permit_to_send_out();
                subject.tools.notify_later_scan_for_pending_payable =
                    Box::new(notify_later_half_mock);
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
        let mut onse_set_of_mark_pending_payable_params = mark_pending_payable_params.remove(0);
        assert!(mark_pending_payable_params.is_empty());
        let first_payable = onse_set_of_mark_pending_payable_params.remove(0);
        assert_eq!(first_payable.0, wallet_account_1);
        assert_eq!(first_payable.1, rowid_for_account_1);
        let second_payable = onse_set_of_mark_pending_payable_params.remove(0);
        assert!(
            onse_set_of_mark_pending_payable_params.is_empty(),
            "{:?}",
            onse_set_of_mark_pending_payable_params
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
                pending_tx_hash_2
            ]
        );
        let update_fingerprints_params = update_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *update_fingerprints_params,
            vec![
                vec![rowid_for_account_1, rowid_for_account_2],
                vec![rowid_for_account_1, rowid_for_account_2],
                vec![rowid_for_account_2]
            ]
        );
        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![vec![rowid_for_account_1]]);
        let delete_record_params = delete_record_params_arc.lock().unwrap();
        assert_eq!(*delete_record_params, vec![vec![rowid_for_account_2]]);
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![vec![fingerprint_2_fourth_round.clone()]]
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
            "WARN: Accountant: Broken transactions 0x000000000000000000000000000000000000000000000000000000000000007b marked as an error. \
             You should take over the care of those to make sure your debts are going to be settled properly. At the moment, there is no automated process fixing that without your assistance");
        log_handler.exists_log_matching("INFO: Accountant: Transaction 0x0000000000000000000000000000000000000000000000000000000000000237 has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
        log_handler.exists_log_containing("INFO: Accountant: Transactions 0x0000000000000000000000000000000000000000000000000000000000000237 went through the whole confirmation process succeeding");
    }

    #[test]
    fn handle_pending_tx_handles_none_returned_for_transaction_receipt() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let tx_receipt_opt = None;
        let rowid = 455;
        let hash = make_tx_hash(2323);
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: SystemTime::now().sub(Duration::from_millis(10000)),
            hash,
            attempt_opt: Some(3),
            amount: 111,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(tx_receipt_opt, fingerprint.clone())],
            response_skeleton_opt: None,
        };

        let result = subject.handle_pending_transaction_with_its_receipt(&msg);

        assert_eq!(
            result,
            PendingPayableScanSummary {
                still_pending: vec![PendingPayableId { hash, rowid }],
                failures: vec![],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_matching(
            "DEBUG: Accountant: Interpreting a receipt for transaction \
            0x0000000000000000000000000000000000000000000000000000000000000913 \
            but none was given; attempt 3, 100\\d\\dms since sending",
        );
    }

    #[test]
    fn accountant_receives_reported_transaction_receipts_and_processes_them_all() {
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let subject_addr = subject.start();
        let transaction_hash_1 = make_tx_hash(4545);
        let mut transaction_receipt_1 = TransactionReceipt::default();
        transaction_receipt_1.transaction_hash = transaction_hash_1;
        transaction_receipt_1.status = Some(U64::from(1)); //success
        let fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(5),
            timestamp: from_time_t(200_000_000),
            hash: transaction_hash_1,
            attempt_opt: Some(2),
            amount: 444,
            process_error: None,
        };
        let transaction_hash_2 = make_tx_hash(3333333);
        let mut transaction_receipt_2 = TransactionReceipt::default();
        transaction_receipt_2.transaction_hash = transaction_hash_2;
        transaction_receipt_2.status = Some(U64::from(1)); //success
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(10),
            timestamp: from_time_t(199_780_000),
            hash: Default::default(),
            attempt_opt: Some(15),
            amount: 1212,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![
                (Some(transaction_receipt_1), fingerprint_1.clone()),
                (Some(transaction_receipt_2), fingerprint_2.clone()),
            ],
            response_skeleton_opt: None,
        };

        subject_addr.try_send(msg).unwrap();

        let system = System::new("processing reported receipts");
        System::current().stop();
        system.run();
        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transactions_confirmed_params,
            vec![vec![fingerprint_1, fingerprint_2]]
        );
    }

    #[test]
    fn confirm_transactions_does_nothing_if_none_found_on_the_blockchain() {
        let mut subject = AccountantBuilder::default().build();

        subject.confirm_transactions(vec![])

        //payable DAO didn't cause a panic which means we skipped the actual process
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = make_tx_hash(4567);
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(777777),
            timestamp: SystemTime::now().sub(Duration::from_millis(150000)),
            hash,
            attempt_opt: Some(5),
            amount: 2222,
            process_error: None,
        };
        let mut scan_summary = PendingPayableScanSummary::default();

        subject.interpret_transaction_receipt(
            &mut scan_summary,
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            scan_summary,
            PendingPayableScanSummary {
                still_pending: vec![],
                failures: vec![PendingPayableId {
                    hash,
                    rowid: 777777
                }],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_matching("ERROR: receipt_check_logger: Pending \
         transaction 0x00000000000000000000000000000000000000000000000000000000000011d7 announced as a failure, interpreting attempt 5 after 1500\\d\\dms from the sending");
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let hash = make_tx_hash(567);
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent = SystemTime::now().sub(Duration::from_millis(100));
        let subject = AccountantBuilder::default().build();
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: when_sent,
            hash,
            attempt_opt: Some(1),
            amount: 123,
            process_error: None,
        };
        let mut scan_summary = PendingPayableScanSummary::default();

        subject.interpret_transaction_receipt(
            &mut scan_summary,
            &tx_receipt,
            &fingerprint,
            &Logger::new("none_within_waiting"),
        );

        assert_eq!(
            scan_summary,
            PendingPayableScanSummary {
                still_pending: vec![PendingPayableId { hash, rowid }],
                failures: vec![],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: none_within_waiting: Pending \
         transaction 0x0000000000000000000000000000000000000000000000000000000000000237 \
          couldn't be confirmed at attempt 1 at ",
        );
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let hash = make_tx_hash(567);
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent =
            SystemTime::now().sub(Duration::from_secs(DEFAULT_PENDING_TOO_LONG_SEC + 5)); //old transaction
        let subject = AccountantBuilder::default().build();
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: when_sent,
            hash,
            attempt_opt: Some(10),
            amount: 123,
            process_error: None,
        };
        let mut scan_summary = PendingPayableScanSummary::default();

        subject.interpret_transaction_receipt(
            &mut scan_summary,
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            scan_summary,
            PendingPayableScanSummary {
                still_pending: vec![],
                failures: vec![PendingPayableId { hash, rowid }],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: receipt_check_logger: Pending transaction 0x0000000000000000000000000000000000000000000000000000000000000237 has exceeded the maximum \
             pending time (21600sec) and the confirmation process is going to be aborted now at the final attempt 10; manual resolution is required from the user to \
               complete the transaction",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending 0x000000000000000000000000000000000000000000000000000000000000007b - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = make_tx_hash(123);
        let subject = AccountantBuilder::default().build();
        let mut scan_summary = PendingPayableScanSummary::default();

        let _ = subject.interpret_transaction_receipt(
            &mut scan_summary,
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn accountant_handles_to_insert_new_fingerprints() {
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao = PendingPayableDaoMock::default()
            .insert_fingerprints_params(&insert_fingerprint_params_arc)
            .insert_fingerprints_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payment_dao)
            .build();
        let accountant_addr = subject.start();
        let tx_hash = make_tx_hash(55);
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let amount = 4055;
        let timestamp = SystemTime::now();
        let hash_1 = make_tx_hash(444444);
        let amount_1 = 12345;
        let hash_2 = make_tx_hash(111111);
        let amount_2 = 87654;
        let init_params = vec![(hash_1, amount_1), (hash_2, amount_2)];
        let init_fingerprints_msg = ReportNewPendingPayableFingerprints {
            batch_wide_timestamp: timestamp,
            init_params: init_params.clone(),
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
            vec![(vec![(hash_1, amount_1), (hash_2, amount_2)], timestamp)]
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Saved new pending payable fingerprints for: \
             0x000000000000000000000000000000000000000000000000000000000006c81c, 0x000000000000000000000000000000000000000000000000000000000001b207",
        );
    }

    #[test]
    fn payable_fingerprint_insertion_clearly_failed_and_we_log_it_at_least() {
        //despite it doesn't happen here this event would cause a panic later
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .insert_fingerprints_params(&insert_fingerprint_params_arc)
            .insert_fingerprints_result(Err(PendingPayableDaoError::InsertionFailed(
                "Crashed".to_string(),
            )));
        let amount = 2345;
        let transaction_hash = make_tx_hash(456);
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let timestamp = SystemTime::now();
        let report_new_fingerprints = ReportNewPendingPayableFingerprints {
            batch_wide_timestamp: timestamp,
            init_params: vec![(transaction_hash, amount)],
        };

        let _ = subject.handle_new_pending_payable_fingerprints(report_new_fingerprints);

        let insert_fingerprint_params = insert_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *insert_fingerprint_params,
            vec![(vec![(transaction_hash, amount)], timestamp)]
        );
        TestLogHandler::new().exists_log_containing("ERROR: Accountant: Failed to process \
         new pending payable fingerprints due to 'InsertionFailed(\"Crashed\")', disabling the automated \
          confirmation for all these transactions: 0x00000000000000000000000000000000000000000000000000000000000001c8");
    }

    #[test]
    fn separate_errors_works_for_no_errs_just_oks() {
        let correct_payment = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Ok(vec![Correct(correct_payment.clone())]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = Accountant::separate_errors(&sent_payable, &Logger::new("test"));

        assert_eq!(oks, vec![&correct_payment]);
        assert_eq!(errs, None)
    }

    #[test]
    fn separate_errors_works_for_our_errors() {
        init_test_logging();
        let error = PayableTransactionFailed {
            msg: "bad timing".to_string(),
            signed_and_saved_txs_opt: None,
        };
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Err(error.clone()),
            response_skeleton_opt: None,
        };

        let (oks, errs) = Accountant::separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert!(oks.is_empty());
        assert_eq!(errs, Some(LocalError(error)));
        TestLogHandler::new().exists_log_containing("WARN: test_logger: Encountered transaction error at our end: \
         Blockchain error: Processing batch requests: bad timing. With no transactions in the state of readiness, none hashed");
    }

    #[test]
    fn separate_errors_works_for_their_errors() {
        init_test_logging();
        let payable_ok = PendingPayable {
            recipient_wallet: make_wallet("blah"),
            hash: make_tx_hash(123),
        };
        let bad_rpc_call = RpcPayableFailure {
            rpc_error: web3::Error::InvalidResponse("that donkey screwed it up".to_string()),
            recipient_wallet: make_wallet("whooa"),
            hash: make_tx_hash(789),
        };
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable_outcomes: Ok(vec![
                Correct(payable_ok.clone()),
                Failure(bad_rpc_call.clone()),
            ]),
            response_skeleton_opt: None,
        };

        let (oks, errs) = Accountant::separate_errors(&sent_payable, &Logger::new("test_logger"));

        assert_eq!(oks, vec![&payable_ok]);
        assert_eq!(errs, Some(RemoteErrors(vec![make_tx_hash(789)])));
        TestLogHandler::new().exists_log_containing("WARN: test_logger: Remote transaction failure: Got invalid response: \
         that donkey screwed it up, for payment to 0x00000000000000000000000000000077686f6f61 and transaction hash \
          0x0000000000000000000000000000000000000000000000000000000000000315. Please check your blockchain service URL configuration.");
    }

    #[test]
    fn count_total_errors_says_unidentifiable_for_very_early_local_error() {
        let sent_payable = Some(LocalError(BlockchainError::InvalidUrl));

        let result = Accountant::count_total_errors(sent_payable.as_ref());

        assert_eq!(result, None)
    }

    #[test]
    fn count_total_errors_says_unidentifiable_for_local_error_before_signing() {
        let error = PayableTransactionFailed {
            msg: "Ouuuups".to_string(),
            signed_and_saved_txs_opt: None,
        };
        let sent_payable = Some(LocalError(error));

        let result = Accountant::count_total_errors(sent_payable.as_ref());

        assert_eq!(result, None)
    }

    #[test]
    fn count_total_errors_works_correctly_for_local_error_after_signing() {
        let error = PayableTransactionFailed {
            msg: "Ouuuups".to_string(),
            signed_and_saved_txs_opt: Some(vec![make_tx_hash(333), make_tx_hash(666)]),
        };
        let sent_payable = Some(LocalError(error));

        let result = Accountant::count_total_errors(sent_payable.as_ref());

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_for_remote_errors() {
        let sent_payable = Some(RemoteErrors(vec![make_tx_hash(123), make_tx_hash(456)]));

        let result = Accountant::count_total_errors(sent_payable.as_ref());

        assert_eq!(result, Some(2))
    }

    #[test]
    fn count_total_errors_works_correctly_if_no_errors_found_at_all() {
        let sent_payable = None;

        let result = Accountant::count_total_errors(sent_payable.as_ref());

        assert_eq!(result, Some(0))
    }

    #[test]
    fn debug_summary_after_error_separation_says_the_count_is_unidentifiable() {
        let oks = vec![];
        let error = BlockchainError::InvalidAddress;
        let errs = Some(LocalError(error));

        let result = Accountant::debugging_summary_after_error_separation(&oks, errs.as_ref());

        assert_eq!(
            result,
            "Received 0 properly sent payables of undetermined number of attempts"
        )
    }

    #[test]
    fn update_fingerprints_does_nothing_if_no_still_pending_transactions_remain() {
        let subject = AccountantBuilder::default().build();

        subject.update_fingerprints(vec![])

        //pending payable DAO didn't cause a panic which means we skipped the actual process
    }

    #[test]
    fn update_fingerprints_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(444888);
        let rowid_1 = 3456;
        let hash_2 = make_tx_hash(444888);
        let rowid_2 = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .update_fingerprints_params(&update_after_cycle_params_arc)
            .update_fingerprints_results(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id_1 = PendingPayableId {
            hash: hash_1,
            rowid: rowid_1,
        };
        let transaction_id_2 = PendingPayableId {
            hash: hash_2,
            rowid: rowid_2,
        };

        let _ = subject.update_fingerprints(vec![transaction_id_1, transaction_id_2]);

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![vec![rowid_1, rowid_2]])
    }

    #[test]
    #[should_panic(
        expected = "Failure on updating payable fingerprints 0x000000000000000000000000000000000000000000000000000000000006c9d8 \
         due to UpdateFailed(\"yeah, bad\")"
    )]
    fn update_fingerprints_sad_path() {
        let hash = make_tx_hash(444888);
        let rowid = 3456;
        let pending_payable_dao =
            PendingPayableDaoMock::default().update_fingerprints_results(Err(
                PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
            ));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id = PendingPayableId { hash, rowid };

        let _ = subject.update_fingerprints(vec![transaction_id]);
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
                    ))
                }
            }
        );
    }

    #[test]
    fn financials_request_produces_financials_response() {
        let payable_dao = PayableDaoMock::new().total_result(23456789);
        let receivable_dao = ReceivableDaoMock::new().total_result(98765432);
        let system = System::new("test");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
            .build();
        subject.financial_statistics.total_paid_payable = 123456;
        subject.financial_statistics.total_paid_receivable = 334455;
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
                total_paid_receivable: 334455
            }
        );
    }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(5),
            timestamp: from_time_t(189_999_888),
            hash: make_tx_hash(56789),
            attempt_opt: Some(1),
            amount: 5478,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(6),
            timestamp: from_time_t(200_000_011),
            hash: make_tx_hash(33333),
            attempt_opt: Some(1),
            amount: 6543,
            process_error: None,
        };
        let mut pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transaction_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()))
            .transactions_confirmed_result(Ok(()));
        pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .payable_dao(payable_dao)
            .build();
        subject.financial_statistics.total_paid_payable += 1111;

        subject.confirm_transactions(vec![fingerprint_1.clone(), fingerprint_2.clone()]);

        assert_eq!(
            subject.financial_statistics.total_paid_payable,
            1111 + 5478 + 6543
        );
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![vec![fingerprint_1, fingerprint_2]]
        )
    }

    #[test]
    fn total_paid_receivable_rises_with_each_bill_paid() {
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_parameters(&more_money_received_params_arc)
            .more_money_receivable_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .receivable_dao(receivable_dao)
            .build();
        subject.financial_statistics.total_paid_receivable += 2222;
        let receivables = vec![
            BlockchainTransaction {
                block_number: 4578910,
                from: make_wallet("wallet_1"),
                gwei_amount: 45780,
            },
            BlockchainTransaction {
                block_number: 4569898,
                from: make_wallet("wallet_2"),
                gwei_amount: 33345,
            },
        ];
        let now = SystemTime::now();

        subject.handle_received_payments(ReceivedPayments {
            timestamp: now,
            payments: receivables.clone(),
            response_skeleton_opt: None,
        });

        assert_eq!(
            subject.financial_statistics.total_paid_receivable,
            2222 + 45780 + 33345
        );
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
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
