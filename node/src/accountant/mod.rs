// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
pub mod big_int_db_processor;
pub mod dao_utils;
pub mod payable_dao;
pub mod pending_payable_dao;
pub mod receivable_dao;
pub mod related_to_financials;
pub mod tools;

#[cfg(test)]
pub mod test_utils;

use core::fmt::Debug;
use masq_lib::constants::{
    REQUEST_WITH_MUTUALLY_EXCLUSIVE_PARAMS, REQUEST_WITH_NO_VALUES, SCAN_ERROR,
};

use masq_lib::messages::{
    QueryResults, ScanType, UiFinancialStatistics, UiPayableAccount, UiReceivableAccount,
    UiScanRequest, UiScanResponse,
};
use masq_lib::ui_gateway::{MessageBody, MessagePath};

use crate::accountant::dao_utils::{
    remap_payable_accounts, remap_receivable_accounts, CustomQuery, DaoFactoryReal,
};
use crate::accountant::payable_dao::{Payable, PayableAccount, PayableDaoError, PayableDaoFactory};
use crate::accountant::pending_payable_dao::{PendingPayableDao, PendingPayableDaoFactory};
use crate::accountant::receivable_dao::{
    ReceivableAccount, ReceivableDaoError, ReceivableDaoFactory,
};
use crate::accountant::tools::accountant_tools::{Scanner, Scanners, TransactionConfirmationTools};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainTransaction};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::db_initializer::DbInitializationConfig;
use crate::sub_lib::accountant::WEIS_OF_GWEI;
use crate::sub_lib::accountant::{AccountantConfig, FinancialStatistics, PaymentThresholds};
use crate::sub_lib::accountant::{AccountantSubs, ReportServicesConsumedMessage};
use crate::sub_lib::accountant::{MessageIdGenerator, MessageIdGeneratorReal};
use crate::sub_lib::accountant::{
    ReportExitServiceProvidedMessage, ReportRoutingServiceProvidedMessage,
};
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
use std::any::type_name;
#[cfg(test)]
use std::any::Any;
use std::default::Default;
use std::fmt::Display;
use std::ops::{Div, Mul};
use std::path::Path;
use std::time::{Duration, SystemTime};
use thousands::Separable;
use web3::types::{TransactionReceipt, H256};
use crate::accountant::related_to_financials::visibility_restricted_module::{check_query_is_within_tech_limits, financials_entry_check};

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
    confirmation_tools: TransactionConfirmationTools,
    financial_statistics: FinancialStatistics,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayables>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
    payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
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
pub struct SentPayables {
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

impl Handler<SentPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: SentPayables, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_sent_payables(msg);
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

    fn handle(&mut self, msg: ReportTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        debug!(
            self.logger,
            "Processing receipts for {} transactions",
            msg.fingerprints_with_receipts.len()
        );
        let statuses = self.handle_pending_transaction_with_its_receipt(&msg);
        self.process_transactions_by_their_status(statuses, ctx);
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

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct CancelFailedPendingTransaction {
    pub id: PendingPayableId,
}

impl Handler<CancelFailedPendingTransaction> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: CancelFailedPendingTransaction,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_cancel_pending_transaction(msg)
    }
}

#[derive(Debug, PartialEq, Eq, Message, Clone)]
pub struct ConfirmPendingTransaction {
    pub pending_payable_fingerprint: PendingPayableFingerprint,
}

impl Handler<ConfirmPendingTransaction> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ConfirmPendingTransaction, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_confirm_pending_transaction(msg)
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
            financial_statistics: FinancialStatistics::default(),
            report_accounts_payable_sub: None,
            retrieve_transactions_sub: None,
            report_new_payments_sub: None,
            report_sent_payments_sub: None,
            ui_message_sub: None,
            confirmation_tools: TransactionConfirmationTools::default(),
            message_id_generator: Box::new(MessageIdGeneratorReal::default()),
            payable_threshold_gauge: Box::new(PayableThresholdsGaugeReal::default()),
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
            report_sent_payments: recipient!(addr, SentPayables),
            scan_errors: recipient!(addr, ScanError),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, DbInitializationConfig::panic_on_migration())
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
        self.payables_debug_summary(&qualified_payables);
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
            self.confirmation_tools
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
        let balance = format!("{}", account.balance_wei / WEIS_OF_GWEI);
        let age = account
            .last_received_timestamp
            .elapsed()
            .unwrap_or_else(|_| Duration::new(0, 0));
        (balance, age)
    }

    fn should_pay(&self, payable: &PayableAccount) -> bool {
        self.payable_exceeded_threshold(payable).is_some()
    }

    fn payable_exceeded_threshold(&self, payable: &PayableAccount) -> Option<u128> {
        let debt_age = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if self.payable_threshold_gauge.is_innocent_age(
            debt_age,
            self.config.payment_thresholds.maturity_threshold_sec as u64,
        ) {
            return None;
        }

        if self.payable_threshold_gauge.is_innocent_balance(
            payable.balance_wei,
            gwei_to_wei(self.config.payment_thresholds.permanent_debt_allowed_gwei),
        ) {
            return None;
        }

        let threshold = self
            .payable_threshold_gauge
            .calculate_payout_threshold_in_gwei(&self.config.payment_thresholds, debt_age);
        if payable.balance_wei > threshold {
            Some(threshold)
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
        let byte_charge = byte_rate as u128 * (payload_size as u128);
        let total_charge = service_rate as u128 + byte_charge;
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
        let byte_charge = byte_rate as u128 * (payload_size as u128);
        let total_charge = service_rate as u128 + byte_charge;
        if !self.our_wallet(wallet) {
            match self.payable_dao
                .as_ref()
                .more_money_payable(timestamp, wallet,total_charge){
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

    //for debugging only
    fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
        let now = SystemTime::now();
        if all_non_pending_payables.is_empty() {
            "Payable scan found no debts".to_string()
        } else {
            struct PayableInfo {
                balance: u128,
                age: Duration,
            }
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
                        || -> bool { p.balance_wei == biggest.balance && p_age > biggest.age };

                    if p.balance_wei > biggest.balance
                        || check_age_parameter_if_the_first_is_the_same()
                    {
                        biggest = PayableInfo {
                            balance: p.balance_wei,
                            age: p_age,
                        }
                    }

                    let check_balance_parameter_if_the_first_is_the_same =
                        || -> bool { p_age == oldest.age && p.balance_wei > oldest.balance };

                    if p_age > oldest.age || check_balance_parameter_if_the_first_is_the_same() {
                        oldest = PayableInfo {
                            balance: p.balance_wei,
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

    fn payables_debug_summary(&self, qualified_payables: &[PayableAccount]) {
        if qualified_payables.is_empty() {
            return;
        }
        debug!(self.logger, "Paying qualified debts:\n{}", {
            let now = SystemTime::now();
            qualified_payables
                .iter()
                .map(|payable| {
                    let p_age = now
                        .duration_since(payable.last_paid_timestamp)
                        .expect("Payable time is corrupt");
                    let threshold = self
                        .payable_exceeded_threshold(payable)
                        .expect("Threshold suddenly changed!");
                    format!(
                        "{} Wei owed for {} sec exceeds threshold: {} Wei; creditor: {}",
                        payable.balance_wei.separate_with_commas(),
                        p_age.as_secs(),
                        threshold.separate_with_commas(),
                        payable.wallet
                    )
                })
                .join("\n")
        })
    }

    fn handle_bind_message(&mut self, msg: BindMessage) {
        self.report_accounts_payable_sub =
            Some(msg.peer_actors.blockchain_bridge.report_accounts_payable);
        self.retrieve_transactions_sub =
            Some(msg.peer_actors.blockchain_bridge.retrieve_transactions);
        self.report_new_payments_sub = Some(msg.peer_actors.accountant.report_new_payments);
        self.report_sent_payments_sub = Some(msg.peer_actors.accountant.report_sent_payments);
        self.ui_message_sub = Some(msg.peer_actors.ui_gateway.node_to_ui_message_sub);
        self.confirmation_tools
            .request_transaction_receipts_subs_opt = Some(
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
                .fold(0, |so_far, now| so_far + now.wei_amount);
            self.receivable_dao
                .as_mut()
                .more_money_received(msg.timestamp, msg.payments);
            self.financial_statistics.total_paid_receivable_wei += total_newly_paid_receivable;
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

    fn handle_sent_payables(&self, sent_payables: SentPayables) {
        let (ok, err) = Self::separate_early_errors(&sent_payables, &self.logger);
        debug!(self.logger, "We gathered these errors at sending transactions for payable: {:?}, out of the total of {} attempts", err, ok.len() + err.len());
        self.mark_pending_payable(ok);
        if !err.is_empty() {
            err.into_iter().for_each(|err|
            if let Some(hash) = err.carries_transaction_hash(){
                self.discard_incomplete_transaction_with_a_failure(hash)
            } else {debug!(self.logger,"Forgetting a transaction attempt that even did not reach the signing stage")})
        }
        if let Some(response_skeleton) = &sent_payables.response_skeleton_opt {
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

    fn discard_incomplete_transaction_with_a_failure(&self, hash: H256) {
        if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(hash) {
            debug!(
                self.logger,
                "Deleting an existing fingerprint for a failed transaction {:?}", hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                panic!("Database unmaintainable; payable fingerprint deletion for transaction {:?} has stayed undone due to {:?}", hash,e)
            }
        };

        warning!(
            self.logger,
            "Failed transaction with a hash '{:?}' but without the record - thrown out",
            hash
        )
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

    fn handle_financials(&self, msg: &UiFinancialsRequest, client_id: u64, context_id: u64) {
        let body: MessageBody = self.compute_financials(msg, context_id);
        self.ui_message_sub
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
            Some(UiFinancialStatistics {
                total_unpaid_and_pending_payable_gwei: wei_to_gwei(self.payable_dao.total()),
                total_paid_payable_gwei: wei_to_gwei(
                    self.financial_statistics.total_paid_payable_wei,
                ),
                total_unpaid_receivable_gwei: wei_to_gwei(self.receivable_dao.total()),
                total_paid_receivable_gwei: wei_to_gwei(
                    self.financial_statistics.total_paid_receivable_wei,
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

    fn handle_cancel_pending_transaction(&self, msg: CancelFailedPendingTransaction) {
        match self
            .pending_payable_dao
            .mark_failure(msg.id.rowid)
        {
            Ok(_) => warning!(
                self.logger,
                "Broken transaction {:?} left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you", msg.id.hash),
            Err(e) => panic!("Unsuccessful attempt for transaction {:?} to mark fatal error at payable fingerprint due to {:?}; database unreliable", msg.id.hash,e),
        }
    }

    fn handle_confirm_pending_transaction(&mut self, msg: ConfirmPendingTransaction) {
        if let Err(e) = self
            .payable_dao
            .transaction_confirmed(&msg.pending_payable_fingerprint)
        {
            panic!(
                "Was unable to uncheck pending payable '{:?}' after confirmation due to '{:?}'",
                msg.pending_payable_fingerprint.hash, e
            )
        } else {
            self.financial_statistics.total_paid_payable_wei +=
                msg.pending_payable_fingerprint.amount;
            debug!(
                self.logger,
                "Confirmation of transaction {:?}; record for payable was modified",
                msg.pending_payable_fingerprint.hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(
                msg.pending_payable_fingerprint
                    .rowid_opt
                    .expectv("initialized rowid"),
            ) {
                panic!("Was unable to delete payable fingerprint '{:?}' after successful transaction due to '{:?}'",msg.pending_payable_fingerprint.hash,e)
            } else {
                info!(
                    self.logger,
                    "Transaction {:?} has gone through the whole confirmation process succeeding",
                    msg.pending_payable_fingerprint.hash
                )
            }
        }
    }

    fn separate_early_errors(
        sent_payments: &SentPayables,
        logger: &Logger,
    ) -> (Vec<Payable>, Vec<BlockchainError>) {
        sent_payments
            .payable
            .iter()
            .fold((vec![],vec![]),|so_far,payment| {
                match payment{
                    Ok(payment_sent) => (plus(so_far.0,payment_sent.clone()),so_far.1),
                    Err(error) => {
                        logger.warning(|| match &error {
                            BlockchainError::TransactionFailed { .. } => format!("Encountered transaction error at this end: '{:?}'", error),
                            x => format!("Outbound transaction failure due to '{:?}'. Please check your blockchain service URL configuration.", x)
                        });
                        (so_far.0,plus(so_far.1,error.clone()))
                    }
                }
            })
    }

    fn mark_pending_payable(&self, sent_payments: Vec<Payable>) {
        sent_payments
            .into_iter()
            .for_each(|payable| {
                let rowid = match self.pending_payable_dao.fingerprint_rowid(payable.tx_hash) {
                    Some(rowid) => rowid,
                    None => panic!("Payable fingerprint for {:?} doesn't exist but should by now; system unreliable", payable.tx_hash)
                };
                match self.payable_dao.as_ref().mark_pending_payable_rowid(&payable.to, rowid ) {
                    Ok(()) => (),
                    Err(e) => panic!("Was unable to create a mark in payables for a new pending payable '{:?}' due to '{:?}'", payable.tx_hash, e)
                }
                debug!(self.logger, "Payable '{:?}' has been marked as pending in the payable table",payable.tx_hash)
            })
    }

    fn handle_pending_transaction_with_its_receipt(
        &self,
        msg: &ReportTransactionReceipts,
    ) -> Vec<PendingTransactionStatus> {
        fn handle_none_receipt(
            payable: &PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            debug!(logger,
                "DEBUG: Accountant: Interpreting a receipt for transaction '{:?}' but none was given; attempt {}, {}ms since sending",
                payable.hash, payable.attempt_opt.expectv("initialized attempt"),elapsed_in_ms(payable.timestamp)
            );
            PendingTransactionStatus::StillPending(PendingPayableId {
                hash: payable.hash,
                rowid: payable.rowid_opt.expectv("initialized rowid"),
            })
        }
        msg.fingerprints_with_receipts
            .iter()
            .map(|(receipt_opt, fingerprint)| match receipt_opt {
                Some(receipt) => {
                    self.interpret_transaction_receipt(receipt, fingerprint, &self.logger)
                }
                None => handle_none_receipt(fingerprint, &self.logger),
            })
            .collect()
    }

    fn interpret_transaction_receipt(
        &self,
        receipt: &TransactionReceipt,
        fingerprint: &PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        fn handle_none_status(
            fingerprint: &PendingPayableFingerprint,
            max_pending_interval: u64,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(logger,"Pending transaction '{:?}' couldn't be confirmed at attempt {} at {}ms after its sending",
                fingerprint.hash,
                fingerprint.attempt_opt.expectv("initialized attempt"),
                elapsed_in_ms(fingerprint.timestamp)
            );
            let elapsed = fingerprint
                .timestamp
                .elapsed()
                .expect("we should be older now");
            let transaction_id = PendingPayableId {
                hash: fingerprint.hash,
                rowid: fingerprint.rowid_opt.expectv("initialized rowid"),
            };
            if max_pending_interval <= elapsed.as_secs() {
                error!(logger,"Pending transaction '{:?}' has exceeded the maximum pending time ({}sec) and the confirmation process is going to be aborted now at the final attempt {}; \
                 manual resolution is required from the user to complete the transaction.", fingerprint.hash, max_pending_interval, fingerprint.attempt_opt.expectv("initialized attempt"));
                PendingTransactionStatus::Failure(transaction_id)
            } else {
                PendingTransactionStatus::StillPending(transaction_id)
            }
        }
        fn handle_status_with_success(
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(
                logger,
                "Transaction '{:?}' has been added to the blockchain; detected locally at attempt {} at {}ms after its sending",
                fingerprint.hash,
                fingerprint.attempt_opt.expectv("initialized attempt"),
                elapsed_in_ms(fingerprint.timestamp)
            );
            PendingTransactionStatus::Confirmed(fingerprint.clone())
        }
        fn handle_status_with_failure(
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            error!(logger,"Pending transaction '{:?}' announced as a failure, interpreting attempt {} after {}ms from the sending",
                fingerprint.hash,
                fingerprint.attempt_opt.expectv("initialized attempt"),
                elapsed_in_ms(fingerprint.timestamp)
            );
            PendingTransactionStatus::Failure(fingerprint.into())
        }
        match receipt.status{
                None => handle_none_status(fingerprint, self.config.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64(){
                    0 => handle_status_with_failure(fingerprint, logger),
                    1 => handle_status_with_success(fingerprint, logger),
                    other => unreachable!("tx receipt for pending '{:?}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}", fingerprint.hash, other)
                }
            }
    }

    fn update_payable_fingerprint(&self, pending_payable_id: PendingPayableId) {
        match self
            .pending_payable_dao
            .update_fingerprint(pending_payable_id.rowid)
        {
            Ok(_) => trace!(
                self.logger,
                "Updated record for rowid: {} ",
                pending_payable_id.rowid
            ),
            Err(e) => panic!(
                "Failure on updating payable fingerprint '{:?}' due to {:?}",
                pending_payable_id.hash, e
            ),
        }
    }

    fn process_transactions_by_their_status(
        &self,
        statuses: Vec<PendingTransactionStatus>,
        ctx: &mut Context<Self>,
    ) {
        statuses.into_iter().for_each(|status| {
            if let PendingTransactionStatus::StillPending(transaction_id) = status {
                self.update_payable_fingerprint(transaction_id)
            } else if let PendingTransactionStatus::Failure(transaction_id) = status {
                self.order_cancel_failed_transaction(transaction_id, ctx)
            } else if let PendingTransactionStatus::Confirmed(fingerprint) = status {
                self.order_confirm_transaction(fingerprint, ctx)
            }
        });
    }

    fn order_cancel_failed_transaction(
        &self,
        transaction_id: PendingPayableId,
        ctx: &mut Context<Self>,
    ) {
        self.confirmation_tools
            .notify_cancel_failed_transaction
            .notify(CancelFailedPendingTransaction { id: transaction_id }, ctx)
    }

    fn order_confirm_transaction(
        &self,
        pending_payable_fingerprint: PendingPayableFingerprint,
        ctx: &mut Context<Self>,
    ) {
        self.confirmation_tools.notify_confirm_transaction.notify(
            ConfirmPendingTransaction {
                pending_payable_fingerprint,
            },
            ctx,
        );
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
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum PendingTransactionStatus {
    StillPending(PendingPayableId), //updates slightly the record, waits an interval and starts a new round
    Failure(PendingPayableId),      //standard tx failure
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

trait PayableThresholdsGauge {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
    fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool;
    fn calculate_payout_threshold_in_gwei(
        &self,
        payment_thresholds: &PaymentThresholds,
        x: u64,
    ) -> u128;
    as_any_dcl!();
}

#[derive(Default)]
struct PayableThresholdsGaugeReal {}

impl PayableThresholdsGauge for PayableThresholdsGaugeReal {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
        age <= limit
    }

    fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool {
        balance <= limit
    }

    fn calculate_payout_threshold_in_gwei(
        &self,
        payment_thresholds: &PaymentThresholds,
        debt_age: u64,
    ) -> u128 {
        ThresholdUtils::calculate_finite_debt_limit_by_age(payment_thresholds, debt_age)
    }
    as_any_impl!();
}

pub struct ThresholdUtils {}

impl ThresholdUtils {
    pub fn slope(payment_thresholds: &PaymentThresholds) -> i128 {
        //remember that any user supplied params must satisfy:
        //PermanentDebtAllowedGwei < DebtThresholdGwei and
        //ThresholdIntervalSec <= 10^9
        (gwei_to_wei::<i128, _>(payment_thresholds.permanent_debt_allowed_gwei)
            - gwei_to_wei::<i128, _>(payment_thresholds.debt_threshold_gwei))
            / payment_thresholds.threshold_interval_sec as i128
    }

    fn calculate_finite_debt_limit_by_age(
        payment_thresholds: &PaymentThresholds,
        debt_age_s: u64,
    ) -> u128 {
        if Self::qualifies_for_permanent_debt_limit(debt_age_s, payment_thresholds) {
            return gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei);
        };
        let m = ThresholdUtils::slope(payment_thresholds);
        let b = ThresholdUtils::compute_theoretical_interception_with_y_axis(
            m,
            payment_thresholds.maturity_threshold_sec as i128,
            gwei_to_wei(payment_thresholds.debt_threshold_gwei),
        );
        let y = m * debt_age_s as i128 + b;
        y as u128
    }

    fn compute_theoretical_interception_with_y_axis(
        m: i128, //is negative
        maturity_threshold_sec: i128,
        debt_threshold_wei: i128,
    ) -> i128 {
        debt_threshold_wei - (maturity_threshold_sec * m)
    }

    fn qualifies_for_permanent_debt_limit(
        debt_age_s: u64,
        payment_thresholds: &PaymentThresholds,
    ) -> bool {
        debt_age_s
            > (payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec)
    }
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
    (T::from(gwei)).mul(T::from(WEIS_OF_GWEI as u32))
}

pub fn wei_to_gwei<T: TryFrom<S>, S: Display + Copy + Div<Output = S> + From<u32>>(wei: S) -> T {
    checked_conversion::<S, T>(wei.div(S::from(WEIS_OF_GWEI as u32)))
}

fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

#[cfg(test)]
pub mod check_sqlite_fns {
    use super::*;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use actix::System;

    #[derive(Message)]
    pub struct TestOurUserDefinedSqliteFunctions {}

    impl Handler<TestOurUserDefinedSqliteFunctions> for Accountant {
        type Result = ();

        fn handle(
            &mut self,
            _msg: TestOurUserDefinedSqliteFunctions,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            //this fn call will kill a test if our user-defined sqlite functions haven't been properly registered
            self.receivable_dao
                .new_delinquencies(SystemTime::now(), &DEFAULT_PAYMENT_THRESHOLDS);
            System::current().stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ops::{Add, Sub};
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::time::Duration;
    use std::time::SystemTime;

    use actix::{Arbiter, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use log::Level;
    use masq_lib::constants::{SCAN_ERROR, VALUE_EXCEEDS_ALLOWED_LIMIT};
    use web3::types::U256;

    use masq_lib::messages::{
        CustomQueries, RangeQuery, ScanType, TopRecordsConfig, UiFinancialStatistics,
        UiMessageError, UiPayableAccount, UiReceivableAccount, UiScanRequest, UiScanResponse,
    };
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::ui_gateway::{MessageBody, MessagePath, NodeFromUiMessage, NodeToUiMessage};

    use crate::accountant::dao_utils::from_time_t;
    use crate::accountant::dao_utils::{to_time_t, CustomQuery};
    use crate::accountant::payable_dao::PayableDaoError;
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::{
        bc_from_ac_plus_earning_wallet, bc_from_ac_plus_wallets, make_payable_account,
        make_pending_payable_fingerprint, make_receivable_account, BannedDaoFactoryMock,
        MessageIdGeneratorMock, PayableDaoFactoryMock, PayableDaoMock,
        PendingPayableDaoFactoryMock, PendingPayableDaoMock, ReceivableDaoFactoryMock,
        ReceivableDaoMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::tools::accountant_tools::{NullScanner, ReceivablesScanner};
    use crate::accountant::Accountant;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::BlockchainTransaction;
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolsWrapperNull;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::sub_lib::accountant::{
        ExitServiceConsumed, RoutingServiceConsumed, ScanIntervals, DEFAULT_PAYMENT_THRESHOLDS,
        WEIS_OF_GWEI,
    };
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::utils::{NotifyHandleReal, NotifyLaterHandleReal};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::unshared_test_utils::{
        make_accountant_config_null, make_populated_accountant_config_with_defaults,
        prove_that_crash_request_handler_is_hooked_up, NotifyHandleMock, NotifyLaterHandleMock,
        SystemKillerActor,
    };
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use masq_lib::messages::TopRecordsOrdering::{Age, Balance};
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use web3::types::{TransactionReceipt, H256};

    #[derive(Default)]
    struct PayableThresholdsGaugeMock {
        is_innocent_age_params: Arc<Mutex<Vec<(u64, u64)>>>,
        is_innocent_age_results: RefCell<Vec<bool>>,
        is_innocent_balance_params: Arc<Mutex<Vec<(u128, u128)>>>,
        is_innocent_balance_results: RefCell<Vec<bool>>,
        calculate_payout_threshold_in_gwei_params: Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
        calculate_payout_threshold_in_gwei_results: RefCell<Vec<u128>>,
    }

    impl PayableThresholdsGauge for PayableThresholdsGaugeMock {
        fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
            self.is_innocent_age_params
                .lock()
                .unwrap()
                .push((age, limit));
            self.is_innocent_age_results.borrow_mut().remove(0)
        }

        fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool {
            self.is_innocent_balance_params
                .lock()
                .unwrap()
                .push((balance, limit));
            self.is_innocent_balance_results.borrow_mut().remove(0)
        }

        fn calculate_payout_threshold_in_gwei(
            &self,
            payment_thresholds: &PaymentThresholds,
            x: u64,
        ) -> u128 {
            self.calculate_payout_threshold_in_gwei_params
                .lock()
                .unwrap()
                .push((*payment_thresholds, x));
            self.calculate_payout_threshold_in_gwei_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl PayableThresholdsGaugeMock {
        fn is_innocent_age_params(mut self, params: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.is_innocent_age_params = params.clone();
            self
        }

        fn is_innocent_age_result(self, result: bool) -> Self {
            self.is_innocent_age_results.borrow_mut().push(result);
            self
        }

        fn is_innocent_balance_params(mut self, params: &Arc<Mutex<Vec<(u128, u128)>>>) -> Self {
            self.is_innocent_balance_params = params.clone();
            self
        }

        fn is_innocent_balance_result(self, result: bool) -> Self {
            self.is_innocent_balance_results.borrow_mut().push(result);
            self
        }

        fn calculate_payout_threshold_in_gwei_params(
            mut self,
            params: &Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
        ) -> Self {
            self.calculate_payout_threshold_in_gwei_params = params.clone();
            self
        }

        fn calculate_payout_threshold_in_gwei_result(self, result: u128) -> Self {
            self.calculate_payout_threshold_in_gwei_results
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

        let transaction_confirmation_tools = result.confirmation_tools;
        transaction_confirmation_tools
            .notify_confirm_transaction
            .as_any()
            .downcast_ref::<NotifyHandleReal<ConfirmPendingTransaction>>()
            .unwrap();
        transaction_confirmation_tools
            .notify_cancel_failed_transaction
            .as_any()
            .downcast_ref::<NotifyHandleReal<CancelFailedPendingTransaction>>()
            .unwrap();
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
            .payable_threshold_gauge
            .as_any()
            .downcast_ref::<PayableThresholdsGaugeReal>()
            .unwrap();
        assert_eq!(result.crashable, false);
        assert_eq!(result.financial_statistics.total_paid_receivable_wei, 0);
        assert_eq!(result.financial_statistics.total_paid_payable_wei, 0);
        result
            .message_id_generator
            .as_any()
            .downcast_ref::<MessageIdGeneratorReal>()
            .unwrap();
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
            balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1),
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
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .build();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let subject_addr = subject.start();
        let system = System::new("test");
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        let sent_payable = SentPayables {
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let expected_payable = Payable::new(
            expected_wallet.clone(),
            expected_amount,
            expected_hash.clone(),
            expected_timestamp,
        );
        let sent_payable = SentPayables {
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
            .pending_payable_dao(pending_payable_dao)
            .build();
        let hash = H256::from_uint(&U256::from(12345));
        let sent_payable = SentPayables {
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
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let wallet = make_wallet("blah");
        let hash_tx_1 = H256::from_uint(&U256::from(5555));
        let hash_tx_2 = H256::from_uint(&U256::from(12345));
        let sent_payable = SentPayables {
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
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("blah"),
                balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 55),
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now())
                        - checked_conversion::<u64, i64>(
                            DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec,
                        )
                        - 5,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("foo"),
                balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 66),
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now())
                        - checked_conversion::<u64, i64>(
                            DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec,
                        )
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
            wei_amount: 456,
        };
        let expected_receivable_2 = BlockchainTransaction {
            block_number: 13,
            from: make_wallet("wallet1"),
            wei_amount: 10000,
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
            balance_wei: 4567,
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
        subject.confirmation_tools.notify_later_scan_for_receivable = Box::new(
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
            hash: H256::from_uint(&U256::from(565)),
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
        subject
            .confirmation_tools
            .notify_later_scan_for_pending_payable = Box::new(
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
            balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 5),
            last_paid_timestamp: from_time_t(
                now - checked_conversion::<u64, i64>(
                    DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 10,
                ),
            ),
            pending_payable_opt: None,
        };
        let mut payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![])
            .non_pending_payables_result(vec![account.clone()]);
        payable_dao.have_non_pending_payable_shut_down_the_system = true;
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .build();
        subject.scanners.pending_payables = Box::new(NullScanner); //skipping
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.confirmation_tools.notify_later_scan_for_payable = Box::new(
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
                balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei - 1),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.threshold_interval_sec + 10,
                    ),
                ),
                pending_payable_opt: None,
            },
            // above balance intersection, to the left of minimum time (outside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: gwei_to_wei(payment_thresholds.debt_threshold_gwei + 1),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.maturity_threshold_sec - 10,
                    ),
                ),
                pending_payable_opt: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 55),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.maturity_threshold_sec + 15,
                    ),
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
                balance_wei: gwei_to_wei(
                    DEFAULT_PAYMENT_THRESHOLDS.permanent_debt_allowed_gwei + 1,
                ),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        DEFAULT_PAYMENT_THRESHOLDS.threshold_interval_sec
                            + DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
                            + 10,
                    ),
                ),
                pending_payable_opt: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 1),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec + 10,
                    ),
                ),
                pending_payable_opt: None,
            },
        ];
        let mut payable_dao = PayableDaoMock::default()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        payable_dao.have_non_pending_payable_shut_down_the_system = true;
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
        subject
            .confirmation_tools
            .request_transaction_receipts_subs_opt = Some(blockchain_bridge_addr.recipient());
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            earning_wallet,
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
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
            "WARN: Accountant: Declining to record a receivable against our wallet {} for service we provided",
            earning_wallet,
        ));
    }

    #[test]
    fn report_services_consumed_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            make_wallet("hi"),
        );
        let more_money_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .more_money_payable_params(more_money_payable_params_arc.clone())
            .more_money_payable_result(Ok(()))
            .more_money_payable_result(Ok(()))
            .more_money_payable_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao_mock)
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
            .payable_dao(payable_dao_mock)
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
        let config = bc_from_ac_plus_wallets(
            make_populated_accountant_config_with_defaults(),
            consuming_wallet.clone(),
            make_wallet("the earning wallet"),
        );
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
        let config = bc_from_ac_plus_earning_wallet(
            make_populated_accountant_config_with_defaults(),
            earning_wallet.clone(),
        );
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
        let config = bc_from_ac_plus_wallets(
            make_accountant_config_null(),
            consuming_wallet.clone(),
            make_wallet("own earning wallet"),
        );
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
        let config =
            bc_from_ac_plus_earning_wallet(make_accountant_config_null(), earning_wallet.clone());
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

    #[test]
    #[should_panic(
        expected = "Was unable to create a mark in payables for a new pending payable '0x000000000000000000000000000000000000000000000000000000000000007b' due to 'SignConversion(9999999999999)'"
    )]
    fn handle_sent_payable_fails_to_make_a_mark_in_payables_and_so_panics() {
        let payable = Payable::new(
            make_wallet("blah"),
            6789,
            H256::from_uint(&U256::from(123)),
            SystemTime::now(),
        );
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_result(Err(PayableDaoError::SignConversion(9999999999999)));
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprint_rowid_result(Some(7879));
        let subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.mark_pending_payable(vec![payable]);
    }

    #[test]
    #[should_panic(
        expected = "Database unmaintainable; payable fingerprint deletion for transaction 0x000000000000000000000000000000000000000000000000000000000000007b \
        has stayed undone due to RecordDeletion(\"we slept over, sorry\")"
    )]
    fn handle_sent_payable_dealing_with_failed_payment_fails_to_delete_the_existing_pending_payable_fingerprint_and_panics(
    ) {
        let rowid = 4;
        let hash = H256::from_uint(&U256::from(123));
        let sent_payable = SentPayables {
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
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.handle_sent_payables(sent_payable);
    }

    #[test]
    fn handle_sent_payable_receives_two_payments_one_incorrect_and_one_correct() {
        //the two failures differ in the logged messages
        init_test_logging();
        let fingerprint_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let now_system = SystemTime::now();
        let payable_1 = Err(BlockchainError::InvalidResponse);
        let payable_2_rowid = 126;
        let payable_hash_2 = H256::from_uint(&U256::from(166));
        let payable_2 = Payable::new(make_wallet("booga"), 6789, payable_hash_2, now_system);
        let payable_3 = Err(BlockchainError::TransactionFailed {
            msg: "closing hours, sorry".to_string(),
            hash_opt: None,
        });
        let sent_payable = SentPayables {
            timestamp: SystemTime::now(),
            payable: vec![payable_1, Ok(payable_2.clone()), payable_3],
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(payable_2_rowid));
        let subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(())))
            .pending_payable_dao(pending_payable_dao)
            .build();

        subject.handle_sent_payables(sent_payable);

        let fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(*fingerprint_rowid_params, vec![payable_hash_2]); //we know the other two errors are associated with an initiated transaction having a backup
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Outbound transaction failure due to 'InvalidResponse'. Please check your blockchain service URL configuration.");
        log_handler.exists_log_containing("DEBUG: Accountant: Payable '0x00000000000000000000000000000000000000000000000000000000000000a6' has been marked as pending in the payable table");
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error at this end: 'TransactionFailed { msg: \"closing hours, sorry\", hash_opt: None }'");
        log_handler.exists_log_containing("DEBUG: Accountant: Forgetting a transaction attempt that even did not reach the signing stage");
    }

    #[test]
    #[should_panic(
        expected = "Payable fingerprint for 0x0000000000000000000000000000000000000000000000000000000000000315 doesn't exist but should by now; system unreliable"
    )]
    fn handle_sent_payable_receives_proper_payment_but_fingerprint_not_found_so_it_panics() {
        init_test_logging();
        let now_system = SystemTime::now();
        let payment_hash = H256::from_uint(&U256::from(789));
        let payment = Payable::new(make_wallet("booga"), 6789, payment_hash, now_system);
        let pending_payable_dao = PendingPayableDaoMock::default().fingerprint_rowid_result(None);
        let subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(())))
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.mark_pending_payable(vec![payment]);
    }

    #[test]
    fn handle_confirm_transaction_works() {
        init_test_logging();
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .delete_fingerprint_params(&delete_pending_payable_fingerprint_params_arc)
            .delete_fingerprint_result(Ok(()));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let amount = 4567;
        let timestamp_from_time_of_payment = from_time_t(200_000_000);
        let rowid = 2;
        let pending_payable_fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: timestamp_from_time_of_payment,
            hash: tx_hash,
            attempt_opt: Some(1),
            amount,
            process_error: None,
        };

        let _ = subject.handle_confirm_pending_transaction(ConfirmPendingTransaction {
            pending_payable_fingerprint: pending_payable_fingerprint.clone(),
        });

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![pending_payable_fingerprint]
        );
        let delete_pending_payable_fingerprint_params =
            delete_pending_payable_fingerprint_params_arc
                .lock()
                .unwrap();
        assert_eq!(*delete_pending_payable_fingerprint_params, vec![rowid]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Confirmation of transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19; record for payable was modified");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 has gone through the whole confirmation process succeeding");
    }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payable '0x0000000000000000000000000000000000000000000000000000000000000315' after confirmation due to 'RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirm_pending_transaction_panics_on_unchecking_payable_table() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .build();
        let mut payment = make_pending_payable_fingerprint();
        payment.rowid_opt = Some(rowid);
        payment.hash = hash;
        let msg = ConfirmPendingTransaction {
            pending_payable_fingerprint: payment.clone(),
        };

        let _ = subject.handle_confirm_pending_transaction(msg);
    }

    #[test]
    #[should_panic(
        expected = "Was unable to delete payable fingerprint '0x0000000000000000000000000000000000000000000000000000000000000315' after successful transaction due to 'RecordDeletion(\"the database is fooling around with us\")'"
    )]
    fn handle_confirm_pending_transaction_panics_on_deleting_pending_payable_fingerprint() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().delete_fingerprint_result(Err(
            PendingPayableDaoError::RecordDeletion(
                "the database is fooling around with us".to_string(),
            ),
        ));
        let mut subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.hash = hash;
        let msg = ConfirmPendingTransaction {
            pending_payable_fingerprint: pending_payable_fingerprint.clone(),
        };

        let _ = subject.handle_confirm_pending_transaction(msg);
    }

    #[test]
    fn handle_cancel_pending_transaction_works() {
        init_test_logging();
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failure_params(&mark_failure_params_arc)
            .mark_failure_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let rowid = 2;
        let transaction_id = PendingPayableId {
            hash: tx_hash,
            rowid,
        };

        let _ = subject.handle_cancel_pending_transaction(CancelFailedPendingTransaction {
            id: transaction_id,
        });

        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![rowid]);
        TestLogHandler::new().exists_log_containing(
            "WARN: Accountant: Broken transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 left with an error mark; you should take over \
             the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 to mark fatal error at payable fingerprint due to UpdateFailed(\"no no no\")"
    )]
    fn handle_cancel_pending_transaction_panics_on_its_inability_to_mark_failure() {
        let payable_dao = PayableDaoMock::default().transaction_canceled_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failure_result(Err(
            PendingPayableDaoError::UpdateFailed("no no no".to_string()),
        ));
        let subject = AccountantBuilder::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());

        let _ = subject.handle_cancel_pending_transaction(CancelFailedPendingTransaction {
            id: PendingPayableId { hash, rowid },
        });
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
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 5000),
                pending_payable_opt: None,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 10000),
                pending_payable_opt: None,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance_wei: 100,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance_wei: 330,
                last_paid_timestamp: same_age_significance,
                pending_payable_opt: None,
            },
        ];

        let result = Accountant::investigate_debt_extremes(payables);

        assert_eq!(result,"Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        init_test_logging();
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
                balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 2000),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.maturity_threshold_sec
                            + payment_thresholds.threshold_interval_sec,
                    ),
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance_wei: gwei_to_wei(payment_thresholds.debt_threshold_gwei - 1),
                last_paid_timestamp: from_time_t(
                    now - checked_conversion::<u64, i64>(
                        payment_thresholds.maturity_threshold_sec + 55,
                    ),
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

        subject.payables_debug_summary(qualified_payables);

        TestLogHandler::new().exists_log_containing("Paying qualified debts:\n\
                   10,002,000,000,000,000 Wei owed for 2678400 sec exceeds threshold: 10,000,000,001,152,000 Wei; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   999,999,999,000,000,000 Wei owed for 86455 sec exceeds threshold: 999,978,993,055,555,580 Wei; creditor: 0x0000000000000000000000000077616c6c657431");
    }

    #[test]
    fn payables_debug_summary_stays_still_if_no_qualified_payments() {
        init_test_logging();
        let mut subject = AccountantBuilder::default().build();
        subject.logger = Logger::new("payables_debug_summary_stays_still_if_no_qualified_payments");

        subject.payables_debug_summary(&vec![]);

        TestLogHandler::new().exists_no_log_containing("DEBUG: payables_debug_summary_prints_nothing_if_no_qualified_payments: Paying qualified debts:");
    }

    #[test]
    fn payout_sloped_segment_in_payment_thresholds_goes_along_proper_line() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 333,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 4444,
            debt_threshold_gwei: 8888,
            threshold_interval_sec: 1111111,
            unban_below_gwei: 0,
        };
        let higher_corner_timestamp = payment_thresholds.maturity_threshold_sec;
        let middle_point_timestamp = payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec / 2;
        let lower_corner_timestamp =
            payment_thresholds.maturity_threshold_sec + payment_thresholds.threshold_interval_sec;
        let tested_fn = |payment_thresholds: &PaymentThresholds, time| {
            PayableThresholdsGaugeReal {}
                .calculate_payout_threshold_in_gwei(payment_thresholds, time) as i128
        };

        let higher_corner_point = tested_fn(&payment_thresholds, higher_corner_timestamp);
        let middle_point = tested_fn(&payment_thresholds, middle_point_timestamp);
        let lower_corner_point = tested_fn(&payment_thresholds, lower_corner_timestamp);

        let allowed_imprecision = WEIS_OF_GWEI;
        let ideal_template_higher: i128 = gwei_to_wei(payment_thresholds.debt_threshold_gwei);
        let ideal_template_middle: i128 = gwei_to_wei(
            (payment_thresholds.debt_threshold_gwei
                - payment_thresholds.permanent_debt_allowed_gwei)
                / 2
                + payment_thresholds.permanent_debt_allowed_gwei,
        );
        let ideal_template_lower: i128 =
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei);
        assert!(
            higher_corner_point <= ideal_template_higher + allowed_imprecision
                && ideal_template_higher - allowed_imprecision <= higher_corner_point,
            "ideal: {}, real: {}",
            ideal_template_higher,
            higher_corner_point
        );
        assert!(
            middle_point <= ideal_template_middle + allowed_imprecision
                && ideal_template_middle - allowed_imprecision <= middle_point,
            "ideal: {}, real: {}",
            ideal_template_middle,
            middle_point
        );
        assert!(
            lower_corner_point <= ideal_template_lower + allowed_imprecision
                && ideal_template_lower - allowed_imprecision <= lower_corner_point,
            "ideal: {}, real: {}",
            ideal_template_lower,
            lower_corner_point
        )
    }

    fn gap_tester(payment_thresholds: &PaymentThresholds) -> Option<u64> {
        let cached = (0_u64..20).map(|to_add| {
            ThresholdUtils::calculate_finite_debt_limit_by_age(&payment_thresholds, 1500 + to_add)
                as u64
        });
        let mut counts_of_unique_elements: HashMap<u64, usize> = HashMap::new();
        cached.for_each(|point_height| {
            counts_of_unique_elements
                .entry(point_height)
                .and_modify(|q| *q += 1)
                .or_insert(1);
        });
        let mut counts_of_groups_of_the_same_size: HashMap<usize, usize> = HashMap::new();
        counts_of_unique_elements.values().for_each(|unique_count| {
            counts_of_groups_of_the_same_size
                .entry(*unique_count)
                .and_modify(|q| *q += 1)
                .or_insert(1);
        });
        let mut sortable = counts_of_groups_of_the_same_size
            .drain()
            .collect::<Vec<_>>();
        sortable.sort_by_key(|(_key, count)| *count);
        let (biggest_groups_size, occurrence) = sortable.last().expect("no values to analyze");
        //checking if the sample of undistorted results (consist size groups) has enough weight compared to 20 tries from the beginning
        if biggest_groups_size * occurrence >= 15 {
            Some(*biggest_groups_size as u64)
        } else {
            panic!("couldn't provide a relevant amount of data for the analysis")
        }
    }

    fn test_height_granularity_with_advancing_time(
        test_scope: &str,
        payment_thresholds: &PaymentThresholds,
        seconds_between_height_change: u64,
    ) {
        let finding_under_135_degree = gap_tester(&payment_thresholds);

        if let Some(seconds_needed_for_smallest_detected_change_in_height) =
            finding_under_135_degree
        {
            assert_eq!(seconds_needed_for_smallest_detected_change_in_height, seconds_between_height_change,
                       "while testing {} we expected that these thresholds: {:?} will require only {} s until we see the height change but computed {} s instead",
                       test_scope, payment_thresholds, seconds_between_height_change, seconds_needed_for_smallest_detected_change_in_height)
        } else {
            panic!(
                "while testing {}, we waited for some finding but got none",
                test_scope
            )
        }
    }

    #[test]
    fn testing_granularity_calculate_sloped_threshold_by_time() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 10_000,
            threshold_interval_sec: 10_000,
            unban_below_gwei: 100,
        };

        test_height_granularity_with_advancing_time("135° slope", &payment_thresholds, 1);

        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 0,
            permanent_debt_allowed_gwei: 100,
            debt_threshold_gwei: 3_420,
            threshold_interval_sec: 10_000,
            unban_below_gwei: 100,
        };

        test_height_granularity_with_advancing_time("160° slope", &payment_thresholds, 1);
    }

    #[test]
    fn checking_chosen_values_for_the_payment_thresholds_defaults_on_height_values_granularity() {
        let payment_thresholds = *DEFAULT_PAYMENT_THRESHOLDS;

        test_height_granularity_with_advancing_time("default thresholds", &payment_thresholds, 1);
    }

    #[test]
    fn slope_has_loose_enough_limitations_to_allow_work_with_number_bigger_than_masq_token_max_supply(
    ) {
        //max masq token supply by August 2022: 37,500,000
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 20,
            payment_grace_period_sec: 33,
            permanent_debt_allowed_gwei: 1,
            debt_threshold_gwei: 37500000000000000,
            threshold_interval_sec: 1,
            unban_below_gwei: 0,
        };

        let slope = ThresholdUtils::slope(&payment_thresholds);

        assert_eq!(slope, -37499999999999999000000000);
        let check = {
            let y_interception = ThresholdUtils::compute_theoretical_interception_with_y_axis(
                slope,
                payment_thresholds.maturity_threshold_sec as i128,
                gwei_to_wei(payment_thresholds.debt_threshold_gwei),
            );
            slope * (payment_thresholds.maturity_threshold_sec + 1) as i128 + y_interception
        };
        assert_eq!(check, WEIS_OF_GWEI)
    }

    #[test]
    fn slope_after_its_end_turns_into_permanent_debt_allowed() {
        let payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1000,
            payment_grace_period_sec: 444,
            permanent_debt_allowed_gwei: 44,
            debt_threshold_gwei: 8888,
            threshold_interval_sec: 11111,
            unban_below_gwei: 0,
        };

        let right_at_the_end = ThresholdUtils::calculate_finite_debt_limit_by_age(
            &payment_thresholds,
            payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec
                + 1,
        );
        let a_certain_distance_further = ThresholdUtils::calculate_finite_debt_limit_by_age(
            &payment_thresholds,
            payment_thresholds.maturity_threshold_sec
                + payment_thresholds.threshold_interval_sec
                + 1234,
        );

        assert_eq!(
            right_at_the_end,
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei)
        );
        assert_eq!(
            a_certain_distance_further,
            gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei)
        )
    }

    #[test]
    fn is_innocent_age_works_for_age_smaller_than_innocent_age() {
        let payable_age = 999;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_age_equal_to_innocent_age() {
        let payable_age = 1000;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_age_works_for_excessive_age() {
        let payable_age = 1001;

        let result = PayableThresholdsGaugeReal::default().is_innocent_age(payable_age, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_smaller_than_innocent_balance() {
        let payable_balance = 999;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_balance_equal_to_innocent_balance() {
        let payable_balance = 1000;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, true)
    }

    #[test]
    fn is_innocent_balance_works_for_excessive_balance() {
        let payable_balance = 1001;

        let result =
            PayableThresholdsGaugeReal::default().is_innocent_balance(payable_balance, 1000);

        assert_eq!(result, false)
    }

    #[test]
    fn payable_is_found_innocent_by_age_and_returns() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(true);
        let mut subject = AccountantBuilder::default().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(123456))
            .unwrap();
        let mut payable = make_payable_account(111);
        payable.last_paid_timestamp = last_paid_timestamp;
        let before = SystemTime::now();

        let result = subject.payable_exceeded_threshold(&payable);

        let after = SystemTime::now();
        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age, threshold_value) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        let time_elapsed_before = before
            .duration_since(last_paid_timestamp)
            .unwrap()
            .as_secs();
        let time_elapsed_after = after.duration_since(last_paid_timestamp).unwrap().as_secs();
        assert!(time_elapsed_before <= debt_age && debt_age <= time_elapsed_after);
        assert_eq!(
            threshold_value,
            DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
        )
        //no other method was called (absence of panic) and that means we returned early
    }

    #[test]
    fn payable_is_found_innocent_by_balance_and_returns() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let is_innocent_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(false)
            .is_innocent_balance_params(&is_innocent_balance_params_arc)
            .is_innocent_balance_result(true);
        let mut subject = AccountantBuilder::default().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let last_paid_timestamp = SystemTime::now()
            .checked_sub(Duration::from_secs(111111))
            .unwrap();
        let mut payable = make_payable_account(222);
        payable.last_paid_timestamp = last_paid_timestamp;
        payable.balance_wei = 123456;
        let before = SystemTime::now();

        let result = subject.payable_exceeded_threshold(&payable);

        let after = SystemTime::now();
        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age, _) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        let time_elapsed_before = before
            .duration_since(last_paid_timestamp)
            .unwrap()
            .as_secs();
        let time_elapsed_after = after.duration_since(last_paid_timestamp).unwrap().as_secs();
        assert!(time_elapsed_before <= debt_age && debt_age <= time_elapsed_after);
        let is_innocent_balance_params = is_innocent_balance_params_arc.lock().unwrap();
        assert_eq!(
            *is_innocent_balance_params,
            vec![(
                123456_u128,
                gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.permanent_debt_allowed_gwei)
            )]
        )
        //no other method was called (absence of panic) and that means we returned early
    }

    #[test]
    fn threshold_calculation_depends_on_user_defined_payment_thresholds() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let is_innocent_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let calculate_payable_threshold_params_arc = Arc::new(Mutex::new(vec![]));
        let balance = gwei_to_wei(5555_u64);
        let how_far_in_past = Duration::from_secs(1111 + 1);
        let last_paid_timestamp = SystemTime::now().sub(how_far_in_past);
        let payable_account = PayableAccount {
            wallet: make_wallet("hi"),
            balance_wei: balance,
            last_paid_timestamp,
            pending_payable_opt: None,
        };
        let custom_payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1111,
            payment_grace_period_sec: 2222,
            permanent_debt_allowed_gwei: 3333,
            debt_threshold_gwei: 4444,
            threshold_interval_sec: 5555,
            unban_below_gwei: 5555,
        };
        let mut bootstrapper_config = BootstrapperConfig::default();
        bootstrapper_config.accountant_config_opt = Some(AccountantConfig {
            scan_intervals: Default::default(),
            payment_thresholds: custom_payment_thresholds,
            suppress_initial_scans: false,
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
        });
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(
                how_far_in_past.as_secs()
                    <= custom_payment_thresholds.maturity_threshold_sec as u64,
            )
            .is_innocent_balance_params(&is_innocent_balance_params_arc)
            .is_innocent_balance_result(
                balance <= gwei_to_wei(custom_payment_thresholds.permanent_debt_allowed_gwei),
            )
            .calculate_payout_threshold_in_gwei_params(&calculate_payable_threshold_params_arc)
            .calculate_payout_threshold_in_gwei_result(4567898); //made up value
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bootstrapper_config)
            .build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let before = SystemTime::now();

        let result = subject.payable_exceeded_threshold(&payable_account);

        let after = SystemTime::now();
        assert_eq!(result, Some(4567898));
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (time_elapsed, curve_derived_time) = is_innocent_age_params.remove(0);
        assert_eq!(*is_innocent_age_params, vec![]);
        let time_elapsed_before = before
            .duration_since(last_paid_timestamp)
            .unwrap()
            .as_secs();
        let time_elapsed_after = after.duration_since(last_paid_timestamp).unwrap().as_secs();
        assert!(time_elapsed_before <= time_elapsed && time_elapsed <= time_elapsed_after);
        assert_eq!(
            curve_derived_time,
            custom_payment_thresholds.maturity_threshold_sec as u64
        );
        let is_innocent_balance_params = is_innocent_balance_params_arc.lock().unwrap();
        assert_eq!(
            *is_innocent_balance_params,
            vec![(
                payable_account.balance_wei,
                gwei_to_wei(custom_payment_thresholds.permanent_debt_allowed_gwei)
            )]
        );
        let mut calculate_payable_curves_params =
            calculate_payable_threshold_params_arc.lock().unwrap();
        let (payment_thresholds, time_elapsed) = calculate_payable_curves_params.remove(0);
        assert_eq!(*calculate_payable_curves_params, vec![]);
        assert!(time_elapsed_before <= time_elapsed && time_elapsed <= time_elapsed_after);
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
        let notify_cancel_failed_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_cancel_failed_transaction_params_arc_cloned =
            notify_cancel_failed_transaction_params_arc.clone(); //because it moves into a closure
        let notify_confirm_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_confirm_transaction_params_arc_cloned =
            notify_confirm_transaction_params_arc.clone(); //because it moves into a closure
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
        let payable_account_balance_1 =
            gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 10);
        let payable_account_balance_2 =
            gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.debt_threshold_gwei + 666);
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
            balance_wei: payable_account_balance_1,
            last_paid_timestamp: past_payable_timestamp_1,
            pending_payable_opt: None,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance_wei: payable_account_balance_2,
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
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));
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
            amount: payable_account_balance_1,
            process_error: None,
        };
        let fingerprint_2_first_round = PendingPayableFingerprint {
            rowid_opt: Some(rowid_for_account_2),
            timestamp: this_payable_timestamp_2,
            hash: pending_tx_hash_2,
            attempt_opt: Some(1),
            amount: payable_account_balance_2,
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
            .insert_fingerprint_params(&insert_fingerprint_params_arc)
            .insert_fingerprint_result(Ok(()))
            .insert_fingerprint_result(Ok(()))
            .fingerprint_rowid_result(Some(rowid_for_account_1))
            .fingerprint_rowid_result(Some(rowid_for_account_2))
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
                subject
                    .confirmation_tools
                    .notify_later_scan_for_pending_payable = Box::new(notify_later_half_mock);
                let notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_cancel_failed_transaction_params_arc_cloned)
                    .permit_to_send_out();
                subject.confirmation_tools.notify_cancel_failed_transaction =
                    Box::new(notify_half_mock);
                let notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_confirm_transaction_params_arc_cloned)
                    .permit_to_send_out();
                subject.confirmation_tools.notify_confirm_transaction = Box::new(notify_half_mock);
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
                pending_tx_hash_2
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
                rowid_for_account_2
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
        let mut notify_confirm_transaction_params =
            notify_confirm_transaction_params_arc.lock().unwrap();
        let actual_confirmed_payable: ConfirmPendingTransaction =
            notify_confirm_transaction_params.remove(0);
        assert!(notify_confirm_transaction_params.is_empty());
        let expected_confirmed_payable = ConfirmPendingTransaction {
            pending_payable_fingerprint: fingerprint_2_fourth_round,
        };
        assert_eq!(actual_confirmed_payable, expected_confirmed_payable);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            "WARN: Accountant: Broken transaction 0x000000000000000000000000000000000000000000000000000000000000007b left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there \
             is no automated process that can fix this without you");
        log_handler.exists_log_matching("INFO: Accountant: Transaction '0x0000000000000000000000000000000000000000000000000000000000000237' has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x0000000000000000000000000000000000000000000000000000000000000237 has gone through the whole confirmation process succeeding");
    }

    #[test]
    fn handle_pending_tx_handles_none_returned_for_transaction_receipt() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let tx_receipt_opt = None;
        let rowid = 455;
        let hash = H256::from_uint(&U256::from(2323));
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
            vec![PendingTransactionStatus::StillPending(PendingPayableId {
                hash,
                rowid
            })]
        );
        TestLogHandler::new().exists_log_matching("DEBUG: Accountant: Interpreting a receipt for transaction '0x0000000000000000000000000000000000000000000000000000000000000913' but none was given; attempt 3, 100\\d\\dms since sending");
    }

    #[test]
    fn accountant_receives_reported_transaction_receipts_and_processes_them_all() {
        let notify_handle_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default().build();
        subject.confirmation_tools.notify_confirm_transaction =
            Box::new(NotifyHandleMock::default().notify_params(&notify_handle_params_arc));
        let subject_addr = subject.start();
        let transaction_hash_1 = H256::from_uint(&U256::from(4545));
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
        let transaction_hash_2 = H256::from_uint(&U256::from(3333333));
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

        let _ = subject_addr.try_send(msg).unwrap();

        let system = System::new("processing reported receipts");
        System::current().stop();
        system.run();
        let notify_handle_params = notify_handle_params_arc.lock().unwrap();
        assert_eq!(
            *notify_handle_params,
            vec![
                ConfirmPendingTransaction {
                    pending_payable_fingerprint: fingerprint_1
                },
                ConfirmPendingTransaction {
                    pending_payable_fingerprint: fingerprint_2
                }
            ]
        );
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let subject = AccountantBuilder::default().build();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = H256::from_uint(&U256::from(4567));
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(777777),
            timestamp: SystemTime::now().sub(Duration::from_millis(150000)),
            hash,
            attempt_opt: Some(5),
            amount: 2222,
            process_error: None,
        };

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId {
                hash,
                rowid: 777777
            })
        );
        TestLogHandler::new().exists_log_matching("ERROR: receipt_check_logger: Pending \
         transaction '0x00000000000000000000000000000000000000000000000000000000000011d7' announced as a failure, interpreting attempt 5 after 1500\\d\\dms from the sending");
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
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

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("none_within_waiting"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: none_within_waiting: Pending \
         transaction '0x0000000000000000000000000000000000000000000000000000000000000237' couldn't be confirmed at attempt 1 at ",
        );
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
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

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: receipt_check_logger: Pending transaction '0x0000000000000000000000000000000000000000000000000000000000000237' has exceeded the maximum \
             pending time (21600sec) and the confirmation process is going to be aborted now at the final attempt 10; manual resolution is required from the user to \
               complete the transaction",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x000000000000000000000000000000000000000000000000000000000000007b' - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = H256::from_uint(&U256::from(123));
        let subject = AccountantBuilder::default().build();

        let _ = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn accountant_handles_pending_payable_fingerprint() {
        init_test_logging();
        let insert_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao = PendingPayableDaoMock::default()
            .insert_fingerprint_params(&insert_fingerprint_params_arc)
            .insert_fingerprint_result(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payment_dao)
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
    fn separate_early_errors_works() {
        let payable_ok = Payable {
            to: make_wallet("blah"),
            amount: 5555,
            timestamp: SystemTime::now(),
            tx_hash: Default::default(),
        };
        let error = BlockchainError::SignedValueConversion(666);
        let sent_payable = SentPayables {
            timestamp: SystemTime::now(),
            payable: vec![Ok(payable_ok.clone()), Err(error.clone())],
            response_skeleton_opt: None,
        };

        let (ok, err) = Accountant::separate_early_errors(&sent_payable, &Logger::new("test"));

        assert_eq!(ok, vec![payable_ok]);
        assert_eq!(err, vec![error])
    }

    #[test]
    fn update_payable_fingerprint_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .update_fingerprint_params(&update_after_cycle_params_arc)
            .update_fingerprint_results(Ok(()));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id = PendingPayableId { hash, rowid };

        let _ = subject.update_payable_fingerprint(transaction_id);

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![rowid])
    }

    #[test]
    #[should_panic(
        expected = "Failure on updating payable fingerprint '0x000000000000000000000000000000000000000000000000000000000006c9d8' \
         due to UpdateFailed(\"yeah, bad\")"
    )]
    fn update_payable_fingerprint_sad_path() {
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default().update_fingerprint_results(Err(
            PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
        ));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id = PendingPayableId { hash, rowid };

        let _ = subject.update_payable_fingerprint(transaction_id);
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
    fn financials_request_with_nothing_to_respond_to_is_refused() {
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
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
        );
    }

    #[test]
    fn compute_financials_processes_defaulted_request() {
        let payable_dao = PayableDaoMock::new().total_result(u64::MAX as u128 + 123456);
        let receivable_dao = ReceivableDaoMock::new().total_result((i64::MAX as i128) * 3);
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
            .build();
        subject.financial_statistics.total_paid_payable_wei = 172_345_602_235_454_454;
        subject.financial_statistics.total_paid_receivable_wei = 4_455_656_989_415_777_555;
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
                query_results_opt: None,
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
            .payable_dao(payable_dao)
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
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
        expected = "Broken code: PayableAccount with less than 1 Gwei passed through db query \
     constrains; wallet: 0x0000000000000000000000000061626364313233, balance: 8686005"
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .payable_dao(payable_dao)
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
        expected = "Broken code: ReceivableAccount with balance between 1 and 0 Gwei passed through \
     db query constrains; wallet: 0x0000000000000000000000000061626364313233, balance: 7686005"
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
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                make_populated_accountant_config_with_defaults(),
                make_wallet("some_wallet_address"),
            ))
            .receivable_dao(receivable_dao)
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
    fn total_paid_payable_rises_with_each_bill_paid() {
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(5),
            timestamp: from_time_t(189_999_888),
            hash: H256::from_uint(&U256::from(56789)),
            attempt_opt: Some(1),
            amount: 5478,
            process_error: None,
        };
        let mut pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprint_result(Ok(()));
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
        let mut subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .payable_dao(payable_dao)
            .build();
        subject.financial_statistics.total_paid_payable_wei += 1111;
        let msg = ConfirmPendingTransaction {
            pending_payable_fingerprint: fingerprint.clone(),
        };

        subject.handle_confirm_pending_transaction(msg);

        assert_eq!(
            subject.financial_statistics.total_paid_payable_wei,
            1111 + 5478
        );
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transaction_confirmed_params, vec![fingerprint])
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
        subject.financial_statistics.total_paid_receivable_wei += 2222;
        let receivables = vec![
            BlockchainTransaction {
                block_number: 4578910,
                from: make_wallet("wallet_1"),
                wei_amount: 45780,
            },
            BlockchainTransaction {
                block_number: 4569898,
                from: make_wallet("wallet_2"),
                wei_amount: 33345,
            },
        ];
        let now = SystemTime::now();

        subject.handle_received_payments(ReceivedPayments {
            timestamp: now,
            payments: receivables.clone(),
            response_skeleton_opt: None,
        });

        assert_eq!(
            subject.financial_statistics.total_paid_receivable_wei,
            2222 + 45780 + 33345
        );
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
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

        assert_eq!(result,Err("Overflow detected with 340282366920938463463374607431768211455: cannot be converted from u128 to i128".to_string()))
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
}
