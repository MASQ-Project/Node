// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_dao;
pub mod pending_payable_dao;
pub mod receivable_dao;
pub mod tools;

#[cfg(test)]
pub mod test_utils;

use crate::accountant::payable_dao::{Payable, PayableAccount, PayableDaoError, PayableDaoFactory};
use crate::accountant::pending_payable_dao::{PendingPayableDao, PendingPayableDaoFactory};
use crate::accountant::receivable_dao::{
    ReceivableAccount, ReceivableDaoError, ReceivableDaoFactory,
};
use crate::accountant::tools::accountant_tools::{Scanners, TransactionConfirmationTools};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::DaoFactoryReal;
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::config_dao::ConfigDaoFactory;
use crate::db_config::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal,
};
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
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
use lazy_static::lazy_static;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::messages::{UiFinancialsResponse, UiPayableAccount, UiReceivableAccount};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use masq_lib::utils::{plus, ExpectValue};
use payable_dao::PayableDao;
use receivable_dao::ReceivableDao;
use std::default::Default;
use std::ops::Add;
use std::path::Path;
use std::time::{Duration, SystemTime};
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "ACCOUNTANT";
pub const DEFAULT_PENDING_TRANSACTION_SCAN_INTERVAL: u64 = 3600;
pub const DEFAULT_PAYABLES_SCAN_INTERVAL: u64 = 3600;
pub const DEFAULT_RECEIVABLES_SCAN_INTERVAL: u64 = 3600;

const SECONDS_PER_DAY: i64 = 86_400;

lazy_static! {
    pub static ref PAYMENT_CURVES: PaymentCurves = PaymentCurves {
        payment_suggested_after_sec: SECONDS_PER_DAY,
        payment_grace_before_ban_sec: SECONDS_PER_DAY,
        permanent_debt_allowed_gwub: 10_000_000,
        balance_to_decrease_from_gwub: 1_000_000_000,
        balance_decreases_for_sec: 30 * SECONDS_PER_DAY,
        unban_when_balance_below_gwub: 10_000_000,
    };
}

pub const DEFAULT_PENDING_TOO_LONG_SEC: u64 = 21_600; //6 hours

#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PaymentCurves {
    pub payment_suggested_after_sec: i64,
    pub payment_grace_before_ban_sec: i64,
    pub permanent_debt_allowed_gwub: i64,
    pub balance_to_decrease_from_gwub: i64,
    pub balance_decreases_for_sec: i64,
    pub unban_when_balance_below_gwub: i64,
}

impl PaymentCurves {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - self.payment_suggested_after_sec - self.payment_grace_before_ban_sec
    }

    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - self.balance_decreases_for_sec
    }
}

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
    persistent_configuration: Box<dyn PersistentConfiguration>,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayable>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

#[derive(Debug, Eq, Message, PartialEq)]
pub struct ReceivedPayments {
    pub payments: Vec<Transaction>,
}

#[derive(Debug, Message, PartialEq)]
pub struct SentPayable {
    pub payable: Vec<Result<Payable, BlockchainError>>,
}

#[derive(Debug, Clone, Copy, Eq, Message, PartialEq)]
pub struct ScanForPayables {}

#[derive(Debug, Clone, Copy, Eq, Message, PartialEq)]
pub struct ScanForReceivables {}

#[derive(Debug, Clone, Copy, Eq, Message, PartialEq)]
pub struct ScanForPendingPayable {}

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
        ctx.notify(ScanForPendingPayable {});
        ctx.notify(ScanForPayables {});
        ctx.notify(ScanForReceivables {});
    }
}

macro_rules! notify_later_assertable {
    ($self: expr, $ctx: expr, $message_type: ident, $notify_later_handle_field: ident,$scan_interval_field: ident) => {
        let closure =
            Box::new(|msg: $message_type, interval: Duration| $ctx.notify_later(msg, interval));
        let _ = $self.tools.$notify_later_handle_field.notify_later(
            $message_type {},
            $self.config.$scan_interval_field,
            closure,
        );
    };
}

impl Handler<ScanForPayables> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: ScanForPayables, ctx: &mut Self::Context) -> Self::Result {
        self.scanners.payables.scan(self);
        notify_later_assertable!(
            self,
            ctx,
            ScanForPayables,
            notify_later_handle_scan_for_payable,
            payables_scan_interval
        );
    }
}

impl Handler<ScanForPendingPayable> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: ScanForPendingPayable, ctx: &mut Self::Context) -> Self::Result {
        self.scanners.pending_payable.scan(self);
        notify_later_assertable!(
            self,
            ctx,
            ScanForPendingPayable,
            notify_later_handle_scan_for_pending_payable,
            pending_payable_scan_interval
        );
    }
}

impl Handler<ScanForReceivables> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: ScanForReceivables, ctx: &mut Self::Context) -> Self::Result {
        self.scanners.receivables.scan(self);
        notify_later_assertable!(
            self,
            ctx,
            ScanForReceivables,
            notify_later_handle_scan_for_receivable,
            receivables_scan_interval
        );
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

#[derive(Debug, PartialEq, Message, Clone)]
pub struct RequestTransactionReceipts {
    pub pending_payable: Vec<PendingPayableFingerprint>,
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ReportTransactionReceipts {
    pub fingerprints_with_receipts: Vec<(Option<TransactionReceipt>, PendingPayableFingerprint)>,
}

impl Handler<ReportTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReportTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        debug!(
            self.logger,
            "Processing receipts for {} transactions",
            msg.fingerprints_with_receipts.len()
        );
        let statuses = self.handle_pending_transaction_with_its_receipt(msg);
        self.process_transaction_by_status(statuses, ctx)
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
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

#[derive(Debug, PartialEq, Message, Clone)]
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

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        let client_id = msg.client_id;
        if let Ok((body, context_id)) = UiFinancialsRequest::fmb(msg.clone().body) {
            self.handle_financials(client_id, context_id, body);
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
        config_dao_factory: Box<dyn ConfigDaoFactory>,
    ) -> Accountant {
        Accountant {
            config: config.accountant_config.clone(),
            consuming_wallet: config.consuming_wallet_opt.clone(),
            earning_wallet: config.earning_wallet.clone(),
            payable_dao: payable_dao_factory.make(),
            receivable_dao: receivable_dao_factory.make(),
            pending_payable_dao: pending_payable_dao_factory.make(),
            banned_dao: banned_dao_factory.make(),
            crashable: config.crash_point == CrashPoint::Message,
            scanners: Scanners::default(),
            tools: TransactionConfirmationTools::default(),
            persistent_configuration: Box::new(PersistentConfigurationReal::new(
                config_dao_factory.make(),
            )),
            report_accounts_payable_sub: None,
            retrieve_transactions_sub: None,
            report_new_payments_sub: None,
            report_sent_payments_sub: None,
            ui_message_sub: None,
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
            pending_payable_fingerprint: recipient!(addr, PendingPayableFingerprint),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayable),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, false, MigratorConfig::panic_on_migration())
    }

    fn scan_for_payables(&self) {
        debug!(self.logger, "Scanning for payables");

        let all_non_pending_payables = self.payable_dao.non_pending_payables();
        debug!(
            self.logger,
            "{}",
            Self::investigate_debt_extremes(&all_non_pending_payables)
        );
        let qualified_payables = all_non_pending_payables
            .into_iter()
            .filter(Accountant::should_pay)
            .collect::<Vec<PayableAccount>>();
        info!(
            self.logger,
            "Chose {} qualified debts to pay",
            qualified_payables.len()
        );
        debug!(
            self.logger,
            "{}",
            Self::payables_debug_summary(&qualified_payables)
        );
        if !qualified_payables.is_empty() {
            self.report_accounts_payable_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(ReportAccountsPayable {
                    accounts: qualified_payables,
                })
                .expect("BlockchainBridge is dead")
        }
    }

    fn scan_for_delinquencies(&self) {
        debug!(self.logger, "Scanning for delinquencies");
        let now = SystemTime::now();
        self.receivable_dao
            .new_delinquencies(now, &PAYMENT_CURVES)
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
            .paid_delinquencies(&PAYMENT_CURVES)
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

    fn scan_for_received_payments(&self) {
        debug!(
            self.logger,
            "Scanning for receivables to {}", self.earning_wallet
        );
        let start_block = match self.persistent_configuration.start_block() {
            Ok(start_block) => start_block,
            Err(pce) => {
                error!(
                    self.logger,
                    "Could not retrieve start block: {:?} - aborting received-payment scan", pce
                );
                return;
            }
        };
        self.retrieve_transactions_sub
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .try_send(RetrieveTransactions {
                start_block,
                recipient: self.earning_wallet.clone(),
            })
            .expect("BlockchainBridge is dead");
    }

    fn scan_for_pending_payable(&self) {
        debug!(self.logger, "Scanning for pending payable");
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

    fn should_pay(payable: &PayableAccount) -> bool {
        Self::payable_exceeded_threshold(payable).is_some()
    }

    fn payable_exceeded_threshold(payable: &PayableAccount) -> Option<u64> {
        // TODO: This calculation should be done in the database, if possible
        let time_since_last_paid = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if time_since_last_paid <= PAYMENT_CURVES.payment_suggested_after_sec as u64 {
            return None;
        }

        if payable.balance <= PAYMENT_CURVES.permanent_debt_allowed_gwub {
            return None;
        }

        let threshold = Accountant::calculate_payout_threshold(time_since_last_paid);
        if payable.balance as f64 > threshold {
            Some(threshold as u64)
        } else {
            None
        }
    }

    fn calculate_payout_threshold(x: u64) -> f64 {
        let m = -((PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - PAYMENT_CURVES.permanent_debt_allowed_gwub as f64)
            / (PAYMENT_CURVES.balance_decreases_for_sec as f64
                - PAYMENT_CURVES.payment_suggested_after_sec as f64));
        let b = PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - m * PAYMENT_CURVES.payment_suggested_after_sec as f64;
        m * x as f64 + b
    }

    fn record_service_provided(
        &self,
        service_rate: u64,
        byte_rate: u64,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.receivable_dao
                .as_ref()
                .more_money_receivable(wallet, total_charge) {
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
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        if !self.our_wallet(wallet) {
            match self.payable_dao
                .as_ref()
                .more_money_payable(wallet, total_charge) {
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
                    //seek for a test for this if you don't understand the purpose
                    let check_age_significance_across =
                        || -> bool { p.balance == biggest.balance && p_age > biggest.age };
                    if p.balance > biggest.balance || check_age_significance_across() {
                        biggest = PayableInfo {
                            balance: p.balance,
                            age: p_age,
                        }
                    }
                    let check_balance_significance_across =
                        || -> bool { p_age == oldest.age && p.balance > oldest.balance };
                    if p_age > oldest.age || check_balance_significance_across() {
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

    fn payables_debug_summary(qualified_payables: &[PayableAccount]) -> String {
        let now = SystemTime::now();
        let list = qualified_payables
            .iter()
            .map(|payable| {
                let p_age = now
                    .duration_since(payable.last_paid_timestamp)
                    .expect("Payable time is corrupt");
                let threshold =
                    Self::payable_exceeded_threshold(payable).expect("Threshold suddenly changed!");
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
        if msg.payments.is_empty() {
            warning!(self.logger, "Handling received payments we got zero payments but expected some, skipping database operations")
        } else {
            self.receivable_dao
                .as_mut()
                .more_money_received(msg.payments);
        }
    }

    fn handle_sent_payable(&self, sent_payable: SentPayable) {
        let (ok, err) = Self::separate_early_errors(sent_payable, &self.logger);
        debug!(self.logger, "We gathered these errors at sending transactions for payable: {:?}, out of the total of {} attempts", err, ok.len() + err.len());
        self.mark_pending_payable(ok);
        if !err.is_empty() {
            err.into_iter().for_each(|err|
            if let Some(hash) = err.carries_transaction_hash(){
                self.discard_incomplete_transaction_with_a_failure(hash)
            } else {debug!(self.logger,"Forgetting a transaction attempt that even did not reach the signing stage")})
        }
    }

    fn discard_incomplete_transaction_with_a_failure(&self, hash: H256) {
        if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(hash) {
            debug!(
                self.logger,
                "Deleting an existing backup for a failed transaction {}", hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                panic!("Database unmaintainable; payable fingerprint deletion for transaction {:?} has stayed undone due to {:?}", hash,e)
            }
        };

        warning!(
            self.logger,
            "Failed transaction with a hash '{}' but without the record - thrown out",
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
            msg.payload_size,
            &msg.earning_wallet,
        );
    }

    fn handle_financials(&mut self, client_id: u64, context_id: u64, request: UiFinancialsRequest) {
        let payables = self
            .payable_dao
            .top_records(request.payable_minimum_amount, request.payable_maximum_age)
            .iter()
            .map(|account| UiPayableAccount {
                wallet: account.wallet.to_string(),
                age: SystemTime::now()
                    .duration_since(account.last_paid_timestamp)
                    .expect("Bad interval")
                    .as_secs(),
                amount: account.balance as u64,
                pending_payable_hash_opt: account
                    .pending_payable_opt
                    .as_ref()
                    .map(|PendingPayableId { hash, .. }| format!("{:?}", hash)),
            })
            .collect_vec();
        let total_payable = self.payable_dao.total();
        let receivables = self
            .receivable_dao
            .top_records(
                request.receivable_minimum_amount,
                request.receivable_maximum_age,
            )
            .iter()
            .map(|account| UiReceivableAccount {
                wallet: account.wallet.to_string(),
                age: SystemTime::now()
                    .duration_since(account.last_received_timestamp)
                    .expect("Bad interval")
                    .as_secs(),
                amount: account.balance as u64,
            })
            .collect_vec();
        let total_receivable = self.receivable_dao.total();
        let body = UiFinancialsResponse {
            payables,
            total_payable,
            receivables,
            total_receivable,
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

    fn handle_cancel_pending_transaction(&self, msg: CancelFailedPendingTransaction) {
        match self
            .pending_payable_dao
            .mark_failure(msg.id.rowid)
        {
            Ok(_) => warning!(
                self.logger,
                "Broken transaction {} left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you", msg.id.hash),
            Err(e) => panic!("Unsuccessful attempt for transaction {} to mark fatal error at payable fingerprint due to {:?}; database unreliable", msg.id.hash,e),
        }
    }

    fn handle_confirm_pending_transaction(&self, msg: ConfirmPendingTransaction) {
        if let Err(e) = self
            .payable_dao
            .transaction_confirmed(&msg.pending_payable_fingerprint)
        {
            panic!(
                "Was unable to uncheck pending payable '{}' after confirmation due to '{:?}'",
                msg.pending_payable_fingerprint.hash, e
            )
        } else {
            debug!(
                self.logger,
                "Confirmation of transaction {}; record for payable was modified",
                msg.pending_payable_fingerprint.hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(
                msg.pending_payable_fingerprint
                    .rowid_opt
                    .expectv("initialized rowid"),
            ) {
                panic!("Was unable to delete payable fingerprint '{}' after successful transaction due to '{:?}'",msg.pending_payable_fingerprint.hash,e)
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
        sent_payments: SentPayable,
        logger: &Logger,
    ) -> (Vec<Payable>, Vec<BlockchainError>) {
        sent_payments
            .payable
            .into_iter()
            .fold((vec![],vec![]),|so_far,payment| {
                match payment{
                    Ok(payment_sent) => (plus(so_far.0,payment_sent),so_far.1),
                    Err(error) => {
                        logger.warning(|| match &error {
                            BlockchainError::TransactionFailed { .. } => format!("Encountered transaction error at this end: '{:?}'", error),
                            x => format!("Outbound transaction failure due to '{:?}'. Please check your blockchain service URL configuration.", x)
                        });
                        (so_far.0,plus(so_far.1,error))
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
                    None => panic!("Payable fingerprint for {} doesn't exist but should by now; system unreliable", payable.tx_hash)
                };
                match self.payable_dao.as_ref().mark_pending_payable_rowid(&payable.to, rowid ) {
                    Ok(()) => (),
                    Err(e) => panic!("Was unable to create a mark in payables for a new pending payable '{}' due to '{:?}'", payable.tx_hash, e)
                }
                debug!(self.logger, "Payable '{}' has been marked as pending in the payable table",payable.tx_hash)
            })
    }

    fn handle_pending_transaction_with_its_receipt(
        &self,
        msg: ReportTransactionReceipts,
    ) -> Vec<PendingTransactionStatus> {
        fn handle_none_receipt(
            payable: PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            debug!(logger,
                "DEBUG: Accountant: Interpreting a receipt for transaction '{}' but none was given; attempt {}, {}ms since sending",
                payable.hash, payable.attempt_opt.expectv("initialized attempt"),elapsed_in_ms(payable.timestamp)
            );
            PendingTransactionStatus::StillPending(PendingPayableId {
                hash: payable.hash,
                rowid: payable.rowid_opt.expectv("initialized rowid"),
            })
        }
        msg.fingerprints_with_receipts
            .into_iter()
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
        receipt: TransactionReceipt,
        fingerprint: PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        fn handle_none_status(
            fingerprint: PendingPayableFingerprint,
            pending_interval: u64,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(logger,"Pending transaction '{}' couldn't be confirmed at attempt {} at {}ms after its sending",fingerprint.hash, fingerprint.attempt_opt.expectv("initialized attempt"), elapsed_in_ms(fingerprint.timestamp));
            let elapsed = fingerprint
                .timestamp
                .elapsed()
                .expect("we should be older now");
            let transaction_id = PendingPayableId {
                hash: fingerprint.hash,
                rowid: fingerprint.rowid_opt.expectv("initialized rowid"),
            };
            if pending_interval <= elapsed.as_secs() {
                error!(logger,"Pending transaction '{}' has exceeded the maximum pending time ({}sec) and the confirmation process is going to be aborted now at the final attempt {}; \
                 manual resolution is required from the user to complete the transaction.",fingerprint.hash,pending_interval,fingerprint.attempt_opt.expectv("initialized attempt"));
                PendingTransactionStatus::Failure(transaction_id)
            } else {
                PendingTransactionStatus::StillPending(transaction_id)
            }
        }
        fn handle_status_with_success(
            fingerprint: PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(
                logger,
                "Transaction '{}' has been added to the blockchain; detected locally at attempt {} at {}ms after its sending",
                fingerprint.hash,
                fingerprint.attempt_opt.expectv("initialized attempt"),
                elapsed_in_ms(fingerprint.timestamp)
            );
            PendingTransactionStatus::Confirmed(fingerprint)
        }
        fn handle_status_with_failure(
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            error!(logger,"Pending transaction '{}' announced as a failure, interpreting attempt {} after {}ms from the sending",fingerprint.hash,fingerprint.attempt_opt.expectv("initialized attempt"),elapsed_in_ms(fingerprint.timestamp));
            PendingTransactionStatus::Failure(fingerprint.into())
        }
        match receipt.status{
                None => handle_none_status(fingerprint, self.config.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64(){
                    0 => handle_status_with_failure(&fingerprint, logger),
                    1 => handle_status_with_success(fingerprint, logger),
                    other => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}", fingerprint.hash, other)
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

    fn process_transaction_by_status(
        &self,
        statuses: Vec<PendingTransactionStatus>,
        ctx: &mut Context<Self>,
    ) {
        statuses.into_iter().for_each(|status| {
            if let PendingTransactionStatus::StillPending(transaction_id) = status {
                self.update_payable_fingerprint(transaction_id)
            } else if let PendingTransactionStatus::Failure(transaction_id) = status {
                self.cancel_failed_transaction(transaction_id, ctx)
            } else if let PendingTransactionStatus::Confirmed(fingerprint) = status {
                self.confirm_transaction(fingerprint, ctx)
            }
        });
    }

    fn cancel_failed_transaction(&self, transaction_id: PendingPayableId, ctx: &mut Context<Self>) {
        let closure = |msg: CancelFailedPendingTransaction| ctx.notify(msg);
        self.tools.notify_handle_cancel_failed_transaction.notify(
            CancelFailedPendingTransaction { id: transaction_id },
            Box::new(closure),
        )
    }

    fn confirm_transaction(
        &self,
        pending_payable_fingerprint: PendingPayableFingerprint,
        ctx: &mut Context<Self>,
    ) {
        let closure = |msg: ConfirmPendingTransaction| ctx.notify(msg);
        self.tools.notify_handle_confirm_transaction.notify(
            ConfirmPendingTransaction {
                pending_payable_fingerprint,
            },
            Box::new(closure),
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
                "Failed to make a fingerprint for pending payable '{}' due to '{:?}'", msg.hash, e
            ),
        }
    }
}

pub fn unsigned_to_signed(unsigned: u64) -> Result<i64, u64> {
    i64::try_from(unsigned).map_err(|_| unsigned)
}

fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

#[derive(Debug, PartialEq, Clone)]
enum PendingTransactionStatus {
    StillPending(PendingPayableId), //updates slightly the record, waits an interval and starts a new round
    Failure(PendingPayableId),      //official tx failure
    Confirmed(PendingPayableFingerprint), //tx was fully processed and successful
}

#[derive(Debug, PartialEq, Clone, Copy)]
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
    use crate::accountant::payable_dao::PayableDaoError;
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::{
        bc_from_ac_plus_earning_wallet, bc_from_ac_plus_wallets, make_pending_payable_fingerprint,
        make_receivable_account, BannedDaoFactoryMock, ConfigDaoFactoryMock, PayableDaoFactoryMock,
        PayableDaoMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock,
        ReceivableDaoFactoryMock, ReceivableDaoMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::tools::accountant_tools::NullScanner;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::blockchain::blockchain_interface::Transaction;
    use crate::blockchain::test_utils::BlockchainInterfaceMock;
    use crate::blockchain::tool_wrappers::SendTransactionToolsWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        prove_that_crash_request_handler_is_hooked_up, CleanUpMessage, DummyActor,
        NotifyHandleMock, NotifyLaterHandleMock,
    };
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::{Arbiter, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
    use std::cell::RefCell;
    use std::ops::Sub;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::time::Duration;
    use std::time::SystemTime;
    use web3::types::U256;
    use web3::types::{TransactionReceipt, H256};

    #[test]
    fn constants_have_correct_values() {
        let payment_curves_expected: PaymentCurves = PaymentCurves {
            payment_suggested_after_sec: SECONDS_PER_DAY,
            payment_grace_before_ban_sec: SECONDS_PER_DAY,
            permanent_debt_allowed_gwub: 10_000_000,
            balance_to_decrease_from_gwub: 1_000_000_000,
            balance_decreases_for_sec: 30 * SECONDS_PER_DAY,
            unban_when_balance_below_gwub: 10_000_000,
        };

        assert_eq!(CRASH_KEY, "ACCOUNTANT");
        assert_eq!(DEFAULT_PENDING_TRANSACTION_SCAN_INTERVAL, 3600);
        assert_eq!(DEFAULT_PAYABLES_SCAN_INTERVAL, 3600);
        assert_eq!(DEFAULT_RECEIVABLES_SCAN_INTERVAL, 3600);
        assert_eq!(SECONDS_PER_DAY, 86_400);
        assert_eq!(DEFAULT_PENDING_TOO_LONG_SEC, 21_600);
        assert_eq!(*PAYMENT_CURVES, payment_curves_expected);
    }

    #[test]
    fn new_calls_factories_properly() {
        let config = BootstrapperConfig::new();
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
        let config_dao_factory_called = Rc::new(RefCell::new(false));
        let config_dao = ConfigDaoMock::new();
        let config_dao_factory =
            ConfigDaoFactoryMock::new(config_dao).called(&config_dao_factory_called);

        let _ = Accountant::new(
            &config,
            Box::new(payable_dao_factory),
            Box::new(receivable_dao_factory),
            Box::new(pending_payable_dao_factory),
            Box::new(banned_dao_factory),
            Box::new(config_dao_factory),
        );

        assert_eq!(payable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(receivable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(
            pending_payable_dao_factory_called.as_ref(),
            &RefCell::new(true)
        );
        assert_eq!(banned_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(config_dao_factory_called.as_ref(), &RefCell::new(true));
    }

    #[test]
    fn financials_request_produces_financials_response() {
        let payable_top_records_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .top_records_parameters(&payable_top_records_parameters_arc)
            .top_records_result(vec![
                PayableAccount {
                    wallet: make_wallet("earning 1"),
                    balance: 12345678,
                    last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(10000)),
                    pending_payable_opt: Some(PendingPayableId {
                        rowid: 789,
                        hash: H256::from_uint(&U256::from(3333333)),
                    }),
                },
                PayableAccount {
                    wallet: make_wallet("earning 2"),
                    balance: 12345679,
                    last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(10001)),
                    pending_payable_opt: None,
                },
            ])
            .total_result(23456789);
        let receivable_top_records_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .top_records_parameters(&receivable_top_records_parameters_arc)
            .top_records_result(vec![
                ReceivableAccount {
                    wallet: make_wallet("consuming 1"),
                    balance: 87654321,
                    last_received_timestamp: SystemTime::now().sub(Duration::from_secs(20000)),
                },
                ReceivableAccount {
                    wallet: make_wallet("consuming 2"),
                    balance: 87654322,
                    last_received_timestamp: SystemTime::now().sub(Duration::from_secs(20001)),
                },
            ])
            .total_result(98765432);
        let system = System::new("test");
        let subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_millis(10_000),
                    receivables_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_millis(10_000),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
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
            body: MessageBody {
                opcode: "financials".to_string(),
                path: Conversation(2222),
                payload: Ok(r#"{"payableMinimumAmount": 50001, "payableMaximumAge": 50002, "receivableMinimumAmount": 50003, "receivableMaximumAge": 50004}"#.to_string()),
            }
        };

        subject_addr.try_send(ui_message).unwrap();

        System::current().stop();
        system.run();
        let payable_top_records_parameters = payable_top_records_parameters_arc.lock().unwrap();
        assert_eq!(*payable_top_records_parameters, vec![(50001, 50002)]);
        let receivable_top_records_parameters =
            receivable_top_records_parameters_arc.lock().unwrap();
        assert_eq!(*receivable_top_records_parameters, vec![(50003, 50004)]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<NodeToUiMessage>(0);
        assert_eq!(response.target, MessageTarget::ClientId(1234));
        assert_eq!(response.body.opcode, "financials".to_string());
        assert_eq!(response.body.path, Conversation(2222));
        let parsed_payload =
            serde_json::from_str::<UiFinancialsResponse>(&response.body.payload.as_ref().unwrap())
                .unwrap();
        assert_eq!(
            parsed_payload,
            UiFinancialsResponse {
                payables: vec![
                    UiPayableAccount {
                        wallet: "0x00000000000000000000006561726e696e672031".to_string(),
                        age: 10000,
                        amount: 12345678,
                        pending_payable_hash_opt: Some(
                            "0x000000000000000000000000000000000000000000000000000000000032dcd5"
                                .to_string()
                        )
                    },
                    UiPayableAccount {
                        wallet: "0x00000000000000000000006561726e696e672032".to_string(),
                        age: 10001,
                        amount: 12345679,
                        pending_payable_hash_opt: None,
                    }
                ],
                total_payable: 23456789,
                receivables: vec![
                    UiReceivableAccount {
                        wallet: "0x000000000000000000636f6e73756d696e672031".to_string(),
                        age: 20000,
                        amount: 87654321,
                    },
                    UiReceivableAccount {
                        wallet: "0x000000000000000000636f6e73756d696e672032".to_string(),
                        age: 20001,
                        amount: 87654322,
                    }
                ],
                total_receivable: 98765432
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
                AccountantConfig {
                    payables_scan_interval: Duration::from_millis(10_000),
                    receivables_scan_interval: Duration::from_millis(10_000),
                    pending_payable_scan_interval: Duration::from_millis(10_000),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
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
        let sent_payable = SentPayable {
            payable: vec![Ok(expected_payable.clone())],
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
        let sent_payable = SentPayable {
            payable: vec![Err(BlockchainError::TransactionFailed {
                msg: "SQLite migraine".to_string(),
                hash_opt: Some(H256::from_uint(&U256::from(12345))),
            })],
        };
        let subject = accountant.start();

        subject
            .try_send(sent_payable)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let log_handler = TestLogHandler::new();
        log_handler.exists_no_log_containing(
            "DEBUG: Accountant: Deleting an existing backup for a failed transaction",
        );
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error at this end: 'TransactionFailed \
         { msg: \"SQLite migraine\", hash_opt: Some(0x0000000000000000000000000000000000000000000000000000000000003039) }'");
        log_handler.exists_log_containing(
            r#"WARN: Accountant: Failed transaction with a hash '0x0000…3039' but without the record - thrown out"#,
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
        let sent_payable = SentPayable {
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
            "DEBUG: Accountant: Deleting an existing backup for a failed transaction 0x0000…3039",
        );
    }

    #[test]
    fn accountant_sends_report_accounts_payable_to_blockchain_bridge_when_qualified_payable_found()
    {
        let (blockchain_bridge, _, blockchain_bridge_recording_arc) = make_recorder();
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("blah"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 55,
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now()) - PAYMENT_CURVES.payment_suggested_after_sec - 5,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("foo"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 66,
                last_paid_timestamp: from_time_t(
                    to_time_t(SystemTime::now()) - PAYMENT_CURVES.payment_suggested_after_sec - 500,
                ),
                pending_payable_opt: None,
            },
        ];
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(accounts.clone());
        let system = System::new("report_accounts_payable forwarded to blockchain_bridge");
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_secs(100_000),
                    receivables_scan_interval: Duration::from_secs(100_000),
                    pending_payable_scan_interval: Duration::from_secs(100_000),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                make_wallet("some_wallet_address"),
            ))
            .payable_dao(payable_dao)
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner);
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
            vec![&ReportAccountsPayable { accounts }]
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
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(1_000_000));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payables_scan_interval: Duration::from_secs(100_000),
                    receivables_scan_interval: Duration::from_secs(100_000),
                    pending_payable_scan_interval: Duration::from_secs(100_000),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                earning_wallet.clone(),
            ))
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .persistent_config(persistent_config)
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner);
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
                start_block: 1_000_000,
                recipient: earning_wallet.clone()
            }
        );
    }

    #[test]
    fn accountant_receives_new_payments_to_the_receivables_dao() {
        let earning_wallet = make_wallet("earner3000");
        let expected_receivable_1 = Transaction {
            block_number: 7,
            from: make_wallet("wallet0"),
            gwei_amount: 456,
        };
        let expected_receivable_2 = Transaction {
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
                AccountantConfig {
                    payables_scan_interval: Duration::from_secs(10_000),
                    receivables_scan_interval: Duration::from_secs(10_000),
                    pending_payable_scan_interval: Duration::from_secs(10_000),
                    when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
                },
                earning_wallet.clone(),
            ))
            .payable_dao(PayableDaoMock::new().non_pending_payables_result(vec![]))
            .receivable_dao(receivable_dao)
            .build();
        let system = System::new("accountant_receives_new_payments_to_the_receivables_dao");
        let subject = accountant.start();

        subject
            .try_send(ReceivedPayments {
                payments: vec![expected_receivable_1.clone(), expected_receivable_2.clone()],
            })
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(
            *more_money_received_params,
            vec![vec![expected_receivable_1, expected_receivable_2]]
        )
    }

    #[test]
    fn accountant_scans_after_startup() {
        init_test_logging();
        let return_all_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let new_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_params_arc = Arc::new(Mutex::new(vec![]));
        let start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let (blockchain_bridge, _, _) = make_recorder();
        let system = System::new("accountant_scans_after_startup");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100), //making sure we cannot enter the first repeated scanning
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_millis(100), //except here, where we use it to stop the system
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
        let persistent_config = PersistentConfigurationMock::default()
            .start_block_params(&start_block_params_arc)
            .start_block_result(Ok(123456));
        let subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .receivable_dao(receivable_dao)
            .pending_payable_dao(pending_payable_dao)
            .persistent_config(persistent_config)
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
        tlh.await_log_containing("DEBUG: Accountant: Scanning for payables", 1000u64);
        tlh.exists_log_containing(&format!(
            "DEBUG: Accountant: Scanning for receivables to {}",
            make_wallet("hi")
        ));
        tlh.exists_log_containing("DEBUG: Accountant: Scanning for delinquencies");
        tlh.exists_log_containing("DEBUG: Accountant: Scanning for pending payable");
        //some more weak proofs but still good enough
        //proof of calling a piece of scan_for_pending_payable
        let return_all_fingerprints_params = return_all_fingerprints_params_arc.lock().unwrap();
        //the last ends this test calling System::current.stop()
        assert_eq!(*return_all_fingerprints_params, vec![(), ()]);
        //proof of calling a piece of scan_for_payable()
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        assert_eq!(*non_pending_payables_params, vec![()]);
        //proof of calling a piece of scan_for_receivable()
        let start_block_params = start_block_params_arc.lock().unwrap();
        assert_eq!(*start_block_params, vec![()]);
        //proof of calling pieces of scan_for_delinquencies()
        let mut new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        let (captured_timestamp, captured_curves) = new_delinquencies_params.remove(0);
        assert!(new_delinquencies_params.is_empty());
        assert!(
            captured_timestamp < SystemTime::now()
                && captured_timestamp >= from_time_t(to_time_t(SystemTime::now()) - 5)
        );
        assert_eq!(captured_curves, *PAYMENT_CURVES);
        let paid_delinquencies_params = paid_delinquencies_params_arc.lock().unwrap();
        assert_eq!(paid_delinquencies_params.len(), 1);
        assert_eq!(paid_delinquencies_params[0], *PAYMENT_CURVES);
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
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_millis(99),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(5))
            .start_block_result(Ok(8))
            .start_block_result(Ok(10));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .persistent_config(persistent_config)
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner);
        subject.scanners.payables = Box::new(NullScanner);
        subject.tools.notify_later_handle_scan_for_receivable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_receivable_params_arc),
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
                    start_block: 5,
                    recipient: earning_wallet.clone()
                },
                &RetrieveTransactions {
                    start_block: 8,
                    recipient: earning_wallet.clone()
                },
                &RetrieveTransactions {
                    start_block: 10,
                    recipient: earning_wallet.clone()
                }
            ]
        );
        //sadly I cannot effectively assert on the exact params
        //they are a) real timestamp of now, b) constant payment_curves
        //the Rust type system gives me enough support to be okay with counting occurrences
        let new_delinquencies_params = new_delinquencies_params_arc.lock().unwrap();
        assert_eq!(new_delinquencies_params.len(), 3); //the third one is the signal to shut the system down
        let ban_params = ban_params_arc.lock().unwrap();
        assert_eq!(*ban_params, vec![wallet_to_be_banned]);
        let notify_later_receivable_params = notify_later_receivable_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_receivable_params,
            vec![
                (ScanForReceivables {}, Duration::from_millis(99)),
                (ScanForReceivables {}, Duration::from_millis(99)),
                (ScanForReceivables {}, Duration::from_millis(99))
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
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_millis(98),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(123456));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .pending_payable_dao(pending_payable_dao)
            .persistent_config(persistent_config)
            .build();
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.scanners.payables = Box::new(NullScanner); //skipping
        subject.tools.notify_later_handle_scan_for_pending_payable = Box::new(
            NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_pending_payable_params_arc),
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
            }
        );
        let notify_later_pending_payable_params =
            notify_later_pending_payable_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_pending_payable_params,
            vec![
                (ScanForPendingPayable {}, Duration::from_millis(98)),
                (ScanForPendingPayable {}, Duration::from_millis(98)),
                (ScanForPendingPayable {}, Duration::from_millis(98))
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
                payables_scan_interval: Duration::from_millis(97),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let now = to_time_t(SystemTime::now());
        // slightly above minimum balance, to the right of the curve (time intersection)
        let account = PayableAccount {
            wallet: make_wallet("wallet"),
            balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 5,
            last_paid_timestamp: from_time_t(now - PAYMENT_CURVES.balance_decreases_for_sec - 10),
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
        let persistent_config =
            PersistentConfigurationMock::default().start_block_result(Ok(123456));
        let mut subject = AccountantBuilder::default()
            .bootstrapper_config(config)
            .payable_dao(payable_dao)
            .persistent_config(persistent_config)
            .build();
        subject.scanners.pending_payable = Box::new(NullScanner); //skipping
        subject.scanners.receivables = Box::new(NullScanner); //skipping
        subject.tools.notify_later_handle_scan_for_payable = Box::new(
            NotifyLaterHandleMock::default().notify_later_params(&notify_later_payables_params_arc),
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
                accounts: vec![account]
            }
        );
        let notify_later_payables_params = notify_later_payables_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_payables_params,
            vec![
                (ScanForPayables {}, Duration::from_millis(97)),
                (ScanForPayables {}, Duration::from_millis(97)),
                (ScanForPayables {}, Duration::from_millis(97))
            ]
        )
    }

    #[test]
    fn scan_for_payable_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(1000),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub - 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payable_opt: None,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec + 10,
                ),
                pending_payable_opt: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub - 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 1,
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

        subject.scan_for_payables();

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
                payables_scan_interval: Duration::from_millis(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
        let now = to_time_t(SystemTime::now());
        let accounts = vec![
            // slightly above minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payable_opt: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 10,
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
        subject.scanners.pending_payable = Box::new(NullScanner);
        subject.scanners.receivables = Box::new(NullScanner);
        let subject_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&subject_addr);
        send_bind_message!(accountant_subs, peer_actors);

        send_start_message!(accountant_subs);

        system.run();
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable { accounts }
        );
    }

    #[test]
    fn scan_for_received_payments_handles_error_retrieving_start_block() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::NotPresent));
        let subject = AccountantBuilder::default()
            .persistent_config(persistent_config)
            .build();

        subject.scan_for_received_payments();

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("ERROR: Accountant: Could not retrieve start block: NotPresent - aborting received-payment scan");
    }

    #[test]
    fn scan_for_delinquencies_triggers_bans_and_unbans() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(1000),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("mine"),
        );
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

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentCurves)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), new_delinquencies_parameters[0].1);
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentCurves>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), paid_delinquencies_parameters[0]);
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

        let _ = subject.scan_for_pending_payable();

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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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

        let _ = account_addr.try_send(ScanForPendingPayable {}).unwrap();

        let dummy_actor = DummyActor::new(None);
        let dummy_addr = dummy_actor.start();
        dummy_addr
            .try_send(CleanUpMessage { sleep_ms: 10 })
            .unwrap();
        system.run();
        let blockchain_bridge_recording = blockchain_bridge_recording_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recording.len(), 1);
        let received_msg = blockchain_bridge_recording.get_record::<RequestTransactionReceipts>(0);
        assert_eq!(
            received_msg,
            &RequestTransactionReceipts {
                pending_payable: vec![payable_fingerprint_1, payable_fingerprint_2]
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Found 2 pending payables to process");
    }

    #[test]
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
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

        let paying_wallet = make_wallet("booga");
        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
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
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
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
    fn handle_received_payments_aborts_if_no_payments_supplied() {
        init_test_logging();
        let mut subject = AccountantBuilder::default().build();
        let msg = ReceivedPayments { payments: vec![] };

        let _ = subject.handle_received_payments(msg);

        TestLogHandler::new().exists_log_containing("WARN: Accountant: Handling received payments we got zero payments but expected some, skipping database operations");
    }

    #[test]
    fn report_exit_service_consumed_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
            (make_wallet("booga"), (1 * 42) + (1234 * 24))
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
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            },
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
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
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

        let _ = subject.record_service_provided(i64::MAX as u64, 1, 2, &wallet);
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

        subject.record_service_provided(i64::MAX as u64, 1, 2, &wallet);

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

        subject.record_service_consumed(service_rate, 1, 2, &wallet);

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

        let _ = subject.record_service_consumed(i64::MAX as u64, 1, 2, &wallet);
    }

    #[test]
    #[should_panic(
        expected = "Was unable to create a mark in payables for a new pending payable '0x0000…007b' due to 'SignConversion(9999999999999)'"
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
        let sent_payable = SentPayable {
            payable: vec![Err(BlockchainError::TransactionFailed {
                msg: "blah".to_string(),
                hash_opt: Some(hash),
            })],
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_result(Some(rowid))
            .delete_fingerprint_result(Err(PendingPayableDaoError::RecordDeletion(
                "we slept over, sorry".to_string(),
            )));
        let subject = AccountantBuilder::default()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.handle_sent_payable(sent_payable);
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
        let sent_payable = SentPayable {
            payable: vec![payable_1, Ok(payable_2.clone()), payable_3],
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(payable_2_rowid));
        let subject = AccountantBuilder::default()
            .payable_dao(PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(())))
            .pending_payable_dao(pending_payable_dao)
            .build();

        subject.handle_sent_payable(sent_payable);

        let fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(*fingerprint_rowid_params, vec![payable_hash_2]); //we know the other two errors are associated with an initiated transaction having a backup
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Outbound transaction failure due to 'InvalidResponse'. Please check your blockchain service URL configuration.");
        log_handler.exists_log_containing("DEBUG: Accountant: Payable '0x0000…00a6' has been marked as pending in the payable table");
        log_handler.exists_log_containing("WARN: Accountant: Encountered transaction error at this end: 'TransactionFailed { msg: \"closing hours, sorry\", hash_opt: None }'");
        log_handler.exists_log_containing("DEBUG: Accountant: Forgetting a transaction attempt that even did not reach the signing stage");
    }

    #[test]
    #[should_panic(
        expected = "Payable fingerprint for 0x0000…0315 doesn't exist but should by now; system unreliable"
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
        let subject = AccountantBuilder::default()
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
        log_handler.exists_log_containing("DEBUG: Accountant: Confirmation of transaction 0x051a…8c19; record for payable was modified");
        log_handler.exists_log_containing("INFO: Accountant: Transaction 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 has gone through the whole confirmation process succeeding");
    }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payable '0x0000…0315' after confirmation due to 'RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirm_pending_transaction_panics_on_unchecking_payable_table() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let subject = AccountantBuilder::default()
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
        expected = "Was unable to delete payable fingerprint '0x0000…0315' after successful transaction due to 'RecordDeletion(\"the database is fooling around with us\")'"
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
        let subject = AccountantBuilder::default()
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
            "WARN: Accountant: Broken transaction 0x051a…8c19 left with an error mark; you should take over \
             the care of this transaction to make sure your debts will be paid because there is no automated process that can fix this without you",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transaction 0x051a…8c19 to mark fatal error at payable fingerprint due to UpdateFailed(\"no no no\")"
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
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1234,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1,
                ),
                pending_payable_opt: None,
            },
        ];

        let result = Accountant::payables_debug_summary(qualified_payables);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
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
        let payable_timestamp_1 = SystemTime::now().sub(Duration::from_secs(
            (PAYMENT_CURVES.payment_suggested_after_sec + 555) as u64,
        ));
        let payable_timestamp_2 = SystemTime::now().sub(Duration::from_secs(
            (PAYMENT_CURVES.payment_suggested_after_sec + 50) as u64,
        ));
        let payable_account_balance_1 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 10;
        let payable_account_balance_2 = PAYMENT_CURVES.balance_to_decrease_from_gwub + 666;
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
            .send_transaction_result(Ok((pending_tx_hash_1, payable_timestamp_1)))
            .send_transaction_result(Ok((pending_tx_hash_2, payable_timestamp_2)))
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
            last_paid_timestamp: payable_timestamp_1,
            pending_payable_opt: None,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: payable_account_balance_2,
            last_paid_timestamp: payable_timestamp_2,
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
                payables_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                receivables_scan_interval: Duration::from_secs(1_000_000), //we don't care about this scan
                pending_payable_scan_interval: Duration::from_millis(pending_payable_scan_interval),
                when_pending_too_long_sec: (PAYMENT_CURVES.payment_suggested_after_sec + 1000)
                    as u64,
            },
            make_wallet("some_wallet_address"),
        );
        let fingerprint_1_first_round = PendingPayableFingerprint {
            rowid_opt: Some(rowid_for_account_1),
            timestamp: payable_timestamp_1,
            hash: pending_tx_hash_1,
            attempt_opt: Some(1),
            amount: payable_account_balance_1 as u64,
            process_error: None,
        };
        let fingerprint_2_first_round = PendingPayableFingerprint {
            rowid_opt: Some(rowid_for_account_2),
            timestamp: payable_timestamp_2,
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
        let pending_payable_dao = PendingPayableDaoMock::default()
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
            //extra one, for a case when we are too fast at some machine
            .return_all_fingerprints_result(vec![])
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
            .delete_fingerprint_params(&delete_record_params_arc)
            //this is used during confirmation of the successful one
            .delete_fingerprint_result(Ok(()));
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
                    .notify_later_params(&notify_later_scan_for_pending_payable_arc_cloned);
                subject.tools.notify_later_handle_scan_for_pending_payable =
                    Box::new(notify_later_half_mock);
                let mut notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_cancel_failed_transaction_params_arc_cloned);
                notify_half_mock.do_you_want_to_proceed_after = true;
                subject.tools.notify_handle_cancel_failed_transaction = Box::new(notify_half_mock);
                let mut notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_confirm_transaction_params_arc_cloned);
                notify_half_mock.do_you_want_to_proceed_after = true;
                subject.tools.notify_handle_confirm_transaction = Box::new(notify_half_mock);
                subject
            });
        let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        peer_actors.accountant = accountant_subs.clone();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);

        send_start_message!(accountant_subs);

        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 1090 })
            .unwrap();
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
        //it varies with machines and sometimes we manage more cycles than necessary,
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
            ScanForPendingPayable {},
            Duration::from_millis(pending_payable_scan_interval),
        );
        let mut notify_later_check_for_confirmation =
            notify_later_scan_for_pending_payable_params_arc
                .lock()
                .unwrap();
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
            "WARN: Accountant: Broken transaction 0x0000…007b left with an error mark; you should take over the care of this transaction to make sure your debts will be paid because there \
             is no automated process that can fix this without you");
        log_handler.exists_log_matching("INFO: Accountant: Transaction '0x0000…0237' has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
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
        };

        let result = subject.handle_pending_transaction_with_its_receipt(msg.clone());

        assert_eq!(
            result,
            vec![PendingTransactionStatus::StillPending(PendingPayableId {
                hash,
                rowid
            })]
        );
        TestLogHandler::new().exists_log_matching("DEBUG: Accountant: Interpreting a receipt for transaction '0x0000…0913' but none was given; attempt 3, 100\\d\\dms since sending");
    }

    #[test]
    fn accountant_receives_reported_transaction_receipts_and_processes_them_all() {
        let notify_handle_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = AccountantBuilder::default().build();
        subject.tools.notify_handle_confirm_transaction =
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
            tx_receipt,
            fingerprint,
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
         transaction '0x0000…11d7' announced as a failure, interpreting attempt 5 after 1500\\d\\dms from the sending");
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
            tx_receipt,
            fingerprint.clone(),
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: receipt_check_logger: Pending \
         transaction '0x0000…0237' couldn't be confirmed at attempt 1 at 100ms after its sending",
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
            tx_receipt,
            fingerprint.clone(),
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: receipt_check_logger: Pending transaction '0x0000…0237' has exceeded the maximum \
             pending time (21600sec) and the confirmation process is going to be aborted now at the final attempt 10; manual resolution is required from the user to \
               complete the transaction",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b' - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = H256::from_uint(&U256::from(123));
        let subject = AccountantBuilder::default().build();

        let _ = subject.interpret_transaction_receipt(
            tx_receipt,
            fingerprint,
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
        TestLogHandler::new().exists_log_containing("ERROR: Accountant: Failed to make a fingerprint for pending payable '0x0000…01c8' due to 'InsertionFailed(\"Crashed\")'");
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
        let sent_payable = SentPayable {
            payable: vec![Ok(payable_ok.clone()), Err(error.clone())],
        };

        let (ok, err) = Accountant::separate_early_errors(sent_payable, &Logger::new("test"));

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
    fn jackass_unsigned_to_signed_handles_zero() {
        let result = unsigned_to_signed(0u64);

        assert_eq!(result, Ok(0i64));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_allowable() {
        let result = unsigned_to_signed(i64::MAX as u64);

        assert_eq!(result, Ok(i64::MAX));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_plus_one() {
        let attempt = (i64::MAX as u64) + 1;
        let result = unsigned_to_signed((i64::MAX as u64) + 1);

        assert_eq!(result, Err(attempt));
    }
}
