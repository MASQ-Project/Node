// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_dao;
pub mod pending_payments_dao;
pub mod receivable_dao;

#[cfg(test)]
pub mod test_utils;

use crate::accountant::payable_dao::{PayableAccount, PayableDaoFactory, Payment};
use crate::accountant::pending_payments_dao::{PendingPaymentsDao, PendingPaymentsDaoFactory};
use crate::accountant::receivable_dao::{ReceivableAccount, ReceivableDaoFactory};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::{
    PendingPaymentBackup, ReportTransactionReceipts, RetrieveTransactions,
};
use crate::blockchain::blockchain_interface::{BlockchainError, Transaction};
use crate::blockchain::tool_wrappers::{NotifyHandle, NotifyLaterHandle};
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
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Addr;
use actix::AsyncContext;
use actix::Context;
use actix::Handler;
use actix::Message;
use actix::Recipient;
use actix::{Actor, SpawnHandle};
use futures::future::Future;
use itertools::Itertools;
use lazy_static::lazy_static;
use masq_lib::crash_point::CrashPoint;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiFinancialsRequest};
use masq_lib::messages::{UiFinancialsResponse, UiPayableAccount, UiReceivableAccount};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use payable_dao::PayableDao;
use receivable_dao::ReceivableDao;
use std::default::Default;
use std::ops::Add;
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime};
use web3::types::{TransactionReceipt, H256};

pub const CRASH_KEY: &str = "ACCOUNTANT";
pub const DEFAULT_PAYABLE_SCAN_INTERVAL: u64 = 3600; // one hour
pub const DEFAULT_PAYMENT_RECEIVED_SCAN_INTERVAL: u64 = 3600; // one hour

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

//TODO this might become chain specific later on
pub const DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS: u64 = 5_000;

//TODO I may need to have two types for both payable and receivable
#[derive(Debug, PartialEq)]
pub enum DebtRecordingError {
    SignConversion(u64),
    RusqliteError(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum PaymentError {
    PreTransaction(PaymentErrorKind, H256),
    PostTransaction(PaymentErrorKind, H256),
}

#[derive(PartialEq, Debug, Clone)]
pub enum PaymentErrorKind {
    SignConversion(u64),
    RusqliteError(String),
    BlockchainError(String),
}

impl From<BlockchainError> for PaymentError {
    fn from(error: BlockchainError) -> Self {
        todo!()
    }
}

#[derive(PartialEq, Debug, Clone)]
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
    pending_payments_dao: Box<dyn PendingPaymentsDao>,
    banned_dao: Box<dyn BannedDao>,
    crashable: bool,
    transaction_confirmation: TransactionConfirmationTools,
    persistent_configuration: Box<dyn PersistentConfiguration>,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    retrieve_transactions_sub: Option<Recipient<RetrieveTransactions>>,
    report_new_payments_sub: Option<Recipient<ReceivedPayments>>,
    report_sent_payments_sub: Option<Recipient<SentPayments>>,
    ui_message_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

struct TransactionConfirmationTools {
    pending_transaction_check_interval_ms: u64,
    request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
    notify_handle_request_transaction_receipts:
        Box<dyn NotifyLaterHandle<RequestTransactionReceipts>>,
    notify_handle_cancel_failed_transaction: Box<dyn NotifyHandle<CancelFailedPendingTransaction>>,
    notify_handle_confirm_tx_after_success: Box<dyn NotifyHandle<ConfirmPendingTransaction>>,
}

impl TransactionConfirmationTools {
    fn new(pending_transaction_check_interval_ms: u64) -> Self {
        Self {
            pending_transaction_check_interval_ms,
            request_transaction_receipts_subs_opt: None,
            notify_handle_request_transaction_receipts: Default::default(),
            notify_handle_cancel_failed_transaction: Default::default(),
            notify_handle_confirm_tx_after_success: Default::default(),
        }
    }
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

#[derive(Debug, Eq, Message, PartialEq)]
pub struct ReceivedPayments {
    payments: Vec<Transaction>,
}

#[derive(Debug, Message, PartialEq)]
pub struct SentPayments {
    pub payments: Vec<Result<Payment, PaymentError>>,
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
        self.handle_start_message();

        ctx.run_interval(self.config.payable_scan_interval, |accountant, _ctx| {
            accountant.scan_for_payables();
        });

        ctx.run_interval(
            self.config.payment_received_scan_interval,
            |accountant, _ctx| {
                accountant.scan_for_received_payments();
                accountant.scan_for_delinquencies();
            },
        );
    }
}

impl Handler<ReceivedPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReceivedPayments, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_received_payments(msg);
    }
}

impl Handler<SentPayments> for Accountant {
    type Result = ();

    fn handle(&mut self, sent_payments: SentPayments, ctx: &mut Self::Context) -> Self::Result {
        let (ok, err) = self.handle_sent_payments(sent_payments);
        if !ok.is_empty() {
            let closure = |msg: RequestTransactionReceipts, dur: Duration| -> SpawnHandle {
                ctx.notify_later(msg, dur)
            };
            let _ = self
                .transaction_confirmation
                .notify_handle_request_transaction_receipts
                .notify_later(
                    RequestTransactionReceipts {
                        pending_payments: ok,
                        attempt: 1,
                    },
                    Duration::from_millis(
                        self.transaction_confirmation
                            .pending_transaction_check_interval_ms,
                    ),
                    Box::new(closure),
                );
        }
        if !err.is_empty() {
            unimplemented!() // self.handle_tx_cancellation(cancellations);
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
    pub pending_payments: Vec<PaymentWithMetadata>,
    pub attempt: u16,
}

impl Handler<RequestTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: RequestTransactionReceipts,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_rely_request_transaction_receipts(msg)
    }
}

impl Handler<ReportTransactionReceipts> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ReportTransactionReceipts, ctx: &mut Self::Context) -> Self::Result {
        let attempt = msg.attempt;
        let statuses = self.handle_pending_txs_check(msg);
        let (cancellations, all_still_pending_as_a_new_actor_msg) =
            PendingTransactionStatus::merge_still_pending_and_separate_from_others(
                statuses, attempt,
            );
        if !cancellations.is_empty() {
            self.handle_tx_cancellation(cancellations, ctx);
        }
        if !all_still_pending_as_a_new_actor_msg
            .pending_payments
            .is_empty()
        {
            let closure = |msg: RequestTransactionReceipts, dur: Duration| -> SpawnHandle {
                ctx.notify_later(msg, dur)
            };
            let _ = self
                .transaction_confirmation
                .notify_handle_request_transaction_receipts
                .notify_later(
                    all_still_pending_as_a_new_actor_msg,
                    Duration::from_millis(
                        self.transaction_confirmation
                            .pending_transaction_check_interval_ms,
                    ),
                    Box::new(closure),
                );
        }
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct CancelFailedPendingTransaction {
    pub tx_id: TxTripleId,
}

//TODO discard
impl Handler<CancelFailedPendingTransaction> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: CancelFailedPendingTransaction,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if let Some(msg) = self.handle_cancel_pending_transaction(msg) {
            unimplemented!()
        }
    }
}

#[derive(Debug, PartialEq, Message, Clone)]
pub struct ConfirmPendingTransaction {
    pub payment: Payment,
}

//TODO discard
impl Handler<ConfirmPendingTransaction> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: ConfirmPendingTransaction, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_confirm_pending_transaction(msg)
    }
}

impl Handler<PendingPaymentBackup> for Accountant {
    type Result = ();
    fn handle(&mut self, msg: PendingPaymentBackup, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_payment_backup_insertion(msg)
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
        pending_payments_dao_factory: Box<dyn PendingPaymentsDaoFactory>,
        banned_dao_factory: Box<dyn BannedDaoFactory>,
        config_dao_factory: Box<dyn ConfigDaoFactory>,
    ) -> Accountant {
        Accountant {
            config: config.accountant_config.clone(),
            consuming_wallet: config.consuming_wallet.clone(),
            earning_wallet: config.earning_wallet.clone(),
            payable_dao: payable_dao_factory.make(),
            receivable_dao: receivable_dao_factory.make(),
            pending_payments_dao: pending_payments_dao_factory.make(),
            banned_dao: banned_dao_factory.make(),
            crashable: config.crash_point == CrashPoint::Message,
            transaction_confirmation: TransactionConfirmationTools::new(
                config
                    .accountant_config
                    .pending_transaction_check_interval_ms,
            ),
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
            transaction_backup: recipient!(addr, PendingPaymentBackup),
            report_transaction_receipts: recipient!(addr, ReportTransactionReceipts),
            report_sent_payments: recipient!(addr, SentPayments),
            ui_message_sub: recipient!(addr, NodeFromUiMessage),
        }
    }

    pub fn dao_factory(data_directory: &Path) -> DaoFactoryReal {
        DaoFactoryReal::new(data_directory, false, MigratorConfig::panic_on_migration())
    }

    fn scan_for_payables(&mut self) {
        debug!(self.logger, "Scanning for payables");
        let future_logger = self.logger.clone();

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
            Self::payments_debug_summary(&qualified_payables)
        );
        if !qualified_payables.is_empty() {
            let report_sent_payments = self.report_sent_payments_sub.clone();
            // TODO: This is bad code. The ReportAccountsPayable message should have no result;
            // instead, when the BlockchainBridge completes processing the ReportAccountsPayable
            // message, it should send a SentPayments message back to the Accountant. There should
            // be no future here: mixing futures and Actors is a bad idea.
            let future = self
                .report_accounts_payable_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .send(ReportAccountsPayable {
                    accounts: qualified_payables,
                })
                .then(move |results| match results {
                    Ok(Ok(results)) => {
                        let results_converted = results
                            .into_iter()
                            .map(|item| item.map_err(PaymentError::from))
                            .collect();
                        report_sent_payments
                            .expect("Accountant is unbound")
                            .try_send(SentPayments {
                                payments: results_converted,
                            })
                            .expect("Accountant is dead");
                        Ok(())
                    }
                    Ok(Err(e)) => {
                        warning!(future_logger, "{}", e);
                        Ok(())
                    }
                    Err(e) => {
                        error!(
                            future_logger,
                            "Unable to send ReportAccountsPayable: {:?}", e
                        );
                        thread::sleep(Duration::from_secs(1));
                        panic!("Unable to send ReportAccountsPayable: {:?}", e);
                    }
                });
            actix::spawn(future);
        }
    }

    fn scan_for_delinquencies(&mut self) {
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

    fn scan_for_received_payments(&mut self) {
        let future_logger = self.logger.clone();
        debug!(
            self.logger,
            "Scanning for payments to {}", self.earning_wallet
        );
        let future_report_new_payments_sub = self.report_new_payments_sub.clone();
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
        let future = self
            .retrieve_transactions_sub
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .send(RetrieveTransactions {
                start_block,
                recipient: self.earning_wallet.clone(),
            })
            .then(move |transactions_possibly| match transactions_possibly {
                Ok(Ok(ref vec)) if vec.is_empty() => {
                    debug!(future_logger, "No payments detected");
                    Ok(())
                }
                Ok(Ok(transactions)) => {
                    future_report_new_payments_sub
                        .expect("Accountant is unbound")
                        .try_send(ReceivedPayments {
                            payments: transactions,
                        })
                        .expect("Accountant is dead.");
                    Ok(())
                }
                Ok(Err(e)) => {
                    warning!(
                        future_logger,
                        "Unable to retrieve transactions from Blockchain Bridge: {:?}",
                        e
                    );
                    Err(())
                }
                Err(e) => {
                    error!(
                        future_logger,
                        "Unable to send to Blockchain Bridge: {:?}", e
                    );
                    thread::sleep(Duration::from_secs(1));
                    panic!("Unable to send to Blockchain Bridge: {:?}", e);
                }
            });
        actix::spawn(future);
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
                Err(DebtRecordingError::SignConversion(_)) => error! (
                    self.logger,
                    "Overflow error trying to record service provided to Node with consuming wallet {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(DebtRecordingError::RusqliteError(e))=> unimplemented!("{}",e)
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
                Err(DebtRecordingError::SignConversion(_)) => error! (
                    self.logger,
                    "Overflow error trying to record service consumed from Node with earning wallet {}: service rate {}, byte rate {}, payload size {}. Skipping",
                    wallet,
                    service_rate,
                    byte_rate,
                    payload_size
                ),
                Err(DebtRecordingError::RusqliteError(e)) => unimplemented!("{}",e)
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

    fn payments_debug_summary(qualified_payables: &[PayableAccount]) -> String {
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
        self.transaction_confirmation
            .request_transaction_receipts_subs_opt = Some(
            msg.peer_actors
                .blockchain_bridge
                .request_transaction_receipts,
        );
        info!(self.logger, "Accountant bound");
    }

    fn handle_start_message(&mut self) {
        self.scan_for_payables();
        self.scan_for_received_payments();
        self.scan_for_delinquencies();
    }

    fn handle_received_payments(&mut self, received_payments: ReceivedPayments) {
        self.receivable_dao
            .as_mut()
            .more_money_received(received_payments.payments);
    }

    fn handle_sent_payments(
        &mut self,
        sent_payments: SentPayments,
    ) -> (Vec<PaymentWithMetadata>, Vec<PaymentError>) {
        let (ok, err) = self.mark_pending_payments_and_separate_failures(sent_payments);
        (
            ok.into_iter()
                .flatten()
                .map(|payment| PaymentWithMetadata {
                    payment,
                    receipt_failure_count: 0,
                })
                .collect(),
            err.into_iter()
                .map(|val| val.expect_err("all the items ought to be errors"))
                .collect(),
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
                pending_transaction: account
                    .pending_payment_transaction
                    .map(|ppt| format!("0x{:0X}", ppt)),
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

    fn handle_cancel_pending_transaction(
        &self,
        msg: CancelFailedPendingTransaction,
    ) -> Option<CancelFailedPendingTransaction> {
        match self
            .payable_dao
            .transaction_canceled(&msg.tx_id.recipient_wallet, msg.tx_id.hash)
        {
            Ok(_) => {
                debug!(
                    self.logger,
                    "Transaction {} for wallet {} was unmarked as pending due to cancellation",
                    msg.tx_id.hash,
                    msg.tx_id.recipient_wallet
                );
                match self
                    .pending_payments_dao
                    .delete_backup_record(msg.tx_id.rowid)
                {
                    Ok(_) => info!(
                        self.logger,
                        "Broken transaction {} for wallet {} was successfully canceled",
                        msg.tx_id.hash,
                        msg.tx_id.recipient_wallet
                    ),
                    Err(e) => unimplemented!("{:?}", e),
                }
            }
            Err(e) => {
                unimplemented!()
                // 1 => {warning!(self.logger,"First attempt to cancel pending transaction '{}' failed on: {:?}",msg.invalid_payment.transaction,e); return Some(CancelFailedPendingTransaction{attempt: msg.attempt + 1, ..msg})}
                // //TODO I'll need to change this, it's not going to become better if we retry, hopeless
                // 2 => error!(self.logger,"We have failed to revert a record of your invalid payment; record for this wallet's account: {} has stayed inconsistent with the reality; this is going to result in a (probably) permanent ban from the creditor; debt balance faultily subtracted for: {}", msg.invalid_payment.to, msg.invalid_payment.amount),
                // _ => unreachable!("this option isn't allowed")
                // };
            }
        }
        None
    }

    fn handle_confirm_pending_transaction(&self, msg: ConfirmPendingTransaction) {
        if let Err(e) = self.payable_dao.transaction_confirmed(&msg.payment) {
            unimplemented!("{:?}", e)
        } else {
            info!(
                self.logger,
                "Confirmation of transaction {:x} was wholly processed", msg.payment.transaction
            )
        }
    }

    fn mark_pending_payments_and_separate_failures(
        &mut self,
        sent_payments: SentPayments,
    ) -> (
        Vec<Result<Payment, PaymentError>>,
        Vec<Result<Payment, PaymentError>>,
    ) {
        sent_payments
            .payments
            .into_iter()
            .map(|payment| match payment {
                Ok(payment) => match self.payable_dao.as_mut().mark_pending_payment(&payment.to, payment.transaction) {
                    Ok(()) => Ok(payment),
                    Err(e) => Err(e)
                },
                Err(e) => Err(e)//warning!(
                //     self.logger,
                //     "{} Please check your blockchain service URL configuration.",
                //     e
                // ),
            }).partition(|val| val.is_ok())
    }

    fn handle_rely_request_transaction_receipts(&self, msg: RequestTransactionReceipts) {
        self.transaction_confirmation
            .request_transaction_receipts_subs_opt
            .as_ref()
            .expect("BlockchainBridge is unbound")
            .try_send(msg)
            .expect("BlockchainBridge is dead")
    }

    fn handle_pending_txs_check(
        &self,
        msg: ReportTransactionReceipts,
    ) -> Vec<PendingTransactionStatus> {
        msg.payments_with_tx_receipts
            .into_iter()
            .map(|(tx_receipt_result, payment)| {
                match tx_receipt_result {
                Ok(receipt_opt) => match receipt_opt {
                    Some(receipt) =>
                                    self.receipt_check_for_pending_tx(
                                        receipt,
                                        payment,
                                        msg.attempt,
                                        &self.logger,
                                    ),
                    None => {
                        debug!(self.logger,"DEBUG: Accountant: Tracking an attempt to interpret a receipt for transaction {} but None was received; attempt {}, retrying", payment.payment.transaction, msg.attempt);
                        PendingTransactionStatus::StillPending {
                            payment,
                            attempt: msg.attempt,
                        }
                    }
                },
                Err(receipt_e) => {
                    match self.pending_payments_dao.read_backup_record(payment.payment.rowid){
                        Ok(_) =>{
                        warning!(self.logger, "Failed to fetch transaction receipt for pending transaction {} due to '{:?}'; given the backup of this payment is all right the confirmation process is now terminating but will be renewed with another scan cycle",
                        format!("{:x}",payment.payment.transaction),receipt_e);
                        PendingTransactionStatus::ConfirmationProcessCrashed((&payment.payment).into())
                        }
                        Err(e) => match payment.receipt_failure_count {
                            attempt @ 0..=1 => {
                                warning!(self.logger,"Failed to fetch transaction receipt for pending transaction {} due to '{:?}'; moreover a payment backup failure detected '{:?}'; attempting retries with maximal count 2 - now {}",format!("{:x}",payment.payment.transaction),receipt_e,e,attempt + 1);
                                let payment_prepared_for_next_round = PaymentWithMetadata{ payment: payment.payment, receipt_failure_count: payment.receipt_failure_count + 1 };
                                PendingTransactionStatus::StillPending{ payment: payment_prepared_for_next_round, attempt: msg.attempt }},
                            _ => unimplemented!(),
                        }
                    }
                }
            }
            })
            .collect()
    }

    fn receipt_check_for_pending_tx(
        &self,
        receipt: TransactionReceipt,
        payment: PaymentWithMetadata,
        attempt: u16,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        fn elapsed_in_ms(payment: &Payment) -> u128 {
            payment
                .timestamp
                .elapsed()
                .expect("time counts for elapsed failed")
                .as_millis()
        }
        fn handle_none_receipt(
            payment: PaymentWithMetadata,
            attempt: u16,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(logger,"Pending transaction '{}' couldn't be confirmed at attempt {} at {}ms after its sending",payment.payment.transaction, attempt, elapsed_in_ms(&payment.payment));
            PendingTransactionStatus::StillPending { payment, attempt }
        }
        fn handle_status_with_success(
            payment: Payment,
            attempt: u16,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            info!(
                logger,
                "Transaction '{}' has been added to the blockchain; detected locally at attempt {} at {}ms after its sending",
                payment.transaction,
                attempt,
                elapsed_in_ms(&payment)
            );
            PendingTransactionStatus::Confirmed(payment)
        }
        fn handle_status_with_failure(
            payment: &Payment,
            attempt: u16,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            warning!(logger,"Pending transaction '{}' announced as a failure on the check of attempt {} at {}ms after its sending",payment.transaction,attempt,elapsed_in_ms(payment));
            PendingTransactionStatus::Failure(payment.into())
        }
        match receipt.status{
                None => handle_none_receipt(payment,attempt,logger),
                Some(status_code) =>
                    match status_code.as_u64(){
                    0 => handle_status_with_success(payment.payment,attempt,logger),
                    1 => handle_status_with_failure(&payment.payment,attempt,logger),
                    other => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}",payment.payment.transaction,other)
                }
            }
    }

    fn handle_tx_cancellation(
        &self,
        cancellations: Vec<PendingTransactionStatus>,
        ctx: &mut Context<Self>,
    ) {
        cancellations.into_iter().for_each(|status| {
            if let PendingTransactionStatus::Failure(tx_id) = status {
                let closure = |msg: CancelFailedPendingTransaction| ctx.notify(msg);
                self.transaction_confirmation
                    .notify_handle_cancel_failed_transaction
                    .notify(CancelFailedPendingTransaction { tx_id }, Box::new(closure));
            } else if let PendingTransactionStatus::Confirmed(payment) = status {
                let closure = |msg: ConfirmPendingTransaction| ctx.notify(msg);
                self.transaction_confirmation
                    .notify_handle_confirm_tx_after_success
                    .notify(ConfirmPendingTransaction { payment }, Box::new(closure));
            }
        });
    }

    fn handle_payment_backup_insertion(&self, msg: PendingPaymentBackup) {
        match self.pending_payments_dao.insert_backup_record(msg){
            Ok(_) => debug!(self.logger, "Processed a backup for payment created with referential rowid {} and balance change {}",msg.rowid, msg.amount),
            Err(e) => warning!(self.logger, "Failure on a backup for pending payment with referential rowid {} and balance change {}, the underlying error: '{:?}'; this could result in potential data loss if the payment did not finish correctly",msg.rowid,msg.amount,e)
        }
    }
}

// At the time of this writing, Rust 1.44.0 was unpredictably producing
// segfaults on the Mac when using u64::try_from (i64). This is an attempt to
// work around that.
pub fn jackass_unsigned_to_signed(unsigned: u64) -> Result<i64, u64> {
    if unsigned <= (i64::MAX as u64) {
        Ok(unsigned as i64)
    } else {
        Err(unsigned)
    }
}

#[derive(Debug, PartialEq, Clone)]
enum PendingTransactionStatus {
    StillPending {
        payment: PaymentWithMetadata,
        attempt: u16,
    }, //will go back, waiting an interval, and start a new round
    Failure(TxTripleId),                    //official tx failure
    Confirmed(Payment),                     //tx was fully processed and successful
    ConfirmationProcessCrashed(TxTripleId), //failure within our confirming process
}

impl PendingTransactionStatus {
    fn merge_still_pending_and_separate_from_others(
        vec: Vec<Self>,
        attempt: u16,
    ) -> (Vec<Self>, RequestTransactionReceipts) {
        let (not_pending, pending): (Vec<PendingTransactionStatus>, Vec<PendingTransactionStatus>) =
            vec.into_iter()
                .filter(|item| {
                    !matches!(
                        item,
                        PendingTransactionStatus::ConfirmationProcessCrashed(_) //TODO why this is there?
                    )
                })
                .partition(|item| item.is_non_pending());

        let init = RequestTransactionReceipts {
            pending_payments: vec![],
            attempt: attempt + 1,
        };
        let recollected = pending.into_iter().fold(init, |mut so_far, now| {
            if let PendingTransactionStatus::StillPending {
                payment,
                attempt: attempt_from_tx_info
            } = now
            {
                if attempt_from_tx_info != attempt {
                   panic!("incompatible attempts of tx confirmations, something is broken; should be {} but was {}", attempt, attempt_from_tx_info)
                };
                so_far.pending_payments.push(payment)
            } else {
               unimplemented!() // panic!("previous measures failed")
            }
            so_far
        });
        (not_pending, recollected)
    }

    fn is_non_pending(&self) -> bool {
        !matches!(self, Self::StillPending { .. })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct TxTripleId {
    pub recipient_wallet: Wallet,
    pub hash: H256,
    pub rowid: u16,
}

impl From<&Payment> for TxTripleId {
    fn from(payment: &Payment) -> Self {
        Self {
            recipient_wallet: payment.to.clone(),
            hash: payment.transaction,
            rowid: payment.rowid,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PaymentWithMetadata {
    pub payment: Payment,
    pub receipt_failure_count: u8,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::accountant::pending_payments_dao::PendingPaymentDaoError;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::{
        bc_from_ac_plus_earning_wallet, bc_from_ac_plus_wallets, earlier_in_seconds,
        make_accountant, make_receivable_account, BannedDaoFactoryMock, BlockchainInterfaceMock,
        ConfigDaoFactoryMock, PayableDaoFactoryMock, PendingPaymentsDaoFactoryMock,
        PendingPaymentsDaoMock, ReceivableDaoFactoryMock,
    };
    use crate::accountant::test_utils::{AccountantBuilder, BannedDaoMock};
    use crate::accountant::PaymentErrorKind::SignConversion;
    use crate::blockchain::blockchain_bridge::BlockchainBridge;
    use crate::blockchain::blockchain_interface::Transaction;
    use crate::blockchain::blockchain_interface::{BlockchainError, TxReceipt};
    use crate::blockchain::test_utils::{NotifyHandleMock, NotifyLaterHandleMock};
    use crate::blockchain::tool_wrappers::SendTransactionToolWrapperNull;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{
        prove_that_crash_request_handler_is_hooked_up, CleanUpMessage, DummyActor,
    };
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::{Arbiter, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
    use rusqlite::{Error, Row, NO_PARAMS};
    use std::cell::RefCell;
    use std::convert::TryFrom;
    use std::ops::Sub;
    use std::rc::Rc;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::thread;
    use std::time::Duration;
    use std::time::SystemTime;
    use web3::types::U256;
    use web3::types::{TransactionReceipt, H256};

    #[derive(Debug, Default)]
    pub struct PayableDaoMock {
        account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
        account_status_results: RefCell<Vec<Option<PayableAccount>>>,
        more_money_payable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_payable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
        non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
        mark_pending_payment_parameters: Arc<Mutex<Vec<(Wallet, H256)>>>,
        mark_pending_payment_results: RefCell<Vec<Result<(), PaymentError>>>,
        transaction_confirmed_params: Arc<Mutex<Vec<Payment>>>,
        transaction_confirmed_results: RefCell<Vec<Result<(), PaymentError>>>,
        transaction_canceled_params: Arc<Mutex<Vec<(Wallet, H256)>>>,
        transaction_canceled_results: RefCell<Vec<Result<(), PaymentError>>>,
        top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
        top_records_results: RefCell<Vec<Vec<PayableAccount>>>,
        total_results: RefCell<Vec<u64>>,
    }

    impl PayableDao for PayableDaoMock {
        fn more_money_payable(
            &self,
            wallet: &Wallet,
            amount: u64,
        ) -> Result<(), DebtRecordingError> {
            self.more_money_payable_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), amount));
            self.more_money_payable_results.borrow_mut().remove(0)
        }

        fn mark_pending_payment(&self, wallet: &Wallet, hash: H256) -> Result<(), PaymentError> {
            self.mark_pending_payment_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), hash));
            self.mark_pending_payment_results.borrow_mut().remove(0)
        }

        fn transaction_confirmed(&self, payment: &Payment) -> Result<(), PaymentError> {
            self.transaction_confirmed_params
                .lock()
                .unwrap()
                .push(payment.clone());
            self.transaction_confirmed_results.borrow_mut().remove(0)
        }

        fn transaction_canceled(&self, wallet: &Wallet, hash: H256) -> Result<(), PaymentError> {
            self.transaction_canceled_params
                .lock()
                .unwrap()
                .push((wallet.clone(), hash));
            self.transaction_canceled_results.borrow_mut().remove(0)
        }

        fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
            self.account_status_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());
            self.account_status_results.borrow_mut().remove(0)
        }

        fn non_pending_payables(&self) -> Vec<PayableAccount> {
            if self.non_pending_payables_results.borrow().is_empty() {
                vec![]
            } else {
                self.non_pending_payables_results.borrow_mut().remove(0)
            }
        }

        fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
            self.top_records_parameters
                .lock()
                .unwrap()
                .push((minimum_amount, maximum_age));
            self.top_records_results.borrow_mut().remove(0)
        }

        fn total(&self) -> u64 {
            self.total_results.borrow_mut().remove(0)
        }
    }

    impl PayableDaoMock {
        pub fn new() -> PayableDaoMock {
            PayableDaoMock::default()
        }

        fn more_money_payable_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_payable_parameters = parameters;
            self
        }

        fn more_money_payable_result(self, result: Result<(), DebtRecordingError>) -> Self {
            self.more_money_payable_results.borrow_mut().push(result);
            self
        }

        fn non_pending_payables_result(self, result: Vec<PayableAccount>) -> Self {
            self.non_pending_payables_results.borrow_mut().push(result);
            self
        }

        pub fn mark_pending_payment_params(
            mut self,
            parameters: &Arc<Mutex<Vec<(Wallet, H256)>>>,
        ) -> Self {
            self.mark_pending_payment_parameters = parameters.clone();
            self
        }

        pub fn mark_pending_payment_result(self, result: Result<(), PaymentError>) -> Self {
            self.mark_pending_payment_results.borrow_mut().push(result);
            self
        }

        pub fn transaction_confirmed_params(mut self, params: &Arc<Mutex<Vec<Payment>>>) -> Self {
            self.transaction_confirmed_params = params.clone();
            self
        }

        pub fn transaction_confirmed_result(self, result: Result<(), PaymentError>) -> Self {
            self.transaction_confirmed_results.borrow_mut().push(result);
            self
        }

        pub fn transaction_canceled_params(
            mut self,
            params: &Arc<Mutex<Vec<(Wallet, H256)>>>,
        ) -> Self {
            self.transaction_canceled_params = params.clone();
            self
        }

        pub fn transaction_canceled_result(self, result: Result<(), PaymentError>) -> Self {
            self.transaction_canceled_results.borrow_mut().push(result);
            self
        }

        fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.top_records_parameters = parameters.clone();
            self
        }

        fn top_records_result(self, result: Vec<PayableAccount>) -> Self {
            self.top_records_results.borrow_mut().push(result);
            self
        }

        fn total_result(self, result: u64) -> Self {
            self.total_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Debug, Default)]
    pub struct ReceivableDaoMock {
        account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
        account_status_results: RefCell<Vec<Option<ReceivableAccount>>>,
        more_money_receivable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_receivable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
        more_money_received_parameters: Arc<Mutex<Vec<Vec<Transaction>>>>,
        more_money_received_results: RefCell<Vec<Result<(), PaymentError>>>,
        receivables_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentCurves>>>,
        paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
        top_records_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        total_results: RefCell<Vec<u64>>,
    }

    impl ReceivableDao for ReceivableDaoMock {
        fn more_money_receivable(
            &self,
            wallet: &Wallet,
            amount: u64,
        ) -> Result<(), DebtRecordingError> {
            self.more_money_receivable_parameters
                .lock()
                .unwrap()
                .push((wallet.clone(), amount));
            self.more_money_receivable_results.borrow_mut().remove(0)
        }

        fn more_money_received(&mut self, transactions: Vec<Transaction>) {
            self.more_money_received_parameters
                .lock()
                .unwrap()
                .push(transactions);
        }

        fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount> {
            self.account_status_parameters
                .lock()
                .unwrap()
                .push(wallet.clone());

            self.account_status_results.borrow_mut().remove(0)
        }

        fn receivables(&self) -> Vec<ReceivableAccount> {
            self.receivables_results.borrow_mut().remove(0)
        }

        fn new_delinquencies(
            &self,
            now: SystemTime,
            payment_curves: &PaymentCurves,
        ) -> Vec<ReceivableAccount> {
            self.new_delinquencies_parameters
                .lock()
                .unwrap()
                .push((now, payment_curves.clone()));
            if self.new_delinquencies_results.borrow().is_empty() {
                vec![]
            } else {
                self.new_delinquencies_results.borrow_mut().remove(0)
            }
        }

        fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount> {
            self.paid_delinquencies_parameters
                .lock()
                .unwrap()
                .push(payment_curves.clone());
            if self.paid_delinquencies_results.borrow().is_empty() {
                vec![]
            } else {
                self.paid_delinquencies_results.borrow_mut().remove(0)
            }
        }

        fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
            self.top_records_parameters
                .lock()
                .unwrap()
                .push((minimum_amount, maximum_age));
            self.top_records_results.borrow_mut().remove(0)
        }

        fn total(&self) -> u64 {
            self.total_results.borrow_mut().remove(0)
        }
    }

    impl ReceivableDaoMock {
        pub fn new() -> ReceivableDaoMock {
            Self::default()
        }

        fn more_money_receivable_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_receivable_parameters = parameters.clone();
            self
        }

        fn more_money_receivable_result(self, result: Result<(), DebtRecordingError>) -> Self {
            self.more_money_receivable_results.borrow_mut().push(result);
            self
        }

        fn more_money_received_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<Vec<Transaction>>>>,
        ) -> Self {
            self.more_money_received_parameters = parameters.clone();
            self
        }

        fn more_money_received_result(self, result: Result<(), PaymentError>) -> Self {
            self.more_money_received_results.borrow_mut().push(result);
            self
        }

        fn new_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        ) -> Self {
            self.new_delinquencies_parameters = parameters.clone();
            self
        }

        fn new_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.new_delinquencies_results.borrow_mut().push(result);
            self
        }

        fn paid_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<PaymentCurves>>>,
        ) -> Self {
            self.paid_delinquencies_parameters = parameters.clone();
            self
        }

        fn paid_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.paid_delinquencies_results.borrow_mut().push(result);
            self
        }

        fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
            self.top_records_parameters = parameters.clone();
            self
        }

        fn top_records_result(self, result: Vec<ReceivableAccount>) -> Self {
            self.top_records_results.borrow_mut().push(result);
            self
        }

        fn total_result(self, result: u64) -> Self {
            self.total_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn new_calls_factories_properly() {
        let config = BootstrapperConfig::new();
        let payable_dao_factory_called = Rc::new(RefCell::new(false));
        let payable_dao = PayableDaoMock::new();
        let payable_dao_factory =
            PayableDaoFactoryMock::new(Box::new(payable_dao)).called(&payable_dao_factory_called);
        let receivable_dao_factory_called = Rc::new(RefCell::new(false));
        let receivable_dao = ReceivableDaoMock::new();
        let receivable_dao_factory =
            ReceivableDaoFactoryMock::new(receivable_dao).called(&receivable_dao_factory_called);
        let payment_recover_dao_factory_called = Rc::new(RefCell::new(false));
        let payment_recover_dao = PendingPaymentsDaoMock::default();
        let payment_recover_dao_factory = PendingPaymentsDaoFactoryMock::new(payment_recover_dao)
            .called(&payment_recover_dao_factory_called);
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
            Box::new(payment_recover_dao_factory),
            Box::new(banned_dao_factory),
            Box::new(config_dao_factory),
        );

        assert_eq!(payable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(receivable_dao_factory_called.as_ref(), &RefCell::new(true));
        assert_eq!(
            payment_recover_dao_factory_called.as_ref(),
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
                    pending_payment_transaction: Some(H256::from_uint(&U256::from(123))),
                    rowid: 1,
                },
                PayableAccount {
                    wallet: make_wallet("earning 2"),
                    balance: 12345679,
                    last_paid_timestamp: SystemTime::now().sub(Duration::from_secs(10001)),
                    pending_payment_transaction: None,
                    rowid: 2,
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
        let subject = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payable_scan_interval: Duration::from_millis(10_000),
                    payment_received_scan_interval: Duration::from_millis(10_000),
                    pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                },
                make_wallet("some_wallet_address"),
            )),
            Some(payable_dao),
            Some(receivable_dao),
            None,
            None,
            None,
        );
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
                        pending_transaction: Some(
                            "0x000000000000000000000000000000000000000000000000000000000000007B"
                                .to_string()
                        ),
                    },
                    UiPayableAccount {
                        wallet: "0x00000000000000000000006561726e696e672032".to_string(),
                        age: 10001,
                        amount: 12345679,
                        pending_transaction: None,
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

    //TODO this test might go away
    #[test]
    fn accountant_records_in_payables_and_pending_payments_tables_when_sent_payments() {
        //     let payment_sent_parameters_arc = Arc::new(Mutex::new(vec![]));
        //     let payable_dao = PayableDaoMock::new()
        //         .non_pending_payables_result(vec![])
        //         .payment_sent_params(&payment_sent_parameters_arc)
        //         .payment_sent_result(Ok(2));
        //     let system = System::new(
        //         "accountant_records_in_payables_and_pending_payments_tables_when_sent_payments",
        //     );
        //     let pending_payments_dao =
        //     let accountant = make_accountant(
        //         Some(bc_from_ac_plus_earning_wallet(
        //             AccountantConfig {
        //                 payable_scan_interval: Duration::from_millis(100),
        //                 payment_received_scan_interval: Duration::from_secs(10_000),
        //                 pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
        //             },
        //             make_wallet("some_wallet_address"),
        //         )),
        //         Some(payable_dao),
        //         None,
        //         None,
        //         None,
        //         None,
        //     );
        //     let expected_wallet = make_wallet("paying_you");
        //     let expected_amount = 1;
        //     let expected_hash = H256::from("transaction_hash".keccak256());
        //     let mut expected_payment = Payment::new(
        //         expected_wallet.clone(),
        //         expected_amount,
        //         expected_hash.clone(),
        //     );
        //     let send_payments = SentPayments {
        //         payments: vec![Ok(expected_payment.clone())],
        //     };
        //     let subject = accountant.start();
        //
        //     subject
        //         .try_send(send_payments)
        //         .expect("unexpected actix error");
        //     System::current().stop();
        //     system.run();
        //
        //     let sent_payment_to = payment_sent_parameters_arc.lock().unwrap();
        //     let actual = sent_payment_to.get(0).unwrap();
        //     expected_payment.timestamp = actual.timestamp;
        //     assert_eq!(actual, &expected_payment);
    }

    #[test]
    fn accountant_logs_warning_when_handle_sent_payments_encounters_a_blockchain_error() {
        init_test_logging();
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let system = System::new("accountant_calls_payable_dao_payment_sent_when_sent_payments");
        let accountant = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payable_scan_interval: Duration::from_millis(100),
                    payment_received_scan_interval: Duration::from_secs(10_000),
                    pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                },
                make_wallet("some_wallet_address"),
            )),
            Some(payable_dao),
            None,
            None,
            None,
            None,
        );
        let send_payments = SentPayments {
            payments: vec![Err(PaymentError::PreTransaction(
                PaymentErrorKind::BlockchainError("Payment attempt failed".to_string()),
                H256::from_uint(&U256::from(12345)),
            ))],
        };
        let subject = accountant.start();

        subject
            .try_send(send_payments)
            .expect("unexpected actix error");

        System::current().stop();
        system.run();
        TestLogHandler::new().await_log_containing(
            r#"WARN: Accountant: Blockchain TransactionFailed("Payment attempt failed"). Please check your blockchain service URL configuration."#,
            1000,
        );
    }

    #[test]
    fn accountant_reports_sent_payments_when_blockchain_bridge_reports_account_payable() {
        let earning_wallet = make_wallet("earner3000");
        let now_system = SystemTime::now();
        let now = to_time_t(now_system);
        let earlier_system = earlier_in_seconds(1000);
        let expected_wallet = make_wallet("blah");
        let expected_wallet_inner = expected_wallet.clone();
        let expected_amount =
            u64::try_from(PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000).unwrap();
        let expected_pending_payment_transaction = H256::from("transaction_hash".keccak256());
        let expected_pending_payment_transaction_inner =
            expected_pending_payment_transaction.clone();
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(vec![PayableAccount {
                wallet: expected_wallet.clone(),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
                rowid: 1,
            }])
            .non_pending_payables_result(vec![]);
        let blockchain_bridge = Recorder::new()
            .report_accounts_payable_response(Ok(vec![Ok(Payment::new(
                expected_wallet_inner,
                expected_amount,
                expected_pending_payment_transaction_inner,
                now_system,
                earlier_system,
                1,
            ))]))
            .retrieve_transactions_response(Ok(vec![]));
        let (accountant_mock, accountant_mock_awaiter, accountant_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new(
                "accountant_reports_sent_payments_when_blockchain_bridge_reports_account_payable",
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .accountant(accountant_mock)
                .build();
            let subject = make_accountant(
                Some(bc_from_ac_plus_earning_wallet(
                    AccountantConfig {
                        payable_scan_interval: Duration::from_millis(100),
                        payment_received_scan_interval: Duration::from_secs(10_000),
                        pending_transaction_check_interval_ms:
                            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                    },
                    earning_wallet.clone(),
                )),
                Some(payable_dao),
                None,
                None,
                None,
                None,
            );
            let subject_addr = subject.start();
            let accountant_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(accountant_subs, peer_actors);
            send_start_message!(accountant_subs);

            system.run();
        });

        accountant_mock_awaiter.await_message_count(1);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let actual_payments = accountant_recording.get_record::<SentPayments>(0);
        let expected_payment = Payment::new(
            expected_wallet,
            expected_amount,
            expected_pending_payment_transaction,
            now_system,
            earlier_system,
            1,
        );
        let payments = actual_payments.payments.clone();
        let maybe_payment = payments.get(0).clone();
        let result_payment = maybe_payment.unwrap().clone();
        assert_eq!(
            actual_payments,
            &SentPayments {
                payments: vec![Ok(expected_payment)]
            }
        );
    }

    #[test]
    fn accountant_logs_warn_when_blockchain_bridge_report_accounts_payable_errors() {
        init_test_logging();
        let earning_wallet = make_wallet("earner3000");
        let now = to_time_t(SystemTime::now());
        let expected_wallet = make_wallet("blockchain_bridge_error");

        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(vec![PayableAccount {
                wallet: expected_wallet.clone(),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
                rowid: 3,
            }])
            .non_pending_payables_result(vec![]);

        let blockchain_bridge = Recorder::new()
            .retrieve_transactions_response(Ok(vec![]))
            .report_accounts_payable_response(Err("Failed to send transaction".to_string()));

        let (accountant_mock, _, accountant_recording_arc) = make_recorder();

        thread::spawn(move || {
            let system = System::new(
                "accountant_reports_sent_payments_when_blockchain_bridge_reports_account_payable",
            );

            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .accountant(accountant_mock)
                .build();
            let subject = make_accountant(
                Some(bc_from_ac_plus_earning_wallet(
                    AccountantConfig {
                        payable_scan_interval: Duration::from_millis(100),
                        payment_received_scan_interval: Duration::from_secs(10_000),
                        pending_transaction_check_interval_ms:
                            DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                    },
                    earning_wallet.clone(),
                )),
                Some(payable_dao),
                None,
                None,
                None,
                None,
            );
            let subject_addr = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        TestLogHandler::new()
            .await_log_containing("WARN: Accountant: Failed to send transaction", 1000u64);

        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(0, accountant_recording.len());
    }

    #[test]
    fn accountant_payment_received_scan_timer_triggers_scanning_for_payments() {
        let paying_wallet = make_wallet("wallet0");
        let earning_wallet = make_wallet("earner3000");
        let amount = 42u64;
        let expected_transactions = vec![Transaction {
            block_number: 7u64,
            from: paying_wallet.clone(),
            gwei_amount: amount,
        }];
        let blockchain_bridge =
            Recorder::new().retrieve_transactions_response(Ok(expected_transactions.clone()));
        let blockchain_bridge_awaiter = blockchain_bridge.get_awaiter();
        let blockchain_bridge_recording = blockchain_bridge.get_recording();
        let (accountant_mock, accountant_awaiter, accountant_recording_arc) = make_recorder();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(10_000),
                payment_received_scan_interval: Duration::from_millis(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );

        thread::spawn(move || {
            let system = System::new(
                "accountant_payment_received_scan_timer_triggers_scanning_for_payments",
            );
            let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![])
                .paid_delinquencies_result(vec![]);
            let config_mock = PersistentConfigurationMock::new().start_block_result(Ok(5));
            let subject = make_accountant(
                Some(config),
                Some(payable_dao),
                Some(receivable_dao),
                None,
                None,
                Some(config_mock),
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .accountant(accountant_mock)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            &RetrieveTransactions {
                start_block: 5u64,
                recipient: earning_wallet,
            },
            retrieve_transactions_message
        );

        accountant_awaiter.await_message_count(1);
        let received_payments_recording = accountant_recording_arc.lock().unwrap();
        let received_payments_message =
            received_payments_recording.get_record::<ReceivedPayments>(0);
        assert_eq!(
            &ReceivedPayments {
                payments: expected_transactions
            },
            received_payments_message
        );
    }

    #[test]
    fn accountant_logs_if_no_transactions_were_detected() {
        init_test_logging();
        let earning_wallet = make_wallet("earner3000");
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Ok(vec![]));
        let blockchain_bridge_awaiter = blockchain_bridge.get_awaiter();
        let blockchain_bridge_recording = blockchain_bridge.get_recording();
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(10_000),
                payment_received_scan_interval: Duration::from_millis(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );

        thread::spawn(move || {
            let system = System::new("accountant_logs_if_no_transactions_were_detected");
            let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![])
                .paid_delinquencies_result(vec![]);
            let config_mock = PersistentConfigurationMock::new().start_block_result(Ok(5));
            let subject = make_accountant(
                Some(config),
                Some(payable_dao),
                Some(receivable_dao),
                None,
                None,
                Some(config_mock),
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .accountant(accountant_mock)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Scanning for payments");
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(
            &RetrieveTransactions {
                start_block: 5u64,
                recipient: earning_wallet,
            },
            retrieve_transactions_message
        );

        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: No payments detected");
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(0, accountant_recording.len())
    }

    #[test]
    fn accountant_logs_error_when_blockchain_bridge_responds_with_error() {
        init_test_logging();
        let earning_wallet = make_wallet("earner3000");
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Err(
            BlockchainError::QueryFailed("really bad".to_string()),
        ));
        let blockchain_bridge_awaiter = blockchain_bridge.get_awaiter();
        let blockchain_bridge_recording = blockchain_bridge.get_recording();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(10_000),
                payment_received_scan_interval: Duration::from_millis(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );

        thread::spawn(move || {
            let system =
                System::new("accountant_logs_error_when_blockchain_bridge_responds_with_error");
            let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![])
                .paid_delinquencies_result(vec![]);
            let config_mock = PersistentConfigurationMock::new().start_block_result(Ok(0));
            let subject = make_accountant(
                Some(config),
                Some(payable_dao),
                Some(receivable_dao),
                None,
                None,
                Some(config_mock),
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        let retrieve_transactions_recording = blockchain_bridge_recording.lock().unwrap();
        let retrieve_transactions_message =
            retrieve_transactions_recording.get_record::<RetrieveTransactions>(0);
        assert_eq!(earning_wallet, retrieve_transactions_message.recipient);

        TestLogHandler::new().exists_log_containing(
            r#"WARN: Accountant: Unable to retrieve transactions from Blockchain Bridge: QueryFailed("really bad")"#,
        );
    }

    #[test]
    fn accountant_receives_new_payments_to_the_receivables_dao() {
        let wallet = make_wallet("wallet0");
        let earning_wallet = make_wallet("earner3000");
        let gwei_amount = 42u64;
        let expected_payment = Transaction {
            block_number: 7u64,
            from: wallet.clone(),
            gwei_amount,
        };
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_parameters(&more_money_received_params_arc)
            .more_money_received_result(Ok(()))
            .more_money_received_result(Ok(()));
        let accountant = make_accountant(
            Some(bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payable_scan_interval: Duration::from_secs(10_000),
                    payment_received_scan_interval: Duration::from_secs(10_000),
                    pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                },
                earning_wallet.clone(),
            )),
            Some(PayableDaoMock::new().non_pending_payables_result(vec![])),
            Some(receivable_dao),
            None,
            None,
            None,
        );

        let system = System::new("accountant_receives_new_payments_to_the_receivables_dao");
        let subject = accountant.start();

        subject
            .try_send(ReceivedPayments {
                payments: vec![expected_payment.clone(), expected_payment.clone()],
            })
            .expect("unexpected actix error");
        System::current().stop();
        system.run();
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(1, more_money_received_params.len());

        let more_money_received_params = more_money_received_params.get(0).unwrap();
        assert_eq!(2, more_money_received_params.len());

        let first_payment = more_money_received_params.get(0).unwrap();
        assert_eq!(expected_payment.from, first_payment.from);
        assert_eq!(gwei_amount, first_payment.gwei_amount);
        let second_payment = more_money_received_params.get(1).unwrap();
        assert_eq!(expected_payment.from, second_payment.from);
        assert_eq!(gwei_amount, second_payment.gwei_amount);
    }

    #[test]
    fn accountant_payable_scan_timer_triggers_scanning_for_payables() {
        init_test_logging();
        let (blockchain_bridge, blockchain_bridge_awaiter, _) = make_recorder();
        let blockchain_bridge = blockchain_bridge
            .retrieve_transactions_response(Ok(vec![]))
            .report_accounts_payable_response(Ok(vec![]));

        thread::spawn(move || {
            let system =
                System::new("accountant_payable_scan_timer_triggers_scanning_for_payables");
            let config = bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payable_scan_interval: Duration::from_millis(100),
                    payment_received_scan_interval: Duration::from_secs(100),
                    pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                },
                make_wallet("hi"),
            );
            let now = to_time_t(SystemTime::now());
            // slightly above minimum balance, to the right of the curve (time intersection)
            let account0 = PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
                rowid: 5,
            };
            let account1 = PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 2,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 12,
                ),
                pending_payment_transaction: None,
                rowid: 7,
            };
            let payable_dao = PayableDaoMock::new()
                .non_pending_payables_result(vec![account0, account1])
                .non_pending_payables_result(vec![]);
            let subject = make_accountant(Some(config), Some(payable_dao), None, None, None, None);
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Scanning for payables");
    }

    #[test]
    fn accountant_scans_after_startup() {
        init_test_logging();
        let (blockchain_bridge, _, _) = make_recorder();

        let system = System::new("accountant_scans_after_startup");
        let config = bc_from_ac_plus_wallets(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(1000),
                payment_received_scan_interval: Duration::from_secs(1000),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            make_wallet("buy"),
            make_wallet("hi"),
        );
        let subject = make_accountant(Some(config), None, None, None, None, None);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let subject_addr: Addr<Accountant> = subject.start();
        let subject_subs = Accountant::make_subs_from(&subject_addr);

        send_bind_message!(subject_subs, peer_actors);
        send_start_message!(subject_subs);

        System::current().stop();
        system.run();

        let tlh = TestLogHandler::new();
        tlh.await_log_containing("DEBUG: Accountant: Scanning for payables", 1000u64);
        tlh.exists_log_containing(&format!(
            "DEBUG: Accountant: Scanning for payments to {}",
            make_wallet("hi")
        ));
        tlh.exists_log_containing("DEBUG: Accountant: Scanning for delinquencies");
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(1000),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
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
                pending_payment_transaction: None,
                rowid: 1,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec + 10,
                ),
                pending_payment_transaction: None,
                rowid: 2,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub - 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 1,
                ),
                pending_payment_transaction: None,
                rowid: 3,
            },
        ];
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub =
            blockchain_bridge_addr.recipient::<ReportAccountsPayable>();
        let mut subject = make_accountant(Some(config), Some(payable_dao), None, None, None, None);
        subject.report_accounts_payable_sub = Some(report_accounts_payable_sub);

        subject.scan_for_payables();

        System::current().stop_with_code(0);
        system.run();

        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_payables_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_millis(100),
                payment_received_scan_interval: Duration::from_millis(1_000),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
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
                pending_payment_transaction: None,
                rowid: 1,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 10,
                ),
                pending_payment_transaction: None,
                rowid: 2,
            },
        ];
        let payable_dao = PayableDaoMock::default()
            .non_pending_payables_result(accounts.clone())
            .non_pending_payables_result(vec![]);
        let (mut blockchain_bridge, blockchain_bridge_awaiter, blockchain_bridge_recordings_arc) =
            make_recorder();
        blockchain_bridge = blockchain_bridge
            .retrieve_transactions_response(Ok(vec![]))
            .report_accounts_payable_response(Ok(vec![]));

        thread::spawn(move || {
            let system = System::new(
                "scan_for_payables_message_triggers_payment_for_balances_over_the_curve",
            );

            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject = make_accountant(Some(config), Some(payable_dao), None, None, None, None);
            let subject_addr = subject.start();
            let accountant_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(accountant_subs, peer_actors);
            send_start_message!(accountant_subs);

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable { accounts }
        );
    }

    #[test]
    fn payment_received_scan_triggers_scan_for_delinquencies() {
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let ban_parameters_arc_inner = ban_parameters_arc.clone();
        let blockchain_bridge = Recorder::new().retrieve_transactions_response(Ok(vec![]));
        thread::spawn(move || {
            let system = System::new("payment_received_scan_triggers_scan_for_delinquencies");
            let config = bc_from_ac_plus_earning_wallet(
                AccountantConfig {
                    payable_scan_interval: Duration::from_secs(10_000),
                    payment_received_scan_interval: Duration::from_millis(100),
                    pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
                },
                make_wallet("hi"),
            );

            let payable_dao = PayableDaoMock::new().non_pending_payables_result(vec![]);
            let receivable_dao = ReceivableDaoMock::new()
                .new_delinquencies_result(vec![make_receivable_account(1234, true)])
                .paid_delinquencies_result(vec![]);
            let banned_dao = BannedDaoMock::new()
                .ban_list_result(vec![])
                .ban_parameters(&ban_parameters_arc_inner);
            let subject = make_accountant(
                Some(config),
                Some(payable_dao),
                Some(receivable_dao),
                None,
                Some(banned_dao),
                None,
            );
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            send_bind_message!(subject_subs, peer_actors);
            send_start_message!(subject_subs);

            system.run();
        });

        thread::sleep(Duration::from_millis(200));

        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert_eq!(
            "0x00000000000000000077616c6c65743132333464",
            &format!("{:#x}", &ban_parameters[0].address())
        );
    }

    #[test]
    fn scan_for_received_payments_handles_error_retrieving_start_block() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Err(PersistentConfigError::NotPresent));
        let mut subject = make_accountant(None, None, None, None, None, Some(persistent_config));

        subject.scan_for_received_payments();

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("ERROR: Accountant: Could not retrieve start block: NotPresent - aborting received-payment scan");
    }

    #[test]
    fn scan_for_delinquencies_triggers_bans_and_unbans() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(1000),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
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
        let mut subject = make_accountant(
            Some(config),
            Some(payable_dao),
            Some(receivable_dao),
            None,
            Some(banned_dao),
            None,
        );

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
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            consuming_wallet.clone(),
            make_wallet("our earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            make_wallet("hi"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            consuming_wallet.clone(),
            make_wallet("the earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            make_wallet("hi"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc)
            .more_money_receivable_result(Ok(()));
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            consuming_wallet.clone(),
            make_wallet("my earning wallet"),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new().non_pending_payables_result(vec![]);
        let receivable_dao_mock = ReceivableDaoMock::new()
            .more_money_receivable_parameters(&more_money_receivable_parameters_arc);
        let subject = make_accountant(
            Some(config),
            Some(payable_dao_mock),
            Some(receivable_dao_mock),
            None,
            None,
            None,
        );
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
    fn report_exit_service_consumed_message_is_received() {
        init_test_logging();
        let config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            make_wallet("hi"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone())
            .more_money_payable_result(Ok(()));
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            consuming_wallet.clone(),
            make_wallet("own earning wallet"),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
                pending_transaction_check_interval_ms: DEFAULT_PENDING_TX_CHECKOUT_INTERVAL_MS,
            },
            earning_wallet.clone(),
        );
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = PayableDaoMock::new()
            .non_pending_payables_result(vec![])
            .more_money_payable_parameters(more_money_payable_parameters_arc.clone());
        let subject = make_accountant(Some(config), Some(payable_dao_mock), None, None, None, None);
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
    fn record_service_provided_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            None,
            Some(
                ReceivableDaoMock::new()
                    .more_money_receivable_result(Err(DebtRecordingError::SignConversion(1234))),
            ),
            None,
            None,
            None,
        );

        subject.record_service_provided(std::i64::MAX as u64, 1, 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error trying to record service provided to Node with consuming wallet {}: service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            std::i64::MAX as u64
        ));
    }

    #[test]
    fn record_service_consumed_handles_overflow() {
        init_test_logging();
        let wallet = make_wallet("booga");
        let subject = make_accountant(
            None,
            Some(
                PayableDaoMock::new()
                    .more_money_payable_result(Err(DebtRecordingError::SignConversion(1234))),
            ),
            None,
            None,
            None,
            None,
        );

        subject.record_service_consumed(std::i64::MAX as u64, 1, 2, &wallet);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error trying to record service consumed from Node with earning wallet {}: service rate {}, byte rate 1, payload size 2. Skipping",
            wallet,
            std::i64::MAX as u64
        ));
    }

    #[test]
    fn handle_sent_payments_receives_successful_payments_but_soon_fails_at_its_own_place_and_then_separates_successes_from_failures(
    ) {
        let payment_sent_params_arc = Arc::new(Mutex::new(vec![]));
        let payment_1_hash = H256::from_uint(&U256::from(123));
        let payment_2_hash = H256::from_uint(&U256::from(789));
        let wallet_1 = make_wallet("booga");
        let wallet_2 = make_wallet("booga_booga");
        let now_system = SystemTime::now();
        let payment_1 = Payment::new(
            wallet_1.clone(),
            6789,
            payment_1_hash,
            now_system,
            earlier_in_seconds(1000),
            1,
        );
        let payment_2 = Payment::new(
            wallet_2.clone(),
            5500,
            payment_2_hash,
            now_system,
            earlier_in_seconds(2000),
            2,
        );
        let payments = SentPayments {
            payments: vec![Ok(payment_1), Ok(payment_2.clone())],
        };
        let mut subject = make_accountant(
            None,
            Some(
                PayableDaoMock::new()
                    .mark_pending_payment_params(&payment_sent_params_arc)
                    .mark_pending_payment_result(Err(PaymentError::PostTransaction(
                        PaymentErrorKind::SignConversion(99999),
                        payment_1_hash,
                    )))
                    .mark_pending_payment_result(Ok(())),
            ),
            None,
            None,
            None,
            None,
        );

        let (ok_payments, mut errors) = subject.handle_sent_payments(payments);

        assert_eq!(
            ok_payments,
            vec![PaymentWithMetadata {
                payment: payment_2,
                receipt_failure_count: 0
            }]
        );
        assert_eq!(
            errors,
            vec![PaymentError::PostTransaction(
                SignConversion(99999),
                payment_1_hash
            )]
        );
        let mark_pending_payment_params = payment_sent_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payment_params,
            vec![(wallet_1, payment_1_hash), (wallet_2, payment_2_hash)]
        )
    }

    #[test]
    fn handle_sent_payments_receives_one_payment_being_incorrect_and_one_correct() {
        let now_system = SystemTime::now();
        let payment_hash_1 = H256::from_uint(&U256::from(789));
        let payment_1 = Err(PaymentError::PreTransaction(
            PaymentErrorKind::BlockchainError("wrong wallet".to_string()),
            payment_hash_1,
        ));
        let payment_hash_2 = H256::from_uint(&U256::from(123));
        let payment_2 = Payment::new(
            make_wallet("booga"),
            6789,
            payment_hash_2,
            now_system,
            earlier_in_seconds(1000),
            2,
        );
        let rowid_assigned_for_payment_2 = 4;
        let payments = SentPayments {
            payments: vec![payment_1, Ok(payment_2.clone())],
        };
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            //one seems to be missing, not really, the execution short-circuited at the outer error
            .insert_backup_record_result(Ok(()));
        let mut subject = make_accountant(
            None,
            Some(PayableDaoMock::new().mark_pending_payment_result(Ok(()))),
            None,
            Some(pending_payments_dao),
            None,
            None,
        );

        let (ok_payments, mut errors) = subject.handle_sent_payments(payments);

        assert_eq!(
            ok_payments,
            vec![PaymentWithMetadata {
                payment: payment_2,
                receipt_failure_count: 0
            }]
        );
        assert_eq!(
            errors,
            vec![PaymentError::PreTransaction(
                PaymentErrorKind::BlockchainError("wrong wallet".to_string()),
                payment_hash_1
            )]
        )
    }

    #[test]
    fn handle_sent_payments_handles_overflow() {
        init_test_logging();
        let now_system = SystemTime::now();
        let wallet = make_wallet("booga");
        let tx_hash = H256::from_uint(&U256::from(1));
        let payments = SentPayments {
            payments: vec![Ok(Payment::new(
                wallet.clone(),
                u64::MAX,
                tx_hash,
                now_system,
                earlier_in_seconds(1000),
                1,
            ))],
        };
        let mut subject = make_accountant(
            None,
            Some(PayableDaoMock::new().mark_pending_payment_result(Err(
                PaymentError::PostTransaction(PaymentErrorKind::SignConversion(1234), tx_hash),
            ))),
            None,
            None,
            None,
            None,
        );

        subject.handle_sent_payments(payments);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Accountant: Overflow error trying to record payment of {} sent to earning wallet {} (transaction {}). Skipping",
            u64::MAX,
            wallet,
            H256::from_uint(&U256::from(1))
        ));
    }

    #[test]
    fn handle_cancel_pending_transaction_works_for_real() {
        unimplemented!()
        // init_test_logging();
        // let home_dir = ensure_node_home_directory_exists(
        //     "accountant",
        //     "handle_cancel_pending_transaction_works_for_real",
        // );
        // let dao_factory = DaoFactoryReal::new(&home_dir, true, MigratorConfig::test_default());
        // let mut subject = AccountantBuilder::default()
        //     .payable_dao_factory(Box::new(dao_factory))
        //     .build();
        // let tx_hash = H256::from("sometransactionhash".keccak256());
        // let recipient_wallet = make_wallet("wallet");
        // let amount = 4567;
        // let timestamp_from_time_of_payment = SystemTime::now();
        // let invalid_payment = Payment {
        //     to: recipient_wallet.clone(),
        //     amount,
        //     timestamp: timestamp_from_time_of_payment,
        //     previous_timestamp: earlier_in_seconds(1000),
        //     transaction: tx_hash,
        // };
        // let sent_payment_msg = SentPayments {
        //     payments: vec![Ok(invalid_payment.clone())],
        // };
        // let conn_for_assertion = DbInitializerReal::default()
        //     .initialize(&home_dir, false, MigratorConfig::test_default())
        //     .unwrap();
        // let mut stm = conn_for_assertion
        //     .prepare("select * from payable where wallet_address = ?")
        //     .unwrap();
        // let res = stm.query_row(&[recipient_wallet.to_string()], |_row| Ok(()));
        // let err = res.unwrap_err();
        // assert_eq!(err, Error::QueryReturnedNoRows);
        // subject.handle_sent_payments(sent_payment_msg);
        // let closure = |row: &Row| {
        //     let wallet: String = row.get(0).unwrap();
        //     let balance: i64 = row.get(1).unwrap();
        //     let timestamp: i64 = row.get(2).unwrap();
        //     let pending_tx_hash_opt: Option<String> = row.get(3).unwrap();
        //     Ok((wallet, balance, timestamp, pending_tx_hash_opt))
        // };
        // let res = stm
        //     .query_row(&[recipient_wallet.to_string()], closure)
        //     .unwrap();
        // let (wallet, balance, timestamp, hash_opt) = res;
        // assert_eq!(wallet, recipient_wallet.to_string());
        // assert_eq!(balance, -(amount as i64));
        // assert_eq!(timestamp, to_time_t(timestamp_from_time_of_payment));
        // let hash = hash_opt.unwrap();
        // assert_eq!(H256::from_str(&hash[2..]).unwrap(), tx_hash);
        //
        // let _ = subject.handle_cancel_pending_transaction(CancelFailedPendingTransaction {
        //     hash: tx_hash
        // });
        //
        // let res = stm
        //     .query_row(&[recipient_wallet.to_string()], closure)
        //     .unwrap();
        // let (wallet, balance, timestamp, hash) = res;
        // assert_eq!(wallet, recipient_wallet.to_string());
        // assert_eq!(balance, 0);
        // assert_eq!(hash, None);
        // TestLogHandler::new().exists_log_containing("INFO: Accountant: Transaction 0x051a…8c19 \
        //  for wallet 0x000000000000000000000000000077616c6c6574 was successfully canceled; state of the \
        //   creditor's account was reverted back to balance 0");
    }

    #[test]
    fn handle_confirm_transaction_works_for_real() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "accountant",
            "handle_confirm_transaction_works_for_real",
        );
        let dao_factory = DaoFactoryReal::new(&home_dir, true, MigratorConfig::test_default());
        let mut subject = AccountantBuilder::default()
            .payable_dao_factory(Box::new(dao_factory))
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let recipient_wallet = make_wallet("wallet");
        let amount = 4567;
        let timestamp_from_time_of_payment = SystemTime::now();
        let payment = Payment {
            to: recipient_wallet.clone(),
            amount,
            timestamp: timestamp_from_time_of_payment,
            previous_timestamp: earlier_in_seconds(1000),
            transaction: tx_hash,
            rowid: 1,
        };
        let sent_payment_msg = SentPayments {
            payments: vec![Ok(payment.clone())],
        };
        let conn_for_assertion = DbInitializerReal::default()
            .initialize(&home_dir, false, MigratorConfig::test_default())
            .unwrap();
        let mut stm = conn_for_assertion
            .prepare("select * from payable where wallet_address = ?")
            .unwrap();
        subject.handle_sent_payments(sent_payment_msg);
        let closure = |row: &Row| {
            let wallet: String = row.get(0).unwrap();
            let balance: i64 = row.get(1).unwrap();
            let timestamp: i64 = row.get(2).unwrap();
            let pending_tx_hash_opt: Option<String> = row.get(3).unwrap();
            Ok((wallet, balance, timestamp, pending_tx_hash_opt))
        };
        let query_result = stm
            .query_row(&[recipient_wallet.to_string()], closure)
            .unwrap();

        let hash_opt = query_result.3.clone();
        let assertion_of_values_not_to_change =
            |query_result: (String, i64, i64, Option<String>)| {
                let (wallet, balance, timestamp, _) = query_result;
                assert_eq!(wallet, recipient_wallet.to_string());
                assert_eq!(balance, -(amount as i64)); //a bit nonsensical balance example but can be excused
                assert_eq!(timestamp, to_time_t(timestamp_from_time_of_payment));
            };
        assertion_of_values_not_to_change(query_result);
        let hash = hash_opt.unwrap();
        assert_eq!(H256::from_str(&hash[2..]).unwrap(), tx_hash);

        let _ = subject.handle_confirm_pending_transaction(ConfirmPendingTransaction { payment });

        let query_result = stm
            .query_row(&[recipient_wallet.to_string()], closure)
            .unwrap();
        let hash_opt = query_result.3.clone();
        assertion_of_values_not_to_change(query_result);
        assert_eq!(hash_opt, None);
        TestLogHandler::new().exists_log_containing(
            "INFO: Accountant: Transaction 051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 was confirmed"
        );
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn accountant_can_be_crashed_properly_but_not_improperly() {
        let mut config = BootstrapperConfig::default();
        config.crash_point = CrashPoint::Message;
        let accountant = make_accountant(Some(config), None, None, None, None, None);

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
                pending_payment_transaction: None,
                rowid: 1,
            },
            //this debt is more significant because beside being high in amount it's also older, so should be prioritized and picked
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: same_amount_significance,
                last_paid_timestamp: from_time_t(now - 10000),
                pending_payment_transaction: None,
                rowid: 2,
            },
            //similarly these two wallets have debts equally old but the second has a bigger balance and should be chosen
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance: 100,
                last_paid_timestamp: same_age_significance,
                pending_payment_transaction: None,
                rowid: 3,
            },
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: 330,
                last_paid_timestamp: same_age_significance,
                pending_payment_transaction: None,
                rowid: 4,
            },
        ];

        let result = Accountant::investigate_debt_extremes(payables);

        assert_eq!(result,"Payable scan found 4 debts; the biggest is 2000000 owed for 10000sec, the oldest is 330 owed for 30000sec")
    }

    #[test]
    fn payment_debug_summary_prints_a_nice_summary() {
        let now = to_time_t(SystemTime::now());
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1234,
                ),
                pending_payment_transaction: None,
                rowid: 1,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 1,
                ),
                pending_payment_transaction: None,
                rowid: 2,
            },
        ];

        let result = Accountant::payments_debug_summary(qualified_payables);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
    }

    #[test]
    fn pending_transaction_is_registered_and_monitored_until_it_gets_confirmed_or_canceled() {
        //We send a list of creditor accounts with mature debts to BlockchainBridge
        //he acts like he's sending transactions for paying them (the transacting part is mocked),
        //next BlockchainBridge rely payments to Accountant with PaymentSent message. There we take care of an update
        //of the payables table, marking a pending tx, after which we register a delayed self-notification
        //to send a message requesting fetching tx receipts, when we get the receipts we process
        //them and make and either registr another self-notification to repeat the cycle (that is for a still
        //pending transaction) or we can demand a cancellation for the reason of either getting a confirmation for
        //the transaction or for having a failure on that transaction.
        //One transaction is canceled after failure detected and the other is successfully confirmed.
        //When a transaction is being clean out, we remove marks from both payables and pending_payments tables.
        //It's a very similar procedure as for a confirmation or remotely happened failure (not a procedural
        //error within our code)
        //Extending beyond the scope of this test: If it were a failure occurred after the moment of sending
        //a theoretically correct transaction what we also call a post-transaction time and if it stands that
        //we can reach a solid backup of the payment we will do just a partial clean-up, leaving the confirmation
        //for another periodical scan for listed but still unconfirmed transactions (but this part is not a part
        //of this test)
        init_test_logging();
        let mark_pending_payment_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_canceled_params_arc = Arc::new(Mutex::new(vec![]));
        let get_transaction_receipt_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_check_for_confirmation_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_check_for_confirmation_params_arc_cloned =
            notify_later_check_for_confirmation_params_arc.clone(); //because it moves into a closure
        let notify_cancel_failed_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_cancel_failed_transaction_params_arc_cloned =
            notify_cancel_failed_transaction_params_arc.clone(); //because it moves into a closure
        let notify_confirm_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_confirm_transaction_params_arc_cloned =
            notify_confirm_transaction_params_arc.clone(); //because it moves into a closure
                                                           //these belongs to 'pending_payment' table
        let insert_record_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_record_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_tx_hash_1 = H256::from_uint(&U256::from(123));
        let pending_tx_hash_2 = H256::from_uint(&U256::from(567));
        let rowid_for_account_1 = 3;
        let rowid_for_account_2 = 5;
        let payment_timestamp_1 = from_time_t(to_time_t(SystemTime::now()) - 2);
        let payment_timestamp_2 = SystemTime::now();
        let transaction_receipt_tx_2_first_round = TransactionReceipt::default();
        let transaction_receipt_tx_1_second_round = TransactionReceipt::default();
        let transaction_receipt_tx_2_second_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_1_third_round = TransactionReceipt::default();
        transaction_receipt_tx_1_third_round.status = Some(U64::from(1)); //failure
        let transaction_receipt_tx_2_third_round = TransactionReceipt::default();
        let mut transaction_receipt_tx_2_fourth_round = TransactionReceipt::default();
        transaction_receipt_tx_2_fourth_round.status = Some(U64::from(0)); // confirmed
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_count_result(Ok(web3::types::U256::from(1)))
            .get_transaction_count_result(Ok(web3::types::U256::from(2)))
            //because we cannot have both, resolution on the higher level and also regarding what's inside blockchain interface,
            //there is (only) one component that is missing in this wholesome test - the part where we send a request to create
            //a backup for the payment's parameters in the DB - this happens inside send_raw_transaction()
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_tools_result(Box::new(SendTransactionToolWrapperNull))
            .send_transaction_result(Ok((pending_tx_hash_1, payment_timestamp_1)))
            .send_transaction_result(Ok((pending_tx_hash_2, payment_timestamp_2)))
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
        let pending_tx_checkout_interval_ms = 10;
        let blockchain_bridge = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            Some(consuming_wallet),
        );
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payment_params(&mark_pending_payment_params_arc)
            .mark_pending_payment_result(Ok(()))
            .mark_pending_payment_result(Ok(()))
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_canceled_params(&transaction_canceled_params_arc)
            .transaction_canceled_result(Ok(()));
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                payment_received_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                pending_transaction_check_interval_ms: pending_tx_checkout_interval_ms,
            },
            make_wallet("some_wallet_address"),
        );
        let pending_payments_dao = PendingPaymentsDaoMock::default()
            .insert_backup_record_params(&insert_record_params_arc)
            .insert_backup_record_result(Ok(()))
            .insert_backup_record_result(Ok(()))
            .delete_backup_record_params(&delete_record_params_arc)
            .delete_backup_record_result(Ok(()));
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let mut subject = make_accountant(
                    Some(bootstrapper_config),
                    Some(payable_dao),
                    None,
                    Some(pending_payments_dao),
                    None,
                    None,
                );
                let notify_later_half_mock = NotifyLaterHandleMock::default()
                    .notify_later_params(&notify_later_check_for_confirmation_params_arc_cloned);
                subject
                    .transaction_confirmation
                    .notify_handle_request_transaction_receipts = Box::new(notify_later_half_mock);
                let notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_cancel_failed_transaction_params_arc_cloned);
                subject
                    .transaction_confirmation
                    .notify_handle_cancel_failed_transaction = Box::new(notify_half_mock);
                let notify_half_mock = NotifyHandleMock::default()
                    .notify_params(&notify_confirm_transaction_params_arc_cloned);
                subject
                    .transaction_confirmation
                    .notify_handle_confirm_tx_after_success = Box::new(notify_half_mock);
                subject
            });
        let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let cloned_recipient_for_sent_payments = accountant_subs.report_sent_payments.clone();
        peer_actors.accountant = accountant_subs.clone();
        let blockchain_bridge_addr = blockchain_bridge.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        let wallet_account_1 = make_wallet("creditor1");
        let last_paid_timestamp_1 = from_time_t(to_time_t(SystemTime::now()) - 150);
        let last_paid_timestamp_2 = from_time_t(to_time_t(SystemTime::now()) - 200);
        let account_1 = PayableAccount {
            wallet: wallet_account_1.clone(),
            balance: 5500,
            last_paid_timestamp: last_paid_timestamp_1,
            pending_payment_transaction: None,
            rowid: rowid_for_account_1,
        };
        let wallet_account_2 = make_wallet("creditor2");
        let account_2 = PayableAccount {
            wallet: wallet_account_2.clone(),
            balance: 123456,
            last_paid_timestamp: last_paid_timestamp_2,
            pending_payment_transaction: None,
            rowid: rowid_for_account_2,
        };
        let creditor_message = ReportAccountsPayable {
            accounts: vec![account_1, account_2],
        };
        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);

        let response = blockchain_bridge_addr.send(creditor_message);

        let future = response.then(move |results| match results {
            Ok(Ok(results)) => {
                let results_converted = results
                    .into_iter()
                    .map(|item| item.map_err(PaymentError::from))
                    .collect();
                cloned_recipient_for_sent_payments
                    .try_send(SentPayments {
                        payments: results_converted,
                    })
                    .expect("Accountant is dead");
                Ok(())
            }
            x => panic!("{:?}", x),
        });
        actix::spawn(future);

        //I need one more actor on an Arbiter's thread (able to invoke a panic if something's wrong);
        //the main subject - BlockchainBridge - is clumsy regarding combining its creation and an Arbiter, so I used this solution
        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 3000 })
            .unwrap();
        assert_eq!(system.run(), 0);
        let mut mark_pending_payment_parameters = mark_pending_payment_params_arc.lock().unwrap();
        let first_payment = mark_pending_payment_parameters.remove(0);
        assert_eq!(first_payment.0, wallet_account_1);
        assert_eq!(first_payment.1, pending_tx_hash_1);
        let second_payment = mark_pending_payment_parameters.remove(0);
        assert!(
            mark_pending_payment_parameters.is_empty(),
            "{:?}",
            mark_pending_payment_parameters
        );
        assert_eq!(second_payment.0, wallet_account_2);
        assert_eq!(second_payment.1, pending_tx_hash_2);
        let expected_params_for_payment_1 = Payment {
            to: wallet_account_1.clone(),
            amount: 5500,
            timestamp: from_time_t(0), //deliberately wrong; I cannot compare the right ones
            previous_timestamp: last_paid_timestamp_1,
            transaction: pending_tx_hash_1,
            rowid: rowid_for_account_1,
        };
        let mut transaction_canceled_params = transaction_canceled_params_arc.lock().unwrap();
        let cancellation_param_for_tx_1 = transaction_canceled_params.remove(0);
        assert!(transaction_canceled_params.is_empty());
        assert_eq!(
            cancellation_param_for_tx_1.0,
            expected_params_for_payment_1.to
        );
        assert_eq!(
            cancellation_param_for_tx_1.1,
            expected_params_for_payment_1.transaction
        );
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
        let delete_record_params = delete_record_params_arc.lock().unwrap();
        assert_eq!(*delete_record_params, vec![rowid_for_account_1]);
        let expected_params_for_payment_2 = Payment {
            to: wallet_account_2,
            amount: 123456,
            timestamp: from_time_t(0), //deliberately wrong; I cannot compare the right ones
            previous_timestamp: last_paid_timestamp_2,
            transaction: pending_tx_hash_2,
            rowid: rowid_for_account_2,
        };
        let mut transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        let payment_confirmed = transaction_confirmed_params.remove(0);
        assert!(transaction_confirmed_params.is_empty());
        assert_eq!(payment_confirmed.to, expected_params_for_payment_2.to);
        assert_eq!(
            payment_confirmed.amount,
            expected_params_for_payment_2.amount
        );
        assert_eq!(
            payment_confirmed.transaction,
            expected_params_for_payment_2.transaction
        );
        assert_eq!(payment_confirmed.rowid, expected_params_for_payment_2.rowid);
        let first_expected_request_tx_receipts_msg_and_interval = (
            RequestTransactionReceipts {
                pending_payments: vec![
                    PaymentWithMetadata {
                        payment: expected_params_for_payment_1,
                        receipt_failure_count: 0,
                    },
                    PaymentWithMetadata {
                        payment: expected_params_for_payment_2.clone(),
                        receipt_failure_count: 0,
                    },
                ],
                attempt: 1,
            },
            Duration::from_millis(pending_tx_checkout_interval_ms),
        );
        let mut second_expected_request_tx_receipts_msg_and_interval =
            first_expected_request_tx_receipts_msg_and_interval.clone();
        second_expected_request_tx_receipts_msg_and_interval
            .0
            .attempt = 2;
        let mut third_expected_request_tx_receipts_msg_and_interval =
            first_expected_request_tx_receipts_msg_and_interval.clone();
        third_expected_request_tx_receipts_msg_and_interval
            .0
            .attempt = 3;
        let fourth_expected_request_tx_msg_and_interval = (
            RequestTransactionReceipts {
                pending_payments: vec![PaymentWithMetadata {
                    payment: expected_params_for_payment_2.clone(),
                    receipt_failure_count: 0,
                }],
                attempt: 4,
            },
            Duration::from_millis(pending_tx_checkout_interval_ms),
        );
        let mut notify_later_check_for_confirmation =
            notify_later_check_for_confirmation_params_arc
                .lock()
                .unwrap();
        //I have to zero the timestamps generated at runtime
        notify_later_check_for_confirmation.iter_mut().for_each(
            |item: &mut (RequestTransactionReceipts, Duration)| {
                item.0.pending_payments.iter_mut().for_each(|payment| {
                    assert!(payment.payment.previous_timestamp < payment.payment.timestamp);
                    payment.payment.timestamp = from_time_t(0);
                })
            },
        );
        assert_eq!(
            *notify_later_check_for_confirmation,
            vec![
                first_expected_request_tx_receipts_msg_and_interval,
                second_expected_request_tx_receipts_msg_and_interval,
                third_expected_request_tx_receipts_msg_and_interval,
                fourth_expected_request_tx_msg_and_interval
            ]
        );
        let notify_cancel_failed_transaction_params =
            notify_cancel_failed_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *notify_cancel_failed_transaction_params,
            vec![CancelFailedPendingTransaction {
                tx_id: TxTripleId {
                    recipient_wallet: wallet_account_1,
                    hash: pending_tx_hash_1,
                    rowid: rowid_for_account_1
                }
            }]
        );
        let mut notify_confirm_transaction_params =
            notify_confirm_transaction_params_arc.lock().unwrap();
        let mut actual_confirmed_payment: ConfirmPendingTransaction =
            notify_confirm_transaction_params.remove(0);
        assert!(notify_confirm_transaction_params.is_empty());
        actual_confirmed_payment.payment.timestamp = from_time_t(0);
        assert_eq!(
            actual_confirmed_payment,
            ConfirmPendingTransaction {
                payment: expected_params_for_payment_2
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: Accountant: Transaction 0x0000…007b for wallet 0x00000000000000000000006372656469746f7231 was unmarked as pending due to cancellation");
        log_handler.exists_log_containing("INFO: Accountant: Broken transaction 0x0000…007b for wallet 0x00000000000000000000006372656469746f7231 was successfully canceled");
        log_handler.exists_log_matching("INFO: Accountant: Transaction '0x0000…0237' has been added to the blockchain; detected locally at attempt 4 at \\d{2,}ms after its sending");
        log_handler.exists_log_containing("INFO: Accountant: Confirmation of transaction 0000000000000000000000000000000000000000000000000000000000000237 was wholly processed");
    }

    #[test]
    //TODO finish this test later by adding code and assertions for coping with errors
    fn check_message_is_not_emitted_if_we_got_no_ok_payments_from_processed_transactions_and_testing_the_tx_cancellation_branch(
    ) {
        let notify_later_check_for_confirmation_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_check_for_confirmation_params_arc_cloned =
            notify_later_check_for_confirmation_params_arc.clone(); //because it moves into a closure
        let mark_pending_payment_params_arc = Arc::new(Mutex::new(vec![]));
        let tx_hash = H256::from_uint(&U256::from(78888));
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payment_params(&mark_pending_payment_params_arc)
            .mark_pending_payment_result(Err(PaymentError::PostTransaction(
                PaymentErrorKind::RusqliteError("database on fire".to_string()),
                tx_hash,
            )));
        let pending_tx_checkout_interval_ms = 2;
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                payment_received_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                pending_transaction_check_interval_ms: pending_tx_checkout_interval_ms,
            },
            make_wallet("some_wallet_address"),
        );
        let system = System::new("no pending tx");
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let mut subject = make_accountant(
                    Some(bootstrapper_config),
                    Some(payable_dao),
                    None,
                    None,
                    None,
                    None,
                );
                let notify_later_half_mock = NotifyLaterHandleMock::default()
                    .notify_later_params(&notify_later_check_for_confirmation_params_arc_cloned);
                subject
                    .transaction_confirmation
                    .notify_handle_request_transaction_receipts = Box::new(notify_later_half_mock);
                subject
            });
        //let mut peer_actors = peer_actors_builder().build();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        //peer_actors.accountant = accountant_subs.clone();
        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        let wallet = make_wallet("creditor1");
        let mut payment = make_payment();
        payment.to = wallet.clone();
        payment.transaction = tx_hash;
        //send_bind_message!(accountant_subs, peer_actors);

        let _ = accountant_subs
            .report_sent_payments
            .try_send(SentPayments {
                payments: vec![Ok(payment.clone())],
            })
            .unwrap();

        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 400 })
            .unwrap();
        assert_eq!(system.run(), 0);
        let mark_pending_params = mark_pending_payment_params_arc.lock().unwrap();
        assert_eq!(*mark_pending_params, vec![(wallet, tx_hash)]);
        let notify_later_check_for_confirmation_params =
            notify_later_check_for_confirmation_params_arc
                .lock()
                .unwrap();
        assert_eq!(*notify_later_check_for_confirmation_params, vec![])
    }

    #[test]
    fn the_first_message_introducing_the_pending_confirmation_process_marks_with_an_attempt_1_and_receipt_failure_count_0(
    ) {
        let mark_pending_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_transaction_params_arc_cloned =
            mark_pending_transaction_params_arc.clone(); //because it moves into a closure
        let notify_later_params_arc = Arc::new(Mutex::new(vec![]));
        let notify_later_params_arc_cloned = notify_later_params_arc.clone(); //because it moves into a closure
        let system = System::new("attempt of the first check message");
        let short_interval_to_speed_up_the_test_ms = 2;
        let (blockchain_bridge, _, recording_arc) = make_recorder();
        let accountant_arbiter = Arbiter::builder().stop_system_on_panic(true);
        let accountant_addr = accountant_arbiter.start(move |_| {
            let payable_dao = PayableDaoMock::default()
                .mark_pending_payment_params(&mark_pending_transaction_params_arc_cloned)
                .mark_pending_payment_result(Ok(()));
            let mut subject = AccountantBuilder::default()
                .payable_dao_factory(Box::new(PayableDaoFactoryMock::new(Box::new(payable_dao))))
                .build();
            let notify_later_check_message_handle = NotifyLaterHandleMock::default()
                .notify_later_params(&notify_later_params_arc_cloned);
            subject
                .transaction_confirmation
                .notify_handle_request_transaction_receipts =
                Box::new(notify_later_check_message_handle);
            subject
                .transaction_confirmation
                .pending_transaction_check_interval_ms = short_interval_to_speed_up_the_test_ms;
            subject
        });
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let peer_actors = peer_actors_builder()
            .blockchain_bridge(blockchain_bridge)
            .build();
        let wallet = make_wallet("creditor1");
        let tx_hash = H256::from_uint(&U256::from(4568));
        let mut payment = make_payment();
        payment.to = wallet.clone();
        payment.transaction = tx_hash;
        send_bind_message!(accountant_subs, peer_actors);

        let _ = accountant_subs
            .report_sent_payments
            .try_send(SentPayments {
                payments: vec![Ok(payment.clone())],
            })
            .unwrap();

        let dummy_actor = DummyActor::new(None);
        let dummy_actor_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        dummy_actor_addr
            .try_send(CleanUpMessage { sleep_ms: 1 })
            .unwrap();
        assert_eq!(system.run(), 0);
        let mark_pending_transaction_params = mark_pending_transaction_params_arc.lock().unwrap();
        assert_eq!(*mark_pending_transaction_params, vec![(wallet, tx_hash)]);
        let notify_later_params = notify_later_params_arc.lock().unwrap();
        assert_eq!(
            *notify_later_params,
            [(
                RequestTransactionReceipts {
                    pending_payments: vec![PaymentWithMetadata {
                        payment,
                        receipt_failure_count: 0
                    }],
                    attempt: 1
                },
                Duration::from_millis(short_interval_to_speed_up_the_test_ms)
            )]
        )
    }

    #[test]
    fn handle_pending_tx_checkout_handles_none_returned_for_tx_receipt() {
        init_test_logging();
        let blockchain_interface =
            BlockchainInterfaceMock::default().get_transaction_receipt_result(Ok(None));
        let subject = AccountantBuilder::default().build();
        let tx_receipt = Ok(None);
        let payment = make_payment();
        let meta_payment = PaymentWithMetadata {
            payment,
            receipt_failure_count: 0,
        };
        let msg = ReportTransactionReceipts {
            payments_with_tx_receipts: vec![(tx_receipt, meta_payment.clone())],
            attempt: 3,
        };

        let result = subject.handle_pending_txs_check(msg.clone());

        assert_eq!(
            result,
            vec![PendingTransactionStatus::StillPending {
                payment: meta_payment,
                attempt: 3
            }]
        );
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Tracking an attempt to interpret a receipt for transaction 0x0000…01c8 but None was received; attempt 3, retrying");
    }

    #[test]
    fn receipt_check_for_pending_tx_when_tx_status_is_a_failure() {
        init_test_logging();
        let blockchain_interface =
            BlockchainInterfaceMock::default().get_transaction_receipt_result(Ok(None));
        let subject = AccountantBuilder::default().build();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(1)); //failure
        let wallet = make_wallet("blah");
        let hash = H256::from_uint(&U256::from(4567));
        let mut payment = make_payment();
        payment.transaction = hash;
        payment.to = wallet.clone();
        payment.timestamp = SystemTime::now().sub(Duration::from_secs(150));

        let meta_payment = PaymentWithMetadata {
            payment,
            receipt_failure_count: 0,
        };
        let attempt = 5;

        let result = subject.receipt_check_for_pending_tx(
            tx_receipt,
            meta_payment,
            attempt,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(TxTripleId {
                recipient_wallet: wallet,
                hash,
                rowid: 1
            })
        );
        TestLogHandler::new().exists_log_containing("WARN: receipt_check_logger: Pending \
         transaction '0x0000…11d7' announced as a failure on the check of attempt 5 at 150000ms after its sending");
    }

    #[test]
    fn receipt_check_for_pending_tx_when_tx_status_is_none() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let tx_receipt = TransactionReceipt::default();
        let when_sent = SystemTime::now().sub(Duration::from_millis(100));
        let previous_timestamp = when_sent.checked_sub(Duration::from_secs(15)).unwrap();
        let attempt = 1;
        let subject = AccountantBuilder::default().build();
        let payment = Payment {
            to: make_wallet("blah"),
            amount: 123,
            timestamp: when_sent,
            previous_timestamp,
            transaction: hash,
            rowid: 1,
        };
        let meta_payment = PaymentWithMetadata {
            payment,
            receipt_failure_count: 0,
        };

        let result = subject.receipt_check_for_pending_tx(
            tx_receipt,
            meta_payment.clone(),
            attempt,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending {
                payment: meta_payment,
                attempt
            }
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: receipt_check_logger: Pending \
         transaction '0x0000…0237' couldn't be confirmed at attempt 1 at 100ms after its sending",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b' - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn receipt_check_for_pending_tx_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut payment = make_payment();
        payment.transaction = H256::from_uint(&U256::from(123));
        let meta_paymenet = PaymentWithMetadata {
            payment,
            receipt_failure_count: 0,
        };
        let subject = AccountantBuilder::default().build();

        let _ = subject.receipt_check_for_pending_tx(
            tx_receipt,
            meta_paymenet,
            1,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn handle_pending_tx_checkout_handles_error_from_tx_receipt_but_payment_backup_is_okay_so_it_just_terminates(
    ) {
        init_test_logging();
        let read_backup_record_params_arc = Arc::new(Mutex::new(vec![]));
        let rowid = 7;
        let recipient_wallet = make_wallet("creditor");
        let hash = H256::from_uint(&U256::from(789));
        let payment_timestamp = from_time_t(200_000_000);
        let payment_backup = PendingPaymentBackup {
            rowid,
            payment_timestamp,
            amount: 100, //irrelevant
        };
        let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .read_backup_record_params(&read_backup_record_params_arc)
                .read_backup_record_result(Ok(payment_backup)),
        );
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
            .build();
        let mut payment = make_payment();
        payment.to = recipient_wallet.clone();
        payment.transaction = hash;
        payment.rowid = rowid;
        let tx_receipt: TxReceipt = Err(BlockchainError::QueryFailed(
            "we couldn't fetch the data".to_string(),
        ));
        let msg = ReportTransactionReceipts {
            payments_with_tx_receipts: vec![(
                tx_receipt,
                PaymentWithMetadata {
                    payment,
                    receipt_failure_count: 0,
                },
            )],
            attempt: 1,
        };

        let result = subject.handle_pending_txs_check(msg);

        let expected_tx_tripleid = TxTripleId {
            recipient_wallet,
            hash,
            rowid,
        };
        assert_eq!(
            result,
            vec![PendingTransactionStatus::ConfirmationProcessCrashed(
                expected_tx_tripleid
            )]
        );
        let read_backup_params = read_backup_record_params_arc.lock().unwrap();
        assert_eq!(*read_backup_params, vec![rowid]);
        TestLogHandler::new().exists_log_containing("WARN: Accountant: Failed to fetch transaction \
         receipt for pending transaction 0000000000000000000000000000000000000000000000000000000000000315 due \
         to 'QueryFailed(\"we couldn't fetch the data\")'; given the backup of this payment is all right the \
         confirmation process is now terminating but will be renewed with another scan cycle");
    }

    #[test]
    fn handle_pending_tx_checkout_handles_error_from_tx_receipt_but_payment_backup_is_also_wrong_so_it_commands_a_retry_twice_and_succeeds_in_the_last_run(
    ) {
        init_test_logging();
        let read_backup_record_params_arc = Arc::new(Mutex::new(vec![]));
        let read_backup_record_params_arc_cloned = read_backup_record_params_arc.clone(); //because it moves into closure
        let rowid = 7;
        let recipient_wallet = make_wallet("creditor");
        let hash = H256::from_uint(&U256::from(789));
        let payment_timestamp = from_time_t(200_000_000);
        let mut transaction_receipt = TransactionReceipt::default();
        transaction_receipt.status = Some(U64::from(0)); //Success
        let blockchain_interface = BlockchainInterfaceMock::default()
            .get_transaction_receipt_result(Err(BlockchainError::QueryFailed("So bad".to_string())))
            .get_transaction_receipt_result(Err(BlockchainError::TransactionFailed(
                "weird".to_string(),
            )))
            .get_transaction_receipt_result(Ok(Some(transaction_receipt)));
        let consuming_wallet = make_paying_wallet(b"wallet");
        let system = System::new("pending_transaction");
        let persistent_config = PersistentConfigurationMock::default().gas_price_result(Ok(130));
        let pending_tx_checkout_interval_ms = 10;
        let blockchain_bridge = BlockchainBridge::new(
            Box::new(blockchain_interface),
            Box::new(persistent_config),
            false,
            Some(consuming_wallet),
        );
        let blockchain_bridge_addr = blockchain_bridge.start();
        let blockchain_bridge_subs = BlockchainBridge::make_subs_from(&blockchain_bridge_addr);
        let system = System::new("fetching tx receipt with failure and retry");
        let bootstrapper_config = bc_from_ac_plus_earning_wallet(
            AccountantConfig {
                payable_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                payment_received_scan_interval: Duration::from_secs(1_000_000), //we don't care about the scan
                pending_transaction_check_interval_ms: pending_tx_checkout_interval_ms,
            },
            make_wallet("some_wallet_address"),
        );
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payment_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        let accountant_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| {
                let payment_backup = PendingPaymentBackup {
                    rowid,
                    payment_timestamp,
                    amount: 0,
                };
                let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
                    PendingPaymentsDaoMock::default()
                        .read_backup_record_params(&read_backup_record_params_arc_cloned)
                        .read_backup_record_result(Err(PendingPaymentDaoError::RecordCannotBeRead))
                        .read_backup_record_result(Err(PendingPaymentDaoError::RecordCannotBeRead)),
                );
                let payable_dao_factory = PayableDaoFactoryMock::new(Box::new(payable_dao));
                let subject = AccountantBuilder::default()
                    .pending_payments_dao_factory(Box::new(pending_payments_dao_factory))
                    .payable_dao_factory(Box::new(payable_dao_factory))
                    .bootstrapper_config(bootstrapper_config)
                    .build();
                subject
            });
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let mut payment = make_payment();
        payment.to = recipient_wallet.clone();
        payment.transaction = hash;
        payment.rowid = rowid;
        let dummy_actor = DummyActor::new(None);
        let dummy_addr = Arbiter::builder()
            .stop_system_on_panic(true)
            .start(move |_| dummy_actor);
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.accountant = accountant_subs.clone();
        peer_actors.blockchain_bridge = blockchain_bridge_subs.clone();
        send_bind_message!(accountant_subs, peer_actors);
        send_bind_message!(blockchain_bridge_subs, peer_actors);
        let msg = SentPayments {
            payments: vec![Ok(payment)],
        };

        let _ = accountant_subs.report_sent_payments.try_send(msg).unwrap();

        let _ = dummy_addr.try_send(CleanUpMessage { sleep_ms: 1 });
        assert_eq!(system.run(), 0);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("WARN: Accountant: Failed to fetch transaction receipt for pending transaction \
         0000000000000000000000000000000000000000000000000000000000000315 due to 'QueryFailed(\"So bad\")'; moreover a payment backup failure detected 'RecordCannotBeRead'; attempting retries with maximal count 2 - now 1");
        log_handler.exists_log_containing("WARN: Accountant: Failed to fetch transaction receipt for pending transaction \
         0000000000000000000000000000000000000000000000000000000000000315 due to 'TransactionFailed(\"weird\")'; moreover a payment backup failure detected 'RecordCannotBeRead'; attempting retries with maximal count 2 - now 2");
        log_handler.exists_log_containing("INFO: Accountant: Confirmation of transaction 0000000000000000000000000000000000000000000000000000000000000315 was wholly processed");
    }

    #[test]
    fn merging_pending_tx_works_including_incrementing_the_attempt_number() {
        let confirmed_status = PendingTransactionStatus::Confirmed(Payment {
            to: make_wallet("brrr"),
            amount: 121212,
            timestamp: from_time_t(300_000_000),
            previous_timestamp: from_time_t(290_000_000),
            transaction: H256::from_uint(&U256::from(1111111)),
            rowid: 10,
        });
        let wallet_1 = make_wallet("hohoho");
        let failure_status = PendingTransactionStatus::Failure(make_tx_triple_id());
        let attempt = 4;
        let first_payment = Payment {
            to: wallet_1,
            amount: 456,
            timestamp: from_time_t(150_000_000),
            previous_timestamp: from_time_t(140_000_000),
            transaction: H256::from_uint(&U256::from(123)),
            rowid: 2,
        };
        let first_pending_tx_status = PendingTransactionStatus::StillPending {
            payment: PaymentWithMetadata {
                payment: first_payment.clone(),
                receipt_failure_count: 0,
            },
            attempt,
        };
        let second_payment = make_payment();
        let second_pending_tx_status = PendingTransactionStatus::StillPending {
            payment: PaymentWithMetadata {
                payment: second_payment.clone(),
                receipt_failure_count: 0,
            },
            attempt,
        };
        let statuses = vec![
            first_pending_tx_status,
            confirmed_status.clone(),
            second_pending_tx_status,
            failure_status.clone(),
        ];

        let result = PendingTransactionStatus::merge_still_pending_and_separate_from_others(
            statuses, attempt,
        );

        let (to_cancel, to_repeat) = result;
        assert_eq!(to_cancel, vec![confirmed_status, failure_status]);
        assert_eq!(
            to_repeat,
            RequestTransactionReceipts {
                pending_payments: vec![
                    PaymentWithMetadata {
                        payment: first_payment,
                        receipt_failure_count: 0
                    },
                    PaymentWithMetadata {
                        payment: second_payment,
                        receipt_failure_count: 0
                    }
                ],
                attempt: 5
            }
        )
    }

    #[test]
    #[should_panic(
        expected = "incompatible attempts of tx confirmations, something is broken; should be 2 but was 5"
    )]
    fn merging_pending_tx_info_panics_at_pending_records_with_incompatible_attempt_numbers() {
        let first_tx_hash = H256::from_uint(&U256::from(123));
        let believed_attempt = 2;
        let attempt_1 = 2;
        let mut payment_1 = make_payment();
        payment_1.transaction = first_tx_hash;
        let first_pending_tx_status = PendingTransactionStatus::StillPending {
            payment: PaymentWithMetadata {
                payment: payment_1,
                receipt_failure_count: 0,
            },
            attempt: attempt_1,
        };
        let second_tx_hash = H256::from_uint(&U256::from(578));
        let mut payment_2 = make_payment();
        payment_2.transaction = second_tx_hash;
        let attempt_2 = 5;
        let second_pending_tx_status = PendingTransactionStatus::StillPending {
            payment: PaymentWithMetadata {
                payment: payment_2,
                receipt_failure_count: 0,
            },
            attempt: attempt_2,
        };
        let statuses = vec![first_pending_tx_status, second_pending_tx_status];

        let _ = PendingTransactionStatus::merge_still_pending_and_separate_from_others(
            statuses,
            believed_attempt,
        );
    }

    #[test]
    fn is_non_pending_is_properly_set() {
        assert_eq!(
            PendingTransactionStatus::Failure(make_tx_triple_id()).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::Confirmed(make_payment()).is_non_pending(),
            true
        );
        assert_eq!(
            PendingTransactionStatus::StillPending {
                payment: PaymentWithMetadata {
                    payment: make_payment(),
                    receipt_failure_count: 0
                },
                attempt: 4
            }
            .is_non_pending(),
            false
        );
    }

    #[test]
    fn accountant_handles_payment_backup_real_test() {
        init_test_logging();
        let home_dir = ensure_node_home_directory_exists(
            "accountant/mod",
            "accountant_handles_payment_backup_real_test",
        );
        let conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let mut stm = conn.prepare("select * from pending_payments").unwrap();
        let res = stm.query_row(NO_PARAMS, |_row| Ok(()));
        let err = res.unwrap_err();
        assert_eq!(err, Error::QueryReturnedNoRows);
        //unfortunately, I have to go through the DB initiation again because of rigid instruments
        let pending_payment_dao_factory =
            DaoFactoryReal::new(&home_dir, false, MigratorConfig::test_default());
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payment_dao_factory))
            .build();
        let accountant_addr = subject.start();
        let accountant_subs = Accountant::make_subs_from(&accountant_addr);
        let timestamp_secs = 150_000_000;
        let backup_message = PendingPaymentBackup {
            rowid: 5,
            payment_timestamp: from_time_t(timestamp_secs),
            amount: 556677,
        };

        let _ = accountant_subs
            .transaction_backup
            .try_send(backup_message.clone())
            .unwrap();

        let system = System::new("real payment backup test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let result: Vec<(u16, i64, i64)> = stm
            .query_map(NO_PARAMS, |row| {
                let payables_rowid = row.get(0).unwrap();
                let amount = row.get(1).unwrap();
                let timestamp = row.get(2).unwrap();
                let non: rusqlite::Result<Option<String>> = row.get(3); //an empty column
                assert_eq!(non.unwrap(), None);
                Ok((payables_rowid, amount, timestamp))
            })
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(
            result,
            vec![(
                backup_message.rowid,
                backup_message.amount as i64,
                timestamp_secs
            )]
        );
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Processed a backup for payment created with referential rowid 5 and balance change 556677");
    }

    #[test]
    fn inserting_payment_backup_failed_nevertheless_payment_still_could_succeed() {
        init_test_logging();
        let insert_backup_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payment_dao_factory = PendingPaymentsDaoFactoryMock::new(
            PendingPaymentsDaoMock::default()
                .insert_backup_record_params(&insert_backup_params_arc)
                .insert_backup_record_result(Err(PendingPaymentDaoError::InsertionFailed(
                    "Crashed".to_string(),
                ))),
        );
        let subject = AccountantBuilder::default()
            .pending_payments_dao_factory(Box::new(pending_payment_dao_factory))
            .build();
        let timestamp_secs = 150_000_000;
        let backup_message = PendingPaymentBackup {
            rowid: 5,
            payment_timestamp: from_time_t(timestamp_secs),
            amount: 556677,
        };

        let _ = subject.handle_payment_backup_insertion(backup_message);

        let insert_backup_params = insert_backup_params_arc.lock().unwrap();
        assert_eq!(*insert_backup_params, vec![backup_message]);
        TestLogHandler::new().exists_log_containing("WARN: Accountant: Failure on a backup for pending payment \
         with referential rowid 5 and balance change 556677, the underlying error: 'InsertionFailed(\"Crashed\")'; this could \
         result in potential data loss if the payment did not finish correctly");
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_zero() {
        let result = jackass_unsigned_to_signed(0u64);

        assert_eq!(result, Ok(0i64));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_allowable() {
        let result = jackass_unsigned_to_signed(i64::MAX as u64);

        assert_eq!(result, Ok(i64::MAX));
    }

    #[test]
    fn jackass_unsigned_to_signed_handles_max_plus_one() {
        let attempt = (i64::MAX as u64) + 1;
        let result = jackass_unsigned_to_signed((i64::MAX as u64) + 1);

        assert_eq!(result, Err(attempt));
    }

    fn make_payment() -> Payment {
        Payment {
            to: make_wallet("booga"),
            amount: 1000,
            timestamp: SystemTime::now(),
            previous_timestamp: earlier_in_seconds(1000),
            transaction: H256::from_uint(&U256::from(456)),
            rowid: 1,
        }
    }

    fn make_tx_triple_id() -> TxTripleId {
        TxTripleId {
            recipient_wallet: make_wallet("booga"),
            hash: H256::from_uint(&U256::from(789)),
            rowid: 1,
        }
    }
}
