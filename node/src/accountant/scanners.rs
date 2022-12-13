// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{Payable, PayableDao};
use crate::accountant::pending_payable_dao::PendingPayableDao;
use crate::accountant::receivable_dao::ReceivableDao;
use crate::accountant::scanners_tools::common_tools::update_timestamp_and_log;
use crate::accountant::scanners_tools::payable_scanner_tools::{
    investigate_debt_extremes, qualified_payables_and_summary, separate_early_errors,
};
use crate::accountant::scanners_tools::pending_payable_scanner_tools::{
    elapsed_in_ms, handle_none_status, handle_status_with_failure, handle_status_with_success,
};
use crate::accountant::scanners_tools::receivable_scanner_tools::balance_and_age;
use crate::accountant::{
    Accountant, ReceivedPayments, ReportTransactionReceipts, RequestTransactionReceipts,
    ResponseSkeleton, ScanForPayables, ScanForPendingPayables, ScanForReceivables, SentPayable,
};
use crate::accountant::{PendingPayableId, PendingTransactionStatus, ReportAccountsPayable};
use crate::banned_dao::BannedDao;
use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
use crate::blockchain::blockchain_interface::BlockchainError;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
use crate::sub_lib::utils::NotifyLaterHandle;
use crate::sub_lib::wallet::Wallet;
use actix::{Message, System};
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
#[cfg(test)]
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use time::format_description::parse;
use time::OffsetDateTime;
use web3::types::TransactionReceipt;

pub struct Scanners {
    pub payable: Box<dyn Scanner<ReportAccountsPayable, SentPayable>>,
    pub pending_payable: Box<dyn Scanner<RequestTransactionReceipts, ReportTransactionReceipts>>,
    pub receivable: Box<dyn Scanner<RetrieveTransactions, ReceivedPayments>>,
}

impl Scanners {
    pub fn new(
        dao_factories: DaoFactories,
        payment_thresholds: Rc<PaymentThresholds>,
        earning_wallet: Rc<Wallet>,
        when_pending_too_long_sec: u64,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Scanners {
            payable: Box::new(PayableScanner::new(
                dao_factories.payable_dao_factory.make(),
                dao_factories.pending_payable_dao_factory.make(),
                Rc::clone(&payment_thresholds),
            )),
            pending_payable: Box::new(PendingPayableScanner::new(
                dao_factories.payable_dao_factory.make(),
                dao_factories.pending_payable_dao_factory.make(),
                Rc::clone(&payment_thresholds),
                when_pending_too_long_sec,
                Rc::clone(&financial_statistics),
            )),
            receivable: Box::new(ReceivableScanner::new(
                dao_factories.receivable_dao_factory.make(),
                dao_factories.banned_dao_factory.make(),
                Rc::clone(&payment_thresholds),
                earning_wallet,
                financial_statistics,
            )),
        }
    }
}

pub trait Scanner<BeginMessage, EndMessage>
where
    BeginMessage: Message,
    EndMessage: Message,
{
    fn begin_scan(
        &mut self,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<BeginMessage, BeginScanError>;
    fn finish_scan(&mut self, message: EndMessage, logger: &Logger) -> Option<NodeToUiMessage>;
    fn scan_started_at(&self) -> Option<SystemTime>;
    fn mark_as_started(&mut self, timestamp: SystemTime);
    fn mark_as_ended(&mut self, logger: &Logger);
    as_any_dcl!();
}

#[derive(Debug, PartialEq, Eq)]
pub enum BeginScanError {
    NothingToProcess,
    ScanAlreadyRunning(SystemTime),
    CalledFromNullScanner, // Exclusive for tests
}

impl BeginScanError {
    pub fn handle_error(
        &self,
        logger: &Logger,
        scan_type: ScanType,
        is_externally_triggered: bool,
    ) {
        match self {
            BeginScanError::NothingToProcess => {
                debug!(
                    logger,
                    "There was nothing to process during {:?} scan.", scan_type
                );
            }
            BeginScanError::ScanAlreadyRunning(timestamp) => {
                let log_message = format!(
                    "{:?} scan was already initiated at {}. \
                     Hence, this scan request will be ignored.",
                    scan_type,
                    BeginScanError::timestamp_as_string(&timestamp)
                );

                match is_externally_triggered {
                    true => info!(logger, "{}", log_message),
                    false => debug!(logger, "{}", log_message),
                }
            }
            BeginScanError::CalledFromNullScanner => {
                if !cfg!(test) {
                    panic!("Null Scanner shouldn't be running inside production code.")
                }
            }
        }
    }

    pub fn timestamp_as_string(timestamp: &SystemTime) -> String {
        const TIME_FORMATTING_STRING: &str =
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]";

        let offset_date_time = OffsetDateTime::from(*timestamp);
        offset_date_time
            .format(&parse(TIME_FORMATTING_STRING).unwrap())
            .unwrap()
    }
}

pub struct ScannerCommon {
    initiated_at_opt: Option<SystemTime>,
    pub payment_thresholds: Rc<PaymentThresholds>,
}

impl ScannerCommon {
    fn new(payment_thresholds: Rc<PaymentThresholds>) -> Self {
        Self {
            initiated_at_opt: None,
            payment_thresholds,
        }
    }
}

pub struct PayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub pending_payable_dao: Box<dyn PendingPayableDao>,
}

impl Scanner<ReportAccountsPayable, SentPayable> for PayableScanner {
    fn begin_scan(
        &mut self,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<ReportAccountsPayable, BeginScanError> {
        if let Some(timestamp) = self.scan_started_at() {
            return Err(BeginScanError::ScanAlreadyRunning(timestamp));
        }
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for payables");
        let all_non_pending_payables = self.payable_dao.non_pending_payables();
        debug!(
            logger,
            "{}",
            investigate_debt_extremes(timestamp, &all_non_pending_payables)
        );
        let (qualified_payables, summary) = qualified_payables_and_summary(
            timestamp,
            all_non_pending_payables,
            self.common.payment_thresholds.as_ref(),
        );
        info!(
            logger,
            "Chose {} qualified debts to pay",
            qualified_payables.len()
        );
        debug!(logger, "{}", summary);
        match qualified_payables.is_empty() {
            true => {
                self.mark_as_ended(logger);
                Err(BeginScanError::NothingToProcess)
            }
            false => Ok(ReportAccountsPayable {
                accounts: qualified_payables,
                response_skeleton_opt,
            }),
        }
    }

    fn finish_scan(&mut self, message: SentPayable, logger: &Logger) -> Option<NodeToUiMessage> {
        let (sent_payables, blockchain_errors) = separate_early_errors(&message, logger);
        debug!(
            logger,
            "We gathered these errors at sending transactions for payable: {:?}, out of the \
                total of {} attempts",
            blockchain_errors,
            sent_payables.len() + blockchain_errors.len()
        );

        self.handle_sent_payables(sent_payables, logger);
        self.handle_blockchain_errors(blockchain_errors, logger);

        self.mark_as_ended(logger);
        message
            .response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        self.common.initiated_at_opt
    }

    fn mark_as_started(&mut self, timestamp: SystemTime) {
        self.common.initiated_at_opt = Some(timestamp);
    }

    fn mark_as_ended(&mut self, logger: &Logger) {
        update_timestamp_and_log(
            &mut self.common.initiated_at_opt,
            ScanType::Payables,
            logger,
        );
    }

    as_any_impl!();
}

impl PayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        pending_payable_dao: Box<dyn PendingPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            pending_payable_dao,
        }
    }

    fn handle_sent_payables(&self, sent_payables: Vec<Payable>, logger: &Logger) {
        for payable in sent_payables {
            if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(payable.tx_hash) {
                if let Err(e) = self
                    .payable_dao
                    .as_ref()
                    .mark_pending_payable_rowid(&payable.to, rowid)
                {
                    panic!(
                        "Was unable to create a mark in payables for a new pending payable \
                            '{}' due to '{:?}'",
                        payable.tx_hash, e
                    );
                }
            } else {
                panic!(
                    "Payable fingerprint for {} doesn't exist but should by now; \
                        system unreliable",
                    payable.tx_hash
                );
            };

            debug!(
                logger,
                "Payable '{}' has been marked as pending in the payable table", payable.tx_hash
            )
        }
    }

    fn handle_blockchain_errors(&self, blockchain_errors: Vec<BlockchainError>, logger: &Logger) {
        for blockchain_error in blockchain_errors {
            if let Some(hash) = blockchain_error.carries_transaction_hash() {
                if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(hash) {
                    debug!(
                        logger,
                        "Deleting an existing fingerprint for a failed transaction {:?}", hash
                    );
                    if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                        panic!(
                            "Database unmaintainable; payable fingerprint deletion for \
                                transaction {:?} has stayed undone due to {:?}",
                            hash, e
                        );
                    };
                };

                warning!(
                    logger,
                    "Failed transaction with a hash '{:?}' but without the record - thrown out",
                    hash
                )
            } else {
                debug!(
                    logger,
                    "Forgetting a transaction attempt that even did not reach the signing stage"
                )
            };
        }
    }
}

pub struct PendingPayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub pending_payable_dao: Box<dyn PendingPayableDao>,
    pub when_pending_too_long_sec: u64,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
}

impl Scanner<RequestTransactionReceipts, ReportTransactionReceipts> for PendingPayableScanner {
    fn begin_scan(
        &mut self,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RequestTransactionReceipts, BeginScanError> {
        if let Some(timestamp) = self.scan_started_at() {
            return Err(BeginScanError::ScanAlreadyRunning(timestamp));
        }
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for pending payable");
        let filtered_pending_payable = self.pending_payable_dao.return_all_fingerprints();
        match filtered_pending_payable.is_empty() {
            true => {
                debug!(
                    logger,
                    "Pending payable scan ended. No pending payable found."
                );
                self.mark_as_ended(logger);
                Err(BeginScanError::NothingToProcess)
            }
            false => {
                debug!(
                    logger,
                    "Found {} pending payables to process",
                    filtered_pending_payable.len()
                );
                Ok(RequestTransactionReceipts {
                    pending_payable: filtered_pending_payable,
                    response_skeleton_opt,
                })
            }
        }
    }

    fn finish_scan(
        &mut self,
        message: ReportTransactionReceipts,
        logger: &Logger,
    ) -> Option<NodeToUiMessage> {
        if message.fingerprints_with_receipts.len() != 0 {
            debug!(
                logger,
                "Processing receipts for {} transactions",
                message.fingerprints_with_receipts.len()
            );
            let statuses = self.handle_pending_transaction_with_its_receipt(&message, logger);
            self.process_transaction_by_status(statuses, logger);
        } else {
            debug!(logger, "No transaction receipts found.");
        }

        self.mark_as_ended(logger);
        message
            .response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        self.common.initiated_at_opt
    }

    fn mark_as_started(&mut self, timestamp: SystemTime) {
        self.common.initiated_at_opt = Some(timestamp);
    }

    fn mark_as_ended(&mut self, logger: &Logger) {
        update_timestamp_and_log(
            &mut self.common.initiated_at_opt,
            ScanType::PendingPayables,
            logger,
        );
    }

    as_any_impl!();
}

impl PendingPayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        pending_payable_dao: Box<dyn PendingPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        when_pending_too_long_sec: u64,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            pending_payable_dao,
            when_pending_too_long_sec,
            financial_statistics,
        }
    }

    fn handle_pending_transaction_with_its_receipt(
        &self,
        msg: &ReportTransactionReceipts,
        logger: &Logger,
    ) -> Vec<PendingTransactionStatus> {
        msg.fingerprints_with_receipts
            .iter()
            .map(|(receipt_opt, fingerprint)| match receipt_opt {
                Some(receipt) => self.interpret_transaction_receipt(receipt, fingerprint, logger),
                None => {
                    debug!(
                        logger,
                        "Interpreting a receipt for transaction '{}' but none was given; \
                            attempt {}, {}ms since sending",
                        fingerprint.hash,
                        fingerprint.attempt_opt.expectv("initialized attempt"),
                        elapsed_in_ms(fingerprint.timestamp)
                    );
                    PendingTransactionStatus::StillPending(PendingPayableId {
                        hash: fingerprint.hash,
                        rowid: fingerprint.rowid_opt.expectv("initialized rowid"),
                    })
                }
            })
            .collect()
    }

    fn interpret_transaction_receipt(
        &self,
        receipt: &TransactionReceipt,
        fingerprint: &PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingTransactionStatus {
        match receipt.status {
                None => handle_none_status(fingerprint, self.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64() {
                        0 => handle_status_with_failure(fingerprint, logger),
                        1 => handle_status_with_success(fingerprint, logger),
                        other => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}", fingerprint.hash, other)
                    }
            }
    }

    fn process_transaction_by_status(
        &mut self,
        statuses: Vec<PendingTransactionStatus>,
        logger: &Logger,
    ) {
        for status in statuses {
            match status {
                PendingTransactionStatus::StillPending(transaction_id) => {
                    self.update_payable_fingerprint(transaction_id, logger);
                }
                PendingTransactionStatus::Failure(transaction_id) => {
                    self.order_cancel_failed_transaction(transaction_id, logger);
                }
                PendingTransactionStatus::Confirmed(fingerprint) => {
                    self.order_confirm_transaction(fingerprint, logger);
                }
            }
        }
    }

    fn update_payable_fingerprint(&self, pending_payable_id: PendingPayableId, logger: &Logger) {
        if let Err(e) = self
            .pending_payable_dao
            .update_fingerprint(pending_payable_id.rowid)
        {
            panic!(
                "Failure on updating payable fingerprint '{:?}' due to {:?}",
                pending_payable_id.hash, e
            );
        } else {
            trace!(
                logger,
                "Updated record for rowid: {} ",
                pending_payable_id.rowid
            );
        }
    }

    fn order_cancel_failed_transaction(&self, transaction_id: PendingPayableId, logger: &Logger) {
        if let Err(e) = self.pending_payable_dao.mark_failure(transaction_id.rowid) {
            panic!(
                "Unsuccessful attempt for transaction {} to mark fatal error at payable \
                    fingerprint due to {:?}; database unreliable",
                transaction_id.hash, e
            )
        } else {
            warning!(
                        logger,
                        "Broken transaction {:?} left with an error mark; you should take over the care \
                        of this transaction to make sure your debts will be paid because there is no \
                        automated process that can fix this without you", transaction_id.hash
                    );
        }
    }

    fn order_confirm_transaction(
        &mut self,
        pending_payable_fingerprint: PendingPayableFingerprint,
        logger: &Logger,
    ) {
        let hash = pending_payable_fingerprint.hash;
        let amount = pending_payable_fingerprint.amount;
        let rowid = pending_payable_fingerprint
            .rowid_opt
            .expectv("initialized rowid");

        if let Err(e) = self
            .payable_dao
            .transaction_confirmed(&pending_payable_fingerprint)
        {
            panic!(
                "Was unable to uncheck pending payable '{}' after confirmation due to '{:?}'",
                hash, e
            );
        } else {
            self.financial_statistics.borrow_mut().total_paid_payable += amount;
            debug!(
                logger,
                "Confirmation of transaction {}; record for payable was modified", hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                panic!(
                    "Was unable to delete payable fingerprint '{}' after successful transaction \
                        due to '{:?}'",
                    hash, e
                );
            } else {
                info!(
                    logger,
                    "Transaction {:?} has gone through the whole confirmation process succeeding",
                    hash
                );
            }
        }
    }
}

pub struct ReceivableScanner {
    pub common: ScannerCommon,
    pub receivable_dao: Box<dyn ReceivableDao>,
    pub banned_dao: Box<dyn BannedDao>,
    pub earning_wallet: Rc<Wallet>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
}

impl Scanner<RetrieveTransactions, ReceivedPayments> for ReceivableScanner {
    fn begin_scan(
        &mut self,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RetrieveTransactions, BeginScanError> {
        if let Some(timestamp) = self.scan_started_at() {
            return Err(BeginScanError::ScanAlreadyRunning(timestamp));
        }
        self.mark_as_started(timestamp);
        info!(
            logger,
            "Scanning for receivables to {}", self.earning_wallet
        );
        self.scan_for_delinquencies(timestamp, logger);

        Ok(RetrieveTransactions {
            recipient: self.earning_wallet.as_ref().clone(),
            response_skeleton_opt,
        })
    }

    fn finish_scan(
        &mut self,
        message: ReceivedPayments,
        logger: &Logger,
    ) -> Option<NodeToUiMessage> {
        if message.payments.is_empty() {
            info!(
                logger,
                "No new received payments were detected during the scanning process."
            )
        } else {
            let total_newly_paid_receivable = message
                .payments
                .iter()
                .fold(0, |so_far, now| so_far + now.gwei_amount);
            self.receivable_dao
                .as_mut()
                .more_money_received(message.timestamp, message.payments);
            self.financial_statistics.borrow_mut().total_paid_receivable +=
                total_newly_paid_receivable;
        }

        self.mark_as_ended(logger);
        message
            .response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        self.common.initiated_at_opt
    }

    fn mark_as_started(&mut self, timestamp: SystemTime) {
        self.common.initiated_at_opt = Some(timestamp);
    }

    fn mark_as_ended(&mut self, logger: &Logger) {
        update_timestamp_and_log(
            &mut self.common.initiated_at_opt,
            ScanType::Receivables,
            logger,
        );
    }

    as_any_impl!();
}

impl ReceivableScanner {
    pub fn new(
        receivable_dao: Box<dyn ReceivableDao>,
        banned_dao: Box<dyn BannedDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        earning_wallet: Rc<Wallet>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            earning_wallet,
            receivable_dao,
            banned_dao,
            financial_statistics,
        }
    }

    pub fn scan_for_delinquencies(&self, timestamp: SystemTime, logger: &Logger) {
        info!(logger, "Scanning for delinquencies");
        self.ban_nodes(timestamp, logger);
        self.unban_nodes(timestamp, logger);
    }

    pub fn ban_nodes(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .new_delinquencies(timestamp, self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet);
                let (balance, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) banned for delinquency",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });
    }

    pub fn unban_nodes(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .paid_delinquencies(self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet);
                let (balance, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} MASQ, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet,
                    balance,
                    age.as_secs()
                )
            });
    }
}

pub struct NullScanner {}

impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for NullScanner
where
    BeginMessage: Message,
    EndMessage: Message,
{
    fn begin_scan(
        &mut self,
        _timestamp: SystemTime,
        _response_skeleton_opt: Option<ResponseSkeleton>,
        _logger: &Logger,
    ) -> Result<BeginMessage, BeginScanError> {
        Err(BeginScanError::CalledFromNullScanner)
    }

    fn finish_scan(&mut self, _message: EndMessage, _logger: &Logger) -> Option<NodeToUiMessage> {
        panic!("Called from NullScanner");
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        panic!("Called from NullScanner");
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        panic!("Called from NullScanner");
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        panic!("Called from NullScanner");
    }

    as_any_impl!();
}

impl Default for NullScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl NullScanner {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct ScannerMock<BeginMessage, EndMessage> {
    begin_scan_params: Arc<Mutex<Vec<()>>>,
    begin_scan_results: RefCell<Vec<Result<BeginMessage, BeginScanError>>>,
    end_scan_params: Arc<Mutex<Vec<EndMessage>>>,
    end_scan_results: RefCell<Vec<Option<NodeToUiMessage>>>,
    stop_system_after_last_message: RefCell<bool>,
}

impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage>
    for ScannerMock<BeginMessage, EndMessage>
where
    BeginMessage: Message,
    EndMessage: Message,
{
    fn begin_scan(
        &mut self,
        _timestamp: SystemTime,
        _response_skeleton_opt: Option<ResponseSkeleton>,
        _logger: &Logger,
    ) -> Result<BeginMessage, BeginScanError> {
        self.begin_scan_params.lock().unwrap().push(());
        if self.is_allowed_to_stop_the_system() && self.is_last_message() {
            System::current().stop();
        }
        self.begin_scan_results.borrow_mut().remove(0)
    }

    fn finish_scan(&mut self, message: EndMessage, _logger: &Logger) -> Option<NodeToUiMessage> {
        self.end_scan_params.lock().unwrap().push(message);
        if self.is_allowed_to_stop_the_system() && self.is_last_message() {
            System::current().stop();
        }
        self.end_scan_results.borrow_mut().remove(0)
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        unimplemented!()
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        unimplemented!()
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        unimplemented!()
    }
}

impl<BeginMessage, EndMessage> Default for ScannerMock<BeginMessage, EndMessage> {
    fn default() -> Self {
        Self::new()
    }
}

impl<BeginMessage, EndMessage> ScannerMock<BeginMessage, EndMessage> {
    pub fn new() -> Self {
        Self {
            begin_scan_params: Arc::new(Mutex::new(vec![])),
            begin_scan_results: RefCell::new(vec![]),
            end_scan_params: Arc::new(Mutex::new(vec![])),
            end_scan_results: RefCell::new(vec![]),
            stop_system_after_last_message: RefCell::new(false),
        }
    }

    pub fn begin_scan_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.begin_scan_params = params.clone();
        self
    }

    pub fn begin_scan_result(self, result: Result<BeginMessage, BeginScanError>) -> Self {
        self.begin_scan_results.borrow_mut().push(result);
        self
    }

    pub fn stop_the_system(self) -> Self {
        self.stop_system_after_last_message.replace(true);
        self
    }

    pub fn is_allowed_to_stop_the_system(&self) -> bool {
        *self.stop_system_after_last_message.borrow()
    }

    pub fn is_last_message(&self) -> bool {
        self.is_last_message_from_begin_scan() || self.is_last_message_from_end_scan()
    }

    pub fn is_last_message_from_begin_scan(&self) -> bool {
        self.begin_scan_results.borrow().len() == 1 && self.end_scan_results.borrow().is_empty()
    }

    pub fn is_last_message_from_end_scan(&self) -> bool {
        self.end_scan_results.borrow().len() == 1 && self.begin_scan_results.borrow().is_empty()
    }
}

#[derive(Default)]
pub struct NotifyLaterForScanners {
    pub scan_for_pending_payable: Box<dyn NotifyLaterHandle<ScanForPendingPayables, Accountant>>,
    pub scan_for_payable: Box<dyn NotifyLaterHandle<ScanForPayables, Accountant>>,
    pub scan_for_receivable: Box<dyn NotifyLaterHandle<ScanForReceivables, Accountant>>,
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::{
        BeginScanError, PayableScanner, PendingPayableScanner, ReceivableScanner, Scanner, Scanners,
    };
    use crate::accountant::test_utils::{
        make_custom_payment_thresholds, make_payables, make_pending_payable_fingerprint,
        make_receivable_account, BannedDaoFactoryMock, BannedDaoMock, PayableDaoFactoryMock,
        PayableDaoMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock,
        ReceivableDaoFactoryMock, ReceivableDaoMock,
    };
    use crate::accountant::{
        PendingPayableId, PendingTransactionStatus, ReceivedPayments, ReportTransactionReceipts,
        RequestTransactionReceipts, SentPayable, DEFAULT_PENDING_TOO_LONG_SEC,
    };
    use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
    use std::cell::RefCell;
    use std::ops::Sub;

    use crate::accountant::payable_dao::{Payable, PayableDaoError};
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainTransaction};
    use crate::database::dao_utils::from_time_t;
    use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::make_wallet;
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H256, U256};

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payment_thresholds = Rc::new(PaymentThresholds::default());
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_result(PayableDaoMock::new())
            .make_result(PayableDaoMock::new());
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new()
            .make_result(PendingPayableDaoMock::new())
            .make_result(PendingPayableDaoMock::new());
        let receivable_dao_factory =
            ReceivableDaoFactoryMock::new().make_result(ReceivableDaoMock::new());
        let banned_dao_factory = BannedDaoFactoryMock::new().make_result(BannedDaoMock::new());
        let scanners = Scanners::new(
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
            },
            Rc::clone(&payment_thresholds),
            Rc::new(make_wallet("earning")),
            0,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        );

        scanners
            .payable
            .as_any()
            .downcast_ref::<PayableScanner>()
            .unwrap();
        scanners
            .pending_payable
            .as_any()
            .downcast_ref::<PendingPayableScanner>()
            .unwrap();
        scanners
            .receivable
            .as_any()
            .downcast_ref::<ReceivableScanner>()
            .unwrap();
    }

    #[test]
    fn payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let (qualified_payable_accounts, _, all_non_pending_payables) =
            make_payables(now, &PaymentThresholds::default());
        let len_of_qualified_payables = qualified_payable_accounts.len();
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);

        let mut subject = PayableScanner::default().payable_dao(payable_dao);

        let result = subject.begin_scan(now, None, &Logger::new(test_name));

        let timestamp = subject.scan_started_at();
        assert_eq!(timestamp, Some(now));
        assert_eq!(
            result,
            Ok(ReportAccountsPayable {
                accounts: qualified_payable_accounts.clone(),
                response_skeleton_opt: None,
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for payables"),
            &format!("INFO: {test_name}: Chose {len_of_qualified_payables} qualified debts to pay"),
        ])
    }

    #[test]
    fn payable_scanner_throws_error_when_a_scan_is_already_running() {
        let now = SystemTime::now();
        let (_, _, all_non_pending_payables) = make_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = PayableScanner::default().payable_dao(payable_dao);
        let _result = subject.begin_scan(now, None, &Logger::new("test"));

        let run_again_result = subject.begin_scan(SystemTime::now(), None, &Logger::new("test"));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            run_again_result,
            Err(BeginScanError::ScanAlreadyRunning(now))
        );
    }

    #[test]
    fn payable_scanner_throws_error_in_case_no_qualified_payable_is_found() {
        init_test_logging();
        let test_name = "payable_scanner_throws_error_in_case_no_qualified_payable_is_found";
        let now = SystemTime::now();
        let (_, unqualified_payable_accounts, _) =
            make_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);

        let mut subject = PayableScanner::default().payable_dao(payable_dao);

        let result = subject.begin_scan(now, None, &Logger::new(test_name));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(result, Err(BeginScanError::NothingToProcess));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for payables"),
            "Chose 0 qualified debts to pay",
        ]);
    }

    #[test]
    #[should_panic(
        expected = "Payable fingerprint for 0x0000…0315 doesn't exist but should by now; system unreliable"
    )]
    fn payable_scanner_throws_error_when_fingerprint_is_not_found() {
        let now = SystemTime::now();
        let payment_hash = H256::from_uint(&U256::from(789));
        let payable = Payable::new(make_wallet("booga"), 6789, payment_hash, now);
        let payable_dao = PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().fingerprint_rowid_result(None);
        let mut subject = PayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        let sent_payable = SentPayable {
            timestamp: now,
            payable: vec![Ok(payable)],
            response_skeleton_opt: None,
        };

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Database unmaintainable; payable fingerprint deletion for transaction \
                0x000000000000000000000000000000000000000000000000000000000000007b has stayed \
                undone due to RecordDeletion(\"we slept over, sorry\")"
    )]
    fn payable_scanner_panics_when_failed_payment_fails_to_delete_the_existing_pending_payable_fingerprint(
    ) {
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
        let mut subject = PayableScanner::default().pending_payable_dao(pending_payable_dao);

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Was unable to create a mark in payables for a new pending payable '0x0000…007b' \
                due to 'SignConversion(9999999999999)'"
    )]
    fn payable_scanner_panics_when_it_fails_to_make_a_mark_in_payables() {
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
        let mut subject = PayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![Ok(payable)],
            response_skeleton_opt: None,
        };

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    #[test]
    fn payable_scanner_handles_sent_payable_message() {
        //the two failures differ in the logged messages
        init_test_logging();
        let test_name = "payable_scanner_handles_sent_payable_message";
        let fingerprint_rowid_params_arc = Arc::new(Mutex::new(vec![]));
        let now = SystemTime::now();
        let payable_1 = Err(BlockchainError::InvalidResponse);
        let payable_2_rowid = 126;
        let payable_2_hash = H256::from_uint(&U256::from(166));
        let payable_2 = Payable::new(make_wallet("booga"), 6789, payable_2_hash, now);
        let payable_3 = Err(BlockchainError::TransactionFailed {
            msg: "closing hours, sorry".to_string(),
            hash_opt: None,
        });
        let sent_payable = SentPayable {
            timestamp: SystemTime::now(),
            payable: vec![payable_1, Ok(payable_2.clone()), payable_3],
            response_skeleton_opt: None,
        };
        let payable_dao = PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(payable_2_rowid));
        let mut subject = PayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(sent_payable, &Logger::new(test_name));

        let is_scan_running = subject.scan_started_at().is_some();
        let fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(is_scan_running, false);
        //we know the other two errors are associated with an initiated transaction having a backup
        assert_eq!(*fingerprint_rowid_params, vec![payable_2_hash]);
        let log_handler = TestLogHandler::new();
        log_handler.assert_logs_contain_in_order(vec![
            &format!(
                "WARN: {test_name}: Outbound transaction failure due to 'InvalidResponse'. \
                Please check your blockchain service URL configuration."
            ),
            &format!(
                "WARN: {test_name}: Encountered transaction error at this end: 'TransactionFailed \
                {{ msg: \"closing hours, sorry\", hash_opt: None }}'"
            ),
            &format!(
                "DEBUG: {test_name}: Payable '0x0000…00a6' has been marked as pending in the payable table"
            ),
            &format!(
                "DEBUG: {test_name}: Forgetting a transaction attempt that even did not reach the signing stage"
            ),
        ]);
        log_handler.exists_log_matching(
            "INFO: payable_scanner_handles_sent_payable_message: The Payables scan ended in \\d+ms.",
        );
    }

    #[test]
    fn pending_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "pending_payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let fingerprints = vec![PendingPayableFingerprint {
            rowid_opt: Some(1234),
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt_opt: Some(1),
            amount: 1_000_000,
            process_error: None,
        }];
        let no_of_pending_payables = fingerprints.len();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(fingerprints.clone());
        let mut pending_payable_scanner =
            PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let is_scan_running = pending_payable_scanner.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                pending_payable: fingerprints,
                response_skeleton_opt: None
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for pending payable"),
            &format!(
                "DEBUG: {test_name}: Found {no_of_pending_payables} pending payables to process"
            ),
        ])
    }

    #[test]
    fn pending_payable_scanner_throws_error_in_case_scan_is_already_running() {
        let now = SystemTime::now();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(vec![
                PendingPayableFingerprint {
                    rowid_opt: Some(1234),
                    timestamp: SystemTime::now(),
                    hash: Default::default(),
                    attempt_opt: Some(1),
                    amount: 1_000_000,
                    process_error: None,
                },
            ]);
        let mut subject = PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);
        let _ = subject.begin_scan(now, None, &Logger::new("test"));

        let result = subject.begin_scan(SystemTime::now(), None, &Logger::new("test"));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(result, Err(BeginScanError::ScanAlreadyRunning(now)));
    }

    #[test]
    fn pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found() {
        init_test_logging();
        let test_name = "pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found";
        let now = SystemTime::now();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(vec![]);
        let mut pending_payable_scanner =
            PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let is_scan_running = pending_payable_scanner.scan_started_at().is_some();
        assert_eq!(result, Err(BeginScanError::NothingToProcess));
        assert_eq!(is_scan_running, false);
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for pending payable"),
            &format!("DEBUG: {test_name}: Pending payable scan ended. No pending payable found."),
        ])
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval";
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent =
            SystemTime::now().sub(Duration::from_secs(DEFAULT_PENDING_TOO_LONG_SEC + 5)); //old transaction
        let subject = PendingPayableScanner::default();
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
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Pending transaction '0x0000…0237' has exceeded the maximum \
            pending time (21600sec) and the confirmation process is going to be aborted now \
            at the final attempt 10; manual resolution is required from the user to complete \
            the transaction"
        ));
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval";
        let subject = PendingPayableScanner::default();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent = SystemTime::now().sub(Duration::from_millis(100));
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
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Pending \
         transaction '0x0000…0237' couldn't be confirmed at attempt 1 at ",
        ));
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
        let subject = PendingPayableScanner::default();

        let _ =
            subject.interpret_transaction_receipt(&tx_receipt, &fingerprint, &Logger::new("test"));
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_a_failure";
        let subject = PendingPayableScanner::default();
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
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId {
                hash,
                rowid: 777777,
            })
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "ERROR: {test_name}: Pending transaction '0x0000…11d7' announced as a failure, \
            interpreting attempt 5 after 1500\\d\\dms from the sending"
        ));
    }

    #[test]
    fn handle_pending_tx_handles_none_returned_for_transaction_receipt() {
        init_test_logging();
        let test_name = "handle_pending_tx_handles_none_returned_for_transaction_receipt";
        let subject = PendingPayableScanner::default();
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

        let result =
            subject.handle_pending_transaction_with_its_receipt(&msg, &Logger::new(test_name));

        assert_eq!(
            result,
            vec![PendingTransactionStatus::StillPending(PendingPayableId {
                hash,
                rowid,
            })]
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "DEBUG: {test_name}: Interpreting a receipt for transaction '0x0000…0913' \
            but none was given; attempt 3, 100\\d\\dms since sending"
        ));
    }

    #[test]
    fn update_payable_fingerprint_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .update_fingerprint_params(&update_after_cycle_params_arc)
            .update_fingerprint_results(Ok(()));
        let subject = PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);
        let transaction_id = PendingPayableId { hash, rowid };

        subject.update_payable_fingerprint(transaction_id, &Logger::new("test"));

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![rowid])
    }

    #[test]
    #[should_panic(expected = "Failure on updating payable fingerprint \
                '0x000000000000000000000000000000000000000000000000000000000006c9d8' \
                due to UpdateFailed(\"yeah, bad\")")]
    fn update_payable_fingerprint_sad_path() {
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default().update_fingerprint_results(Err(
            PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
        ));
        let subject = PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);
        let transaction_id = PendingPayableId { hash, rowid };

        subject.update_payable_fingerprint(transaction_id, &Logger::new("test"));
    }

    #[test]
    fn order_cancel_pending_transaction_works() {
        init_test_logging();
        let test_name = "order_cancel_pending_transaction_works";
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failure_params(&mark_failure_params_arc)
            .mark_failure_result(Ok(()));
        let subject = PendingPayableScanner::default().pending_payable_dao(pending_payable_dao);
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let rowid = 2;
        let transaction_id = PendingPayableId {
            hash: tx_hash,
            rowid,
        };

        subject.order_cancel_failed_transaction(transaction_id, &Logger::new(test_name));

        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(*mark_failure_params, vec![rowid]);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Broken transaction \
            0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 left with an error \
            mark; you should take over the care of this transaction to make sure your debts will \
            be paid because there is no automated process that can fix this without you",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transaction 0x051a…8c19 to mark fatal error at payable \
                fingerprint due to UpdateFailed(\"no no no\"); database unreliable"
    )]
    fn order_cancel_pending_transaction_panics_when_it_fails_to_mark_failure() {
        let payable_dao = PayableDaoMock::default().transaction_canceled_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failure_result(Err(
            PendingPayableDaoError::UpdateFailed("no no no".to_string()),
        ));
        let subject = PendingPayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());
        let transaction_id = PendingPayableId { hash, rowid };

        subject.order_cancel_failed_transaction(transaction_id, &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Was unable to delete payable fingerprint '0x0000…0315' after successful \
                transaction due to 'RecordDeletion(\"the database is fooling around with us\")'"
    )]
    fn handle_confirm_pending_transaction_panics_while_deleting_pending_payable_fingerprint() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().delete_fingerprint_result(Err(
            PendingPayableDaoError::RecordDeletion(
                "the database is fooling around with us".to_string(),
            ),
        ));
        let mut subject = PendingPayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.hash = hash;

        subject.order_confirm_transaction(pending_payable_fingerprint, &Logger::new("test"));
    }

    #[test]
    fn order_confirm_transaction_works() {
        init_test_logging();
        let test_name = "order_confirm_transaction_works";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .delete_fingerprint_params(&delete_pending_payable_fingerprint_params_arc)
            .delete_fingerprint_result(Ok(()));
        let mut subject = PendingPayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
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

        subject.order_confirm_transaction(
            pending_payable_fingerprint.clone(),
            &Logger::new(test_name),
        );

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        let delete_pending_payable_fingerprint_params =
            delete_pending_payable_fingerprint_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *transaction_confirmed_params,
            vec![pending_payable_fingerprint]
        );
        assert_eq!(*delete_pending_payable_fingerprint_params, vec![rowid]);
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &format!(
                "DEBUG: {test_name}: Confirmation of transaction 0x051a…8c19; \
                    record for payable was modified"
            ),
            &format!(
                "INFO: {test_name}: Transaction \
                0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19 \
                has gone through the whole confirmation process succeeding"
            ),
        ]);
    }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        let test_name = "total_paid_payable_rises_with_each_bill_paid";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(5),
            timestamp: from_time_t(189_999_888),
            hash: H256::from_uint(&U256::from(56789)),
            attempt_opt: Some(1),
            amount: 5478,
            process_error: None,
        };
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprint_result(Ok(()));
        let mut subject = PendingPayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.order_confirm_transaction(fingerprint.clone(), &Logger::new(test_name));

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable;
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(total_paid_payable, 1111 + 5478);
        assert_eq!(*transaction_confirmed_params, vec![fingerprint])
    }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payable '0x0000…0315' after confirmation due to \
                'RusqliteError(\"record change not successful\")'"
    )]
    fn order_confirm_transaction_panics_on_unchecking_payable_table() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = PendingPayableScanner::default().payable_dao(payable_dao);
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.rowid_opt = Some(rowid);
        fingerprint.hash = hash;

        subject.order_confirm_transaction(fingerprint, &Logger::new("test"));
    }

    #[test]
    fn pending_payable_scanner_handles_report_transaction_receipts_message() {
        init_test_logging();
        let test_name = "pending_payable_scanner_handles_report_transaction_receipts_message";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::new()
            .delete_fingerprint_result(Ok(()))
            .delete_fingerprint_result(Ok(()));
        let mut subject = PendingPayableScanner::default()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao);
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
        let transaction_hash_2 = H256::from_uint(&U256::from(1234));
        let mut transaction_receipt_2 = TransactionReceipt::default();
        transaction_receipt_2.transaction_hash = transaction_hash_2;
        transaction_receipt_2.status = Some(U64::from(1)); //success
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(10),
            timestamp: from_time_t(199_780_000),
            hash: transaction_hash_2,
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
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(msg, &Logger::new(test_name));

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(
            *transaction_confirmed_params,
            vec![fingerprint_1, fingerprint_2]
        );
        assert_eq!(subject.scan_started_at(), None);
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!(
                "INFO: {}: Transaction {:?} has gone through the whole confirmation process succeeding",
                test_name, transaction_hash_1
            ),
            &format!(
                "INFO: {}: Transaction {:?} has gone through the whole confirmation process succeeding",
                test_name, transaction_hash_2
            ),
                "INFO: pending_payable_scanner_handles_report_transaction_receipts_message: The \
                PendingPayables scan ended in \\d+ms.",
        ]);
    }

    #[test]
    fn pending_payable_scanner_handles_report_transaction_receipts_message_with_empty_vector() {
        init_test_logging();
        let test_name =
            "pending_payable_scanner_handles_report_transaction_receipts_message_with_empty_vector";
        let mut subject = PendingPayableScanner::default();
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![],
            response_skeleton_opt: None,
        };
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(msg, &Logger::new(test_name));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(message_opt, None);
        assert_eq!(is_scan_running, false);
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching(&format!(
            "DEBUG: {test_name}: No transaction receipts found."
        ));
        tlh.exists_log_matching(&format!(
            "INFO: {test_name}: The PendingPayables scan ended in \\d+ms."
        ));
    }

    #[test]
    fn receivable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "receivable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let earning_wallet = make_wallet("earning");
        let mut receivable_scanner = ReceivableScanner::default()
            .receivable_dao(receivable_dao)
            .earning_wallet(earning_wallet.clone());

        let result = receivable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let is_scan_running = receivable_scanner.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Ok(RetrieveTransactions {
                recipient: earning_wallet.clone(),
                response_skeleton_opt: None
            })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Scanning for receivables to {earning_wallet}"
        ));
    }

    #[test]
    fn receivable_scanner_throws_error_in_case_scan_is_already_running() {
        let now = SystemTime::now();
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let earning_wallet = make_wallet("earning");
        let mut receivable_scanner = ReceivableScanner::default()
            .receivable_dao(receivable_dao)
            .earning_wallet(earning_wallet.clone());
        let _ = receivable_scanner.begin_scan(now, None, &Logger::new("test"));

        let result = receivable_scanner.begin_scan(SystemTime::now(), None, &Logger::new("test"));

        let is_scan_running = receivable_scanner.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(result, Err(BeginScanError::ScanAlreadyRunning(now)));
    }

    #[test]
    fn receivable_scanner_scans_for_delinquencies() {
        init_test_logging();
        let newly_banned_1 = make_receivable_account(1234, true);
        let newly_banned_2 = make_receivable_account(2345, true);
        let newly_unbanned_1 = make_receivable_account(3456, false);
        let newly_unbanned_2 = make_receivable_account(4567, false);
        let new_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_parameters_arc)
            .new_delinquencies_result(vec![newly_banned_1.clone(), newly_banned_2.clone()])
            .paid_delinquencies_parameters(&paid_delinquencies_parameters_arc)
            .paid_delinquencies_result(vec![newly_unbanned_1.clone(), newly_unbanned_2.clone()]);
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payment_thresholds = make_custom_payment_thresholds();
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let mut receivable_scanner = ReceivableScanner::default()
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .payment_thresholds(payment_thresholds.clone());

        let _result = receivable_scanner.begin_scan(
            SystemTime::now(),
            None,
            &Logger::new("DELINQUENCY_TEST"),
        );

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentThresholds)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(
            payment_thresholds.clone(),
            new_delinquencies_parameters[0].1
        );
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentThresholds>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(payment_thresholds, paid_delinquencies_parameters[0]);
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet));
        assert!(ban_parameters.contains(&newly_banned_2.wallet));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743132333464 \
            \\(balance: 1234 MASQ, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743233343564 \
            \\(balance: 2345 MASQ, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574333435366e \
            \\(balance: 3456 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574343536376e \
            \\(balance: 4567 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
    }

    #[test]
    fn receivable_scanner_aborts_scan_if_no_payments_were_supplied() {
        init_test_logging();
        let test_name = "receivable_scanner_aborts_scan_if_no_payments_were_supplied";
        let mut subject = ReceivableScanner::default();
        let msg = ReceivedPayments {
            timestamp: SystemTime::now(),
            payments: vec![],
            response_skeleton_opt: None,
        };

        let message_opt = subject.finish_scan(msg, &Logger::new(test_name));

        assert_eq!(message_opt, None);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: No new received payments were detected during the scanning process."
        ));
    }

    #[test]
    fn receivable_scanner_handles_received_payments_message() {
        init_test_logging();
        let test_name = "receivable_scanner_handles_received_payments_message";
        let now = SystemTime::now();
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_parameters(&more_money_received_params_arc)
            .more_money_receivable_result(Ok(()));
        let mut subject = ReceivableScanner::default().receivable_dao(receivable_dao);
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_receivable += 2222;
        subject.financial_statistics.replace(financial_statistics);
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
        let msg = ReceivedPayments {
            timestamp: now,
            payments: receivables.clone(),
            response_skeleton_opt: None,
        };
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(msg, &Logger::new(test_name));

        let total_paid_receivable = subject.financial_statistics.borrow().total_paid_receivable;
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(subject.scan_started_at(), None);
        assert_eq!(total_paid_receivable, 2222 + 45780 + 33345);
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
        TestLogHandler::new().exists_log_matching(
            "INFO: receivable_scanner_handles_received_payments_message: The Receivables scan ended in \\d+ms.",
        );
    }
}
