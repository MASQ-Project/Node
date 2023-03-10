// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{PayableAccount, PayableDao, PendingPayable};
use crate::accountant::pending_payable_dao::PendingPayableDao;
use crate::accountant::receivable_dao::ReceivableDao;
use crate::accountant::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
    LocallyCausedError, RemotelyCausedErrors,
};
use crate::accountant::scanners_utils::payable_scanner_utils::{
    debugging_summary_after_error_separation, fatal_database_mark_pending_payable_error,
    investigate_debt_extremes, log_failed_payments_having_fingerprints_and_return_ids,
    panic_for_failed_payments_lacking_fingerprints, payables_debug_summary, separate_errors,
    PayableThresholdsGauge, PayableThresholdsGaugeReal, PayableTransactingErrorEnum,
    RefWalletAndRowidOptCoupledWithHash, VecOfRowidOptAndHash,
};
use crate::accountant::scanners_utils::pending_payable_scanner_utils::{
    elapsed_in_ms, handle_none_status, handle_status_with_failure, handle_status_with_success,
    PendingPayableScanReport,
};
use crate::accountant::scanners_utils::receivable_scanner_utils::balance_and_age;
use crate::accountant::{
    gwei_to_wei, Accountant, ReceivedPayments, ReportTransactionReceipts,
    RequestTransactionReceipts, ResponseSkeleton, ScanForPayables, ScanForPendingPayables,
    ScanForReceivables, SentPayables, COMMA_SEPARATOR,
};
use crate::accountant::{PendingPayableId, ReportAccountsPayable};
use crate::banned_dao::BannedDao;
use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
use crate::sub_lib::utils::NotifyLaterHandle;
use crate::sub_lib::wallet::Wallet;
use actix::{Message, System};
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::logger::TIME_FORMATTING_STRING;
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
use web3::types::{TransactionReceipt, H256};

pub struct Scanners {
    pub payable: Box<dyn Scanner<ReportAccountsPayable, SentPayables>>,
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

    fn remove_timestamp(&mut self, scan_type: ScanType, now: SystemTime, logger: &Logger) {
        match self.initiated_at_opt.take() {
            Some(timestamp) => {
                let elapsed_time = now
                    .duration_since(timestamp)
                    .expect("Unable to calculate elapsed time for the scan.")
                    .as_millis();
                info!(
                    logger,
                    "The {:?} scan ended in {}ms.",
                    scan_type,
                    match elapsed_time {
                        0 => 1,
                        x => x,
                    }
                );
            }
            None => {
                error!(
                    logger,
                    "Called scan_finished() for {:?} scanner but timestamp was not found",
                    scan_type
                );
            }
        };
    }
}

macro_rules! time_marking_methods {
    ($scan_type_variant: ident) => {
        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        fn mark_as_started(&mut self, timestamp: SystemTime) {
            self.common.initiated_at_opt = Some(timestamp);
        }

        fn mark_as_ended(&mut self, logger: &Logger) {
            self.common
                .remove_timestamp(ScanType::$scan_type_variant, SystemTime::now(), logger);
        }
    };
}

pub struct PayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub pending_payable_dao: Box<dyn PendingPayableDao>,
    pub payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
}

impl Scanner<ReportAccountsPayable, SentPayables> for PayableScanner {
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

        let qualified_payable =
            self.sniff_out_alarming_payables_and_maybe_log_them(all_non_pending_payables, logger);

        match qualified_payable.is_empty() {
            true => {
                self.mark_as_ended(logger);
                Err(BeginScanError::NothingToProcess)
            }
            false => {
                info!(
                    logger,
                    "Chose {} qualified debts to pay",
                    qualified_payable.len()
                );
                Ok(ReportAccountsPayable {
                    accounts: qualified_payable,
                    response_skeleton_opt,
                })
            }
        }
    }

    fn finish_scan(&mut self, message: SentPayables, logger: &Logger) -> Option<NodeToUiMessage> {
        let (sent_payables, err_opt) = separate_errors(&message, logger);

        debug!(
            logger,
            "{}",
            debugging_summary_after_error_separation(&sent_payables, &err_opt)
        );

        if !sent_payables.is_empty() {
            self.mark_pending_payable(&sent_payables, logger);
        }
        self.handle_sent_payable_errors(err_opt, logger);

        self.mark_as_ended(logger);
        message
            .response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    time_marking_methods!(Payables);

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
            payable_threshold_gauge: Box::new(PayableThresholdsGaugeReal::default()),
        }
    }

    fn sniff_out_alarming_payables_and_maybe_log_them(
        &self,
        non_pending_payables: Vec<PayableAccount>,
        logger: &Logger,
    ) -> Vec<PayableAccount> {
        fn pass_payables_and_drop_points(
            qp_tp: impl Iterator<Item = (PayableAccount, u128)>,
        ) -> Vec<PayableAccount> {
            let (payables, _) = qp_tp.unzip::<_, _, Vec<PayableAccount>, Vec<_>>();
            payables
        }

        let qualified_payables_and_points_uncollected =
            non_pending_payables.into_iter().flat_map(|account| {
                self.payable_exceeded_threshold(&account, SystemTime::now())
                    .map(|threshold_point| (account, threshold_point))
            });
        match logger.debug_enabled() {
            false => pass_payables_and_drop_points(qualified_payables_and_points_uncollected),
            true => {
                let qualified_and_points_collected =
                    qualified_payables_and_points_uncollected.collect_vec();
                payables_debug_summary(&qualified_and_points_collected, logger);
                pass_payables_and_drop_points(qualified_and_points_collected.into_iter())
            }
        }
    }

    fn payable_exceeded_threshold(
        &self,
        payable: &PayableAccount,
        now: SystemTime,
    ) -> Option<u128> {
        let debt_age = now
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if self.payable_threshold_gauge.is_innocent_age(
            debt_age,
            self.common.payment_thresholds.maturity_threshold_sec,
        ) {
            return None;
        }

        if self.payable_threshold_gauge.is_innocent_balance(
            payable.balance_wei,
            gwei_to_wei(self.common.payment_thresholds.permanent_debt_allowed_gwei),
        ) {
            return None;
        }

        let threshold = self
            .payable_threshold_gauge
            .calculate_payout_threshold_in_gwei(&self.common.payment_thresholds, debt_age);
        if payable.balance_wei > threshold {
            Some(threshold)
        } else {
            None
        }
    }

    fn separate_id_triples_from_existent_and_nonexistent_fingerprints<'a>(
        &'a self,
        sent_payments: &'a [&'a PendingPayable],
    ) -> (
        Vec<RefWalletAndRowidOptCoupledWithHash>,
        Vec<RefWalletAndRowidOptCoupledWithHash>,
    ) {
        let hashes = sent_payments
            .iter()
            .map(|pending_payable| pending_payable.hash)
            .collect::<Vec<H256>>();
        self.pending_payable_dao
            .fingerprints_rowids(&hashes)
            .into_iter()
            .zip(sent_payments.iter())
            .map(|((rowid_opt, hash), pending_payable)| {
                ((&pending_payable.recipient_wallet, rowid_opt), hash)
            })
            .partition(|((_, rowid_opt), _)| rowid_opt.is_some())
    }

    fn mark_pending_payable(&self, sent_payments: &[&PendingPayable], logger: &Logger) {
        fn missing_fingerprints_msg(nonexistent: &[RefWalletAndRowidOptCoupledWithHash]) -> String {
            format!(
                "Expected pending payable fingerprints for {} were not found; system unreliable",
                join_displayable_items_by_commas(nonexistent, |((wallet, _), hash)| format!(
                    "(tx: {:?}, to wallet: {})",
                    hash, wallet
                ))
            )
        }
        fn ready_data_for_supply<'a>(
            existent: &'a [RefWalletAndRowidOptCoupledWithHash],
        ) -> Vec<(&'a Wallet, u64)> {
            existent
                .iter()
                .map(|((wallet, ever_some_rowid), _)| (*wallet, ever_some_rowid.expectv("rowid")))
                .collect()
        }

        let (existent, nonexistent) =
            self.separate_id_triples_from_existent_and_nonexistent_fingerprints(sent_payments);
        let mark_p_payables_input_data = ready_data_for_supply(&existent);
        if !mark_p_payables_input_data.is_empty() {
            if let Err(e) = self
                .payable_dao
                .as_ref()
                .mark_pending_payables_rowids(&mark_p_payables_input_data)
            {
                fatal_database_mark_pending_payable_error(
                    sent_payments,
                    &nonexistent,
                    e,
                    missing_fingerprints_msg,
                    logger,
                )
            }
            debug!(
                logger,
                "Payables {} marked as pending in the payable table",
                join_displayable_items_by_commas(sent_payments, |pending_p| format!(
                    "{:?}",
                    pending_p.hash
                ))
            )
        }
        if !nonexistent.is_empty() {
            panic!("{}", missing_fingerprints_msg(&nonexistent))
        }
    }

    fn handle_sent_payable_errors(
        &self,
        err_opt: Option<PayableTransactingErrorEnum>,
        logger: &Logger,
    ) {
        if let Some(err) = err_opt {
            match err {
                LocallyCausedError(PayableTransactionFailed {
                    signed_and_saved_txs_opt: Some(hashes),
                    ..
                })
                | RemotelyCausedErrors(hashes) => {
                    self.discard_failed_transactions_with_possible_fingerprints(hashes, logger)
                }
                e =>
                    debug!(
                        logger,
                        "Ignoring a non-fatal error on our end from before the transactions are hashed: {:?}",
                        e
                    )
            }
        }
    }

    fn discard_failed_transactions_with_possible_fingerprints(
        &self,
        hashes_of_the_failed: Vec<H256>,
        logger: &Logger,
    ) {
        fn serialize_hashes(hashes: &[H256]) -> String {
            join_displayable_items_by_commas(hashes, |hash| format!("{:?}", hash))
        }

        let (existent, nonexistent): (VecOfRowidOptAndHash, VecOfRowidOptAndHash) = self
            .pending_payable_dao
            .fingerprints_rowids(&hashes_of_the_failed)
            .into_iter()
            .partition(|(rowid_opt, _hash)| rowid_opt.is_some());

        if !nonexistent.is_empty() {
            panic_for_failed_payments_lacking_fingerprints(nonexistent, serialize_hashes)
        }

        if !existent.is_empty() {
            let ids = log_failed_payments_having_fingerprints_and_return_ids(
                existent,
                serialize_hashes,
                logger,
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprints(&ids) {
                panic!(
                    "Database corrupt: payable fingerprint deletion for transactions {} failed \
                 due to {:?}",
                    serialize_hashes(&hashes_of_the_failed),
                    e
                )
            }
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
        let response_skeleton_opt = message.response_skeleton_opt;

        match message.fingerprints_with_receipts.is_empty() {
            true => debug!(logger, "No transaction receipts found."),
            false => {
                debug!(
                    logger,
                    "Processing receipts for {} transactions",
                    message.fingerprints_with_receipts.len()
                );
                let scan_report = self.handle_receipts_for_pending_transactions(message, logger);
                self.process_transactions_by_reported_state(scan_report, logger);
            }
        }

        self.mark_as_ended(logger);
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }

    time_marking_methods!(PendingPayables);

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

    fn handle_receipts_for_pending_transactions(
        &self,
        msg: ReportTransactionReceipts,
        logger: &Logger,
    ) -> PendingPayableScanReport {
        fn handle_none_receipt(
            mut scan_report: PendingPayableScanReport,
            payable: PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingPayableScanReport {
            debug!(logger,
                "Interpreting a receipt for transaction {:?} but none was given; attempt {}, {}ms since sending",
                payable.hash, payable.attempt,elapsed_in_ms(payable.timestamp)
            );

            scan_report
                .still_pending
                .push(PendingPayableId::new(payable.rowid, payable.hash));
            scan_report
        }

        let scan_report = PendingPayableScanReport::default();
        msg.fingerprints_with_receipts.into_iter().fold(
            scan_report,
            |scan_report_so_far, (receipt_opt, fingerprint)| match receipt_opt {
                Some(receipt) => self.interpret_transaction_receipt(
                    scan_report_so_far,
                    &receipt,
                    fingerprint,
                    logger,
                ),
                None => handle_none_receipt(scan_report_so_far, fingerprint, logger),
            },
        )
    }

    fn interpret_transaction_receipt(
        &self,
        scan_report: PendingPayableScanReport,
        receipt: &TransactionReceipt,
        fingerprint: PendingPayableFingerprint,
        logger: &Logger,
    ) -> PendingPayableScanReport {
        match receipt.status {
            None => handle_none_status(scan_report, fingerprint, self.when_pending_too_long_sec, logger),
            Some(status_code) => match status_code.as_u64() {
                0 => handle_status_with_failure(scan_report, fingerprint, logger),
                1 => handle_status_with_success(scan_report, fingerprint, logger),
                other => unreachable!(
                    "tx receipt for pending {:?}: status code other than 0 or 1 shouldn't be possible, but was {}",
                    fingerprint.hash, other
                ),
            },
        }
    }

    fn process_transactions_by_reported_state(
        &mut self,
        scan_report: PendingPayableScanReport,
        logger: &Logger,
    ) {
        self.confirm_transactions(scan_report.confirmed, logger);
        self.cancel_failed_transactions(scan_report.failures, logger);
        self.update_remaining_fingerprints(scan_report.still_pending, logger)
    }

    fn update_remaining_fingerprints(&self, ids: Vec<PendingPayableId>, logger: &Logger) {
        if !ids.is_empty() {
            let rowids = PendingPayableId::rowids(&ids);
            match self.pending_payable_dao.increment_scan_attempts(&rowids) {
                Ok(_) => trace!(
                    logger,
                    "Updated records for rowids: {} ",
                    join_displayable_items_by_commas(&rowids, |id| id.to_string())
                ),
                Err(e) => panic!(
                    "Failure on incrementing scan attempts for fingerprints of {} due to {:?}",
                    PendingPayableId::serialize_hashes_to_string(&ids),
                    e
                ),
            }
        }
    }

    fn cancel_failed_transactions(&self, ids: Vec<PendingPayableId>, logger: &Logger) {
        if !ids.is_empty() {
            //TODO this function is imperfect. It waits for GH-663
            let rowids = PendingPayableId::rowids(&ids);
            match self.pending_payable_dao.mark_failures(&rowids) {
                Ok(_) => warning!(
                    logger,
                    "Broken transactions {} marked as an error. You should take over the care \
                 of those to make sure your debts are going to be settled properly. At the moment, \
                 there is no automated process fixing that without your assistance",
                    PendingPayableId::serialize_hashes_to_string(&ids)
                ),
                Err(e) => panic!(
                    "Unsuccessful attempt for transactions {} \
                    to mark fatal error at payable fingerprint due to {:?}; database unreliable",
                    PendingPayableId::serialize_hashes_to_string(&ids),
                    e
                ),
            }
        }
    }

    fn confirm_transactions(
        &mut self,
        fingerprints: Vec<PendingPayableFingerprint>,
        logger: &Logger,
    ) {
        fn serialize_hashes(fingerprints: &[PendingPayableFingerprint]) -> String {
            join_displayable_items_by_commas(fingerprints, |fgp| format!("{:?}", fgp.hash))
        }

        if !fingerprints.is_empty() {
            if let Err(e) = self.payable_dao.transactions_confirmed(&fingerprints) {
                panic!(
                    "Unable to cast confirmed pending payables {} into adjustment in the corresponding payable \
                     records due to {:?}", serialize_hashes(&fingerprints), e
                )
            } else {
                self.add_to_the_total_of_paid_payable(&fingerprints, serialize_hashes, logger);
                let rowids = fingerprints
                    .iter()
                    .map(|fingerprint| fingerprint.rowid)
                    .collect::<Vec<u64>>();
                if let Err(e) = self.pending_payable_dao.delete_fingerprints(&rowids) {
                    panic!("Unable to delete payable fingerprints {} of verified transactions due to {:?}",
                           serialize_hashes(&fingerprints), e)
                } else {
                    info!(
                        logger,
                        "Transactions {} completed their confirmation process succeeding",
                        serialize_hashes(&fingerprints)
                    )
                }
            }
        }
    }

    fn add_to_the_total_of_paid_payable(
        &mut self,
        fingerprints: &[PendingPayableFingerprint],
        serialize_hashes: fn(&[PendingPayableFingerprint]) -> String,
        logger: &Logger,
    ) {
        fingerprints.iter().for_each(|fingerprint| {
            self.financial_statistics
                .borrow_mut()
                .total_paid_payable_wei += fingerprint.amount
        });
        debug!(
            logger,
            "Confirmation of transactions {}; record for total paid payable was modified",
            serialize_hashes(fingerprints)
        );
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
                .fold(0, |so_far, now| so_far + now.wei_amount);
            self.receivable_dao
                .as_mut()
                .more_money_received(message.timestamp, message.payments);
            self.financial_statistics
                .borrow_mut()
                .total_paid_receivable_wei += total_newly_paid_receivable;
        }

        self.mark_as_ended(logger);
        message
            .response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    time_marking_methods!(Receivables);

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
        self.find_and_ban_delinquents(timestamp, logger);
        self.find_and_unban_reformed_nodes(timestamp, logger);
    }

    fn find_and_ban_delinquents(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .new_delinquencies(timestamp, self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet);
                let (balance_str_wei, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} gwei, age: {} sec) banned for delinquency",
                    account.wallet,
                    balance_str_wei,
                    age.as_secs()
                )
            });
    }

    fn find_and_unban_reformed_nodes(&self, timestamp: SystemTime, logger: &Logger) {
        self.receivable_dao
            .paid_delinquencies(self.common.payment_thresholds.as_ref())
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet);
                let (balance_str_wei, age) = balance_and_age(timestamp, &account);
                info!(
                    logger,
                    "Wallet {} (balance: {} gwei, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet,
                    balance_str_wei,
                    age.as_secs()
                )
            });
    }
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
        let log_message_opt = match self {
            BeginScanError::NothingToProcess => Some(format!(
                "There was nothing to process during {:?} scan.",
                scan_type
            )),
            BeginScanError::ScanAlreadyRunning(timestamp) => Some(format!(
                "{:?} scan was already initiated at {}. \
                 Hence, this scan request will be ignored.",
                scan_type,
                BeginScanError::timestamp_as_string(timestamp)
            )),
            BeginScanError::CalledFromNullScanner => match cfg!(test) {
                true => None,
                false => panic!("Null Scanner shouldn't be running inside production code."),
            },
        };

        if let Some(log_message) = log_message_opt {
            match is_externally_triggered {
                true => info!(logger, "{}", log_message),
                false => debug!(logger, "{}", log_message),
            }
        }
    }

    fn timestamp_as_string(timestamp: &SystemTime) -> String {
        let offset_date_time = OffsetDateTime::from(*timestamp);
        offset_date_time
            .format(
                &parse(TIME_FORMATTING_STRING)
                    .expect("Error while parsing the time formatting string."),
            )
            .expect("Error while formatting timestamp as string.")
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
        panic!("Called finish_scan() from NullScanner");
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        panic!("Called scan_started_at() from NullScanner");
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        panic!("Called mark_as_started() from NullScanner");
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        panic!("Called mark_as_ended() from NullScanner");
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
        intentionally_blank!()
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        intentionally_blank!()
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        intentionally_blank!()
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

pub fn join_displayable_items_by_commas<T, F>(collection: &[T], stringify: F) -> String
where
    F: FnMut(&T) -> String,
{
    collection.iter().map(stringify).join(COMMA_SEPARATOR)
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::{
        BeginScanError, PayableScanner, PendingPayableScanner, ReceivableScanner, Scanner,
        ScannerCommon, Scanners,
    };
    use crate::accountant::test_utils::{
        make_custom_payment_thresholds, make_payable_account, make_payables,
        make_pending_payable_fingerprint, make_receivable_account, BannedDaoFactoryMock,
        BannedDaoMock, PayableDaoFactoryMock, PayableDaoMock, PayableScannerBuilder,
        PayableThresholdsGaugeMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock,
        PendingPayableScannerBuilder, ReceivableDaoFactoryMock, ReceivableDaoMock,
        ReceivableScannerBuilder,
    };
    use crate::accountant::{
        gwei_to_wei, PendingPayableId, ReceivedPayments, ReportTransactionReceipts,
        RequestTransactionReceipts, SentPayables, DEFAULT_PENDING_TOO_LONG_SEC,
    };
    use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
    use std::cell::RefCell;
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::accountant::payable_dao::{PayableAccount, PayableDaoError, PendingPayable};
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::scanners_utils::payable_scanner_utils::PayableThresholdsGaugeReal;
    use crate::accountant::scanners_utils::pending_payable_scanner_utils::PendingPayableScanReport;
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failed};
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainTransaction, RpcPayableFailure,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::{
        DaoFactories, FinancialStatistics, PaymentThresholds, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::make_wallet;
    use actix::{Message, System};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::logger::Logger;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use regex::Regex;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H256, U256};
    use web3::Error;

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_result(PayableDaoMock::new())
            .make_result(PayableDaoMock::new());
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new()
            .make_result(PendingPayableDaoMock::new())
            .make_result(PendingPayableDaoMock::new());
        let receivable_dao_factory =
            ReceivableDaoFactoryMock::new().make_result(ReceivableDaoMock::new());
        let banned_dao_factory = BannedDaoFactoryMock::new().make_result(BannedDaoMock::new());
        let when_pending_too_long_sec = 1234;
        let financial_statistics = FinancialStatistics {
            total_paid_payable_wei: 1,
            total_paid_receivable_wei: 2,
        };
        let earning_wallet = make_wallet("unique_wallet");
        let payment_thresholds = make_custom_payment_thresholds();
        let payment_thresholds_rc = Rc::new(payment_thresholds);
        let initial_rc_count = Rc::strong_count(&payment_thresholds_rc);

        let scanners = Scanners::new(
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
            },
            Rc::clone(&payment_thresholds_rc),
            Rc::new(earning_wallet.clone()),
            when_pending_too_long_sec,
            Rc::new(RefCell::new(financial_statistics.clone())),
        );

        let payable_scanner = scanners
            .payable
            .as_any()
            .downcast_ref::<PayableScanner>()
            .unwrap();
        let pending_payable_scanner = scanners
            .pending_payable
            .as_any()
            .downcast_ref::<PendingPayableScanner>()
            .unwrap();
        let receivable_scanner = scanners
            .receivable
            .as_any()
            .downcast_ref::<ReceivableScanner>()
            .unwrap();
        assert_eq!(
            payable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(payable_scanner.common.initiated_at_opt.is_some(), false);
        payable_scanner
            .payable_threshold_gauge
            .as_any()
            .downcast_ref::<PayableThresholdsGaugeReal>()
            .unwrap();
        assert_eq!(
            pending_payable_scanner.when_pending_too_long_sec,
            when_pending_too_long_sec
        );
        assert_eq!(
            *pending_payable_scanner.financial_statistics.borrow(),
            financial_statistics
        );
        assert_eq!(
            pending_payable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(
            pending_payable_scanner.common.initiated_at_opt.is_some(),
            false
        );
        assert_eq!(
            *receivable_scanner.financial_statistics.borrow(),
            financial_statistics
        );
        assert_eq!(
            receivable_scanner.earning_wallet.address(),
            earning_wallet.address()
        );
        assert_eq!(
            receivable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(receivable_scanner.common.initiated_at_opt.is_some(), false);
        assert_eq!(
            Rc::strong_count(&payment_thresholds_rc),
            initial_rc_count + 3
        );
    }

    #[test]
    fn payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let (qualified_payable_accounts, _, all_non_pending_payables) =
            make_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();

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
            &format!(
                "INFO: {test_name}: Chose {} qualified debts to pay",
                qualified_payable_accounts.len()
            ),
        ])
    }

    #[test]
    fn payable_scanner_throws_error_when_a_scan_is_already_running() {
        let now = SystemTime::now();
        let (_, _, all_non_pending_payables) = make_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
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
        let now = SystemTime::now();
        let (_, unqualified_payable_accounts, _) =
            make_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();

        let result = subject.begin_scan(now, None, &Logger::new("test"));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(result, Err(BeginScanError::NothingToProcess));
    }

    #[test]
    fn payable_scanner_handles_sent_payable_message() {
        init_test_logging();
        let test_name = "payable_scanner_handles_sent_payable_message";
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let correct_payable_hash_1 = make_tx_hash(111);
        let correct_payable_rowid_1 = 125;
        let correct_payable_wallet_1 = make_wallet("tralala");
        let correct_pending_payable_1 =
            PendingPayable::new(correct_payable_wallet_1.clone(), correct_payable_hash_1);
        let failure_payable_hash_2 = make_tx_hash(222);
        let failure_payable_rowid_2 = 126;
        let failure_payable_wallet_2 = make_wallet("hihihi");
        let failure_payable_2 = RpcPayableFailure {
            rpc_error: Error::InvalidResponse(
                "Learn how to write before you send your garbage!".to_string(),
            ),
            recipient_wallet: failure_payable_wallet_2,
            hash: failure_payable_hash_2,
        };
        let correct_payable_hash_3 = make_tx_hash(333);
        let correct_payable_rowid_3 = 127;
        let correct_payable_wallet_3 = make_wallet("booga");
        let correct_pending_payable_3 =
            PendingPayable::new(correct_payable_wallet_3.clone(), correct_payable_hash_3);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(vec![
                (Some(correct_payable_rowid_1), correct_payable_hash_1),
                (Some(correct_payable_rowid_3), correct_payable_hash_3),
            ])
            .fingerprints_rowids_result(vec![(
                Some(failure_payable_rowid_2),
                failure_payable_hash_2,
            )])
            .delete_fingerprints_params(&delete_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()));
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payables_rowids_params(&mark_pending_payables_params_arc)
            .mark_pending_payables_rowids_result(Ok(()))
            .mark_pending_payables_rowids_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![
                Correct(correct_pending_payable_1),
                Failed(failure_payable_2),
                Correct(correct_pending_payable_3),
            ]),
            response_skeleton_opt: None,
        };
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(sent_payable, &logger);

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(message_opt, None);
        assert_eq!(is_scan_running, false);
        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(
            *fingerprints_rowids_params,
            vec![
                vec![correct_payable_hash_1, correct_payable_hash_3],
                vec![failure_payable_hash_2]
            ]
        );
        let mark_pending_payables_params = mark_pending_payables_params_arc.lock().unwrap();
        assert_eq!(
            *mark_pending_payables_params,
            vec![vec![
                (correct_payable_wallet_1, correct_payable_rowid_1),
                (correct_payable_wallet_3, correct_payable_rowid_3)
            ]]
        );
        let delete_fingerprint_params = delete_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *delete_fingerprint_params,
            vec![vec![failure_payable_rowid_2]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.assert_logs_contain_in_order(vec![
            &format!(
                "WARN: {test_name}: Remote transaction failure: 'Got invalid response: Learn how to write before you send your garbage!' \
                for payment to 0x0000000000000000000000000000686968696869 and transaction hash \
                0x00000000000000000000000000000000000000000000000000000000000000de. Please check your blockchain service URL configuration"
            ),
            &format!("DEBUG: {test_name}: Got 2 properly sent payables of 3 attempts"),
            &format!(
                "DEBUG: {test_name}: Payables 0x000000000000000000000000000000000000000000000000000000000000006f, \
                 0x000000000000000000000000000000000000000000000000000000000000014d marked as pending in the payable table"
            ),
            &format!(
                "WARN: {test_name}: Deleting fingerprints for failed transactions \
                 0x00000000000000000000000000000000000000000000000000000000000000de"
            ),
        ]);
        log_handler.exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }

    #[test]
    fn payable_scanner_discovers_failed_transactions_and_pending_payable_fingerprints_been_really_created(
    ) {
        init_test_logging();
        let test_name = "payable_scanner_discovers_failed_transactions_and_pending_payable_fingerprints_been_really_created";
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_tx_1 = make_tx_hash(5555);
        let hash_tx_2 = make_tx_hash(12345);
        let first_fingerprint_rowid = 3;
        let second_fingerprint_rowid = 5;
        let system = System::new(test_name);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(vec![
                (Some(first_fingerprint_rowid), hash_tx_1),
                (Some(second_fingerprint_rowid), hash_tx_2),
            ])
            .delete_fingerprints_params(&delete_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let sent_payable = SentPayables {
            payment_procedure_result: Err(BlockchainError::PayableTransactionFailed {
                msg: "Attempt failed".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_tx_1, hash_tx_2]),
            }),
            response_skeleton_opt: None,
        };

        let result = subject.finish_scan(sent_payable, &logger);

        System::current().stop();
        system.run();
        assert_eq!(result, None);
        let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
        assert_eq!(
            *fingerprints_rowids_params,
            vec![vec![hash_tx_1, hash_tx_2]]
        );
        let delete_fingerprints_params = delete_fingerprint_params_arc.lock().unwrap();
        assert_eq!(
            *delete_fingerprints_params,
            vec![vec![first_fingerprint_rowid, second_fingerprint_rowid]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: \
         Failed process to be screened for persisted data. Caused by: Blockchain error: Occurred at the final batch processing: \"Attempt failed\". \
         Successfully signed and hashed these transactions: 0x00000000000000000000000000000000000000000000000000000000000015b3, \
         0x0000000000000000000000000000000000000000000000000000000000003039."));
        log_handler.exists_log_containing(
            &format!("WARN: {test_name}: \
            Deleting fingerprints for failed transactions 0x00000000000000000000000000000000000000000000000000000000000015b3, \
            0x0000000000000000000000000000000000000000000000000000000000003039",
        ));
        //we haven't supplied any result for mark_pending_payable() and so it's proved uncalled
    }

    #[test]
    fn payable_scanner_handles_error_born_too_early_to_see_transaction_hash() {
        init_test_logging();
        let test_name = "payable_scanner_handles_error_born_too_early_to_see_transaction_hash";
        let sent_payable = SentPayables {
            payment_procedure_result: Err(BlockchainError::PayableTransactionFailed {
                msg: "Some error".to_string(),
                signed_and_saved_txs_opt: None,
            }),
            response_skeleton_opt: None,
        };
        let mut subject = PayableScannerBuilder::new().build();

        subject.finish_scan(sent_payable, &Logger::new(test_name));

        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Got 0 properly sent payables of not \
         determinable number of attempts"
        ));
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Ignoring a non-fatal error on our end from before \
            the transactions are hashed: LocallyCausedError(PayableTransactionFailed \
             {{ msg: \"Some error\", signed_and_saved_txs_opt: None }})"
        ));
    }

    #[test]
    #[should_panic(
        expected = "Expected pending payable fingerprints for (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, \
     to wallet: 0x000000000000000000000000000000626f6f6761), (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, \
     to wallet: 0x00000000000000000000000000000061676f6f62) were not found; system unreliable"
    )]
    fn payable_scanner_panics_when_fingerprint_is_not_found() {
        let hash_1 = make_tx_hash(789);
        let payment_1 = PendingPayable::new(make_wallet("booga"), hash_1);
        let hash_2 = make_tx_hash(789);
        let payment_2 = PendingPayable::new(make_wallet("agoob"), hash_2);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(None, hash_1), (None, hash_2)]);
        let payable_dao = PayableDaoMock::new().mark_pending_payables_rowids_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![Correct(payment_1), Correct(payment_2)]),
            response_skeleton_opt: None,
        };

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: payable fingerprint deletion for transactions \
        0x000000000000000000000000000000000000000000000000000000000000007b, 0x00000000000000000000\
        00000000000000000000000000000000000000000315 failed due to RecordDeletion(\"Gosh, I overslept \
        without an alarm set\")"
    )]
    fn payable_scanner_panics_at_deletion_of_failed_payments_fingerprints() {
        let rowid_1 = 4;
        let hash_1 = make_tx_hash(123);
        let rowid_2 = 6;
        let hash_2 = make_tx_hash(789);
        let sent_payable = SentPayables {
            payment_procedure_result: Err(BlockchainError::PayableTransactionFailed {
                msg: "blah".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_1, hash_2]),
            }),
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(rowid_1), hash_1), (Some(rowid_2), hash_2)])
            .delete_fingerprints_result(Err(PendingPayableDaoError::RecordDeletion(
                "Gosh, I overslept without an alarm set".to_string(),
            )));
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    #[test]
    fn payable_scanner_finds_missing_fingerprints_before_it_deletes_fingerprints_of_failed_payments(
    ) {
        init_test_logging();
        let test_name = "payable_scanner_finds_missing_fingerprints_before_it_deletes_fingerprints_of_failed_payments";
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
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let failed_payment_1 = Failed(RpcPayableFailure {
            rpc_error: Error::Unreachable,
            recipient_wallet: make_wallet("abc"),
            hash: existent_record_hash,
        });
        let failed_payment_2 = Failed(RpcPayableFailure {
            rpc_error: Error::Unreachable,
            recipient_wallet: make_wallet("def"),
            hash: nonexistent_record_hash,
        });
        let sent_payable = SentPayables {
            payment_procedure_result: Ok(vec![failed_payment_1, failed_payment_2]),
            response_skeleton_opt: None,
        };

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payable, &Logger::new(test_name))
        }))
        .err()
        .unwrap();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Running into failed transactions 0x0000000000000000000000000\
        0000000000000000000000000000000000004d2 with missing fingerprints"
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Remote transaction failure: 'Server is unreachable' \
         for payment to 0x0000000000000000000000000000000000616263 and transaction hash 0x00000000000000000000000\
         0000000000000000000000000000000000000b26e. Please check your blockchain service URL configuration."));
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Remote transaction failure: 'Server is unreachable' \
        for payment to 0x0000000000000000000000000000000000646566 and transaction hash 0x000000000000000000000000\
        00000000000000000000000000000000000004d2. Please check your blockchain service URL configuration."));
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Got 0 properly sent payables of 2 attempts"
        ));
    }

    #[test]
    fn payable_scanner_panics_when_errors_from_post_hash_time_are_found_and_fingerprints_do_not_exist(
    ) {
        init_test_logging();
        let test_name = "payable_scanner_panics_when_errors_from_post_hash_time_are_found_and_fingerprints_do_not_exist";
        let hash_1 = make_tx_hash(112233);
        let hash_2 = make_tx_hash(12345);
        let hash_3 = make_tx_hash(8765);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(333), hash_1), (None, hash_2), (None, hash_3)])
            .delete_fingerprints_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayables {
            payment_procedure_result: Err(BlockchainError::PayableTransactionFailed {
                msg: "SQLite migraine".to_string(),
                signed_and_saved_txs_opt: Some(vec![hash_1, hash_2, hash_3]),
            }),
            response_skeleton_opt: None,
        };

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payable, &Logger::new(test_name))
        }))
        .err()
        .unwrap();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(panic_msg, "Running into failed transactions 0x0000000000000000000000000000000000\
        000000000000000000000000003039, 0x000000000000000000000000000000000000000000000000000000000000223d \
        with missing fingerprints");
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            &format!("WARN: {test_name}: Failed process to be screened for persisted data. Caused by: \
             Blockchain error: Occurred at the final batch processing: \"SQLite migraine\". Successfully signed and hashed \
             these transactions: \
               0x000000000000000000000000000000000000000000000000000000000001b669, \
              0x0000000000000000000000000000000000000000000000000000000000003039, \
               0x000000000000000000000000000000000000000000000000000000000000223d."));
        log_handler.exists_no_log_containing(&format!(
            "DEBUG: {test_name}: Deleting an existing backup for a failed transaction {:?}",
            hash_1
        ));
    }

    fn common_body_for_failing_to_mark_rowids_tests(
        test_name: &str,
        pending_payable_dao: PendingPayableDaoMock,
        hash_1: H256,
        hash_2: H256,
    ) {
        let payable_1 = PendingPayable::new(make_wallet("blah111"), hash_1);
        let payable_2 = PendingPayable::new(make_wallet("blah222"), hash_2);
        let payable_dao = PayableDaoMock::new().mark_pending_payables_rowids_result(Err(
            PayableDaoError::SignConversion(9999999999999),
        ));
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payables = SentPayables {
            payment_procedure_result: Ok(vec![Correct(payable_1), Correct(payable_2)]),
            response_skeleton_opt: None,
        };

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payables, &Logger::new(test_name))
        }))
        .err()
        .unwrap();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Unable to create a mark in the payable table for wallets 0x00000000000\
        000000000000000626c6168313131, 0x00000000000000000000000000626c6168323232 due to \
         SignConversion(9999999999999)"
        );
    }

    #[test]
    fn payable_scanner_fails_on_marking_pending_payable_and_panics_clear_not_having_run_into_nonexistent_fingerprints(
    ) {
        init_test_logging();
        let test_name = "payable_scanner_fails_on_marking_pending_payable_and_panics_clear_not_having_run_into_nonexistent_fingerprints";
        let hash_1 = make_tx_hash(248);
        let hash_2 = make_tx_hash(139);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(Some(7879), hash_1), (Some(7881), hash_2)]);

        common_body_for_failing_to_mark_rowids_tests(
            test_name,
            pending_payable_dao,
            hash_1,
            hash_2,
        );

        TestLogHandler::new().exists_no_log_matching(&format!(
            "ERROR: {test_name}: Payable fingerprints for (\
         .*) not found but should exist by now; system unreliable"
        ));
    }

    #[test]
    fn payable_scanner_fails_on_marking_pending_payable_and_panics_clear_while_also_having_run_into_nonexistent_fingerprints(
    ) {
        init_test_logging();
        let test_name = "payable_scanner_fails_on_marking_pending_payable_and_panics_clear_while_also_having_run_into_nonexistent_fingerprints";
        let hash_1 = make_tx_hash(248);
        let hash_2 = make_tx_hash(139);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(vec![(None, hash_1), (Some(7881), hash_2)]);

        common_body_for_failing_to_mark_rowids_tests(
            test_name,
            pending_payable_dao,
            hash_1,
            hash_2,
        );

        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: Expected pending payable \
         fingerprints for (tx: 0x00000000000000000000000000000000000000000000000000000000000000f8, to wallet: \
          0x00000000000000000000000000626c6168313131) were not found; system unreliable"));
    }

    #[test]
    fn payable_is_found_innocent_by_age_and_returns() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(true);
        let mut subject = PayableScannerBuilder::new().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let now = SystemTime::now();
        let debt_age_s = 111_222;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
        let mut payable = make_payable_account(111);
        payable.last_paid_timestamp = last_paid_timestamp;

        let result = subject.payable_exceeded_threshold(&payable, now);

        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned, threshold_value) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        assert_eq!(debt_age_returned, debt_age_s);
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
        let mut subject = PayableScannerBuilder::new().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let now = SystemTime::now();
        let debt_age_s = 3_456;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
        let mut payable = make_payable_account(222);
        payable.last_paid_timestamp = last_paid_timestamp;
        payable.balance_wei = 123456;

        let result = subject.payable_exceeded_threshold(&payable, now);

        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned, _) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        assert_eq!(debt_age_returned, debt_age_s);
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
        let now = SystemTime::now();
        let debt_age_s = 1111 + 1;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
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
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(
                debt_age_s <= custom_payment_thresholds.maturity_threshold_sec as u64,
            )
            .is_innocent_balance_params(&is_innocent_balance_params_arc)
            .is_innocent_balance_result(
                balance <= gwei_to_wei(custom_payment_thresholds.permanent_debt_allowed_gwei),
            )
            .calculate_payout_threshold_in_gwei_params(&calculate_payable_threshold_params_arc)
            .calculate_payout_threshold_in_gwei_result(4567898); //made up value
        let mut subject = PayableScannerBuilder::new()
            .payment_thresholds(custom_payment_thresholds)
            .build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);

        let result = subject.payable_exceeded_threshold(&payable_account, now);

        assert_eq!(result, Some(4567898));
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned_innocent, curve_derived_time) = is_innocent_age_params.remove(0);
        assert_eq!(*is_innocent_age_params, vec![]);
        assert_eq!(debt_age_returned_innocent, debt_age_s);
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
        let (payment_thresholds, debt_age_returned_curves) =
            calculate_payable_curves_params.remove(0);
        assert_eq!(*calculate_payable_curves_params, vec![]);
        assert_eq!(debt_age_returned_curves, debt_age_s);
        assert_eq!(payment_thresholds, custom_payment_thresholds)
    }

    #[test]
    fn payable_with_debt_under_the_slope_is_marked_unqualified() {
        init_test_logging();
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let debt = gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 1);
        let time = to_time_t(now) - payment_thresholds.maturity_threshold_sec as i64 - 1;
        let unqualified_payable_account = vec![PayableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: debt,
            last_paid_timestamp: from_time_t(time),
            pending_payable_opt: None,
        }];
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let test_name =
            "payable_with_debt_above_the_slope_is_qualified_and_the_threshold_value_is_returned";
        let logger = Logger::new(test_name);

        let result = subject
            .sniff_out_alarming_payables_and_maybe_log_them(unqualified_payable_account, &logger);

        assert_eq!(result, vec![]);
        TestLogHandler::new()
            .exists_no_log_containing(&format!("DEBUG: {}: Paying qualified debts", test_name));
    }

    #[test]
    fn payable_with_debt_above_the_slope_is_qualified() {
        init_test_logging();
        let payment_thresholds = PaymentThresholds::default();
        let debt = gwei_to_wei(payment_thresholds.debt_threshold_gwei - 1);
        let time = (payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec
            - 1) as i64;
        let qualified_payable = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: debt,
            last_paid_timestamp: from_time_t(time),
            pending_payable_opt: None,
        };
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let test_name = "payable_with_debt_above_the_slope_is_qualified";
        let logger = Logger::new(test_name);

        let result = subject.sniff_out_alarming_payables_and_maybe_log_them(
            vec![qualified_payable.clone()],
            &logger,
        );

        assert_eq!(result, vec![qualified_payable]);
        TestLogHandler::new().exists_log_matching(&format!(
            "DEBUG: {}: Paying qualified debts:\n999,999,999,000,000,\
            000 wei owed for \\d+ sec exceeds threshold: 500,000,000,000,000,000 wei; creditor: \
             0x0000000000000000000000000077616c6c657430",
            test_name
        ));
    }

    #[test]
    fn non_pending_payables_turn_into_an_empty_vector_if_all_unqualified() {
        init_test_logging();
        let test_name = "non_pending_payables_turn_into_an_empty_vector_if_all_unqualified";
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let unqualified_payable_account = vec![PayableAccount {
            wallet: make_wallet("wallet1"),
            balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 1),
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec as i64 + 1,
            ),
            pending_payable_opt: None,
        }];
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let logger = Logger::new(test_name);

        let result = subject
            .sniff_out_alarming_payables_and_maybe_log_them(unqualified_payable_account, &logger);

        assert_eq!(result, vec![]);
        TestLogHandler::new()
            .exists_no_log_containing(&format!("DEBUG: {test_name}: Paying qualified debts"));
    }

    #[test]
    fn pending_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "pending_payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let payable_fingerprint_1 = PendingPayableFingerprint {
            rowid: 555,
            timestamp: from_time_t(210_000_000),
            hash: make_tx_hash(45678),
            attempt: 1,
            amount: 4444,
            process_error: None,
        };
        let payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: 550,
            timestamp: from_time_t(210_000_100),
            hash: make_tx_hash(112233),
            attempt: 1,
            amount: 7999,
            process_error: None,
        };
        let fingerprints = vec![payable_fingerprint_1, payable_fingerprint_2];
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(fingerprints.clone());
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let no_of_pending_payables = fingerprints.len();
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
                    rowid: 1234,
                    timestamp: SystemTime::now(),
                    hash: Default::default(),
                    attempt: 1,
                    amount: 1_000_000,
                    process_error: None,
                },
            ]);
        let mut subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let logger = Logger::new("test");
        let _ = subject.begin_scan(now, None, &logger);

        let result = subject.begin_scan(SystemTime::now(), None, &logger);

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(result, Err(BeginScanError::ScanAlreadyRunning(now)));
    }

    #[test]
    fn pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found() {
        let now = SystemTime::now();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(vec![]);
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new("test"));

        let is_scan_running = pending_payable_scanner.scan_started_at().is_some();
        assert_eq!(result, Err(BeginScanError::NothingToProcess));
        assert_eq!(is_scan_running, false);
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval";
        let hash = make_tx_hash(567);
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent =
            SystemTime::now().sub(Duration::from_secs(DEFAULT_PENDING_TOO_LONG_SEC + 5)); //old transaction
        let subject = PendingPayableScannerBuilder::new().build();
        let fingerprint = PendingPayableFingerprint {
            rowid,
            timestamp: when_sent,
            hash,
            attempt: 10,
            amount: 123,
            process_error: None,
        };
        let logger = Logger::new(test_name);
        let scan_report = PendingPayableScanReport::default();

        let result =
            subject.interpret_transaction_receipt(scan_report, &tx_receipt, fingerprint, &logger);

        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![],
                failures: vec![PendingPayableId::new(rowid, hash)],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Pending transaction 0x00000000000000000000000000000000000000\
            00000000000000000000000237 has exceeded the maximum pending time (21600sec) and the \
            confirmation process is going to be aborted now at the final attempt 10; manual \
            resolution is required from the user to complete the transaction"
        ));
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval";
        let subject = PendingPayableScannerBuilder::new().build();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let duration_in_ms = 100;
        let when_sent = SystemTime::now().sub(Duration::from_millis(duration_in_ms));
        let fingerprint = PendingPayableFingerprint {
            rowid,
            timestamp: when_sent,
            hash,
            attempt: 1,
            amount: 123,
            process_error: None,
        };
        let logger = Logger::new(test_name);
        let scan_report = PendingPayableScanReport::default();

        let result =
            subject.interpret_transaction_receipt(scan_report, &tx_receipt, fingerprint, &logger);

        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![PendingPayableId::new(rowid, hash)],
                failures: vec![],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Pending transaction 0x0000000000000000000000000000000000000000000000000\
            000000000000237 couldn't be confirmed at attempt 1 at {duration_in_ms}ms after its sending",
        ));
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending 0x000000000000000000000000000000000000000000000000000000000000007b: \
         status code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = H256::from_uint(&U256::from(123));
        let subject = PendingPayableScannerBuilder::new().build();
        let scan_report = PendingPayableScanReport::default();
        let logger = Logger::new("test");

        let _ =
            subject.interpret_transaction_receipt(scan_report, &tx_receipt, fingerprint, &logger);
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_a_failure";
        let subject = PendingPayableScannerBuilder::new().build();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = H256::from_uint(&U256::from(4567));
        let fingerprint = PendingPayableFingerprint {
            rowid: 777777,
            timestamp: SystemTime::now().sub(Duration::from_millis(150000)),
            hash,
            attempt: 5,
            amount: 2222,
            process_error: None,
        };
        let logger = Logger::new(test_name);
        let scan_report = PendingPayableScanReport::default();

        let result =
            subject.interpret_transaction_receipt(scan_report, &tx_receipt, fingerprint, &logger);

        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![],
                failures: vec![PendingPayableId::new(777777, hash,)],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "ERROR: {test_name}: Pending transaction 0x0000000000000000000000000000000000000000\
            0000000000000000000011d7 announced as a failure, interpreting attempt 5 after \
            1500\\d\\dms from the sending"
        ));
    }

    #[test]
    fn handle_pending_txs_with_receipts_handles_none_for_receipt() {
        init_test_logging();
        let test_name = "handle_pending_txs_with_receipts_handles_none_for_receipt";
        let subject = PendingPayableScannerBuilder::new().build();
        let tx_receipt_opt = None;
        let rowid = 455;
        let hash = H256::from_uint(&U256::from(2323));
        let fingerprint = PendingPayableFingerprint {
            rowid,
            timestamp: SystemTime::now().sub(Duration::from_millis(10000)),
            hash,
            attempt: 3,
            amount: 111,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(tx_receipt_opt, fingerprint.clone())],
            response_skeleton_opt: None,
        };

        let result = subject.handle_receipts_for_pending_transactions(msg, &Logger::new(test_name));

        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![PendingPayableId::new(rowid, hash)],
                failures: vec![],
                confirmed: vec![]
            }
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "DEBUG: {test_name}: Interpreting a receipt for transaction \
            0x0000000000000000000000000000000000000000000000000000000000000913 \
            but none was given; attempt 3, 100\\d\\dms since sending"
        ));
    }

    #[test]
    fn increment_scan_attempts_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(444888);
        let rowid_1 = 3456;
        let hash_2 = make_tx_hash(444888);
        let rowid_2 = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .increment_scan_attempts_params(&update_after_cycle_params_arc)
            .increment_scan_attempts_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id_1 = PendingPayableId::new(rowid_1, hash_1);
        let transaction_id_2 = PendingPayableId::new(rowid_2, hash_2);

        let _ = subject.update_remaining_fingerprints(
            vec![transaction_id_1, transaction_id_2],
            &Logger::new("test"),
        );

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![vec![rowid_1, rowid_2]])
    }

    #[test]
    #[should_panic(
        expected = "Failure on incrementing scan attempts for fingerprints of \
                0x000000000000000000000000000000000000000000000000000000000006c9d8 \
                due to UpdateFailed(\"yeah, bad\")"
    )]
    fn increment_scan_attempts_sad_path() {
        let hash = make_tx_hash(444888);
        let rowid = 3456;
        let pending_payable_dao =
            PendingPayableDaoMock::default().increment_scan_attempts_result(Err(
                PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
            ));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let logger = Logger::new("test");
        let transaction_id = PendingPayableId::new(rowid, hash);

        let _ = subject.update_remaining_fingerprints(vec![transaction_id], &logger);
    }

    #[test]
    fn update_remaining_fingerprints_does_nothing_if_no_still_pending_transactions_remain() {
        let subject = PendingPayableScannerBuilder::new().build();

        subject.update_remaining_fingerprints(vec![], &Logger::new("test"))

        //mocked pending payable DAO didn't panic which means we skipped the actual process
    }

    #[test]
    fn cancel_failed_transaction_works() {
        init_test_logging();
        let test_name = "cancel_pending_transaction_works";
        let mark_failures_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failures_params(&mark_failures_params_arc)
            .mark_failures_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let id_1 = PendingPayableId::new(2, make_tx_hash(123));
        let id_2 = PendingPayableId::new(3, make_tx_hash(456));

        subject.cancel_failed_transactions(vec![id_1, id_2], &Logger::new(test_name));

        let mark_failures_params = mark_failures_params_arc.lock().unwrap();
        assert_eq!(*mark_failures_params, vec![vec![2, 3]]);
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Broken transactions 0x000000000000000000000000000000000000000000000000000000000000007b, \
            0x00000000000000000000000000000000000000000000000000000000000001c8 marked as an error. You should take over \
            the care of those to make sure your debts are going to be settled properly. At the moment, there is no automated \
            process fixing that without your assistance",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unsuccessful attempt for transactions 0x00000000000000000000000000000000000\
        0000000000000000000000000014d, 0x000000000000000000000000000000000000000000000000000000\
        00000001bc to mark fatal error at payable fingerprint due to UpdateFailed(\"no no no\"); \
        database unreliable"
    )]
    fn cancel_tailed_transaction_panics_when_it_fails_to_mark_failure() {
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failures_result(Err(
            PendingPayableDaoError::UpdateFailed("no no no".to_string()),
        ));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id_1 = PendingPayableId::new(2, make_tx_hash(333));
        let transaction_id_2 = PendingPayableId::new(3, make_tx_hash(444));
        let transaction_ids = vec![transaction_id_1, transaction_id_2];

        subject.cancel_failed_transactions(transaction_ids, &Logger::new("test"));
    }

    #[test]
    fn cancel_transactions_does_nothing_if_no_tx_failures_detected() {
        let subject = PendingPayableScannerBuilder::new().build();

        subject.cancel_failed_transactions(vec![], &Logger::new("test"))

        //mocked pending payable DAO didn't panic which means we skipped the actual process
    }

    #[test]
    #[should_panic(
        expected = "Unable to delete payable fingerprints 0x000000000000000000000000000000000\
        0000000000000000000000000000315 of verified transactions due to RecordDeletion(\"the database \
        is fooling around with us\")"
    )]
    fn confirm_transaction_panics_while_deleting_pending_payable_fingerprint() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().delete_fingerprints_result(Err(
            PendingPayableDaoError::RecordDeletion(
                "the database is fooling around with us".to_string(),
            ),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        pending_payable_fingerprint.rowid = rowid;
        pending_payable_fingerprint.hash = hash;

        subject.confirm_transactions(vec![pending_payable_fingerprint], &Logger::new("test"));
    }

    #[test]
    fn confirm_transactions_does_nothing_if_none_found_on_the_blockchain() {
        let mut subject = PendingPayableScannerBuilder::new().build();

        subject.confirm_transactions(vec![], &Logger::new("test"))

        //mocked payable DAO didn't panic which means we skipped the actual process
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
            .delete_fingerprints_params(&delete_pending_payable_fingerprint_params_arc)
            .delete_fingerprints_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid_1 = 2;
        let rowid_2 = 5;
        let pending_payable_fingerprint_1 = PendingPayableFingerprint {
            rowid: rowid_1,
            timestamp: from_time_t(199_000_000),
            hash: H256::from("some_hash".keccak256()),
            attempt: 1,
            amount: 4567,
            process_error: None,
        };
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: rowid_2,
            timestamp: from_time_t(200_000_000),
            hash: H256::from("different_hash".keccak256()),
            attempt: 1,
            amount: 5555,
            process_error: None,
        };

        subject.confirm_transactions(
            vec![
                pending_payable_fingerprint_1.clone(),
                pending_payable_fingerprint_2.clone(),
            ],
            &Logger::new("confirm_transactions_works"),
        );

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
        log_handler.exists_log_containing(
            "DEBUG: confirm_transactions_works: \
         Confirmation of transactions \
         0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
         0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7; \
         record for total paid payable was modified",
        );
        log_handler.exists_log_containing(
            "INFO: confirm_transactions_works: \
         Transactions \
         0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
         0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7 \
         completed their confirmation process succeeding",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unable to cast confirmed pending payables 0x0000000000000000000000000000000000000000000\
    000000000000000000315 into adjustment in the corresponding payable records due to RusqliteError\
    (\"record change not successful\")"
    )]
    fn confirm_transaction_panics_on_unchecking_payable_table() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.rowid = rowid;
        fingerprint.hash = hash;

        subject.confirm_transactions(vec![fingerprint], &Logger::new("test"));
    }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        let test_name = "total_paid_payable_rises_with_each_bill_paid";
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 5,
            timestamp: from_time_t(189_999_888),
            hash: make_tx_hash(56789),
            attempt: 1,
            amount: 5478,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 6,
            timestamp: from_time_t(200_000_011),
            hash: make_tx_hash(33333),
            attempt: 1,
            amount: 6543,
            process_error: None,
        };
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable_wei += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.confirm_transactions(
            vec![fingerprint_1.clone(), fingerprint_2.clone()],
            &Logger::new(test_name),
        );

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable_wei;
        let transaction_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(total_paid_payable, 1111 + 5478 + 6543);
        assert_eq!(
            *transaction_confirmed_params,
            vec![vec![fingerprint_1, fingerprint_2]]
        )
    }

    #[test]
    fn pending_payable_scanner_handles_report_transaction_receipts_message() {
        init_test_logging();
        let test_name = "pending_payable_scanner_handles_report_transaction_receipts_message";
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::new().delete_fingerprints_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_hash_1 = H256::from_uint(&U256::from(4545));
        let mut transaction_receipt_1 = TransactionReceipt::default();
        transaction_receipt_1.transaction_hash = transaction_hash_1;
        transaction_receipt_1.status = Some(U64::from(1)); //success
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 5,
            timestamp: from_time_t(200_000_000),
            hash: transaction_hash_1,
            attempt: 2,
            amount: 444,
            process_error: None,
        };
        let transaction_hash_2 = H256::from_uint(&U256::from(1234));
        let mut transaction_receipt_2 = TransactionReceipt::default();
        transaction_receipt_2.transaction_hash = transaction_hash_2;
        transaction_receipt_2.status = Some(U64::from(1)); //success
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 10,
            timestamp: from_time_t(199_780_000),
            hash: transaction_hash_2,
            attempt: 15,
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

        let transaction_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(
            *transaction_confirmed_params,
            vec![vec![fingerprint_1, fingerprint_2]]
        );
        assert_eq!(subject.scan_started_at(), None);
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!(
                "INFO: {}: Transactions {:?}, {:?} completed their confirmation process succeeding",
                test_name, transaction_hash_1, transaction_hash_2
            ),
            &format!("INFO: {test_name}: The PendingPayables scan ended in \\d+ms."),
        ]);
    }

    #[test]
    fn pending_payable_scanner_handles_empty_report_transaction_receipts_message() {
        init_test_logging();
        let test_name =
            "pending_payable_scanner_handles_report_transaction_receipts_message_with_empty_vector";
        let mut subject = PendingPayableScannerBuilder::new().build();
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
        tlh.exists_log_containing(&format!(
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
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .earning_wallet(earning_wallet.clone())
            .build();

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
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .earning_wallet(earning_wallet)
            .build();
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
        let earning_wallet = make_wallet("earning");
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .payment_thresholds(payment_thresholds)
            .earning_wallet(earning_wallet.clone())
            .build();
        let logger = Logger::new("DELINQUENCY_TEST");
        let now = SystemTime::now();

        let result = receivable_scanner.begin_scan(now, None, &logger);

        assert_eq!(
            result,
            Ok(RetrieveTransactions {
                recipient: earning_wallet,
                response_skeleton_opt: None
            })
        );
        let new_delinquencies_parameters = new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(new_delinquencies_parameters.len(), 1);
        let (timestamp_actual, payment_thresholds_actual) = new_delinquencies_parameters[0];
        assert_eq!(timestamp_actual, now);
        assert_eq!(payment_thresholds_actual, payment_thresholds);
        let paid_delinquencies_parameters = paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(paid_delinquencies_parameters.len(), 1);
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
            \\(balance: 1,234 gwei, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743233343564 \
            \\(balance: 2,345 gwei, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574333435366e \
            \\(balance: 3,456 gwei, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574343536376e \
            \\(balance: 4,567 gwei, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
    }

    #[test]
    fn receivable_scanner_aborts_scan_if_no_payments_were_supplied() {
        init_test_logging();
        let test_name = "receivable_scanner_aborts_scan_if_no_payments_were_supplied";
        let mut subject = ReceivableScannerBuilder::new().build();
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
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_receivable_wei += 2_222_123_123;
        subject.financial_statistics.replace(financial_statistics);
        let receivables = vec![
            BlockchainTransaction {
                block_number: 4578910,
                from: make_wallet("wallet_1"),
                wei_amount: 45_780,
            },
            BlockchainTransaction {
                block_number: 4569898,
                from: make_wallet("wallet_2"),
                wei_amount: 3_333_345,
            },
        ];
        let msg = ReceivedPayments {
            timestamp: now,
            payments: receivables.clone(),
            response_skeleton_opt: None,
        };
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(msg, &Logger::new(test_name));

        let total_paid_receivable = subject
            .financial_statistics
            .borrow()
            .total_paid_receivable_wei;
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(subject.scan_started_at(), None);
        assert_eq!(total_paid_receivable, 2_222_123_123 + 45_780 + 3_333_345);
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
        TestLogHandler::new().exists_log_matching(
            "INFO: receivable_scanner_handles_received_payments_message: The Receivables scan ended in \\d+ms.",
        );
    }

    #[test]
    fn remove_timestamp_and_log_if_timestamp_is_correct() {
        init_test_logging();
        let test_name = "remove_timestamp_and_log_if_timestamp_is_correct";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        let now = SystemTime::now();
        let later_timestamp = now.checked_add(Duration::from_millis(3)).unwrap();
        subject.initiated_at_opt = Some(now);

        subject.remove_timestamp(ScanType::Payables, later_timestamp, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: The Payables scan ended in 3ms."
        ));
    }

    #[test]
    fn remove_timestamp_and_log_if_timestamp_is_not_found() {
        init_test_logging();
        let test_name = "remove_timestamp_and_log_if_timestamp_is_not_found";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        subject.initiated_at_opt = None;

        subject.remove_timestamp(ScanType::Receivables, SystemTime::now(), &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Called scan_finished() for Receivables scanner but timestamp was not found"
        ));
    }

    #[test]
    fn remove_timestamp_refers_to_the_smallest_possible_duration_of_scan_as_1_ms() {
        init_test_logging();
        let test_name = "remove_timestamp_refers_to_the_smallest_possible_duration_of_scan_as_1_ms";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        let now = SystemTime::now();
        subject.initiated_at_opt = Some(now);

        subject.remove_timestamp(ScanType::Payables, now, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: The Payables scan ended in 1ms."
        ));
    }

    fn assert_on_scanner<S: Message, T: Message>(
        scanner: &mut dyn Scanner<S, T>,
        scanner_name: &str,
        test_name: &str,
        logger: &Logger,
        log_handler: &TestLogHandler,
        digits_capturing_regex: &Regex,
    ) {
        fn flip_0_to_1_or_leave_it(num: u128) -> u128 {
            match num {
                0 => 1,
                x => x,
            }
        }
        let before = SystemTime::now();
        scanner.mark_as_started(before);

        scanner.mark_as_ended(&logger);

        let after = SystemTime::now();
        let idx = log_handler.exists_log_containing(&format!(
            "INFO: {}: The {} scan ended in ",
            test_name, scanner_name
        ));
        let particular_log_msg = log_handler.get_log_at(idx);
        let captures = digits_capturing_regex
            .captures(&particular_log_msg)
            .unwrap();
        let millis_str = captures.get(1).unwrap().as_str();
        let millis = millis_str.parse::<u128>().unwrap();
        let actual_millis = flip_0_to_1_or_leave_it(millis);
        let max_time_elapsed_uncorrected = after.duration_since(before).unwrap().as_millis();
        let max_time_elapsed = flip_0_to_1_or_leave_it(max_time_elapsed_uncorrected);
        assert!(
            actual_millis <= max_time_elapsed,
            "We expected the time elapsed ({}) to be equal or shorter to {}",
            actual_millis,
            max_time_elapsed
        )
    }

    #[test]
    fn mark_as_ended_uses_the_right_time_reference_for_each_scanner() {
        init_test_logging();
        let test_name = "mark_as_ended_uses_the_right_time_reference_for_each_scanner";
        let logger = Logger::new(test_name);
        let log_handler = TestLogHandler::new();
        let digits_capturing_regex = Regex::new(r#"scan ended in (\d*)ms"#).unwrap();

        assert_on_scanner::<ReportAccountsPayable, SentPayables>(
            &mut PayableScannerBuilder::new().build(),
            "Payables",
            test_name,
            &logger,
            &log_handler,
            &digits_capturing_regex,
        );
        assert_on_scanner::<RequestTransactionReceipts, ReportTransactionReceipts>(
            &mut PendingPayableScannerBuilder::new().build(),
            "PendingPayables",
            test_name,
            &logger,
            &log_handler,
            &digits_capturing_regex,
        );
        assert_on_scanner::<RetrieveTransactions, ReceivedPayments>(
            &mut ReceivableScannerBuilder::new().build(),
            "Receivables",
            test_name,
            &logger,
            &log_handler,
            &digits_capturing_regex,
        );
    }
}
