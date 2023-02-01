// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoError, PendingPayable};
use crate::accountant::pending_payable_dao::PendingPayableDao;
use crate::accountant::receivable_dao::ReceivableDao;
use crate::accountant::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
    LocallyCausedError, RemotelyCausedErrors,
};
use crate::accountant::scanners_utils::payable_scanner_utils::{debugging_summary_after_error_separation, investigate_debt_extremes, payables_debug_summary, separate_errors, PayableThresholdsGauge, PayableThresholdsGaugeReal, PayableTransactingErrorEnum, VecOfRowidOptAndHash, RefWalletAndRowidOptCoupledWithHash};
use crate::accountant::scanners_utils::pending_payable_scanner_utils::{
    elapsed_in_ms, handle_none_status, handle_status_with_failure, handle_status_with_success,
    PendingPayableScanSummary,
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
use crate::blockchain::blockchain_interface::BlockchainError;
use crate::blockchain::blockchain_interface::BlockchainError::PayableTransactionFailed;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
use crate::sub_lib::utils::NotifyLaterHandle;
use crate::sub_lib::wallet::Wallet;
use actix::{Message, System};
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::logger::TIME_FORMATTING_STRING;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::MessageTarget::ClientId;
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

    fn remove_timestamp(&mut self, scan_type: ScanType, logger: &Logger) {
        match self.initiated_at_opt.take() {
            Some(timestamp) => {
                let elapsed_time = SystemTime::now()
                    .duration_since(timestamp)
                    .expect("Unable to calculate elapsed time for the scan.")
                    .as_millis();
                info!(
                    logger,
                    "The {:?} scan ended in {}ms.", scan_type, elapsed_time
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
                .remove_timestamp(ScanType::$scan_type_variant, logger);
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
            self.sniff_out_alarming_payables_and_log_them(all_non_pending_payables, logger);

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
        let (sent_payables, errors) = separate_errors(&message, logger);
        // debug!(
        //     logger,
        //     "We gathered these errors at sending transactions for payable: {:?}, out of the \
        //         total of {} attempts",
        //     errors,
        //     sent_payables.len() + errors.len()
        // );
        //TODO prove that replaced correctly
        debug!(
            self.logger,
            "{}",
            debugging_summary_after_error_separation(&ok, &err_opt)
        );

        if !sent_payables.is_empty() {
            self.mark_pending_payable(sent_payables);
        }
        self.handle_errors(errors, logger);

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

    fn sniff_out_alarming_payables_and_log_them(
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

    fn separate_id_triples_by_existent_and_nonexistent_fingerprints(
        &self,
        sent_payments: &[&PendingPayable],
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

    fn mark_pending_payable_mine(&self, sent_payments: &[&PendingPayable], logger: &Logger) {
        fn missing_fingerprints_msg(nonexistent: &[RefWalletAndRowidOptCoupledWithHash]) -> String {
            format!(
                "Payable fingerprints for {} not found but should exist by now; system unreliable",
                join_collection_by_commas(nonexistent, |((wallet, _), hash)| format!(
                    "(tx: {:?}, to wallet: {})",
                    hash, wallet
                ))
            )
        }
        fn properly_adjusted_input_data(
            existent: &[RefWalletAndRowidOptCoupledWithHash],
        ) -> Vec<(&Wallet, u64)> {
            existent
                .iter()
                .map(|((wallet, ever_some_rowid), _)| (*wallet, ever_some_rowid.expectv("rowid")))
                .collect()
        }
        fn fatal_database_mark_pp_error(
            sent_payments: &[&PendingPayable],
            nonexistent: &[RefWalletAndRowidOptCoupledWithHash],
            error: PayableDaoError,
            logger: &Logger,
        ) {
            if !nonexistent.is_empty() {
                error!(logger, "{}", missing_fingerprints_msg(&nonexistent))
            }
            panic!(
                "Was unable to create a mark in payables due to {:?} for new pending payables {}",
                error,
                join_collection_by_commas(sent_payments, |pending_payable| pending_payable
                    .recipient_wallet
                    .to_string())
            )
        }

        let (existent, nonexistent) =
            self.separate_id_triples_by_existent_and_nonexistent_fingerprints(sent_payments);
        let mark_payables_input_data = properly_adjusted_input_data(&existent);
        if !mark_payables_input_data.is_empty() {
            if let Err(e) = self
                .payable_dao
                .as_ref()
                .mark_pending_payables_rowids(&mark_payables_input_data)
            {
                fatal_database_mark_pp_error(sent_payments, &nonexistent, e)
            }
            debug!(
                logger,
                "Payables {} have been marked as pending in the payable table",
                join_collection_by_commas(sent_payments, |pending_payable_dao| format!(
                    "{:?}",
                    pending_payable_dao.hash
                ))
            )
        }
        if !nonexistent.is_empty() {
            panic!("{}", missing_fingerprints_msg(&nonexistent))
        }
    }

    fn handle_errors(&self, errors: Option<PayableTransactingErrorEnum>, logger: &Logger) {
        //TODO check for tests carefully
        if let Some(err) = err_opt {
            match err {
                RemotelyCausedErrors(hashes)
                | LocallyCausedError(PayableTransactionFailed {
                    signed_and_saved_txs_opt: Some(hashes),
                    ..
                }) => self.discard_failed_transactions_with_possible_fingerprints(hashes, logger),
                e => debug!(
                    logger,
                    "Dismissing a local error from place before signed transactions: {:?}", e
                ),
            }
        }
    }

    fn discard_failed_transactions_with_possible_fingerprints(
        &self,
        hashes: Vec<H256>,
        logger: &Logger,
    ) {
        fn serialized_hashes(hashes: &[H256]) -> String {
            hashes.iter().map(|hash| format!("{:?}", hash)).join(", ")
        }
        fn log_failed_payments_lacking_fingerprints(
            ids_of_payments: VecOfRowidOptAndHash,
            logger: &Logger,
        ) {
            let hashes_of_nonexistent = ids_of_payments
                .into_iter()
                .map(|(_, hash)| hash)
                .collect::<Vec<H256>>();
            warning!(
                logger,
                "Throwing out failed transactions {} with missing records",
                serialized_hashes(&hashes_of_nonexistent),
            )
        }
        fn log_failed_payments_having_fingerprints_and_return_ids(
            ids_of_payments: VecOfRowidOptAndHash,
            logger: &Logger,
        ) -> Vec<u64> {
            let (ids, hashes): (Vec<u64>, Vec<H256>) = ids_of_payments
                .into_iter()
                .map(|(ever_some_rowid, hash)| (ever_some_rowid.expectv("validated rowid"), hash))
                .unzip();
            warning!(
                logger,
                "Deleting existing fingerprints for failed transactions {}",
                serialized_hashes(&hashes)
            );
            ids
        }
        let (existent, nonexistent): (VecOfRowidOptAndHash, VecOfRowidOptAndHash) = self
            .pending_payable_dao
            .fingerprints_rowids(&hashes)
            .into_iter()
            .partition(|(rowid_opt, _hash)| rowid_opt.is_some());

        if !nonexistent.is_empty() {
            log_failed_payments_lacking_fingerprints(nonexistent, logger)
        }

        if !existent.is_empty() {
            let ids = log_failed_payments_having_fingerprints_and_return_ids(existent, logger);
            if let Err(e) = self.pending_payable_dao.delete_fingerprints(&ids) {
                panic!("Database corrupt: payable fingerprint deletion for transactions {} has stayed undone due to {:?}", serialized_hashes(&hashes), e)
            }
        }
    }
    // for blockchain_error in errors {
    //     if let Some(hash) = blockchain_error.carries_transaction_hash() {
    //         if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(hash) {
    //             debug!(
    //                 logger,
    //                 "Deleting an existing fingerprint for a failed transaction {:?}", hash
    //             );
    //             if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
    //                 panic!(
    //                     "Database unmaintainable; payable fingerprint deletion for \
    //                         transaction {:?} has stayed undone due to {:?}",
    //                     hash, e
    //                 );
    //             };
    //         };
    //
    //         warning!(
    //             logger,
    //             "Failed transaction with a hash '{:?}' but without the record - thrown out",
    //             hash
    //         )
    //     } else {
    //         debug!(
    //             logger,
    //             "Forgetting a transaction attempt that even did not reach the signing stage"
    //         )
    //     };
    // }

    // //TODO probably about to disappear
    // fn handle_sent_payables(&self, sent_payables: Vec<Payable>, logger: &Logger) {
    //     // for payable in sent_payables {
    //     //     if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(payable.tx_hash) {
    //     //         if let Err(e) = self
    //     //             .payable_dao
    //     //             .as_ref()
    //     //             .mark_pending_payable_rowids(&payable.to, rowid)
    //     //         {
    //     //             panic!(
    //     //                 "Was unable to create a mark in payables for a new pending payable \
    //     //                     '{}' due to '{:?}'",
    //     //                 payable.tx_hash, e
    //     //             );
    //     //         }
    //     //     } else {
    //     //         panic!(
    //     //             "Payable fingerprint for {} doesn't exist but should by now; system unreliable",
    //     //             payable.tx_hash
    //     //         );
    //     //     };
    //     //
    //     //     debug!(
    //     //         logger,
    //     //         "Payable '{}' has been marked as pending in the payable table", payable.tx_hash
    //     //     )
    //     // }
    // }
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
        if !message.fingerprints_with_receipts.is_empty() {
            debug!(
                logger,
                "Processing receipts for {} transactions",
                message.fingerprints_with_receipts.len()
            );
            //TODO check this name corresponds to test names
            let statuses = self.handle_pending_transactions_with_receipts(&message, logger);
            self.process_pending_transactions_by_status(statuses, logger);
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

    fn handle_pending_transactions_with_receipts(
        &self,
        msg: &ReportTransactionReceipts,
        logger: &Logger,
    ) -> PendingPayableScanSummary {
        fn handle_none_receipt(
            scan_summary: &mut PendingPayableScanSummary,
            payable: &PendingPayableFingerprint,
            logger: &Logger,
        ) {
            debug!(logger,
                "DEBUG: Accountant: Interpreting a receipt for transaction {:?} but none was given; attempt {}, {}ms since sending",
                payable.hash, payable.attempt,elapsed_in_ms(payable.timestamp)
            );

            scan_summary.still_pending.push(
                //TODO do we want a constructor?
                PendingPayableId {
                    hash: payable.hash,
                    rowid: payable.rowid,
                },
            )
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
    ) -> PendingTransactionStatus {
        match receipt.status {
            None => handle_none_status(scan_summary,fingerprint, self.when_pending_too_long_sec, logger),
            Some(status_code) => match status_code.as_u64() {
                0 => handle_status_with_failure(scan_summary,fingerprint, logger),
                1 => handle_status_with_success(scan_summary,fingerprint, logger),
                other => unreachable!(
                    "tx receipt for pending '{}': status code other than 0 or 1 shouldn't be possible, but was {}",
                    fingerprint.hash, other
                ),
            },
        }
    }

    fn process_pending_transactions_by_status(
        &mut self,
        scan_summary: PendingPayableScanSummary,
        logger: &Logger,
    ) {
        self.confirm_transactions(scan_summary.confirmed, logger);
        self.cancel_transactions(scan_summary.failures, logger);
        self.update_fingerprints(scan_summary.still_pending, logger)
    }

    //TODO prove that tested
    fn update_fingerprints(&self, ids: Vec<PendingPayableId>, logger: &Logger) {
        if !ids.is_empty() {
            let rowids = PendingPayableId::rowids(&ids);
            match self.pending_payable_dao.update_fingerprints(&rowids) {
                Ok(_) => trace!(
                    logger,
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

    // fn update_payable_fingerprints(&self, pending_payable_id: PendingPayableId, logger: &Logger) {
    //     if let Err(e) = self
    //         .pending_payable_dao
    //         .update_fingerprints(pending_payable_id.rowid)
    //     {
    //         panic!(
    //             "Failure on updating payable fingerprint '{:?}' due to {:?}",
    //             pending_payable_id.hash, e
    //         );
    //     } else {
    //         trace!(
    //             logger,
    //             "Updated record for rowid: {} ",
    //             pending_payable_id.rowid
    //         );
    //     }
    // }

    fn cancel_failed_transactions(&self, ids: Vec<PendingPayableId>, logger: &Logger) {
        if !ids.is_empty() {
            //TODO we should have a function clearing these failures out from the pending_payable table after a certain long time period passes
            let rowids = PendingPayableId::rowids(&ids);
            match self
                    .pending_payable_dao
                    .mark_failures(&rowids)
                {
                    Ok(_) => warning!(
                logger, "Broken transactions {} marked as an error. You should take over the care of those \
                 to make sure your debts are going to be settled properly. At the moment, there is no automated process fixing that without your assistance",
                PendingPayableId::hashes_as_single_string(&ids)),
                    Err(e) => panic!("Unsuccessful attempt for transactions {} to mark fatal error \
                     at payable fingerprint due to {:?}; database unreliable", PendingPayableId::hashes_as_single_string(&ids), e),
                }
            //TODO I think it should also remove the mark at the payable table
        }
    }

    // fn cancel_tailed_transaction(&self, transaction_id: PendingPayableId, logger: &Logger) {
    //     if let Err(e) = self.pending_payable_dao.mark_failure(transaction_id.rowid) {
    //         panic!(
    //             "Unsuccessful attempt for transaction {} to mark fatal error at payable \
    //                 fingerprint due to {:?}; database unreliable",
    //             transaction_id.hash, e
    //         )
    //     } else {
    //         warning!(
    //                     logger,
    //                     "Broken transaction {:?} left with an error mark; you should take over the care \
    //                     of this transaction to make sure your debts will be paid because there is no \
    //                     automated process that can fix this without you", transaction_id.hash
    //                 );
    //     }
    // }

    // fn confirm_transactions(&mut self, fingerprints: Vec<PendingPayableFingerprint>) {
    //     fn serialized_hashes(fingerprints: &[PendingPayableFingerprint]) -> String {
    //         fingerprints
    //             .iter()
    //             .map(|fgp| format!("{:?}", fgp.hash))
    //             .join(", ")
    //     }
    //
    //     if !fingerprints.is_empty() {
    //         if let Err(e) = self.payable_dao.transactions_confirmed(&fingerprints) {
    //             panic!(
    //                 "Was unable to uncheck pending payables {} during their confirmation due to {:?}",
    //                 serialized_hashes(&fingerprints),
    //                 e
    //             )
    //         } else {
    //             self.add_to_the_total_of_paid_payable(&fingerprints, serialized_hashes);
    //             let rowids = fingerprints
    //                 .iter()
    //                 .map(|fingerprint| fingerprint.rowid)
    //                 .collect::<Vec<u64>>();
    //             if let Err(e) = self.pending_payable_dao.delete_fingerprints(&rowids) {
    //                 panic!("Was unable to delete payable fingerprints {} for successful transactions due to {:?}",
    //                     serialized_hashes(&fingerprints), e)
    //             } else {
    //                 info!(
    //                     self.logger,
    //                     "Transactions {} went through the whole confirmation process succeeding",
    //                     serialized_hashes(&fingerprints)
    //                 )
    //             }
    //         }
    //     }
    // }

    // fn add_to_the_total_of_paid_payable(
    //     &mut self,
    //     fingerprints: &[PendingPayableFingerprint],
    //     serialized_hashes: fn(&[PendingPayableFingerprint]) -> String,
    // ) {
    //     fingerprints.iter().for_each(|fingerprint| {
    //         self.financial_statistics.total_paid_payable_wei += fingerprint.amount
    //     });
    //     debug!(
    //         self.logger,
    //         "Confirmation of transactions {}; record for total paid payable was modified",
    //         serialized_hashes(fingerprints)
    //     );
    // }

    fn confirm_transaction(
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
                "Was unable to uncheck pending payable '{:?}' after confirmation due to '{:?}'",
                hash, e
            );
        } else {
            self.financial_statistics
                .borrow_mut()
                .total_paid_payable_wei += amount;
            debug!(
                logger,
                "Confirmation of transaction {}; record for payable was modified", hash
            );
            if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                panic!(
                    "Was unable to delete payable fingerprint for successful transaction '{:?}' \
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

pub fn join_collection_by_commas<T, F>(collection: &[T], stringify: F) -> String
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

    use crate::accountant::dao_utils::{from_time_t, to_time_t};
    use crate::accountant::payable_dao::{PayableAccount, PayableDaoError};
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::scanners_utils::payable_scanner_utils::PayableThresholdsGaugeReal;
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainTransaction};
    use crate::sub_lib::accountant::{
        DaoFactories, FinancialStatistics, PaymentThresholds, DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::make_wallet;
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::logger::Logger;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H256, U256};
    use crate::blockchain::test_utils::make_tx_hash;

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

    // #[test]
    // fn handle_sent_payable_process_two_correct_and_one_incorrect_rpc_calls() {
    //     //the two failures differ in the logged messages
    //     init_test_logging();
    //     let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
    //     let mark_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
    //     let delete_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
    //     let payable_hash_1 = make_tx_hash(111);
    //     let payable_rowid_1 = 125;
    //     let wallet_1 = make_wallet("tralala");
    //     let pending_payable_1 = PendingPayable::new(wallet_1.clone(), payable_hash_1);
    //     let error_payable_hash_2 = make_tx_hash(222);
    //     let error_payable_rowid_2 = 126;
    //     let error_wallet_2 = make_wallet("hohoho");
    //     let error_payable_2 = RpcPayableFailure {
    //         rpc_error: Error::InvalidResponse(
    //             "Learn how to write before you send your garbage!".to_string(),
    //         ),
    //         recipient_wallet: error_wallet_2,
    //         hash: error_payable_hash_2,
    //     };
    //     let payable_hash_3 = make_tx_hash(333);
    //     let payable_rowid_3 = 127;
    //     let wallet_3 = make_wallet("booga");
    //     let pending_payable_3 = PendingPayable::new(wallet_3.clone(), payable_hash_3);
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
    //         .fingerprints_rowids_result(vec![
    //             (Some(payable_rowid_1), payable_hash_1),
    //             (Some(payable_rowid_3), payable_hash_3),
    //         ])
    //         .fingerprints_rowids_result(vec![(Some(error_payable_rowid_2), error_payable_hash_2)])
    //         .delete_fingerprint_params(&delete_fingerprint_params_arc)
    //         .delete_fingerprints_result(Ok(()));
    //     let subject = AccountantBuilder::default()
    //         .payable_dao(
    //             PayableDaoMock::new()
    //                 .mark_pending_payables_rowids_params(&mark_pending_payables_params_arc)
    //                 .mark_pending_payables_rowids_result(Ok(()))
    //                 .mark_pending_payables_rowids_result(Ok(())),
    //         )
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //     let sent_payable = SentPayables {
    //         payment_outcome: Ok(vec![
    //             Correct(pending_payable_1),
    //             Failure(error_payable_2),
    //             Correct(pending_payable_3),
    //         ]),
    //         response_skeleton_opt: None,
    //     };
    //
    //     subject.handle_sent_payables(sent_payable);
    //
    //     let fingerprints_rowids_params = fingerprints_rowids_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *fingerprints_rowids_params,
    //         vec![
    //             vec![payable_hash_1, payable_hash_3],
    //             vec![error_payable_hash_2]
    //         ]
    //     );
    //     let mark_pending_payables_params = mark_pending_payables_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *mark_pending_payables_params,
    //         vec![vec![
    //             (wallet_1, payable_rowid_1),
    //             (wallet_3, payable_rowid_3)
    //         ]]
    //     );
    //     let delete_fingerprint_params = delete_fingerprint_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *delete_fingerprint_params,
    //         vec![vec![error_payable_rowid_2]]
    //     );
    //     let log_handler = TestLogHandler::new();
    //     log_handler.exists_log_containing("WARN: Accountant: Remote transaction failure: \
    //      Got invalid response: Learn how to write before you send your garbage!, for payment to 0x0000000000000000000000000000686f686f686f \
    //       and transaction hash 0x00000000000000000000000000000000000000000000000000000000000000de. \
    //        Please check your blockchain service URL configuration");
    //     log_handler.exists_log_containing("DEBUG: Accountant: Payables 0x000000000000000000000000000000000000000000000000000000000000006f, \
    //      0x000000000000000000000000000000000000000000000000000000000000014d have been marked as pending in the payable table");
    //     log_handler.exists_log_containing("WARN: Accountant: Deleting existing fingerprints for failed transactions 0x00000000000000000000000000000000000000000000000000000000000000de");
    // }

    #[test]
    fn payable_scanner_handles_sent_payable_message() {
        //one payment out of three was successful
        //those two failures differ in their log messages
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
        let sent_payable = SentPayables {
            payment_outcome: (),
            payable: vec![payable_1, Ok(payable_2.clone()), payable_3],
            response_skeleton_opt: None,
        };
        let payable_dao = PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_params(&fingerprint_rowid_params_arc)
            .fingerprint_rowid_result(Some(payable_2_rowid));
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        subject.mark_as_started(SystemTime::now());

        let message_opt = subject.finish_scan(sent_payable, &Logger::new(test_name));

        let is_scan_running = subject.scan_started_at().is_some();
        let fingerprint_rowid_params = fingerprint_rowid_params_arc.lock().unwrap();
        assert_eq!(message_opt, None);
        assert_eq!(is_scan_running, false);
        //we know the other two errors are associated with an initiated transaction having its existing fingerprint
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
        log_handler.exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }

    // fn common_body_for_failing_to_mark_rowids_tests(
    //     test_name: &str,
    //     pending_payable_dao: PendingPayableDaoMock,
    //     hash_1: H256,
    //     hash_2: H256,
    // ) {
    //     let payable_1 = PendingPayable::new(make_wallet("blah111"), hash_1);
    //     let payable_2 = PendingPayable::new(make_wallet("blah222"), hash_2);
    //     let payable_dao = PayableDaoMock::new().mark_pending_payables_rowids_result(Err(
    //         PayableDaoError::SignConversion(9999999999999),
    //     ));
    //     let mut subject = AccountantBuilder::default()
    //         .payable_dao(payable_dao)
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //     subject.logger = Logger::new(test_name);
    //
    //     let caught_panic = catch_unwind(AssertUnwindSafe(|| {
    //         subject.mark_pending_payable(vec![&payable_1, &payable_2])
    //     }))
    //     .unwrap_err();
    //
    //     let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
    //     assert_eq!(panic_msg, "Was unable to create a mark in payables due to SignConversion(9999999999999) for new pending payables \
    //      0x00000000000000000000000000626c6168313131, 0x00000000000000000000000000626c6168323232");
    // }
    //
    // #[test]
    // fn handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_nonexistent_fingerprints_to_report_about(
    // ) {
    //     init_test_logging();
    //     let hash_1 = make_tx_hash(248);
    //     let hash_2 = make_tx_hash(139);
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .fingerprints_rowids_result(vec![(Some(7879), hash_1), (Some(7881), hash_2)]);
    //     common_body_for_failing_to_mark_rowids_tests("handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_wrongs_from_fetching_rowids_to_report_about",pending_payable_dao, hash_1, hash_2);
    //     TestLogHandler::new().exists_no_log_matching("ERROR: handle_sent_payable_fails_on_marking_rowid_and_panics_clear_while_no_wrongs_from_fetching_rowids_to_report_about: Payable fingerprints for (\
    //      .*) not found but should exist by now; system unreliable");
    // }
    //
    // #[test]
    // fn handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_nonexistent_fingerprints(
    // ) {
    //     init_test_logging();
    //     let hash_1 = make_tx_hash(248);
    //     let hash_2 = make_tx_hash(139);
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .fingerprints_rowids_result(vec![(None, hash_1), (Some(7881), hash_2)]);
    //     common_body_for_failing_to_mark_rowids_tests("handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_wrongs_from_fetching_rowids",pending_payable_dao, hash_1, hash_2);
    //     TestLogHandler::new().exists_log_containing("ERROR: handle_sent_payable_fails_to_mark_and_panics_clear_while_having_run_into_wrongs_from_fetching_rowids: Payable fingerprints for \
    //      (tx: 0x00000000000000000000000000000000000000000000000000000000000000f8, to wallet: 0x00000000000000000000000000626c6168313131) not found but should exist by now; system unreliable");
    // }

    // #[test]
    // fn handle_sent_payable_handles_error_born_too_early_to_see_transaction_hash() {
    //     init_test_logging();
    //     let sent_payable = SentPayables {
    //         payment_outcome: Err(BlockchainError::PayableTransactionFailed {
    //             msg: "Some error".to_string(),
    //             signed_and_saved_txs_opt: None,
    //         }),
    //         response_skeleton_opt: None,
    //     };
    //     let mut subject = AccountantBuilder::default().build();
    //     subject.logger =
    //         Logger::new("handle_sent_payable_handles_error_born_too_early_to_see_transaction_hash");
    //
    //     subject.handle_sent_payables(sent_payable);
    //
    //     TestLogHandler::new().exists_log_containing(
    //         "DEBUG: handle_sent_payable_handles_error_born_too_early_to_see_transaction_hash: Dismissing a local error from place before signed transactions: ",
    //     );
    // }

    // #[test]
    // #[should_panic(
    // expected = "Payable fingerprints for (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, to wallet: 0x000000000000000000000000000000626f6f6761), \
    //      (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, to wallet: 0x00000000000000000000000000000061676f6f62) not found but should exist by now; system unreliable"
    // )]
    // fn mark_pending_payable_receives_proper_payment_but_fingerprint_not_found_so_it_panics() {
    //     init_test_logging();
    //     let hash_1 = make_tx_hash(789);
    //     let payment_1 = PendingPayable::new(make_wallet("booga"), hash_1);
    //     let hash_2 = make_tx_hash(789);
    //     let payment_2 = PendingPayable::new(make_wallet("agoob"), hash_2);
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .fingerprints_rowids_result(vec![(None, hash_1), (None, hash_2)]);
    //     let subject = AccountantBuilder::default()
    //         .payable_dao(PayableDaoMock::new().mark_pending_payables_rowids_result(Ok(())))
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //
    //     let _ = subject.mark_pending_payable(vec![&payment_1, &payment_2]);
    // }

    #[test]
    #[should_panic(
        expected = "Payable fingerprint for 0x0000…0315 doesn't exist but should by now; system unreliable"
    )]
    fn payable_scanner_panics_when_fingerprint_is_not_found() {
        let now = SystemTime::now();
        let payment_hash = H256::from_uint(&U256::from(789));
        let payable = Payable::new(make_wallet("booga"), 6789, payment_hash, now);
        let pending_payable_dao = PendingPayableDaoMock::default().fingerprint_rowid_result(None);
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayables {
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
        let sent_payable = SentPayables {
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
        let mut subject = PayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();

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
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let sent_payable = SentPayables {
            timestamp: SystemTime::now(),
            payable: vec![Ok(payable)],
            response_skeleton_opt: None,
        };

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
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

        let result =
            subject.sniff_out_alarming_payables_and_log_them(unqualified_payable_account, &logger);

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

        let result = subject
            .sniff_out_alarming_payables_and_log_them(vec![qualified_payable.clone()], &logger);

        assert_eq!(result, vec![qualified_payable]);
        TestLogHandler::new().exists_log_matching(&format!(
            "DEBUG: {}: Paying qualified debts:\n999,999,999,000,000,\
            000 wei owed for \\d+ sec exceeds threshold: 500,000,000,000,000,000 wei; creditor: \
             0x0000000000000000000000000077616c6c657430",
            test_name
        ));
    }

    #[test]
    fn accounts_qualified_to_payment_returns_an_empty_vector_if_all_unqualified() {
        init_test_logging();
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
        let test_name = "qualified_payables_and_summary_returns_an_empty_vector_if_all_unqualified";
        let logger = Logger::new(test_name);

        let result =
            subject.sniff_out_alarming_payables_and_log_them(unqualified_payable_account, &logger);

        assert_eq!(result, vec![]);
        TestLogHandler::new()
            .exists_no_log_containing(&format!("DEBUG: {}: Paying qualified debts", test_name));
    }

    #[test]
    fn pending_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "pending_payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let fingerprints = vec![PendingPayableFingerprint {
            rowid: 1234,
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt: 1,
            amount: 1_000_000,
            process_error: None,
        }];
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
                    rowid_opt: Some(1234),
                    timestamp: SystemTime::now(),
                    hash: Default::default(),
                    attempt_opt: Some(1),
                    amount: 1_000_000,
                    process_error: None,
                },
            ]);
        let mut subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let _ = subject.begin_scan(now, None, &Logger::new("test"));

        let result = subject.begin_scan(SystemTime::now(), None, &Logger::new("test"));

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
        let hash = H256::from_uint(&U256::from(567));
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

        let scan_summary = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new(test_name),
        );

        assert_eq!(
            scan_summary,
            PendingPayableScanSummary {
                still_pending: vec![],
                failures: vec![PendingPayableId { hash, rowid }],
                confirmed: vec![]
            }
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
            "INFO: {}: Pending transaction '{:?}' couldn't be confirmed at attempt 1 at {}ms after its sending",
            test_name, hash, duration_in_ms
        ));
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b': status code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = H256::from_uint(&U256::from(123));
        let subject = PendingPayableScannerBuilder::new().build();

        let _ =
            subject.interpret_transaction_receipt(&tx_receipt, &fingerprint, &Logger::new("test"));
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

        let result =
            subject.handle_pending_transactions_with_receipts(&msg, &Logger::new(test_name));

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

    // #[test]
    // fn update_fingerprints_happy_path() {
    //     let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
    //     let hash_1 = make_tx_hash(444888);
    //     let rowid_1 = 3456;
    //     let hash_2 = make_tx_hash(444888);
    //     let rowid_2 = 3456;
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .update_fingerprints_params(&update_after_cycle_params_arc)
    //         .update_fingerprints_results(Ok(()));
    //     let subject = AccountantBuilder::default()
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //     let transaction_id_1 = PendingPayableId {
    //         hash: hash_1,
    //         rowid: rowid_1,
    //     };
    //     let transaction_id_2 = PendingPayableId {
    //         hash: hash_2,
    //         rowid: rowid_2,
    //     };
    //
    //     let _ = subject.update_fingerprints(vec![transaction_id_1, transaction_id_2]);
    //
    //     let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
    //     assert_eq!(*update_after_cycle_params, vec![vec![rowid_1, rowid_2]])
    // }

    #[test]
    fn update_payable_fingerprint_happy_path() {
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .update_fingerprint_params(&update_after_cycle_params_arc)
            .update_fingerprint_results(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id = PendingPayableId { hash, rowid };

        subject.update_payable_fingerprints(transaction_id, &Logger::new("test"));

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![rowid])
    }

    #[test]
    #[should_panic(expected = "Failure on updating payable fingerprints \
                '0x000000000000000000000000000000000000000000000000000000000006c9d8' \
                due to UpdateFailed(\"yeah, bad\")")]
    fn update_fingerprints_sad_path() {
        let hash = make_tx_hash(444888);
        let rowid = 3456;
        let pending_payable_dao =
            PendingPayableDaoMock::default().update_fingerprints_results(Err(
                PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
            ));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_id = PendingPayableId { hash, rowid };

        let _ = subject.update_fingerprints(vec![transaction_id]);
    }

    //TODO probably obsolete test...
    // #[test]
    // fn update_fingerprints_does_nothing_if_no_still_pending_transactions_remain() {
    //     let subject = AccountantBuilder::default().build();
    //
    //     subject.update_fingerprints(vec![])
    //
    //     //mocked pending payable DAO didn't panic which means we skipped the actual process
    // }

    // #[test]
    // fn cancel_transactions_works() {
    //     init_test_logging();
    //     let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .mark_failures_params(&mark_failure_params_arc)
    //         .mark_failures_result(Ok(()));
    //     let subject = AccountantBuilder::default()
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //     let id_1 = PendingPayableId {
    //         hash: H256::from("sometransactionhash".keccak256()),
    //         rowid: 2,
    //     };
    //     let id_2 = PendingPayableId {
    //         hash: H256::from("anothertransactionhash".keccak256()),
    //         rowid: 3,
    //     };
    //
    //     let _ = subject.cancel_transactions(vec![id_1, id_2]);
    //
    //     let mark_failure_params = mark_failure_params_arc.lock().unwrap();
    //     assert_eq!(*mark_failure_params, vec![vec![2, 3]]);
    //     TestLogHandler::new().exists_log_containing(
    //         "WARN: Accountant: Broken transactions 0x051aae12b9595ccaa43c2eabfd5b86347c37fa0988167165b0b17b23fcaa8c19, \
    //          0x06c979a34cca4fb22247b14a7b60bef387a550c255a8d708f81f19dd4c4a1c51 marked as an error. You should take over \
    //          the care of those to make sure your debts are going to be settled properly. At the moment, there is no automated \
    //           process fixing that without your assistance",
    //     );
    // }

    #[test]
    fn cancel_tailed_transaction_works() {
        init_test_logging();
        let test_name = "order_cancel_pending_transaction_works";
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failure_params(&mark_failure_params_arc)
            .mark_failure_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let rowid = 2;
        let transaction_id = PendingPayableId {
            hash: tx_hash,
            rowid,
        };

        subject.cancel_tailed_transaction(transaction_id, &Logger::new(test_name));

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
    fn cancel_tailed_transaction_panics_when_it_fails_to_mark_failure() {
        let payable_dao = PayableDaoMock::default().transaction_canceled_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failure_result(Err(
            PendingPayableDaoError::UpdateFailed("no no no".to_string()),
        ));
        let subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());
        let transaction_id = PendingPayableId { hash, rowid };

        subject.cancel_tailed_transaction(transaction_id, &Logger::new("test"));
    }

    //TODO this is probably obsolete test
    // #[test]
    // fn cancel_transactions_does_nothing_if_no_tx_failures_detected() {
    //     let subject = AccountantBuilder::default().build();
    //
    //     subject.cancel_transactions(vec![])
    //
    //     //mocked pending payable DAO didn't panic which means we skipped the actual process
    // }
    //

    #[test]
    #[should_panic(
        expected = "Was unable to delete payable fingerprint for successful transaction '0x000000000\
        0000000000000000000000000000000000000000000000000000315' due to 'RecordDeletion(\"the database \
        is fooling around with us\")'"
    )]
    fn confirm_transaction_panics_while_deleting_pending_payable_fingerprint() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().delete_fingerprint_result(Err(
            PendingPayableDaoError::RecordDeletion(
                "the database is fooling around with us".to_string(),
            ),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut pending_payable_fingerprint = make_pending_payable_fingerprint();
        pending_payable_fingerprint.rowid_opt = Some(rowid);
        pending_payable_fingerprint.hash = hash;

        subject.confirm_transaction(pending_payable_fingerprint, &Logger::new("test"));
    }

    // #[test]
    // fn confirm_transactions_works() {
    //     init_test_logging();
    //     let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
    //     let delete_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
    //     let payable_dao = PayableDaoMock::default()
    //         .transactions_confirmed_params(&transaction_confirmed_params_arc)
    //         .transactions_confirmed_result(Ok(()));
    //     let pending_payable_dao = PendingPayableDaoMock::default()
    //         .delete_fingerprint_params(&delete_pending_payable_fingerprint_params_arc)
    //         .delete_fingerprints_result(Ok(()));
    //     let mut subject = AccountantBuilder::default()
    //         .payable_dao(payable_dao)
    //         .pending_payable_dao(pending_payable_dao)
    //         .build();
    //     let rowid_1 = 2;
    //     let pending_payable_fingerprint_1 = PendingPayableFingerprint {
    //         rowid: rowid_1,
    //         timestamp: from_time_t(199_000_000),
    //         hash: H256::from("some_hash".keccak256()),
    //         attempt: 1,
    //         amount: 4567,
    //         process_error: None,
    //     };
    //     let rowid_2 = 5;
    //     let pending_payable_fingerprint_2 = PendingPayableFingerprint {
    //         rowid: rowid_2,
    //         timestamp: from_time_t(200_000_000),
    //         hash: H256::from("different_hash".keccak256()),
    //         attempt: 1,
    //         amount: 5555,
    //         process_error: None,
    //     };
    //
    //     subject.confirm_transactions(vec![
    //         pending_payable_fingerprint_1.clone(),
    //         pending_payable_fingerprint_2.clone(),
    //     ]);
    //
    //     let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *transaction_confirmed_params,
    //         vec![vec![
    //             pending_payable_fingerprint_1,
    //             pending_payable_fingerprint_2
    //         ]]
    //     );
    //     let delete_pending_payable_fingerprint_params =
    //         delete_pending_payable_fingerprint_params_arc
    //             .lock()
    //             .unwrap();
    //     assert_eq!(
    //         *delete_pending_payable_fingerprint_params,
    //         vec![vec![rowid_1, rowid_2]]
    //     );
    //     let log_handler = TestLogHandler::new();
    //     log_handler.exists_log_containing("DEBUG: Accountant: Confirmation of transactions 0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
    //      0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7; record for total paid payable was modified");
    //     log_handler.exists_log_containing("INFO: Accountant: Transactions 0xf1b05f6ad99d9548555cfb6274489a8f021e10000e828d7e23cbc3e009ed5c7f, \
    //      0xd4089b39b14acdb44e7f85ce4fa40a47a50061dafb3190ff4ad206ffb64956a7 went through the whole confirmation process succeeding");
    // }

    #[test]
    fn confirm_transaction_works() {
        init_test_logging();
        let test_name = "confirm_transaction_works";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .delete_fingerprint_params(&delete_pending_payable_fingerprint_params_arc)
            .delete_fingerprint_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
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

        subject.confirm_transaction(pending_payable_fingerprint.clone(), &Logger::new(test_name));

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

    // #[test]
    // #[should_panic(
    // expected = "Was unable to uncheck pending payables 0x0000000000000000000000000000000000000000000000000000000000000315 \
    //      during their confirmation due to RusqliteError(\"record change not successful\")"
    // )]
    // fn confirm_transactions_panics_on_unchecking_payable_table() {
    //     init_test_logging();
    //     let hash = make_tx_hash(789);
    //     let rowid = 3;
    //     let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Err(
    //         PayableDaoError::RusqliteError("record change not successful".to_string()),
    //     ));
    //     let mut subject = AccountantBuilder::default()
    //         .payable_dao(payable_dao)
    //         .build();
    //     let mut payment = make_pending_payable_fingerprint();
    //     payment.rowid = rowid;
    //     payment.hash = hash;
    //
    //     subject.confirm_transactions(vec![payment]);
    // }

    #[test]
    #[should_panic(
        expected = "Was unable to uncheck pending payable '0x0000000000000000000000000000000000000000000\
    000000000000000000315' after confirmation due to 'RusqliteError(\"record change not successful\")'"
    )]
    fn confirm_transaction_panics_on_unchecking_payable_table() {
        let hash = H256::from_uint(&U256::from(789));
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transaction_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.rowid_opt = Some(rowid);
        fingerprint.hash = hash;

        subject.confirm_transaction(fingerprint, &Logger::new("test"));
    }

    // #[test]
    // fn total_paid_payable_rises_with_each_bill_paid() {
    //     let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
    //     let fingerprint_1 = PendingPayableFingerprint {
    //         rowid: 5,
    //         timestamp: from_time_t(189_999_888),
    //         hash: make_tx_hash(56789),
    //         attempt: 1,
    //         amount: 5478,
    //         process_error: None,
    //     };
    //     let fingerprint_2 = PendingPayableFingerprint {
    //         rowid: 6,
    //         timestamp: from_time_t(200_000_011),
    //         hash: make_tx_hash(33333),
    //         attempt: 1,
    //         amount: 6543,
    //         process_error: None,
    //     };
    //     let mut pending_payable_dao =
    //         PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
    //     let payable_dao = PayableDaoMock::default()
    //         .transactions_confirmed_params(&transaction_confirmed_params_arc)
    //         .transactions_confirmed_result(Ok(()))
    //         .transactions_confirmed_result(Ok(()));
    //     pending_payable_dao.have_return_all_fingerprints_shut_down_the_system = true;
    //     let mut subject = AccountantBuilder::default()
    //         .pending_payable_dao(pending_payable_dao)
    //         .payable_dao(payable_dao)
    //         .build();
    //     subject.financial_statistics.total_paid_payable_wei += 1111;
    //
    //     subject.confirm_transactions(vec![fingerprint_1.clone(), fingerprint_2.clone()]);
    //
    //     assert_eq!(
    //         subject.financial_statistics.total_paid_payable_wei,
    //         1111 + 5478 + 6543
    //     );
    //     let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *transaction_confirmed_params,
    //         vec![vec![fingerprint_1, fingerprint_2]]
    //     )
    // }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        let test_name = "total_paid_payable_rises_with_each_bill_paid";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let fingerprint = PendingPayableFingerprint {
            rowid: 5,
            timestamp: from_time_t(189_999_888),
            hash: H256::from_uint(&U256::from(56789)),
            attempt: 1,
            amount: 5478,
            process_error: None,
        };
        let payable_dao = PayableDaoMock::default()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao =
            PendingPayableDaoMock::default().delete_fingerprints_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable_wei += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.confirm_transaction(fingerprint.clone(), &Logger::new(test_name));

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable_wei;
        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(total_paid_payable, 1111 + 5478);
        assert_eq!(*transaction_confirmed_params, vec![fingerprint])
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
        let now = SystemTime::now();

        let result = receivable_scanner.begin_scan(now, None, &Logger::new("DELINQUENCY_TEST"));

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

    //TODO an obsolete test; take just inspiration
    // #[test]
    // fn total_paid_receivable_rises_with_each_bill_paid() {
    //     let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
    //     let receivable_dao = ReceivableDaoMock::new()
    //         .more_money_received_parameters(&more_money_received_params_arc)
    //         .more_money_receivable_result(Ok(()));
    //     let mut subject = AccountantBuilder::default()
    //         .receivable_dao(receivable_dao)
    //         .build();
    //     subject.financial_statistics.total_paid_receivable_wei += 2222;
    //     let receivables = vec![
    //         BlockchainTransaction {
    //             block_number: 4578910,
    //             from: make_wallet("wallet_1"),
    //             wei_amount: 45780,
    //         },
    //         BlockchainTransaction {
    //             block_number: 4569898,
    //             from: make_wallet("wallet_2"),
    //             wei_amount: 33345,
    //         },
    //     ];
    //     let now = SystemTime::now();
    //
    //     subject.handle_received_payments(ReceivedPayments {
    //         timestamp: now,
    //         payments: receivables.clone(),
    //         response_skeleton_opt: None,
    //     });
    //
    //     assert_eq!(
    //         subject.financial_statistics.total_paid_receivable_wei,
    //         2222 + 45780 + 33345
    //     );
    //     let more_money_received_params = more_money_received_params_arc.lock().unwrap();
    //     assert_eq!(*more_money_received_params, vec![(now, receivables)]);
    // }

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
        let time_in_past = SystemTime::now().sub(Duration::from_secs(10));
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        subject.initiated_at_opt = Some(time_in_past);

        subject.remove_timestamp(ScanType::Payables, &logger);

        TestLogHandler::new().exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }

    #[test]
    fn remove_timestamp_and_log_if_timestamp_is_not_found() {
        init_test_logging();
        let test_name = "remove_timestamp_and_log_if_timestamp_is_not_found";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        subject.initiated_at_opt = None;

        subject.remove_timestamp(ScanType::Receivables, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Called scan_finished() for Receivables scanner but timestamp was not found"
        ));
    }
}
