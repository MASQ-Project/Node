// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner_extension;
pub mod scan_schedulers;
pub mod scanners_utils;
pub mod test_utils;

use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::pending_payable_dao::{PendingPayable, PendingPayableDao};
use crate::accountant::db_access_objects::receivable_dao::ReceivableDao;
use crate::accountant::payment_adjuster::{PaymentAdjuster, PaymentAdjusterReal};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{
    LocallyCausedError, RemotelyCausedErrors,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{debugging_summary_after_error_separation, err_msg_for_failure_with_expected_but_missing_fingerprints, investigate_debt_extremes, mark_pending_payable_fatal_error, payables_debug_summary, separate_errors, separate_rowids_and_hashes, OperationOutcome, PayableScanResult, PayableThresholdsGauge, PayableThresholdsGaugeReal, PayableTransactingErrorEnum, PendingPayableMetadata};
use crate::accountant::scanners::scanners_utils::pending_payable_scanner_utils::{handle_none_receipt, handle_status_with_failure, handle_status_with_success, PendingPayableScanReport, PendingPayableScanResult};
use crate::accountant::scanners::scanners_utils::receivable_scanner_utils::balance_and_age;
use crate::accountant::{join_with_separator, PendingPayableId, ScanError, ScanForPendingPayables, ScanForRetryPayables};
use crate::accountant::{
    comma_joined_stringifiable, gwei_to_wei, ReceivedPayments,
    ReportTransactionReceipts, RequestTransactionReceipts, ResponseSkeleton, ScanForNewPayables,
    ScanForReceivables, SentPayables,
};
use crate::accountant::db_access_objects::banned_dao::BannedDao;
use crate::blockchain::blockchain_bridge::{BlockMarker, PendingPayableFingerprint, RetrieveTransactions};
use crate::sub_lib::accountant::{
    DaoFactories, FinancialStatistics, PaymentThresholds,
};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use actix::{Message};
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::logger::TIME_FORMATTING_STRING;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::rc::Rc;
use std::time::{SystemTime};
use time::format_description::parse;
use time::OffsetDateTime;
use variant_count::VariantCount;
use web3::types::H256;
use crate::accountant::db_access_objects::failed_payable_dao::{FailedPayableDao, FailedPayableDaoError, FailedTx, FailureReason, FailureStatus};
use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::ByHash;
use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDao;
use crate::accountant::db_access_objects::utils::{RowId, TxHash, TxIdentifiers};
use crate::accountant::scanners::payable_scanner_extension::{MultistageDualPayableScanner, PreparedAdjustment, SolvencySensitivePaymentInstructor};
use crate::accountant::scanners::payable_scanner_extension::msgs::{BlockchainAgentWithContextMessage, QualifiedPayablesMessage, UnpricedQualifiedPayables};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionReceiptResult, TxStatus};
use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError;
use crate::db_config::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};

// Leave the individual scanner objects private!
pub struct Scanners {
    payable: Box<dyn MultistageDualPayableScanner>,
    aware_of_unresolved_pending_payable: bool,
    initial_pending_payable_scan: bool,
    pending_payable: Box<
        dyn PrivateScanner<
            ScanForPendingPayables,
            RequestTransactionReceipts,
            ReportTransactionReceipts,
            PendingPayableScanResult,
        >,
    >,
    receivable: Box<
        dyn PrivateScanner<
            ScanForReceivables,
            RetrieveTransactions,
            ReceivedPayments,
            Option<NodeToUiMessage>,
        >,
    >,
}

impl Scanners {
    pub fn new(
        dao_factories: DaoFactories,
        payment_thresholds: Rc<PaymentThresholds>,
        when_pending_too_long_sec: u64,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        let payable = Box::new(PayableScanner::new(
            dao_factories.payable_dao_factory.make(),
            dao_factories.sent_payable_dao_factory.make(),
            dao_factories.failed_payable_dao_factory.make(),
            Rc::clone(&payment_thresholds),
            Box::new(PaymentAdjusterReal::new()),
        ));

        let pending_payable = Box::new(PendingPayableScanner::new(
            dao_factories.payable_dao_factory.make(),
            dao_factories.pending_payable_dao_factory.make(),
            Rc::clone(&payment_thresholds),
            when_pending_too_long_sec,
            Rc::clone(&financial_statistics),
        ));

        let persistent_configuration =
            PersistentConfigurationReal::from(dao_factories.config_dao_factory.make());

        let receivable = Box::new(ReceivableScanner::new(
            dao_factories.receivable_dao_factory.make(),
            dao_factories.banned_dao_factory.make(),
            Box::new(persistent_configuration),
            Rc::clone(&payment_thresholds),
            financial_statistics,
        ));

        Scanners {
            payable,
            aware_of_unresolved_pending_payable: false,
            initial_pending_payable_scan: true,
            pending_payable,
            receivable,
        }
    }

    pub fn start_new_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                MTError::AutomaticScanConflict,
            ));
        }
        if let Some(started_at) = self.payable.scan_started_at() {
            return Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at,
            });
        }

        Self::start_correct_payable_scanner::<ScanForNewPayables>(
            &mut *self.payable,
            wallet,
            timestamp,
            response_skeleton_opt,
            logger,
        )
    }

    // Note: This scanner cannot be started on its own. It always runs after the pending payable
    // scan, but only if it is clear that a retry is needed.
    pub fn start_retry_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        if let Some(started_at) = self.payable.scan_started_at() {
            unreachable!(
                "Guards should ensure that no payable scanner can run if the pending payable \
                 repetitive sequence is still ongoing. However, some other payable scan intruded \
                 at {} and is still running at {}",
                StartScanError::timestamp_as_string(started_at),
                StartScanError::timestamp_as_string(SystemTime::now())
            )
        }

        Self::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut *self.payable,
            wallet,
            timestamp,
            response_skeleton_opt,
            logger,
        )
    }

    pub fn start_pending_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<RequestTransactionReceipts, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        self.check_general_conditions_for_pending_payable_scan(
            triggered_manually,
            automatic_scans_enabled,
        )?;
        match (
            self.pending_payable.scan_started_at(),
            self.payable.scan_started_at(),
        ) {
            (Some(pp_timestamp), Some(p_timestamp)) =>
            // If you're wondering, then yes, this condition should be the sacred truth between
            // PendingPayableScanner and NewPayableScanner.
            {
                unreachable!(
                    "Any payable-related scanners should never be allowed to run in parallel. \
                    Scan for pending payables started at: {}, scan for payables started at: {}",
                    StartScanError::timestamp_as_string(pp_timestamp),
                    StartScanError::timestamp_as_string(p_timestamp)
                )
            }
            (Some(started_at), None) => {
                return Err(StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: None,
                    started_at,
                })
            }
            (None, Some(started_at)) => {
                return Err(StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: Some(ScanType::Payables),
                    started_at,
                })
            }
            (None, None) => (),
        }
        self.pending_payable
            .start_scan(wallet, timestamp, response_skeleton_opt, logger)
    }

    pub fn start_receivable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<RetrieveTransactions, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                MTError::AutomaticScanConflict,
            ));
        }
        if let Some(started_at) = self.receivable.scan_started_at() {
            return Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at,
            });
        }

        self.receivable
            .start_scan(wallet, timestamp, response_skeleton_opt, logger)
    }

    pub fn finish_payable_scan(&mut self, msg: SentPayables, logger: &Logger) -> PayableScanResult {
        let scan_result = self.payable.finish_scan(msg, logger);
        match scan_result.result {
            OperationOutcome::NewPendingPayable => self.aware_of_unresolved_pending_payable = true,
            OperationOutcome::Failure => (),
        };
        scan_result
    }

    pub fn finish_pending_payable_scan(
        &mut self,
        msg: ReportTransactionReceipts,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        self.pending_payable.finish_scan(msg, logger)
    }

    pub fn finish_receivable_scan(
        &mut self,
        msg: ReceivedPayments,
        logger: &Logger,
    ) -> Option<NodeToUiMessage> {
        self.receivable.finish_scan(msg, logger)
    }

    pub fn acknowledge_scan_error(&mut self, error: &ScanError, logger: &Logger) {
        match error.scan_type {
            ScanType::Payables => {
                self.payable.mark_as_ended(logger);
            }
            ScanType::PendingPayables => {
                self.pending_payable.mark_as_ended(logger);
            }
            ScanType::Receivables => {
                self.receivable.mark_as_ended(logger);
            }
        };
    }

    pub fn try_skipping_payable_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        self.payable.try_skipping_payment_adjustment(msg, logger)
    }

    pub fn perform_payable_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        self.payable.perform_payment_adjustment(setup, logger)
    }

    pub fn initial_pending_payable_scan(&self) -> bool {
        self.initial_pending_payable_scan
    }

    pub fn unset_initial_pending_payable_scan(&mut self) {
        self.initial_pending_payable_scan = false
    }

    // This is a helper function reducing a boilerplate of complex trait resolving where
    // the compiler requires to specify which trigger message distinguish the scan to run.
    // The payable scanner offers two modes through doubled implementations of StartableScanner
    // which uses the trigger message type as the only distinction between them.
    fn start_correct_payable_scanner<'a, TriggerMessage>(
        scanner: &'a mut (dyn MultistageDualPayableScanner + 'a),
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError>
    where
        TriggerMessage: Message,
        (dyn MultistageDualPayableScanner + 'a):
            StartableScanner<TriggerMessage, QualifiedPayablesMessage>,
    {
        <(dyn MultistageDualPayableScanner + 'a) as StartableScanner<
            TriggerMessage,
            QualifiedPayablesMessage,
        >>::start_scan(scanner, wallet, timestamp, response_skeleton_opt, logger)
    }

    fn check_general_conditions_for_pending_payable_scan(
        &mut self,
        triggered_manually: bool,
        automatic_scans_enabled: bool,
    ) -> Result<(), StartScanError> {
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                MTError::AutomaticScanConflict,
            ));
        }
        if self.initial_pending_payable_scan {
            return Ok(());
        }
        if triggered_manually && !self.aware_of_unresolved_pending_payable {
            return Err(StartScanError::ManualTriggerError(
                MTError::UnnecessaryRequest {
                    hint_opt: Some("Run the Payable scanner first.".to_string()),
                },
            ));
        }
        if !self.aware_of_unresolved_pending_payable {
            unreachable!(
                "Automatic pending payable scan should never start if there are no pending \
                payables to process."
            )
        }

        Ok(())
    }
}

pub(in crate::accountant::scanners) trait PrivateScanner<
    TriggerMessage,
    StartMessage,
    EndMessage,
    ScanResult,
>:
    StartableScanner<TriggerMessage, StartMessage> + Scanner<EndMessage, ScanResult> where
    TriggerMessage: Message,
    StartMessage: Message,
    EndMessage: Message,
{
}

trait StartableScanner<TriggerMessage, StartMessage>
where
    TriggerMessage: Message,
    StartMessage: Message,
{
    fn start_scan(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<StartMessage, StartScanError>;
}

trait Scanner<EndMessage, ScanResult>
where
    EndMessage: Message,
{
    fn finish_scan(&mut self, message: EndMessage, logger: &Logger) -> ScanResult;
    fn scan_started_at(&self) -> Option<SystemTime>;
    fn mark_as_started(&mut self, timestamp: SystemTime);
    fn mark_as_ended(&mut self, logger: &Logger);

    as_any_ref_in_trait!();
    as_any_mut_in_trait!();
}

pub struct ScannerCommon {
    initiated_at_opt: Option<SystemTime>,
    payment_thresholds: Rc<PaymentThresholds>,
}

impl ScannerCommon {
    fn new(payment_thresholds: Rc<PaymentThresholds>) -> Self {
        Self {
            initiated_at_opt: None,
            payment_thresholds,
        }
    }

    fn signal_scanner_completion(&mut self, scan_type: ScanType, now: SystemTime, logger: &Logger) {
        match self.initiated_at_opt.take() {
            Some(timestamp) => {
                let elapsed_time = now
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

#[macro_export]
macro_rules! time_marking_methods {
    ($scan_type_variant: ident) => {
        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        fn mark_as_started(&mut self, timestamp: SystemTime) {
            self.common.initiated_at_opt = Some(timestamp);
        }

        fn mark_as_ended(&mut self, logger: &Logger) {
            self.common.signal_scanner_completion(
                ScanType::$scan_type_variant,
                SystemTime::now(),
                logger,
            );
        }
    };
}

pub struct PayableScanner {
    pub payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    // TODO: GH-605: Insert FailedPayableDao, maybe introduce SentPayableDao once you eliminate PendingPayableDao
    pub payment_adjuster: Box<dyn PaymentAdjuster>,
}

impl MultistageDualPayableScanner for PayableScanner {}

impl StartableScanner<ScanForNewPayables, QualifiedPayablesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for new payables");
        let all_non_pending_payables = self.payable_dao.non_pending_payables();

        debug!(
            logger,
            "{}",
            investigate_debt_extremes(timestamp, &all_non_pending_payables)
        );

        let qualified_payables =
            self.sniff_out_alarming_payables_and_maybe_log_them(all_non_pending_payables, logger);

        match qualified_payables.is_empty() {
            true => {
                self.mark_as_ended(logger);
                Err(StartScanError::NothingToProcess)
            }
            false => {
                info!(
                    logger,
                    "Chose {} qualified debts to pay",
                    qualified_payables.len()
                );
                let qualified_payables = UnpricedQualifiedPayables::from(qualified_payables);
                let outgoing_msg = QualifiedPayablesMessage::new(
                    qualified_payables,
                    consuming_wallet.clone(),
                    response_skeleton_opt,
                );
                Ok(outgoing_msg)
            }
        }
    }
}

impl StartableScanner<ScanForRetryPayables, QualifiedPayablesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        _consuming_wallet: &Wallet,
        _timestamp: SystemTime,
        _response_skeleton_opt: Option<ResponseSkeleton>,
        _logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        todo!("Complete me under GH-605")
        // 1. Find the failed payables
        // 2. Look into the payable DAO to update the amount
        // 3. Prepare UnpricedQualifiedPayables
    }
}

impl Scanner<SentPayables, PayableScanResult> for PayableScanner {
    fn finish_scan(&mut self, message: SentPayables, logger: &Logger) -> PayableScanResult {
        let result = match message.payment_procedure_result {
            Either::Left(batch_results) => {
                // let (sent_payables, err_opt) = separate_errors(&message, logger);
                // debug!(
                //     logger,
                //     "{}",
                //     debugging_summary_after_error_separation(&sent_payables, &err_opt)
                // );

                // if !sent_payables.is_empty() {
                //     self.mark_pending_payable(&sent_payables, logger);
                // }

                // self.handle_sent_payable_errors(err_opt, logger);

                todo!("Segregate transactions and migrate them from the SentPayableDao to the FailedPayableDao");
            }
            Either::Right(local_err) => {
                // No need to update the FailedPayableDao as the error was local
                warning!(
                    logger,
                    "Any persisted data from failed process will be deleted. Caused by: {}",
                    local_err
                );

                if let LocalPayableError::Sending { hashes, .. } = local_err {
                    debug!(
                        logger,
                        "Migrating failed transactions to the FailedPayableDao: {}",
                        join_with_separator(&hashes, |hash| format!("{:?}", hash), ", ")
                    );
                    self.discard_failed_transactions_with_possible_fingerprints(hashes, logger)
                } else {
                    debug!(
                        logger,
                        "Ignoring a non-fatal error on our end from before the transactions are hashed: {:?}",
                        local_err
                    )
                }

                OperationOutcome::Failure
            }
        };

        self.mark_as_ended(logger);

        let ui_response_opt =
            message
                .response_skeleton_opt
                .map(|response_skeleton| NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                });

        PayableScanResult {
            ui_response_opt,
            result,
        }
    }

    time_marking_methods!(Payables);

    as_any_ref_in_trait_impl!();
}

impl SolvencySensitivePaymentInstructor for PayableScanner {
    fn try_skipping_payment_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        match self
            .payment_adjuster
            .search_for_indispensable_adjustment(&msg, logger)
        {
            Ok(None) => Ok(Either::Left(OutboundPaymentsInstructions::new(
                msg.qualified_payables,
                msg.agent,
                msg.response_skeleton_opt,
            ))),
            Ok(Some(adjustment)) => Ok(Either::Right(PreparedAdjustment::new(msg, adjustment))),
            Err(_e) => todo!("be implemented with GH-711"),
        }
    }

    fn perform_payment_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        let now = SystemTime::now();
        self.payment_adjuster.adjust_payments(setup, now, logger)
    }
}

impl PayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        sent_payable_dao: Box<dyn SentPayableDao>,
        failed_payable_dao: Box<dyn FailedPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        payment_adjuster: Box<dyn PaymentAdjuster>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            sent_payable_dao,
            failed_payable_dao,
            payable_threshold_gauge: Box::new(PayableThresholdsGaugeReal::default()),
            payment_adjuster,
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

    fn separate_existent_and_nonexistent_fingerprints<'a>(
        &'a self,
        sent_payables: &[&'a PendingPayable],
    ) -> (Vec<PendingPayableMetadata>, Vec<PendingPayableMetadata>) {
        let hashes = sent_payables
            .iter()
            .map(|pending_payable| pending_payable.hash)
            .collect::<Vec<H256>>();
        let mut sent_payables_hashmap = sent_payables
            .iter()
            .map(|payable| (payable.hash, &payable.recipient_wallet))
            .collect::<HashMap<H256, &Wallet>>();

        // let transaction_hashes = self.pending_payable_dao.fingerprints_rowids(&hashes);
        let transaction_hashes =
            todo!("instead of retrieving it from PendingPayableDao, retrieve from SentPayableDao");
        // let mut hashes_from_db = transaction_hashes
        //     .rowid_results
        //     .iter()
        //     .map(|(_rowid, hash)| *hash)
        //     .collect::<HashSet<H256>>();
        // for hash in &transaction_hashes.no_rowid_results {
        //     hashes_from_db.insert(*hash);
        // }
        // let sent_payables_hashes = hashes.iter().copied().collect::<HashSet<H256>>();
        //
        // if !Self::is_symmetrical(sent_payables_hashes, hashes_from_db) {
        //     panic!(
        //         "Inconsistency in two maps, they cannot be matched by hashes. Data set directly \
        //         sent from BlockchainBridge: {:?}, set derived from the DB: {:?}",
        //         sent_payables, transaction_hashes
        //     )
        // }
        //
        // let pending_payables_with_rowid = transaction_hashes
        //     .rowid_results
        //     .into_iter()
        //     .map(|(rowid, hash)| {
        //         let wallet = sent_payables_hashmap
        //             .remove(&hash)
        //             .expect("expect transaction hash, but it disappear");
        //         PendingPayableMetadata::new(wallet, hash, Some(rowid))
        //     })
        //     .collect_vec();
        // let pending_payables_without_rowid = transaction_hashes
        //     .no_rowid_results
        //     .into_iter()
        //     .map(|hash| {
        //         let wallet = sent_payables_hashmap
        //             .remove(&hash)
        //             .expect("expect transaction hash, but it disappear");
        //         PendingPayableMetadata::new(wallet, hash, None)
        //     })
        //     .collect_vec();
        //
        // (pending_payables_with_rowid, pending_payables_without_rowid)
    }

    fn is_symmetrical(
        sent_payables_hashes: HashSet<H256>,
        fingerptint_hashes: HashSet<H256>,
    ) -> bool {
        sent_payables_hashes == fingerptint_hashes
    }

    fn mark_pending_payable(&self, sent_payments: &[&PendingPayable], logger: &Logger) {
        fn missing_fingerprints_msg(nonexistent: &[PendingPayableMetadata]) -> String {
            format!(
                "Expected pending payable fingerprints for {} were not found; system unreliable",
                comma_joined_stringifiable(nonexistent, |pp_triple| format!(
                    "(tx: {:?}, to wallet: {})",
                    pp_triple.hash, pp_triple.recipient
                ))
            )
        }
        fn ready_data_for_supply<'a>(
            existent: &'a [PendingPayableMetadata],
        ) -> Vec<(&'a Wallet, u64)> {
            existent
                .iter()
                .map(|pp_triple| (pp_triple.recipient, pp_triple.rowid_opt.expectv("rowid")))
                .collect()
        }

        let (existent, nonexistent) =
            self.separate_existent_and_nonexistent_fingerprints(sent_payments);
        let mark_pp_input_data = ready_data_for_supply(&existent);
        if !mark_pp_input_data.is_empty() {
            if let Err(e) = self
                .payable_dao
                .as_ref()
                .mark_pending_payables_rowids(&mark_pp_input_data)
            {
                mark_pending_payable_fatal_error(
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
                comma_joined_stringifiable(sent_payments, |pending_p| format!(
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
                LocallyCausedError(LocalPayableError::Sending { hashes, .. })
                | RemotelyCausedErrors(hashes) => {
                    self.discard_failed_transactions_with_possible_fingerprints(hashes, logger)
                }
                non_fatal =>
                    debug!(
                        logger,
                        "Ignoring a non-fatal error on our end from before the transactions are hashed: {:?}",
                        non_fatal
                    )
            }
        }
    }

    fn find_absent_tx_hashes(
        tx_identifiers: &TxIdentifiers,
        hashset: HashSet<TxHash>,
    ) -> Option<HashSet<TxHash>> {
        let absent_hashes: HashSet<TxHash> = hashset
            .into_iter()
            .filter(|hash| !tx_identifiers.contains_key(hash))
            .collect();

        if absent_hashes.is_empty() {
            None
        } else {
            Some(absent_hashes)
        }
    }

    fn migrate_from_sent_payable_to_failed_payable(
        &self,
        hashes: &HashSet<TxHash>,
    ) -> Result<(), String> {
        let failed_txs: HashSet<FailedTx> = self
            .sent_payable_dao
            .retrieve_txs(Some(ByHash(hashes.clone())))
            .into_iter()
            .map(|tx| FailedTx {
                hash: tx.hash,
                receiver_address: tx.receiver_address,
                amount: tx.amount,
                timestamp: tx.timestamp,
                gas_price_wei: tx.gas_price_wei,
                nonce: tx.nonce,
                reason: FailureReason::LocalSendingFailed,
                status: FailureStatus::RetryRequired,
            })
            .collect();

        if let Err(e) = self.failed_payable_dao.insert_new_records(&failed_txs) {
            return Err(format!("During Insertion in FailedPayable Table: {:?}", e));
        }

        if let Err(e) = self.sent_payable_dao.delete_records(hashes) {
            return Err(format!("During Deletion in FailedPayable Table: {:?}", e));
        };

        Ok(())
    }

    fn serialize_hashes(hashes: &[H256]) -> String {
        comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
    }

    fn discard_failed_transactions_with_possible_fingerprints(
        &self,
        hashes_of_failed: Vec<H256>, // TODO: GH-605: This should be a HashMap<TxHash, FailureReason>
        logger: &Logger,
    ) {
        // TODO: GH-605: We should transfer the payables to the FailedPayableDao
        let hashset = hashes_of_failed.iter().cloned().collect::<HashSet<H256>>();
        if hashset.len() < hashes_of_failed.len() {
            warning!(
                logger,
                "Some hashes were duplicated, this may be due to a bug in our code: {}",
                join_with_separator(&hashes_of_failed, |hash| format!("{:?}", hash), ", ")
            )
        }
        let tx_identifiers = self.sent_payable_dao.get_tx_identifiers(&hashset);
        if !tx_identifiers.is_empty() {
            let tx_hashes: HashSet<TxHash> = tx_identifiers.keys().cloned().collect();
            if let Err(e) = self.migrate_from_sent_payable_to_failed_payable(&tx_hashes) {
                panic!("While migrating transactions from SentPayable table to FailedPayable Table: {}", e);
            }

            if let Some(absent_hashes) = Self::find_absent_tx_hashes(&tx_identifiers, hashset) {
                panic!(
                    "Ran into failed transactions {} with missing fingerprints. System no longer reliable",
                    join_with_separator(&absent_hashes, |hash| format!("{:?}", hash), ", ")
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

impl
    PrivateScanner<
        ScanForPendingPayables,
        RequestTransactionReceipts,
        ReportTransactionReceipts,
        PendingPayableScanResult,
    > for PendingPayableScanner
{
}

impl StartableScanner<ScanForPendingPayables, RequestTransactionReceipts>
    for PendingPayableScanner
{
    fn start_scan(
        &mut self,
        _wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RequestTransactionReceipts, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for pending payable");
        let filtered_pending_payable = self.pending_payable_dao.return_all_errorless_fingerprints();
        match filtered_pending_payable.is_empty() {
            true => {
                self.mark_as_ended(logger);
                Err(StartScanError::NothingToProcess)
            }
            false => {
                debug!(
                    logger,
                    "Found {} pending payables to process",
                    filtered_pending_payable.len()
                );
                Ok(RequestTransactionReceipts {
                    pending_payable_fingerprints: filtered_pending_payable,
                    response_skeleton_opt,
                })
            }
        }
    }
}

impl Scanner<ReportTransactionReceipts, PendingPayableScanResult> for PendingPayableScanner {
    fn finish_scan(
        &mut self,
        message: ReportTransactionReceipts,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        let response_skeleton_opt = message.response_skeleton_opt;

        let requires_payment_retry = match message.fingerprints_with_receipts.is_empty() {
            true => {
                warning!(logger, "No transaction receipts found.");
                todo!("This requires the payment retry. GH-631 must be completed first");
            }
            false => {
                debug!(
                    logger,
                    "Processing receipts for {} transactions",
                    message.fingerprints_with_receipts.len()
                );
                let scan_report = self.handle_receipts_for_pending_transactions(message, logger);
                let requires_payment_retry =
                    self.process_transactions_by_reported_state(scan_report, logger);

                self.mark_as_ended(logger);

                requires_payment_retry
            }
        };

        if requires_payment_retry {
            PendingPayableScanResult::PaymentRetryRequired
        } else {
            let ui_msg_opt = response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            });
            PendingPayableScanResult::NoPendingPayablesLeft(ui_msg_opt)
        }
    }

    time_marking_methods!(PendingPayables);

    as_any_ref_in_trait_impl!();
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
        let scan_report = PendingPayableScanReport::default();
        msg.fingerprints_with_receipts.into_iter().fold(
            scan_report,
            |scan_report_so_far, (receipt_result, fingerprint)| match receipt_result {
                TransactionReceiptResult::RpcResponse(tx_receipt) => match tx_receipt.status {
                    TxStatus::Pending => handle_none_receipt(
                        scan_report_so_far,
                        fingerprint,
                        "none was given",
                        logger,
                    ),
                    TxStatus::Failed => {
                        handle_status_with_failure(scan_report_so_far, fingerprint, logger)
                    }
                    TxStatus::Succeeded(_) => {
                        handle_status_with_success(scan_report_so_far, fingerprint, logger)
                    }
                },
                TransactionReceiptResult::LocalError(e) => handle_none_receipt(
                    scan_report_so_far,
                    fingerprint,
                    &format!("failed due to {}", e),
                    logger,
                ),
            },
        )
    }

    fn process_transactions_by_reported_state(
        &mut self,
        scan_report: PendingPayableScanReport,
        logger: &Logger,
    ) -> bool {
        let requires_payments_retry = scan_report.requires_payments_retry();

        self.confirm_transactions(scan_report.confirmed, logger);
        self.cancel_failed_transactions(scan_report.failures, logger);
        self.update_remaining_fingerprints(scan_report.still_pending, logger);

        requires_payments_retry
    }

    fn update_remaining_fingerprints(&self, ids: Vec<PendingPayableId>, logger: &Logger) {
        if !ids.is_empty() {
            let rowids = PendingPayableId::rowids(&ids);
            match self.pending_payable_dao.increment_scan_attempts(&rowids) {
                Ok(_) => trace!(
                    logger,
                    "Updated records for rowids: {} ",
                    comma_joined_stringifiable(&rowids, |id| id.to_string())
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
            comma_joined_stringifiable(fingerprints, |fgp| format!("{:?}", fgp.hash))
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
    pub persistent_configuration: Box<dyn PersistentConfiguration>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
}

impl
    PrivateScanner<
        ScanForReceivables,
        RetrieveTransactions,
        ReceivedPayments,
        Option<NodeToUiMessage>,
    > for ReceivableScanner
{
}

impl StartableScanner<ScanForReceivables, RetrieveTransactions> for ReceivableScanner {
    fn start_scan(
        &mut self,
        earning_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RetrieveTransactions, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for receivables to {}", earning_wallet);
        self.scan_for_delinquencies(timestamp, logger);

        Ok(RetrieveTransactions {
            recipient: earning_wallet.clone(),
            response_skeleton_opt,
        })
    }
}

impl Scanner<ReceivedPayments, Option<NodeToUiMessage>> for ReceivableScanner {
    fn finish_scan(&mut self, msg: ReceivedPayments, logger: &Logger) -> Option<NodeToUiMessage> {
        self.handle_new_received_payments(&msg, logger);
        self.mark_as_ended(logger);

        msg.response_skeleton_opt
            .map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            })
    }

    time_marking_methods!(Receivables);

    as_any_ref_in_trait_impl!();
    as_any_mut_in_trait_impl!();
}

impl ReceivableScanner {
    pub fn new(
        receivable_dao: Box<dyn ReceivableDao>,
        banned_dao: Box<dyn BannedDao>,
        persistent_configuration: Box<dyn PersistentConfiguration>,
        payment_thresholds: Rc<PaymentThresholds>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            receivable_dao,
            banned_dao,
            persistent_configuration,
            financial_statistics,
        }
    }

    fn handle_new_received_payments(
        &mut self,
        received_payments_msg: &ReceivedPayments,
        logger: &Logger,
    ) {
        if received_payments_msg.transactions.is_empty() {
            info!(
                logger,
                "No newly received payments were detected during the scanning process."
            );
            let new_start_block = received_payments_msg.new_start_block;
            if let BlockMarker::Value(start_block_number) = new_start_block {
                match self
                    .persistent_configuration
                    .set_start_block(Some(start_block_number))
                {
                    Ok(()) => debug!(logger, "Start block updated to {}", start_block_number),
                    Err(e) => panic!(
                        "Attempt to set new start block to {} failed due to: {:?}",
                        start_block_number, e
                    ),
                }
            }
        } else {
            let mut txn = self.receivable_dao.as_mut().more_money_received(
                received_payments_msg.timestamp,
                &received_payments_msg.transactions,
            );
            let new_start_block = received_payments_msg.new_start_block;
            if let BlockMarker::Value(start_block_number) = new_start_block {
                match self
                    .persistent_configuration
                    .set_start_block_from_txn(Some(start_block_number), &mut txn)
                {
                    Ok(()) => debug!(logger, "Start block updated to {}", start_block_number),
                    Err(e) => panic!(
                        "Attempt to set new start block to {} failed due to: {:?}",
                        start_block_number, e
                    ),
                }
            } else {
                unreachable!("Failed to get start_block while transactions were present");
            }
            match txn.commit() {
                Ok(_) => {
                    debug!(logger, "Received payments have been commited to database");
                }
                Err(e) => panic!("Commit of received transactions failed: {:?}", e),
            }
            let total_newly_paid_receivable = received_payments_msg
                .transactions
                .iter()
                .fold(0, |so_far, now| so_far + now.wei_amount);

            self.financial_statistics
                .borrow_mut()
                .total_paid_receivable_wei += total_newly_paid_receivable;
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

#[derive(Debug, PartialEq, Eq, Clone, VariantCount)]
pub enum StartScanError {
    NothingToProcess,
    NoConsumingWalletFound,
    ScanAlreadyRunning {
        cross_scan_cause_opt: Option<ScanType>,
        started_at: SystemTime,
    },
    CalledFromNullScanner, // Exclusive for tests
    ManualTriggerError(MTError),
}

impl StartScanError {
    pub fn log_error(&self, logger: &Logger, scan_type: ScanType, is_externally_triggered: bool) {
        enum ErrorType {
            Temporary(String),
            Permanent(String),
        }

        let log_message = match self {
            StartScanError::NothingToProcess => ErrorType::Temporary(format!(
                "There was nothing to process during {:?} scan.",
                scan_type
            )),
            StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt,
                started_at,
            } => ErrorType::Temporary(Self::scan_already_running_msg(
                scan_type,
                *cross_scan_cause_opt,
                *started_at,
            )),
            StartScanError::NoConsumingWalletFound => ErrorType::Permanent(format!(
                "Cannot initiate {:?} scan because no consuming wallet was found.",
                scan_type
            )),
            StartScanError::CalledFromNullScanner => match cfg!(test) {
                true => ErrorType::Permanent(format!(
                    "Called from NullScanner, not the {:?} scanner.",
                    scan_type
                )),
                false => panic!("Null Scanner shouldn't be running inside production code."),
            },
            StartScanError::ManualTriggerError(e) => match e {
                MTError::AutomaticScanConflict => ErrorType::Permanent(format!(
                    "User requested {:?} scan was denied. Automatic mode prevents manual triggers.",
                    scan_type
                )),
                MTError::UnnecessaryRequest { hint_opt } => ErrorType::Temporary(format!(
                    "User requested {:?} scan was denied expecting zero findings.{}",
                    scan_type,
                    match hint_opt {
                        Some(hint) => format!(" {}", hint),
                        None => "".to_string(),
                    }
                )),
            },
        };

        match log_message {
            ErrorType::Temporary(msg) => match is_externally_triggered {
                true => info!(logger, "{}", msg),
                false => debug!(logger, "{}", msg),
            },
            ErrorType::Permanent(msg) => warning!(logger, "{}", msg),
        }
    }

    fn timestamp_as_string(timestamp: SystemTime) -> String {
        let offset_date_time = OffsetDateTime::from(timestamp);
        offset_date_time
            .format(
                &parse(TIME_FORMATTING_STRING)
                    .expect("Error while parsing the time formatting string."),
            )
            .expect("Error while formatting timestamp as string.")
    }

    fn scan_already_running_msg(
        request_of: ScanType,
        cross_scan_cause_opt: Option<ScanType>,
        scan_started: SystemTime,
    ) -> String {
        let (blocking_scanner, request_spec) = if let Some(cross_scan_cause) = cross_scan_cause_opt
        {
            (cross_scan_cause, format!("the {:?}", request_of))
        } else {
            (request_of, "this".to_string())
        };

        format!(
            "{:?} scan was already initiated at {}. Hence, {} scan request will be ignored.",
            blocking_scanner,
            StartScanError::timestamp_as_string(scan_started),
            request_spec
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MTError {
    AutomaticScanConflict,
    UnnecessaryRequest { hint_opt: Option<String> },
}

pub trait RealScannerMarker {}

macro_rules! impl_real_scanner_marker {
    ($($t:ty),*) => {
        $(impl RealScannerMarker for $t {})*
    }
}

impl_real_scanner_marker!(PayableScanner, PendingPayableScanner, ReceivableScanner);

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::test_utils::{FailedTxBuilder, TxBuilder};
    use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDaoError};
    use crate::accountant::db_access_objects::pending_payable_dao::{
        PendingPayable, PendingPayableDaoError, TransactionHashes,
    };
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp, TxIdentifiers};
    use crate::accountant::scanners::payable_scanner_extension::msgs::{QualifiedPayablesBeforeGasPriceSelection, QualifiedPayablesMessage, UnpricedQualifiedPayables};
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{OperationOutcome, PayableScanResult, PendingPayableMetadata};
    use crate::accountant::scanners::scanners_utils::pending_payable_scanner_utils::{handle_none_status, handle_status_with_failure, PendingPayableScanReport, PendingPayableScanResult};
    use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner, PayableScanner, PendingPayableScanner, ReceivableScanner, ScannerCommon, Scanners, MTError};
    use crate::accountant::test_utils::{make_custom_payment_thresholds, make_payable_account, make_qualified_and_unqualified_payables, make_pending_payable_fingerprint, make_receivable_account, BannedDaoFactoryMock, BannedDaoMock, ConfigDaoFactoryMock, PayableDaoFactoryMock, PayableDaoMock, PayableScannerBuilder, PayableThresholdsGaugeMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock, PendingPayableScannerBuilder, ReceivableDaoFactoryMock, ReceivableDaoMock, ReceivableScannerBuilder, FailedPayableDaoMock, FailedPayableDaoFactoryMock, SentPayableDaoFactoryMock, SentPayableDaoMock};
    use crate::accountant::{gwei_to_wei, PendingPayableId, ReceivedPayments, ReportTransactionReceipts, RequestTransactionReceipts, ScanError, ScanForRetryPayables, SentPayables, DEFAULT_PENDING_TOO_LONG_SEC};
    use crate::blockchain::blockchain_bridge::{BlockMarker, PendingPayableFingerprint, RetrieveTransactions};
    use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError;
    use crate::blockchain::blockchain_interface::data_structures::{
        BlockchainTransaction, IndividualBatchResult, RpcPayableFailure,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::{
        DaoFactories, FinancialStatistics, PaymentThresholds,
        DEFAULT_PAYMENT_THRESHOLDS,
    };
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::{Message, System};
    use ethereum_types::U64;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use regex::{Regex};
    use rusqlite::{ffi, ErrorCode};
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use itertools::Either;
    use web3::types::{TransactionReceipt, H256};
    use web3::Error;
    use masq_lib::messages::ScanType;
    use masq_lib::ui_gateway::NodeToUiMessage;
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason, FailureStatus};
    use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
    use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::ByHash;
    use crate::accountant::scanners::test_utils::{assert_timestamps_from_str, parse_system_time_from_str, MarkScanner, NullScanner, ReplacementType, ScannerReplacement};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock, TransactionReceiptResult, TxReceipt, TxStatus};

    impl Scanners {
        pub fn replace_scanner(&mut self, replacement: ScannerReplacement) {
            match replacement {
                ScannerReplacement::Payable(ReplacementType::Real(scanner)) => {
                    self.payable = Box::new(scanner)
                }
                ScannerReplacement::Payable(ReplacementType::Mock(scanner)) => {
                    self.payable = Box::new(scanner)
                }
                ScannerReplacement::Payable(ReplacementType::Null) => {
                    self.payable = Box::new(NullScanner::default())
                }
                ScannerReplacement::PendingPayable(ReplacementType::Real(scanner)) => {
                    self.pending_payable = Box::new(scanner)
                }
                ScannerReplacement::PendingPayable(ReplacementType::Mock(scanner)) => {
                    self.pending_payable = Box::new(scanner)
                }
                ScannerReplacement::PendingPayable(ReplacementType::Null) => {
                    self.pending_payable = Box::new(NullScanner::default())
                }
                ScannerReplacement::Receivable(ReplacementType::Real(scanner)) => {
                    self.receivable = Box::new(scanner)
                }
                ScannerReplacement::Receivable(ReplacementType::Mock(scanner)) => {
                    self.receivable = Box::new(scanner)
                }
                ScannerReplacement::Receivable(ReplacementType::Null) => {
                    self.receivable = Box::new(NullScanner::default())
                }
            }
        }

        pub fn reset_scan_started(&mut self, scan_type: ScanType, value: MarkScanner) {
            match scan_type {
                ScanType::Payables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.payable, value)
                }
                ScanType::PendingPayables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.pending_payable, value)
                }
                ScanType::Receivables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.receivable, value)
                }
            }
        }

        pub fn aware_of_unresolved_pending_payables(&self) -> bool {
            self.aware_of_unresolved_pending_payable
        }

        pub fn set_aware_of_unresolved_pending_payables(&mut self, value: bool) {
            self.aware_of_unresolved_pending_payable = value
        }

        fn simple_scanner_timestamp_treatment<Scanner, EndMessage, ScanResult>(
            scanner: &mut Scanner,
            value: MarkScanner,
        ) where
            Scanner: self::Scanner<EndMessage, ScanResult> + ?Sized,
            EndMessage: actix::Message,
        {
            match value {
                MarkScanner::Ended(logger) => scanner.mark_as_ended(logger),
                MarkScanner::Started(timestamp) => scanner.mark_as_started(timestamp),
            }
        }

        pub fn scan_started_at(&self, scan_type: ScanType) -> Option<SystemTime> {
            match scan_type {
                ScanType::Payables => self.payable.scan_started_at(),
                ScanType::PendingPayables => self.pending_payable.scan_started_at(),
                ScanType::Receivables => self.receivable.scan_started_at(),
            }
        }
    }

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_result(PayableDaoMock::new())
            .make_result(PayableDaoMock::new());
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new()
            .make_result(PendingPayableDaoMock::new())
            .make_result(PendingPayableDaoMock::new());
        let sent_payable_dao_factory = SentPayableDaoFactoryMock::new();
        let failed_payable_dao_factory = FailedPayableDaoFactoryMock::new();
        let receivable_dao = ReceivableDaoMock::new();
        let receivable_dao_factory = ReceivableDaoFactoryMock::new().make_result(receivable_dao);
        let banned_dao_factory = BannedDaoFactoryMock::new().make_result(BannedDaoMock::new());
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao_mock = ConfigDaoMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let config_dao_factory = ConfigDaoFactoryMock::new().make_result(config_dao_mock);
        let when_pending_too_long_sec = 1234;
        let financial_statistics = FinancialStatistics {
            total_paid_payable_wei: 1,
            total_paid_receivable_wei: 2,
        };
        let payment_thresholds = make_custom_payment_thresholds();
        let payment_thresholds_rc = Rc::new(payment_thresholds);
        let initial_rc_count = Rc::strong_count(&payment_thresholds_rc);

        let mut scanners = Scanners::new(
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                sent_payable_dao_factory: Box::new(sent_payable_dao_factory),
                failed_payable_dao_factory: Box::new(failed_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
                config_dao_factory: Box::new(config_dao_factory),
            },
            Rc::clone(&payment_thresholds_rc),
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
            .as_any_mut()
            .downcast_mut::<ReceivableScanner>()
            .unwrap();
        assert_eq!(
            payable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(payable_scanner.common.initiated_at_opt.is_some(), false);
        assert_eq!(scanners.aware_of_unresolved_pending_payable, false);
        assert_eq!(scanners.initial_pending_payable_scan, true);
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
            receivable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(receivable_scanner.common.initiated_at_opt.is_some(), false);
        receivable_scanner
            .persistent_configuration
            .set_start_block(Some(136890))
            .unwrap();
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("start_block".to_string(), Some("136890".to_string()))]
        );
        assert_eq!(
            Rc::strong_count(&payment_thresholds_rc),
            initial_rc_count + 3
        );
    }

    #[test]
    fn new_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "new_payable_scanner_can_initiate_a_scan";
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let (qualified_payable_accounts, _, all_non_pending_payables) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let timestamp = subject.payable.scan_started_at();
        assert_eq!(timestamp, Some(now));
        let qualified_payables_count = qualified_payable_accounts.len();
        let expected_unpriced_qualified_payables = UnpricedQualifiedPayables {
            payables: qualified_payable_accounts
                .into_iter()
                .map(|payable| QualifiedPayablesBeforeGasPriceSelection::new(payable, None))
                .collect::<Vec<_>>(),
        };
        assert_eq!(
            result,
            Ok(QualifiedPayablesMessage {
                qualified_payables: expected_unpriced_qualified_payables,
                consuming_wallet,
                response_skeleton_opt: None,
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for new payables"),
            &format!(
                "INFO: {test_name}: Chose {} qualified debts to pay",
                qualified_payables_count
            ),
        ])
    }

    #[test]
    fn new_payable_scanner_cannot_be_initiated_if_it_is_already_running() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let (_, _, all_non_pending_payables) = make_qualified_and_unqualified_payables(
            SystemTime::now(),
            &PaymentThresholds::default(),
        );
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);
        let previous_scan_started_at = SystemTime::now();
        let _ = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            previous_scan_started_at,
            None,
            &Logger::new("test"),
            true,
        );

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: previous_scan_started_at
            })
        );
    }

    #[test]
    fn new_payable_scanner_throws_error_in_case_no_qualified_payable_is_found() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let (_, unqualified_payable_accounts, _) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);
        let mut subject = make_dull_subject();
        subject.payable = Box::new(
            PayableScannerBuilder::new()
                .payable_dao(payable_dao)
                .build(),
        );

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.scan_started_at(ScanType::Payables).is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(result, Err(StartScanError::NothingToProcess));
    }

    #[test]
    fn retry_payable_scanner_can_initiate_a_scan() {
        //
        // Setup Part:
        // DAOs: PayableDao, FailedPayableDao
        // Fetch data from FailedPayableDao (inject it into Payable Scanner -- allow the change in production code).
        // Scanners constructor will require to create it with the Factory -- try it
        // Configure it such that it returns at least 2 failed tx
        // Once I get those 2 records, I should get hold of those identifiers used in the Payable DAO
        // Update the new balance for those transactions
        // Modify Payable DAO and add another method, that will return just the corresponding payments
        // The account which I get from the PayableDAO can go straight to the QualifiedPayableBeforePriceSelection

        todo!("this must be set up under GH-605");
        // TODO make sure the QualifiedPayableRawPack will express the difference from
        // the NewPayable scanner: The QualifiedPayablesBeforeGasPriceSelection needs to carry
        // `Some(<previous gas price value>)` instead of None
        // init_test_logging();
        // let test_name = "retry_payable_scanner_can_initiate_a_scan";
        // let consuming_wallet = make_paying_wallet(b"consuming wallet");
        // let now = SystemTime::now();
        // let (qualified_payable_accounts, _, all_non_pending_payables) =
        //     make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        // let payable_dao =
        //     PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        // let mut subject = make_dull_subject();
        // let payable_scanner = PayableScannerBuilder::new()
        //     .payable_dao(payable_dao)
        //     .build();
        // subject.payable = Box::new(payable_scanner);
        //
        // let result = subject.start_retry_payable_scan_guarded(
        //     &consuming_wallet,
        //     now,
        //     None,
        //     &Logger::new(test_name),
        // );
        //
        // let timestamp = subject.payable.scan_started_at();
        // assert_eq!(timestamp, Some(now));
        // assert_eq!(
        //     result,
        //     Ok(QualifiedPayablesMessage {
        //         qualified_payables: todo!(""),
        //         consuming_wallet,
        //         response_skeleton_opt: None,
        //     })
        // );
        // TestLogHandler::new().assert_logs_match_in_order(vec![
        //     &format!("INFO: {test_name}: Scanning for retry-required payables"),
        //     &format!(
        //         "INFO: {test_name}: Chose {} qualified debts to pay",
        //         qualified_payable_accounts.len()
        //     ),
        // ])
    }

    #[test]
    fn retry_payable_scanner_panics_in_case_scan_is_already_running() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let (_, _, all_non_pending_payables) = make_qualified_and_unqualified_payables(
            SystemTime::now(),
            &PaymentThresholds::default(),
        );
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);
        let before = SystemTime::now();
        let _ = subject.start_retry_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
        );

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<QualifiedPayablesMessage, StartScanError> = subject
                .start_retry_payable_scan_guarded(
                    &consuming_wallet,
                    SystemTime::now(),
                    None,
                    &Logger::new("test"),
                );
        }))
        .unwrap_err();

        let after = SystemTime::now();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        let expected_needle_1 = "internal error: entered unreachable code: Guard for pending \
        payables should've prevented running the tandem of scanners if the payable scanner was \
        still running. It started ";
        assert!(
            panic_msg.contains(expected_needle_1),
            "We looked for {} but the actual string doesn't contain it: {}",
            expected_needle_1,
            panic_msg
        );
        let expected_needle_2 = "and is still running at ";
        assert!(
            panic_msg.contains(expected_needle_2),
            "We looked for {} but the actual string doesn't contain it: {}",
            expected_needle_2,
            panic_msg
        );
        check_timestamps_in_panic_for_already_running_retry_payable_scanner(
            &panic_msg, before, after,
        )
    }

    fn check_timestamps_in_panic_for_already_running_retry_payable_scanner(
        panic_msg: &str,
        before: SystemTime,
        after: SystemTime,
    ) {
        let system_times = parse_system_time_from_str(panic_msg);
        let first_actual = system_times[0];
        let second_actual = system_times[1];

        assert!(
            before <= first_actual
                && first_actual <= second_actual
                && second_actual <= after,
            "We expected this relationship before({:?}) <= first_actual({:?}) <= second_actual({:?}) \
            <= after({:?}), but it does not hold true",
            before,
            first_actual,
            second_actual,
            after
        );
    }

    #[test]
    #[should_panic(expected = "Complete me with GH-605")]
    fn retry_payable_scanner_panics_in_case_no_qualified_payable_is_found() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let (_, unqualified_payable_accounts, _) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();

        let _ = Scanners::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut subject,
            &consuming_wallet,
            now,
            None,
            &Logger::new("test"),
        );
    }

    #[test]
    fn payable_scanner_handles_sent_payable_message() {
        init_test_logging();
        let test_name = "payable_scanner_handles_sent_payable_message";
        let fingerprints_rowids_params_arc = Arc::new(Mutex::new(vec![]));
        let mark_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let correct_payable_hash_1 = make_tx_hash(0x6f);
        let correct_payable_rowid_1 = 125;
        let correct_payable_wallet_1 = make_wallet("tralala");
        let correct_pending_payable_1 =
            PendingPayable::new(correct_payable_wallet_1.clone(), correct_payable_hash_1);
        let failure_payable_hash_2 = make_tx_hash(0xde);
        let failure_payable_rowid_2 = 126;
        let failure_payable_wallet_2 = make_wallet("hihihi");
        let failure_payable_2 = RpcPayableFailure {
            rpc_error: Error::InvalidResponse(
                "Learn how to write before you send your garbage!".to_string(),
            ),
            recipient_wallet: failure_payable_wallet_2,
            hash: failure_payable_hash_2,
        };
        let correct_payable_hash_3 = make_tx_hash(0x14d);
        let correct_payable_rowid_3 = 127;
        let correct_payable_wallet_3 = make_wallet("booga");
        let correct_pending_payable_3 =
            PendingPayable::new(correct_payable_wallet_3.clone(), correct_payable_hash_3);
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_params(&fingerprints_rowids_params_arc)
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![
                    (correct_payable_rowid_3, correct_payable_hash_3),
                    (correct_payable_rowid_1, correct_payable_hash_1),
                ],
                no_rowid_results: vec![],
            })
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(failure_payable_rowid_2, failure_payable_hash_2)],
                no_rowid_results: vec![],
            })
            .delete_fingerprints_params(&delete_fingerprints_params_arc)
            .delete_fingerprints_result(Ok(()));
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payables_rowids_params(&mark_pending_payables_params_arc)
            .mark_pending_payables_rowids_result(Ok(()))
            .mark_pending_payables_rowids_result(Ok(()));
        let mut payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Left(vec![
                IndividualBatchResult::Pending(correct_pending_payable_1),
                IndividualBatchResult::Failed(failure_payable_2),
                IndividualBatchResult::Pending(correct_pending_payable_3),
            ]),
            response_skeleton_opt: None,
        };
        payable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.payable = Box::new(payable_scanner);
        let aware_of_unresolved_pending_payable_before =
            subject.aware_of_unresolved_pending_payable;

        let payable_scan_result = subject.finish_payable_scan(sent_payable, &logger);

        let is_scan_running = subject.scan_started_at(ScanType::Payables).is_some();
        let aware_of_unresolved_pending_payable_after = subject.aware_of_unresolved_pending_payable;
        assert_eq!(
            payable_scan_result,
            PayableScanResult {
                ui_response_opt: None,
                result: OperationOutcome::NewPendingPayable
            }
        );
        assert_eq!(is_scan_running, false);
        assert_eq!(aware_of_unresolved_pending_payable_before, false);
        assert_eq!(aware_of_unresolved_pending_payable_after, true);
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
                (correct_payable_wallet_3, correct_payable_rowid_3),
                (correct_payable_wallet_1, correct_payable_rowid_1),
            ]]
        );
        let delete_fingerprints_params = delete_fingerprints_params_arc.lock().unwrap();
        assert_eq!(
            *delete_fingerprints_params,
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
    fn entries_must_be_kept_consistent_and_aligned() {
        let wallet_1 = make_wallet("abc");
        let hash_1 = make_tx_hash(123);
        let wallet_2 = make_wallet("def");
        let hash_2 = make_tx_hash(345);
        let wallet_3 = make_wallet("ghi");
        let hash_3 = make_tx_hash(546);
        let wallet_4 = make_wallet("jkl");
        let hash_4 = make_tx_hash(678);
        let pending_payables_owned = vec![
            PendingPayable::new(wallet_1.clone(), hash_1),
            PendingPayable::new(wallet_2.clone(), hash_2),
            PendingPayable::new(wallet_3.clone(), hash_3),
            PendingPayable::new(wallet_4.clone(), hash_4),
        ];
        let pending_payables_ref = pending_payables_owned
            .iter()
            .collect::<Vec<&PendingPayable>>();
        let pending_payable_dao =
            PendingPayableDaoMock::new().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(4, hash_4), (1, hash_1), (3, hash_3), (2, hash_2)],
                no_rowid_results: vec![],
            });
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();

        let (existent, nonexistent) =
            subject.separate_existent_and_nonexistent_fingerprints(&pending_payables_ref);

        assert_eq!(
            existent,
            vec![
                PendingPayableMetadata::new(&wallet_4, hash_4, Some(4)),
                PendingPayableMetadata::new(&wallet_1, hash_1, Some(1)),
                PendingPayableMetadata::new(&wallet_3, hash_3, Some(3)),
                PendingPayableMetadata::new(&wallet_2, hash_2, Some(2)),
            ]
        );
        assert!(nonexistent.is_empty())
    }

    struct TestingMismatchedDataAboutPendingPayables {
        pending_payables: Vec<PendingPayable>,
        common_hash_1: H256,
        common_hash_3: H256,
        intruder_for_hash_2: H256,
    }

    fn prepare_values_for_mismatched_setting() -> TestingMismatchedDataAboutPendingPayables {
        let hash_1 = make_tx_hash(123);
        let hash_2 = make_tx_hash(456);
        let hash_3 = make_tx_hash(789);
        let intruder = make_tx_hash(567);
        let pending_payables = vec![
            PendingPayable::new(make_wallet("abc"), hash_1),
            PendingPayable::new(make_wallet("def"), hash_2),
            PendingPayable::new(make_wallet("ghi"), hash_3),
        ];
        TestingMismatchedDataAboutPendingPayables {
            pending_payables,
            common_hash_1: hash_1,
            common_hash_3: hash_3,
            intruder_for_hash_2: intruder,
        }
    }

    #[test]
    #[should_panic(
        expected = "Inconsistency in two maps, they cannot be matched by hashes. \
    Data set directly sent from BlockchainBridge: \
    [PendingPayable { recipient_wallet: Wallet { kind: Address(0x0000000000000000000000000000000000616263) }, \
    hash: 0x000000000000000000000000000000000000000000000000000000000000007b }, \
    PendingPayable { recipient_wallet: Wallet { kind: Address(0x0000000000000000000000000000000000646566) }, \
    hash: 0x00000000000000000000000000000000000000000000000000000000000001c8 }, \
    PendingPayable { recipient_wallet: Wallet { kind: Address(0x0000000000000000000000000000000000676869) }, \
    hash: 0x0000000000000000000000000000000000000000000000000000000000000315 }], \
    set derived from the DB: \
    TransactionHashes { rowid_results: \
    [(4, 0x000000000000000000000000000000000000000000000000000000000000007b), \
    (1, 0x0000000000000000000000000000000000000000000000000000000000000237), \
    (3, 0x0000000000000000000000000000000000000000000000000000000000000315)], \
    no_rowid_results: [] }"
    )]
    fn two_sourced_information_of_new_pending_payables_and_their_fingerprints_is_not_symmetrical() {
        let vals = prepare_values_for_mismatched_setting();
        let pending_payables_ref = vals
            .pending_payables
            .iter()
            .collect::<Vec<&PendingPayable>>();
        let pending_payable_dao =
            PendingPayableDaoMock::new().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![
                    (4, vals.common_hash_1),
                    (1, vals.intruder_for_hash_2),
                    (3, vals.common_hash_3),
                ],
                no_rowid_results: vec![],
            });
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();

        subject.separate_existent_and_nonexistent_fingerprints(&pending_payables_ref);
    }

    #[test]
    fn symmetry_check_happy_path() {
        let hash_1 = make_tx_hash(123);
        let hash_2 = make_tx_hash(456);
        let hash_3 = make_tx_hash(789);
        let pending_payables_sent_from_blockchain_bridge = vec![
            PendingPayable::new(make_wallet("abc"), hash_1),
            PendingPayable::new(make_wallet("def"), hash_2),
            PendingPayable::new(make_wallet("ghi"), hash_3),
        ];
        let pending_payables_ref = pending_payables_sent_from_blockchain_bridge
            .iter()
            .map(|ppayable| ppayable.hash)
            .collect::<HashSet<H256>>();
        let hashes_from_fingerprints = vec![(hash_1, 3), (hash_2, 5), (hash_3, 6)]
            .iter()
            .map(|(hash, _id)| *hash)
            .collect::<HashSet<H256>>();

        let result = PayableScanner::is_symmetrical(pending_payables_ref, hashes_from_fingerprints);

        assert_eq!(result, true)
    }

    #[test]
    fn symmetry_check_sad_path_for_intruder() {
        let vals = prepare_values_for_mismatched_setting();
        let pending_payables_ref_from_blockchain_bridge = vals
            .pending_payables
            .iter()
            .map(|ppayable| ppayable.hash)
            .collect::<HashSet<H256>>();
        let rowids_and_hashes_from_fingerprints = vec![
            (vals.common_hash_1, 3),
            (vals.intruder_for_hash_2, 5),
            (vals.common_hash_3, 6),
        ]
        .iter()
        .map(|(hash, _rowid)| *hash)
        .collect::<HashSet<H256>>();

        let result = PayableScanner::is_symmetrical(
            pending_payables_ref_from_blockchain_bridge,
            rowids_and_hashes_from_fingerprints,
        );

        assert_eq!(result, false)
    }

    #[test]
    fn symmetry_check_indifferent_to_wrong_order_on_the_input() {
        let hash_1 = make_tx_hash(123);
        let hash_2 = make_tx_hash(456);
        let hash_3 = make_tx_hash(789);
        let pending_payables_sent_from_blockchain_bridge = vec![
            PendingPayable::new(make_wallet("abc"), hash_1),
            PendingPayable::new(make_wallet("def"), hash_2),
            PendingPayable::new(make_wallet("ghi"), hash_3),
        ];
        let bb_returned_p_payables_ref = pending_payables_sent_from_blockchain_bridge
            .iter()
            .map(|ppayable| ppayable.hash)
            .collect::<HashSet<H256>>();
        // Not in ascending order
        let rowids_and_hashes_from_fingerprints = vec![(hash_1, 3), (hash_3, 5), (hash_2, 6)]
            .iter()
            .map(|(hash, _id)| *hash)
            .collect::<HashSet<H256>>();

        let result = PayableScanner::is_symmetrical(
            bb_returned_p_payables_ref,
            rowids_and_hashes_from_fingerprints,
        );

        assert_eq!(result, true)
    }

    #[test]
    #[should_panic(
        expected = "Expected pending payable fingerprints for (tx: 0x0000000000000000000000000000000000000000000000000000000000000315, \
     to wallet: 0x000000000000000000000000000000626f6f6761), (tx: 0x000000000000000000000000000000000000000000000000000000000000007b, \
     to wallet: 0x00000000000000000000000000000061676f6f62) were not found; system unreliable"
    )]
    fn payable_scanner_panics_when_fingerprints_for_correct_payments_not_found() {
        let hash_1 = make_tx_hash(0x315);
        let payment_1 = PendingPayable::new(make_wallet("booga"), hash_1);
        let hash_2 = make_tx_hash(0x7b);
        let payment_2 = PendingPayable::new(make_wallet("agoob"), hash_2);
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![],
                no_rowid_results: vec![hash_1, hash_2],
            });
        let payable_dao = PayableDaoMock::new();
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let mut subject = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Left(vec![
                IndividualBatchResult::Pending(payment_1),
                IndividualBatchResult::Pending(payment_2),
            ]),
            response_skeleton_opt: None,
        };

        let _ = subject.finish_scan(sent_payable, &Logger::new("test"));
    }

    fn assert_panic_from_failing_to_mark_pending_payable_rowid(
        test_name: &str,
        failed_payable_dao: FailedPayableDaoMock,
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
            .failed_payable_dao(failed_payable_dao)
            .build();
        let sent_payables = SentPayables {
            payment_procedure_result: Either::Left(vec![
                IndividualBatchResult::Pending(payable_1),
                IndividualBatchResult::Pending(payable_2),
            ]),
            response_skeleton_opt: None,
        };

        let caught_panic_in_err = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payables, &Logger::new(test_name))
        }));

        let caught_panic = caught_panic_in_err.unwrap_err();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Unable to create a mark in the payable table for wallets 0x00000000000\
        000000000000000626c6168313131, 0x00000000000000000000000000626c6168323232 due to \
         SignConversion(9999999999999)"
        );
    }

    #[test]
    fn payable_scanner_mark_pending_payable_only_panics_all_fingerprints_found() {
        init_test_logging();
        let test_name = "payable_scanner_mark_pending_payable_only_panics_all_fingerprints_found";
        let hash_1 = make_tx_hash(248);
        let hash_2 = make_tx_hash(139);
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(7879, hash_1), (7881, hash_2)],
                no_rowid_results: vec![],
            });

        assert_panic_from_failing_to_mark_pending_payable_rowid(
            test_name,
            failed_payable_dao,
            hash_1,
            hash_2,
        );

        // Missing fingerprints, being an additional issue, would provoke an error log, but not here.
        TestLogHandler::new().exists_no_log_containing(&format!("ERROR: {test_name}:"));
    }

    #[test]
    fn payable_scanner_mark_pending_payable_panics_nonexistent_fingerprints_also_found() {
        init_test_logging();
        let test_name =
            "payable_scanner_mark_pending_payable_panics_nonexistent_fingerprints_also_found";
        let hash_1 = make_tx_hash(0xff);
        let hash_2 = make_tx_hash(0xf8);
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(7881, hash_1)],
                no_rowid_results: vec![hash_2],
            });

        assert_panic_from_failing_to_mark_pending_payable_rowid(
            test_name,
            failed_payable_dao,
            hash_1,
            hash_2,
        );

        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: Expected pending payable \
         fingerprints for (tx: 0x00000000000000000000000000000000000000000000000000000000000000f8, to wallet: \
          0x00000000000000000000000000626c6168323232) were not found; system unreliable"));
    }

    #[test]
    fn payable_scanner_is_facing_failed_transactions_and_their_fingerprints_exist() {
        init_test_logging();
        let test_name =
            "payable_scanner_is_facing_failed_transactions_and_their_fingerprints_exist";
        let get_tx_identifiers_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let tx1_hash = make_tx_hash(0x15b3);
        let tx2_hash = make_tx_hash(0x3039);
        let tx1_rowid = 2;
        let tx2_rowid = 1;
        let tx1 = TxBuilder::default().hash(tx1_hash).nonce(1).build();
        let tx2 = TxBuilder::default().hash(tx2_hash).nonce(2).build();
        let sent_txs = vec![tx1, tx2];
        let system = System::new(test_name);
        let sent_payable_dao = SentPayableDaoMock::default()
            .get_tx_identifiers_params(&get_tx_identifiers_params_arc)
            .retrieve_txs_params(&retrieve_txs_params_arc)
            .delete_records_params(&delete_records_params_arc)
            .get_tx_identifiers_result(TxIdentifiers::from([
                (tx1_hash, tx1_rowid),
                (tx2_hash, tx2_rowid),
            ]))
            .retrieve_txs_result(sent_txs.clone())
            .delete_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let payable_scanner = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Right(LocalPayableError::Sending {
                msg: "Attempt failed".to_string(),
                hashes: vec![tx1_hash, tx2_hash],
            }),
            response_skeleton_opt: None,
        };
        let mut subject = make_dull_subject();
        subject.payable = Box::new(payable_scanner);
        let aware_of_unresolved_pending_payable_before =
            subject.aware_of_unresolved_pending_payable;

        let payable_scan_result = subject.finish_payable_scan(sent_payable, &logger);

        let aware_of_unresolved_pending_payable_after = subject.aware_of_unresolved_pending_payable;
        System::current().stop();
        system.run();
        assert_eq!(
            payable_scan_result,
            PayableScanResult {
                ui_response_opt: None,
                result: OperationOutcome::Failure
            }
        );
        assert_eq!(aware_of_unresolved_pending_payable_before, false);
        assert_eq!(aware_of_unresolved_pending_payable_after, false);
        let get_tx_identifiers_params = get_tx_identifiers_params_arc.lock().unwrap();
        assert_eq!(
            *get_tx_identifiers_params,
            vec![HashSet::from([tx1_hash, tx2_hash])]
        );
        let retrieve_txs_params = retrieve_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_txs_params,
            vec![Some(ByHash(HashSet::from([tx1_hash, tx2_hash])))]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(
            *delete_records_params,
            vec![HashSet::from([tx1_hash, tx2_hash])]
        );
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        let expected_failed_txs: HashSet<FailedTx> = sent_txs
            .iter()
            .map(|tx| FailedTx {
                hash: tx.hash,
                receiver_address: tx.receiver_address,
                amount: tx.amount,
                timestamp: tx.timestamp,
                gas_price_wei: tx.gas_price_wei,
                nonce: tx.nonce,
                reason: FailureReason::LocalSendingFailed,
                status: FailureStatus::RetryRequired,
            })
            .collect();
        assert_eq!(*insert_new_records_params, vec![expected_failed_txs]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Any persisted data from failed process will be deleted. \
            Caused by: Sending phase: \"Attempt failed\". \
            Signed and hashed transactions: \
            0x00000000000000000000000000000000000000000000000000000000000015b3, \
            0x0000000000000000000000000000000000000000000000000000000000003039"
        ));
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: \
            Migrating failed transactions to the FailedPayableDao: \
            0x00000000000000000000000000000000000000000000000000000000000015b3, \
            0x0000000000000000000000000000000000000000000000000000000000003039",
        ));
        // TODO: GH-605: Maybe you'd like to change the comment below
        // we haven't supplied any result for mark_pending_payable() and so it's proved uncalled
    }

    #[test]
    fn payable_scanner_handles_error_born_too_early_to_see_transaction_hash() {
        init_test_logging();
        let test_name = "payable_scanner_handles_error_born_too_early_to_see_transaction_hash";
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Right(LocalPayableError::Signing(
                "Some error".to_string(),
            )),
            response_skeleton_opt: None,
        };
        let payable_scanner = PayableScannerBuilder::new().build();
        let mut subject = make_dull_subject();
        subject.payable = Box::new(payable_scanner);
        let aware_of_unresolved_pending_payable_before =
            subject.aware_of_unresolved_pending_payable;

        subject.finish_payable_scan(sent_payable, &Logger::new(test_name));

        let aware_of_unresolved_pending_payable_after = subject.aware_of_unresolved_pending_payable;
        assert_eq!(aware_of_unresolved_pending_payable_before, false);
        assert_eq!(aware_of_unresolved_pending_payable_after, false);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Got 0 properly sent payables of an unknown number of attempts"
        ));
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Ignoring a non-fatal error on our end from before \
            the transactions are hashed: LocallyCausedError(Signing(\"Some error\"))"
        ));
    }

    #[test]
    fn payable_scanner_finds_fingerprints_for_failed_payments_but_panics_at_their_deletion() {
        let test_name =
            "payable_scanner_finds_fingerprints_for_failed_payments_but_panics_at_their_deletion";
        let rowid_1 = 4;
        let hash_1 = make_tx_hash(0x7b);
        let rowid_2 = 6;
        let hash_2 = make_tx_hash(0x315);
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Right(LocalPayableError::Sending {
                msg: "blah".to_string(),
                hashes: vec![hash_1, hash_2],
            }),
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(rowid_1, hash_1), (rowid_2, hash_2)],
                no_rowid_results: vec![],
            })
            .delete_fingerprints_result(Err(PendingPayableDaoError::RecordDeletion(
                "Gosh, I overslept without an alarm set".to_string(),
            )));
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();

        let caught_panic_in_err = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payable, &Logger::new(test_name))
        }));

        let caught_panic = caught_panic_in_err.unwrap_err();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Database corrupt: payable fingerprint deletion for transactions \
        0x000000000000000000000000000000000000000000000000000000000000007b, 0x00000000000000000000\
        00000000000000000000000000000000000000000315 failed due to RecordDeletion(\"Gosh, I overslept \
        without an alarm set\")");
        let log_handler = TestLogHandler::new();
        // There is a possible situation when we stumble over missing fingerprints, so we log it.
        // Here we don't and so any ERROR log shouldn't turn up
        log_handler.exists_no_log_containing(&format!("ERROR: {}", test_name))
    }

    #[test]
    fn payable_scanner_panics_for_missing_fingerprints_but_deletion_of_some_works() {
        init_test_logging();
        let test_name =
            "payable_scanner_panics_for_missing_fingerprints_but_deletion_of_some_works";
        let hash_1 = make_tx_hash(0x1b669);
        let hash_2 = make_tx_hash(0x3039);
        let hash_3 = make_tx_hash(0x223d);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(333, hash_1)],
                no_rowid_results: vec![hash_2, hash_3],
            })
            .delete_fingerprints_result(Ok(()));
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Right(LocalPayableError::Sending {
                msg: "SQLite migraine".to_string(),
                hashes: vec![hash_1, hash_2, hash_3],
            }),
            response_skeleton_opt: None,
        };

        let caught_panic_in_err = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payable, &Logger::new(test_name))
        }));

        let caught_panic = caught_panic_in_err.unwrap_err();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(panic_msg, "Ran into failed transactions 0x0000000000000000000000000000000000\
        000000000000000000000000003039, 0x000000000000000000000000000000000000000000000000000000000000223d \
        with missing fingerprints. System no longer reliable");
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            &format!("WARN: {test_name}: Any persisted data from failed process will be deleted. Caused by: \
             Sending phase: \"SQLite migraine\". Signed and hashed transactions: \
               0x000000000000000000000000000000000000000000000000000000000001b669, \
              0x0000000000000000000000000000000000000000000000000000000000003039, \
               0x000000000000000000000000000000000000000000000000000000000000223d"));
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Deleting fingerprints for failed transactions {:?}",
            hash_1
        ));
    }

    #[test]
    fn payable_scanner_for_failed_rpcs_one_fingerprint_missing_and_deletion_of_the_other_one_fails()
    {
        // Two fatal failures at once, missing fingerprints and fingerprint deletion error are both
        // legitimate reasons for panic
        init_test_logging();
        let test_name = "payable_scanner_for_failed_rpcs_one_fingerprint_missing_and_deletion_of_the_other_one_fails";
        let existent_record_hash = make_tx_hash(0xb26e);
        let nonexistent_record_hash = make_tx_hash(0x4d2);
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprints_rowids_result(TransactionHashes {
                rowid_results: vec![(45, existent_record_hash)],
                no_rowid_results: vec![nonexistent_record_hash],
            })
            .delete_fingerprints_result(Err(PendingPayableDaoError::RecordDeletion(
                "Another failure. Really???".to_string(),
            )));
        let failed_payable_dao = todo!("replace pending payable dao with failed payable dao");
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_payment_1 = RpcPayableFailure {
            rpc_error: Error::Unreachable,
            recipient_wallet: make_wallet("abc"),
            hash: existent_record_hash,
        };
        let failed_payment_2 = RpcPayableFailure {
            rpc_error: Error::Internal,
            recipient_wallet: make_wallet("def"),
            hash: nonexistent_record_hash,
        };
        let sent_payable = SentPayables {
            payment_procedure_result: Either::Left(vec![
                IndividualBatchResult::Failed(failed_payment_1),
                IndividualBatchResult::Failed(failed_payment_2),
            ]),
            response_skeleton_opt: None,
        };

        let caught_panic_in_err = catch_unwind(AssertUnwindSafe(|| {
            subject.finish_scan(sent_payable, &Logger::new(test_name))
        }));

        let caught_panic = caught_panic_in_err.unwrap_err();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Database corrupt: payable fingerprint deletion for transactions 0x00000000000000000000000\
         0000000000000000000000000000000000000b26e failed due to RecordDeletion(\"Another failure. Really???\")");
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Remote transaction failure: 'Server is unreachable' \
         for payment to 0x0000000000000000000000000000000000616263 and transaction hash 0x00000000000000000000000\
         0000000000000000000000000000000000000b26e. Please check your blockchain service URL configuration."));
        log_handler.exists_log_containing(&format!("WARN: {test_name}: Remote transaction failure: 'Internal Web3 error' \
        for payment to 0x0000000000000000000000000000000000646566 and transaction hash 0x000000000000000000000000\
        00000000000000000000000000000000000004d2. Please check your blockchain service URL configuration."));
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Got 0 properly sent payables of 2 attempts"
        ));
        log_handler.exists_log_containing(&format!("ERROR: {test_name}: Ran into failed transactions 0x0000000000000000\
        0000000000000000000000000000000000000000000004d2 with missing fingerprints. System no longer reliable"));
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
        // No panic and so no other method was called, which means an early return
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
        let time = to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 - 1;
        let unqualified_payable_account = vec![PayableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: debt,
            last_paid_timestamp: from_unix_timestamp(time),
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
            last_paid_timestamp: from_unix_timestamp(time),
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
            last_paid_timestamp: from_unix_timestamp(
                to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 + 1,
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
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
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
            attempt: 1,
            amount: 7999,
            process_error: None,
        };
        let fingerprints = vec![payable_fingerprint_1, payable_fingerprint_2];
        let pending_payable_dao = PendingPayableDaoMock::new()
            .return_all_errorless_fingerprints_result(fingerprints.clone());
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.payable = Box::new(payable_scanner);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let no_of_pending_payables = fingerprints.len();
        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                pending_payable_fingerprints: fingerprints,
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
    fn pending_payable_scanner_cannot_be_initiated_if_it_itself_is_already_running() {
        let now = SystemTime::now();
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_dao = PendingPayableDaoMock::new()
            .return_all_errorless_fingerprints_result(vec![make_pending_payable_fingerprint()]);
        let pending_payable_scanner = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.payable = Box::new(payable_scanner);
        let logger = Logger::new("test");
        let _ =
            subject.start_pending_payable_scan_guarded(&consuming_wallet, now, None, &logger, true);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &logger,
            true,
        );

        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: now
            })
        );
    }

    #[test]
    fn pending_payable_scanner_cannot_be_initiated_if_payable_scanner_is_still_running() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let payable_scanner = PayableScannerBuilder::new().build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.payable = Box::new(payable_scanner);
        let logger = Logger::new("test");
        let previous_scan_started_at = SystemTime::now();
        subject.payable.mark_as_started(previous_scan_started_at);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &logger,
            true,
        );

        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: Some(ScanType::Payables),
                started_at: previous_scan_started_at
            })
        );
    }

    #[test]
    fn both_payable_scanners_cannot_be_detected_in_progress_at_the_same_time() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.payable = Box::new(payable_scanner);
        let timestamp_pending_payable_start = SystemTime::now()
            .checked_sub(Duration::from_millis(12))
            .unwrap();
        let timestamp_payable_scanner_start = SystemTime::now();
        subject.aware_of_unresolved_pending_payable = true;
        subject
            .pending_payable
            .mark_as_started(timestamp_pending_payable_start);
        subject
            .payable
            .mark_as_started(timestamp_payable_scanner_start);

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = subject.start_pending_payable_scan_guarded(
                &consuming_wallet,
                SystemTime::now(),
                None,
                &Logger::new("test"),
                true,
            );
        }))
        .unwrap_err();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        let expected_msg_fragment_1 = "internal error: entered unreachable code: Any payable-\
        related scanners should never be allowed to run in parallel. Scan for pending payables \
        started at: ";
        assert!(
            panic_msg.contains(expected_msg_fragment_1),
            "This fragment '{}' wasn't found in \
        '{}'",
            expected_msg_fragment_1,
            panic_msg
        );
        let expected_msg_fragment_2 = ", scan for payables started at: ";
        assert!(
            panic_msg.contains(expected_msg_fragment_2),
            "This fragment '{}' wasn't found in \
        '{}'",
            expected_msg_fragment_2,
            panic_msg
        );
        assert_timestamps_from_str(
            panic_msg,
            vec![
                timestamp_pending_payable_start,
                timestamp_payable_scanner_start,
            ],
        )
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Automatic pending payable \
    scan should never start if there are no pending payables to process."
    )]
    fn pending_payable_scanner_bumps_into_zero_pending_payable_awareness_in_the_automatic_mode() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.aware_of_unresolved_pending_payable = false;

        let _ = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );
    }

    #[test]
    fn pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found() {
        let now = SystemTime::now();
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_errorless_fingerprints_result(vec![]);
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();

        let result =
            pending_payable_scanner.start_scan(&consuming_wallet, now, None, &Logger::new("test"));

        let is_scan_running = pending_payable_scanner.scan_started_at().is_some();
        assert_eq!(result, Err(StartScanError::NothingToProcess));
        assert_eq!(is_scan_running, false);
    }

    #[test]
    fn check_general_conditions_for_pending_payable_scan_if_it_is_initial_pending_payable_scan() {
        let mut subject = make_dull_subject();
        subject.initial_pending_payable_scan = true;

        let result = subject.check_general_conditions_for_pending_payable_scan(false, true);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.initial_pending_payable_scan, true);
    }

    fn assert_interpreting_none_status_for_pending_payable(
        test_name: &str,
        when_pending_too_long_sec: u64,
        pending_payable_age_sec: u64,
        rowid: u64,
        hash: H256,
    ) -> PendingPayableScanReport {
        init_test_logging();
        let when_sent = SystemTime::now().sub(Duration::from_secs(pending_payable_age_sec));
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

        handle_none_status(scan_report, fingerprint, when_pending_too_long_sec, &logger)
    }

    fn assert_log_msg_and_elapsed_time_in_log_makes_sense(
        expected_msg: &str,
        elapsed_after: u64,
        capture_regex: &str,
    ) {
        let log_handler = TestLogHandler::default();
        let log_idx = log_handler.exists_log_matching(expected_msg);
        let log = log_handler.get_log_at(log_idx);
        let capture = captures_for_regex_time_in_sec(&log, capture_regex);
        assert!(capture <= elapsed_after)
    }

    fn captures_for_regex_time_in_sec(stack: &str, capture_regex: &str) -> u64 {
        let capture_regex = Regex::new(capture_regex).unwrap();
        let time_str = capture_regex
            .captures(stack)
            .unwrap()
            .get(1)
            .unwrap()
            .as_str();
        time_str.parse().unwrap()
    }

    fn elapsed_since_secs_back(sec: u64) -> u64 {
        SystemTime::now()
            .sub(Duration::from_secs(sec))
            .elapsed()
            .unwrap()
            .as_secs()
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval";
        let hash = make_tx_hash(0x237);
        let rowid = 466;

        let result = assert_interpreting_none_status_for_pending_payable(
            test_name,
            DEFAULT_PENDING_TOO_LONG_SEC,
            DEFAULT_PENDING_TOO_LONG_SEC + 1,
            rowid,
            hash,
        );

        let elapsed_after = elapsed_since_secs_back(DEFAULT_PENDING_TOO_LONG_SEC + 1);
        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![],
                failures: vec![PendingPayableId::new(rowid, hash)],
                confirmed: vec![]
            }
        );
        let capture_regex = "(\\d+){2}sec";
        assert_log_msg_and_elapsed_time_in_log_makes_sense(&format!(
            "ERROR: {}: Pending transaction 0x00000000000000000000000000000000000000\
            00000000000000000000000237 has exceeded the maximum pending time \\({}sec\\) with the age \
            \\d+sec and the confirmation process is going to be aborted now at the final attempt 1; manual \
            resolution is required from the user to complete the transaction"
            , test_name, DEFAULT_PENDING_TOO_LONG_SEC, ), elapsed_after, capture_regex)
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval";
        let hash = make_tx_hash(0x7b);
        let rowid = 333;
        let pending_payable_age = DEFAULT_PENDING_TOO_LONG_SEC - 1;

        let result = assert_interpreting_none_status_for_pending_payable(
            test_name,
            DEFAULT_PENDING_TOO_LONG_SEC,
            pending_payable_age,
            rowid,
            hash,
        );

        let elapsed_after_ms = elapsed_since_secs_back(pending_payable_age) * 1000;
        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![PendingPayableId::new(rowid, hash)],
                failures: vec![],
                confirmed: vec![]
            }
        );
        let capture_regex = r#"\s(\d+)ms"#;
        assert_log_msg_and_elapsed_time_in_log_makes_sense(&format!(
            "INFO: {test_name}: Pending transaction 0x0000000000000000000000000000000000000000000000000\
            00000000000007b couldn't be confirmed at attempt 1 at \\d+ms after its sending"), elapsed_after_ms, capture_regex);
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_time_equals_the_limit() {
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_none_and_time_equals_the_limit";
        let hash = make_tx_hash(0x237);
        let rowid = 466;
        let pending_payable_age = DEFAULT_PENDING_TOO_LONG_SEC;

        let result = assert_interpreting_none_status_for_pending_payable(
            test_name,
            DEFAULT_PENDING_TOO_LONG_SEC,
            pending_payable_age,
            rowid,
            hash,
        );

        let elapsed_after_ms = elapsed_since_secs_back(pending_payable_age) * 1000;
        assert_eq!(
            result,
            PendingPayableScanReport {
                still_pending: vec![PendingPayableId::new(rowid, hash)],
                failures: vec![],
                confirmed: vec![]
            }
        );
        let capture_regex = r#"\s(\d+)ms"#;
        assert_log_msg_and_elapsed_time_in_log_makes_sense(&format!(
            "INFO: {test_name}: Pending transaction 0x0000000000000000000000000000000000000000000000000\
            000000000000237 couldn't be confirmed at attempt 1 at \\d+ms after its sending",
        ), elapsed_after_ms, capture_regex);
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let test_name = "interpret_transaction_receipt_when_transaction_status_is_a_failure";
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = make_tx_hash(0xd7);
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

        let result = handle_status_with_failure(scan_report, fingerprint, &logger);

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
            0000000000000000000000d7 announced as a failure, interpreting attempt 5 after \
            1500\\d\\dms from the sending"
        ));
    }

    #[test]
    fn handle_pending_txs_with_receipts_handles_none_for_receipt() {
        init_test_logging();
        let test_name = "handle_pending_txs_with_receipts_handles_none_for_receipt";
        let subject = PendingPayableScannerBuilder::new().build();
        let rowid = 455;
        let hash = make_tx_hash(0x913);
        let fingerprint = PendingPayableFingerprint {
            rowid,
            timestamp: SystemTime::now().sub(Duration::from_millis(10000)),
            hash,
            attempt: 3,
            amount: 111,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(
                TransactionReceiptResult::RpcResponse(TxReceipt {
                    transaction_hash: hash,
                    status: TxStatus::Pending,
                }),
                fingerprint.clone(),
            )],
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
        let update_remaining_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(444888);
        let rowid_1 = 3456;
        let hash_2 = make_tx_hash(444888);
        let rowid_2 = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .increment_scan_attempts_params(&update_remaining_fingerprints_params_arc)
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

        let update_remaining_fingerprints_params =
            update_remaining_fingerprints_params_arc.lock().unwrap();
        assert_eq!(
            *update_remaining_fingerprints_params,
            vec![vec![rowid_1, rowid_2]]
        )
    }

    #[test]
    #[should_panic(
        expected = "Failure on incrementing scan attempts for fingerprints of \
                0x000000000000000000000000000000000000000000000000000000000006c9d8 \
                due to UpdateFailed(\"yeah, bad\")"
    )]
    fn increment_scan_attempts_sad_path() {
        let hash = make_tx_hash(0x6c9d8);
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
    fn cancel_failed_transactions_works() {
        init_test_logging();
        let test_name = "cancel_failed_transactions_works";
        let mark_failures_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failures_params(&mark_failures_params_arc)
            .mark_failures_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .pending_payable_dao(pending_payable_dao)
            .build();
        let id_1 = PendingPayableId::new(2, make_tx_hash(0x7b));
        let id_2 = PendingPayableId::new(3, make_tx_hash(0x1c8));

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
    fn cancel_failed_transactions_panics_when_it_fails_to_mark_failure() {
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
    fn cancel_failed_transactions_does_nothing_if_no_tx_failures_detected() {
        let subject = PendingPayableScannerBuilder::new().build();

        subject.cancel_failed_transactions(vec![], &Logger::new("test"))

        //mocked pending payable DAO didn't panic which means we skipped the actual process
    }

    #[test]
    #[should_panic(
        expected = "Unable to delete payable fingerprints 0x000000000000000000000000000000000\
        0000000000000000000000000000315, 0x00000000000000000000000000000000000000000000000000\
        0000000000021a of verified transactions due to RecordDeletion(\"the database \
        is fooling around with us\")"
    )]
    fn confirm_transactions_panics_while_deleting_pending_payable_fingerprint() {
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
        let mut fingerprint_1 = make_pending_payable_fingerprint();
        fingerprint_1.rowid = 1;
        fingerprint_1.hash = make_tx_hash(0x315);
        let mut fingerprint_2 = make_pending_payable_fingerprint();
        fingerprint_2.rowid = 1;
        fingerprint_2.hash = make_tx_hash(0x21a);

        subject.confirm_transactions(vec![fingerprint_1, fingerprint_2], &Logger::new("test"));
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
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_fingerprints_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .delete_fingerprints_params(&delete_fingerprints_params_arc)
            .delete_fingerprints_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let rowid_1 = 2;
        let rowid_2 = 5;
        let pending_payable_fingerprint_1 = PendingPayableFingerprint {
            rowid: rowid_1,
            timestamp: from_unix_timestamp(199_000_000),
            hash: make_tx_hash(0x123),
            attempt: 1,
            amount: 4567,
            process_error: None,
        };
        let pending_payable_fingerprint_2 = PendingPayableFingerprint {
            rowid: rowid_2,
            timestamp: from_unix_timestamp(200_000_000),
            hash: make_tx_hash(0x567),
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

        let confirm_transactions_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *confirm_transactions_params,
            vec![vec![
                pending_payable_fingerprint_1,
                pending_payable_fingerprint_2
            ]]
        );
        let delete_fingerprints_params = delete_fingerprints_params_arc.lock().unwrap();
        assert_eq!(*delete_fingerprints_params, vec![vec![rowid_1, rowid_2]]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(
            "DEBUG: confirm_transactions_works: \
         Confirmation of transactions \
         0x0000000000000000000000000000000000000000000000000000000000000123, \
         0x0000000000000000000000000000000000000000000000000000000000000567; \
         record for total paid payable was modified",
        );
        log_handler.exists_log_containing(
            "INFO: confirm_transactions_works: \
         Transactions \
         0x0000000000000000000000000000000000000000000000000000000000000123, \
         0x0000000000000000000000000000000000000000000000000000000000000567 \
         completed their confirmation process succeeding",
        );
    }

    #[test]
    #[should_panic(
        expected = "Unable to cast confirmed pending payables 0x0000000000000000000000000000000000000000000\
    000000000000000000315 into adjustment in the corresponding payable records due to RusqliteError\
    (\"record change not successful\")"
    )]
    fn confirm_transactions_panics_on_unchecking_payable_table() {
        let hash = make_tx_hash(0x315);
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
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 5,
            timestamp: from_unix_timestamp(189_999_888),
            hash: make_tx_hash(56789),
            attempt: 1,
            amount: 5478,
            process_error: None,
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 6,
            timestamp: from_unix_timestamp(200_000_011),
            hash: make_tx_hash(33333),
            attempt: 1,
            amount: 6543,
            process_error: None,
        };
        let payable_dao = PayableDaoMock::default().transactions_confirmed_result(Ok(()));
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
        assert_eq!(total_paid_payable, 1111 + 5478 + 6543);
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
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .pending_payable_dao(pending_payable_dao)
            .build();
        let transaction_hash_1 = make_tx_hash(4545);
        let transaction_receipt_1 = TxReceipt {
            transaction_hash: transaction_hash_1,
            status: TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: U64::from(1234),
            }),
        };
        let fingerprint_1 = PendingPayableFingerprint {
            rowid: 5,
            timestamp: from_unix_timestamp(200_000_000),
            hash: transaction_hash_1,
            attempt: 2,
            amount: 444,
            process_error: None,
        };
        let transaction_hash_2 = make_tx_hash(1234);
        let transaction_receipt_2 = TxReceipt {
            transaction_hash: transaction_hash_2,
            status: TxStatus::Succeeded(TransactionBlock {
                block_hash: Default::default(),
                block_number: U64::from(2345),
            }),
        };
        let fingerprint_2 = PendingPayableFingerprint {
            rowid: 10,
            timestamp: from_unix_timestamp(199_780_000),
            hash: transaction_hash_2,
            attempt: 15,
            amount: 1212,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![
                (
                    TransactionReceiptResult::RpcResponse(transaction_receipt_1),
                    fingerprint_1.clone(),
                ),
                (
                    TransactionReceiptResult::RpcResponse(transaction_receipt_2),
                    fingerprint_2.clone(),
                ),
            ],
            response_skeleton_opt: None,
        };
        pending_payable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.pending_payable = Box::new(pending_payable_scanner);

        let result = subject.finish_pending_payable_scan(msg, &Logger::new(test_name));

        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            result,
            PendingPayableScanResult::NoPendingPayablesLeft(None)
        );
        assert_eq!(
            *transactions_confirmed_params,
            vec![vec![fingerprint_1, fingerprint_2]]
        );
        assert_eq!(subject.scan_started_at(ScanType::PendingPayables), None);
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
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![],
            response_skeleton_opt: None,
        };
        pending_payable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.pending_payable = Box::new(pending_payable_scanner);

        let result = subject.finish_pending_payable_scan(msg, &Logger::new(test_name));

        let is_scan_running = subject.scan_started_at(ScanType::PendingPayables).is_some();
        assert_eq!(
            result,
            PendingPayableScanResult::NoPendingPayablesLeft(None)
        );
        assert_eq!(is_scan_running, false);
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "WARN: {test_name}: No transaction receipts found."
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
        let mut subject = make_dull_subject();
        let receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .build();
        subject.receivable = Box::new(receivable_scanner);

        let result = subject.start_receivable_scan_guarded(
            &earning_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let is_scan_running = subject.receivable.scan_started_at().is_some();
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
        let mut subject = make_dull_subject();
        let receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .build();
        subject.receivable = Box::new(receivable_scanner);
        let _ = subject.start_receivable_scan_guarded(
            &earning_wallet,
            now,
            None,
            &Logger::new("test"),
            true,
        );

        let result = subject.start_receivable_scan_guarded(
            &earning_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.receivable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: now
            })
        );
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
            .build();
        let logger = Logger::new("DELINQUENCY_TEST");
        let now = SystemTime::now();

        let result = receivable_scanner.start_scan(&earning_wallet, now, None, &logger);

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
    fn receivable_scanner_handles_no_new_payments_found() {
        init_test_logging();
        let test_name = "receivable_scanner_handles_no_new_payments_found";
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let new_start_block = BlockMarker::Value(4321);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let receivable_scanner = ReceivableScannerBuilder::new()
            .persistent_configuration(persistent_config)
            .build();
        let msg = ReceivedPayments {
            timestamp: SystemTime::now(),
            new_start_block,
            response_skeleton_opt: None,
            transactions: vec![],
        };
        let mut subject = make_dull_subject();
        subject.receivable = Box::new(receivable_scanner);

        let ui_msg_opt = subject.finish_receivable_scan(msg, &Logger::new(test_name));

        assert_eq!(ui_msg_opt, None);
        let set_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*set_start_block_params, vec![Some(4321)]);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: No newly received payments were detected during the scanning process."
        ));
    }

    #[test]
    #[should_panic(expected = "Attempt to set new start block to 6709 failed due to: \
    UninterpretableValue(\"Illiterate database manager\")")]
    fn no_transactions_received_but_start_block_setting_fails() {
        init_test_logging();
        let test_name = "no_transactions_received_but_start_block_setting_fails";
        let now = SystemTime::now();
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let new_start_block = BlockMarker::Value(6709u64);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Err(PersistentConfigError::UninterpretableValue(
                "Illiterate database manager".to_string(),
            )));
        let mut subject = ReceivableScannerBuilder::new()
            .persistent_configuration(persistent_config)
            .build();
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block,
            response_skeleton_opt: None,
            transactions: vec![],
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    fn receivable_scanner_handles_received_payments_message() {
        init_test_logging();
        let test_name = "receivable_scanner_handles_received_payments_message";
        let now = SystemTime::now();
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let set_start_block_from_txn_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_id = ArbitraryIdStamp::new();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default()
            .commit_params(&commit_params_arc)
            .commit_result(Ok(()))
            .set_arbitrary_id_stamp(transaction_id);
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_params(&set_start_block_from_txn_params_arc)
            .set_start_block_from_txn_result(Ok(()));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_params(&more_money_received_params_arc)
            .more_money_received_result(transaction);
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let mut financial_statistics = receivable_scanner.financial_statistics.borrow().clone();
        financial_statistics.total_paid_receivable_wei += 2_222_123_123;
        receivable_scanner
            .financial_statistics
            .replace(financial_statistics);
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
            new_start_block: BlockMarker::Value(7890123),
            response_skeleton_opt: None,
            transactions: receivables.clone(),
        };
        receivable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.receivable = Box::new(receivable_scanner);

        let ui_msg_opt = subject.finish_receivable_scan(msg, &Logger::new(test_name));

        let scanner_after = subject
            .receivable
            .as_any()
            .downcast_ref::<ReceivableScanner>()
            .unwrap();
        let total_paid_receivable = scanner_after
            .financial_statistics
            .borrow()
            .total_paid_receivable_wei;
        assert_eq!(ui_msg_opt, None);
        assert_eq!(scanner_after.scan_started_at(), None);
        assert_eq!(total_paid_receivable, 2_222_123_123 + 45_780 + 3_333_345);
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
        let set_by_guest_transaction_params = set_start_block_from_txn_params_arc.lock().unwrap();
        assert_eq!(
            *set_by_guest_transaction_params,
            vec![(Some(7890123u64), transaction_id)]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
        TestLogHandler::new().exists_log_matching(
            "INFO: receivable_scanner_handles_received_payments_message: The Receivables scan ended in \\d+ms.",
        );
    }

    #[test]
    #[should_panic(
        expected = "entered unreachable code: Failed to get start_block while transactions were present"
    )]
    fn receivable_scanner_panics_when_failing_to_get_start_block_after_receiving_transactions() {
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default();
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new().start_block_result(Ok(None));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("wallet_1"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: SystemTime::now(),
            new_start_block: BlockMarker::Uninitialized,
            response_skeleton_opt: None,
            transactions: receivables,
        };
        subject.mark_as_started(SystemTime::now());

        let _ = subject.finish_scan(msg, &Logger::new("test"));
    }

    #[test]
    #[should_panic(expected = "Attempt to set new start block to 7890123 failed due to: \
    DatabaseError(\"Fatigue\")")]
    fn received_transactions_processed_but_start_block_setting_fails() {
        init_test_logging();
        let test_name = "received_transactions_processed_but_start_block_setting_fails";
        let now = SystemTime::now();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default();
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_result(Err(PersistentConfigError::DatabaseError(
                "Fatigue".to_string(),
            )));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("abc"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block: BlockMarker::Value(7890123),
            response_skeleton_opt: None,
            transactions: receivables,
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    #[should_panic(
        expected = "Commit of received transactions failed: SqliteFailure(Error { code: \
    InternalMalfunction, extended_code: 0 }, Some(\"blah\"))"
    )]
    fn transaction_for_balance_start_block_updates_fails_on_its_commit() {
        init_test_logging();
        let test_name = "transaction_for_balance_start_block_updates_fails_on_its_commit";
        let now = SystemTime::now();
        let commit_err = Err(rusqlite::Error::SqliteFailure(
            ffi::Error {
                code: ErrorCode::InternalMalfunction,
                extended_code: 0,
            },
            Some("blah".to_string()),
        ));
        let txn_inner_builder =
            TransactionInnerWrapperMockBuilder::default().commit_result(commit_err);
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_result(Ok(()));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("abc"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block: BlockMarker::Value(0),
            response_skeleton_opt: None,
            transactions: receivables,
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    fn signal_scanner_completion_and_log_if_timestamp_is_correct() {
        init_test_logging();
        let test_name = "signal_scanner_completion_and_log_if_timestamp_is_correct";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        let start = from_unix_timestamp(1_000_000_000);
        let end = start.checked_add(Duration::from_millis(145)).unwrap();
        subject.initiated_at_opt = Some(start);

        subject.signal_scanner_completion(ScanType::Payables, end, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: The Payables scan ended in 145ms."
        ));
    }

    #[test]
    fn signal_scanner_completion_and_log_if_timestamp_is_not_found() {
        init_test_logging();
        let test_name = "signal_scanner_completion_and_log_if_timestamp_is_not_found";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        subject.initiated_at_opt = None;

        subject.signal_scanner_completion(ScanType::Receivables, SystemTime::now(), &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Called scan_finished() for Receivables scanner but timestamp was not found"
        ));
    }

    fn assert_elapsed_time_in_mark_as_ended<EndMessage: Message, ScanResult>(
        subject: &mut dyn Scanner<EndMessage, ScanResult>,
        scanner_name: &str,
        test_name: &str,
        logger: &Logger,
        log_handler: &TestLogHandler,
    ) {
        let before = SystemTime::now();
        subject.mark_as_started(before);

        subject.mark_as_ended(&logger);

        let after = SystemTime::now();
        let idx = log_handler.exists_log_containing(&format!(
            "INFO: {}: The {} scan ended in ",
            test_name, scanner_name
        ));
        let our_log_msg = log_handler.get_log_at(idx);
        let captures = Regex::new(r#"scan ended in (\d*)ms"#)
            .unwrap()
            .captures(&our_log_msg)
            .unwrap();
        let millis_str = captures.get(1).unwrap().as_str();
        let actual_millis = millis_str.parse::<u128>().unwrap();
        let max_millis_elapsed = after.duration_since(before).unwrap().as_millis();
        assert!(
            actual_millis <= max_millis_elapsed,
            "We expected the time elapsed ({}) to be equal or shorter to {}",
            actual_millis,
            max_millis_elapsed
        )
    }

    #[test]
    fn mark_as_ended_computes_elapsed_time_properly_in_each_scanner() {
        init_test_logging();
        let test_name = "mark_as_ended_computes_elapsed_time_properly_in_each_scanner";
        let logger = Logger::new(test_name);
        let log_handler = TestLogHandler::new();

        assert_elapsed_time_in_mark_as_ended::<SentPayables, PayableScanResult>(
            &mut PayableScannerBuilder::new().build(),
            "Payables",
            test_name,
            &logger,
            &log_handler,
        );
        assert_elapsed_time_in_mark_as_ended::<ReportTransactionReceipts, PendingPayableScanResult>(
            &mut PendingPayableScannerBuilder::new().build(),
            "PendingPayables",
            test_name,
            &logger,
            &log_handler,
        );
        assert_elapsed_time_in_mark_as_ended::<ReceivedPayments, Option<NodeToUiMessage>>(
            &mut ReceivableScannerBuilder::new().build(),
            "Receivables",
            test_name,
            &logger,
            &log_handler,
        );
    }

    #[test]
    fn scan_already_running_msg_displays_correctly_if_blocked_by_requested_scan() {
        test_scan_already_running_msg(
            ScanType::PendingPayables,
            None,
            "PendingPayables scan was already initiated at",
            ". Hence, this scan request will be ignored.",
        )
    }

    #[test]
    fn scan_already_running_msg_displays_correctly_if_blocked_by_other_scan_than_directly_requested(
    ) {
        test_scan_already_running_msg(
            ScanType::PendingPayables,
            Some(ScanType::Payables),
            "Payables scan was already initiated at",
            ". Hence, the PendingPayables scan request will be ignored.",
        )
    }

    fn test_scan_already_running_msg(
        requested_scan: ScanType,
        cross_scan_blocking_cause_opt: Option<ScanType>,
        expected_leading_msg_fragment: &str,
        expected_trailing_msg_fragment: &str,
    ) {
        let some_time = SystemTime::now();

        let result = StartScanError::scan_already_running_msg(
            requested_scan,
            cross_scan_blocking_cause_opt,
            some_time,
        );

        assert!(
            result.contains(expected_leading_msg_fragment),
            "We expected {} but the msg is: {}",
            expected_leading_msg_fragment,
            result
        );
        assert!(
            result.contains(expected_trailing_msg_fragment),
            "We expected {} but the msg is: {}",
            expected_trailing_msg_fragment,
            result
        );
        assert_timestamps_from_str(&result, vec![some_time]);
    }

    #[test]
    fn acknowledge_scan_error_works() {
        fn scan_error(scan_type: ScanType) -> ScanError {
            ScanError {
                scan_type,
                response_skeleton_opt: None,
                msg: "bluh".to_string(),
            }
        }

        init_test_logging();
        let test_name = "acknowledge_scan_error_works";
        let inputs: Vec<(
            ScanType,
            Box<dyn Fn(&mut Scanners)>,
            Box<dyn Fn(&Scanners) -> Option<SystemTime>>,
        )> = vec![
            (
                ScanType::Payables,
                Box::new(|subject| subject.payable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.payable.scan_started_at()),
            ),
            (
                ScanType::PendingPayables,
                Box::new(|subject| subject.pending_payable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.pending_payable.scan_started_at()),
            ),
            (
                ScanType::Receivables,
                Box::new(|subject| subject.receivable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.receivable.scan_started_at()),
            ),
        ];
        let mut subject = make_dull_subject();
        subject.payable = Box::new(PayableScannerBuilder::new().build());
        subject.pending_payable = Box::new(PendingPayableScannerBuilder::new().build());
        subject.receivable = Box::new(ReceivableScannerBuilder::new().build());
        let logger = Logger::new(test_name);
        let test_log_handler = TestLogHandler::new();

        inputs
            .into_iter()
            .for_each(|(scan_type, set_started, get_started_at)| {
                set_started(&mut subject);
                let started_at_before = get_started_at(&subject);

                subject.acknowledge_scan_error(&scan_error(scan_type), &logger);

                let started_at_after = get_started_at(&subject);
                assert!(
                    started_at_before.is_some(),
                    "Should've been started for {:?}",
                    scan_type
                );
                assert_eq!(
                    started_at_after, None,
                    "Should've been unset for {:?}",
                    scan_type
                );
                test_log_handler.exists_log_containing(&format!(
                    "INFO: {test_name}: The {:?} scan ended in",
                    scan_type
                ));
            })
    }

    #[test]
    fn log_error_works_fine() {
        init_test_logging();
        let test_name = "log_error_works_fine";
        let now = SystemTime::now();
        let input: Vec<(StartScanError, Box<dyn Fn(&str) -> String>, &str, &str)> = vec![
            (
                StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: None,
                    started_at: now,
                },
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: Payables scan was already initiated at {}",
                        StartScanError::timestamp_as_string(now)
                    )
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::ManualTriggerError(MTError::AutomaticScanConflict),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied. Automatic mode prevents manual triggers.")
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::ManualTriggerError(MTError::UnnecessaryRequest {
                    hint_opt: Some("Wise words".to_string()),
                }),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied expecting zero findings. Wise words")
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::ManualTriggerError(MTError::UnnecessaryRequest { hint_opt: None }),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied expecting zero findings.")
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::CalledFromNullScanner,
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: Called from NullScanner, not the Payables scanner."
                    )
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::NoConsumingWalletFound,
                Box::new(|sev| {
                    format!("{sev}: {test_name}: Cannot initiate Payables scan because no consuming wallet was found.")
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::NothingToProcess,
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: There was nothing to process during Payables scan."
                    )
                }),
                "INFO",
                "DEBUG",
            ),
        ];
        let logger = Logger::new(test_name);
        let test_log_handler = TestLogHandler::new();

        input.into_iter().for_each(
            |(
                err,
                form_expected_log_msg,
                log_severity_for_externally_triggered_scans,
                log_severity_for_automatic_scans,
            )| {
                let test_log_error_by_mode =
                    |is_externally_triggered: bool, expected_severity: &str| {
                        err.log_error(&logger, ScanType::Payables, is_externally_triggered);
                        let expected_log_msg = form_expected_log_msg(expected_severity);
                        test_log_handler.exists_log_containing(&expected_log_msg);
                    };

                test_log_error_by_mode(true, log_severity_for_externally_triggered_scans);

                test_log_error_by_mode(false, log_severity_for_automatic_scans);
            },
        );
    }

    fn make_dull_subject() -> Scanners {
        Scanners {
            payable: Box::new(NullScanner::new()),
            aware_of_unresolved_pending_payable: false,
            initial_pending_payable_scan: false,
            pending_payable: Box::new(NullScanner::new()),
            receivable: Box::new(NullScanner::new()),
        }
    }
}
