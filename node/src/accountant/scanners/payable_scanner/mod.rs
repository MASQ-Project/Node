pub mod test_utils;

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::SystemTime;
use ethereum_types::H256;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use crate::accountant::db_access_objects::failed_payable_dao::{FailedPayableDao, FailedTx, FailureReason, FailureStatus};
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDao;
use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::{comma_joined_stringifiable, gwei_to_wei, join_with_separator, ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables, SentPayables};
use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::Submission;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::ByHash;
use crate::accountant::db_access_objects::utils::{TxHash, TxIdentifiers};
use crate::accountant::scanners::payable_scanner_extension::msgs::{BlockchainAgentWithContextMessage, QualifiedPayablesMessage, UnpricedQualifiedPayables};
use crate::accountant::scanners::payable_scanner_extension::{MultistageDualPayableScanner, PreparedAdjustment, SolvencySensitivePaymentInstructor};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{investigate_debt_extremes, payables_debug_summary, OperationOutcome, PayableScanResult, PayableThresholdsGauge, PayableThresholdsGaugeReal, PayableTransactingErrorEnum};
use crate::accountant::scanners::{Scanner, ScannerCommon, StartScanError, StartableScanner};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableTransactingErrorEnum::{LocallyCausedError, RemotelyCausedErrors};
use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError;
use crate::blockchain::blockchain_interface::data_structures::{IndividualBatchResult, RpcPayableFailure};
use crate::blockchain::errors::AppRpcError::Local;
use crate::blockchain::errors::LocalError::Internal;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use masq_lib::messages::ScanType;
use crate::time_marking_methods;

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

        // 1. Fetch all records with RetryRequired
        // 2. Query the txs with the same accounts from the PayableDao
        // 3. Form UnpricedQualifiedPayables, a collection vector
    }
}

impl Scanner<SentPayables, PayableScanResult> for PayableScanner {
    fn finish_scan(&mut self, message: SentPayables, logger: &Logger) -> PayableScanResult {
        let result = self.process_result(message.payment_procedure_result, logger);

        self.mark_as_ended(logger);

        let ui_response_opt = Self::generate_ui_response(message.response_skeleton_opt);

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

    pub fn sniff_out_alarming_payables_and_maybe_log_them(
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

    pub fn payable_exceeded_threshold(
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

    fn map_hashes_to_local_failures(hashes: Vec<TxHash>) -> HashMap<TxHash, FailureReason> {
        hashes
            .into_iter()
            .map(|hash| (hash, FailureReason::Submission(Local(Internal))))
            .collect()
    }

    fn separate_batch_results(
        batch_results: Vec<IndividualBatchResult>,
    ) -> (Vec<PendingPayable>, HashMap<TxHash, FailureReason>) {
        batch_results.into_iter().fold(
            (vec![], HashMap::new()),
            |(mut pending, mut failures), result| {
                match result {
                    IndividualBatchResult::Pending(payable) => {
                        pending.push(payable);
                    }
                    IndividualBatchResult::Failed(RpcPayableFailure {
                        hash, rpc_error, ..
                    }) => {
                        failures.insert(hash, Submission(rpc_error.into()));
                    }
                }
                (pending, failures)
            },
        )
    }

    fn check_pending_payables_in_sent_db(
        &self,
        pending_payables: &[PendingPayable],
        logger: &Logger,
    ) {
        let pending_hashes: HashSet<H256> = pending_payables.iter().map(|pp| pp.hash).collect();
        let sent_payables = self
            .sent_payable_dao
            .retrieve_txs(Some(ByHash(pending_hashes.clone())));
        let sent_hashes: HashSet<H256> = sent_payables.iter().map(|sp| sp.hash).collect();

        let missing_hashes: Vec<TxHash> =
            pending_hashes.difference(&sent_hashes).cloned().collect();

        if !missing_hashes.is_empty() {
            // TODO: GH-605: Test me
            panic!(
                "The following pending payables are missing from the sent payable database: {}",
                Self::serialize_hashes(&missing_hashes)
            );
        } else {
            // TODO: GH-605: Test me
            debug!(
                logger,
                "All {} pending payables are present in the sent payable database",
                pending_payables.len()
            );
        }
    }

    fn migrate_payables(&self, failed_payables: &HashSet<FailedTx>) {
        let hashes: HashSet<TxHash> = failed_payables.iter().map(|tx| tx.hash).collect();
        let common_string = format!(
            "Error during migration from SentPayable to FailedPayable Table for transactions:\n{}",
            join_with_separator(&hashes, |hash| format!("{:?}", hash), "\n")
        );

        if let Err(e) = self.failed_payable_dao.insert_new_records(failed_payables) {
            panic!(
                "{}\nFailed to insert transactions into the FailedPayable table.\nError: {:?}",
                common_string, e
            );
        }

        if let Err(e) = self.sent_payable_dao.delete_records(&hashes) {
            panic!(
                "{}\nFailed to delete transactions from the SentPayable table.\nError: {:?}",
                common_string, e
            );
        }
    }

    fn serialize_hashes(hashes: &[H256]) -> String {
        comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
    }

    fn panic_if_payables_were_missing(
        failed_payables: &HashSet<FailedTx>,
        failures: &HashMap<TxHash, FailureReason>,
    ) {
        let failed_payable_hashes: HashSet<&TxHash> =
            failed_payables.iter().map(|tx| &tx.hash).collect();
        let missing_hashes: Vec<&TxHash> = failures
            .keys()
            .filter(|hash| !failed_payable_hashes.contains(hash))
            .collect();

        if !missing_hashes.is_empty() {
            panic!(
                "Could not find entries for the following transactions in the database:\n\
                {}\n\
                The found transactions have been migrated.",
                join_with_separator(&missing_hashes, |&hash| format!("{:?}", hash), "\n")
            )
        }
    }

    fn generate_failed_payables(
        &self,
        hashes_with_reason: &HashMap<TxHash, FailureReason>,
    ) -> HashSet<FailedTx> {
        let hashes: HashSet<TxHash> = hashes_with_reason.keys().cloned().collect();
        let sent_payables = self.sent_payable_dao.retrieve_txs(Some(ByHash(hashes)));

        sent_payables
            .iter()
            .filter_map(|tx| {
                hashes_with_reason.get(&tx.hash).map(|reason| FailedTx {
                    hash: tx.hash,
                    receiver_address: tx.receiver_address,
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    gas_price_wei: tx.gas_price_wei,
                    nonce: tx.nonce,
                    reason: reason.clone(),
                    status: FailureStatus::RetryRequired,
                })
            })
            .collect()
    }

    fn record_failed_txs_in_db(
        &self,
        hashes_with_reason: &HashMap<TxHash, FailureReason>,
        logger: &Logger,
    ) {
        if hashes_with_reason.is_empty() {
            return; // TODO: GH-605: Test me
        }

        debug!(
            logger,
            "Recording {} failed transactions in database: {}",
            hashes_with_reason.len(),
            join_with_separator(
                hashes_with_reason.keys(),
                |hash| format!("{:?}", hash),
                ", "
            )
        );

        let failed_payables = self.generate_failed_payables(hashes_with_reason);

        self.migrate_payables(&failed_payables);

        Self::panic_if_payables_were_missing(&failed_payables, hashes_with_reason);
    }

    fn handle_batch_results(&self, batch_results: Vec<IndividualBatchResult>, logger: &Logger) {
        let (pending, failures) = Self::separate_batch_results(batch_results);

        let pending_tx_count = pending.len();
        let failed_tx_count = failures.len();
        debug!(
            logger,
            "Processed payables while sending to RPC: \
             Total: {total}, Sent to RPC: {success}, Failed to send: {failed}. \
             Updating database...",
            total = pending_tx_count + failed_tx_count,
            success = pending_tx_count,
            failed = failed_tx_count
        );

        self.record_failed_txs_in_db(&failures, logger);

        self.check_pending_payables_in_sent_db(&pending, logger);
    }

    fn handle_local_error(&self, local_err: LocalPayableError, logger: &Logger) {
        if let LocalPayableError::Sending { hashes, .. } = local_err {
            let failures = Self::map_hashes_to_local_failures(hashes);
            self.record_failed_txs_in_db(&failures, logger);
        } else {
            debug!(
                logger,
                "Local error occurred before transaction signing. Error: {}", local_err
            );
        }
    }

    fn process_result(
        &self,
        payment_procedure_result: Either<Vec<IndividualBatchResult>, LocalPayableError>,
        logger: &Logger,
    ) -> OperationOutcome {
        match payment_procedure_result {
            Either::Left(batch_results) => {
                // TODO: GH-605: Test me
                self.handle_batch_results(batch_results, logger);
                OperationOutcome::NewPendingPayable
            }
            Either::Right(local_err) => {
                self.handle_local_error(local_err, logger);
                OperationOutcome::Failure
            }
        }
    }

    // Done
    fn generate_ui_response(
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Option<NodeToUiMessage> {
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }
}

#[cfg(test)]
mod tests {
    // Migrate all tests for PayableScanner here

    use super::*;

    #[test]
    fn generate_ui_response_works_correctly() {
        assert_eq!(PayableScanner::generate_ui_response(None), None);
        assert_eq!(
            PayableScanner::generate_ui_response(Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 5678
            })),
            Some(NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiScanResponse {}.tmb(5678),
            })
        );
    }
}
