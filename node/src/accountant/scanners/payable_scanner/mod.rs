pub mod data_structures;
mod finish_scan;
mod start_scan;
pub mod test_utils;

use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::Submission;
use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureReason, FailureStatus,
};
use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::db_access_objects::sent_payable_dao::RetrieveCondition::ByHash;
use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDao;
use crate::accountant::db_access_objects::utils::{from_unix_timestamp, TxHash};
use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::{
    RetryTxTemplate, RetryTxTemplates,
};
use crate::accountant::scanners::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner_extension::{
    MultistageDualPayableScanner, PreparedAdjustment, SolvencySensitivePaymentInstructor,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{
    payables_debug_summary, OperationOutcome, PayableThresholdsGauge, PayableThresholdsGaugeReal,
};
use crate::accountant::scanners::{Scanner, ScannerCommon, StartableScanner};
use crate::accountant::{
    comma_joined_stringifiable, gwei_to_wei, join_with_separator, ResponseSkeleton,
};
use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError;
use crate::blockchain::blockchain_interface::data_structures::{
    IndividualBatchResult, RpcPayableFailure,
};
use crate::blockchain::errors::AppRpcError::Local;
use crate::blockchain::errors::LocalError::Internal;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::H256;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::time::SystemTime;
use web3::types::Address;

pub struct PayableScanner {
    pub payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub payment_adjuster: Box<dyn PaymentAdjuster>,
}

impl MultistageDualPayableScanner for PayableScanner {}

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

    fn migrate_payables(&self, failed_payables: &HashSet<FailedTx>, logger: &Logger) {
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

        debug!(
            logger,
            "Successfully migrated following hashes from SentPayable table to FailedPayable table: {}",
            join_with_separator(hashes, |hash| format!("{:?}", hash), ", ")
        )
    }

    fn serialize_hashes(hashes: &[H256]) -> String {
        comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
    }

    fn verify_pending_tx_hashes_in_db(&self, pending_payables: &[PendingPayable], logger: &Logger) {
        if pending_payables.is_empty() {
            return;
        }

        let pending_hashes: HashSet<H256> = pending_payables.iter().map(|pp| pp.hash).collect();
        let sent_payables = self
            .sent_payable_dao
            .retrieve_txs(Some(ByHash(pending_hashes.clone())));
        let sent_hashes: HashSet<H256> = sent_payables.iter().map(|sp| sp.hash).collect();
        let missing_hashes: Vec<TxHash> =
            pending_hashes.difference(&sent_hashes).cloned().collect();

        if missing_hashes.is_empty() {
            debug!(
                logger,
                "All {} pending transactions were present in the sent payable database",
                pending_payables.len()
            );
        } else {
            panic!(
                "The following pending transactions were missing from the sent payable database: {}",
                Self::serialize_hashes(&missing_hashes)
            );
        }
    }

    fn verify_failed_tx_hashes_in_db(
        migrated_failures: &HashSet<FailedTx>,
        all_failures_with_reasons: &HashMap<TxHash, FailureReason>,
        logger: &Logger,
    ) {
        let migrated_hashes: HashSet<&TxHash> =
            migrated_failures.iter().map(|tx| &tx.hash).collect();
        let missing_hashes: Vec<&TxHash> = all_failures_with_reasons
            .keys()
            .filter(|hash| !migrated_hashes.contains(hash))
            .collect();

        if missing_hashes.is_empty() {
            debug!(
                logger,
                "All {} failed transactions were present in the sent payable database",
                migrated_hashes.len()
            );
        } else {
            panic!(
                "The found transactions have been migrated.\n\
                 The following failed transactions were missing from the sent payable database:\n\
                 {}",
                join_with_separator(&missing_hashes, |&hash| format!("{:?}", hash), "\n")
            );
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
            return;
        }

        debug!(
            logger,
            "Recording {} failed transactions in database",
            hashes_with_reason.len(),
        );

        let failed_payables = self.generate_failed_payables(hashes_with_reason);

        self.migrate_payables(&failed_payables, logger);

        Self::verify_failed_tx_hashes_in_db(&failed_payables, hashes_with_reason, logger);
    }

    fn handle_batch_results(
        &self,
        batch_results: Vec<IndividualBatchResult>,
        logger: &Logger,
    ) -> OperationOutcome {
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
        self.verify_pending_tx_hashes_in_db(&pending, logger);

        if pending_tx_count > 0 {
            OperationOutcome::NewPendingPayable
        } else {
            OperationOutcome::Failure
        }
    }

    fn handle_local_error(
        &self,
        local_err: LocalPayableError,
        logger: &Logger,
    ) -> OperationOutcome {
        if let LocalPayableError::Sending { hashes, .. } = local_err {
            let failures = Self::map_hashes_to_local_failures(hashes);
            self.record_failed_txs_in_db(&failures, logger);
        } else {
            debug!(
                logger,
                "Local error occurred before transaction signing. Error: {}", local_err
            );
        }

        OperationOutcome::Failure
    }

    fn process_result(
        &self,
        payment_procedure_result: Either<Vec<IndividualBatchResult>, LocalPayableError>,
        logger: &Logger,
    ) -> OperationOutcome {
        match payment_procedure_result {
            Either::Left(batch_results) => self.handle_batch_results(batch_results, logger),
            Either::Right(local_err) => self.handle_local_error(local_err, logger),
        }
    }

    fn generate_ui_response(
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Option<NodeToUiMessage> {
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }

    fn get_txs_to_retry(&self) -> Vec<FailedTx> {
        self.failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)))
    }

    fn find_corresponding_payables_in_db(
        &self,
        txs_to_retry: &[FailedTx],
    ) -> HashMap<Address, PayableAccount> {
        let addresses = Self::filter_receiver_addresses(&txs_to_retry);
        self.payable_dao
            .non_pending_payables(Some(ByAddresses(addresses)))
            .into_iter()
            .map(|payable| (payable.wallet.address(), payable))
            .collect()
    }

    fn filter_receiver_addresses(txs_to_retry: &[FailedTx]) -> BTreeSet<Address> {
        txs_to_retry
            .iter()
            .map(|tx_to_retry| tx_to_retry.receiver_address)
            .collect()
    }

    // We can also return UnpricedQualifiedPayable here
    fn generate_retry_tx_templates(
        payables_from_db: &HashMap<Address, PayableAccount>,
        txs_to_retry: &[FailedTx],
    ) -> RetryTxTemplates {
        RetryTxTemplates(
            txs_to_retry
                .iter()
                .map(|tx_to_retry| Self::generate_retry_tx_template(payables_from_db, tx_to_retry))
                .collect(),
        )
    }

    fn generate_retry_tx_template(
        payables_from_db: &HashMap<Address, PayableAccount>,
        tx_to_retry: &FailedTx,
    ) -> RetryTxTemplate {
        let mut tx_template = RetryTxTemplate::from(tx_to_retry);
        if let Some(payable) = payables_from_db.get(&tx_to_retry.receiver_address) {
            tx_template.base.amount_in_wei = tx_template.base.amount_in_wei + payable.balance_wei;
        };

        tx_template
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailedPayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoError;
    use crate::accountant::db_access_objects::test_utils::{FailedTxBuilder, TxBuilder};
    use crate::accountant::scanners::payable_scanner::test_utils::{
        make_pending_payable, make_rpc_payable_failure, PayableScannerBuilder,
    };
    use crate::accountant::test_utils::{FailedPayableDaoMock, SentPayableDaoMock};
    use crate::blockchain::errors::AppRpcError::Remote;
    use crate::blockchain::errors::RemoteError::Unreachable;
    use crate::blockchain::test_utils::make_tx_hash;
    use actix::System;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

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

    #[test]
    fn map_hashes_to_local_failures_works() {
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes = vec![hash1, hash2];

        let result = PayableScanner::map_hashes_to_local_failures(hashes);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get(&hash1),
            Some(&FailureReason::Submission(Local(Internal)))
        );
        assert_eq!(
            result.get(&hash2),
            Some(&FailureReason::Submission(Local(Internal)))
        );
    }

    #[test]
    fn separate_batch_results_works() {
        let pending_payable1 = make_pending_payable(1);
        let pending_payable2 = make_pending_payable(2);
        let failed_payable1 = make_rpc_payable_failure(1);
        let mut failed_payable2 = make_rpc_payable_failure(2);
        failed_payable2.rpc_error = web3::Error::Unreachable;
        let batch_results = vec![
            IndividualBatchResult::Pending(pending_payable1.clone()),
            IndividualBatchResult::Failed(failed_payable1.clone()),
            IndividualBatchResult::Pending(pending_payable2.clone()),
            IndividualBatchResult::Failed(failed_payable2.clone()),
        ];

        let (pending, failures) = PayableScanner::separate_batch_results(batch_results);

        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0], pending_payable1);
        assert_eq!(pending[1], pending_payable2);
        assert_eq!(failures.len(), 2);
        assert_eq!(
            failures.get(&failed_payable1.hash).unwrap(),
            &Submission(failed_payable1.rpc_error.into())
        );
        assert_eq!(
            failures.get(&failed_payable2.hash).unwrap(),
            &Submission(failed_payable2.rpc_error.into())
        );
    }

    #[test]
    fn verify_pending_tx_hashes_in_db_works() {
        init_test_logging();
        let test_name = "verify_pending_tx_hashes_in_db_works";
        let pending_payable1 = make_pending_payable(1);
        let pending_payable2 = make_pending_payable(2);
        let pending_payables = vec![pending_payable1.clone(), pending_payable2.clone()];
        let tx1 = TxBuilder::default().hash(pending_payable1.hash).build();
        let tx2 = TxBuilder::default().hash(pending_payable2.hash).build();
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![tx1, tx2]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let logger = Logger::new("test");
        subject.verify_pending_tx_hashes_in_db(&pending_payables, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: test: All {} pending transactions were present in the sent payable database",
            pending_payables.len()
        ));
    }

    #[test]
    #[should_panic(
        expected = "The following pending transactions were missing from the sent payable database:"
    )]
    fn verify_pending_tx_hashes_in_db_panics_when_hashes_are_missing() {
        init_test_logging();
        let test_name = "verify_pending_tx_hashes_in_db_panics_when_hashes_are_missing";
        let pending_payable1 = make_pending_payable(1);
        let pending_payable2 = make_pending_payable(2);
        let pending_payable3 = make_pending_payable(3);
        let pending_payables = vec![
            pending_payable1.clone(),
            pending_payable2.clone(),
            pending_payable3.clone(),
        ];
        let tx1 = TxBuilder::default().hash(pending_payable1.hash).build();
        let tx2 = TxBuilder::default().hash(pending_payable2.hash).build();
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![tx1, tx2]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let logger = Logger::new(test_name);

        subject.verify_pending_tx_hashes_in_db(&pending_payables, &logger);
    }

    #[test]
    fn migrate_payables_works_correctly() {
        init_test_logging();
        let test_name = "migrate_payables_works_correctly";
        let failed_tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_tx2 = FailedTxBuilder::default().hash(make_tx_hash(2)).build();
        let failed_payables = HashSet::from([failed_tx1, failed_tx2]);
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().delete_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let logger = Logger::new(test_name);

        subject.migrate_payables(&failed_payables, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Successfully migrated following hashes from SentPayable table to FailedPayable table:"
        ));
    }

    #[test]
    fn migrate_payables_panics_when_insert_fails() {
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_payables = HashSet::from([failed_tx]);

        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Err(
            FailedPayableDaoError::PartialExecution("The Times 03/Jan/2009".to_string()),
        ));
        let sent_payable_dao = SentPayableDaoMock::default();

        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = catch_unwind(AssertUnwindSafe(move || {
            let _ = subject.migrate_payables(&failed_payables, &Logger::new("test"));
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Error during migration from SentPayable to FailedPayable Table for transactions:\n\
             0x0000000000000000000000000000000000000000000000000000000000000001\n\
             Failed to insert transactions into the FailedPayable table.\n\
             Error: PartialExecution(\"The Times 03/Jan/2009\")"
        )
    }

    #[test]
    fn migrate_payables_panics_when_delete_fails() {
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_payables = HashSet::from([failed_tx]);
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().delete_records_result(Err(
            SentPayableDaoError::PartialExecution("The Times 03/Jan/2009".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.migrate_payables(&failed_payables, &Logger::new("test"));
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Error during migration from SentPayable to FailedPayable Table for transactions:\n\
             0x0000000000000000000000000000000000000000000000000000000000000001\n\
             Failed to delete transactions from the SentPayable table.\n\
             Error: PartialExecution(\"The Times 03/Jan/2009\")"
        )
    }

    #[test]
    fn verify_failed_tx_hashes_in_db_works_when_all_hashes_match() {
        init_test_logging();
        let test_name = "verify_failed_tx_hashes_in_db_works_when_all_hashes_match";
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let failed_tx1 = FailedTxBuilder::default().hash(hash1).build();
        let failed_tx2 = FailedTxBuilder::default().hash(hash2).build();
        let migrated_failures = HashSet::from([failed_tx1, failed_tx2]);
        let all_failures_with_reasons = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Local(Internal))),
        ]);
        let logger = Logger::new(test_name);

        PayableScanner::verify_failed_tx_hashes_in_db(
            &migrated_failures,
            &all_failures_with_reasons,
            &logger,
        );

        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: All 2 failed transactions were present in the sent payable database",
            test_name
        ));
    }

    #[test]
    fn verify_failed_tx_hashes_in_db_panics_when_hashes_are_missing() {
        init_test_logging();
        let test_name = "verify_failed_tx_hashes_in_db_panics_when_hashes_are_missing";
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hash3 = make_tx_hash(3);
        let failed_tx1 = FailedTxBuilder::default().hash(hash1).build();
        let failed_tx2 = FailedTxBuilder::default().hash(hash2).build();
        let migrated_failures = HashSet::from([failed_tx1, failed_tx2]);
        let all_failures_with_reasons = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Local(Internal))),
            (hash3, FailureReason::Submission(Local(Internal))),
        ]);
        let logger = Logger::new(test_name);

        let result = catch_unwind(AssertUnwindSafe(|| {
            PayableScanner::verify_failed_tx_hashes_in_db(
                &migrated_failures,
                &all_failures_with_reasons,
                &logger,
            );
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("The found transactions have been migrated."));
        assert!(panic_msg.contains(
            "The following failed transactions were missing from the sent payable database:"
        ));
        assert!(panic_msg.contains(&format!("{:?}", hash3)));
    }

    #[test]
    fn generate_failed_payables_works_correctly() {
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes_with_reason = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Remote(Unreachable))),
        ]);
        let tx1 = TxBuilder::default().hash(hash1).nonce(1).build();
        let tx2 = TxBuilder::default().hash(hash2).nonce(2).build();
        let sent_payable_dao =
            SentPayableDaoMock::default().retrieve_txs_result(vec![tx1.clone(), tx2.clone()]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.generate_failed_payables(&hashes_with_reason);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&FailedTx {
            hash: hash1,
            receiver_address: tx1.receiver_address,
            amount: tx1.amount,
            timestamp: tx1.timestamp,
            gas_price_wei: tx1.gas_price_wei,
            nonce: tx1.nonce,
            reason: FailureReason::Submission(Local(Internal)),
            status: FailureStatus::RetryRequired,
        }));
        assert!(result.contains(&FailedTx {
            hash: hash2,
            receiver_address: tx2.receiver_address,
            amount: tx2.amount,
            timestamp: tx2.timestamp,
            gas_price_wei: tx2.gas_price_wei,
            nonce: tx2.nonce,
            reason: FailureReason::Submission(Remote(Unreachable)),
            status: FailureStatus::RetryRequired,
        }));
    }

    #[test]
    fn generate_failed_payables_can_be_a_subset_of_hashes_with_reason() {
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes_with_reason = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Remote(Unreachable))),
        ]);
        let tx1 = TxBuilder::default().hash(hash1).build();
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![tx1]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.generate_failed_payables(&hashes_with_reason);

        assert_eq!(result.len(), 1);
        assert!(result.iter().any(|tx| tx.hash == hash1));
        assert!(!result.iter().any(|tx| tx.hash == hash2));
    }

    #[test]
    fn record_failed_txs_in_db_returns_early_if_hashes_with_reason_is_empty() {
        init_test_logging();
        let test_name = "record_failed_txs_in_db_returns_early_if_hashes_with_reason_is_empty";
        let logger = Logger::new(test_name);
        let subject = PayableScannerBuilder::new().build();

        subject.record_failed_txs_in_db(&HashMap::new(), &logger);

        TestLogHandler::new().exists_no_log_containing(&format!("DEBUG: {test_name}: Recording"));
    }

    #[test]
    fn record_failed_txs_in_db_successfully_migrates_and_verifies_all_transactions() {
        init_test_logging();
        let test_name =
            "record_failed_txs_in_db_successfully_migrates_and_verifies_all_transactions";
        let logger = Logger::new(test_name);
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes_with_reason = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Local(Internal))),
        ]);
        let tx1 = TxBuilder::default().hash(hash1).build();
        let tx2 = TxBuilder::default().hash(hash2).build();
        let sent_payable_dao = SentPayableDaoMock::default()
            .retrieve_txs_result(vec![tx1, tx2])
            .delete_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();

        subject.record_failed_txs_in_db(&hashes_with_reason, &logger);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 2 failed transactions in database"
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Successfully migrated following hashes from SentPayable table to FailedPayable table:"
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: All 2 failed transactions were present in the sent payable database"
        ));
    }

    #[test]
    fn record_failed_txs_in_db_panics_when_fewer_transactions_are_retrieved() {
        init_test_logging();
        let test_name = "record_failed_txs_in_db_panics_when_fewer_transactions_are_retrieved";
        let logger = Logger::new(test_name);
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes_with_reason = HashMap::from([
            (hash1, FailureReason::Submission(Local(Internal))),
            (hash2, FailureReason::Submission(Local(Internal))),
        ]);
        let tx1 = TxBuilder::default().hash(hash1).build();
        let sent_payable_dao = SentPayableDaoMock::default()
            .retrieve_txs_result(vec![tx1])
            .delete_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.record_failed_txs_in_db(&hashes_with_reason, &logger);
        }))
        .unwrap_err();

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 2 failed transactions in database"
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Successfully migrated following hashes from SentPayable table to FailedPayable table:"
        ));
        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("The found transactions have been migrated."));
        assert!(panic_msg.contains(
            "The following failed transactions were missing from the sent payable database:"
        ));
        assert!(panic_msg
            .contains("0x0000000000000000000000000000000000000000000000000000000000000002"));
    }

    #[test]
    fn handle_local_error_handles_sending_error() {
        init_test_logging();
        let test_name = "handle_local_error_handles_sending_error";
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let logger = Logger::new(test_name);
        let hash1 = make_tx_hash(1);
        let hash2 = make_tx_hash(2);
        let hashes = vec![hash1, hash2];
        let local_err = LocalPayableError::Sending {
            msg: "Test sending error".to_string(),
            hashes: hashes.clone(),
        };
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()))
            .retrieve_txs_result(vec![
                TxBuilder::default().hash(hash1).build(),
                TxBuilder::default().hash(hash2).build(),
            ]);
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        subject.handle_local_error(local_err, &logger);

        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        let inserted_records = &insert_new_records_params[0];
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        let deleted_hashes = &delete_records_params[0];
        assert_eq!(inserted_records.len(), 2);
        assert!(inserted_records.iter().any(|tx| tx.hash == hash1));
        assert!(inserted_records.iter().any(|tx| tx.hash == hash2));
        assert!(inserted_records
            .iter()
            .all(|tx| tx.reason == FailureReason::Submission(Local(Internal))));
        assert!(inserted_records
            .iter()
            .all(|tx| tx.status == FailureStatus::RetryRequired));
        assert_eq!(deleted_hashes.len(), 2);
        assert!(deleted_hashes.contains(&hash1));
        assert!(deleted_hashes.contains(&hash2));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 2 failed transactions in database"
        ));
    }

    #[test]
    fn handle_local_error_logs_non_sending_errors() {
        init_test_logging();
        let test_name = "handle_local_error_logs_non_sending_errors";
        let logger = Logger::new(test_name);
        let local_err = LocalPayableError::Signing("Test signing error".to_string());
        let subject = PayableScannerBuilder::new().build();

        subject.handle_local_error(local_err, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {}: Local error occurred before transaction signing. Error: Signing phase: \"Test signing error\"",
            test_name
        ));
    }

    #[test]
    fn handle_batch_results_works_as_expected() {
        init_test_logging();
        let test_name = "handle_batch_results_works_as_expected";
        let logger = Logger::new(test_name);
        let failed_payable_dao_insert_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao_delete_params = Arc::new(Mutex::new(vec![]));
        let pending_payable = make_pending_payable(1);
        let failed_payable = make_rpc_payable_failure(2);
        let batch_results = vec![
            IndividualBatchResult::Pending(pending_payable.clone()),
            IndividualBatchResult::Failed(failed_payable.clone()),
        ];
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&failed_payable_dao_insert_params)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&sent_payable_dao_delete_params)
            .retrieve_txs_result(vec![TxBuilder::default().hash(failed_payable.hash).build()])
            .delete_records_result(Ok(()))
            .retrieve_txs_result(vec![TxBuilder::default()
                .hash(pending_payable.hash)
                .build()]);
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.handle_batch_results(batch_results, &logger);

        let inserted_records = &failed_payable_dao_insert_params.lock().unwrap()[0];
        let deleted_hashes = sent_payable_dao_delete_params.lock().unwrap()[0].clone();
        assert_eq!(result, OperationOutcome::NewPendingPayable);
        assert_eq!(inserted_records.len(), 1);
        assert_eq!(deleted_hashes.len(), 1);
        assert!(inserted_records
            .iter()
            .any(|tx| tx.hash == failed_payable.hash));
        assert!(deleted_hashes.contains(&failed_payable.hash));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
            Total: 2, Sent to RPC: 1, Failed to send: 1. \
            Updating database...",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 1 failed transactions in database",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: All 1 pending transactions were present in the sent payable database",
        ));
    }

    #[test]
    fn handle_batch_results_handles_all_pending() {
        init_test_logging();
        let test_name = "handle_batch_results_handles_all_pending";
        let logger = Logger::new(test_name);
        let pending_payable_1 = make_pending_payable(1);
        let pending_payable_2 = make_pending_payable(2);
        let batch_results = vec![
            IndividualBatchResult::Pending(pending_payable_1.clone()),
            IndividualBatchResult::Pending(pending_payable_2.clone()),
        ];
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![
            TxBuilder::default().hash(pending_payable_1.hash).build(),
            TxBuilder::default().hash(pending_payable_2.hash).build(),
        ]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.handle_batch_results(batch_results, &logger);

        assert_eq!(result, OperationOutcome::NewPendingPayable);
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
            Total: 2, Sent to RPC: 2, Failed to send: 0. \
            Updating database...",
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: All 2 pending transactions were present in the sent payable database",
        ));
    }

    #[test]
    fn handle_batch_results_handles_all_failed() {
        init_test_logging();
        let test_name = "handle_batch_results_handles_all_failed";
        let logger = Logger::new(test_name);
        let failed_payable_dao_insert_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao_delete_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_1 = make_rpc_payable_failure(1);
        let failed_payable_2 = make_rpc_payable_failure(2);
        let batch_results = vec![
            IndividualBatchResult::Failed(failed_payable_1.clone()),
            IndividualBatchResult::Failed(failed_payable_2.clone()),
        ];
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&failed_payable_dao_insert_params)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&sent_payable_dao_delete_params)
            .retrieve_txs_result(vec![
                TxBuilder::default().hash(failed_payable_1.hash).build(),
                TxBuilder::default().hash(failed_payable_2.hash).build(),
            ])
            .delete_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.handle_batch_results(batch_results, &logger);

        let inserted_records = &failed_payable_dao_insert_params.lock().unwrap()[0];
        let deleted_hashes = sent_payable_dao_delete_params.lock().unwrap()[0].clone();
        assert_eq!(result, OperationOutcome::Failure);
        assert_eq!(inserted_records.len(), 2);
        assert_eq!(deleted_hashes.len(), 2);
        assert!(inserted_records
            .iter()
            .any(|tx| tx.hash == failed_payable_1.hash));
        assert!(inserted_records
            .iter()
            .any(|tx| tx.hash == failed_payable_2.hash));
        assert!(deleted_hashes.contains(&failed_payable_1.hash));
        assert!(deleted_hashes.contains(&failed_payable_2.hash));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
            Total: 2, Sent to RPC: 0, Failed to send: 2. \
            Updating database...",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 2 failed transactions in database",
        ));
    }

    #[test]
    fn handle_batch_results_can_panic_while_recording_failures() {
        init_test_logging();
        let test_name = "handle_batch_results_can_panic_while_recording_failures";
        let logger = Logger::new(test_name);
        let failed_payable_dao_insert_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao_delete_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_1 = make_rpc_payable_failure(1);
        let failed_payable_2 = make_rpc_payable_failure(2);
        let batch_results = vec![
            IndividualBatchResult::Failed(failed_payable_1.clone()),
            IndividualBatchResult::Failed(failed_payable_2.clone()),
        ];
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&failed_payable_dao_insert_params)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&sent_payable_dao_delete_params)
            .retrieve_txs_result(vec![TxBuilder::default()
                .hash(failed_payable_1.hash)
                .build()])
            .delete_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = subject.handle_batch_results(batch_results, &logger);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        let inserted_records = &failed_payable_dao_insert_params.lock().unwrap()[0];
        let deleted_hashes = sent_payable_dao_delete_params.lock().unwrap()[0].clone();
        assert_eq!(inserted_records.len(), 1);
        assert_eq!(deleted_hashes.len(), 1);
        assert!(inserted_records
            .iter()
            .any(|tx| tx.hash == failed_payable_1.hash));
        assert!(deleted_hashes.contains(&failed_payable_1.hash));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
            Total: 2, Sent to RPC: 0, Failed to send: 2. \
            Updating database...",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 2 failed transactions in database",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Successfully migrated following hashes from \
            SentPayable table to FailedPayable table: {:?}",
            failed_payable_1.hash
        ));
        assert_eq!(
            panic_msg,
            "The found transactions have been migrated.\n\
             The following failed transactions were missing from the sent payable database:\n\
             0x0000000000000000000000000000000000000000000000000000000000072a86"
        )
    }

    #[test]
    fn handle_batch_results_can_panic_while_verifying_pending() {
        init_test_logging();
        let test_name = "handle_batch_results_can_panic_while_verifying_pending";
        let logger = Logger::new(test_name);
        let failed_payable_dao_insert_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao_delete_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_1 = make_rpc_payable_failure(1);
        let pending_payable_ = make_pending_payable(2);
        let batch_results = vec![
            IndividualBatchResult::Failed(failed_payable_1.clone()),
            IndividualBatchResult::Pending(pending_payable_.clone()),
        ];
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&failed_payable_dao_insert_params)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&sent_payable_dao_delete_params)
            .retrieve_txs_result(vec![TxBuilder::default()
                .hash(failed_payable_1.hash)
                .build()])
            .delete_records_result(Ok(()))
            .retrieve_txs_result(vec![]);
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = subject.handle_batch_results(batch_results, &logger);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        let inserted_records = &failed_payable_dao_insert_params.lock().unwrap()[0];
        let deleted_hashes = sent_payable_dao_delete_params.lock().unwrap()[0].clone();
        assert_eq!(inserted_records.len(), 1);
        assert_eq!(deleted_hashes.len(), 1);
        assert!(inserted_records
            .iter()
            .any(|tx| tx.hash == failed_payable_1.hash));
        assert!(deleted_hashes.contains(&failed_payable_1.hash));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
            Total: 2, Sent to RPC: 1, Failed to send: 1. \
            Updating database...",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Recording 1 failed transactions in database",
        ));
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Successfully migrated following hashes from \
            SentPayable table to FailedPayable table: {:?}",
            failed_payable_1.hash
        ));
        assert_eq!(
            panic_msg,
            "The following pending transactions were missing from the sent payable database: \
            0x000000000000000000000000000000000000000000000000000000000090317e"
        )
    }

    #[test]
    fn process_result_handles_batch() {
        init_test_logging();
        let test_name = "process_result_handles_batch";
        let pending_payable = make_pending_payable(1);
        let tx = TxBuilder::default().hash(pending_payable.hash).build();
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![tx]);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let batch_results = vec![IndividualBatchResult::Pending(pending_payable)];

        let result = subject.process_result(Either::Left(batch_results), &logger);

        assert_eq!(result, OperationOutcome::NewPendingPayable);
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed payables while sending to RPC: \
             Total: 1, Sent to RPC: 1, Failed to send: 0. \
             Updating database..."
        ));
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: All 1 pending transactions were present \
            in the sent payable database"
        ));
    }

    #[test]
    fn process_result_handles_error() {
        init_test_logging();
        let test_name = "process_result_handles_error";
        let subject = PayableScannerBuilder::new().build();
        let logger = Logger::new(test_name);

        let result = subject.process_result(
            Either::Right(LocalPayableError::MissingConsumingWallet),
            &logger,
        );

        assert_eq!(result, OperationOutcome::Failure);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Local error occurred before transaction signing. \
             Error: Missing consuming wallet to pay payable from"
        ));
    }
}
