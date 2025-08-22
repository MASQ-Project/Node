// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
mod finish_scan;
pub mod msgs;
mod start_scan;
pub mod test_utils;
pub mod tx_templates;

pub mod payment_adjuster_integration;
pub mod utils;

use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureReason, FailureRetrieveCondition, FailureStatus,
    ValidationStatus,
};
use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDao, Tx};
use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
use crate::accountant::scanners::payable_scanner::payment_adjuster_integration::SolvencySensitivePaymentInstructor;
use crate::accountant::scanners::payable_scanner::utils::{
    batch_stats, calculate_lengths, filter_receiver_addresses_from_txs, generate_status_updates,
    payables_debug_summary, OperationOutcome, PayableScanResult, PayableThresholdsGauge,
    PayableThresholdsGaugeReal,
};
use crate::accountant::scanners::{Scanner, ScannerCommon, StartableScanner};
use crate::accountant::{
    gwei_to_wei, join_with_separator, PayableScanType, ResponseSkeleton, ScanForNewPayables,
    ScanForRetryPayables, SentPayables,
};
use crate::blockchain::blockchain_interface::data_structures::BatchResults;
use crate::sub_lib::accountant::PaymentThresholds;
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::collections::{BTreeSet, HashMap};
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

pub(in crate::accountant::scanners) trait MultistageDualPayableScanner:
    StartableScanner<ScanForNewPayables, InitialTemplatesMessage>
    + StartableScanner<ScanForRetryPayables, InitialTemplatesMessage>
    + SolvencySensitivePaymentInstructor
    + Scanner<SentPayables, PayableScanResult>
{
}

impl MultistageDualPayableScanner for PayableScanner {}

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
        retrieve_payables: Vec<PayableAccount>,
        logger: &Logger,
    ) -> Vec<PayableAccount> {
        fn pass_payables_and_drop_points(
            qp_tp: impl Iterator<Item = (PayableAccount, u128)>,
        ) -> Vec<PayableAccount> {
            let (payables, _) = qp_tp.unzip::<_, _, Vec<PayableAccount>, Vec<_>>();
            payables
        }

        let qualified_payables_and_points_uncollected =
            retrieve_payables.into_iter().flat_map(|account| {
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

    fn detect_outcome(msg: &SentPayables) -> OperationOutcome {
        if let Ok(batch_results) = msg.clone().payment_procedure_result {
            if batch_results.sent_txs.is_empty() {
                if batch_results.failed_txs.is_empty() {
                    return OperationOutcome::NewPayableScan;
                } else {
                    return OperationOutcome::RetryPayableScan;
                }
            }

            OperationOutcome::PendingPayableScan
        } else {
            match msg.payable_scan_type {
                PayableScanType::New => OperationOutcome::NewPayableScan,
                PayableScanType::Retry => OperationOutcome::RetryPayableScan,
            }
        }
    }

    fn process_message(&self, msg: &SentPayables, logger: &Logger) {
        match &msg.payment_procedure_result {
            Ok(batch_results) => match msg.payable_scan_type {
                PayableScanType::New => self.handle_new(batch_results, logger),
                PayableScanType::Retry => self.handle_retry(batch_results, logger),
            },
            Err(local_error) => Self::log_local_error(local_error, logger),
        }
    }

    fn handle_new(&self, batch_results: &BatchResults, logger: &Logger) {
        let (sent, failed) = calculate_lengths(&batch_results);
        debug!(
            logger,
            "Processed new txs while sending to RPC: {}",
            batch_stats(sent, failed),
        );
        if sent > 0 {
            self.insert_records_in_sent_payables(&batch_results.sent_txs);
        }
        if failed > 0 {
            self.insert_records_in_failed_payables(&batch_results.failed_txs);
        }
    }

    fn handle_retry(&self, batch_results: &BatchResults, logger: &Logger) {
        let (sent, failed) = calculate_lengths(&batch_results);
        debug!(
            logger,
            "Processed retried txs while sending to RPC: {}",
            batch_stats(sent, failed),
        );

        if sent > 0 {
            self.insert_records_in_sent_payables(&batch_results.sent_txs);
            self.update_statuses_of_prev_txs(&batch_results.sent_txs);
        }
        if failed > 0 {
            // TODO: Would it be a good ides to update Retry attempt of previous tx?
            Self::log_failed_txs_during_retry(&batch_results.failed_txs, logger);
        }
    }

    fn update_statuses_of_prev_txs(&self, sent_txs: &Vec<Tx>) {
        // TODO: We can do better here, possibly by creating a relationship between failed and sent txs
        // Also, consider the fact that some txs will be with PendingTooLong status, what should we do with them?
        let retrieved_txs = self.retrieve_failed_txs_by_receiver_addresses(&sent_txs);
        let (pending_too_long, other_reasons): (BTreeSet<_>, BTreeSet<_>) = retrieved_txs
            .into_iter()
            .partition(|tx| matches!(tx.reason, FailureReason::PendingTooLong));
        if !pending_too_long.is_empty() {
            self.update_failed_txs(
                &pending_too_long,
                FailureStatus::RecheckRequired(ValidationStatus::Waiting),
            );
        }
        if !other_reasons.is_empty() {
            self.update_failed_txs(&other_reasons, FailureStatus::Concluded);
        }
    }

    fn retrieve_failed_txs_by_receiver_addresses(&self, sent_txs: &Vec<Tx>) -> BTreeSet<FailedTx> {
        let receiver_addresses = filter_receiver_addresses_from_txs(sent_txs.iter());
        self.failed_payable_dao
            .retrieve_txs(Some(FailureRetrieveCondition::ByReceiverAddresses(
                receiver_addresses,
            )))
    }

    fn update_failed_txs(&self, failed_txs: &BTreeSet<FailedTx>, status: FailureStatus) {
        let status_updates = generate_status_updates(failed_txs, status);
        self.failed_payable_dao
            .update_statuses(status_updates)
            .unwrap_or_else(|e| panic!("Failed to conclude txs in database: {:?}", e));
    }

    fn log_failed_txs_during_retry(failed_txs: &[FailedTx], logger: &Logger) {
        warning!(
            logger,
            "While retrying, {} transactions with hashes: {} have failed.",
            failed_txs.len(),
            join_with_separator(failed_txs, |failed_tx| format!("{:?}", failed_tx.hash), ",")
        )
    }

    fn log_local_error(local_error: &str, logger: &Logger) {
        warning!(
            logger,
            "Local error occurred before transaction signing. Error: {}",
            local_error
        )
    }

    fn insert_records_in_sent_payables(&self, sent_txs: &Vec<Tx>) {
        self.sent_payable_dao
            .insert_new_records(&sent_txs.iter().cloned().collect())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to insert transactions into the SentPayable table. Error: {:?}",
                    e
                )
            });
    }

    fn insert_records_in_failed_payables(&self, failed_txs: &Vec<FailedTx>) {
        self.failed_payable_dao
            .insert_new_records(&failed_txs.iter().cloned().collect())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to insert transactions into the FailedPayable table. Error: {:?}",
                    e
                )
            });
    }

    fn generate_ui_response(
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Option<NodeToUiMessage> {
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }

    fn get_txs_to_retry(&self) -> BTreeSet<FailedTx> {
        self.failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)))
    }

    fn find_amount_from_payables(
        &self,
        txs_to_retry: &BTreeSet<FailedTx>,
    ) -> HashMap<Address, u128> {
        let addresses = filter_receiver_addresses_from_txs(txs_to_retry.iter());
        self.payable_dao
            .retrieve_payables(Some(ByAddresses(addresses)))
            .into_iter()
            .map(|payable| (payable.wallet.address(), payable.balance_wei))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailedPayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoError;
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, FailedTxBuilder, TxBuilder,
    };
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::test_utils::{FailedPayableDaoMock, SentPayableDaoMock};
    use crate::blockchain::test_utils::make_tx_hash;
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

    //// New Code

    #[test]
    fn detect_outcome_works() {
        // Error
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::NewPayableScan
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::RetryPayableScan
        );

        // BatchResults is empty
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::NewPayableScan
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::NewPayableScan
        );

        // Only FailedTxs
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::RetryPayableScan
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::RetryPayableScan
        );

        // Only SentTxs
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::PendingPayableScan
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::PendingPayableScan
        );

        // Both SentTxs and FailedTxs are present
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::PendingPayableScan
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::PendingPayableScan
        );
    }

    #[test]
    fn update_statuses_of_prev_txs_updates_statuses_correctly() {
        let retrieve_txs_params = Arc::new(Mutex::new(vec![]));
        let update_statuses_params = Arc::new(Mutex::new(vec![]));
        let tx_hash_1 = make_tx_hash(1);
        let tx_hash_2 = make_tx_hash(2);
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_txs_params)
            .retrieve_txs_result(BTreeSet::from([
                FailedTxBuilder::default()
                    .hash(tx_hash_1)
                    .reason(FailureReason::PendingTooLong)
                    .build(),
                FailedTxBuilder::default()
                    .hash(tx_hash_2)
                    .reason(FailureReason::Reverted)
                    .build(),
            ]))
            .update_statuses_params(&update_statuses_params)
            .update_statuses_result(Ok(()))
            .update_statuses_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let sent_txs = vec![make_sent_tx(1), make_sent_tx(2)];

        subject.update_statuses_of_prev_txs(&sent_txs);

        let update_params = update_statuses_params.lock().unwrap();
        assert_eq!(update_params.len(), 2);
        assert_eq!(
            update_params[0],
            hashmap!(tx_hash_1 => FailureStatus::RecheckRequired(ValidationStatus::Waiting))
        );
        assert_eq!(
            update_params[1],
            hashmap!(tx_hash_2 => FailureStatus::Concluded)
        );
    }

    #[test]
    fn insert_records_in_sent_payables_inserts_records_successfully() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let sent_txs = vec![tx1.clone(), tx2.clone()];

        subject.insert_records_in_sent_payables(&sent_txs);

        let params = insert_new_records_params.lock().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], sent_txs.into_iter().collect());
    }

    #[test]
    fn insert_records_in_sent_payables_panics_on_error() {
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Err(
            SentPayableDaoError::PartialExecution("Test error".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx = TxBuilder::default().hash(make_tx_hash(1)).build();
        let sent_txs = vec![tx];

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.insert_records_in_sent_payables(&sent_txs);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("Failed to insert transactions into the SentPayable table"));
        assert!(panic_msg.contains("Test error"));
    }

    #[test]
    fn insert_records_in_failed_payables_inserts_records_successfully() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_tx2 = FailedTxBuilder::default().hash(make_tx_hash(2)).build();
        let failed_txs = vec![failed_tx1.clone(), failed_tx2.clone()];

        subject.insert_records_in_failed_payables(&failed_txs);

        let params = insert_new_records_params.lock().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], BTreeSet::from([failed_tx1, failed_tx2]));
    }

    #[test]
    fn insert_records_in_failed_payables_panics_on_error() {
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Err(
            FailedPayableDaoError::PartialExecution("Test error".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_txs = vec![failed_tx];

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.insert_records_in_failed_payables(&failed_txs);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("Failed to insert transactions into the FailedPayable table"));
        assert!(panic_msg.contains("Test error"));
    }

    #[test]
    fn handle_new_does_not_perform_any_operation_when_sent_txs_is_empty() {
        let insert_new_records_params_sent = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_sent);
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![],
            failed_txs: vec![make_failed_tx(1)],
        };

        subject.handle_new(&batch_results, &Logger::new("test"));

        assert!(insert_new_records_params_sent.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_new_does_not_perform_any_operation_when_failed_txs_is_empty() {
        let insert_new_records_params_failed = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_failed);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![make_sent_tx(1)],
            failed_txs: vec![],
        };

        subject.handle_new(&batch_results, &Logger::new("test"));

        assert!(insert_new_records_params_failed.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_retry_does_not_perform_any_operation_when_sent_txs_is_empty() {
        let insert_new_records_params_sent = Arc::new(Mutex::new(vec![]));
        let retrieve_txs_params = Arc::new(Mutex::new(vec![]));
        let update_statuses_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_sent);
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_txs_params)
            .update_statuses_params(&update_statuses_params);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![],
            failed_txs: vec![make_failed_tx(1)],
        };

        subject.handle_retry(&batch_results, &Logger::new("test"));

        assert!(insert_new_records_params_sent.lock().unwrap().is_empty());
        assert!(retrieve_txs_params.lock().unwrap().is_empty());
        assert!(update_statuses_params.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_retry_logs_no_warn_when_failed_txs_exist() {
        init_test_logging();
        let test_name = "handle_retry_logs_no_warn_when_failed_txs_exist";
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_result(BTreeSet::from([make_failed_tx(1)]))
            .update_statuses_result(Ok(()))
            .update_statuses_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![make_sent_tx(1)],
            failed_txs: vec![],
        };

        subject.handle_retry(&batch_results, &Logger::new(test_name));

        let tlh = TestLogHandler::new();
        tlh.exists_no_log_containing(&format!("WARN: {test_name}"));
    }

    #[test]
    fn update_failed_txs_panics_on_error() {
        let failed_payable_dao = FailedPayableDaoMock::default().update_statuses_result(Err(
            FailedPayableDaoError::SqlExecutionFailed("I slept too much".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_txs = BTreeSet::from([failed_tx]);

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.update_failed_txs(&failed_txs, FailureStatus::Concluded);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains(
            "Failed to conclude txs in database: SqlExecutionFailed(\"I slept too much\")"
        ));
    }
}
