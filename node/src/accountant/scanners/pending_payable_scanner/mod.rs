// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureRetrieveCondition,
};
use crate::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoError};
use crate::accountant::db_access_objects::sent_payable_dao::{
    RetrieveCondition, SentPayableDao, SentPayableDaoError, SentTx,
};
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::pending_payable_scanner::utils::{handle_status_with_failure, CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailuresRequiringDoubleCheck, PendingPayableScanResult, PresortedTxFailure, ReceiptScanReport, Retry, TxCaseToBeInterpreted, FailedValidationByTable, TxReclaim, NormalTxConfirmation};
use crate::accountant::scanners::{
    PrivateScanner, Scanner, ScannerCommon, StartScanError, StartableScanner,
};
use crate::accountant::{
    comma_joined_stringifiable, PendingPayableId, RequestTransactionReceipts, ResponseSkeleton,
    ScanForPendingPayables, TxReceiptsMessage,
};
use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::time_marking_methods;
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::SystemTime;
use thousands::Separable;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionBlock;

pub struct PendingPayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
    pub current_sent_payables: CurrentPendingPayables,
    pub yet_unproven_failures: FailuresRequiringDoubleCheck,
}

impl
    PrivateScanner<
        ScanForPendingPayables,
        RequestTransactionReceipts,
        TxReceiptsMessage,
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

        let pending_sent_txs = self
            .sent_payable_dao
            .retrieve_txs(Some(RetrieveCondition::IsPending));

        let unproven_failures = self
            .failed_payable_dao
            .retrieve_txs(Some(FailureRetrieveCondition::EveryRecheckRequiredRecord));

        // TODO 1) check non-empty collections
        // 2) fill in the respective caches
        // 3) form a joint collection for the message
        todo!("fix me");

        // match pending_sent_txs.is_empty() {
        //     true => {
        //         self.mark_as_ended(logger);
        //         Err(StartScanError::NothingToProcess)
        //     }
        //     false => {
        //         debug!(
        //             logger,
        //             "Found {} pending payables to process",
        //             pending_sent_txs.len()
        //         );
        //         Ok(RequestTransactionReceipts {
        //             tx_hashes: pending_sent_txs,
        //             response_skeleton_opt,
        //         })
        //     }
        // }
    }
}

impl Scanner<TxReceiptsMessage, PendingPayableScanResult> for PendingPayableScanner {
    fn finish_scan(
        &mut self,
        message: TxReceiptsMessage,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        let response_skeleton_opt = message.response_skeleton_opt;

        let scan_report = self.interpret_tx_receipts(message, logger);

        let retry_opt = scan_report.requires_payments_retry();

        self.process_txs_by_state(scan_report, logger);

        self.mark_as_ended(logger);

        Self::compose_scan_result(retry_opt, response_skeleton_opt)
    }

    time_marking_methods!(PendingPayables);

    as_any_ref_in_trait_impl!();
}

impl PendingPayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        sent_payable_dao: Box<dyn SentPayableDao>,
        failed_payable_dao: Box<dyn FailedPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        // let yet_unproven_failures = FailuresRequiringDoubleCheck::new(
        //     failed_payable_dao.retrieve_txs(Some(FailureRetrieveCondition::ByStatus(
        //         todo!(), //FailureRetrieveCondition::EveryRecheckRequiredRecord
        //     ))),
        // );

        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            sent_payable_dao,
            failed_payable_dao,
            financial_statistics,
            current_sent_payables: CurrentPendingPayables::default(),
            yet_unproven_failures: FailuresRequiringDoubleCheck::default(),
        }
    }

    fn emptiness_check(&self, msg: &TxReceiptsMessage) {
        if msg.results.is_empty() {
            unreachable!("We should never receive an empty list of results. Even missing receipts can be interpreted")
        }
    }

    fn interpret_tx_receipts(
        &mut self,
        msg: TxReceiptsMessage,
        logger: &Logger,
    ) -> ReceiptScanReport {
        self.emptiness_check(&msg);

        debug!(logger, "Processing receipts for {} txs", msg.results.len());

        let interpretable_data = self.prepare_cases_to_interpret(msg);
        self.compose_receipt_scan_report(interpretable_data, logger)
    }

    fn prepare_cases_to_interpret(&mut self, msg: TxReceiptsMessage) -> Vec<TxCaseToBeInterpreted> {
        //TODO pull the records out from the caches and leave them empty
        todo!()
    }

    fn compose_receipt_scan_report(
        &self,
        tx_cases: Vec<TxCaseToBeInterpreted>,
        logger: &Logger,
    ) -> ReceiptScanReport {
        todo!()
        // let scan_report = ReceiptScanReport::default();
        // msg.results
        //     .into_iter()
        //     .fold(
        //         scan_report,
        //         |scan_report_so_far, receipt_result| match receipt_result {
        //             TxReceiptResult::Ok(sent_tx_with_status) => match sent_tx_with_status.status {
        //                 StatusReadFromReceiptCheck::Succeeded(tx_block) => handle_successful_tx(
        //                     scan_report_so_far,
        //                     self.yet_unproven_failures.hashes(),
        //                     sent_tx_with_status.tx_hash,
        //                     tx_block,
        //                     logger,
        //                 ),
        //                 StatusReadFromReceiptCheck::Failed(reason) => handle_status_with_failure(
        //                     scan_report_so_far,
        //                     sent_tx_with_status.sent_tx,
        //                     reason,
        //                     logger,
        //                 ),
        //                 StatusReadFromReceiptCheck::Pending => handle_still_pending_tx(
        //                     scan_report_so_far,
        //                     sent_tx_with_status.sent_tx,
        //                     logger,
        //                 ),
        //             },
        //             TxReceiptResult::Err(e) => handle_rpc_failure(
        //                 scan_report_so_far,
        //                 self.yet_unproven_failures.hashes(),
        //                 e,
        //                 logger,
        //             ),
        //         },
        //     )
    }

    fn process_txs_by_state(&mut self, scan_report: ReceiptScanReport, logger: &Logger) {
        self.handle_confirmed_transactions(scan_report.confirmations, logger);
        self.handle_failed_transactions(scan_report.failures, logger);
    }

    fn handle_confirmed_transactions(
        &mut self,
        confirmed_txs: DetectedConfirmations,
        logger: &Logger,
    ) {
        self.handle_tx_failure_reclaims(confirmed_txs.reclaims, logger);
        self.handle_normal_confirmations(confirmed_txs.normal_confirmations, logger);
    }

    fn handle_tx_failure_reclaims(&self, reclaimed: Vec<TxReclaim>, logger: &Logger) {
        if reclaimed.is_empty() {todo!()}
        todo!()
    }

    fn handle_normal_confirmations(
        &self,
        confirmed_txs: Vec<NormalTxConfirmation>,
        logger: &Logger,
    ) {
        if confirmed_txs.is_empty() {
            todo!()
        }
        todo!()
    }

    fn compose_tx_confirmation_inputs(
        confirmed_txs: &[SentTx],
    ) -> HashMap<TxHash, TransactionBlock> {
        todo!()
    }

    fn transaction_confirmed_panic(confirmed_txs: &[SentTx], e: PayableDaoError) -> ! {
        let wallets = confirmed_txs
            .iter()
            .map(|tx| tx.receiver_address)
            .collect_vec();
        panic!(
            "Unable to complete the tx confirmation by the adjustment of the payable accounts {} \
            due to {:?}",
            comma_joined_stringifiable(&wallets, |wallet| format!("{:?}", wallet)),
            e
        )
    }

    fn update_tx_blocks_panic(
        tx_hashes_and_tx_blocks: &HashMap<TxHash, TransactionBlock>,
        e: SentPayableDaoError,
    ) -> ! {
        panic!(
            "Unable to update sent payable records {} by their tx blocks due to {:?}",
            comma_joined_stringifiable(
                &tx_hashes_and_tx_blocks.keys().sorted().collect_vec(),
                |tx_hash| format!("{:?}", tx_hash)
            ),
            e
        )
    }

    fn log_tx_success(
        logger: &Logger,
        tx_hashes_and_tx_blocks: &HashMap<TxHash, TransactionBlock>,
    ) {
        logger.info(|| {
            let pretty_pairs = tx_hashes_and_tx_blocks
                .iter()
                .sorted()
                .map(|(hash, tx_confirmation)| {
                    format!("{:?} (block {})", hash, tx_confirmation.block_number)
                })
                .join(", ");
            match tx_hashes_and_tx_blocks.len() {
                1 => format!("Tx {} has been confirmed", pretty_pairs),
                _ => format!("Txs {} have been confirmed", pretty_pairs),
            }
        });
    }

    fn add_to_the_total_of_paid_payable(&mut self, confirmed_payments: &[SentTx], logger: &Logger) {
        let to_be_added: u128 = confirmed_payments
            .iter()
            .map(|sent_tx| sent_tx.amount_minor)
            .sum();

        let total_paid_payable = &mut self
            .financial_statistics
            .borrow_mut()
            .total_paid_payable_wei;

        *total_paid_payable += to_be_added;

        debug!(
            logger,
            "The total paid payables increased by {} to {} wei",
            to_be_added.separate_with_commas(),
            total_paid_payable.separate_with_commas()
        );
    }

    fn handle_failed_transactions(&self, failures: DetectedFailures, logger: &Logger) {
        self.handle_tx_failures(failures.tx_failures, logger);
        self.handle_rpc_failures(failures.tx_receipt_rpc_failures, logger);
    }

    fn handle_tx_failures(&self, failures: Vec<PresortedTxFailure>, logger: &Logger) {
        let (new_failures, rechecks_completed): (Vec<FailedTx>, Vec<TxHash>) =
            failures.into_iter().fold(
                (vec![], vec![]),
                |(mut new_failures, mut rechecks_completed), failure| {
                    match failure {
                        PresortedTxFailure::NewEntry(failed_tx) => {
                            todo!()
                        }
                        PresortedTxFailure::RecheckCompleted(hash) => {
                            todo!()
                        }
                    }
                    (new_failures, rechecks_completed)
                },
            );
        self.add_new_failures(new_failures, logger);
        self.finalize_unproven_failures(rechecks_completed, logger);
    }

    fn add_new_failures(&self, new_failures: Vec<FailedTx>, logger: &Logger) {
        todo!()
    }

    fn finalize_unproven_failures(&self, rechecks_completed: Vec<TxHash>, logger: &Logger) {
        todo!()
    }

    fn handle_rpc_failures(&self, failures: Vec<FailedValidationByTable>, logger: &Logger) {
        todo!()
    }

    fn compose_scan_result(
        retry_opt: Option<Retry>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> PendingPayableScanResult {
        if let Some(retry) = retry_opt {
            PendingPayableScanResult::PaymentRetryRequired(retry)
        } else {
            let ui_msg_opt = response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            });
            PendingPayableScanResult::NoPendingPayablesLeft(ui_msg_opt)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedPayableDaoError, FailedTx, FailureReason, FailureRetrieveCondition, FailureStatus, ValidationStatus};
    use crate::accountant::db_access_objects::payable_dao::PayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::{Detection, RetrieveCondition, SentPayableDaoError, TxStatus};
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
    use crate::accountant::scanners::pending_payable_scanner::utils::{handle_status_with_failure, DetectedConfirmations, DetectedFailures, FailedValidation, FailedValidationByTable, NormalTxConfirmation, PendingPayableCache, PresortedTxFailure, ReceiptScanReport, TxByTable, TxHashByTable, TxReclaim};
    use crate::accountant::test_utils::{make_failed_tx, make_sent_tx, make_transaction_block, FailedPayableDaoMock, PayableDaoMock, PendingPayableScannerBuilder, SentPayableDaoMock};
    use crate::accountant::{ResponseSkeleton, TxReceiptsMessage};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{BlockchainTxFailure, RetrievedTxStatus, StatusReadFromReceiptCheck, TransactionBlock, TxReceiptError, TxReceiptResult};
    use crate::blockchain::errors::{AppRpcError, LocalError, RemoteError};
    use crate::blockchain::test_utils::{make_block_hash, make_tx_hash};
    use crate::test_utils::unshared_test_utils::capture_numbers_with_separators_from_str;

    #[test]
    fn interprets_tx_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let test_name = "interprets_tx_receipt_when_transaction_status_is_a_failure";
        let hash = make_tx_hash(0xabc);
        let mut sent_tx = make_sent_tx(2244);
        sent_tx.hash = hash;
        let blockchain_failure = BlockchainTxFailure::Unrecognized;
        let logger = Logger::new(test_name);
        let scan_report = ReceiptScanReport::default();

        let result = handle_status_with_failure(
            scan_report,
            TxByTable::SentPayable(sent_tx.clone()),
            blockchain_failure,
            &logger,
        );

        let failure_reason = blockchain_failure.into();
        let failed_tx = FailedTx::from((sent_tx, failure_reason));
        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![PresortedTxFailure::NewEntry(failed_tx)],
                    tx_receipt_rpc_failures: vec![]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000abc \
            failed on blockchain due to: Failure unrecognized",
        ));
    }

    #[test]
    fn handles_tx_receipt_if_the_tx_keeps_pending() {
        init_test_logging();
        let test_name = "handles_tx_receipt_if_the_tx_keeps_pending";
        let mut subject = PendingPayableScannerBuilder::new().build();
        let hash = make_tx_hash(0x913);
        let sent_tx_timestamp = to_unix_timestamp(
            SystemTime::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
        );
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = hash;
        sent_tx.timestamp = sent_tx_timestamp;
        let failed_tx = make_failed_tx(789);
        let msg = TxReceiptsMessage {
            results: vec![
                TxReceiptResult::Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx.hash),
                    StatusReadFromReceiptCheck::Pending,
                )),
                TxReceiptResult::Ok(RetrievedTxStatus::new(
                    TxHashByTable::FailedPayable(failed_tx.hash),
                    StatusReadFromReceiptCheck::Pending,
                )),
            ],
            response_skeleton_opt: None,
        };
        subject
            .current_sent_payables
            .load_cache(hashmap!(sent_tx.hash => sent_tx.clone()));
        subject
            .yet_unproven_failures
            .load_cache(hashmap!(failed_tx.hash => failed_tx));
        let before = SystemTime::now();

        let result = subject.interpret_tx_receipts(msg, &Logger::new(test_name));

        let after = SystemTime::now();
        let expected_failed_tx = FailedTx::from((sent_tx, FailureReason::PendingTooLong));
        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![PresortedTxFailure::NewEntry(expected_failed_tx)],
                    tx_receipt_rpc_failures: vec![]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        let log_handler = TestLogHandler::new();
        let log_idx = log_handler.exists_log_matching(&format!(
            "INFO: {test_name}: Tx \
            0x0000000000000000000000000000000000000000000000000000000000000913 not confirmed within \
            \\d{{1,3}}(,\\d{{3}})* ms. Will resubmit with higher gas price"
        ));
        let log_msg = log_handler.get_log_at(log_idx);
        let str_elapsed_ms = capture_numbers_with_separators_from_str(&log_msg, 3, ',');
        let elapsed_ms = str_elapsed_ms[0].replace(",", "").parse::<u128>().unwrap();
        let elapsed_ms_when_before = before
            .duration_since(from_unix_timestamp(sent_tx_timestamp))
            .unwrap()
            .as_millis();
        let elapsed_ms_when_after = after
            .duration_since(from_unix_timestamp(sent_tx_timestamp))
            .unwrap()
            .as_millis();
        assert!(
            elapsed_ms_when_before <= elapsed_ms && elapsed_ms <= elapsed_ms_when_after,
            "we expected the elapsed time {} ms to be between {} and {}.",
            elapsed_ms,
            elapsed_ms_when_before,
            elapsed_ms_when_after
        );
    }

    #[test]
    fn interprets_a_failing_attempt_to_retrieve_a_tx_receipt() {
        init_test_logging();
        let test_name = "interprets_a_failing_attempt_to_retrieve_a_tx_receipt";
        let mut subject = PendingPayableScannerBuilder::new().build();
        let tx_hash_1 = make_tx_hash(0x913);
        let tx_hash_2 = make_tx_hash(0x914);
        let sent_tx_timestamp = to_unix_timestamp(
            SystemTime::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
        );
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = tx_hash_1;
        sent_tx.timestamp = sent_tx_timestamp;
        let rpc_error_1 = AppRpcError::Remote(RemoteError::InvalidResponse("bluh".to_string()));
        let rpc_error_2 = AppRpcError::Local(LocalError::Internal);
        let msg = TxReceiptsMessage {
            results: vec![
                TxReceiptResult::Err(TxReceiptError::new(
                    TxHashByTable::SentPayable(tx_hash_1),
                    rpc_error_1.clone(),
                )),
                TxReceiptResult::Err(TxReceiptError::new(
                    TxHashByTable::FailedPayable(tx_hash_2),
                    rpc_error_2.clone(),
                )),
            ],
            response_skeleton_opt: None,
        };

        let result = subject.interpret_tx_receipts(msg, &Logger::new(test_name));

        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![],
                    tx_receipt_rpc_failures: vec![
                        FailedValidationByTable::SentPayable(FailedValidation {
                            tx_hash: tx_hash_1,
                            failure: rpc_error_1
                        }),
                        FailedValidationByTable::FailedPayable(FailedValidation {
                            tx_hash: tx_hash_2,
                            failure: rpc_error_2
                        })
                    ]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        let log_handler = TestLogHandler::new();
        let log_idx = log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Failed to retrieve tx receipt for \
            0x0000000000000000000000000000000000000000000000000000000000000913: \
            Remote(InvalidResponse(\"bluh\")). \
            Will retry receipt retrieval next cycle"
        ));
    }

    #[test]
    fn handle_failed_transactions_can_process_standard_tx_failures() {
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1.clone()),
                PresortedTxFailure::NewEntry(failed_tx_2.clone()),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_records_params,
            vec![vec![failed_tx_1, failed_tx_2]]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![hash_1, hash_2]]);
    }

    #[test]
    fn handle_failed_transactions_can_process_receipt_retrieval_rpc_failures() {
        let retrieve_failed_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let update_status_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_sent_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        failed_tx_1.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        failed_tx_2.status = FailureStatus::RecheckRequired(ValidationStatus::Reattempting {
            attempt: 1,
            error: AppRpcError::Local(LocalError::Internal),
        });
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_failed_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1, failed_tx_2])
            .update_statuses_params(&update_status_params_arc)
            .update_statuses_result(Ok(()));
        let hash_3 = make_tx_hash(0x987);
        let mut sent_tx = make_sent_tx(789);
        sent_tx.hash = hash_3;
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);
        let sent_payable_dao = SentPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_sent_txs_params_arc)
            .retrieve_txs_result(vec![sent_tx.clone()])
            .replace_records_params(&replace_records_params_arc)
            .replace_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![
                FailedValidationByTable::FailedPayable(FailedValidation {
                    tx_hash: hash_1,
                    failure: AppRpcError::Remote(RemoteError::Unreachable),
                }),
                FailedValidationByTable::FailedPayable(FailedValidation {
                    tx_hash: hash_2,
                    failure: AppRpcError::Local(LocalError::Internal),
                }),
                FailedValidationByTable::SentPayable(FailedValidation {
                    tx_hash: hash_1,
                    failure: AppRpcError::Remote(RemoteError::InvalidResponse("Booga".to_string())),
                }),
            ],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let retrieve_failed_txs_params = retrieve_failed_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_failed_txs_params,
            vec![Some(FailureRetrieveCondition::ByTxHash(vec![
                hash_1, hash_2
            ]))]
        );
        let update_status_params = update_status_params_arc.lock().unwrap();
        assert_eq!(
            *update_status_params,
            vec![
                hashmap!(
                    hash_1 => FailureStatus::RecheckRequired(
                        ValidationStatus::Reattempting {
                            attempt: 1,
                            error: AppRpcError::Remote(RemoteError::Unreachable)
                        }
                    ),
                    hash_2 => FailureStatus::RecheckRequired(
                        ValidationStatus::Reattempting {
                            attempt: 2,
                            error: AppRpcError::Local(LocalError::Internal)
                        }
                    )
                )
            ]
        );
        let retrieve_sent_txs_params = retrieve_sent_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_sent_txs_params,
            vec![Some(RetrieveCondition::ByHash(vec![hash_3]))]
        );
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        let mut expected_updated_record = sent_tx;
        expected_updated_record.status = TxStatus::Pending(ValidationStatus::Reattempting {
            attempt: 1,
            error: AppRpcError::Remote(RemoteError::InvalidResponse("Booga".to_string())),
        });
        assert_eq!(*replace_records_params, vec![vec![expected_updated_record]]);
    }

    #[test]
    fn handle_failed_transactions_can_process_mixed_failures() {
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_failed_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let update_status_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_failed_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1.clone()])
            .update_statuses_params(&update_status_params_arc)
            .update_statuses_result(Ok(()))
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![PresortedTxFailure::NewEntry(failed_tx_1)],
            tx_receipt_rpc_failures: vec![FailedValidationByTable::SentPayable(FailedValidation {
                tx_hash: hash_1,
                failure: AppRpcError::Local(LocalError::Internal),
            })],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let retrieve_failed_txs_params = retrieve_failed_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_failed_txs_params,
            vec![Some(FailureRetrieveCondition::ByTxHash(vec![
                hash_1, hash_2
            ]))]
        );
        let update_status_params = update_status_params_arc.lock().unwrap();
        assert_eq!(
            *update_status_params,
            vec![
                hashmap!(hash_1 => FailureStatus::RecheckRequired(ValidationStatus::Reattempting {attempt: 1,error: AppRpcError::Local(LocalError::Internal)}))
            ]
        );
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(*insert_new_records_params, vec![vec![failed_tx_2]]);
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![hash_2]]);
    }

    #[test]
    #[should_panic(expected = "Unable to record failed payables \
        0x000000000000000000000000000000000000000000000000000000000000014d, \
        0x00000000000000000000000000000000000000000000000000000000000001bc due to NoChange")]
    fn handle_failed_transactions_panics_when_it_fails_to_insert_failed_tx_record() {
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_result(Err(FailedPayableDaoError::NoChange));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x14d);
        let hash_2 = make_tx_hash(0x1bc);
        let mut failed_tx_1 = make_failed_tx(789);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1),
                PresortedTxFailure::NewEntry(failed_tx_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));
    }

    #[test]
    #[should_panic(expected = "Unable to delete sent_payable entries for failed txs \
        0x000000000000000000000000000000000000000000000000000000000000014d, \
        0x00000000000000000000000000000000000000000000000000000000000001bc due to \
        InvalidInput(\"Booga\")")]
    fn handle_failed_transactions_panics_when_it_fails_to_delete_obsolete_sent_tx_records() {
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_result(Err(SentPayableDaoError::InvalidInput("Booga".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x14d);
        let hash_2 = make_tx_hash(0x1bc);
        let mut failed_tx_1 = make_failed_tx(789);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1),
                PresortedTxFailure::NewEntry(failed_tx_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));
    }

    #[test]
    fn handle_failed_transactions_does_nothing_if_no_failure_detected() {
        let subject = PendingPayableScannerBuilder::new().build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"))

        //mocked pending payable DAO didn't panic which means we skipped the actual process
    }

    #[test]
    #[should_panic(
        expected = "Unable to update sent payable records 0x000000000000000000000000000000000000000\
        000000000000000000000021a, 0x0000000000000000000000000000000000000000000000000000000000000315 \
        by their tx blocks due to SqlExecutionFailed(\"The database manager is \
        a funny guy, he's fooling around with us\")"
    )]
    fn handle_confirmed_transactions_panics_while_updating_sent_payable_records_with_the_tx_blocks()
    {
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().confirm_tx_result(Err(
            SentPayableDaoError::SqlExecutionFailed(
                "The database manager is a funny guy, he's fooling around with us".to_string(),
            ),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let mut sent_tx_1 = make_sent_tx(456);
        let block = make_transaction_block(678);
        sent_tx_1.hash = make_tx_hash(0x315);
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", block.block_hash),
            block_number: block.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(789);
        sent_tx_2.hash = make_tx_hash(0x21a);
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", block.block_hash),
            block_number: block.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation { tx: sent_tx_1 },
                    NormalTxConfirmation { tx: sent_tx_2 },
                ],
                reclaims: vec![],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    fn handle_confirmed_transactions_does_nothing_if_no_confirmation_found_on_the_blockchain() {
        let mut subject = PendingPayableScannerBuilder::new().build();

        subject
            .handle_confirmed_transactions(DetectedConfirmations::default(), &Logger::new("test"))

        // Mocked payable DAO didn't panic, which means we skipped the actual process
    }

    #[test]
    fn handle_confirmed_transactions_works() {
        init_test_logging();
        let test_name = "handle_confirmed_transactions_works";
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let confirm_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .confirm_tx_params(&confirm_tx_params_arc)
            .confirm_tx_result(Ok(()))
            .replace_records_params(&replace_records_params_arc)
            .replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let logger = Logger::new(test_name);
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let tx_hash_3 = make_tx_hash(0x913);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TransactionBlock {
            block_hash: make_block_hash(45),
            block_number: 4_578_989_878_u64.into(),
        };
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_1.block_hash),
            block_number: tx_block_1.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(987_987);
        sent_tx_2.hash = tx_hash_2;
        let tx_block_2 = TransactionBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_3 = make_sent_tx(567_567);
        sent_tx_3.hash = tx_hash_3;
        let tx_block_3 = TransactionBlock {
            block_hash: make_block_hash(78),
            block_number: 7_898_989_878_u64.into(),
        };
        sent_tx_3.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_3.block_hash),
            block_number: tx_block_3.block_number.as_u64(),
            detection: Detection::Reclaim,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation {
                        tx: sent_tx_1.clone(),
                    },
                    NormalTxConfirmation {
                        tx: sent_tx_2.clone(),
                    },
                ],
                reclaims: vec![TxReclaim {
                    reclaimed: sent_tx_3.clone(),
                }],
            },
            &logger,
        );

        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transactions_confirmed_params,
            vec![vec![sent_tx_1, sent_tx_2, sent_tx_3.clone()]]
        );
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(
            *confirm_tx_params,
            vec![hashmap![tx_hash_1 => tx_block_1, tx_hash_2 => tx_block_2]]
        );
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(*replace_records_params, vec![vec![sent_tx_3]]);
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![tx_hash_3]]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 4578989878), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 7898989878), txxxxbluh (block bluh) have been confirmed",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unable to complete the tx confirmation by the adjustment of the payable accounts \
        0x000000000000000000000077616c6c6574343536 due to \
        RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirmed_transactions_panics_on_unchecking_payable_table() {
        let hash = make_tx_hash(0x315);
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = hash;

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation { tx: sent_tx }],
                reclaims: vec![],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    fn log_tx_success_is_agnostic_to_singular_or_plural_form() {
        init_test_logging();
        let test_name = "log_tx_success_is_agnostic_to_singular_or_plural_form";
        let plural_case_name = format!("{}_testing_plural_case", test_name);
        let singular_case_name = format!("{}_testing_singular_case", test_name);
        let logger_plural = Logger::new(&plural_case_name);
        let logger_singular = Logger::new(&singular_case_name);
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut tx_block_1 = make_transaction_block(456);
        tx_block_1.block_number = 1_234_501_u64.into();
        let mut tx_block_2 = make_transaction_block(789);
        tx_block_2.block_number = 1_234_502_u64.into();
        let mut tx_hashes_and_blocks = hashmap!(tx_hash_1 => tx_block_1, tx_hash_2 => tx_block_2);

        PendingPayableScanner::log_tx_success(&logger_plural, &tx_hashes_and_blocks);

        tx_hashes_and_blocks.remove(&tx_hash_2);

        PendingPayableScanner::log_tx_success(&logger_singular, &tx_hashes_and_blocks);

        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {plural_case_name}: Txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 1234501), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 1234502) have been confirmed",
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {singular_case_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 1234501) has been confirmed",
        ));
    }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        init_test_logging();
        let test_name = "total_paid_payable_rises_with_each_bill_paid";
        let mut sent_tx_1 = make_sent_tx(456);
        sent_tx_1.amount_minor = 5478;
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: 89898,
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(789);
        sent_tx_2.amount_minor = 3344;
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(234)),
            block_number: 66312,
            detection: Detection::Normal,
        };
        let mut sent_tx_3 = make_sent_tx(789);
        sent_tx_3.amount_minor = 6543;
        sent_tx_3.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(321)),
            block_number: 67676,
            detection: Detection::Reclaim,
        };
        let payable_dao = PayableDaoMock::default().transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().confirm_tx_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable_wei += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation { tx: sent_tx_1 },
                    NormalTxConfirmation { tx: sent_tx_2 },
                ],
                reclaims: vec![TxReclaim {
                    reclaimed: sent_tx_3,
                }],
            },
            &Logger::new(test_name),
        );

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable_wei;
        assert_eq!(total_paid_payable, 1111 + 5478 + 3344 + 6543);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: The total paid payables increased by blouuh to bluuuuuh wei"
        ));
    }
}
