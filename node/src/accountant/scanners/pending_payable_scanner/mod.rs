// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::SystemTime;
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use crate::accountant::db_access_objects::payable_dao::PayableDao;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDao;
use crate::accountant::{comma_joined_stringifiable, PendingPayableId, ReportTransactionReceipts, RequestTransactionReceipts, ResponseSkeleton, ScanForPendingPayables};
use crate::accountant::scanners::{PrivateScanner, Scanner, ScannerCommon, StartScanError, StartableScanner};
use crate::accountant::scanners::pending_payable_scanner::utils::{handle_none_receipt, handle_status_with_failure, handle_status_with_success, PendingPayableScanReport, PendingPayableScanResult};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionReceiptResult, TxStatus};
use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::time_marking_methods;

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

#[cfg(test)]
mod tests {
    use std::ops::Sub;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use ethereum_types::{H256, U64};
    use regex::Regex;
    use web3::types::TransactionReceipt;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::accountant::{PendingPayableId, ReportTransactionReceipts, DEFAULT_PENDING_TOO_LONG_SEC};
    use crate::accountant::db_access_objects::payable_dao::PayableDaoError;
    use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDaoError;
    use crate::accountant::db_access_objects::utils::from_unix_timestamp;
    use crate::accountant::scanners::pending_payable_scanner::utils::{handle_none_status, handle_status_with_failure, PendingPayableScanReport};
    use crate::accountant::test_utils::{make_pending_payable_fingerprint, PayableDaoMock, PendingPayableDaoMock, PendingPayableScannerBuilder};
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionReceiptResult, TxReceipt, TxStatus};
    use crate::blockchain::test_utils::make_tx_hash;

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
}
