// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::{ScanCleanUpError, Scanner};
use crate::accountant::{PayableScanType, SentPayables, SimplePayable};
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::time::SystemTime;

impl Scanner<SentPayables, PayableScanResult, PayableScannerCleanupArgs> for PayableScanner {
    fn finish_scan(&mut self, msg: SentPayables, logger: &Logger) -> PayableScanResult {
        // TODO: Remove this check once GH-655 is implemented. Until then, keep it.
        if !msg.batch_results.sent_txs.is_empty() || !msg.batch_results.failed_txs.is_empty() {
            let payables = Self::collect_simple_payables_from_batch_results(&msg.batch_results);
            self.check_on_missing_sent_txs(msg.payable_scan_type, &payables);
        }

        self.process_sent_payables(&msg, logger);

        self.mark_as_ended(logger);

        PayableScanResult {
            ui_response_opt: Self::generate_ui_response(msg.response_skeleton_opt),
        }
    }

    fn clean_up_after_error(
        &mut self,
        args: PayableScannerCleanupArgs,
        logger: &Logger,
    ) -> Result<(), ScanCleanUpError> {
        debug!(
            logger,
            "Cleaning up in the {} payable scanner after a scan error", args.payable_scan_type
        );

        if !args.failed_txs.is_empty() {
            // TODO: Remove this check once GH-655 is implemented. Until then, keep it.
            let payables = Self::collect_simple_payables_from_cleanup_args(&args);
            self.check_on_missing_sent_txs(args.payable_scan_type, &payables);
            //TODO check out if this is properly tested
            self.process_failed_payables(&args.failed_txs, logger);
        }

        self.mark_as_ended(logger);

        Ok(())
    }

    time_marking_methods!(Payables);

    as_any_ref_in_trait_impl!();
}

pub struct PayableScannerCleanupArgs {
    pub payable_scan_type: PayableScanType,
    pub failed_txs: Vec<FailedTx>,
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureStatus};
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, FailedTxBuilder,
    };
    use crate::accountant::db_access_objects::utils::TxHash;
    use crate::accountant::scanners::payable_scanner::finish_scan::PayableScannerCleanupArgs;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
    use crate::accountant::scanners::Scanner;
    use crate::accountant::test_utils::{
        FailedPayableDaoMock, PendingPayableScannerBuilder, SentPayableDaoMock,
    };
    use crate::accountant::{
        join_with_separator, PayableScanType, ResponseSkeleton, SentPayables, SimplePayable,
    };
    use crate::blockchain::blockchain_interface::data_structures::BatchResults;
    use crate::blockchain::errors::validation_status::ValidationStatus::Waiting;
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::logger::Logger;
    use masq_lib::messages::{ToMessageBody, UiScanResponse};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn new_payable_scan_finishes_as_expected() {
        init_test_logging();
        let test_name = "new_payable_scan_finishes_as_expected";
        let get_existing_tx_records_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_tx_1 = make_failed_tx(12);
        let failed_tx_2 = make_failed_tx(22);
        let sent_tx_1 = make_sent_tx(19);
        let sent_tx_2 = make_sent_tx(29);
        let hashes = btreeset![
            sent_tx_1.hash,
            sent_tx_2.hash,
            failed_tx_1.hash,
            failed_tx_2.hash
        ];
        let batch_results = BatchResults {
            sent_txs: vec![sent_tx_1.clone(), sent_tx_2.clone()],
            failed_txs: vec![failed_tx_1.clone(), failed_tx_2.clone()],
        };
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 5678,
        };
        let sent_payable_dao = SentPayableDaoMock::default()
            .get_existing_tx_records_params(&get_existing_tx_records_params_arc)
            .get_existing_tx_records_result(hashes.clone())
            .insert_new_records_params(&sent_payable_insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&failed_payable_insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        subject.mark_as_started(SystemTime::now());
        let sent_payables = SentPayables {
            batch_results,
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: Some(response_skeleton),
        };
        let logger = Logger::new(test_name);

        let result = subject.finish_scan(sent_payables, &logger);

        let get_existing_tx_records_params = get_existing_tx_records_params_arc.lock().unwrap();
        assert_eq!(*get_existing_tx_records_params, vec![hashes]);
        let sent_payable_insert_new_records_params =
            sent_payable_insert_new_records_params_arc.lock().unwrap();
        let failed_payable_insert_new_records_params =
            failed_payable_insert_new_records_params_arc.lock().unwrap();
        assert_eq!(sent_payable_insert_new_records_params.len(), 1);
        assert_eq!(
            sent_payable_insert_new_records_params[0],
            BTreeSet::from([sent_tx_1, sent_tx_2])
        );
        assert_eq!(failed_payable_insert_new_records_params.len(), 1);
        assert!(failed_payable_insert_new_records_params[0].contains(&failed_tx_1));
        assert!(failed_payable_insert_new_records_params[0].contains(&failed_tx_2));
        assert_eq!(
            result,
            PayableScanResult {
                ui_response_opt: Some(NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                }),
            }
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }

    #[test]
    fn retry_payable_scan_finishes_as_expected() {
        init_test_logging();
        let test_name = "retry_payable_scan_finishes_as_expected";
        let get_existing_tx_records_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_update_statuses_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_tx_1 = make_failed_tx(12);
        let failed_tx_2 = make_failed_tx(22);
        let sent_tx_1 = make_sent_tx(19);
        let sent_tx_2 = make_sent_tx(29);
        let hashes = btreeset![
            sent_tx_1.hash,
            sent_tx_2.hash,
            failed_tx_1.hash,
            failed_tx_2.hash
        ];
        let sent_txs = vec![sent_tx_1, sent_tx_2];
        let failed_txs = vec![failed_tx_1, failed_tx_2];
        let sent_payable_dao = SentPayableDaoMock::default()
            .get_existing_tx_records_params(&get_existing_tx_records_params_arc)
            .get_existing_tx_records_result(hashes.clone())
            .insert_new_records_params(&sent_payable_insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let prev_failed_txs: BTreeSet<FailedTx> = sent_txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let i = (i + 1) * 10;
                FailedTxBuilder::default()
                    .hash(make_tx_hash(i as u32))
                    .nonce(i as u64)
                    .receiver_address(tx.receiver_address)
                    .build()
            })
            .collect();
        let failed_paybale_dao = FailedPayableDaoMock::default()
            .update_statuses_params(&failed_payable_update_statuses_params_arc)
            .retrieve_txs_result(prev_failed_txs)
            .update_statuses_result(Ok(()));
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_paybale_dao)
            .build();
        subject.mark_as_started(SystemTime::now());
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 5678,
        };
        let sent_payables = SentPayables {
            batch_results: BatchResults {
                sent_txs: sent_txs.clone(),
                failed_txs: failed_txs.clone(),
            },
            payable_scan_type: PayableScanType::Retry,
            response_skeleton_opt: Some(response_skeleton),
        };
        let logger = Logger::new(test_name);

        let result = subject.finish_scan(sent_payables, &logger);

        let get_existing_tx_records_params = get_existing_tx_records_params_arc.lock().unwrap();
        assert_eq!(*get_existing_tx_records_params, vec![hashes]);
        let sent_payable_insert_new_records_params =
            sent_payable_insert_new_records_params_arc.lock().unwrap();
        let failed_payable_update_statuses_params =
            failed_payable_update_statuses_params_arc.lock().unwrap();
        assert_eq!(
            sent_payable_insert_new_records_params[0],
            sent_txs.iter().cloned().collect::<BTreeSet<_>>()
        );
        assert_eq!(sent_payable_insert_new_records_params.len(), 1);
        let updated_statuses = failed_payable_update_statuses_params[0].clone();
        assert_eq!(failed_payable_update_statuses_params.len(), 1);

        assert_eq!(updated_statuses.len(), 2);
        assert_eq!(
            updated_statuses.get(&make_tx_hash(10)).unwrap(),
            &FailureStatus::RecheckRequired(Waiting)
        );
        assert_eq!(
            updated_statuses.get(&make_tx_hash(20)).unwrap(),
            &FailureStatus::RecheckRequired(Waiting)
        );
        assert_eq!(
            result,
            PayableScanResult {
                ui_response_opt: Some(NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                }),
            }
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "WARN: {test_name}: While retrying, 2 transactions with hashes: {} have failed.",
            join_with_separator(failed_txs, |failed_tx| format!("{:?}", failed_tx.hash), ",")
        ));
        tlh.exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000019 to recipient: \
    0x000000000000000000004b00000000004b000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000029 to recipient: \
    0x000000000000000000007b00000000007b000000) \
    were not found once the payment should have completed in the new payable scanner. \
    System is in an unreliable state")]
    fn new_payable_scanner_finishes_scan_by_panicking_on_missing_only_sent_tx_records() {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_only_sent_tx_records(
            PayableScanType::New,
        );
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000019 to recipient: \
    0x000000000000000000004b00000000004b000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000029 to recipient: \
    0x000000000000000000007b00000000007b000000) \
    were not found once the payment should have completed in the retry payable scanner. \
    System is in an unreliable state")]
    fn retry_payable_scanner_finishes_scan_by_panicking_on_missing_only_sent_tx_records() {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_only_sent_tx_records(
            PayableScanType::Retry,
        )
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000012 to recipient: \
    0x00000000000000000003cc0000000003cc000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000032 to recipient: \
    0x0000000000000000001d4c000000001d4c000000) \
    were not found once the payment should have completed in the new payable scanner. \
    System is in an unreliable state")]
    fn new_payable_scanner_finishes_scan_by_panicking_on_missing_only_failed_tx_records() {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_only_failed_tx_records(
            PayableScanType::New,
        );
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000012 to recipient: \
    0x00000000000000000003cc0000000003cc000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000032 to recipient: \
    0x0000000000000000001d4c000000001d4c000000) \
    were not found once the payment should have completed in the retry payable scanner. \
    System is in an unreliable state")]
    fn retry_payable_scanner_finishes_scan_by_panicking_on_missing_only_failed_tx_records() {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_only_failed_tx_records(
            PayableScanType::Retry,
        )
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000019 to recipient: \
    0x000000000000000000004b00000000004b000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000039 to recipient: \
    0x00000000000000000000ab0000000000ab000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000022 to recipient: \
    0x0000000000000000000d8c000000000d8c000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000032 to recipient: \
    0x0000000000000000001d4c000000001d4c000000) \
    were not found once the payment should have completed in the new payable scanner. \
    System is in an unreliable state")]
    fn new_payable_scanner_finishes_scan_by_panicking_on_missing_both_sent_and_failed_tx_records() {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_both_sent_and_failed_tx_records(
            PayableScanType::New,
        );
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x0000000000000000000000000000000000000000000000000000000000000019 to recipient: \
    0x000000000000000000004b00000000004b000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000039 to recipient: \
    0x00000000000000000000ab0000000000ab000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000022 to recipient: \
    0x0000000000000000000d8c000000000d8c000000), \
    (tx: 0x0000000000000000000000000000000000000000000000000000000000000032 to recipient: \
    0x0000000000000000001d4c000000001d4c000000) \
    were not found once the payment should have completed in the retry payable scanner. \
    System is in an unreliable state")]
    fn retry_payable_scanner_finishes_scan_by_panicking_on_missing_both_sent_and_failed_tx_records()
    {
        test_payable_scanner_finishes_scan_by_panicking_on_missing_both_sent_and_failed_tx_records(
            PayableScanType::Retry,
        )
    }

    fn test_payable_scanner_finishes_scan_by_panicking_on_missing_only_sent_tx_records(
        payable_scan_type: PayableScanType,
    ) {
        let failed_tx_1 = make_failed_tx(0x12);
        let failed_tx_1_hash = failed_tx_1.hash.clone();
        let failed_tx_2 = make_failed_tx(0x22);
        let failed_tx_2_hash = failed_tx_2.hash.clone();
        let sent_tx_1 = make_sent_tx(0x19);
        let sent_tx_2 = make_sent_tx(0x29);
        let sent_tx_3 = make_sent_tx(0x39);
        let sent_tx_3_hash = sent_tx_3.hash.clone();
        let batch_results = BatchResults {
            sent_txs: vec![sent_tx_1, sent_tx_2, sent_tx_3],
            failed_txs: vec![failed_tx_1, failed_tx_2],
        };
        let get_existing_tx_records_result =
            btreeset!(sent_tx_3_hash, failed_tx_1_hash, failed_tx_2_hash);

        test_payable_scanner_finishes_scan_by_panicking_on_missing_tx_records(
            payable_scan_type,
            batch_results,
            get_existing_tx_records_result,
        )
    }

    fn test_payable_scanner_finishes_scan_by_panicking_on_missing_only_failed_tx_records(
        payable_scan_type: PayableScanType,
    ) {
        let failed_tx_1 = make_failed_tx(0x12);
        let failed_tx_2 = make_failed_tx(0x22);
        let failed_tx_2_hash = failed_tx_2.hash.clone();
        let failed_tx_3 = make_failed_tx(0x32);
        let sent_tx_1 = make_sent_tx(0x19);
        let sent_tx_1_hash = sent_tx_1.hash.clone();
        let sent_tx_2 = make_sent_tx(0x29);
        let sent_tx_2_hash = sent_tx_2.hash.clone();
        let batch_results = BatchResults {
            sent_txs: vec![sent_tx_1, sent_tx_2],
            failed_txs: vec![failed_tx_1, failed_tx_2, failed_tx_3],
        };
        let get_existing_tx_records_result =
            btreeset!(failed_tx_2_hash, sent_tx_1_hash, sent_tx_2_hash);

        test_payable_scanner_finishes_scan_by_panicking_on_missing_tx_records(
            payable_scan_type,
            batch_results,
            get_existing_tx_records_result,
        )
    }

    fn test_payable_scanner_finishes_scan_by_panicking_on_missing_both_sent_and_failed_tx_records(
        payable_scan_type: PayableScanType,
    ) {
        let failed_tx_1 = make_failed_tx(0x12);
        let failed_tx_1_hash = failed_tx_1.hash.clone();
        let failed_tx_2 = make_failed_tx(0x22);
        let failed_tx_3 = make_failed_tx(0x32);
        let sent_tx_1 = make_sent_tx(0x19);
        let sent_tx_2 = make_sent_tx(0x29);
        let sent_tx_2_hash = sent_tx_2.hash.clone();
        let sent_tx_3 = make_sent_tx(0x39);
        let batch_results = BatchResults {
            sent_txs: vec![sent_tx_1, sent_tx_2, sent_tx_3],
            failed_txs: vec![failed_tx_1, failed_tx_2, failed_tx_3],
        };
        let get_existing_tx_records_result = btreeset!(failed_tx_1_hash, sent_tx_2_hash);

        test_payable_scanner_finishes_scan_by_panicking_on_missing_tx_records(
            payable_scan_type,
            batch_results,
            get_existing_tx_records_result,
        )
    }

    fn test_payable_scanner_finishes_scan_by_panicking_on_missing_tx_records(
        payable_scan_type: PayableScanType,
        batch_results: BatchResults,
        get_existing_tx_records_result: BTreeSet<TxHash>,
    ) {
        let sent_payable_dao = SentPayableDaoMock::default()
            .get_existing_tx_records_result(get_existing_tx_records_result);
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        subject.mark_as_started(SystemTime::now());
        let sent_payables = SentPayables {
            batch_results,
            payable_scan_type,
            response_skeleton_opt: None,
        };
        let logger = Logger::new("test");

        let _ = subject.finish_scan(sent_payables, &logger);
    }

    #[test]
    fn clean_up_after_error_happy_path_for_new_payable_scanner() {
        test_clean_up_after_error_happy_path(PayableScanType::New);
    }

    #[test]
    fn clean_up_after_error_happy_path_for_retry_payable_scanner() {
        test_clean_up_after_error_happy_path(PayableScanType::Retry);
    }

    fn test_clean_up_after_error_happy_path(payable_scan_type: PayableScanType) {
        let get_existing_tx_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_tx_1 = make_failed_tx(123);
        let tx_hash_1 = failed_tx_1.hash.clone();
        let failed_tx_2 = make_failed_tx(456);
        let tx_hash_2 = failed_tx_2.hash.clone();
        let existing_tx_records = btreeset!(tx_hash_1, tx_hash_2);
        let sent_payable_dao = SentPayableDaoMock::default()
            .get_existing_tx_records_params(&get_existing_tx_records_params_arc)
            .get_existing_tx_records_result(existing_tx_records);
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        subject.mark_as_started(SystemTime::now());

        let result = subject.clean_up_after_error(
            PayableScannerCleanupArgs {
                payable_scan_type,
                failed_txs: vec![failed_tx_1, failed_tx_2],
            },
            &Logger::new("test"),
        );

        assert_eq!(result, Ok(()));
        assert_eq!(subject.scan_started_at(), None);
        let get_existing_tx_records_params = get_existing_tx_records_params_arc.lock().unwrap();
        assert_eq!(
            *get_existing_tx_records_params,
            vec![btreeset![tx_hash_1, tx_hash_2]]
        );
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x00000000000000000000000000000000000000000000000000000000000001c8 to recipient: \
    0x0000000000000000002556000000002556000000) were not found once the payment should have \
    completed in the new payable scanner. System is in an unreliable state")]
    fn clean_up_after_error_sad_path_for_new_payable_scanner() {
        test_clean_up_after_error_sad_path(PayableScanType::New);
    }

    #[test]
    #[should_panic(expected = "Expected sent-payable records for (tx: \
    0x00000000000000000000000000000000000000000000000000000000000001c8 to recipient: \
    0x0000000000000000002556000000002556000000) were not found once the payment should have \
    completed in the retry payable scanner. System is in an unreliable state")]
    fn clean_up_after_error_sad_path_for_retry_payable_scanner() {
        test_clean_up_after_error_sad_path(PayableScanType::Retry);
    }

    fn test_clean_up_after_error_sad_path(payable_scan_type: PayableScanType) {
        let failed_tx_1 = make_failed_tx(123);
        let tx_hash_1 = failed_tx_1.hash.clone();
        let failed_tx_2 = make_failed_tx(456);
        let tx_hash_2 = failed_tx_2.hash.clone();
        let existing_tx_records = btreeset!(tx_hash_1);
        let sent_payable_dao =
            SentPayableDaoMock::default().get_existing_tx_records_result(existing_tx_records);
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        subject.mark_as_started(SystemTime::now());

        let _ = subject.clean_up_after_error(
            PayableScannerCleanupArgs {
                payable_scan_type,
                failed_txs: vec![failed_tx_1, failed_tx_2],
            },
            &Logger::new("test"),
        );
    }
}
