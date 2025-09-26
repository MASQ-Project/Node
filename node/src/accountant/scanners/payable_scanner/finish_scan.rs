// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::Scanner;
use crate::accountant::SentPayables;
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::time::SystemTime;

impl Scanner<SentPayables, PayableScanResult> for PayableScanner {
    fn finish_scan(&mut self, msg: SentPayables, logger: &Logger) -> PayableScanResult {
        self.process_message(&msg, logger);

        self.mark_as_ended(logger);

        PayableScanResult {
            ui_response_opt: Self::generate_ui_response(msg.response_skeleton_opt),
            result: Self::determine_next_scan_to_run(&msg),
        }
    }

    time_marking_methods!(Payables);

    as_any_ref_in_trait_impl!();
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureStatus};
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, FailedTxBuilder,
    };
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner::utils::{NextScanToRun, PayableScanResult};
    use crate::accountant::scanners::Scanner;
    use crate::accountant::test_utils::{FailedPayableDaoMock, SentPayableDaoMock};
    use crate::accountant::{join_with_separator, PayableScanType, ResponseSkeleton, SentPayables};
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
        let sent_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_tx_1 = make_failed_tx(1);
        let failed_tx_2 = make_failed_tx(2);
        let sent_tx_1 = make_sent_tx(1);
        let sent_tx_2 = make_sent_tx(2);
        let batch_results = BatchResults {
            sent_txs: vec![sent_tx_1.clone(), sent_tx_2.clone()],
            failed_txs: vec![failed_tx_1.clone(), failed_tx_2.clone()],
        };
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 5678,
        };
        let sent_payable_dao = SentPayableDaoMock::default()
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
            payment_procedure_result: Ok(batch_results),
            payable_scan_type: PayableScanType::New,
            response_skeleton_opt: Some(response_skeleton),
        };
        let logger = Logger::new(test_name);

        let result = subject.finish_scan(sent_payables, &logger);

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
                result: NextScanToRun::PendingPayableScan,
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
        let sent_payable_insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_update_statuses_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&sent_payable_insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_txs = vec![make_sent_tx(1), make_sent_tx(2)];
        let failed_txs = vec![make_failed_tx(1), make_failed_tx(2)];
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
            payment_procedure_result: Ok(BatchResults {
                sent_txs: sent_txs.clone(),
                failed_txs: failed_txs.clone(),
            }),
            payable_scan_type: PayableScanType::Retry,
            response_skeleton_opt: Some(response_skeleton),
        };
        let logger = Logger::new(test_name);

        let result = subject.finish_scan(sent_payables, &logger);

        let sent_payable_insert_new_records_params =
            sent_payable_insert_new_records_params_arc.lock().unwrap();
        let failed_payable_update_statuses_params =
            failed_payable_update_statuses_params_arc.lock().unwrap();
        assert_eq!(sent_payable_insert_new_records_params.len(), 1);
        assert_eq!(
            sent_payable_insert_new_records_params[0],
            sent_txs.iter().cloned().collect::<BTreeSet<_>>()
        );
        assert_eq!(failed_payable_update_statuses_params.len(), 1);
        let updated_statuses = failed_payable_update_statuses_params[0].clone();
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
                result: NextScanToRun::PendingPayableScan,
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
    fn payable_scanner_with_error_works_as_expected() {
        test_execute_payable_scanner_finish_scan_with_an_error(PayableScanType::New, "new");
        test_execute_payable_scanner_finish_scan_with_an_error(PayableScanType::Retry, "retry");
    }

    fn test_execute_payable_scanner_finish_scan_with_an_error(
        payable_scan_type: PayableScanType,
        suffix: &str,
    ) {
        init_test_logging();
        let test_name = &format!("test_execute_payable_scanner_finish_scan_with_an_error_{suffix}");
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 5678,
        };
        let mut subject = PayableScannerBuilder::new().build();
        subject.mark_as_started(SystemTime::now());
        let sent_payables = SentPayables {
            payment_procedure_result: Err("Any error".to_string()),
            payable_scan_type,
            response_skeleton_opt: Some(response_skeleton),
        };
        let logger = Logger::new(test_name);

        let result = subject.finish_scan(sent_payables, &logger);

        assert_eq!(
            result,
            PayableScanResult {
                ui_response_opt: Some(NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                }),
                result: match payable_scan_type {
                    PayableScanType::New => NextScanToRun::NewPayableScan,
                    PayableScanType::Retry => NextScanToRun::RetryPayableScan,
                },
            }
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "WARN: {test_name}: Local error occurred before transaction signing. Error: Any error"
        ));
        tlh.exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }
}
