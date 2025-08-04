use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableScanResult;
use crate::accountant::scanners::Scanner;
use crate::accountant::SentPayables;
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::time::SystemTime;

impl Scanner<SentPayables, PayableScanResult> for PayableScanner {
    fn finish_scan(&mut self, msg: SentPayables, logger: &Logger) -> PayableScanResult {
        self.process_message(msg.clone(), logger);

        self.mark_as_ended(logger);

        PayableScanResult {
            ui_response_opt: Self::generate_ui_response(msg.response_skeleton_opt),
            result: Self::detect_outcome(&msg),
        }
    }

    time_marking_methods!(Payables);

    as_any_ref_in_trait_impl!();
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::test_utils::TxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::{
        make_pending_payable, PayableScannerBuilder,
    };
    use crate::accountant::scanners::payable_scanner::tests::{make_failed_tx, make_sent_tx};
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{
        OperationOutcome, PayableScanResult,
    };
    use crate::accountant::scanners::Scanner;
    use crate::accountant::test_utils::{FailedPayableDaoMock, SentPayableDaoMock};
    use crate::accountant::{PayableScanType, ResponseSkeleton, SentPayables};
    use crate::blockchain::blockchain_interface::data_structures::{
        BatchResults, IndividualBatchResult,
    };
    use actix::System;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::messages::{ToMessageBody, UiScanResponse};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn finish_scan_works_as_expected() {
        init_test_logging();
        let test_name = "finish_scan_works_as_expected";
        let system = System::new(test_name);
        let pending_payable = make_pending_payable(1);
        let tx = TxBuilder::default()
            .hash(pending_payable.hash)
            .nonce(1)
            .build();
        let sent_payable_dao = SentPayableDaoMock::default().retrieve_txs_result(vec![tx]);
        let mut subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        todo!("BatchResults");
        // let sent_payables = SentPayables {
        //     payment_procedure_result: Either::Left(vec![IndividualBatchResult::Pending(
        //         pending_payable,
        //     )]),
        //     response_skeleton_opt: Some(ResponseSkeleton {
        //         client_id: 1234,
        //         context_id: 5678,
        //     }),
        // };
        // subject.mark_as_started(SystemTime::now());
        //
        // let scan_result = subject.finish_scan(sent_payables, &logger);
        //
        // System::current().stop();
        // system.run();
        // assert_eq!(scan_result.result, OperationOutcome::NewPendingPayable);
        // assert_eq!(
        //     scan_result.ui_response_opt,
        //     Some(NodeToUiMessage {
        //         target: MessageTarget::ClientId(1234),
        //         body: UiScanResponse {}.tmb(5678),
        //     })
        // );
        // TestLogHandler::new().exists_log_matching(&format!(
        //     "INFO: {test_name}: The Payables scan ended in \\d+ms."
        // ));
    }

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
            vec![sent_tx_1, sent_tx_2]
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
                result: OperationOutcome::NewPendingPayable,
            }
        );
        TestLogHandler::new().exists_log_matching(&format!(
            "INFO: {test_name}: The Payables scan ended in \\d+ms."
        ));
    }
}
