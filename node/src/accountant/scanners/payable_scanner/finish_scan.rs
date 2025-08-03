use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableScanResult;
use crate::accountant::scanners::Scanner;
use crate::accountant::SentPayables;
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::time::SystemTime;

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

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::test_utils::TxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::{
        make_pending_payable, PayableScannerBuilder,
    };
    use crate::accountant::scanners::scanners_utils::payable_scanner_utils::OperationOutcome;
    use crate::accountant::scanners::Scanner;
    use crate::accountant::test_utils::SentPayableDaoMock;
    use crate::accountant::{ResponseSkeleton, SentPayables};
    use crate::blockchain::blockchain_interface::data_structures::IndividualBatchResult;
    use actix::System;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::messages::{ToMessageBody, UiScanResponse};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
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
}
