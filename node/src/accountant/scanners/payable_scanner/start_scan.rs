use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition;
use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    QualifiedPayablesMessage, UnpricedQualifiedPayables,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::investigate_debt_extremes;
use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
use crate::accountant::{ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::time::SystemTime;

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
        let all_non_pending_payables = self.payable_dao.non_pending_payables(None);

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
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<QualifiedPayablesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for retry payables");
        self.failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)));

        Ok(QualifiedPayablesMessage {
            qualified_payables: UnpricedQualifiedPayables { payables: vec![] },
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt,
        })
        // 1. Find the failed payables
        // 2. Look into the payable DAO to update the amount
        // 3. Prepare UnpricedQualifiedPayables

        // 1. Fetch all records with RetryRequired
        // 2. Query the txs with the same accounts from the PayableDao
        // 3. Form UnpricedQualifiedPayables, a collection vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::PendingTooLong;
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDao, FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
    use crate::accountant::db_access_objects::test_utils::FailedTxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::Scanners;
    use crate::accountant::test_utils::{FailedPayableDaoMock, PayableDaoMock};
    use crate::accountant::PendingPayableId;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_paying_wallet;
    use actix::System;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn start_scan_for_retry_works() {
        init_test_logging();
        let test_name = "start_scan_for_retry_works";
        let logger = Logger::new(test_name);
        let failed_payables_retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let timestamp = SystemTime::now();
        let client_id = 1234;
        let context_id = 4321;
        let tx_hash_1 = make_tx_hash(1);
        let failed_tx_1 = FailedTxBuilder::default()
            .nonce(1)
            .hash(tx_hash_1)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let consuming_wallet = make_paying_wallet(b"consuming");
        let failed_payable_dao = FailedPayableDaoMock::new()
            .retrieve_txs_params(&failed_payables_retrieve_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1]);
        let payable_dao = PayableDaoMock::new();
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .payable_dao(payable_dao)
            .build();
        let system = System::new(test_name);

        let result = Scanners::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut subject,
            &consuming_wallet,
            timestamp,
            Some(ResponseSkeleton {
                client_id,
                context_id,
            }),
            &logger,
        );

        System::current().stop();
        let scan_started_at = subject.scan_started_at();
        let failed_payables_retrieve_txs_params =
            failed_payables_retrieve_txs_params_arc.lock().unwrap();
        assert_eq!(
            result,
            Ok(QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables { payables: vec![] },
                consuming_wallet: consuming_wallet.clone(),
                response_skeleton_opt: Some(ResponseSkeleton {
                    client_id,
                    context_id,
                }),
            })
        );
        assert_eq!(scan_started_at, Some(timestamp));
        assert_eq!(
            failed_payables_retrieve_txs_params[0],
            Some(ByStatus(FailureStatus::RetryRequired))
        );
        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: {test_name}: Scanning for retry payables"));
    }
}
