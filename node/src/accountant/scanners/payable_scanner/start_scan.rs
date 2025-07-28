use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::utils::from_unix_timestamp;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    QualifiedPayablesBeforeGasPriceSelection, QualifiedPayablesMessage, UnpricedQualifiedPayables,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::investigate_debt_extremes;
use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
use crate::accountant::{ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::collections::BTreeSet;
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
        let txs_to_retry = self.get_txs_to_retry();
        let payables_from_db = self.find_corresponding_payables_in_db(&txs_to_retry);
        let payables = Self::create_updated_payables(&payables_from_db, &txs_to_retry);

        Ok(QualifiedPayablesMessage {
            qualified_payables: UnpricedQualifiedPayables { payables },
            consuming_wallet: consuming_wallet.clone(),
            response_skeleton_opt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailureReason::PendingTooLong;
    use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus;
    use crate::accountant::db_access_objects::payable_dao::{
        PayableAccount, PayableRetrieveCondition,
    };
    use crate::accountant::db_access_objects::test_utils::FailedTxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner_extension::msgs::QualifiedPayablesBeforeGasPriceSelection;
    use crate::accountant::scanners::Scanners;
    use crate::accountant::test_utils::{
        make_payable_account, FailedPayableDaoMock, PayableDaoMock,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::System;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn start_scan_for_retry_works() {
        init_test_logging();
        let test_name = "start_scan_for_retry_works";
        let logger = Logger::new(test_name);
        let retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let non_pending_payables_params_arc = Arc::new(Mutex::new(vec![]));
        let timestamp = SystemTime::now();
        let consuming_wallet = make_paying_wallet(b"consuming");
        let response_skeleton = ResponseSkeleton {
            client_id: 1234,
            context_id: 4321,
        };
        let payable_account_1 = make_payable_account(42);
        let receiver_address_1 = payable_account_1.wallet.address();
        let receiever_wallet_2 = make_wallet("absent in payable dao");
        let receiver_address_2 = receiever_wallet_2.address();
        let failed_tx_1 = FailedTxBuilder::default()
            .nonce(1)
            .hash(make_tx_hash(1))
            .receiver_address(receiver_address_1)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let failed_tx_2 = FailedTxBuilder::default()
            .nonce(2)
            .hash(make_tx_hash(2))
            .receiver_address(receiver_address_2)
            .reason(PendingTooLong)
            .status(RetryRequired)
            .build();
        let expected_addresses = BTreeSet::from([receiver_address_1, receiver_address_2]);
        let failed_payable_dao = FailedPayableDaoMock::new()
            .retrieve_txs_params(&retrieve_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1.clone(), failed_tx_2.clone()]);
        let payable_dao = PayableDaoMock::new()
            .non_pending_payables_params(&non_pending_payables_params_arc)
            .non_pending_payables_result(vec![payable_account_1.clone()]); // the second record is absent
        let mut subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .payable_dao(payable_dao)
            .build();

        let result = Scanners::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut subject,
            &consuming_wallet,
            timestamp,
            Some(response_skeleton),
            &logger,
        );

        let scan_started_at = subject.scan_started_at();
        let failed_payables_retrieve_txs_params = retrieve_txs_params_arc.lock().unwrap();
        let non_pending_payables_params = non_pending_payables_params_arc.lock().unwrap();
        let expected_payables = {
            let mut payables_vec = vec![];
            let mut expected_payable_1 = payable_account_1;
            expected_payable_1.balance_wei = expected_payable_1.balance_wei + failed_tx_1.amount;
            payables_vec.push(QualifiedPayablesBeforeGasPriceSelection {
                payable: expected_payable_1,
                previous_attempt_gas_price_minor_opt: Some(failed_tx_1.gas_price_wei),
            });

            let expected_payable_2 = PayableAccount {
                wallet: receiever_wallet_2,
                balance_wei: failed_tx_2.amount,
                last_paid_timestamp: from_unix_timestamp(failed_tx_2.timestamp),
                pending_payable_opt: None,
            };
            payables_vec.push(QualifiedPayablesBeforeGasPriceSelection {
                payable: expected_payable_2,
                previous_attempt_gas_price_minor_opt: Some(failed_tx_2.gas_price_wei),
            });

            payables_vec
        };
        assert_eq!(
            result,
            Ok(QualifiedPayablesMessage {
                qualified_payables: UnpricedQualifiedPayables {
                    payables: expected_payables
                },
                consuming_wallet: consuming_wallet.clone(),
                response_skeleton_opt: Some(response_skeleton),
            })
        );
        assert_eq!(scan_started_at, Some(timestamp));
        assert_eq!(
            failed_payables_retrieve_txs_params[0],
            Some(ByStatus(FailureStatus::RetryRequired))
        );
        assert_eq!(failed_payables_retrieve_txs_params.len(), 1);
        assert_eq!(
            non_pending_payables_params[0],
            Some(PayableRetrieveCondition::ByAddresses(expected_addresses))
        );
        assert_eq!(non_pending_payables_params.len(), 1);
        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: {test_name}: Scanning for retry payables"));
    }
}
