// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::RetryTxTemplates;
use crate::accountant::scanners::payable_scanner::utils::investigate_debt_extremes;
use crate::accountant::scanners::payable_scanner::PayableScanner;
use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
use crate::accountant::{ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables};
use crate::sub_lib::wallet::Wallet;
use itertools::Either;
use masq_lib::logger::Logger;
use std::time::SystemTime;

impl StartableScanner<ScanForNewPayables, InitialTemplatesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<InitialTemplatesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for new payables");
        let all_retrieved_payables = self.payable_dao.retrieve_payables(None);

        debug!(
            logger,
            "{}",
            investigate_debt_extremes(timestamp, &all_retrieved_payables)
        );

        let qualified_payables =
            self.sniff_out_alarming_payables_and_maybe_log_them(all_retrieved_payables, logger);

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
                let new_tx_templates = NewTxTemplates::from(&qualified_payables);
                Ok(InitialTemplatesMessage {
                    initial_templates: Either::Left(new_tx_templates),
                    consuming_wallet: consuming_wallet.clone(),
                    response_skeleton_opt,
                })
            }
        }
    }
}

impl StartableScanner<ScanForRetryPayables, InitialTemplatesMessage> for PayableScanner {
    fn start_scan(
        &mut self,
        consuming_wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<InitialTemplatesMessage, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for retry payables");
        let failed_txs = self.get_txs_to_retry();
        let amount_from_payables = self.find_amount_from_payables(&failed_txs);
        let retry_tx_templates = RetryTxTemplates::new(&failed_txs, &amount_from_payables);

        Ok(InitialTemplatesMessage {
            initial_templates: Either::Right(retry_tx_templates),
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
    use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition;
    use crate::accountant::db_access_objects::test_utils::FailedTxBuilder;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::{
        RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::Scanners;
    use crate::accountant::test_utils::{
        make_payable_account, FailedPayableDaoMock, PayableDaoMock,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::{make_paying_wallet, make_wallet};
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
        let retrieve_payables_params_arc = Arc::new(Mutex::new(vec![]));
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
            .retrieve_txs_result(BTreeSet::from([failed_tx_1.clone(), failed_tx_2.clone()]));
        let payable_dao = PayableDaoMock::new()
            .retrieve_payables_params(&retrieve_payables_params_arc)
            .retrieve_payables_result(vec![payable_account_1.clone()]); // the second record is absent
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
        let retrieve_payables_params = retrieve_payables_params_arc.lock().unwrap();
        let expected_tx_templates = {
            let mut tx_template_1 = RetryTxTemplate::from(&failed_tx_1);
            tx_template_1.base.amount_in_wei =
                tx_template_1.base.amount_in_wei + payable_account_1.balance_wei;

            let tx_template_2 = RetryTxTemplate::from(&failed_tx_2);

            RetryTxTemplates(vec![tx_template_2, tx_template_1])
        };
        assert_eq!(
            result,
            Ok(InitialTemplatesMessage {
                initial_templates: Either::Right(expected_tx_templates),
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
            retrieve_payables_params[0],
            Some(PayableRetrieveCondition::ByAddresses(expected_addresses))
        );
        assert_eq!(retrieve_payables_params.len(), 1);
        TestLogHandler::new()
            .exists_log_containing(&format!("INFO: {test_name}: Scanning for retry payables"));
    }
}
