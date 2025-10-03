// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason};
use crate::accountant::db_access_objects::sent_payable_dao::{
    Detection, RetrieveCondition, SentPayableDao, SentTx, TxStatus,
};
use crate::accountant::db_access_objects::utils::from_unix_timestamp;
use crate::accountant::scanners::pending_payable_scanner::utils::{
    ConfirmationType, FailedValidation, FailedValidationByTable, ReceiptScanReport, TxByTable,
    TxCaseToBeInterpreted, TxHashByTable,
};
use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
use crate::blockchain::blockchain_interface::data_structures::{
    StatusReadFromReceiptCheck, TxBlock,
};
use crate::blockchain::errors::internal_errors::InternalErrorKind;
use crate::blockchain::errors::rpc_errors::AppRpcError;
use crate::blockchain::errors::BlockchainErrorKind;
use itertools::Either;
use masq_lib::logger::Logger;
use std::time::SystemTime;
use thousands::Separable;

#[derive(Default)]
pub struct TxReceiptInterpreter {}

impl TxReceiptInterpreter {
    pub fn compose_receipt_scan_report(
        &self,
        tx_cases: Vec<TxCaseToBeInterpreted>,
        pending_payable_scanner: &PendingPayableScanner,
        logger: &Logger,
    ) -> ReceiptScanReport {
        let scan_report = ReceiptScanReport::default();
        tx_cases
            .into_iter()
            .fold(scan_report, |scan_report_so_far, tx_case| {
                match tx_case.tx_receipt_result {
                    Ok(tx_status) => match tx_status {
                        StatusReadFromReceiptCheck::Succeeded(tx_block) => {
                            Self::handle_tx_confirmation(
                                scan_report_so_far,
                                tx_case.tx_by_table,
                                tx_block,
                                logger,
                            )
                        }
                        StatusReadFromReceiptCheck::Reverted => Self::handle_reverted_tx(
                            scan_report_so_far,
                            tx_case.tx_by_table,
                            logger,
                        ),
                        StatusReadFromReceiptCheck::Pending => Self::handle_still_pending_tx(
                            scan_report_so_far,
                            tx_case.tx_by_table,
                            &*pending_payable_scanner.sent_payable_dao,
                            logger,
                        ),
                    },
                    Err(e) => {
                        Self::handle_rpc_failure(scan_report_so_far, tx_case.tx_by_table, e, logger)
                    }
                }
            })
    }

    fn handle_still_pending_tx(
        mut scan_report: ReceiptScanReport,
        tx: TxByTable,
        sent_payable_dao: &dyn SentPayableDao,
        logger: &Logger,
    ) -> ReceiptScanReport {
        match tx {
            TxByTable::SentPayable(sent_tx) => {
                info!(
                    logger,
                    "Tx {:?} not confirmed within {} ms. Will resubmit with higher gas price",
                    sent_tx.hash,
                    Self::elapsed_in_ms(from_unix_timestamp(sent_tx.timestamp))
                        .separate_with_commas()
                );
                let failed_tx = FailedTx::from((sent_tx, FailureReason::PendingTooLong));
                scan_report.register_new_failure(failed_tx);
            }
            TxByTable::FailedPayable(failed_tx) => {
                if failed_tx.reason != FailureReason::PendingTooLong {
                    unreachable!(
                        "Transaction is both pending and failed (failure reason: '{:?}'). Should be \
                        possible only with the reason 'PendingTooLong'",
                        failed_tx.reason
                    )
                }
                let replacement_tx = sent_payable_dao
                    .retrieve_txs(Some(RetrieveCondition::ByNonce(vec![failed_tx.nonce])));
                let replacement_tx_hash = replacement_tx
                    .iter()
                    .next()
                    .unwrap_or_else(|| {
                        panic!(
                            "Attempted to display a replacement tx for {:?} but couldn't find \
                        one in the database",
                            failed_tx.hash
                        )
                    })
                    .hash;
                warning!(
                    logger,
                    "Previously failed tx {:?} found still pending unexpectedly; should have been \
                    replaced by {:?}",
                    failed_tx.hash,
                    replacement_tx_hash
                );
                scan_report.register_rpc_failure(FailedValidationByTable::FailedPayable(
                    FailedValidation::new(
                        failed_tx.hash,
                        BlockchainErrorKind::Internal(InternalErrorKind::PendingTooLongNotReplaced),
                        failed_tx.status,
                    ),
                ))
            }
        }
        scan_report
    }

    fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
        timestamp
            .elapsed()
            .expect("time calculation for elapsed failed")
            .as_millis()
    }

    fn handle_tx_confirmation(
        mut scan_report: ReceiptScanReport,
        tx: TxByTable,
        tx_block: TxBlock,
        logger: &Logger,
    ) -> ReceiptScanReport {
        match tx {
            TxByTable::SentPayable(sent_tx) => {
                info!(logger, "Tx {:?} confirmed", sent_tx.hash,);

                let completed_sent_tx = SentTx {
                    status: TxStatus::Confirmed {
                        block_hash: format!("{:?}", tx_block.block_hash),
                        block_number: tx_block.block_number.as_u64(),
                        detection: Detection::Normal,
                    },
                    ..sent_tx
                };
                scan_report.register_confirmed_tx(completed_sent_tx, ConfirmationType::Normal);
            }
            TxByTable::FailedPayable(failed_tx) => {
                info!(
                    logger,
                    "Previously failed tx {:?} confirmed; will be reclaimed", failed_tx.hash
                );

                let sent_tx = SentTx::from((failed_tx, tx_block));
                scan_report.register_confirmed_tx(sent_tx, ConfirmationType::Reclaim);
            }
        }
        scan_report
    }

    //TODO: failures handling might need enhancement suggested by GH-693
    fn handle_reverted_tx(
        mut scan_report: ReceiptScanReport,
        tx: TxByTable,
        logger: &Logger,
    ) -> ReceiptScanReport {
        match tx {
            TxByTable::SentPayable(sent_tx) => {
                let failure_reason = FailureReason::Reverted;
                let failed_tx = FailedTx::from((sent_tx, failure_reason));

                warning!(logger, "Tx {:?} reverted", failed_tx.hash,);

                scan_report.register_new_failure(failed_tx);
            }
            TxByTable::FailedPayable(failed_tx) => {
                debug!(
                    logger,
                    "Reverted tx {:?} on a recheck after {}. Status will be changed to \"Concluded\"",
                    failed_tx.hash,
                    failed_tx.reason,
                );

                scan_report.register_finalization_of_unproven_failure(failed_tx.hash);
            }
        }
        scan_report
    }

    fn handle_rpc_failure(
        mut scan_report: ReceiptScanReport,
        tx_by_table: TxByTable,
        rpc_error: AppRpcError,
        logger: &Logger,
    ) -> ReceiptScanReport {
        warning!(
            logger,
            "Failed to retrieve tx receipt for {:?}: {:?}. Will retry receipt retrieval next cycle",
            TxHashByTable::from(&tx_by_table),
            rpc_error
        );
        let hash = tx_by_table.hash();
        let validation_status_update = match tx_by_table {
            TxByTable::SentPayable(sent_tx) => {
                FailedValidationByTable::new(hash, rpc_error, Either::Left(sent_tx.status))
            }
            TxByTable::FailedPayable(failed_tx) => {
                FailedValidationByTable::new(hash, rpc_error, Either::Right(failed_tx.status))
            }
        };
        scan_report.register_rpc_failure(validation_status_update);
        scan_report
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{
        Detection, RetrieveCondition, SentTx, TxStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{make_failed_tx, make_sent_tx};
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::pending_payable_scanner::tx_receipt_interpreter::TxReceiptInterpreter;
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        DetectedConfirmations, DetectedFailures, FailedValidation, FailedValidationByTable,
        PresortedTxFailure, ReceiptScanReport, TxByTable,
    };
    use crate::accountant::test_utils::{make_transaction_block, SentPayableDaoMock};
    use crate::blockchain::errors::internal_errors::InternalErrorKind;
    use crate::blockchain::errors::rpc_errors::{
        AppRpcError, AppRpcErrorKind, LocalError, LocalErrorKind, RemoteError,
    };
    use crate::blockchain::errors::validation_status::{PreviousAttempts, ValidationStatus};
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::unshared_test_utils::capture_digits_with_separators_from_str;
    use masq_lib::logger::Logger;
    use masq_lib::simple_clock::SimpleClockReal;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    #[test]
    fn interprets_receipt_for_pending_tx_if_it_is_a_success() {
        init_test_logging();
        let test_name = "interprets_tx_receipt_if_it_is_a_success";
        let hash = make_tx_hash(0xcdef);
        let mut sent_tx = make_sent_tx(2244);
        sent_tx.hash = hash;
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);
        let tx_block = make_transaction_block(1234);
        let logger = Logger::new(test_name);
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_tx_confirmation(
            scan_report,
            TxByTable::SentPayable(sent_tx.clone()),
            tx_block,
            &logger,
        );

        let mut updated_tx = sent_tx;
        updated_tx.status = TxStatus::Confirmed {
            block_hash: "0x000000000000000000000000000000000000000000000000000000003b9aced2"
                .to_string(),
            block_number: 1879080904,
            detection: Detection::Normal,
        };
        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures::default(),
                confirmations: DetectedConfirmations {
                    normal_confirmations: vec![updated_tx],
                    reclaims: vec![]
                }
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Tx 0x000000000000000000000000000000000000000000000000000000000000\
            cdef confirmed",
        ));
    }

    #[test]
    fn interprets_receipt_for_failed_tx_being_rechecked_when_it_is_a_success() {
        init_test_logging();
        let test_name = "interprets_receipt_for_failed_tx_being_rechecked_when_it_is_a_success";
        let hash = make_tx_hash(0xcdef);
        let mut failed_tx = make_failed_tx(2244);
        failed_tx.hash = hash;
        failed_tx.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        failed_tx.reason = FailureReason::PendingTooLong;
        let tx_block = make_transaction_block(1234);
        let logger = Logger::new(test_name);
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_tx_confirmation(
            scan_report,
            TxByTable::FailedPayable(failed_tx.clone()),
            tx_block,
            &logger,
        );

        let sent_tx = SentTx::from((failed_tx, tx_block));
        assert!(
            matches!(
                sent_tx.status,
                TxStatus::Confirmed {
                    detection: Detection::Reclaim,
                    ..
                }
            ),
            "We expected reclaimed tx, but it says: {:?}",
            sent_tx
        );
        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures::default(),
                confirmations: DetectedConfirmations {
                    normal_confirmations: vec![],
                    reclaims: vec![sent_tx]
                }
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Previously failed tx 0x00000000000000000000000000000000000000000000\
            0000000000000000cdef confirmed; will be reclaimed",
        ));
    }

    #[test]
    fn interprets_tx_receipt_for_pending_tx_when_tx_status_says_reverted() {
        init_test_logging();
        let test_name = "interprets_tx_receipt_for_pending_tx_when_tx_status_says_reverted";
        let hash = make_tx_hash(0xabc);
        let mut sent_tx = make_sent_tx(2244);
        sent_tx.hash = hash;
        let logger = Logger::new(test_name);
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_reverted_tx(
            scan_report,
            TxByTable::SentPayable(sent_tx.clone()),
            &logger,
        );

        let failed_tx = FailedTx::from((sent_tx, FailureReason::Reverted));
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
            "WARN: {test_name}: Tx 0x0000000000000000000000000000000000000000000000000000000\
            000000abc reverted",
        ));
    }

    #[test]
    fn interprets_tx_receipt_for_failed_tx_when_newly_fetched_tx_status_says_reverted() {
        init_test_logging();
        let test_name = "interprets_tx_receipt_for_failed_tx_when_tx_status_reveals_failure";
        let tx_hash = make_tx_hash(0xabc);
        let mut failed_tx = make_failed_tx(2244);
        failed_tx.hash = tx_hash;
        failed_tx.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        failed_tx.reason = FailureReason::PendingTooLong;
        let logger = Logger::new(test_name);
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_reverted_tx(
            scan_report,
            TxByTable::FailedPayable(failed_tx.clone()),
            &logger,
        );

        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![PresortedTxFailure::RecheckCompleted(tx_hash)],
                    tx_receipt_rpc_failures: vec![]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Reverted tx 0x000000000000000000000000000000000000000000000000000000\
            0000000abc on a recheck after \"PendingTooLong\". Status will be changed to \"Concluded\"",
        ));
    }

    #[test]
    fn interprets_tx_receipt_for_pending_payable_if_the_tx_keeps_pending() {
        init_test_logging();
        let retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let test_name = "interprets_tx_receipt_for_pending_payable_if_the_tx_keeps_pending";
        let newer_sent_tx_for_older_failed_tx = make_sent_tx(2244);
        let sent_payable_dao = SentPayableDaoMock::new()
            .retrieve_txs_params(&retrieve_txs_params_arc)
            .retrieve_txs_result(BTreeSet::from([newer_sent_tx_for_older_failed_tx]));
        let hash = make_tx_hash(0x913);
        let sent_tx_timestamp = to_unix_timestamp(
            SystemTime::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
        );
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = hash;
        sent_tx.timestamp = sent_tx_timestamp;
        let scan_report = ReceiptScanReport::default();
        let before = SystemTime::now();

        let result = TxReceiptInterpreter::handle_still_pending_tx(
            scan_report,
            TxByTable::SentPayable(sent_tx.clone()),
            &sent_payable_dao,
            &Logger::new(test_name),
        );

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
        let str_elapsed_ms = capture_digits_with_separators_from_str(&log_msg, 3, ',');
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
    fn interprets_tx_receipt_for_supposedly_failed_tx_if_the_tx_keeps_pending() {
        init_test_logging();
        let retrieve_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let test_name = "interprets_tx_receipt_for_supposedly_failed_tx_if_the_tx_keeps_pending";
        let mut newer_sent_tx_for_older_failed_tx = make_sent_tx(2244);
        newer_sent_tx_for_older_failed_tx.hash = make_tx_hash(0x7c6);
        let sent_payable_dao = SentPayableDaoMock::new()
            .retrieve_txs_params(&retrieve_txs_params_arc)
            .retrieve_txs_result(BTreeSet::from([newer_sent_tx_for_older_failed_tx]));
        let tx_hash = make_tx_hash(0x913);
        let mut failed_tx = make_failed_tx(789);
        let failed_tx_nonce = failed_tx.nonce;
        failed_tx.hash = tx_hash;
        failed_tx.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        failed_tx.reason = FailureReason::PendingTooLong;
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_still_pending_tx(
            scan_report,
            TxByTable::FailedPayable(failed_tx.clone()),
            &sent_payable_dao,
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![],
                    tx_receipt_rpc_failures: vec![FailedValidationByTable::FailedPayable(
                        FailedValidation::new(
                            tx_hash,
                            BlockchainErrorKind::Internal(
                                InternalErrorKind::PendingTooLongNotReplaced
                            ),
                            FailureStatus::RecheckRequired(ValidationStatus::Waiting)
                        )
                    )]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        let retrieve_txs_params = retrieve_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_txs_params,
            vec![Some(RetrieveCondition::ByNonce(vec![failed_tx_nonce]))]
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Previously failed tx 0x00000000000000000000000000000000000000000000\
            00000000000000000913 found still pending unexpectedly; should have been replaced \
            by 0x00000000000000000000000000000000000000000000000000000000000007c6"
        ));
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Transaction is both pending \
    and failed (failure reason: 'Reverted'). Should be possible only with the reason 'PendingTooLong'"
    )]
    fn interprets_failed_tx_recheck_as_still_pending_while_the_failure_reason_wasnt_pending_too_long(
    ) {
        let mut newer_sent_tx_for_older_failed_tx = make_sent_tx(2244);
        newer_sent_tx_for_older_failed_tx.hash = make_tx_hash(0x7c6);
        let sent_payable_dao = SentPayableDaoMock::new();
        let tx_hash = make_tx_hash(0x913);
        let mut failed_tx = make_failed_tx(789);
        failed_tx.hash = tx_hash;
        failed_tx.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        failed_tx.reason = FailureReason::Reverted;
        let scan_report = ReceiptScanReport::default();

        let _ = TxReceiptInterpreter::handle_still_pending_tx(
            scan_report,
            TxByTable::FailedPayable(failed_tx),
            &sent_payable_dao,
            &Logger::new("test"),
        );
    }

    #[test]
    #[should_panic(
        expected = "Attempted to display a replacement tx for 0x000000000000000000000000000\
    00000000000000000000000000000000001c8 but couldn't find one in the database"
    )]
    fn handle_still_pending_tx_if_unexpected_behavior_due_to_already_failed_tx_and_db_retrieval_fails(
    ) {
        let scan_report = ReceiptScanReport::default();
        let still_pending_tx = make_failed_tx(456);
        let sent_payable_dao = SentPayableDaoMock::new().retrieve_txs_result(BTreeSet::new());

        let _ = TxReceiptInterpreter::handle_still_pending_tx(
            scan_report,
            TxByTable::FailedPayable(still_pending_tx),
            &sent_payable_dao,
            &Logger::new("test"),
        );
    }

    #[test]
    fn interprets_failed_retrieval_of_receipt_for_pending_payable_in_first_attempt() {
        let test_name =
            "interprets_failed_retrieval_of_receipt_for_pending_payable_in_first_attempt";

        test_failed_retrieval_of_receipt_for_pending_payable(
            test_name,
            TxStatus::Pending(ValidationStatus::Waiting),
        );
    }

    #[test]
    fn interprets_failed_retrieval_of_receipt_for_pending_payable_as_reattempt() {
        let test_name = "interprets_failed_retrieval_of_receipt_for_pending_payable_as_reattempt";

        test_failed_retrieval_of_receipt_for_pending_payable(
            test_name,
            TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                &SimpleClockReal::default(),
            ))),
        );
    }

    fn test_failed_retrieval_of_receipt_for_pending_payable(
        test_name: &str,
        current_tx_status: TxStatus,
    ) {
        init_test_logging();
        let tx_hash = make_tx_hash(913);
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = tx_hash;
        sent_tx.status = current_tx_status.clone();
        let rpc_error = AppRpcError::Remote(RemoteError::InvalidResponse("blah".to_string()));
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_rpc_failure(
            scan_report,
            TxByTable::SentPayable(sent_tx),
            rpc_error.clone(),
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![],
                    tx_receipt_rpc_failures: vec![FailedValidationByTable::SentPayable(
                        FailedValidation::new(
                            tx_hash,
                            BlockchainErrorKind::AppRpc((&rpc_error).into()),
                            current_tx_status
                        )
                    ),]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        TestLogHandler::new().exists_log_containing(
            &format!("WARN: {test_name}: Failed to retrieve tx receipt for SentPayable(0x0000000000\
            000000000000000000000000000000000000000000000000000391): Remote(InvalidResponse(\"blah\")). \
            Will retry receipt retrieval next cycle"));
    }

    #[test]
    fn interprets_failed_retrieval_of_receipt_for_failed_tx_in_first_attempt() {
        let test_name = "interprets_failed_retrieval_of_receipt_for_failed_tx_in_first_attempt";

        test_failed_retrieval_of_receipt_for_failed_tx(
            test_name,
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        );
    }

    #[test]
    fn interprets_failed_retrieval_of_receipt_for_failed_tx_as_reattempt() {
        let test_name = "interprets_failed_retrieval_of_receipt_for_failed_tx_as_reattempt";

        test_failed_retrieval_of_receipt_for_failed_tx(
            test_name,
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                &SimpleClockReal::default(),
            ))),
        );
    }

    fn test_failed_retrieval_of_receipt_for_failed_tx(
        test_name: &str,
        current_failure_status: FailureStatus,
    ) {
        init_test_logging();
        let tx_hash = make_tx_hash(914);
        let mut failed_tx = make_failed_tx(456);
        failed_tx.hash = tx_hash;
        failed_tx.status = current_failure_status.clone();
        let rpc_error = AppRpcError::Local(LocalError::Internal);
        let scan_report = ReceiptScanReport::default();

        let result = TxReceiptInterpreter::handle_rpc_failure(
            scan_report,
            TxByTable::FailedPayable(failed_tx),
            rpc_error.clone(),
            &Logger::new(test_name),
        );

        assert_eq!(
            result,
            ReceiptScanReport {
                failures: DetectedFailures {
                    tx_failures: vec![],
                    tx_receipt_rpc_failures: vec![FailedValidationByTable::FailedPayable(
                        FailedValidation::new(
                            tx_hash,
                            BlockchainErrorKind::AppRpc((&rpc_error).into()),
                            current_failure_status
                        )
                    )]
                },
                confirmations: DetectedConfirmations::default()
            }
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: Failed to retrieve tx receipt for FailedPayable(0x0000000000\
            000000000000000000000000000000000000000000000000000392): Local(Internal). \
            Will retry receipt retrieval next cycle"
        ));
    }
}
