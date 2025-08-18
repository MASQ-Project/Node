// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedTx, FailureReason, FailureStatus,
};
use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
use crate::accountant::db_access_objects::utils::TxHash;
use crate::blockchain::blockchain_interface::data_structures::{
    BlockchainTxFailure, TxReceiptError, TxReceiptResult,
};
use crate::blockchain::errors::blockchain_loggable_error::BlockchainLoggableError;
use crate::blockchain::errors::validation_status::{
    PreviousAttempts, ValidationFailureClock, ValidationStatus,
};
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::collections::HashMap;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ReceiptScanReport {
    pub failures: DetectedFailures,
    pub confirmations: DetectedConfirmations,
}

impl ReceiptScanReport {
    pub fn requires_payments_retry(&self) -> Option<Retry> {
        match (
            self.failures.requires_retry(),
            self.confirmations.is_empty(),
        ) {
            (None, true) => unreachable!("reading tx receipts gave no results"),
            (None, _) => None,
            (Some(retry), _) => Some(retry),
        }
    }

    pub(super) fn register_confirmed_tx(&mut self, confirmation: NormalTxConfirmation) {
        self.confirmations.normal_confirmations.push(confirmation);
    }

    pub(super) fn register_failure_reclaim(&mut self, reclaim: TxReclaim) {
        self.confirmations.reclaims.push(reclaim)
    }

    pub(super) fn register_new_failure(&mut self, failed_tx: FailedTx) {
        self.failures
            .tx_failures
            .push(PresortedTxFailure::NewEntry(failed_tx));
    }

    pub(super) fn register_finalization_of_unproven_failure(&mut self, tx_hash: TxHash) {
        self.failures
            .tx_failures
            .push(PresortedTxFailure::RecheckCompleted(tx_hash));
    }

    pub(super) fn register_rpc_failure(&mut self, status_update: FailedValidationByTable) {
        self.failures.tx_receipt_rpc_failures.push(status_update);
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct DetectedConfirmations {
    pub normal_confirmations: Vec<NormalTxConfirmation>,
    pub reclaims: Vec<TxReclaim>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NormalTxConfirmation {
    pub tx: SentTx,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxReclaim {
    pub reclaimed: SentTx,
}

impl DetectedConfirmations {
    pub(super) fn is_empty(&self) -> bool {
        self.normal_confirmations.is_empty() && self.reclaims.is_empty()
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct DetectedFailures {
    pub tx_failures: Vec<PresortedTxFailure>,
    pub tx_receipt_rpc_failures: Vec<FailedValidationByTable>,
}

impl DetectedFailures {
    fn requires_retry(&self) -> Option<Retry> {
        if self.tx_failures.is_empty() && self.tx_receipt_rpc_failures.is_empty() {
            None
        } else if !self.tx_failures.is_empty() {
            Some(Retry::RetryPayments)
        } else {
            Some(Retry::RetryTxStatusCheckOnly)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PresortedTxFailure {
    NewEntry(FailedTx),
    RecheckCompleted(TxHash),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum FailedValidationByTable {
    SentPayable(FailedValidation<TxStatus>),
    FailedPayable(FailedValidation<FailureStatus>),
}

impl From<(TxReceiptError, TxStatus)> for FailedValidationByTable {
    fn from((tx_receipt_error, current_status): (TxReceiptError, TxStatus)) -> Self {
        match tx_receipt_error.tx_hash {
            TxHashByTable::SentPayable(tx_hash) => Self::SentPayable(FailedValidation::new(
                tx_hash,
                Box::new(tx_receipt_error.err),
                current_status,
            )),

            TxHashByTable::FailedPayable(tx_hash) => {
                unreachable!(
                    "Mismatch in the type of tx record (failed tx) and status type (TxStatus) for {:?}", tx_hash
                )
            }
        }
    }
}

impl From<(TxReceiptError, FailureStatus)> for FailedValidationByTable {
    fn from((tx_receipt_error, current_status): (TxReceiptError, FailureStatus)) -> Self {
        match tx_receipt_error.tx_hash {
            TxHashByTable::FailedPayable(tx_hash) => Self::FailedPayable(FailedValidation::new(
                tx_hash,
                Box::new(tx_receipt_error.err),
                current_status,
            )),
            TxHashByTable::SentPayable(tx_hash) => {
                unreachable!(
                    "Mismatch in the type of tx record (sent tx) and status type (FailureStatus) for {:?}",tx_hash
                )
            }
        }
    }
}

#[derive(Debug, Eq, Clone)]
pub struct FailedValidation<RecordStatus> {
    pub tx_hash: TxHash,
    pub validation_failure: Box<dyn BlockchainLoggableError>,
    pub current_status: RecordStatus,
}

// I was forced to implement this manually
impl<RecordStatus: PartialEq> PartialEq for FailedValidation<RecordStatus> {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash == other.tx_hash
            && &self.validation_failure == &other.validation_failure
            && self.current_status == other.current_status
    }
}

impl<RecordStatus> FailedValidation<RecordStatus>
where
    RecordStatus: UpdatableValidationStatus,
{
    pub fn new(
        tx_hash: TxHash,
        validation_failure: Box<dyn BlockchainLoggableError>,
        current_status: RecordStatus,
    ) -> Self {
        Self {
            tx_hash,
            validation_failure,
            current_status,
        }
    }

    pub fn new_status(&self, clock: &dyn ValidationFailureClock) -> Option<RecordStatus> {
        self.current_status
            .update_after_failure(self.validation_failure.clone(), clock)
    }
}

pub trait UpdatableValidationStatus {
    fn update_after_failure(
        &self,
        error: Box<dyn BlockchainLoggableError>,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self>
    where
        Self: Sized;
}

impl UpdatableValidationStatus for TxStatus {
    fn update_after_failure(
        &self,
        error: Box<dyn BlockchainLoggableError>,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self> {
        match self {
            TxStatus::Pending(ValidationStatus::Waiting) => Some(TxStatus::Pending(
                ValidationStatus::Reattempting(PreviousAttempts::new(error.into(), clock)),
            )),
            TxStatus::Pending(ValidationStatus::Reattempting(previous_attempts)) => {
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    previous_attempts.clone().add_attempt(error.into(), clock),
                )))
            }
            TxStatus::Confirmed { .. } => None,
        }
    }
}

impl UpdatableValidationStatus for FailureStatus {
    fn update_after_failure(
        &self,
        error: Box<dyn BlockchainLoggableError>,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self> {
        match self {
            FailureStatus::RecheckRequired(ValidationStatus::Waiting) => {
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(error.into(), clock)),
                ))
            }
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting(previous_attempts)) => {
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(
                        previous_attempts.clone().add_attempt(error.into(), clock),
                    ),
                ))
            }
            FailureStatus::RetryRequired | FailureStatus::Concluded => None,
        }
    }
}

pub struct MismatchReport {
    pub noticed_at: TxHashByTable,
    pub remaining_hashes: Vec<TxHashByTable>,
}

pub trait PendingPayableCache<Record> {
    fn load_cache(&mut self, records: Vec<Record>);
    fn get_record_by_hash(&mut self, hashes: TxHash) -> Option<Record>;
    fn ensure_empty_cache(&mut self, logger: &Logger);
    fn dump_cache(&mut self) -> HashMap<TxHash, Record>;
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct CurrentPendingPayables {
    pub(super) sent_payables: HashMap<TxHash, SentTx>,
}

impl PendingPayableCache<SentTx> for CurrentPendingPayables {
    fn load_cache(&mut self, records: Vec<SentTx>) {
        self.sent_payables
            .extend(records.into_iter().map(|tx| (tx.hash, tx)));
    }

    fn get_record_by_hash(&mut self, hashes: TxHash) -> Option<SentTx> {
        self.sent_payables.remove(&hashes)
    }

    fn ensure_empty_cache(&mut self, logger: &Logger) {
        if !self.sent_payables.is_empty() {
            debug!(
                logger,
                "Cache misuse - some pending payables left unprocessed: {:?}. Dumping.",
                self.sent_payables
            );
        }
        self.sent_payables.clear()
    }

    fn dump_cache(&mut self) -> HashMap<TxHash, SentTx> {
        self.sent_payables.drain().collect()
    }
}

impl CurrentPendingPayables {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct RecheckRequiringFailures {
    pub(super) failures: HashMap<TxHash, FailedTx>,
}

impl PendingPayableCache<FailedTx> for RecheckRequiringFailures {
    fn load_cache(&mut self, records: Vec<FailedTx>) {
        self.failures
            .extend(records.into_iter().map(|tx| (tx.hash, tx)));
    }

    fn get_record_by_hash(&mut self, hashes: TxHash) -> Option<FailedTx> {
        self.failures.remove(&hashes)
    }

    fn ensure_empty_cache(&mut self, logger: &Logger) {
        if !self.failures.is_empty() {
            debug!(
                logger,
                "Cache misuse - some tx failures left unprocessed: {:?}. Dumping.", self.failures
            );
        }
        self.failures.clear()
    }

    fn dump_cache(&mut self) -> HashMap<TxHash, FailedTx> {
        self.failures.drain().collect()
    }
}

impl RecheckRequiringFailures {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PendingPayableScanResult {
    NoPendingPayablesLeft(Option<NodeToUiMessage>),
    PaymentRetryRequired(Retry),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Retry {
    RetryPayments,
    RetryTxStatusCheckOnly,
}

pub struct TxCaseToBeInterpreted {
    pub tx_by_table: TxByTable,
    pub tx_receipt_result: TxReceiptResult,
}

impl TxCaseToBeInterpreted {
    pub fn new(tx_by_table: TxByTable, tx_receipt_result: TxReceiptResult) -> Self {
        Self {
            tx_by_table,
            tx_receipt_result,
        }
    }
}

pub enum TxByTable {
    SentPayable(SentTx),
    FailedPayable(FailedTx),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TxHashByTable {
    SentPayable(TxHash),
    FailedPayable(TxHash),
}

impl From<BlockchainTxFailure> for FailureReason {
    fn from(failure: BlockchainTxFailure) -> Self {
        match failure {
            BlockchainTxFailure::Unrecognized => FailureReason::Reverted,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus;
    use crate::accountant::db_access_objects::sent_payable_dao::{Detection, TxStatus};
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
        FailedValidationByTable, NormalTxConfirmation, PendingPayableCache, PresortedTxFailure,
        ReceiptScanReport, RecheckRequiringFailures, Retry, TxHashByTable, TxReceiptError,
        TxReclaim,
    };
    use crate::accountant::test_utils::{make_failed_tx, make_sent_tx};
    use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
    use crate::blockchain::errors::blockchain_loggable_error::app_rpc_web3_error::{
        AppRpcWeb3Error, LocalError, RemoteError,
    };
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal, ValidationStatus,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::any::Any;
    use std::ops::Sub;
    use std::time::{Duration, SystemTime};
    use std::vec;

    #[test]
    fn detected_confirmations_is_empty_works() {
        let subject = DetectedConfirmations {
            normal_confirmations: vec![],
            reclaims: vec![],
        };

        assert_eq!(subject.is_empty(), true);
    }

    #[test]
    fn requires_payments_retry() {
        // Maximalist approach: exhaustive set of tested variants:
        let tx_failures_feedings = vec![
            vec![PresortedTxFailure::NewEntry(make_failed_tx(456))],
            vec![PresortedTxFailure::RecheckCompleted(make_tx_hash(123))],
            vec![
                PresortedTxFailure::NewEntry(make_failed_tx(123)),
                PresortedTxFailure::NewEntry(make_failed_tx(456)),
            ],
            vec![
                PresortedTxFailure::RecheckCompleted(make_tx_hash(654)),
                PresortedTxFailure::RecheckCompleted(make_tx_hash(321)),
            ],
            vec![
                PresortedTxFailure::NewEntry(make_failed_tx(456)),
                PresortedTxFailure::RecheckCompleted(make_tx_hash(654)),
            ],
        ];
        let tx_receipt_rpc_failures_feeding = vec![
            vec![],
            vec![FailedValidationByTable::SentPayable(FailedValidation::new(
                make_tx_hash(2222),
                Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                TxStatus::Pending(ValidationStatus::Waiting),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(12121),
                    Box::new(AppRpcWeb3Error::Remote(RemoteError::InvalidResponse(
                        "blah".to_string(),
                    ))),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            Box::new(AppRpcWeb3ErrorKind::Internal),
                            &ValidationFailureClockReal::default(),
                        ),
                    )),
                ),
            )],
        ];
        let detected_confirmations_feeding = vec![
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(456),
                }],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(777),
                }],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
        ];

        tx_failures_feedings.iter().for_each(|tx_failures| {
            tx_receipt_rpc_failures_feeding
                .iter()
                .for_each(|rpc_failures| {
                    detected_confirmations_feeding
                        .iter()
                        .for_each(|detected_confirmations| {
                            let case = ReceiptScanReport {
                                failures: DetectedFailures {
                                    tx_failures: tx_failures.clone(),
                                    tx_receipt_rpc_failures: rpc_failures.clone(),
                                },
                                confirmations: detected_confirmations.clone(),
                            };

                            let result = case.requires_payments_retry();

                            assert_eq!(
                                result,
                                Some(Retry::RetryPayments),
                                "We expected Some(Retry::RetryPayments) but got {:?} for case {:?}",
                                result,
                                case
                            );
                        })
                })
        });
    }

    #[test]
    fn requires_only_receipt_retrieval_retry() {
        let rpc_failure_feedings = vec![
            vec![FailedValidationByTable::SentPayable(FailedValidation::new(
                make_tx_hash(2222),
                Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                TxStatus::Pending(ValidationStatus::Waiting),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(1234),
                    Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                ),
            )],
            vec![
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    make_tx_hash(2222),
                    Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                    TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                        Box::new(AppRpcWeb3ErrorKind::Internal),
                        &ValidationFailureClockReal::default(),
                    ))),
                )),
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    make_tx_hash(1234),
                    Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            Box::new(AppRpcWeb3ErrorKind::Internal),
                            &ValidationFailureClockReal::default(),
                        ),
                    )),
                )),
            ],
        ];
        let detected_confirmations_feeding = vec![
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(777),
                }],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(777),
                }],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
        ];

        rpc_failure_feedings.into_iter().for_each(|rpc_failures|{
            detected_confirmations_feeding.iter().for_each(|detected_confirmations|{
                let case = ReceiptScanReport {
                    failures: DetectedFailures {
                        tx_failures: vec![], // This is the determinant
                        tx_receipt_rpc_failures: rpc_failures.clone(),
                    },
                    confirmations: detected_confirmations.clone(),
                };

                let result = case.requires_payments_retry();

                assert_eq!(result, Some(Retry::RetryTxStatusCheckOnly), "We expected Some(Retry::RetryTxStatusCheckOnly) but got {:?} for case {:?}", result, case);
            })
        });
    }

    #[test]
    fn requires_payments_retry_says_no() {
        let detected_confirmations_feeding = vec![
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(777),
                }],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation {
                    tx: make_sent_tx(777),
                }],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![TxReclaim {
                    reclaimed: make_sent_tx(999),
                }],
            },
        ];

        detected_confirmations_feeding
            .into_iter()
            .for_each(|detected_confirmations| {
                let case = ReceiptScanReport {
                    failures: DetectedFailures {
                        tx_failures: vec![],
                        tx_receipt_rpc_failures: vec![],
                    },
                    confirmations: detected_confirmations.clone(),
                };

                let result = case.requires_payments_retry();

                assert_eq!(
                    result, None,
                    "We expected None but got {:?} for case {:?}",
                    result, case
                );
            });
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: reading tx receipts gave \
    no results"
    )]
    fn requires_payments_retry_with_no_results_in_whole_summary() {
        let report = ReceiptScanReport {
            failures: DetectedFailures {
                tx_failures: vec![],
                tx_receipt_rpc_failures: vec![],
            },
            confirmations: DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![],
            },
        };

        let _ = report.requires_payments_retry();
    }

    #[test]
    fn pending_payable_cache_insert_and_get_methods_single_record() {
        let mut subject = CurrentPendingPayables::new();
        let sent_tx = make_sent_tx(123);
        let tx_hash = sent_tx.hash;
        let records = vec![sent_tx.clone()];
        let state_before = subject.sent_payables.clone();
        subject.load_cache(records);

        let first_attempt = subject.get_record_by_hash(tx_hash);
        let second_attempt = subject.get_record_by_hash(tx_hash);

        assert_eq!(state_before, hashmap!());
        assert_eq!(first_attempt, Some(sent_tx));
        assert_eq!(second_attempt, None);
        assert!(
            subject.sent_payables.is_empty(),
            "Should be empty but was {:?}",
            subject.sent_payables
        );
    }

    #[test]
    fn pending_payable_cache_insert_and_get_methods_multiple_records() {
        let mut subject = CurrentPendingPayables::new();
        let sent_tx_1 = make_sent_tx(123);
        let tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(456);
        let tx_hash_2 = sent_tx_2.hash;
        let sent_tx_3 = make_sent_tx(789);
        let tx_hash_3 = sent_tx_3.hash;
        let sent_tx_4 = make_sent_tx(101);
        let tx_hash_4 = sent_tx_4.hash;
        let nonexistent_tx_hash = make_tx_hash(234);
        let records = vec![
            sent_tx_1.clone(),
            sent_tx_2.clone(),
            sent_tx_3.clone(),
            sent_tx_4.clone(),
        ];

        let first_query = subject.get_record_by_hash(tx_hash_1);
        subject.load_cache(records);
        let second_query = subject.get_record_by_hash(nonexistent_tx_hash);
        let third_query = subject.get_record_by_hash(tx_hash_2);
        let fourth_query = subject.get_record_by_hash(tx_hash_1);
        let fifth_query = subject.get_record_by_hash(tx_hash_4);
        let sixth_query = subject.get_record_by_hash(tx_hash_1);
        let seventh_query = subject.get_record_by_hash(tx_hash_1);
        let eighth_query = subject.get_record_by_hash(tx_hash_3);

        assert_eq!(first_query, None);
        assert_eq!(second_query, None);
        assert_eq!(third_query, Some(sent_tx_2));
        assert_eq!(fourth_query, Some(sent_tx_1));
        assert_eq!(fifth_query, Some(sent_tx_4));
        assert_eq!(sixth_query, None);
        assert_eq!(seventh_query, None);
        assert_eq!(eighth_query, Some(sent_tx_3));
        assert!(
            subject.sent_payables.is_empty(),
            "Expected empty cache, but got {:?}",
            subject.sent_payables
        );
    }

    #[test]
    fn pending_payable_cache_ensure_empty_happy_path() {
        init_test_logging();
        let test_name = "pending_payable_cache_ensure_empty_happy_path";
        let mut subject = CurrentPendingPayables::new();
        let sent_tx = make_sent_tx(567);
        let tx_hash = sent_tx.hash;
        let records = vec![sent_tx.clone()];
        let logger = Logger::new(test_name);
        subject.load_cache(records);
        let _ = subject.get_record_by_hash(tx_hash);

        subject.ensure_empty_cache(&logger);

        assert!(
            subject.sent_payables.is_empty(),
            "Should be empty by now but was {:?}",
            subject.sent_payables
        );
        TestLogHandler::default().exists_no_log_containing(&format!(
            "DEBUG: {test_name}: \
        Cache misuse - some pending payables left unprocessed:"
        ));
    }

    #[test]
    fn pending_payable_cache_ensure_empty_sad_path() {
        init_test_logging();
        let test_name = "pending_payable_cache_ensure_empty_sad_path";
        let mut subject = CurrentPendingPayables::new();
        let sent_tx = make_sent_tx(567);
        let tx_timestamp = sent_tx.timestamp;
        let records = vec![sent_tx.clone()];
        let logger = Logger::new(test_name);
        subject.load_cache(records);

        subject.ensure_empty_cache(&logger);

        assert!(
            subject.sent_payables.is_empty(),
            "Should be empty by now but was {:?}",
            subject.sent_payables
        );
        TestLogHandler::default().exists_log_containing(&format!(
            "DEBUG: {test_name}: \
        Cache misuse - some pending payables left unprocessed: \
        {{0x0000000000000000000000000000000000000000000000000000000000000237: SentTx {{ hash: \
        0x0000000000000000000000000000000000000000000000000000000000000237, receiver_address: \
        0x000000000000000000000077616c6c6574353637, amount_minor: 321489000000000, timestamp: \
        {tx_timestamp}, gas_price_minor: 567000000000, nonce: 567, status: Pending(Waiting) }}}}. \
        Dumping."
        ));
    }

    #[test]
    fn pending_payable_cache_dump_works() {
        let mut subject = CurrentPendingPayables::new();
        let sent_tx_1 = make_sent_tx(567);
        let tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(456);
        let tx_hash_2 = sent_tx_2.hash;
        let sent_tx_3 = make_sent_tx(789);
        let tx_hash_3 = sent_tx_3.hash;
        let records = vec![sent_tx_1.clone(), sent_tx_2.clone(), sent_tx_3.clone()];
        subject.load_cache(records);

        let result = subject.dump_cache();

        assert_eq!(
            result,
            hashmap! (
                tx_hash_1 => sent_tx_1,
                tx_hash_2 => sent_tx_2,
                tx_hash_3 => sent_tx_3
            )
        );
    }

    #[test]
    fn failure_cache_insert_and_get_methods_single_record() {
        let mut subject = RecheckRequiringFailures::new();
        let failed_tx = make_failed_tx(567);
        let tx_hash = failed_tx.hash;
        let records = vec![failed_tx.clone()];
        let state_before = subject.failures.clone();
        subject.load_cache(records);

        let first_attempt = subject.get_record_by_hash(tx_hash);
        let second_attempt = subject.get_record_by_hash(tx_hash);

        assert_eq!(state_before, hashmap!());
        assert_eq!(first_attempt, Some(failed_tx));
        assert_eq!(second_attempt, None);
        assert!(
            subject.failures.is_empty(),
            "Should be empty but was {:?}",
            subject.failures
        );
    }

    #[test]
    fn failure_cache_insert_and_get_methods_multiple_records() {
        let mut subject = RecheckRequiringFailures::new();
        let failed_tx_1 = make_failed_tx(123);
        let tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(456);
        let tx_hash_2 = failed_tx_2.hash;
        let failed_tx_3 = make_failed_tx(789);
        let tx_hash_3 = failed_tx_3.hash;
        let failed_tx_4 = make_failed_tx(101);
        let tx_hash_4 = failed_tx_4.hash;
        let nonexistent_tx_hash = make_tx_hash(234);
        let records = vec![
            failed_tx_1.clone(),
            failed_tx_2.clone(),
            failed_tx_3.clone(),
            failed_tx_4.clone(),
        ];

        let first_query = subject.get_record_by_hash(tx_hash_1);
        subject.load_cache(records);
        let second_query = subject.get_record_by_hash(nonexistent_tx_hash);
        let third_query = subject.get_record_by_hash(tx_hash_2);
        let fourth_query = subject.get_record_by_hash(tx_hash_1);
        let fifth_query = subject.get_record_by_hash(tx_hash_4);
        let sixth_query = subject.get_record_by_hash(tx_hash_1);
        let seventh_query = subject.get_record_by_hash(tx_hash_1);
        let eighth_query = subject.get_record_by_hash(tx_hash_3);

        assert_eq!(first_query, None);
        assert_eq!(second_query, None);
        assert_eq!(third_query, Some(failed_tx_2));
        assert_eq!(fourth_query, Some(failed_tx_1));
        assert_eq!(fifth_query, Some(failed_tx_4));
        assert_eq!(sixth_query, None);
        assert_eq!(seventh_query, None);
        assert_eq!(eighth_query, Some(failed_tx_3));
        assert!(
            subject.failures.is_empty(),
            "Expected empty cache, but got {:?}",
            subject.failures
        );
    }

    #[test]
    fn failure_cache_ensure_empty_happy_path() {
        init_test_logging();
        let test_name = "failure_cache_ensure_empty_happy_path";
        let mut subject = RecheckRequiringFailures::new();
        let failed_tx = make_failed_tx(567);
        let tx_hash = failed_tx.hash;
        let records = vec![failed_tx.clone()];
        let logger = Logger::new(test_name);
        subject.load_cache(records);
        let _ = subject.get_record_by_hash(tx_hash);

        subject.ensure_empty_cache(&logger);

        assert!(
            subject.failures.is_empty(),
            "Should be empty by now but was {:?}",
            subject.failures
        );
        TestLogHandler::default().exists_no_log_containing(&format!(
            "DEBUG: {test_name}: \
        Cache misuse - some tx failures left unprocessed:"
        ));
    }

    #[test]
    fn failure_cache_ensure_empty_sad_path() {
        init_test_logging();
        let test_name = "failure_cache_ensure_empty_sad_path";
        let mut subject = RecheckRequiringFailures::new();
        let failed_tx = make_failed_tx(567);
        let tx_timestamp = failed_tx.timestamp;
        let records = vec![failed_tx.clone()];
        let logger = Logger::new(test_name);
        subject.load_cache(records);

        subject.ensure_empty_cache(&logger);

        assert!(
            subject.failures.is_empty(),
            "Should be empty by now but was {:?}",
            subject.failures
        );
        TestLogHandler::default().exists_log_containing(&format!(
            "DEBUG: {test_name}: \
        Cache misuse - some tx failures left unprocessed: \
        {{0x0000000000000000000000000000000000000000000000000000000000000237: FailedTx {{ hash: \
        0x0000000000000000000000000000000000000000000000000000000000000237, receiver_address: \
        0x000000000000000000000077616c6c6574353637, amount_minor: 321489000000000, timestamp: \
        {tx_timestamp}, gas_price_minor: 567000000000, nonce: 567, reason: PendingTooLong, status: \
        RetryRequired }}}}. Dumping."
        ));
    }

    #[test]
    fn failure_cache_dump_works() {
        let mut subject = RecheckRequiringFailures::new();
        let failed_tx_1 = make_failed_tx(567);
        let tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(456);
        let tx_hash_2 = failed_tx_2.hash;
        let failed_tx_3 = make_failed_tx(789);
        let tx_hash_3 = failed_tx_3.hash;
        let records = vec![
            failed_tx_1.clone(),
            failed_tx_2.clone(),
            failed_tx_3.clone(),
        ];
        subject.load_cache(records);

        let result = subject.dump_cache();

        assert_eq!(
            result,
            hashmap! (
                tx_hash_1 => failed_tx_1,
                tx_hash_2 => failed_tx_2,
                tx_hash_3 => failed_tx_3
            )
        );
    }

    #[test]
    fn tx_receipt_error_can_be_converted_to_failed_validation_by_table() {
        let tx_hash_sent_tx = make_tx_hash(123);
        let api_error_sent_tx = AppRpcWeb3Error::Local(LocalError::Internal);
        let receipt_error_for_sent_tx = TxReceiptError::new(
            TxHashByTable::SentPayable(tx_hash_sent_tx),
            api_error_sent_tx.clone(),
        );
        let tx_hash_failed_tx = make_tx_hash(456);
        let api_error_failed_tx = AppRpcWeb3Error::Remote(RemoteError::Unreachable);
        let receipt_error_for_failed_tx = TxReceiptError::new(
            TxHashByTable::FailedPayable(tx_hash_failed_tx),
            api_error_failed_tx.clone(),
        );

        let result_1 = FailedValidationByTable::from((
            receipt_error_for_sent_tx,
            TxStatus::Pending(ValidationStatus::Waiting),
        ));
        let result_2 = FailedValidationByTable::from((
            receipt_error_for_failed_tx,
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        ));

        assert_eq!(
            result_1,
            FailedValidationByTable::SentPayable(FailedValidation::new(
                tx_hash_sent_tx,
                Box::new(api_error_sent_tx),
                TxStatus::Pending(ValidationStatus::Waiting)
            ))
        );
        assert_eq!(
            result_2,
            FailedValidationByTable::FailedPayable(FailedValidation::new(
                tx_hash_failed_tx,
                Box::new(api_error_failed_tx),
                FailureStatus::RecheckRequired(ValidationStatus::Waiting)
            ))
        );
    }

    #[test]
    #[should_panic(
        expected = "Mismatch in the type of tx record (failed tx) and status type (TxStatus) for \
        0x000000000000000000000000000000000000000000000000000000000000007b"
    )]
    fn tx_status_mismatch_in_conversion_to_failed_validation_by_table() {
        let tx_hash = make_tx_hash(123);
        let api_error = AppRpcWeb3Error::Local(LocalError::Internal);
        let mismatched_receipt_error =
            TxReceiptError::new(TxHashByTable::FailedPayable(tx_hash), api_error);

        let _ = FailedValidationByTable::from((
            mismatched_receipt_error,
            TxStatus::Pending(ValidationStatus::Waiting),
        ));
    }

    #[test]
    #[should_panic(
        expected = "Mismatch in the type of tx record (sent tx) and status type (FailureStatus) for \
        0x000000000000000000000000000000000000000000000000000000000000007b"
    )]
    fn tx_status_mismatch_in_conversion_to_failed_validation_by_table_2() {
        let tx_hash = make_tx_hash(123);
        let api_error = AppRpcWeb3Error::Local(LocalError::Internal);
        let mismatched_receipt_error =
            TxReceiptError::new(TxHashByTable::SentPayable(tx_hash), api_error);

        let _ = FailedValidationByTable::from((
            mismatched_receipt_error,
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        ));
    }

    #[test]
    fn failed_validation_new_status_works_for_tx_statuses() {
        let timestamp_a = SystemTime::now();
        let timestamp_b = SystemTime::now().sub(Duration::from_secs(11));
        let timestamp_c = SystemTime::now().sub(Duration::from_secs(22));
        let validation_failure_clock = ValidationFailureClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_c);
        let mal_validated_tx_statuses = vec![
            (
                FailedValidation::new(
                    make_tx_hash(123),
                    Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                    TxStatus::Pending(ValidationStatus::Waiting),
                ),
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    PreviousAttempts::new(
                        Box::new(AppRpcWeb3ErrorKind::Internal),
                        &ValidationFailureClockMock::default().now_result(timestamp_a),
                    ),
                ))),
            ),
            (
                FailedValidation::new(
                    make_tx_hash(123),
                    Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
                    TxStatus::Pending(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            Box::new(AppRpcWeb3ErrorKind::Internal),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            Box::new(AppRpcWeb3ErrorKind::Internal),
                            &ValidationFailureClockReal::default(),
                        ),
                    )),
                ),
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    PreviousAttempts::new(
                        Box::new(AppRpcWeb3ErrorKind::ServerUnreachable),
                        &ValidationFailureClockMock::default().now_result(timestamp_c),
                    )
                    .add_attempt(
                        Box::new(AppRpcWeb3ErrorKind::Internal),
                        &ValidationFailureClockMock::default().now_result(timestamp_b),
                    )
                    .add_attempt(
                        Box::new(AppRpcWeb3ErrorKind::Internal),
                        &ValidationFailureClockReal::default(),
                    ),
                ))),
            ),
        ];

        mal_validated_tx_statuses.into_iter().for_each(
            |(failed_validation, expected_tx_status)| {
                assert_eq!(
                    failed_validation.new_status(&validation_failure_clock),
                    expected_tx_status
                );
            },
        );
    }

    #[test]
    fn failed_validation_new_status_works_for_failure_statuses() {
        let timestamp_a = SystemTime::now().sub(Duration::from_secs(222));
        let timestamp_b = SystemTime::now().sub(Duration::from_secs(3333));
        let timestamp_c = SystemTime::now().sub(Duration::from_secs(44444));
        let validation_failure_clock = ValidationFailureClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_b);
        let mal_validated_failure_statuses = vec![
            (
                FailedValidation::new(
                    make_tx_hash(456),
                    Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                ),
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(
                        Box::new(AppRpcWeb3ErrorKind::Internal),
                        &ValidationFailureClockMock::default().now_result(timestamp_a),
                    )),
                )),
            ),
            (
                FailedValidation::new(
                    make_tx_hash(456),
                    Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            Box::new(AppRpcWeb3ErrorKind::ServerUnreachable),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            Box::new(AppRpcWeb3ErrorKind::InvalidResponse),
                            &ValidationFailureClockMock::default().now_result(timestamp_c),
                        ),
                    )),
                ),
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            Box::new(AppRpcWeb3ErrorKind::ServerUnreachable),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            Box::new(AppRpcWeb3ErrorKind::InvalidResponse),
                            &ValidationFailureClockMock::default().now_result(timestamp_c),
                        )
                        .add_attempt(
                            Box::new(AppRpcWeb3ErrorKind::ServerUnreachable),
                            &ValidationFailureClockReal::default(),
                        ),
                    ),
                )),
            ),
        ];

        mal_validated_failure_statuses.into_iter().for_each(
            |(failed_validation, expected_failed_tx_status)| {
                assert_eq!(
                    failed_validation.new_status(&validation_failure_clock),
                    expected_failed_tx_status
                );
            },
        )
    }

    #[test]
    fn failed_validation_new_status_has_no_effect_on_unexpected_tx_status() {
        let validation_failure_clock = ValidationFailureClockMock::default();
        let mal_validated_tx_status = FailedValidation::new(
            make_tx_hash(123),
            Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
            TxStatus::Confirmed {
                block_hash: "".to_string(),
                block_number: 0,
                detection: Detection::Normal,
            },
        );

        assert_eq!(
            mal_validated_tx_status.new_status(&validation_failure_clock),
            None
        );
    }

    #[test]
    fn failed_validation_new_status_has_no_effect_on_unexpected_failure_status() {
        let validation_failure_clock = ValidationFailureClockMock::default();
        let mal_validated_failure_statuses = vec![
            FailedValidation::new(
                make_tx_hash(456),
                Box::new(AppRpcWeb3Error::Local(LocalError::Internal)),
                FailureStatus::RetryRequired,
            ),
            FailedValidation::new(
                make_tx_hash(789),
                Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
                FailureStatus::Concluded,
            ),
        ];

        mal_validated_failure_statuses
            .into_iter()
            .enumerate()
            .for_each(|(idx, failed_validation)| {
                let result = failed_validation.new_status(&validation_failure_clock);
                assert_eq!(
                    result, None,
                    "Failed validation should evaluate to 'None' but was '{:?}' for idx: {}",
                    result, idx
                )
            });
    }

    // #[derive(Debug, Eq, Clone)]
    // pub struct FailedValidation<RecordStatus> {
    //     pub tx_hash: TxHash,
    //     pub validation_failure: Box<dyn BlockchainLoggableError>,
    //     pub current_status: RecordStatus,
    // }
    //
    // // I was forced to implement this manually
    // impl <RecordStatus> PartialEq for crate::accountant::scanners::pending_payable_scanner::utils::FailedValidation<RecordStatus> {
    //     fn eq(&self, other: &Self) -> bool {
    //         todo!()
    //     }
    // }

    #[test]
    fn partial_eq_is_implemented_for_failed_validation() {
        let correct_hash = make_tx_hash(123);
        let correct_error = Box::new(AppRpcWeb3Error::Local(LocalError::Internal));
        let correct_tx_status = TxStatus::Pending(ValidationStatus::Waiting);
        let failed_validation_1 = FailedValidation::new(
            correct_hash,
            correct_error.clone(),
            correct_tx_status.clone(),
        );
        let failed_validation_2 = FailedValidation::new(
            make_tx_hash(345),
            correct_error.clone(),
            correct_tx_status.clone(),
        );
        let failed_validation_3 = FailedValidation::new(
            correct_hash,
            Box::new(AppRpcWeb3Error::Remote(RemoteError::Unreachable)),
            correct_tx_status.clone(),
        );
        let failed_validation_4 = FailedValidation::new(
            correct_hash,
            correct_error.clone(),
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        );
        let failed_validation_5 =
            FailedValidation::new(correct_hash, correct_error.clone(), correct_tx_status);
        let failed_validation_6 = FailedValidation::new(
            correct_hash,
            correct_error,
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        );

        assert_ne!(failed_validation_1, failed_validation_2);
        assert_ne!(failed_validation_1, failed_validation_3);
        assert_ne!(failed_validation_1.type_id(), failed_validation_4.type_id());
        assert_eq!(failed_validation_1, failed_validation_5);
        assert_eq!(failed_validation_4, failed_validation_6);
    }
}
