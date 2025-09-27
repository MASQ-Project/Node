// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureStatus};
use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::{ResponseSkeleton, TxReceiptResult};
use crate::blockchain::errors::rpc_errors::AppRpcError;
use crate::blockchain::errors::validation_status::{
    PreviousAttempts, ValidationFailureClock, ValidationStatus,
};
use crate::blockchain::errors::BlockchainErrorKind;
use itertools::Either;
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
            (None, true) => unreachable!("reading tx receipts gave no results, but always should"),
            (None, _) => None,
            (Some(retry), _) => Some(retry),
        }
    }

    pub(super) fn register_confirmed_tx(
        &mut self,
        confirmed_tx: SentTx,
        confirmation_type: ConfirmationType,
    ) {
        match confirmation_type {
            ConfirmationType::Normal => self.confirmations.normal_confirmations.push(confirmed_tx),
            ConfirmationType::Reclaim => self.confirmations.reclaims.push(confirmed_tx),
        }
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
    pub normal_confirmations: Vec<SentTx>,
    pub reclaims: Vec<SentTx>,
}

impl DetectedConfirmations {
    pub(super) fn is_empty(&self) -> bool {
        self.normal_confirmations.is_empty() && self.reclaims.is_empty()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmationType {
    Normal,
    Reclaim,
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

impl FailedValidationByTable {
    pub fn new(
        tx_hash: TxHash,
        error: AppRpcError,
        status: Either<TxStatus, FailureStatus>,
    ) -> Self {
        match status {
            Either::Left(tx_status) => Self::SentPayable(FailedValidation::new(
                tx_hash,
                BlockchainErrorKind::AppRpc((&error).into()),
                tx_status,
            )),
            Either::Right(failure_reason) => Self::FailedPayable(FailedValidation::new(
                tx_hash,
                BlockchainErrorKind::AppRpc((&error).into()),
                failure_reason,
            )),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct FailedValidation<RecordStatus> {
    pub tx_hash: TxHash,
    pub validation_failure: BlockchainErrorKind,
    pub current_status: RecordStatus,
}

impl<RecordStatus> FailedValidation<RecordStatus>
where
    RecordStatus: UpdatableValidationStatus,
{
    pub fn new(
        tx_hash: TxHash,
        validation_failure: BlockchainErrorKind,
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
            .update_after_failure(self.validation_failure, clock)
    }
}

pub trait UpdatableValidationStatus {
    fn update_after_failure(
        &self,
        error: BlockchainErrorKind,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self>
    where
        Self: Sized;
}

impl UpdatableValidationStatus for TxStatus {
    fn update_after_failure(
        &self,
        error: BlockchainErrorKind,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self> {
        match self {
            TxStatus::Pending(ValidationStatus::Waiting) => Some(TxStatus::Pending(
                ValidationStatus::Reattempting(PreviousAttempts::new(error, clock)),
            )),
            TxStatus::Pending(ValidationStatus::Reattempting(previous_attempts)) => {
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    previous_attempts.clone().add_attempt(error, clock),
                )))
            }
            TxStatus::Confirmed { .. } => None,
        }
    }
}

impl UpdatableValidationStatus for FailureStatus {
    fn update_after_failure(
        &self,
        error: BlockchainErrorKind,
        clock: &dyn ValidationFailureClock,
    ) -> Option<Self> {
        match self {
            FailureStatus::RecheckRequired(ValidationStatus::Waiting) => {
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(error, clock)),
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
    pub noticed_with: TxHashByTable,
    pub remaining_hashes: Vec<TxHashByTable>,
}

pub trait PendingPayableCache<Record> {
    fn load_cache(&mut self, records: Vec<Record>);
    fn get_record_by_hash(&mut self, hash: TxHash) -> Option<Record>;
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

    fn get_record_by_hash(&mut self, hash: TxHash) -> Option<SentTx> {
        self.sent_payables.remove(&hash)
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

    fn get_record_by_hash(&mut self, hash: TxHash) -> Option<FailedTx> {
        self.failures.remove(&hash)
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
    PaymentRetryRequired(Option<ResponseSkeleton>),
    ProcedureShouldBeRepeated(Option<NodeToUiMessage>),
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

#[derive(Debug)]
pub enum TxByTable {
    SentPayable(SentTx),
    FailedPayable(FailedTx),
}

impl TxByTable {
    pub fn hash(&self) -> TxHash {
        match self {
            TxByTable::SentPayable(tx) => tx.hash,
            TxByTable::FailedPayable(tx) => tx.hash,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum TxHashByTable {
    SentPayable(TxHash),
    FailedPayable(TxHash),
}

impl TxHashByTable {
    pub fn hash(&self) -> TxHash {
        match self {
            TxHashByTable::SentPayable(hash) => *hash,
            TxHashByTable::FailedPayable(hash) => *hash,
        }
    }
}

impl From<&TxByTable> for TxHashByTable {
    fn from(tx: &TxByTable) -> Self {
        match tx {
            TxByTable::SentPayable(tx) => TxHashByTable::SentPayable(tx.hash),
            TxByTable::FailedPayable(tx) => TxHashByTable::FailedPayable(tx.hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus;
    use crate::accountant::db_access_objects::sent_payable_dao::{Detection, TxStatus};
    use crate::accountant::db_access_objects::test_utils::{make_failed_tx, make_sent_tx};
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
        FailedValidationByTable, PendingPayableCache, PresortedTxFailure, ReceiptScanReport,
        RecheckRequiringFailures, Retry, TxByTable, TxHashByTable,
    };
    use crate::blockchain::errors::rpc_errors::{AppRpcErrorKind, LocalErrorKind, RemoteErrorKind};
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal, ValidationStatus,
    };
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
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
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                TxStatus::Pending(ValidationStatus::Waiting),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(12121),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::InvalidResponse,
                    )),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                                LocalErrorKind::Internal,
                            )),
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
                normal_confirmations: vec![make_sent_tx(456)],
                reclaims: vec![make_sent_tx(999)],
            },
            DetectedConfirmations {
                normal_confirmations: vec![make_sent_tx(777)],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![make_sent_tx(999)],
            },
        ];

        for tx_failures in &tx_failures_feedings {
            for rpc_failures in &tx_receipt_rpc_failures_feeding {
                for detected_confirmations in &detected_confirmations_feeding {
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
                        "Expected Some(Retry::RetryPayments) but got {:?} for case {:?}",
                        result,
                        case
                    );
                }
            }
        }
    }

    #[test]
    fn requires_only_receipt_retrieval_retry() {
        let rpc_failure_feedings = vec![
            vec![FailedValidationByTable::SentPayable(FailedValidation::new(
                make_tx_hash(2222),
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                TxStatus::Pending(ValidationStatus::Waiting),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(1234),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                ),
            )],
            vec![
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    make_tx_hash(2222),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                            LocalErrorKind::Internal,
                        )),
                        &ValidationFailureClockReal::default(),
                    ))),
                )),
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    make_tx_hash(1234),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                                LocalErrorKind::Internal,
                            )),
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
                normal_confirmations: vec![make_sent_tx(777)],
                reclaims: vec![make_sent_tx(999)],
            },
            DetectedConfirmations {
                normal_confirmations: vec![make_sent_tx(777)],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![make_sent_tx(999)],
            },
        ];

        for rpc_failures in &rpc_failure_feedings {
            for detected_confirmations in &detected_confirmations_feeding {
                let case = ReceiptScanReport {
                    failures: DetectedFailures {
                        tx_failures: vec![], // This is the determinant
                        tx_receipt_rpc_failures: rpc_failures.clone(),
                    },
                    confirmations: detected_confirmations.clone(),
                };

                let result = case.requires_payments_retry();

                assert_eq!(
                    result,
                    Some(Retry::RetryTxStatusCheckOnly),
                    "Expected Some(Retry::RetryTxStatusCheckOnly) but got {:?} for case {:?}",
                    result,
                    case
                );
            }
        }
    }

    #[test]
    fn requires_payments_retry_says_no() {
        let detected_confirmations_feeding = vec![
            DetectedConfirmations {
                normal_confirmations: vec![make_sent_tx(777)],
                reclaims: vec![make_sent_tx(999)],
            },
            DetectedConfirmations {
                normal_confirmations: vec![make_sent_tx(777)],
                reclaims: vec![],
            },
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![make_sent_tx(999)],
            },
        ];

        for detected_confirmations in detected_confirmations_feeding {
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
        }
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: reading tx receipts gave no results, \
        but always should"
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
        let sent_tx = make_sent_tx(0x567);
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
        {{0x0000000000000000000000000000000000000000000000000000000000000567: SentTx {{ hash: \
        0x0000000000000000000000000000000000000000000000000000000000000567, receiver_address: \
        0x0000000000000000001035000000001035000000, amount_minor: 3658379210721, timestamp: \
        275427216, gas_price_minor: 2645248887, nonce: 1383, status: Pending(Waiting) }}}}. \
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
        let failed_tx = make_failed_tx(0x567);
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
        {{0x0000000000000000000000000000000000000000000000000000000000000567: FailedTx {{ hash: \
        0x0000000000000000000000000000000000000000000000000000000000000567, receiver_address: \
        0x00000000000000000003cc0000000003cc000000, amount_minor: 3658379210721, timestamp: \
        275427216, gas_price_minor: 2645248887, nonce: 1383, reason: PendingTooLong, status: \
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
    fn failed_validation_new_status_works_for_tx_statuses() {
        let timestamp_a = SystemTime::now();
        let timestamp_b = SystemTime::now().sub(Duration::from_secs(11));
        let timestamp_c = SystemTime::now().sub(Duration::from_secs(22));
        let clock = ValidationFailureClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_c);
        let cases = vec![
            (
                FailedValidation::new(
                    make_tx_hash(123),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    TxStatus::Pending(ValidationStatus::Waiting),
                ),
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    PreviousAttempts::new(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                            LocalErrorKind::Internal,
                        )),
                        &ValidationFailureClockMock::default().now_result(timestamp_a),
                    ),
                ))),
            ),
            (
                FailedValidation::new(
                    make_tx_hash(123),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    TxStatus::Pending(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                                LocalErrorKind::Internal,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                                LocalErrorKind::Internal,
                            )),
                            &ValidationFailureClockReal::default(),
                        ),
                    )),
                ),
                Some(TxStatus::Pending(ValidationStatus::Reattempting(
                    PreviousAttempts::new(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                            RemoteErrorKind::Unreachable,
                        )),
                        &ValidationFailureClockMock::default().now_result(timestamp_c),
                    )
                    .add_attempt(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                            LocalErrorKind::Internal,
                        )),
                        &ValidationFailureClockMock::default().now_result(timestamp_b),
                    )
                    .add_attempt(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                            LocalErrorKind::Internal,
                        )),
                        &ValidationFailureClockReal::default(),
                    ),
                ))),
            ),
        ];

        cases.into_iter().for_each(|(input, expected)| {
            assert_eq!(input.new_status(&clock), expected);
        });
    }

    #[test]
    fn failed_validation_new_status_works_for_failure_statuses() {
        let timestamp_a = SystemTime::now().sub(Duration::from_secs(222));
        let timestamp_b = SystemTime::now().sub(Duration::from_secs(3333));
        let timestamp_c = SystemTime::now().sub(Duration::from_secs(44444));
        let clock = ValidationFailureClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_b);
        let cases = vec![
            (
                FailedValidation::new(
                    make_tx_hash(456),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                ),
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(
                        BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                            LocalErrorKind::Internal,
                        )),
                        &ValidationFailureClockMock::default().now_result(timestamp_a),
                    )),
                )),
            ),
            (
                FailedValidation::new(
                    make_tx_hash(456),
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                                RemoteErrorKind::Unreachable,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                                RemoteErrorKind::InvalidResponse,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_c),
                        ),
                    )),
                ),
                Some(FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                                RemoteErrorKind::Unreachable,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_b),
                        )
                        .add_attempt(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                                RemoteErrorKind::InvalidResponse,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_c),
                        )
                        .add_attempt(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                                RemoteErrorKind::Unreachable,
                            )),
                            &ValidationFailureClockReal::default(),
                        ),
                    ),
                )),
            ),
        ];

        cases.into_iter().for_each(|(input, expected)| {
            assert_eq!(input.new_status(&clock), expected);
        })
    }

    #[test]
    fn failed_validation_new_status_has_no_effect_on_unexpected_tx_status() {
        let validation_failure_clock = ValidationFailureClockMock::default();
        let mal_validated_tx_status = FailedValidation::new(
            make_tx_hash(123),
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
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
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                FailureStatus::RetryRequired,
            ),
            FailedValidation::new(
                make_tx_hash(789),
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)),
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

    #[test]
    fn tx_hash_by_table_provides_plain_hash() {
        let expected_hash_a = make_tx_hash(123);
        let a = TxHashByTable::SentPayable(expected_hash_a);
        let expected_hash_b = make_tx_hash(654);
        let b = TxHashByTable::FailedPayable(expected_hash_b);

        let result_a = a.hash();
        let result_b = b.hash();

        assert_eq!(result_a, expected_hash_a);
        assert_eq!(result_b, expected_hash_b);
    }

    #[test]
    fn tx_by_table_can_provide_hash() {
        let sent_tx = make_sent_tx(123);
        let expected_hash_a = sent_tx.hash;
        let a = TxByTable::SentPayable(sent_tx);
        let failed_tx = make_failed_tx(654);
        let expected_hash_b = failed_tx.hash;
        let b = TxByTable::FailedPayable(failed_tx);

        let result_a = a.hash();
        let result_b = b.hash();

        assert_eq!(result_a, expected_hash_a);
        assert_eq!(result_b, expected_hash_b);
    }

    #[test]
    fn tx_by_table_can_be_converted_into_tx_hash_by_table() {
        let sent_tx = make_sent_tx(123);
        let expected_hash_a = sent_tx.hash;
        let a = TxByTable::SentPayable(sent_tx);
        let failed_tx = make_failed_tx(654);
        let expected_hash_b = failed_tx.hash;
        let b = TxByTable::FailedPayable(failed_tx);

        let result_a = TxHashByTable::from(&a);
        let result_b = TxHashByTable::from(&b);

        assert_eq!(result_a, TxHashByTable::SentPayable(expected_hash_a));
        assert_eq!(result_b, TxHashByTable::FailedPayable(expected_hash_b));
    }
}
