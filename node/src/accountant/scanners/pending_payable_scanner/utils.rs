// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedTx, FailureReason, FailureStatus,
};
use crate::accountant::db_access_objects::sent_payable_dao::{
    Detection, RetrieveCondition, SentPayableDao, SentTx, TxStatus,
};
use crate::accountant::db_access_objects::utils::{from_unix_timestamp, TxHash};
use crate::blockchain::blockchain_interface::data_structures::{
    BlockchainTxFailure, TransactionBlock, TxReceiptError, TxReceiptResult,
};
use crate::blockchain::errors::AppRpcError;
use actix::Message;
use ethereum_types::{H256, U64};
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeToUiMessage;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::time::SystemTime;
use thousands::Separable;
use variant_count::VariantCount;

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

    fn register_confirmed_tx(&mut self, confirmation: NormalTxConfirmation) {
        self.confirmations.normal_confirmations.push(confirmation);
    }

    fn register_failure_reclaim(&mut self, reclaim: TxReclaim) {
        self.confirmations.reclaims.push(reclaim)
    }

    fn register_new_failure(&mut self, failed_tx: PresortedTxFailure) {
        self.failures.tx_failures.push(failed_tx);
    }

    fn register_finalization_of_unproven_failure(&mut self, tx_hash: TxHash) {
        todo!()
    }

    fn register_rpc_failure(&mut self, status_update: FailedValidationByTable) {
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
    SentPayable(FailedValidation),
    FailedPayable(FailedValidation),
}

impl From<TxReceiptError> for FailedValidationByTable {
    fn from(tx_receipt_error: TxReceiptError) -> Self {
        match tx_receipt_error.tx_hash {
            TxHashByTable::SentPayable(tx_hash) => {
                Self::SentPayable(FailedValidation::new(tx_hash, tx_receipt_error.err))
            }
            TxHashByTable::FailedPayable(tx_hash) => {
                Self::FailedPayable(FailedValidation::new(tx_hash, tx_receipt_error.err))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FailedValidation {
    pub tx_hash: TxHash,
    pub failure: AppRpcError,
}

impl FailedValidation {
    pub fn new(tx_hash: TxHash, failure: AppRpcError) -> Self {
        Self { tx_hash, failure }
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

    pub fn hashes(&self) -> &[TxHash] {
        todo!()
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

pub fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

pub fn handle_still_pending_tx(
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
                elapsed_in_ms(from_unix_timestamp(sent_tx.timestamp)).separate_with_commas()
            );
            let failed_tx = FailedTx::from((sent_tx, FailureReason::PendingTooLong));
            scan_report.register_new_failure(PresortedTxFailure::NewEntry(failed_tx));
        }
        TxByTable::FailedPayable(failed_tx) => {
            let replacement_tx = sent_payable_dao
                .retrieve_txs(Some(RetrieveCondition::ByNonce(vec![failed_tx.nonce])));
            error!(
                logger,
                "Failed tx on a recheck was found pending by its receipt. Unexpected behavior. \
                Tx {:?} was supposed to be replaced by the newer {:?}",
                failed_tx.hash,
                replacement_tx
                    .get(0)
                    .unwrap_or_else(|| panic!(
                        "Attempted to display a replacement tx for {:?} but couldn't find \
                        one in the database",
                        failed_tx.hash
                    ))
                    .hash
            )
        }
    }
    scan_report
}

pub fn handle_tx_confirmation(
    mut scan_report: ReceiptScanReport,
    tx: TxByTable,
    tx_block: TransactionBlock,
    logger: &Logger,
) -> ReceiptScanReport {
    match tx {
        TxByTable::SentPayable(sent_tx) => {
            info!(
                logger,
                "Pending tx {:?} was confirmed on the blockchain", sent_tx.hash,
            );

            let completed_sent_tx = SentTx {
                status: TxStatus::Confirmed {
                    block_hash: format!("{:?}", tx_block.block_hash),
                    block_number: tx_block.block_number.as_u64(),
                    detection: Detection::Normal,
                },
                ..sent_tx
            };
            let tx_confirmation = NormalTxConfirmation {
                tx: completed_sent_tx,
            };
            scan_report.register_confirmed_tx(tx_confirmation);
        }
        TxByTable::FailedPayable(failed_tx) => {
            info!(
                logger,
                "Failed tx {:?} was later confirmed on the blockchain and will be reclaimed",
                failed_tx.hash
            );

            let sent_tx = SentTx::from((failed_tx, tx_block));
            let reclaim = TxReclaim { reclaimed: sent_tx };
            scan_report.register_failure_reclaim(reclaim);
        }
    }
    scan_report
}

//TODO: failures handling might need enhancement suggested by GH-693
pub fn handle_status_with_failure(
    mut scan_report: ReceiptScanReport,
    tx: TxByTable,
    blockchain_failure: BlockchainTxFailure,
    logger: &Logger,
) -> ReceiptScanReport {
    match tx {
        TxByTable::SentPayable(sent_tx) => {
            let failure_reason = FailureReason::from(blockchain_failure);
            let failed_tx = FailedTx::from((sent_tx, failure_reason));

            warning!(
                logger,
                "Pending tx {:?} failed on the blockchain due to: {}",
                failed_tx.hash,
                blockchain_failure
            );

            scan_report.register_new_failure(PresortedTxFailure::NewEntry(failed_tx));
        }
        TxByTable::FailedPayable(failed_tx) => {
            debug!(
                logger,
                "Failed tx {:?} on a recheck after {}. Status will be changed to \
            \"Concluded\" due to blockchain failure: {}",
                failed_tx.hash,
                failed_tx.reason,
                blockchain_failure
            );

            scan_report.register_new_failure(PresortedTxFailure::RecheckCompleted(failed_tx.hash));
        }
    }
    scan_report
}

pub fn handle_rpc_failure(
    mut scan_report: ReceiptScanReport,
    rpc_error: TxReceiptError,
    logger: &Logger,
) -> ReceiptScanReport {
    warning!(
        logger,
        "Failed to retrieve tx receipt for {:?}: {:?}. Will retry receipt retrieval next cycle",
        rpc_error.tx_hash,
        rpc_error.err
    );
    let validation_status_update = FailedValidationByTable::from(rpc_error);
    scan_report.register_rpc_failure(validation_status_update);
    scan_report
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
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
        FailedValidationByTable, NormalTxConfirmation, PendingPayableCache, PresortedTxFailure,
        ReceiptScanReport, RecheckRequiringFailures, Retry, TransactionBlock, TxHashByTable,
        TxReceiptError, TxReceiptResult, TxReclaim,
    };
    use crate::accountant::test_utils::{make_failed_tx, make_sent_tx, make_transaction_block};
    use crate::blockchain::errors::{AppRpcError, LocalError, RemoteError};
    use crate::blockchain::test_utils::make_tx_hash;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};

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
                AppRpcError::Local(LocalError::Internal),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(12121),
                    AppRpcError::Remote(RemoteError::InvalidResponse("blah".to_string())),
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
                AppRpcError::Local(LocalError::Internal),
            ))],
            vec![FailedValidationByTable::FailedPayable(
                FailedValidation::new(
                    make_tx_hash(1234),
                    AppRpcError::Remote(RemoteError::Unreachable),
                ),
            )],
            vec![
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    make_tx_hash(2222),
                    AppRpcError::Local(LocalError::Internal),
                )),
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    make_tx_hash(1234),
                    AppRpcError::Remote(RemoteError::Unreachable),
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
    fn pending_payables_cache_insert_and_get_methods_single_record() {
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
    fn pending_payables_cache_insert_and_get_methods_multiple_records() {
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
    fn pending_payables_cache_ensure_empty_happy_path() {
        init_test_logging();
        let test_name = "pending_payables_cache_ensure_empty_happy_path";
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
    fn pending_payables_cache_ensure_empty_sad_path() {
        init_test_logging();
        let test_name = "pending_payables_cache_ensure_empty_sad_path";
        let mut subject = CurrentPendingPayables::new();
        let sent_tx = make_sent_tx(567);
        let tx_hash = sent_tx.hash;
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
    fn pending_payables_cache_dump_works() {
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
        let tx_hash = failed_tx.hash;
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
        let api_error_sent_tx = AppRpcError::Local(LocalError::Internal);
        let receipt_error_for_sent_tx = TxReceiptError::new(
            TxHashByTable::SentPayable(tx_hash_sent_tx),
            api_error_sent_tx.clone(),
        );
        let tx_hash_failed_tx = make_tx_hash(456);
        let api_error_failed_tx = AppRpcError::Remote(RemoteError::Unreachable);
        let receipt_error_for_failed_tx = TxReceiptError::new(
            TxHashByTable::FailedPayable(tx_hash_failed_tx),
            api_error_failed_tx.clone(),
        );

        let result_1 = FailedValidationByTable::from(receipt_error_for_sent_tx);
        let result_2 = FailedValidationByTable::from(receipt_error_for_failed_tx);

        assert_eq!(
            result_1,
            FailedValidationByTable::SentPayable(FailedValidation::new(
                tx_hash_sent_tx,
                api_error_sent_tx
            ))
        );
        assert_eq!(
            result_2,
            FailedValidationByTable::FailedPayable(FailedValidation::new(
                tx_hash_failed_tx,
                api_error_failed_tx
            ))
        );
    }
}
