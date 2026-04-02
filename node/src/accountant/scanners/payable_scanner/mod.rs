// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
mod finish_scan;
pub mod msgs;
mod start_scan;
pub mod test_utils;
pub mod tx_templates;

pub mod payment_adjuster_integration;
pub mod utils;

use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureReason, FailureRetrieveCondition, FailureStatus,
};
use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDao, SentTx};
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
use crate::accountant::scanners::payable_scanner::payment_adjuster_integration::SolvencySensitivePaymentInstructor;
use crate::accountant::scanners::payable_scanner::utils::{
    batch_stats, calculate_occurences, filter_receiver_addresses_from_txs, generate_status_updates,
    payables_debug_summary, NextScanToRun, PayableScanResult, PayableThresholdsGauge,
    PayableThresholdsGaugeReal, PendingPayableMissingInDb,
};
use crate::accountant::scanners::{Scanner, ScannerCommon, StartableScanner};
use crate::accountant::{
    gwei_to_wei, join_with_commas, join_with_separator, PayableScanType, PendingPayable,
    ResponseSkeleton, ScanForNewPayables, ScanForRetryPayables, SentPayables,
};
use crate::blockchain::blockchain_interface::data_structures::BatchResults;
use crate::blockchain::errors::validation_status::ValidationStatus;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use masq_lib::utils::ExpectValue;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::time::SystemTime;
use web3::types::Address;

pub(in crate::accountant::scanners) trait MultistageDualPayableScanner:
    StartableScanner<ScanForNewPayables, InitialTemplatesMessage>
    + StartableScanner<ScanForRetryPayables, InitialTemplatesMessage>
    + SolvencySensitivePaymentInstructor
    + Scanner<SentPayables, PayableScanResult>
{
}

pub struct PayableScanner {
    pub payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub payment_adjuster: Box<dyn PaymentAdjuster>,
}

impl MultistageDualPayableScanner for PayableScanner {}

impl PayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        sent_payable_dao: Box<dyn SentPayableDao>,
        failed_payable_dao: Box<dyn FailedPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        payment_adjuster: Box<dyn PaymentAdjuster>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            sent_payable_dao,
            failed_payable_dao,
            payable_threshold_gauge: Box::new(PayableThresholdsGaugeReal::default()),
            payment_adjuster,
        }
    }

    pub fn sniff_out_alarming_payables_and_maybe_log_them(
        &self,
        retrieve_payables: Vec<PayableAccount>,
        logger: &Logger,
    ) -> Vec<PayableAccount> {
        fn pass_payables_and_drop_points(
            qp_tp: impl Iterator<Item = (PayableAccount, u128)>,
        ) -> Vec<PayableAccount> {
            let (payables, _) = qp_tp.unzip::<_, _, Vec<PayableAccount>, Vec<_>>();
            payables
        }

        let qualified_payables_and_points_uncollected =
            retrieve_payables.into_iter().flat_map(|account| {
                self.payable_exceeded_threshold(&account, SystemTime::now())
                    .map(|threshold_point| (account, threshold_point))
            });
        match logger.debug_enabled() {
            false => pass_payables_and_drop_points(qualified_payables_and_points_uncollected),
            true => {
                let qualified_and_points_collected =
                    qualified_payables_and_points_uncollected.collect_vec();
                payables_debug_summary(&qualified_and_points_collected, logger);
                pass_payables_and_drop_points(qualified_and_points_collected.into_iter())
            }
        }
    }

    fn payable_exceeded_threshold(
        &self,
        payable: &PayableAccount,
        now: SystemTime,
    ) -> Option<u128> {
        let debt_age = now
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if self.payable_threshold_gauge.is_innocent_age(
            debt_age,
            self.common.payment_thresholds.maturity_threshold_sec,
        ) {
            return None;
        }

        if self.payable_threshold_gauge.is_innocent_balance(
            payable.balance_wei,
            gwei_to_wei(self.common.payment_thresholds.permanent_debt_allowed_gwei),
        ) {
            return None;
        }

        let threshold = self
            .payable_threshold_gauge
            .calculate_payout_threshold_in_gwei(&self.common.payment_thresholds, debt_age);
        if payable.balance_wei > threshold {
            Some(threshold)
        } else {
            None
        }
    }

    fn check_for_missing_records(
        &self,
        just_baked_sent_payables: &[&PendingPayable],
    ) -> Vec<PendingPayableMissingInDb> {
        let actual_sent_payables_len = just_baked_sent_payables.len();
        let hashset_with_hashes_to_eliminate_duplicates = just_baked_sent_payables
            .iter()
            .map(|pending_payable| pending_payable.hash)
            .collect::<BTreeSet<TxHash>>();

        if hashset_with_hashes_to_eliminate_duplicates.len() != actual_sent_payables_len {
            panic!(
                "Found duplicates in the recent sent txs: {:?}",
                just_baked_sent_payables
            );
        }

        let transaction_hashes_and_rowids_from_db = self
            .sent_payable_dao
            .get_tx_identifiers(&hashset_with_hashes_to_eliminate_duplicates);
        let hashes_from_db = transaction_hashes_and_rowids_from_db
            .keys()
            .copied()
            .collect::<BTreeSet<TxHash>>();

        let missing_sent_payables_hashes = hashset_with_hashes_to_eliminate_duplicates
            .difference(&hashes_from_db)
            .copied();

        let mut sent_payables_hashmap = just_baked_sent_payables
            .iter()
            .map(|payable| (payable.hash, &payable.recipient_wallet))
            .collect::<HashMap<TxHash, &Wallet>>();
        missing_sent_payables_hashes
            .map(|hash| {
                let wallet_address = sent_payables_hashmap
                    .remove(&hash)
                    .expectv("wallet")
                    .address();
                PendingPayableMissingInDb::new(wallet_address, hash)
            })
            .collect()
    }

    // TODO this should be used when Utkarsh picks the card GH-701 where he postponed the fix of saving the SentTxs
    #[allow(dead_code)]
    fn check_on_missing_sent_tx_records(&self, sent_payments: &[&PendingPayable]) {
        fn missing_record_msg(nonexistent: &[PendingPayableMissingInDb]) -> String {
            format!(
                "Expected sent-payable records for {} were not found. The system has become unreliable",
                join_with_commas(nonexistent, |missing_sent_tx_ids| format!(
                    "(tx: {:?}, to wallet: {:?})",
                    missing_sent_tx_ids.hash, missing_sent_tx_ids.recipient
                ))
            )
        }

        let missing_sent_tx_records = self.check_for_missing_records(sent_payments);
        if !missing_sent_tx_records.is_empty() {
            panic!("{}", missing_record_msg(&missing_sent_tx_records))
        }
    }

    fn determine_next_scan_to_run(msg: &SentPayables) -> NextScanToRun {
        match &msg.payment_procedure_result {
            Ok(batch_results) => {
                if batch_results.sent_txs.is_empty() {
                    if batch_results.failed_txs.is_empty() {
                        return NextScanToRun::NewPayableScan;
                    } else {
                        return NextScanToRun::RetryPayableScan;
                    }
                }

                NextScanToRun::PendingPayableScan
            }
            Err(_e) => match msg.payable_scan_type {
                PayableScanType::New => NextScanToRun::NewPayableScan,
                PayableScanType::Retry => NextScanToRun::RetryPayableScan,
            },
        }
    }

    fn process_message(&self, msg: &SentPayables, logger: &Logger) {
        match &msg.payment_procedure_result {
            Ok(batch_results) => match msg.payable_scan_type {
                PayableScanType::New => {
                    self.handle_batch_results_for_new_scan(batch_results, logger)
                }
                PayableScanType::Retry => {
                    self.handle_batch_results_for_retry_scan(batch_results, logger)
                }
            },
            Err(local_error) => Self::log_local_error(local_error, logger),
        }
    }

    fn handle_batch_results_for_new_scan(&self, batch_results: &BatchResults, logger: &Logger) {
        let (sent, failed) = calculate_occurences(batch_results);
        debug!(
            logger,
            "Processed new txs while sending to RPC: {}",
            batch_stats(sent, failed),
        );
        if sent > 0 {
            self.insert_records_in_sent_payables(&batch_results.sent_txs);
        }
        if failed > 0 {
            debug!(
                logger,
                "Recording failed txs: {:?}", batch_results.failed_txs
            );
            self.insert_records_in_failed_payables(&batch_results.failed_txs);
        }
    }

    fn handle_batch_results_for_retry_scan(&self, batch_results: &BatchResults, logger: &Logger) {
        let (sent, failed) = calculate_occurences(batch_results);
        debug!(
            logger,
            "Processed retried txs while sending to RPC: {}",
            batch_stats(sent, failed),
        );

        if sent > 0 {
            self.insert_records_in_sent_payables(&batch_results.sent_txs);
            self.update_statuses_of_prev_txs(&batch_results.sent_txs);
        }
        if failed > 0 {
            // TODO: Would it be a good ides to update Retry attempt of previous tx?
            Self::log_failed_txs_during_retry(&batch_results.failed_txs, logger);
        }
    }

    fn update_statuses_of_prev_txs(&self, sent_txs: &[SentTx]) {
        // TODO: We can do better here, possibly by creating a relationship between failed and sent txs
        // Also, consider the fact that some txs will be with PendingTooLong status, what should we do with them?
        let retrieved_txs = self.retrieve_failed_txs_by_receiver_addresses(sent_txs);
        let (pending_too_long, other_reasons): (BTreeSet<_>, BTreeSet<_>) = retrieved_txs
            .into_iter()
            .partition(|tx| matches!(tx.reason, FailureReason::PendingTooLong));
        if !pending_too_long.is_empty() {
            self.update_failed_txs(
                &pending_too_long,
                FailureStatus::RecheckRequired(ValidationStatus::Waiting),
            );
        }
        if !other_reasons.is_empty() {
            self.update_failed_txs(&other_reasons, FailureStatus::Concluded);
        }
    }

    fn retrieve_failed_txs_by_receiver_addresses(&self, sent_txs: &[SentTx]) -> BTreeSet<FailedTx> {
        let receiver_addresses = filter_receiver_addresses_from_txs(sent_txs.iter());
        self.failed_payable_dao
            .retrieve_txs(Some(FailureRetrieveCondition::ByReceiverAddresses(
                receiver_addresses,
            )))
    }

    fn update_failed_txs(&self, failed_txs: &BTreeSet<FailedTx>, status: FailureStatus) {
        let status_updates = generate_status_updates(failed_txs, status);
        self.failed_payable_dao
            .update_statuses(&status_updates)
            .unwrap_or_else(|e| panic!("Failed to conclude txs in database: {:?}", e));
    }

    fn log_failed_txs_during_retry(failed_txs: &[FailedTx], logger: &Logger) {
        warning!(
            logger,
            "While retrying, {} transactions with hashes: {} have failed.",
            failed_txs.len(),
            join_with_separator(failed_txs, |failed_tx| format!("{:?}", failed_tx.hash), ",")
        )
    }

    fn log_local_error(local_error: &str, logger: &Logger) {
        warning!(
            logger,
            "Local error occurred before transaction signing. Error: {}",
            local_error
        )
    }

    fn insert_records_in_sent_payables(&self, sent_txs: &[SentTx]) {
        self.sent_payable_dao
            .insert_new_records(&sent_txs.iter().cloned().collect())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to insert transactions into the SentPayable table. Error: {:?}",
                    e
                )
            });
    }

    fn insert_records_in_failed_payables(&self, failed_txs: &[FailedTx]) {
        self.failed_payable_dao
            .insert_new_records(&failed_txs.iter().cloned().collect())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to insert transactions into the FailedPayable table. Error: {:?}",
                    e
                )
            });
    }

    fn generate_ui_response(
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Option<NodeToUiMessage> {
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }

    fn get_txs_to_retry(&self) -> BTreeSet<FailedTx> {
        self.failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)))
    }

    fn find_amount_from_payables(
        &self,
        txs_to_retry: &BTreeSet<FailedTx>,
    ) -> HashMap<Address, u128> {
        let addresses = filter_receiver_addresses_from_txs(txs_to_retry.iter());
        self.payable_dao
            .retrieve_payables(Some(ByAddresses(addresses)))
            .into_iter()
            .map(|payable| (payable.wallet.address(), payable.balance_wei))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailedPayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::SentPayableDaoError;
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, FailedTxBuilder, TxBuilder,
    };
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::test_utils::{
        make_payable_account, FailedPayableDaoMock, PayableThresholdsGaugeMock, SentPayableDaoMock,
    };
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use crate::test_utils::make_wallet;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn generate_ui_response_works_correctly() {
        assert_eq!(PayableScanner::generate_ui_response(None), None);
        assert_eq!(
            PayableScanner::generate_ui_response(Some(ResponseSkeleton {
                client_id: 1234,
                context_id: 5678
            })),
            Some(NodeToUiMessage {
                target: MessageTarget::ClientId(1234),
                body: UiScanResponse {}.tmb(5678),
            })
        );
    }

    #[test]
    fn determine_next_scan_to_run_works() {
        // Error
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            NextScanToRun::NewPayableScan
        );
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            NextScanToRun::RetryPayableScan
        );

        // BatchResults is empty
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            NextScanToRun::NewPayableScan
        );
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            NextScanToRun::NewPayableScan
        );

        // Only FailedTxs
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            NextScanToRun::RetryPayableScan
        );
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            NextScanToRun::RetryPayableScan
        );

        // Only SentTxs
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            NextScanToRun::PendingPayableScan
        );
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            NextScanToRun::PendingPayableScan
        );

        // Both SentTxs and FailedTxs are present
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            NextScanToRun::PendingPayableScan
        );
        assert_eq!(
            PayableScanner::determine_next_scan_to_run(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            NextScanToRun::PendingPayableScan
        );
    }

    #[test]
    fn update_statuses_of_prev_txs_updates_statuses_correctly() {
        let retrieve_txs_params = Arc::new(Mutex::new(vec![]));
        let update_statuses_params = Arc::new(Mutex::new(vec![]));
        let tx_hash_1 = make_tx_hash(1);
        let tx_hash_2 = make_tx_hash(2);
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_txs_params)
            .retrieve_txs_result(BTreeSet::from([
                FailedTxBuilder::default()
                    .hash(tx_hash_1)
                    .reason(FailureReason::PendingTooLong)
                    .build(),
                FailedTxBuilder::default()
                    .hash(tx_hash_2)
                    .reason(FailureReason::Reverted)
                    .build(),
            ]))
            .update_statuses_params(&update_statuses_params)
            .update_statuses_result(Ok(()))
            .update_statuses_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let sent_txs = vec![make_sent_tx(1), make_sent_tx(2)];

        subject.update_statuses_of_prev_txs(&sent_txs);

        let update_params = update_statuses_params.lock().unwrap();
        assert_eq!(update_params.len(), 2);
        assert_eq!(
            update_params[0],
            hashmap!(tx_hash_1 => FailureStatus::RecheckRequired(ValidationStatus::Waiting))
        );
        assert_eq!(
            update_params[1],
            hashmap!(tx_hash_2 => FailureStatus::Concluded)
        );
    }

    #[test]
    fn no_missing_records() {
        let wallet_1 = make_wallet("abc");
        let hash_1 = make_tx_hash(123);
        let wallet_2 = make_wallet("def");
        let hash_2 = make_tx_hash(345);
        let wallet_3 = make_wallet("ghi");
        let hash_3 = make_tx_hash(546);
        let wallet_4 = make_wallet("jkl");
        let hash_4 = make_tx_hash(678);
        let pending_payables_owned = vec![
            PendingPayable::new(wallet_1.clone(), hash_1),
            PendingPayable::new(wallet_2.clone(), hash_2),
            PendingPayable::new(wallet_3.clone(), hash_3),
            PendingPayable::new(wallet_4.clone(), hash_4),
        ];
        let pending_payables_ref = pending_payables_owned
            .iter()
            .collect::<Vec<&PendingPayable>>();
        let sent_payable_dao = SentPayableDaoMock::new().get_tx_identifiers_result(
            hashmap!(hash_4 => 4, hash_1 => 1, hash_3 => 3, hash_2 => 2),
        );
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let missing_records = subject.check_for_missing_records(&pending_payables_ref);

        assert!(
            missing_records.is_empty(),
            "We thought the vec would be empty but contained: {:?}",
            missing_records
        );
    }

    #[test]
    #[should_panic(
        expected = "Found duplicates in the recent sent txs: [PendingPayable { recipient_wallet: \
        Wallet { kind: Address(0x0000000000000000000000000000000000616263) }, hash: \
        0x000000000000000000000000000000000000000000000000000000000000007b }, PendingPayable { \
        recipient_wallet: Wallet { kind: Address(0x0000000000000000000000000000000000646566) }, \
        hash: 0x00000000000000000000000000000000000000000000000000000000000001c8 }, \
        PendingPayable { recipient_wallet: Wallet { kind: \
        Address(0x0000000000000000000000000000000000676869) }, hash: \
        0x00000000000000000000000000000000000000000000000000000000000001c8 }, PendingPayable { \
        recipient_wallet: Wallet { kind: Address(0x00000000000000000000000000000000006a6b6c) }, \
        hash: 0x0000000000000000000000000000000000000000000000000000000000000315 }]"
    )]
    fn just_baked_pending_payables_contain_duplicates() {
        let hash_1 = make_tx_hash(123);
        let hash_2 = make_tx_hash(456);
        let hash_3 = make_tx_hash(789);
        let pending_payables = vec![
            PendingPayable::new(make_wallet("abc"), hash_1),
            PendingPayable::new(make_wallet("def"), hash_2),
            PendingPayable::new(make_wallet("ghi"), hash_2),
            PendingPayable::new(make_wallet("jkl"), hash_3),
        ];
        let pending_payables_ref = pending_payables.iter().collect::<Vec<&PendingPayable>>();
        let sent_payable_dao = SentPayableDaoMock::new()
            .get_tx_identifiers_result(hashmap!(hash_1 => 1, hash_2 => 3, hash_3 => 5));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        subject.check_for_missing_records(&pending_payables_ref);
    }

    #[test]
    fn payable_is_found_innocent_by_age_and_returns() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(true);
        let mut subject = PayableScannerBuilder::new().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let now = SystemTime::now();
        let debt_age_s = 111_222;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
        let mut payable = make_payable_account(111);
        payable.last_paid_timestamp = last_paid_timestamp;

        let result = subject.payable_exceeded_threshold(&payable, now);

        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned, threshold_value) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        assert_eq!(debt_age_returned, debt_age_s);
        assert_eq!(
            threshold_value,
            DEFAULT_PAYMENT_THRESHOLDS.maturity_threshold_sec
        )
        // No panic and so no other method was called, which means an early return
    }

    #[test]
    fn payable_is_found_innocent_by_balance_and_returns() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let is_innocent_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(false)
            .is_innocent_balance_params(&is_innocent_balance_params_arc)
            .is_innocent_balance_result(true);
        let mut subject = PayableScannerBuilder::new().build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);
        let now = SystemTime::now();
        let debt_age_s = 3_456;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
        let mut payable = make_payable_account(222);
        payable.last_paid_timestamp = last_paid_timestamp;
        payable.balance_wei = 123456;

        let result = subject.payable_exceeded_threshold(&payable, now);

        assert_eq!(result, None);
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned, _) = is_innocent_age_params.remove(0);
        assert!(is_innocent_age_params.is_empty());
        assert_eq!(debt_age_returned, debt_age_s);
        let is_innocent_balance_params = is_innocent_balance_params_arc.lock().unwrap();
        assert_eq!(
            *is_innocent_balance_params,
            vec![(
                123456_u128,
                gwei_to_wei(DEFAULT_PAYMENT_THRESHOLDS.permanent_debt_allowed_gwei)
            )]
        )
        //no other method was called (absence of panic), and that means we returned early
    }

    #[test]
    fn threshold_calculation_depends_on_user_defined_payment_thresholds() {
        let is_innocent_age_params_arc = Arc::new(Mutex::new(vec![]));
        let is_innocent_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let calculate_payable_threshold_params_arc = Arc::new(Mutex::new(vec![]));
        let balance = gwei_to_wei(5555_u64);
        let now = SystemTime::now();
        let debt_age_s = 1111 + 1;
        let last_paid_timestamp = now.checked_sub(Duration::from_secs(debt_age_s)).unwrap();
        let payable_account = PayableAccount {
            wallet: make_wallet("hi"),
            balance_wei: balance,
            last_paid_timestamp,
        };
        let custom_payment_thresholds = PaymentThresholds {
            maturity_threshold_sec: 1111,
            payment_grace_period_sec: 2222,
            permanent_debt_allowed_gwei: 3333,
            debt_threshold_gwei: 4444,
            threshold_interval_sec: 5555,
            unban_below_gwei: 5555,
        };
        let payable_thresholds_gauge = PayableThresholdsGaugeMock::default()
            .is_innocent_age_params(&is_innocent_age_params_arc)
            .is_innocent_age_result(
                debt_age_s <= custom_payment_thresholds.maturity_threshold_sec as u64,
            )
            .is_innocent_balance_params(&is_innocent_balance_params_arc)
            .is_innocent_balance_result(
                balance <= gwei_to_wei(custom_payment_thresholds.permanent_debt_allowed_gwei),
            )
            .calculate_payout_threshold_in_gwei_params(&calculate_payable_threshold_params_arc)
            .calculate_payout_threshold_in_gwei_result(4567898); //made up value
        let mut subject = PayableScannerBuilder::new()
            .payment_thresholds(custom_payment_thresholds)
            .build();
        subject.payable_threshold_gauge = Box::new(payable_thresholds_gauge);

        let result = subject.payable_exceeded_threshold(&payable_account, now);

        assert_eq!(result, Some(4567898));
        let mut is_innocent_age_params = is_innocent_age_params_arc.lock().unwrap();
        let (debt_age_returned_innocent, curve_derived_time) = is_innocent_age_params.remove(0);
        assert_eq!(*is_innocent_age_params, vec![]);
        assert_eq!(debt_age_returned_innocent, debt_age_s);
        assert_eq!(
            curve_derived_time,
            custom_payment_thresholds.maturity_threshold_sec as u64
        );
        let is_innocent_balance_params = is_innocent_balance_params_arc.lock().unwrap();
        assert_eq!(
            *is_innocent_balance_params,
            vec![(
                payable_account.balance_wei,
                gwei_to_wei(custom_payment_thresholds.permanent_debt_allowed_gwei)
            )]
        );
        let mut calculate_payable_curves_params =
            calculate_payable_threshold_params_arc.lock().unwrap();
        let (payment_thresholds, debt_age_returned_curves) =
            calculate_payable_curves_params.remove(0);
        assert_eq!(*calculate_payable_curves_params, vec![]);
        assert_eq!(debt_age_returned_curves, debt_age_s);
        assert_eq!(payment_thresholds, custom_payment_thresholds)
    }

    #[test]
    fn payable_with_debt_under_the_slope_is_marked_unqualified() {
        init_test_logging();
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let debt = gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 1);
        let time = to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 - 1;
        let unqualified_payable_account = vec![PayableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: debt,
            last_paid_timestamp: from_unix_timestamp(time),
        }];
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let test_name =
            "payable_with_debt_above_the_slope_is_qualified_and_the_threshold_value_is_returned";
        let logger = Logger::new(test_name);

        let result = subject
            .sniff_out_alarming_payables_and_maybe_log_them(unqualified_payable_account, &logger);

        assert_eq!(result, vec![]);
        TestLogHandler::new()
            .exists_no_log_containing(&format!("DEBUG: {}: Paying qualified debts", test_name));
    }

    #[test]
    fn payable_with_debt_above_the_slope_is_qualified() {
        init_test_logging();
        let payment_thresholds = PaymentThresholds::default();
        let debt = gwei_to_wei(payment_thresholds.debt_threshold_gwei - 1);
        let time = (payment_thresholds.maturity_threshold_sec
            + payment_thresholds.threshold_interval_sec
            - 1) as i64;
        let qualified_payable = PayableAccount {
            wallet: make_wallet("wallet0"),
            balance_wei: debt,
            last_paid_timestamp: from_unix_timestamp(time),
        };
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let test_name = "payable_with_debt_above_the_slope_is_qualified";
        let logger = Logger::new(test_name);

        let result = subject.sniff_out_alarming_payables_and_maybe_log_them(
            vec![qualified_payable.clone()],
            &logger,
        );

        assert_eq!(result, vec![qualified_payable]);
        TestLogHandler::new().exists_log_matching(&format!(
            "DEBUG: {}: Paying qualified debts:\n\
            999,999,999,000,000,000 wei owed for \\d+ sec exceeds the threshold \
            500,000,000,000,000,000 wei for creditor 0x0000000000000000000000000077616c6c657430",
            test_name
        ));
    }

    #[test]
    fn retrieved_payables_turn_into_an_empty_vector_if_all_unqualified() {
        init_test_logging();
        let test_name = "retrieved_payables_turn_into_an_empty_vector_if_all_unqualified";
        let now = SystemTime::now();
        let payment_thresholds = PaymentThresholds::default();
        let unqualified_payable_account = vec![PayableAccount {
            wallet: make_wallet("wallet1"),
            balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 1),
            last_paid_timestamp: from_unix_timestamp(
                to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 + 1,
            ),
        }];
        let subject = PayableScannerBuilder::new()
            .payment_thresholds(payment_thresholds)
            .build();
        let logger = Logger::new(test_name);

        let result = subject
            .sniff_out_alarming_payables_and_maybe_log_them(unqualified_payable_account, &logger);

        assert_eq!(result, vec![]);
        TestLogHandler::new()
            .exists_no_log_containing(&format!("DEBUG: {test_name}: Paying qualified debts"));
    }

    #[test]
    fn insert_records_in_sent_payables_inserts_records_successfully() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx1 = TxBuilder::default().hash(make_tx_hash(1)).build();
        let tx2 = TxBuilder::default().hash(make_tx_hash(2)).build();
        let sent_txs = vec![tx1.clone(), tx2.clone()];

        subject.insert_records_in_sent_payables(&sent_txs);

        let params = insert_new_records_params.lock().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], sent_txs.into_iter().collect());
    }

    #[test]
    fn insert_records_in_sent_payables_panics_on_error() {
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Err(
            SentPayableDaoError::PartialExecution("Test error".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx = TxBuilder::default().hash(make_tx_hash(1)).build();
        let sent_txs = vec![tx];

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.insert_records_in_sent_payables(&sent_txs);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("Failed to insert transactions into the SentPayable table"));
        assert!(panic_msg.contains("Test error"));
    }

    #[test]
    fn insert_records_in_failed_payables_inserts_records_successfully() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx1 = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_tx2 = FailedTxBuilder::default().hash(make_tx_hash(2)).build();
        let failed_txs = vec![failed_tx1.clone(), failed_tx2.clone()];

        subject.insert_records_in_failed_payables(&failed_txs);

        let params = insert_new_records_params.lock().unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], BTreeSet::from([failed_tx1, failed_tx2]));
    }

    #[test]
    fn insert_records_in_failed_payables_panics_on_error() {
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Err(
            FailedPayableDaoError::PartialExecution("Test error".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_txs = vec![failed_tx];

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.insert_records_in_failed_payables(&failed_txs);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains("Failed to insert transactions into the FailedPayable table"));
        assert!(panic_msg.contains("Test error"));
    }

    #[test]
    fn handle_batch_results_for_new_scan_does_not_perform_any_operation_when_sent_txs_is_empty() {
        let insert_new_records_sent_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let insert_new_records_failed_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_sent_tx_params_arc);
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_failed_tx_params_arc)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![],
            failed_txs: vec![make_failed_tx(1)],
        };

        subject.handle_batch_results_for_new_scan(&batch_results, &Logger::new("test"));

        assert_eq!(
            insert_new_records_failed_tx_params_arc
                .lock()
                .unwrap()
                .len(),
            1
        );
        assert!(insert_new_records_sent_tx_params_arc
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn handle_batch_results_for_new_scan_does_not_perform_any_operation_when_failed_txs_is_empty() {
        let insert_new_records_params_failed = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_failed);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![make_sent_tx(1)],
            failed_txs: vec![],
        };

        subject.handle_batch_results_for_new_scan(&batch_results, &Logger::new("test"));

        assert!(insert_new_records_params_failed.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_batch_results_for_retry_scan_does_not_perform_any_operation_when_sent_txs_is_empty() {
        let insert_new_records_sent_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_txs_params = Arc::new(Mutex::new(vec![]));
        let update_statuses_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_sent_tx_params_arc);
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_txs_params)
            .update_statuses_params(&update_statuses_params);
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![],
            failed_txs: vec![make_failed_tx(1)],
        };

        subject.handle_batch_results_for_retry_scan(&batch_results, &Logger::new("test"));

        assert!(insert_new_records_sent_tx_params_arc
            .lock()
            .unwrap()
            .is_empty());
        assert!(retrieve_txs_params.lock().unwrap().is_empty());
        assert!(update_statuses_params.lock().unwrap().is_empty());
    }

    #[test]
    fn handle_retry_logs_no_warn_when_failed_txs_exist() {
        init_test_logging();
        let test_name = "handle_retry_logs_no_warn_when_failed_txs_exist";
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_result(BTreeSet::from([make_failed_tx(1)]))
            .update_statuses_result(Ok(()))
            .update_statuses_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let batch_results = BatchResults {
            sent_txs: vec![make_sent_tx(1)],
            failed_txs: vec![],
        };

        subject.handle_batch_results_for_retry_scan(&batch_results, &Logger::new(test_name));

        let tlh = TestLogHandler::new();
        tlh.exists_no_log_containing(&format!("WARN: {test_name}"));
    }

    #[test]
    fn update_failed_txs_panics_on_error() {
        let failed_payable_dao = FailedPayableDaoMock::default().update_statuses_result(Err(
            FailedPayableDaoError::SqlExecutionFailed("I slept too much".to_string()),
        ));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let failed_tx = FailedTxBuilder::default().hash(make_tx_hash(1)).build();
        let failed_txs = BTreeSet::from([failed_tx]);

        let result = catch_unwind(AssertUnwindSafe(|| {
            subject.update_failed_txs(&failed_txs, FailureStatus::Concluded);
        }))
        .unwrap_err();

        let panic_msg = result.downcast_ref::<String>().unwrap();
        assert!(panic_msg.contains(
            "Failed to conclude txs in database: SqlExecutionFailed(\"I slept too much\")"
        ));
    }
}
