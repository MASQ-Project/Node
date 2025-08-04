pub mod data_structures;
mod finish_scan;
mod start_scan;
pub mod test_utils;

use crate::accountant::db_access_objects::failed_payable_dao::FailureRetrieveCondition::ByStatus;
use crate::accountant::db_access_objects::failed_payable_dao::FailureStatus::RetryRequired;
use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureRetrieveCondition, FailureStatus, ValidationStatus,
};
use crate::accountant::db_access_objects::payable_dao::PayableRetrieveCondition::ByAddresses;
use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PayableDao};
use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDao, Tx};
use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::{
    RetryTxTemplate, RetryTxTemplates,
};
use crate::accountant::scanners::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner_extension::{
    MultistageDualPayableScanner, PreparedAdjustment, SolvencySensitivePaymentInstructor,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::{
    payables_debug_summary, OperationOutcome, PayableScanResult, PayableThresholdsGauge,
    PayableThresholdsGaugeReal,
};
use crate::accountant::scanners::{Scanner, ScannerCommon, StartableScanner};
use crate::accountant::{
    comma_joined_stringifiable, gwei_to_wei, join_with_separator, PayableScanType,
    ResponseSkeleton, SentPayables,
};
use crate::blockchain::blockchain_interface::data_structures::BatchResults;
use crate::sub_lib::accountant::PaymentThresholds;
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use ethereum_types::H256;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::messages::{ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::time::SystemTime;
use web3::types::Address;

pub struct PayableScanner {
    pub payable_threshold_gauge: Box<dyn PayableThresholdsGauge>,
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub payment_adjuster: Box<dyn PaymentAdjuster>,
}

impl MultistageDualPayableScanner for PayableScanner {}

impl SolvencySensitivePaymentInstructor for PayableScanner {
    fn try_skipping_payment_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        match self
            .payment_adjuster
            .search_for_indispensable_adjustment(&msg, logger)
        {
            Ok(None) => Ok(Either::Left(OutboundPaymentsInstructions::new(
                msg.priced_templates,
                msg.agent,
                msg.response_skeleton_opt,
            ))),
            Ok(Some(adjustment)) => Ok(Either::Right(PreparedAdjustment::new(msg, adjustment))),
            Err(_e) => todo!("be implemented with GH-711"),
        }
    }

    fn perform_payment_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        let now = SystemTime::now();
        self.payment_adjuster.adjust_payments(setup, now, logger)
    }
}

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
        non_pending_payables: Vec<PayableAccount>,
        logger: &Logger,
    ) -> Vec<PayableAccount> {
        fn pass_payables_and_drop_points(
            qp_tp: impl Iterator<Item = (PayableAccount, u128)>,
        ) -> Vec<PayableAccount> {
            let (payables, _) = qp_tp.unzip::<_, _, Vec<PayableAccount>, Vec<_>>();
            payables
        }

        let qualified_payables_and_points_uncollected =
            non_pending_payables.into_iter().flat_map(|account| {
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

    pub fn payable_exceeded_threshold(
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

    fn serialize_hashes(hashes: &[H256]) -> String {
        comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
    }

    fn detect_outcome(msg: &SentPayables) -> OperationOutcome {
        if let Ok(batch_results) = msg.clone().payment_procedure_result {
            if batch_results.sent_txs.is_empty() {
                OperationOutcome::Failure
            } else {
                match msg.payable_scan_type {
                    PayableScanType::New => OperationOutcome::NewPendingPayable,
                    PayableScanType::Retry => OperationOutcome::RetryPendingPayable,
                }
            }
        } else {
            OperationOutcome::Failure
        }
    }

    fn process_message(&self, msg: SentPayables, logger: &Logger) {
        match msg.payment_procedure_result {
            Ok(batch_results) => match msg.payable_scan_type {
                PayableScanType::New => {
                    let sent = batch_results.sent_txs.len();
                    let failed = batch_results.failed_txs.len();
                    debug!(
                        logger,
                        "Processed payables while sending to RPC: \
                         Total: {total}, Sent to RPC: {sent}, Failed to send: {failed}. \
                         Updating database...",
                        total = sent + failed,
                    );
                    self.insert_records_in_sent_payables(&batch_results.sent_txs);
                    self.insert_records_in_failed_payables(&batch_results.failed_txs);
                }
                PayableScanType::Retry => {
                    // We can do better here, possibly by creating a relationship between failed and sent txs
                    Self::log_failed_txs(&batch_results.failed_txs, logger);
                    self.insert_records_in_sent_payables(&batch_results.sent_txs);
                    self.update_records_in_failed_payables(&batch_results.sent_txs);
                }
            },
            Err(local_error) => debug!(
                logger,
                "Local error occurred before transaction signing. Error: {}", local_error
            ),
        }
    }

    fn update_records_in_failed_payables(&self, sent_txs: &Vec<Tx>) {
        let receiver_addresses = sent_txs
            .iter()
            .map(|sent_tx| sent_tx.receiver_address)
            .collect();
        let retrieved_txs = self.failed_payable_dao.retrieve_txs(Some(
            FailureRetrieveCondition::ByReceiverAddresses(receiver_addresses),
        ));
        let status_updates = retrieved_txs
            .iter()
            .map(|tx| {
                (
                    tx.hash,
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                )
            })
            .collect();
        self.failed_payable_dao
            .update_statuses(status_updates)
            .unwrap_or_else(|e| panic!("Failed to update statuses in FailedPayable Table"));
    }

    fn log_failed_txs(failed_txs: &[FailedTx], logger: &Logger) {
        debug!(
            logger,
            "While retrying, 2 transactions with hashes: {} have failed.",
            join_with_separator(failed_txs, |failed_tx| format!("{:?}", failed_tx.hash), ",")
        )
    }

    fn insert_records_in_sent_payables(&self, sent_txs: &Vec<Tx>) {
        if !sent_txs.is_empty() {
            if let Err(e) = self.sent_payable_dao.insert_new_records(sent_txs) {
                panic!(
                    "Failed to insert transactions into the SentPayable table. Error: {:?}",
                    e
                );
            }
        }
    }

    fn insert_records_in_failed_payables(&self, failed_txs: &Vec<FailedTx>) {
        if !failed_txs.is_empty() {
            let failed_txs_set: HashSet<FailedTx> = failed_txs.iter().cloned().collect();
            if let Err(e) = self.failed_payable_dao.insert_new_records(&failed_txs_set) {
                panic!(
                    "Failed to insert transactions into the FailedPayable table. Error: {:?}",
                    e
                );
            }
        }
    }

    fn generate_ui_response(
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Option<NodeToUiMessage> {
        response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
            target: MessageTarget::ClientId(response_skeleton.client_id),
            body: UiScanResponse {}.tmb(response_skeleton.context_id),
        })
    }

    fn get_txs_to_retry(&self) -> Vec<FailedTx> {
        self.failed_payable_dao
            .retrieve_txs(Some(ByStatus(RetryRequired)))
    }

    fn find_corresponding_payables_in_db(
        &self,
        txs_to_retry: &[FailedTx],
    ) -> HashMap<Address, PayableAccount> {
        let addresses = Self::filter_receiver_addresses(&txs_to_retry);
        self.payable_dao
            .non_pending_payables(Some(ByAddresses(addresses)))
            .into_iter()
            .map(|payable| (payable.wallet.address(), payable))
            .collect()
    }

    fn filter_receiver_addresses(txs_to_retry: &[FailedTx]) -> BTreeSet<Address> {
        txs_to_retry
            .iter()
            .map(|tx_to_retry| tx_to_retry.receiver_address)
            .collect()
    }

    // We can also return UnpricedQualifiedPayable here
    fn generate_retry_tx_templates(
        payables_from_db: &HashMap<Address, PayableAccount>,
        txs_to_retry: &[FailedTx],
    ) -> RetryTxTemplates {
        RetryTxTemplates(
            txs_to_retry
                .iter()
                .map(|tx_to_retry| Self::generate_retry_tx_template(payables_from_db, tx_to_retry))
                .collect(),
        )
    }

    fn generate_retry_tx_template(
        payables_from_db: &HashMap<Address, PayableAccount>,
        tx_to_retry: &FailedTx,
    ) -> RetryTxTemplate {
        let mut tx_template = RetryTxTemplate::from(tx_to_retry);
        if let Some(payable) = payables_from_db.get(&tx_to_retry.receiver_address) {
            tx_template.base.amount_in_wei = tx_template.base.amount_in_wei + payable.balance_wei;
        };

        tx_template
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::failed_payable_dao::FailedPayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDaoError, Tx};
    use crate::accountant::db_access_objects::test_utils::{
        make_failed_tx, make_sent_tx, FailedTxBuilder, TxBuilder,
    };
    use crate::accountant::scanners::payable_scanner::test_utils::{
        make_pending_payable, make_rpc_payable_failure, PayableScannerBuilder,
    };
    use crate::accountant::test_utils::{FailedPayableDaoMock, SentPayableDaoMock};
    use crate::blockchain::errors::AppRpcError::Remote;
    use crate::blockchain::errors::RemoteError::Unreachable;
    use crate::blockchain::test_utils::make_tx_hash;
    use actix::System;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

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

    //// New Code

    #[test]
    fn detect_outcome_works() {
        // Error
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Err("Any error".to_string()),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );

        // BatchResults is empty
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );

        // Only SentTxs is empty
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::Failure
        );

        // Only FailedTxs is empty
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::NewPendingPayable
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::RetryPendingPayable
        );

        // Both SentTxs and FailedTxs are present
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::New,
                response_skeleton_opt: None,
            }),
            OperationOutcome::NewPendingPayable
        );
        assert_eq!(
            PayableScanner::detect_outcome(&SentPayables {
                payment_procedure_result: Ok(BatchResults {
                    sent_txs: vec![make_sent_tx(1), make_sent_tx(2)],
                    failed_txs: vec![make_failed_tx(1), make_failed_tx(2)],
                }),
                payable_scan_type: PayableScanType::Retry,
                response_skeleton_opt: None,
            }),
            OperationOutcome::RetryPendingPayable
        );
    }

    #[test]
    fn insert_records_in_sent_payables_does_nothing_for_empty_vec() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        subject.insert_records_in_sent_payables(&vec![]);

        assert!(insert_new_records_params.lock().unwrap().is_empty());
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
        assert_eq!(params[0], sent_txs);
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
    fn insert_records_in_failed_payables_does_nothing_for_empty_vec() {
        let insert_new_records_params = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params)
            .insert_new_records_result(Ok(()));
        let subject = PayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();

        subject.insert_records_in_failed_payables(&vec![]);

        assert!(insert_new_records_params.lock().unwrap().is_empty());
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
        assert_eq!(params[0], HashSet::from([failed_tx1, failed_tx2]));
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
}
