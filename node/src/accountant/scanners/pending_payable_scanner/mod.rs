// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod tx_receipt_interpreter;
pub mod utils;

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureRetrieveCondition, FailureStatus,
};
use crate::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoError};
use crate::accountant::db_access_objects::sent_payable_dao::{
    RetrieveCondition, SentPayableDao, SentPayableDaoError, SentTx, TxStatus,
};
use crate::accountant::db_access_objects::utils::{TxHash, TxRecordWithHash};
use crate::accountant::scanners::pending_payable_scanner::tx_receipt_interpreter::TxReceiptInterpreter;
use crate::accountant::scanners::pending_payable_scanner::utils::{
    CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
    FailedValidationByTable, MismatchReport, NormalTxConfirmation, PendingPayableCache,
    PendingPayableScanResult, PresortedTxFailure, ReceiptScanReport, RecheckRequiringFailures,
    Retry, TxByTable, TxCaseToBeInterpreted, TxHashByTable, TxReclaim, UpdatableValidationStatus,
};
use crate::accountant::scanners::{
    PrivateScanner, Scanner, ScannerCommon, StartScanError, StartableScanner,
};
use crate::accountant::{
    comma_joined_stringifiable, PendingPayableId, RequestTransactionReceipts, ResponseSkeleton,
    ScanForPendingPayables, TxReceiptsMessage,
};
use crate::blockchain::blockchain_interface::data_structures::{
    StatusReadFromReceiptCheck, TransactionBlock, TxReceiptResult,
};
use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::time_marking_methods;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::rc::Rc;
use std::time::SystemTime;
use thousands::Separable;

pub struct PendingPayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
    pub current_sent_payables: Box<dyn PendingPayableCache<SentTx>>,
    pub yet_unproven_failed_payables: Box<dyn PendingPayableCache<FailedTx>>,
}

impl
    PrivateScanner<
        ScanForPendingPayables,
        RequestTransactionReceipts,
        TxReceiptsMessage,
        PendingPayableScanResult,
    > for PendingPayableScanner
{
}

impl StartableScanner<ScanForPendingPayables, RequestTransactionReceipts>
    for PendingPayableScanner
{
    fn start_scan(
        &mut self,
        _wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<RequestTransactionReceipts, StartScanError> {
        self.mark_as_started(timestamp);
        info!(logger, "Scanning for pending payable");

        let pending_tx_hashes_opt = self.handle_pending_payables();
        let failure_hashes_opt = self.handle_unproven_failures();

        if pending_tx_hashes_opt.is_none() && failure_hashes_opt.is_none() {
            self.mark_as_ended(logger);
            return Err(StartScanError::NothingToProcess);
        }

        Self::log_records_found_for_receipt_check(
            pending_tx_hashes_opt.as_ref(),
            failure_hashes_opt.as_ref(),
            logger,
        );

        let all_hashes = pending_tx_hashes_opt
            .unwrap_or_default()
            .into_iter()
            .chain(failure_hashes_opt.unwrap_or_default())
            .collect_vec();

        Ok(RequestTransactionReceipts {
            tx_hashes: all_hashes,
            response_skeleton_opt,
        })
    }
}

impl Scanner<TxReceiptsMessage, PendingPayableScanResult> for PendingPayableScanner {
    fn finish_scan(
        &mut self,
        message: TxReceiptsMessage,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        let response_skeleton_opt = message.response_skeleton_opt;

        let scan_report = self.interpret_tx_receipts(message, logger);

        let retry_opt = scan_report.requires_payments_retry();

        self.process_txs_by_state(scan_report, logger);

        self.mark_as_ended(logger);

        Self::compose_scan_result(retry_opt, response_skeleton_opt)
    }

    time_marking_methods!(PendingPayables);

    as_any_ref_in_trait_impl!();

    as_any_mut_in_trait_impl!();
}

impl PendingPayableScanner {
    pub fn new(
        payable_dao: Box<dyn PayableDao>,
        sent_payable_dao: Box<dyn SentPayableDao>,
        failed_payable_dao: Box<dyn FailedPayableDao>,
        payment_thresholds: Rc<PaymentThresholds>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        Self {
            common: ScannerCommon::new(payment_thresholds),
            payable_dao,
            sent_payable_dao,
            failed_payable_dao,
            financial_statistics,
            current_sent_payables: Box::new(CurrentPendingPayables::default()),
            yet_unproven_failed_payables: Box::new(RecheckRequiringFailures::default()),
        }
    }

    fn handle_pending_payables(&mut self) -> Option<Vec<TxHashByTable>> {
        let pending_txs = self
            .sent_payable_dao
            .retrieve_txs(Some(RetrieveCondition::IsPending));

        if !pending_txs.is_empty() {
            let pending_tx_hashes =
                Self::get_wrapped_hashes(&pending_txs, TxHashByTable::SentPayable);

            if !pending_txs.is_empty() {
                self.current_sent_payables.load_cache(pending_txs)
            }

            Some(pending_tx_hashes)
        } else {
            None
        }
    }

    fn handle_unproven_failures(&mut self) -> Option<Vec<TxHashByTable>> {
        let failures = self
            .failed_payable_dao
            .retrieve_txs(Some(FailureRetrieveCondition::EveryRecheckRequiredRecord));

        if !failures.is_empty() {
            let failure_hashes = Self::get_wrapped_hashes(&failures, TxHashByTable::FailedPayable);

            if !failures.is_empty() {
                self.yet_unproven_failed_payables.load_cache(failures)
            }

            Some(failure_hashes)
        } else {
            None
        }
    }

    fn get_wrapped_hashes<Record>(
        records: &[Record],
        wrap_the_hash: fn(TxHash) -> TxHashByTable,
    ) -> Vec<TxHashByTable>
    where
        Record: TxRecordWithHash,
    {
        records
            .iter()
            .map(|record| wrap_the_hash(record.hash()))
            .collect_vec()
    }

    fn emptiness_check(&self, msg: &TxReceiptsMessage) {
        if msg.results.is_empty() {
            unreachable!("We should never receive an empty list of results. Even missing receipts can be interpreted")
        }
    }

    fn compose_scan_result(
        retry_opt: Option<Retry>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> PendingPayableScanResult {
        if let Some(retry) = retry_opt {
            PendingPayableScanResult::PaymentRetryRequired(retry)
        } else {
            let ui_msg_opt = response_skeleton_opt.map(|response_skeleton| NodeToUiMessage {
                target: MessageTarget::ClientId(response_skeleton.client_id),
                body: UiScanResponse {}.tmb(response_skeleton.context_id),
            });
            PendingPayableScanResult::NoPendingPayablesLeft(ui_msg_opt)
        }
    }

    fn interpret_tx_receipts(
        &mut self,
        msg: TxReceiptsMessage,
        logger: &Logger,
    ) -> ReceiptScanReport {
        self.emptiness_check(&msg);

        debug!(logger, "Processing receipts for {} txs", msg.results.len());

        let interpretable_data = self.prepare_cases_to_interpret(msg, logger);
        TxReceiptInterpreter::default().compose_receipt_scan_report(
            interpretable_data,
            &self,
            logger,
        )
    }

    fn prepare_cases_to_interpret(
        &mut self,
        msg: TxReceiptsMessage,
        logger: &Logger,
    ) -> Vec<TxCaseToBeInterpreted> {
        let init: Either<Vec<TxCaseToBeInterpreted>, MismatchReport> = Either::Left(vec![]);
        let either = msg
            .results
            .into_iter()
            .fold(init, |acc, receipt_result| match acc {
                Either::Left(cases) => {
                    let tx_hash = receipt_result.hash();

                    self.resolve_real_query(cases, receipt_result, tx_hash)
                }
                Either::Right(mut mismatch_report) => {
                    mismatch_report.remaining_hashes.push(receipt_result.hash());
                    Either::Right(mismatch_report)
                }
            });

        let cases = match either {
            Either::Left(cases) => cases,
            Either::Right(mismatch_report) => self.panic_dump(mismatch_report),
        };

        self.current_sent_payables.ensure_empty_cache(logger);
        self.yet_unproven_failed_payables.ensure_empty_cache(logger);

        cases
    }

    fn resolve_real_query(
        &mut self,
        mut cases: Vec<TxCaseToBeInterpreted>,
        receipt_result: TxReceiptResult,
        looked_up_hash: TxHashByTable,
    ) -> Either<Vec<TxCaseToBeInterpreted>, MismatchReport> {
        match looked_up_hash {
            TxHashByTable::SentPayable(tx_hash) => {
                match self.current_sent_payables.get_record_by_hash(tx_hash) {
                    Some(sent_tx) => {
                        cases.push(TxCaseToBeInterpreted::new(
                            TxByTable::SentPayable(sent_tx),
                            receipt_result,
                        ));
                        Either::Left(cases)
                    }
                    None => Either::Right(MismatchReport {
                        noticed_at: looked_up_hash,
                        remaining_hashes: vec![],
                    }),
                }
            }
            TxHashByTable::FailedPayable(tx_hash) => {
                match self
                    .yet_unproven_failed_payables
                    .get_record_by_hash(tx_hash)
                {
                    Some(failed_tx) => {
                        cases.push(TxCaseToBeInterpreted::new(
                            TxByTable::FailedPayable(failed_tx),
                            receipt_result,
                        ));
                        Either::Left(cases)
                    }
                    None => Either::Right(MismatchReport {
                        noticed_at: looked_up_hash,
                        remaining_hashes: vec![],
                    }),
                }
            }
        }
    }

    fn panic_dump(&mut self, mismatch_report: MismatchReport) -> ! {
        fn rearrange<Record>(hashmap: HashMap<TxHash, Record>) -> Vec<Record> {
            hashmap
                .into_iter()
                .sorted_by_key(|(tx_hash, _)| *tx_hash)
                .map(|(_, record)| record)
                .collect_vec()
        }

        panic!(
            "Looking up '{:?}' in the cache, the record could not be found. Dumping \
            the remaining values. Pending payables: {:?}. Unproven failures: {:?}. \
            All yet-to-look-up hashes: {:?}.",
            mismatch_report.noticed_at,
            rearrange(self.current_sent_payables.dump_cache()),
            rearrange(self.yet_unproven_failed_payables.dump_cache()),
            mismatch_report.remaining_hashes
        )
    }

    fn process_txs_by_state(&mut self, scan_report: ReceiptScanReport, logger: &Logger) {
        self.handle_confirmed_transactions(scan_report.confirmations, logger);
        self.handle_failed_transactions(scan_report.failures, logger);
    }

    fn handle_confirmed_transactions(
        &mut self,
        confirmed_txs: DetectedConfirmations,
        logger: &Logger,
    ) {
        self.handle_tx_failure_reclaims(confirmed_txs.reclaims, logger);
        self.handle_normal_confirmations(confirmed_txs.normal_confirmations, logger);
    }

    fn handle_tx_failure_reclaims(&self, reclaimed: Vec<TxReclaim>, logger: &Logger) {
        if reclaimed.is_empty() {
            return;
        }

        todo!()
    }

    fn handle_normal_confirmations(
        &self,
        confirmed_txs: Vec<NormalTxConfirmation>,
        logger: &Logger,
    ) {
        if confirmed_txs.is_empty() {
            return;
        }

        todo!()
        // if !confirmed_txs.is_empty() {
        //     if let Err(e) = self.payable_dao.transactions_confirmed(&confirmed_txs) {
        //         Self::transaction_confirmed_panic(&confirmed_txs, e)
        //     } else {
        //         self.add_to_the_total_of_paid_payable(&confirmed_txs, logger);
        //
        //         let tx_confirmations = Self::compose_tx_confirmation_inputs(&confirmed_txs);
        //
        //         if let Err(e) = self.sent_payable_dao.confirm_tx(&tx_confirmations) {
        //             Self::update_tx_blocks_panic(&tx_confirmations, e)
        //         } else {
        //             Self::log_tx_success(logger, &tx_confirmations);
        //         }
        //     }
        // }
    }

    fn compose_tx_confirmation_inputs(
        confirmed_txs: &[SentTx],
    ) -> HashMap<TxHash, TransactionBlock> {
        todo!()
    }

    fn transaction_confirmed_panic(confirmed_txs: &[SentTx], e: PayableDaoError) -> ! {
        let wallets = confirmed_txs
            .iter()
            .map(|tx| tx.receiver_address)
            .collect_vec();
        panic!(
            "Unable to complete the tx confirmation by the adjustment of the payable accounts {} \
            due to {:?}",
            comma_joined_stringifiable(&wallets, |wallet| format!("{:?}", wallet)),
            e
        )
    }

    fn update_tx_blocks_panic(
        tx_hashes_and_tx_blocks: &HashMap<TxHash, TransactionBlock>,
        e: SentPayableDaoError,
    ) -> ! {
        panic!(
            "Unable to update sent payable records {} by their tx blocks due to {:?}",
            comma_joined_stringifiable(
                &tx_hashes_and_tx_blocks.keys().sorted().collect_vec(),
                |tx_hash| format!("{:?}", tx_hash)
            ),
            e
        )
    }

    fn log_tx_success(
        logger: &Logger,
        tx_hashes_and_tx_blocks: &HashMap<TxHash, TransactionBlock>,
    ) {
        logger.info(|| {
            let pretty_pairs = tx_hashes_and_tx_blocks
                .iter()
                .sorted()
                .map(|(hash, tx_confirmation)| {
                    format!("{:?} (block {})", hash, tx_confirmation.block_number)
                })
                .join(", ");
            match tx_hashes_and_tx_blocks.len() {
                1 => format!("Tx {} has been confirmed", pretty_pairs),
                _ => format!("Txs {} have been confirmed", pretty_pairs),
            }
        });
    }

    fn add_to_the_total_of_paid_payable(&mut self, confirmed_payments: &[SentTx], logger: &Logger) {
        let to_be_added: u128 = confirmed_payments
            .iter()
            .map(|sent_tx| sent_tx.amount_minor)
            .sum();

        let total_paid_payable = &mut self
            .financial_statistics
            .borrow_mut()
            .total_paid_payable_wei;

        *total_paid_payable += to_be_added;

        debug!(
            logger,
            "The total paid payables increased by {} to {} wei",
            to_be_added.separate_with_commas(),
            total_paid_payable.separate_with_commas()
        );
    }

    fn handle_failed_transactions(&self, failures: DetectedFailures, logger: &Logger) {
        self.handle_tx_failures(failures.tx_failures, logger);
        self.handle_rpc_failures(failures.tx_receipt_rpc_failures, logger);
    }

    fn handle_tx_failures(&self, failures: Vec<PresortedTxFailure>, logger: &Logger) {
        #[derive(Default)]
        struct GroupedFailures {
            new_failures: Vec<FailedTx>,
            rechecks_completed: Vec<TxHash>,
        }

        let grouped_failures =
            failures
                .into_iter()
                .fold(GroupedFailures::default(), |mut acc, failure| {
                    match failure {
                        PresortedTxFailure::NewEntry(failed_tx) => {
                            acc.new_failures.push(failed_tx);
                        }
                        PresortedTxFailure::RecheckCompleted(hash) => {
                            todo!()
                        }
                    }
                    acc
                });

        self.add_new_failures(grouped_failures.new_failures, logger);
        self.finalize_unproven_failures(grouped_failures.rechecks_completed, logger);
    }

    fn add_new_failures(&self, new_failures: Vec<FailedTx>, logger: &Logger) {
        fn prepare_hashset(failures: &[FailedTx]) -> HashSet<TxHash> {
            failures.iter().map(|failure| failure.hash).collect()
        }
        fn log_procedure_finished(logger: &Logger, new_failures: &[FailedTx]) {
            info!(
                logger,
                "Failed txs {} were processed in the db",
                comma_joined_stringifiable(new_failures, |failure| format!("{:?}", failure.hash))
            )
        }

        if new_failures.is_empty() {
            return;
        }

        if let Err(e) = self.failed_payable_dao.insert_new_records(&new_failures) {
            panic!(
                "Unable to persist failed txs {} due to {:?}",
                comma_joined_stringifiable(&new_failures, |failure| format!("{:?}", failure.hash)),
                e
            )
        }

        match self
            .sent_payable_dao
            .delete_records(&prepare_hashset(&new_failures))
        {
            Ok(_) => {
                log_procedure_finished(logger, &new_failures);
            }
            Err(e) => {
                panic!(
                    "Unable to purge sent payable records for failed txs {} due to {:?}",
                    comma_joined_stringifiable(&new_failures, |failure| format!(
                        "{:?}",
                        failure.hash
                    )),
                    e
                )
            }
        }
    }

    fn finalize_unproven_failures(&self, rechecks_completed: Vec<TxHash>, logger: &Logger) {
        if rechecks_completed.is_empty() {
            return;
        }

        todo!()
    }

    fn handle_rpc_failures(&self, failures: Vec<FailedValidationByTable>, logger: &Logger) {
        if failures.is_empty() {
            return;
        }

        let (sent_payable_failures, failed_payable_failures): (
            Vec<FailedValidation<TxStatus>>,
            Vec<FailedValidation<FailureStatus>>,
        ) = failures.into_iter().partition_map(|failure| match failure {
            FailedValidationByTable::SentPayable(failed_validation) => {
                Either::Left(failed_validation)
            }
            FailedValidationByTable::FailedPayable(failed_validation) => {
                Either::Right(failed_validation)
            }
        });

        self.update_validation_status_for_sent_txs(sent_payable_failures, logger);

        self.update_validation_status_for_failed_txs(failed_payable_failures, logger);
    }

    fn update_validation_status_for_sent_txs(
        &self,
        sent_payable_failures: Vec<FailedValidation<TxStatus>>,
        logger: &Logger,
    ) {
        if !sent_payable_failures.is_empty() {
            let updatable = Self::prepare_statuses_for_update(&sent_payable_failures, logger);
            if !updatable.is_empty() {
                match self.sent_payable_dao.update_statuses(&updatable) {
                    Ok(_) => {
                        info!(
                            logger,
                            "Pending-tx statuses were processed in the db for validation \
                        failure of txs {}",
                            comma_joined_stringifiable(&sent_payable_failures, |failure| {
                                format!("{:?}", failure.tx_hash)
                            })
                        )
                    }
                    Err(e) => {
                        panic!(
                            "Unable to update pending-tx statuses for validation failures '{:?}' \
                        due to {:?}",
                            sent_payable_failures, e
                        )
                    }
                }
            }
        }
    }

    fn update_validation_status_for_failed_txs(
        &self,
        failed_txs_validation_failures: Vec<FailedValidation<FailureStatus>>,
        logger: &Logger,
    ) {
        if !failed_txs_validation_failures.is_empty() {
            let updatable =
                Self::prepare_statuses_for_update(&failed_txs_validation_failures, logger);
            if !updatable.is_empty() {
                match self.failed_payable_dao.update_statuses(&updatable) {
                    Ok(_) => {
                        info!(
                            logger,
                            "Failed-tx statuses were processed in the db for validation \
                        failure of txs {}",
                            comma_joined_stringifiable(
                                &failed_txs_validation_failures,
                                |failure| { format!("{:?}", failure.tx_hash) }
                            )
                        )
                    }
                    Err(e) => {
                        panic!(
                            "Unable to update failed-tx statuses for validation failures '{:?}' \
                        due to {:?}",
                            failed_txs_validation_failures, e
                        )
                    }
                }
            }
        }
    }

    fn prepare_statuses_for_update<Status: UpdatableValidationStatus + Display>(
        failures: &[FailedValidation<Status>],
        logger: &Logger,
    ) -> HashMap<TxHash, Status> {
        failures
            .iter()
            .flat_map(|failure| {
                failure
                    .new_status()
                    .map(|tx_status| (failure.tx_hash, tx_status))
                    .or_else(|| {
                        debug!(
                            logger,
                            "{}",
                            PendingPayableScanner::status_not_updatable_log_msg(
                                &failure.current_status
                            )
                        );
                        None
                    })
            })
            .collect()
    }

    fn status_not_updatable_log_msg(status: &dyn Display) -> String {
        format!(
            "Handling a validation failure, but the status {} cannot be updated.",
            status
        )
    }

    fn log_records_found_for_receipt_check(
        pending_tx_hashes_opt: Option<&Vec<TxHashByTable>>,
        failure_hashes_opt: Option<&Vec<TxHashByTable>>,
        logger: &Logger,
    ) {
        fn resolve_optional_vec(vec_opt: Option<&Vec<TxHashByTable>>) -> usize {
            vec_opt.map(|hashes| hashes.len()).unwrap_or_default()
        }

        debug!(
            logger,
            "Found {} pending payables and {} unfinalized failures to be checked",
            resolve_optional_vec(pending_tx_hashes_opt),
            resolve_optional_vec(failure_hashes_opt)
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDaoError, FailedTx, FailureReason, FailureRetrieveCondition, FailureStatus,
        ValidationStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::PayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::{
        Detection, RetrieveCondition, SentPayableDaoError, SentTx, TxStatus,
    };
    use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp};
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
        FailedValidationByTable, NormalTxConfirmation, PendingPayableCache,
        PendingPayableScanResult, PresortedTxFailure, ReceiptScanReport, RecheckRequiringFailures,
        Retry, TxByTable, TxHashByTable, TxReclaim,
    };
    use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
    use crate::accountant::scanners::test_utils::PendingPayableCacheMock;
    use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
    use crate::accountant::test_utils::{
        make_failed_tx, make_sent_tx, make_transaction_block, FailedPayableDaoMock, PayableDaoMock,
        PendingPayableScannerBuilder, SentPayableDaoMock,
    };
    use crate::accountant::{RequestTransactionReceipts, TxReceiptsMessage};
    use crate::blockchain::blockchain_interface::data_structures::{
        RetrievedTxStatus, StatusReadFromReceiptCheck, TransactionBlock, TxReceiptError,
        TxReceiptResult,
    };
    use crate::blockchain::errors::{AppRpcError, LocalError, RemoteError};
    use crate::blockchain::test_utils::{make_block_hash, make_tx_hash};
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use regex::Regex;
    use std::fmt::format;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn start_scan_fills_in_caches_and_returns_msg() {
        let sent_tx_1 = make_sent_tx(456);
        let sent_tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(789);
        let sent_tx_hash_2 = sent_tx_2.hash;
        let failed_tx_1 = make_failed_tx(567);
        let failed_tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(890);
        let failed_tx_hash_2 = failed_tx_2.hash;
        let sent_payable_dao = SentPayableDaoMock::new()
            .retrieve_txs_result(vec![sent_tx_1.clone(), sent_tx_2.clone()]);
        let failed_payable_dao = FailedPayableDaoMock::new()
            .retrieve_txs_result(vec![failed_tx_1.clone(), failed_tx_2.clone()]);
        let mut subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let logger = Logger::new("start_scan_fills_in_caches_and_returns_msg");
        subject.current_sent_payables = Box::new(CurrentPendingPayables::default());
        subject.yet_unproven_failed_payables = Box::new(RecheckRequiringFailures::default());
        let pending_payable_cache_before = subject.current_sent_payables.dump_cache();
        let failed_payable_cache_before = subject.yet_unproven_failed_payables.dump_cache();

        let result = subject.start_scan(&make_wallet("bluh"), SystemTime::now(), None, &logger);

        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                tx_hashes: vec![
                    TxHashByTable::SentPayable(sent_tx_hash_1),
                    TxHashByTable::SentPayable(sent_tx_hash_2),
                    TxHashByTable::FailedPayable(failed_tx_hash_1),
                    TxHashByTable::FailedPayable(failed_tx_hash_2)
                ],
                response_skeleton_opt: None
            })
        );
        assert!(
            pending_payable_cache_before.is_empty(),
            "Should have been empty but {:?}",
            pending_payable_cache_before
        );
        assert!(
            failed_payable_cache_before.is_empty(),
            "Should have been empty but {:?}",
            failed_payable_cache_before
        );
        let pending_payable_cache_after = subject.current_sent_payables.dump_cache();
        let failed_payable_cache_after = subject.yet_unproven_failed_payables.dump_cache();
        assert_eq!(
            pending_payable_cache_after,
            hashmap!(sent_tx_hash_1 => sent_tx_1, sent_tx_hash_2 => sent_tx_2)
        );
        assert_eq!(
            failed_payable_cache_after,
            hashmap!(failed_tx_hash_1 => failed_tx_1, failed_tx_hash_2 => failed_tx_2)
        );
    }

    #[test]
    fn finish_scan_operates_caches_and_clear_them_after_use() {
        let pending_payable_ensure_empty_cache_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_ensure_empty_cache_params_arc = Arc::new(Mutex::new(vec![]));
        // To confirm a fresh, pending tx
        let confirm_tx_params_arc = Arc::new(Mutex::new(vec![]));
        // To reclaim a confirmed tx believed having been a failure
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        // To register a failed tx as it's pending too long
        let insert_new_failed_records_params_arc = Arc::new(Mutex::new(vec![]));
        // To update the validation status at a tx whose receipt couldn't be fetched
        let update_statuses_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_tx_1 = make_sent_tx(456);
        let sent_tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(789);
        let sent_tx_hash_2 = sent_tx_2.hash;
        let failed_tx_1 = make_failed_tx(567);
        let failed_tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(890);
        let failed_tx_hash_2 = failed_tx_2.hash;
        let sent_payable_dao = SentPayableDaoMock::new()
            .confirm_tx_params(&confirm_tx_params_arc)
            .replace_records_params(&replace_records_params_arc);
        let failed_payable_dao = FailedPayableDaoMock::new()
            .insert_new_records_params(&insert_new_failed_records_params_arc)
            .update_statuses_params(&update_statuses_params_arc);
        let pending_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_result(Some(sent_tx_1.clone()))
            .get_record_by_hash_result(Some(sent_tx_2))
            .ensure_empty_cache_params(&pending_payable_ensure_empty_cache_params_arc);
        let failed_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_result(Some(failed_tx_1))
            .get_record_by_hash_result(Some(failed_tx_2))
            .ensure_empty_cache_params(&failed_payable_ensure_empty_cache_params_arc);
        let mut subject = PendingPayableScannerBuilder::new()
            .pending_payables_cache(Box::new(pending_payable_cache))
            .failed_payables_cache(Box::new(failed_payable_cache))
            .build();
        let logger = Logger::new("test");
        let confirmed_tx_block_sent_tx = make_transaction_block(901);
        let confirmed_tx_block_failed_tx = make_transaction_block(902);
        let msg = TxReceiptsMessage {
            results: vec![
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_1),
                    StatusReadFromReceiptCheck::Pending,
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(confirmed_tx_block_sent_tx),
                ))),
                TxReceiptResult(Err(TxReceiptError::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_1),
                    AppRpcError::Local(LocalError::Internal),
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(confirmed_tx_block_failed_tx),
                ))),
            ],
            response_skeleton_opt: None,
        };

        let result = subject.finish_scan(msg, &logger);

        assert_eq!(
            result,
            PendingPayableScanResult::PaymentRetryRequired(Retry::RetryPayments)
        );
        assert!(
            subject.current_sent_payables.dump_cache().is_empty(),
            "Sent payable cache should have been emptied but {:?}",
            subject.current_sent_payables.dump_cache()
        );
        assert!(
            subject.yet_unproven_failed_payables.dump_cache().is_empty(),
            "Failed payable cache Should have been emptied but {:?}",
            subject.yet_unproven_failed_payables.dump_cache()
        );
        let pending_payable_ensure_empty_cache_params =
            pending_payable_ensure_empty_cache_params_arc
                .lock()
                .unwrap();
        assert_eq!(*pending_payable_ensure_empty_cache_params, vec![()]);
        let failed_payable_ensure_empty_cache_params =
            failed_payable_ensure_empty_cache_params_arc.lock().unwrap();
        assert_eq!(*failed_payable_ensure_empty_cache_params, vec![()]);
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(
            *confirm_tx_params,
            vec![hashmap!(sent_tx_hash_1 => confirmed_tx_block_sent_tx)]
        );
        let insert_new_failed_records_params = insert_new_failed_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_failed_records_params,
            vec![vec![FailedTx::from((
                sent_tx_1,
                FailureReason::PendingTooLong
            ))]]
        );
        let update_statuses_params = update_statuses_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_params,
            vec![
                hashmap!(failed_tx_hash_1 => FailureStatus::RecheckRequired(ValidationStatus::Reattempting { attempt: 1, error: AppRpcError::Local(LocalError::Internal)}))
            ]
        );
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(*replace_records_params, vec![vec![]]);
    }

    #[test]
    fn finish_scan_with_missing_records_inside_caches_noticed_on_missing_sent_tx() {
        let sent_tx_1 = make_sent_tx(456);
        let sent_tx_hash_1 = sent_tx_1.hash;
        let sent_tx_hash_2 = make_tx_hash(777);
        let failed_tx_1 = make_failed_tx(567);
        let failed_tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(890);
        let failed_tx_hash_2 = failed_tx_2.hash;
        let mut pending_payable_cache = CurrentPendingPayables::default();
        pending_payable_cache.load_cache(vec![sent_tx_1]);
        let mut failed_payable_cache = RecheckRequiringFailures::default();
        failed_payable_cache.load_cache(vec![failed_tx_1, failed_tx_2]);
        let mut subject = PendingPayableScannerBuilder::new().build();
        subject.current_sent_payables = Box::new(pending_payable_cache);
        subject.yet_unproven_failed_payables = Box::new(failed_payable_cache);
        let logger = Logger::new("test");
        let msg = TxReceiptsMessage {
            results: vec![
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_1),
                    StatusReadFromReceiptCheck::Pending,
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(make_transaction_block(444)),
                ))),
                TxReceiptResult(Err(TxReceiptError::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_1),
                    AppRpcError::Local(LocalError::Internal),
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(make_transaction_block(555)),
                ))),
            ],
            response_skeleton_opt: None,
        };

        let panic =
            catch_unwind(AssertUnwindSafe(|| subject.finish_scan(msg, &logger))).unwrap_err();

        let panic_msg = panic.downcast_ref::<String>().unwrap();
        let regex_str_in_pieces = vec![
            r#"Looking up 'SentPayable\(0x0000000000000000000000000000000000000000000000000000000000000309\)'"#,
            r#" in the cache, the record could not be found. Dumping the remaining values. Pending payables: \[\]."#,
            r#" Unproven failures: \[FailedTx \{"#,
            r#" hash: 0x0000000000000000000000000000000000000000000000000000000000000237, receiver_address:"#,
            r#" 0x000000000000000000000077616c6c6574353637, amount_minor: 321489000000000, timestamp: \d*,"#,
            r#" gas_price_minor: 567000000000, nonce: 567, reason: PendingTooLong, status: RetryRequired \},"#,
            r#" FailedTx \{ hash:"#,
            r#" 0x000000000000000000000000000000000000000000000000000000000000037a, receiver_address:"#,
            r#" 0x000000000000000000000077616c6c6574383930, amount_minor: 792100000000000, timestamp: \d*,"#,
            r#" gas_price_minor: 890000000000, nonce: 890, reason: PendingTooLong, status: RetryRequired \}\]."#,
            r#" All yet-to-look-up hashes: \[FailedPayable\(0x000000000000000000000000000000000000000000000000000"#,
            r#"0000000000237\), FailedPayable\(0x000000000000000000000000000000000000000000000000000000000000037a\)\]."#,
        ];
        let regex_str = regex_str_in_pieces.join("");
        let expected_msg_regex = Regex::new(&regex_str).unwrap();
        assert!(
            expected_msg_regex.is_match(panic_msg),
            "Expected string that matches this regex '{}' but it couldn't with '{}'",
            regex_str,
            panic_msg
        );
    }

    #[test]
    fn finish_scan_with_missing_records_inside_caches_noticed_on_missing_failed_tx() {
        let sent_tx_1 = make_sent_tx(456);
        let sent_tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(789);
        let sent_tx_hash_2 = sent_tx_2.hash;
        let failed_tx_1 = make_failed_tx(567);
        let failed_tx_hash_1 = failed_tx_1.hash;
        let failed_tx_hash_2 = make_tx_hash(901);
        let mut pending_payable_cache = CurrentPendingPayables::default();
        pending_payable_cache.load_cache(vec![sent_tx_1, sent_tx_2]);
        let mut failed_payable_cache = RecheckRequiringFailures::default();
        failed_payable_cache.load_cache(vec![failed_tx_1]);
        let mut subject = PendingPayableScannerBuilder::new().build();
        subject.current_sent_payables = Box::new(pending_payable_cache);
        subject.yet_unproven_failed_payables = Box::new(failed_payable_cache);
        let logger = Logger::new("test");
        let msg = TxReceiptsMessage {
            results: vec![
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_1),
                    StatusReadFromReceiptCheck::Pending,
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::SentPayable(sent_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(make_transaction_block(444)),
                ))),
                TxReceiptResult(Err(TxReceiptError::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_1),
                    AppRpcError::Local(LocalError::Internal),
                ))),
                TxReceiptResult(Ok(RetrievedTxStatus::new(
                    TxHashByTable::FailedPayable(failed_tx_hash_2),
                    StatusReadFromReceiptCheck::Succeeded(make_transaction_block(555)),
                ))),
            ],
            response_skeleton_opt: None,
        };

        let panic =
            catch_unwind(AssertUnwindSafe(|| subject.finish_scan(msg, &logger))).unwrap_err();

        let panic_msg = panic.downcast_ref::<String>().unwrap();
        let regex_str_in_pieces = vec![
            r#"Looking up 'FailedPayable\(0x0000000000000000000000000000000000000000000000000000000000000385\)'"#,
            r#" in the cache, the record could not be found. Dumping the remaining values. Pending payables: \[\]."#,
            r#" Unproven failures: \[\]. All yet-to-look-up hashes: \[\]."#,
        ];
        let regex_str = regex_str_in_pieces.join("");
        let expected_msg_regex = Regex::new(&regex_str).unwrap();
        assert!(
            expected_msg_regex.is_match(panic_msg),
            "Expected string that matches this regex '{}' but it couldn't with '{}'",
            regex_str,
            panic_msg
        );
    }

    #[test]
    fn throws_an_error_when_no_records_to_process_were_found() {
        let now = SystemTime::now();
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let sent_payable_dao = SentPayableDaoMock::new().retrieve_txs_result(vec![]);
        let failed_payable_dao = FailedPayableDaoMock::new().retrieve_txs_result(vec![]);
        let mut subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();

        let result = subject.start_scan(&consuming_wallet, now, None, &Logger::new("test"));

        let is_scan_running = subject.scan_started_at().is_some();
        assert_eq!(result, Err(StartScanError::NothingToProcess));
        assert_eq!(is_scan_running, false);
    }

    #[test]
    fn handle_failed_transactions_can_process_standard_tx_failures() {
        init_test_logging();
        let test_name = "handle_failed_transactions_can_process_standard_tx_failures";
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1.clone()),
                PresortedTxFailure::NewEntry(failed_tx_2.clone()),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new(test_name));

        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_records_params,
            vec![vec![failed_tx_1, failed_tx_2]]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![hash_1, hash_2]]);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Failed txs 0x0000000000000000000000000000000000000000000000000000000000000321, \
            0x0000000000000000000000000000000000000000000000000000000000000654 were processed in the db"
        ));
    }

    #[test]
    fn handle_failed_transactions_can_process_receipt_retrieval_rpc_failures() {
        init_test_logging();
        let test_name = "handle_failed_transactions_can_process_receipt_retrieval_rpc_failures";
        let retrieve_failed_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let update_statuses_sent_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_sent_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let update_statuses_failed_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let hash_3 = make_tx_hash(0x987);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        failed_tx_1.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        failed_tx_2.status = FailureStatus::RecheckRequired(ValidationStatus::Reattempting {
            attempt: 1,
            error: AppRpcError::Local(LocalError::Internal),
        });
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_failed_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1, failed_tx_2])
            .update_statuses_params(&update_statuses_sent_tx_params_arc)
            .update_statuses_result(Ok(()));
        let mut sent_tx = make_sent_tx(789);
        sent_tx.hash = hash_3;
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);
        let sent_payable_dao = SentPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_sent_txs_params_arc)
            .retrieve_txs_result(vec![sent_tx.clone()])
            .update_statuses_params(&update_statuses_failed_tx_params_arc)
            .update_statuses_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    hash_1,
                    AppRpcError::Remote(RemoteError::Unreachable),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                )),
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    hash_2,
                    AppRpcError::Local(LocalError::Internal),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting {
                        attempt: 1,
                        error: AppRpcError::Local(LocalError::Internal),
                    }),
                )),
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    hash_3,
                    AppRpcError::Remote(RemoteError::InvalidResponse("Booga".to_string())),
                    TxStatus::Pending(ValidationStatus::Waiting),
                )),
            ],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new(test_name));

        let update_statuses_sent_tx_params = update_statuses_sent_tx_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_sent_tx_params,
            vec![hashmap!(
                hash_1 => FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting {
                        attempt: 1,
                        error: AppRpcError::Remote(RemoteError::Unreachable)
                    }
                ),
                hash_2 => FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting {
                        attempt: 2,
                        error: AppRpcError::Local(LocalError::Internal)
                    }
                )
            )]
        );
        let update_statuses_failed_tx_params = update_statuses_failed_tx_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_failed_tx_params,
            vec![
                hashmap![hash_3 => TxStatus::Pending(ValidationStatus::Reattempting {
                    attempt: 1,
                    error: AppRpcError::Remote(RemoteError::InvalidResponse("Booga".to_string())),
                })]
            ]
        );
        let test_log_handler = TestLogHandler::new();
        test_log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Pending-tx statuses were processed in the db for validation failure \
            of txs 0x0000000000000000000000000000000000000000000000000000000000000987"
        ));
        test_log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Failed-tx statuses were processed in the db for validation failure \
            of txs 0x0000000000000000000000000000000000000000000000000000000000000321, \
            0x0000000000000000000000000000000000000000000000000000000000000654"
        ));
        let expectedly_missing_log_msg_fragment = "Handling a validation failure, but the status";
        let otherwise_possible_log_msg =
            PendingPayableScanner::status_not_updatable_log_msg(&"Something");
        assert!(
            otherwise_possible_log_msg.contains(expectedly_missing_log_msg_fragment),
            "We expected to select a true log fragment '{}', but it is not included in '{}'",
            expectedly_missing_log_msg_fragment,
            otherwise_possible_log_msg
        );
        test_log_handler.exists_no_log_containing(&format!(
            "DEBUG: {test_name}: {}",
            expectedly_missing_log_msg_fragment
        ))
    }

    #[test]
    fn handle_rpc_failures_when_requested_for_a_status_which_cannot_be_updated() {
        init_test_logging();
        let test_name = "handle_rpc_failures_when_requested_for_a_status_which_cannot_be_updated";
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let subject = PendingPayableScannerBuilder::new().build();

        subject.handle_rpc_failures(
            vec![
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    hash_1,
                    AppRpcError::Remote(RemoteError::Unreachable),
                    FailureStatus::RetryRequired,
                )),
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    hash_2,
                    AppRpcError::Remote(RemoteError::InvalidResponse("Booga".to_string())),
                    TxStatus::Confirmed {
                        block_hash: "abc".to_string(),
                        block_number: 0,
                        detection: Detection::Normal,
                    },
                )),
            ],
            &Logger::new(test_name),
        );

        let test_log_handler = TestLogHandler::new();
        test_log_handler.exists_no_log_containing(&format!("INFO: {test_name}: "));
        test_log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Handling a validation failure, but the status \
            {{\"Confirmed\":{{\"block_hash\":\"abc\",\"block_number\":0,\"detection\":\"Normal\"}}}} \
            cannot be updated.",
        ));
        test_log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Handling a validation failure, but the status \"RetryRequired\" \
            cannot be updated."
        ));
        // It didn't panic, which means none of the DAO methods was called because the DAOs are
        // mocked in this test
    }

    #[test]
    #[should_panic(
        expected = "Unable to update pending-tx statuses for validation failures \
    '[FailedValidation { tx_hash: 0x00000000000000000000000000000000000000000000000000000000000001c8, \
    validation_failure: Local(Internal), current_status: Pending(Waiting) }]' due to \
    InvalidInput(\"bluh\")"
    )]
    fn update_validation_status_for_sent_txs_panics_on_update_statuses() {
        let failed_validation = FailedValidation::new(
            make_tx_hash(456),
            AppRpcError::Local(LocalError::Internal),
            TxStatus::Pending(ValidationStatus::Waiting),
        );
        let sent_payable_dao = SentPayableDaoMock::default()
            .update_statuses_result(Err(SentPayableDaoError::InvalidInput("bluh".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();

        let _ = subject
            .update_validation_status_for_sent_txs(vec![failed_validation], &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Unable to update failed-tx statuses for validation failures \
    '[FailedValidation { tx_hash: 0x00000000000000000000000000000000000000000000000000000000000001c8, \
    validation_failure: Local(Internal), current_status: RecheckRequired(Waiting) }]' due to \
    InvalidInput(\"bluh\")"
    )]
    fn update_validation_status_for_failed_txs_panics_on_update_statuses() {
        let failed_validation = FailedValidation::new(
            make_tx_hash(456),
            AppRpcError::Local(LocalError::Internal),
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        );
        let failed_payable_dao = FailedPayableDaoMock::default()
            .update_statuses_result(Err(FailedPayableDaoError::InvalidInput("bluh".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();

        let _ = subject
            .update_validation_status_for_failed_txs(vec![failed_validation], &Logger::new("test"));
    }

    #[test]
    fn handle_failed_transactions_can_process_mixed_failures() {
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let retrieve_failed_txs_params_arc = Arc::new(Mutex::new(vec![]));
        let update_status_params_arc = Arc::new(Mutex::new(vec![]));
        let hash_1 = make_tx_hash(0x321);
        let hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_failed_txs_params_arc)
            .retrieve_txs_result(vec![failed_tx_1.clone()])
            .update_statuses_params(&update_status_params_arc)
            .update_statuses_result(Ok(()))
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![PresortedTxFailure::NewEntry(failed_tx_1)],
            tx_receipt_rpc_failures: vec![FailedValidationByTable::SentPayable(
                FailedValidation::new(
                    hash_1,
                    AppRpcError::Local(LocalError::Internal),
                    TxStatus::Pending(ValidationStatus::Waiting),
                ),
            )],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let retrieve_failed_txs_params = retrieve_failed_txs_params_arc.lock().unwrap();
        assert_eq!(
            *retrieve_failed_txs_params,
            vec![Some(FailureRetrieveCondition::ByTxHash(vec![
                hash_1, hash_2
            ]))]
        );
        let update_status_params = update_status_params_arc.lock().unwrap();
        assert_eq!(
            *update_status_params,
            vec![
                hashmap!(hash_1 => FailureStatus::RecheckRequired(ValidationStatus::Reattempting {attempt: 1,error: AppRpcError::Local(LocalError::Internal)}))
            ]
        );
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(*insert_new_records_params, vec![vec![failed_tx_2]]);
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![hash_2]]);
    }

    #[test]
    #[should_panic(expected = "Unable to persist failed txs \
        0x000000000000000000000000000000000000000000000000000000000000014d, \
        0x00000000000000000000000000000000000000000000000000000000000001bc due to NoChange")]
    fn handle_failed_transactions_panics_when_it_fails_to_insert_failed_tx_record() {
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_result(Err(FailedPayableDaoError::NoChange));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x14d);
        let hash_2 = make_tx_hash(0x1bc);
        let mut failed_tx_1 = make_failed_tx(789);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1),
                PresortedTxFailure::NewEntry(failed_tx_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));
    }

    #[test]
    #[should_panic(expected = "Unable to purge sent payable records for failed txs \
        0x000000000000000000000000000000000000000000000000000000000000014d, \
        0x00000000000000000000000000000000000000000000000000000000000001bc due to \
        InvalidInput(\"Booga\")")]
    fn handle_failed_transactions_panics_when_it_fails_to_delete_obsolete_sent_tx_records() {
        let failed_payable_dao = FailedPayableDaoMock::default().insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .delete_records_result(Err(SentPayableDaoError::InvalidInput("Booga".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let hash_1 = make_tx_hash(0x14d);
        let hash_2 = make_tx_hash(0x1bc);
        let mut failed_tx_1 = make_failed_tx(789);
        failed_tx_1.hash = hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::NewEntry(failed_tx_1),
                PresortedTxFailure::NewEntry(failed_tx_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));
    }

    #[test]
    fn handle_failed_transactions_does_nothing_if_no_failure_detected() {
        let subject = PendingPayableScannerBuilder::new().build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"))

        //mocked pending payable DAO didn't panic which means we skipped the actual process
    }

    #[test]
    #[should_panic(
        expected = "Unable to update sent payable records 0x000000000000000000000000000000000000000\
        000000000000000000000021a, 0x0000000000000000000000000000000000000000000000000000000000000315 \
        by their tx blocks due to SqlExecutionFailed(\"The database manager is \
        a funny guy, he's fooling around with us\")"
    )]
    fn handle_confirmed_transactions_panics_while_updating_sent_payable_records_with_the_tx_blocks()
    {
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().confirm_tx_result(Err(
            SentPayableDaoError::SqlExecutionFailed(
                "The database manager is a funny guy, he's fooling around with us".to_string(),
            ),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let mut sent_tx_1 = make_sent_tx(456);
        let block = make_transaction_block(678);
        sent_tx_1.hash = make_tx_hash(0x315);
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", block.block_hash),
            block_number: block.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(789);
        sent_tx_2.hash = make_tx_hash(0x21a);
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", block.block_hash),
            block_number: block.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation { tx: sent_tx_1 },
                    NormalTxConfirmation { tx: sent_tx_2 },
                ],
                reclaims: vec![],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    fn handle_confirmed_transactions_does_nothing_if_no_confirmation_found_on_the_blockchain() {
        let mut subject = PendingPayableScannerBuilder::new().build();

        subject
            .handle_confirmed_transactions(DetectedConfirmations::default(), &Logger::new("test"))

        // Mocked payable DAO didn't panic, which means we skipped the actual process
    }

    #[test]
    fn handle_confirmed_transactions_works() {
        init_test_logging();
        let test_name = "handle_confirmed_transactions_works";
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let confirm_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .confirm_tx_params(&confirm_tx_params_arc)
            .confirm_tx_result(Ok(()))
            .replace_records_params(&replace_records_params_arc)
            .replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let logger = Logger::new(test_name);
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let tx_hash_3 = make_tx_hash(0x913);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TransactionBlock {
            block_hash: make_block_hash(45),
            block_number: 4_578_989_878_u64.into(),
        };
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_1.block_hash),
            block_number: tx_block_1.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(987_987);
        sent_tx_2.hash = tx_hash_2;
        let tx_block_2 = TransactionBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_3 = make_sent_tx(567_567);
        sent_tx_3.hash = tx_hash_3;
        let tx_block_3 = TransactionBlock {
            block_hash: make_block_hash(78),
            block_number: 7_898_989_878_u64.into(),
        };
        sent_tx_3.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_3.block_hash),
            block_number: tx_block_3.block_number.as_u64(),
            detection: Detection::Reclaim,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation {
                        tx: sent_tx_1.clone(),
                    },
                    NormalTxConfirmation {
                        tx: sent_tx_2.clone(),
                    },
                ],
                reclaims: vec![TxReclaim {
                    reclaimed: sent_tx_3.clone(),
                }],
            },
            &logger,
        );

        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transactions_confirmed_params,
            vec![vec![sent_tx_1, sent_tx_2, sent_tx_3.clone()]]
        );
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(
            *confirm_tx_params,
            vec![hashmap![tx_hash_1 => tx_block_1, tx_hash_2 => tx_block_2]]
        );
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(*replace_records_params, vec![vec![sent_tx_3]]);
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![hashset![tx_hash_3]]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 4578989878), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 7898989878), txxxxbluh (block bluh) have been confirmed",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unable to complete the tx confirmation by the adjustment of the payable accounts \
        0x000000000000000000000077616c6c6574343536 due to \
        RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirmed_transactions_panics_on_unchecking_payable_table() {
        let hash = make_tx_hash(0x315);
        let rowid = 3;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Err(
            PayableDaoError::RusqliteError("record change not successful".to_string()),
        ));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        let mut sent_tx = make_sent_tx(456);
        sent_tx.hash = hash;

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![NormalTxConfirmation { tx: sent_tx }],
                reclaims: vec![],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    fn log_tx_success_is_agnostic_to_singular_or_plural_form() {
        init_test_logging();
        let test_name = "log_tx_success_is_agnostic_to_singular_or_plural_form";
        let plural_case_name = format!("{}_testing_plural_case", test_name);
        let singular_case_name = format!("{}_testing_singular_case", test_name);
        let logger_plural = Logger::new(&plural_case_name);
        let logger_singular = Logger::new(&singular_case_name);
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut tx_block_1 = make_transaction_block(456);
        tx_block_1.block_number = 1_234_501_u64.into();
        let mut tx_block_2 = make_transaction_block(789);
        tx_block_2.block_number = 1_234_502_u64.into();
        let mut tx_hashes_and_blocks = hashmap!(tx_hash_1 => tx_block_1, tx_hash_2 => tx_block_2);

        PendingPayableScanner::log_tx_success(&logger_plural, &tx_hashes_and_blocks);

        tx_hashes_and_blocks.remove(&tx_hash_2);

        PendingPayableScanner::log_tx_success(&logger_singular, &tx_hashes_and_blocks);

        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {plural_case_name}: Txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 1234501), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 1234502) have been confirmed",
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {singular_case_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 1234501) has been confirmed",
        ));
    }

    #[test]
    fn total_paid_payable_rises_with_each_bill_paid() {
        init_test_logging();
        let test_name = "total_paid_payable_rises_with_each_bill_paid";
        let mut sent_tx_1 = make_sent_tx(456);
        sent_tx_1.amount_minor = 5478;
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: 89898,
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(789);
        sent_tx_2.amount_minor = 3344;
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(234)),
            block_number: 66312,
            detection: Detection::Normal,
        };
        let mut sent_tx_3 = make_sent_tx(789);
        sent_tx_3.amount_minor = 6543;
        sent_tx_3.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(321)),
            block_number: 67676,
            detection: Detection::Reclaim,
        };
        let payable_dao = PayableDaoMock::default().transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default().confirm_tx_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable_wei += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![
                    NormalTxConfirmation { tx: sent_tx_1 },
                    NormalTxConfirmation { tx: sent_tx_2 },
                ],
                reclaims: vec![TxReclaim {
                    reclaimed: sent_tx_3,
                }],
            },
            &Logger::new(test_name),
        );

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable_wei;
        assert_eq!(total_paid_payable, 1111 + 5478 + 3344 + 6543);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: The total paid payables increased by blouuh to bluuuuuh wei"
        ));
    }
}
