// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod test_utils;
mod tx_receipt_interpreter;
pub mod utils;

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedPayableDao, FailedTx, FailureRetrieveCondition, FailureStatus,
};
use crate::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoError};
use crate::accountant::db_access_objects::sent_payable_dao::{
    RetrieveCondition, SentPayableDao, SentPayableDaoError, SentTx, TxStatus,
};
use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::db_access_objects::Transaction;
use crate::accountant::scanners::pending_payable_scanner::tx_receipt_interpreter::TxReceiptInterpreter;
use crate::accountant::scanners::pending_payable_scanner::utils::{
    CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
    FailedValidationByTable, MismatchReport, PendingPayableCache, PendingPayableScanResult,
    PresortedTxFailure, ReceiptScanReport, RecheckRequiringFailures, Retry, TxByTable,
    TxCaseToBeInterpreted, TxHashByTable, UpdatableValidationStatus,
};
use crate::accountant::scanners::{
    PrivateScanner, Scanner, ScannerCommon, StartScanError, StartableScanner,
};
use crate::accountant::{
    comma_joined_stringifiable, RequestTransactionReceipts, ResponseSkeleton,
    ScanForPendingPayables, TxReceiptResult, TxReceiptsMessage,
};
use crate::blockchain::blockchain_interface::data_structures::TxBlock;
use crate::blockchain::errors::validation_status::{
    ValidationFailureClock, ValidationFailureClockReal,
};
use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::time_marking_methods;
use itertools::{Either, Itertools};
use masq_lib::logger::Logger;
use masq_lib::messages::{ScanType, ToMessageBody, UiScanResponse};
use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Display;
use std::rc::Rc;
use std::str::FromStr;
use std::time::SystemTime;
use thousands::Separable;
use web3::types::H256;

pub struct PendingPayableScanner {
    pub common: ScannerCommon,
    pub payable_dao: Box<dyn PayableDao>,
    pub sent_payable_dao: Box<dyn SentPayableDao>,
    pub failed_payable_dao: Box<dyn FailedPayableDao>,
    pub financial_statistics: Rc<RefCell<FinancialStatistics>>,
    pub current_sent_payables: Box<dyn PendingPayableCache<SentTx>>,
    pub yet_unproven_failed_payables: Box<dyn PendingPayableCache<FailedTx>>,
    pub clock: Box<dyn ValidationFailureClock>,
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
            clock: Box::new(ValidationFailureClockReal::default()),
        }
    }

    fn handle_pending_payables(&mut self) -> Option<Vec<TxHashByTable>> {
        let pending_txs = self
            .sent_payable_dao
            .retrieve_txs(Some(RetrieveCondition::IsPending));

        if pending_txs.is_empty() {
            return None;
        }

        let pending_txs_vec: Vec<SentTx> = pending_txs.into_iter().collect();

        let pending_tx_hashes =
            Self::get_wrapped_hashes(&pending_txs_vec, TxHashByTable::SentPayable);
        self.current_sent_payables.load_cache(pending_txs_vec);
        Some(pending_tx_hashes)
    }

    fn handle_unproven_failures(&mut self) -> Option<Vec<TxHashByTable>> {
        let failures = self
            .failed_payable_dao
            .retrieve_txs(Some(FailureRetrieveCondition::EveryRecheckRequiredRecord));

        if failures.is_empty() {
            return None;
        }

        let failures_vec: Vec<FailedTx> = failures.into_iter().collect();

        let failure_hashes = Self::get_wrapped_hashes(&failures_vec, TxHashByTable::FailedPayable);
        self.yet_unproven_failed_payables.load_cache(failures_vec);
        Some(failure_hashes)
    }

    fn get_wrapped_hashes<Record>(
        records: &[Record],
        wrap_the_hash: fn(TxHash) -> TxHashByTable,
    ) -> Vec<TxHashByTable>
    where
        Record: Transaction,
    {
        records
            .iter()
            .map(|record| wrap_the_hash(record.hash()))
            .collect_vec()
    }

    fn emptiness_check(&self, msg: &TxReceiptsMessage) {
        if msg.results.is_empty() {
            panic!(
                "We should never receive an empty list of results. \
                Even receipts that could not be retrieved can be interpreted"
            )
        }
    }

    fn compose_scan_result(
        retry_opt: Option<Retry>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> PendingPayableScanResult {
        if let Some(retry) = retry_opt {
            if let Some(response_skeleton) = response_skeleton_opt {
                let ui_msg = NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                };
                PendingPayableScanResult::PaymentRetryRequired(Either::Right(ui_msg))
            } else {
                PendingPayableScanResult::PaymentRetryRequired(Either::Left(retry))
            }
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
            // This must be in for predictability in tests
            .sorted_by_key(|(hash_by_table, _)| hash_by_table.hash())
            .fold(
                init,
                |acc, (tx_hash_by_table, tx_receipt_result)| match acc {
                    Either::Left(cases) => {
                        self.resolve_real_query(cases, tx_receipt_result, tx_hash_by_table)
                    }
                    Either::Right(mut mismatch_report) => {
                        mismatch_report.remaining_hashes.push(tx_hash_by_table);
                        Either::Right(mismatch_report)
                    }
                },
            );

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
                        noticed_with: looked_up_hash,
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
                        noticed_with: looked_up_hash,
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
            Hashes yet not looked up: {:?}.",
            mismatch_report.noticed_with,
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

    fn handle_tx_failure_reclaims(&mut self, reclaimed: Vec<SentTx>, logger: &Logger) {
        if reclaimed.is_empty() {
            return;
        }

        let hashes_and_blocks = Self::collect_and_sort_hashes_and_blocks(&reclaimed);

        self.replace_sent_tx_records(&reclaimed, &hashes_and_blocks, logger);

        self.delete_failed_tx_records(&hashes_and_blocks, logger);

        self.add_to_the_total_of_paid_payable(&reclaimed, logger)
    }

    fn isolate_hashes(reclaimed: &[(TxHash, TxBlock)]) -> BTreeSet<TxHash> {
        reclaimed.iter().map(|(tx_hash, _)| *tx_hash).collect()
    }

    fn collect_and_sort_hashes_and_blocks(sent_txs: &[SentTx]) -> Vec<(TxHash, TxBlock)> {
        Self::collect_hashes_and_blocks(sent_txs)
            .into_iter()
            .sorted()
            .collect_vec()
    }

    fn collect_hashes_and_blocks(reclaimed: &[SentTx]) -> HashMap<TxHash, TxBlock> {
        reclaimed
            .iter()
            .map(|reclaim| {
                let tx_block = if let TxStatus::Confirmed { block_hash, block_number, .. } =
                    &reclaim.status
                {
                    TxBlock{
                        block_hash: H256::from_str(&block_hash[2..]).expect("Failed to construct hash from str"),
                        block_number: (*block_number).into()
                    }
                } else {
                    panic!(
                        "Processing a reclaim for tx {:?} which isn't filled with the confirmation details",
                        reclaim.hash
                    )
                };
                (reclaim.hash, tx_block)
            })
            .collect()
    }

    fn replace_sent_tx_records(
        &self,
        sent_txs_to_reclaim: &[SentTx],
        hashes_and_blocks: &[(TxHash, TxBlock)],
        logger: &Logger,
    ) {
        let btreeset: BTreeSet<SentTx> = sent_txs_to_reclaim.iter().cloned().collect();

        match self.sent_payable_dao.replace_records(&btreeset) {
            Ok(_) => {
                debug!(logger, "Replaced records for txs being reclaimed")
            }
            Err(e) => {
                panic!(
                    "Unable to proceed in a reclaim as the replacement of sent tx records \
                {} failed due to: {:?}",
                    comma_joined_stringifiable(hashes_and_blocks, |(tx_hash, _)| {
                        format!("{:?}", tx_hash)
                    }),
                    e
                )
            }
        }
    }

    fn delete_failed_tx_records(&self, hashes_and_blocks: &[(TxHash, TxBlock)], logger: &Logger) {
        let hashes = Self::isolate_hashes(hashes_and_blocks);
        match self.failed_payable_dao.delete_records(&hashes.into()) {
            Ok(_) => {
                info!(
                    logger,
                    "Reclaimed txs {} as confirmed on-chain",
                    comma_joined_stringifiable(hashes_and_blocks, |(tx_hash, tx_block)| {
                        format!("{:?} (block {})", tx_hash, tx_block.block_number)
                    })
                )
            }
            Err(e) => {
                panic!(
                    "Unable to delete failed tx records {} to finish the reclaims due to: {:?}",
                    comma_joined_stringifiable(hashes_and_blocks, |(tx_hash, _)| {
                        format!("{:?}", tx_hash)
                    }),
                    e
                )
            }
        }
    }

    fn handle_normal_confirmations(&mut self, confirmed_txs: Vec<SentTx>, logger: &Logger) {
        if confirmed_txs.is_empty() {
            return;
        }

        self.confirm_transactions(&confirmed_txs);

        self.update_tx_blocks(&confirmed_txs, logger);

        self.add_to_the_total_of_paid_payable(&confirmed_txs, logger);
    }

    fn confirm_transactions(&self, confirmed_sent_txs: &[SentTx]) {
        if let Err(e) = self.payable_dao.transactions_confirmed(confirmed_sent_txs) {
            Self::transaction_confirmed_panic(confirmed_sent_txs, e);
        }
    }

    fn update_tx_blocks(&self, confirmed_sent_txs: &[SentTx], logger: &Logger) {
        let tx_confirmations = Self::collect_hashes_and_blocks(confirmed_sent_txs);

        if let Err(e) = self.sent_payable_dao.confirm_txs(&tx_confirmations) {
            Self::update_tx_blocks_panic(&tx_confirmations, e);
        } else {
            Self::log_tx_success(logger, &tx_confirmations);
        }
    }

    fn log_tx_success(logger: &Logger, tx_hashes_and_tx_blocks: &HashMap<TxHash, TxBlock>) {
        logger.info(|| {
            let pretty_pairs = tx_hashes_and_tx_blocks
                .iter()
                .sorted()
                .map(|(hash, tx_confirmation)| {
                    format!("{:?} (block {})", hash, tx_confirmation.block_number)
                })
                .join(", ");
            match tx_hashes_and_tx_blocks.len() {
                1 => format!("Tx {} was confirmed", pretty_pairs),
                _ => format!("Txs {} were confirmed", pretty_pairs),
            }
        });
    }

    fn transaction_confirmed_panic(confirmed_txs: &[SentTx], e: PayableDaoError) -> ! {
        panic!(
            "Unable to complete the tx confirmation by the adjustment of the payable accounts \
            {} due to: {:?}",
            comma_joined_stringifiable(
                &confirmed_txs
                    .iter()
                    .map(|tx| tx.receiver_address)
                    .collect_vec(),
                |wallet| format!("{:?}", wallet)
            ),
            e
        )
    }
    fn update_tx_blocks_panic(
        tx_hashes_and_tx_blocks: &HashMap<TxHash, TxBlock>,
        e: SentPayableDaoError,
    ) -> ! {
        panic!(
            "Unable to update sent payable records {} by their tx blocks due to: {:?}",
            comma_joined_stringifiable(
                &tx_hashes_and_tx_blocks.keys().sorted().collect_vec(),
                |tx_hash| format!("{:?}", tx_hash)
            ),
            e
        )
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
                        PresortedTxFailure::RecheckCompleted(tx_hash) => {
                            acc.rechecks_completed.push(tx_hash);
                        }
                    }
                    acc
                });

        self.add_new_failures(grouped_failures.new_failures, logger);
        self.finalize_unproven_failures(grouped_failures.rechecks_completed, logger);
    }

    fn add_new_failures(&self, new_failures: Vec<FailedTx>, logger: &Logger) {
        fn prepare_btreeset(failures: &[FailedTx]) -> BTreeSet<TxHash> {
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

        let new_failures_btree_set: BTreeSet<FailedTx> = new_failures.iter().cloned().collect();

        if let Err(e) = self
            .failed_payable_dao
            .insert_new_records(&new_failures_btree_set)
        {
            panic!(
                "Unable to persist failed txs {} due to: {:?}",
                comma_joined_stringifiable(&new_failures, |failure| format!("{:?}", failure.hash)),
                e
            )
        }

        match self
            .sent_payable_dao
            .delete_records(&prepare_btreeset(&new_failures))
        {
            Ok(_) => {
                log_procedure_finished(logger, &new_failures);
            }
            Err(e) => {
                panic!(
                    "Unable to purge sent payable records for failed txs {} due to: {:?}",
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
        fn prepare_hashmap(rechecks_completed: &[TxHash]) -> HashMap<TxHash, FailureStatus> {
            rechecks_completed
                .iter()
                .map(|tx_hash| (tx_hash.clone(), FailureStatus::Concluded))
                .collect()
        }

        if rechecks_completed.is_empty() {
            return;
        }

        match self
            .failed_payable_dao
            .update_statuses(&prepare_hashmap(&rechecks_completed))
        {
            Ok(_) => {
                debug!(
                    logger,
                    "Concluded failures that had required rechecks: {}.",
                    comma_joined_stringifiable(&rechecks_completed, |tx_hash| format!(
                        "{:?}",
                        tx_hash
                    ))
                );
            }
            Err(e) => {
                panic!(
                    "Unable to conclude rechecks for failed txs {} due to: {:?}",
                    comma_joined_stringifiable(&rechecks_completed, |tx_hash| format!(
                        "{:?}",
                        tx_hash
                    )),
                    e
                )
            }
        }
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
            let updatable =
                Self::prepare_statuses_for_update(&sent_payable_failures, &*self.clock, logger);
            if !updatable.is_empty() {
                match self.sent_payable_dao.update_statuses(&updatable) {
                    Ok(_) => {
                        info!(
                            logger,
                            "Pending-tx statuses were processed in the db for validation failure \
                            of txs {}",
                            comma_joined_stringifiable(&sent_payable_failures, |failure| {
                                format!("{:?}", failure.tx_hash)
                            })
                        )
                    }
                    Err(e) => {
                        panic!(
                            "Unable to update pending-tx statuses for validation failures '{:?}' \
                        due to: {:?}",
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
            let updatable = Self::prepare_statuses_for_update(
                &failed_txs_validation_failures,
                &*self.clock,
                logger,
            );
            if !updatable.is_empty() {
                match self.failed_payable_dao.update_statuses(&updatable) {
                    Ok(_) => {
                        info!(
                            logger,
                            "Failed-tx statuses were processed in the db for validation failure \
                            of txs {}",
                            comma_joined_stringifiable(
                                &failed_txs_validation_failures,
                                |failure| { format!("{:?}", failure.tx_hash) }
                            )
                        )
                    }
                    Err(e) => {
                        panic!(
                            "Unable to update failed-tx statuses for validation failures '{:?}' \
                        due to: {:?}",
                            failed_txs_validation_failures, e
                        )
                    }
                }
            }
        }
    }

    fn prepare_statuses_for_update<Status: UpdatableValidationStatus + Display>(
        failures: &[FailedValidation<Status>],
        clock: &dyn ValidationFailureClock,
        logger: &Logger,
    ) -> HashMap<TxHash, Status> {
        failures
            .iter()
            .flat_map(|failure| {
                failure
                    .new_status(clock)
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
            "Found {} pending payables and {} unfinalized failures to process",
            resolve_optional_vec(pending_tx_hashes_opt),
            resolve_optional_vec(failure_hashes_opt)
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedPayableDaoError, FailureStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::PayableDaoError;
    use crate::accountant::db_access_objects::sent_payable_dao::{
        Detection, SentPayableDaoError, TxStatus,
    };
    use crate::accountant::db_access_objects::test_utils::{make_failed_tx, make_sent_tx};
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, DetectedConfirmations, DetectedFailures, FailedValidation,
        FailedValidationByTable, PendingPayableCache, PendingPayableScanResult, PresortedTxFailure,
        RecheckRequiringFailures, Retry, TxHashByTable,
    };
    use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
    use crate::accountant::scanners::test_utils::PendingPayableCacheMock;
    use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
    use crate::accountant::test_utils::{
        make_transaction_block, FailedPayableDaoMock, PayableDaoMock, PendingPayableScannerBuilder,
        SentPayableDaoMock,
    };
    use crate::accountant::{RequestTransactionReceipts, TxReceiptsMessage};
    use crate::blockchain::blockchain_interface::data_structures::{
        StatusReadFromReceiptCheck, TxBlock,
    };
    use crate::blockchain::errors::rpc_errors::{
        AppRpcError, AppRpcErrorKind, LocalError, LocalErrorKind, RemoteErrorKind,
    };
    use crate::blockchain::errors::validation_status::{
        PreviousAttempts, ValidationFailureClockReal, ValidationStatus,
    };
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::{make_block_hash, make_tx_hash};
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use itertools::{Either, Itertools};
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use regex::Regex;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

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
            .retrieve_txs_result(btreeset![sent_tx_1.clone(), sent_tx_2.clone()]);
        let failed_payable_dao = FailedPayableDaoMock::new()
            .retrieve_txs_result(btreeset![failed_tx_1.clone(), failed_tx_2.clone()]);
        let mut subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_cache(Box::new(CurrentPendingPayables::default()))
            .failed_payable_cache(Box::new(RecheckRequiringFailures::default()))
            .build();
        let logger = Logger::new("start_scan_fills_in_caches_and_returns_msg");
        let pending_payable_cache_before = subject.current_sent_payables.dump_cache();
        let failed_payable_cache_before = subject.yet_unproven_failed_payables.dump_cache();

        let result = subject.start_scan(&make_wallet("blah"), SystemTime::now(), None, &logger);

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
    fn finish_scan_operates_caches_and_clears_them_after_use() {
        let get_record_by_hash_failed_payable_cache_params_arc = Arc::new(Mutex::new(vec![]));
        let get_record_by_hash_sent_payable_cache_params_arc = Arc::new(Mutex::new(vec![]));
        let ensure_empty_cache_failed_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let ensure_empty_cache_sent_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_tx_1 = make_sent_tx(456);
        let sent_tx_hash_1 = sent_tx_1.hash;
        let sent_tx_2 = make_sent_tx(789);
        let sent_tx_hash_2 = sent_tx_2.hash;
        let failed_tx_1 = make_failed_tx(567);
        let failed_tx_hash_1 = failed_tx_1.hash;
        let failed_tx_2 = make_failed_tx(890);
        let failed_tx_hash_2 = failed_tx_2.hash;
        let payable_dao = PayableDaoMock::new().transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::new()
            .confirm_tx_result(Ok(()))
            .replace_records_result(Ok(()))
            .delete_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::new()
            .insert_new_records_result(Ok(()))
            .delete_records_result(Ok(()));
        let sent_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_params(&get_record_by_hash_sent_payable_cache_params_arc)
            .get_record_by_hash_result(Some(sent_tx_1.clone()))
            .get_record_by_hash_result(Some(sent_tx_2))
            .ensure_empty_cache_params(&ensure_empty_cache_sent_payable_params_arc);
        let failed_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_params(&get_record_by_hash_failed_payable_cache_params_arc)
            .get_record_by_hash_result(Some(failed_tx_1))
            .get_record_by_hash_result(Some(failed_tx_2))
            .ensure_empty_cache_params(&ensure_empty_cache_failed_payable_params_arc);
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_cache(Box::new(sent_payable_cache))
            .failed_payable_cache(Box::new(failed_payable_cache))
            .build();
        let logger = Logger::new("test");
        let confirmed_tx_block_sent_tx = make_transaction_block(901);
        let confirmed_tx_block_failed_tx = make_transaction_block(902);
        let msg = TxReceiptsMessage {
            results: hashmap![
                TxHashByTable::SentPayable(sent_tx_hash_1) => Ok(StatusReadFromReceiptCheck::Pending),
                TxHashByTable::SentPayable(sent_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(confirmed_tx_block_sent_tx)),
                TxHashByTable::FailedPayable(failed_tx_hash_1) => Err(AppRpcError::Local(LocalError::Internal)),
                TxHashByTable::FailedPayable(failed_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(confirmed_tx_block_failed_tx))
            ],
            response_skeleton_opt: None,
        };

        let result = subject.finish_scan(msg, &logger);

        assert_eq!(
            result,
            PendingPayableScanResult::PaymentRetryRequired(Either::Left(Retry::RetryPayments))
        );
        let get_record_by_hash_failed_payable_cache_params =
            get_record_by_hash_failed_payable_cache_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *get_record_by_hash_failed_payable_cache_params,
            vec![failed_tx_hash_1, failed_tx_hash_2]
        );
        let get_record_by_hash_sent_payable_cache_params =
            get_record_by_hash_sent_payable_cache_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *get_record_by_hash_sent_payable_cache_params,
            vec![sent_tx_hash_1, sent_tx_hash_2]
        );
        let pending_payable_ensure_empty_cache_params =
            ensure_empty_cache_sent_payable_params_arc.lock().unwrap();
        assert_eq!(*pending_payable_ensure_empty_cache_params, vec![()]);
        let failed_payable_ensure_empty_cache_params =
            ensure_empty_cache_failed_payable_params_arc.lock().unwrap();
        assert_eq!(*failed_payable_ensure_empty_cache_params, vec![()]);
    }

    #[test]
    fn finish_scan_with_missing_records_inside_caches_noticed_on_missing_sent_tx() {
        // Note: the ordering of the hashes matters in this test
        let sent_tx_hash_1 = make_tx_hash(0x123);
        let mut sent_tx_1 = make_sent_tx(456);
        sent_tx_1.hash = sent_tx_hash_1;
        let sent_tx_hash_2 = make_tx_hash(0x876);
        let failed_tx_hash_1 = make_tx_hash(0x987);
        let mut failed_tx_1 = make_failed_tx(567);
        failed_tx_1.hash = failed_tx_hash_1;
        let failed_tx_hash_2 = make_tx_hash(0x789);
        let mut failed_tx_2 = make_failed_tx(890);
        failed_tx_2.hash = failed_tx_hash_2;
        let mut pending_payable_cache = CurrentPendingPayables::default();
        pending_payable_cache.load_cache(vec![sent_tx_1]);
        let mut failed_payable_cache = RecheckRequiringFailures::default();
        failed_payable_cache.load_cache(vec![failed_tx_1, failed_tx_2]);
        let mut subject = PendingPayableScannerBuilder::new().build();
        subject.current_sent_payables = Box::new(pending_payable_cache);
        subject.yet_unproven_failed_payables = Box::new(failed_payable_cache);
        let logger = Logger::new("test");
        let msg = TxReceiptsMessage {
            results: hashmap![TxHashByTable::SentPayable(sent_tx_hash_1) => Ok(
                    StatusReadFromReceiptCheck::Pending),
                TxHashByTable::SentPayable(sent_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(make_transaction_block(444))),
                TxHashByTable::FailedPayable(failed_tx_hash_1) => Err(AppRpcError::Local(LocalError::Internal)),
                TxHashByTable::FailedPayable(failed_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(make_transaction_block(555))),
            ],
            response_skeleton_opt: None,
        };

        let panic =
            catch_unwind(AssertUnwindSafe(|| subject.finish_scan(msg, &logger))).unwrap_err();

        let panic_msg = panic.downcast_ref::<String>().unwrap();
        let regex_str_in_pieces = vec![
            r#"Looking up 'SentPayable\(0x0000000000000000000000000000000000000000000000000000000000000876\)'"#,
            r#" in the cache, the record could not be found. Dumping the remaining values. Pending payables: \[\]."#,
            r#" Unproven failures: \[FailedTx \{ hash:"#,
            r#" 0x0000000000000000000000000000000000000000000000000000000000000987, receiver_address:"#,
            r#" 0x000000000000000000000077616c6c6574353637, amount_minor: 321489000000000, timestamp: \d*,"#,
            r#" gas_price_minor: 567000000000, nonce: 567, reason: PendingTooLong, status: RetryRequired \}\]."#,
            r#" Hashes yet not looked up: \[FailedPayable\(0x000000000000000000000000000000000000000"#,
            r#"0000000000000000000000987\)\]"#,
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
            results: hashmap![TxHashByTable::SentPayable(sent_tx_hash_1) => Ok(StatusReadFromReceiptCheck::Pending),
                TxHashByTable::SentPayable(sent_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(make_transaction_block(444))),
                TxHashByTable::FailedPayable(failed_tx_hash_1) => Err(AppRpcError::Local(LocalError::Internal)),
                TxHashByTable::FailedPayable(failed_tx_hash_2) => Ok(StatusReadFromReceiptCheck::Succeeded(make_transaction_block(555))),
            ],
            response_skeleton_opt: None,
        };

        let panic =
            catch_unwind(AssertUnwindSafe(|| subject.finish_scan(msg, &logger))).unwrap_err();

        let panic_msg = panic.downcast_ref::<String>().unwrap();
        let regex_str_in_pieces = vec![
            r#"Looking up 'FailedPayable\(0x0000000000000000000000000000000000000000000000000000000000000385\)'"#,
            r#" in the cache, the record could not be found. Dumping the remaining values. Pending payables: \[\]."#,
            r#" Unproven failures: \[\]. Hashes yet not looked up: \[\]."#,
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
        let sent_payable_dao = SentPayableDaoMock::new().retrieve_txs_result(btreeset![]);
        let failed_payable_dao = FailedPayableDaoMock::new().retrieve_txs_result(btreeset![]);
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
    fn handle_failed_transactions_does_nothing_if_no_failure_detected() {
        let subject = PendingPayableScannerBuilder::new().build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"))

        // Mocked pending payable DAO without prepared results didn't panic which means none of its
        // methods was used in this test
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
            vec![btreeset![failed_tx_1, failed_tx_2]]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![btreeset![hash_1, hash_2]]);
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
        let timestamp_a = SystemTime::now();
        let timestamp_b = SystemTime::now().sub(Duration::from_secs(1));
        let timestamp_c = SystemTime::now().sub(Duration::from_secs(2));
        let timestamp_d = SystemTime::now().sub(Duration::from_secs(3));
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = hash_1;
        failed_tx_1.status = FailureStatus::RecheckRequired(ValidationStatus::Waiting);
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = hash_2;
        failed_tx_2.status =
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                &ValidationFailureClockMock::default().now_result(timestamp_a),
            )));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_failed_txs_params_arc)
            .retrieve_txs_result(btreeset![failed_tx_1, failed_tx_2])
            .update_statuses_params(&update_statuses_failed_tx_params_arc)
            .update_statuses_result(Ok(()));
        let mut sent_tx = make_sent_tx(789);
        sent_tx.hash = hash_3;
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);
        let sent_payable_dao = SentPayableDaoMock::default()
            .retrieve_txs_params(&retrieve_sent_txs_params_arc)
            .retrieve_txs_result(btreeset![sent_tx.clone()])
            .update_statuses_params(&update_statuses_sent_tx_params_arc)
            .update_statuses_result(Ok(()));
        let validation_failure_clock = ValidationFailureClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_b)
            .now_result(timestamp_c);
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .validation_failure_clock(Box::new(validation_failure_clock))
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![],
            tx_receipt_rpc_failures: vec![
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    hash_1,
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    FailureStatus::RecheckRequired(ValidationStatus::Waiting),
                )),
                FailedValidationByTable::FailedPayable(FailedValidation::new(
                    hash_2,
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    FailureStatus::RecheckRequired(ValidationStatus::Reattempting(
                        PreviousAttempts::new(
                            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                                LocalErrorKind::Internal,
                            )),
                            &ValidationFailureClockMock::default().now_result(timestamp_d),
                        ),
                    )),
                )),
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    hash_3,
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::InvalidResponse,
                    )),
                    TxStatus::Pending(ValidationStatus::Waiting),
                )),
            ],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new(test_name));

        let update_statuses_sent_tx_params = update_statuses_sent_tx_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_sent_tx_params,
            vec![
                hashmap![hash_3 => TxStatus::Pending(ValidationStatus::Reattempting (PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::InvalidResponse)), &ValidationFailureClockMock::default().now_result(timestamp_a))))]
            ]
        );
        let mut update_statuses_failed_tx_params =
            update_statuses_failed_tx_params_arc.lock().unwrap();
        let actual_params = update_statuses_failed_tx_params
            .remove(0)
            .into_iter()
            .sorted_by_key(|(key, _)| *key)
            .collect::<HashMap<_, _>>();
        let expected_params = hashmap!(
                hash_1 => FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)), &ValidationFailureClockMock::default().now_result(timestamp_b)))
                ),
                hash_2 => FailureStatus::RecheckRequired(
                    ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)), &ValidationFailureClockMock::default().now_result(timestamp_d)).add_attempt(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)), &ValidationFailureClockReal::default())))
            ).into_iter().sorted_by_key(|(key,_)|*key).collect::<HashMap<_, _>>();
        assert_eq!(actual_params, expected_params);
        assert!(
            update_statuses_failed_tx_params.is_empty(),
            "Should be empty but: {:?}",
            update_statuses_sent_tx_params
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
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::Unreachable,
                    )),
                    FailureStatus::RetryRequired,
                )),
                FailedValidationByTable::SentPayable(FailedValidation::new(
                    hash_2,
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(
                        RemoteErrorKind::InvalidResponse,
                    )),
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
        expected = "Unable to update pending-tx statuses for validation failures '[FailedValidation \
    { tx_hash: 0x00000000000000000000000000000000000000000000000000000000000001c8, validation_failure: \
    AppRpc(Local(Internal)), current_status: Pending(Waiting) }]' due to: InvalidInput(\"blah\")"
    )]
    fn update_validation_status_for_sent_txs_panics_on_update_statuses() {
        let failed_validation = FailedValidation::new(
            make_tx_hash(456),
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
            TxStatus::Pending(ValidationStatus::Waiting),
        );
        let sent_payable_dao = SentPayableDaoMock::default()
            .update_statuses_result(Err(SentPayableDaoError::InvalidInput("blah".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .validation_failure_clock(Box::new(ValidationFailureClockReal::default()))
            .build();

        let _ = subject
            .update_validation_status_for_sent_txs(vec![failed_validation], &Logger::new("test"));
    }

    #[test]
    #[should_panic(
        expected = "Unable to update failed-tx statuses for validation failures '[FailedValidation \
    { tx_hash: 0x00000000000000000000000000000000000000000000000000000000000001c8, validation_failure: \
    AppRpc(Local(Internal)), current_status: RecheckRequired(Waiting) }]' due to: InvalidInput(\"blah\")"
    )]
    fn update_validation_status_for_failed_txs_panics_on_update_statuses() {
        let failed_validation = FailedValidation::new(
            make_tx_hash(456),
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
            FailureStatus::RecheckRequired(ValidationStatus::Waiting),
        );
        let failed_payable_dao = FailedPayableDaoMock::default()
            .update_statuses_result(Err(FailedPayableDaoError::InvalidInput("blah".to_string())));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .validation_failure_clock(Box::new(ValidationFailureClockReal::default()))
            .build();

        let _ = subject
            .update_validation_status_for_failed_txs(vec![failed_validation], &Logger::new("test"));
    }

    #[test]
    fn handle_failed_transactions_can_process_mixed_failures() {
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let update_status_params_arc = Arc::new(Mutex::new(vec![]));
        let tx_hash_1 = make_tx_hash(0x321);
        let tx_hash_2 = make_tx_hash(0x654);
        let timestamp = SystemTime::now();
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = tx_hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = tx_hash_2;
        let failed_payable_dao = FailedPayableDaoMock::default()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .update_statuses_params(&update_status_params_arc)
            .update_statuses_result(Ok(()))
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .validation_failure_clock(Box::new(
                ValidationFailureClockMock::default().now_result(timestamp),
            ))
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![PresortedTxFailure::NewEntry(failed_tx_1.clone())],
            tx_receipt_rpc_failures: vec![FailedValidationByTable::SentPayable(
                FailedValidation::new(
                    tx_hash_2,
                    BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)),
                    TxStatus::Pending(ValidationStatus::Waiting),
                ),
            )],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        assert_eq!(
            *insert_new_records_params,
            vec![BTreeSet::from([failed_tx_1])]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        assert_eq!(*delete_records_params, vec![btreeset![tx_hash_1]]);
        let update_statuses_params = update_status_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_params,
            vec![
                hashmap!(tx_hash_2 => TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)), &ValidationFailureClockMock::default().now_result(timestamp)))))
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Unable to persist failed txs \
        0x000000000000000000000000000000000000000000000000000000000000014d, \
        0x00000000000000000000000000000000000000000000000000000000000001bc due to: NoChange")]
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
        0x00000000000000000000000000000000000000000000000000000000000001bc due to: \
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
    fn handle_failed_transactions_can_conclude_rechecked_failures() {
        let update_status_params_arc = Arc::new(Mutex::new(vec![]));
        let tx_hash_1 = make_tx_hash(0x321);
        let tx_hash_2 = make_tx_hash(0x654);
        let mut failed_tx_1 = make_failed_tx(123);
        failed_tx_1.hash = tx_hash_1;
        let mut failed_tx_2 = make_failed_tx(456);
        failed_tx_2.hash = tx_hash_2;
        let failed_payable_dao = FailedPayableDaoMock::default()
            .update_statuses_params(&update_status_params_arc)
            .update_statuses_result(Ok(()));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::RecheckCompleted(tx_hash_1),
                PresortedTxFailure::RecheckCompleted(tx_hash_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));

        let update_status_params = update_status_params_arc.lock().unwrap();
        assert_eq!(
            *update_status_params,
            vec![
                hashmap!(tx_hash_1 => FailureStatus::Concluded, tx_hash_2 => FailureStatus::Concluded),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Unable to conclude rechecks for failed txs \
    0x0000000000000000000000000000000000000000000000000000000000000321, \
    0x0000000000000000000000000000000000000000000000000000000000000654 due to: \
    InvalidInput(\"Booga\")")]
    fn concluding_rechecks_fails_on_updating_statuses() {
        let tx_hash_1 = make_tx_hash(0x321);
        let tx_hash_2 = make_tx_hash(0x654);
        let failed_payable_dao = FailedPayableDaoMock::default().update_statuses_result(Err(
            FailedPayableDaoError::InvalidInput("Booga".to_string()),
        ));
        let subject = PendingPayableScannerBuilder::new()
            .failed_payable_dao(failed_payable_dao)
            .build();
        let detected_failures = DetectedFailures {
            tx_failures: vec![
                PresortedTxFailure::RecheckCompleted(tx_hash_1),
                PresortedTxFailure::RecheckCompleted(tx_hash_2),
            ],
            tx_receipt_rpc_failures: vec![],
        };

        subject.handle_failed_transactions(detected_failures, &Logger::new("test"));
    }

    #[test]
    fn handle_confirmed_transactions_does_nothing_if_no_confirmation_found_on_the_blockchain() {
        let mut subject = PendingPayableScannerBuilder::new().build();

        subject
            .handle_confirmed_transactions(DetectedConfirmations::default(), &Logger::new("test"))

        // Mocked payable DAO without prepared results didn't panic, which means none of its methods
        // was used in this test
    }

    #[test]
    fn handles_failure_reclaims_alone() {
        init_test_logging();
        let test_name = "handles_failure_reclaims_alone";
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        let delete_records_params_arc = Arc::new(Mutex::new(vec![]));
        let sent_payable_dao = SentPayableDaoMock::default()
            .replace_records_params(&replace_records_params_arc)
            .replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .delete_records_params(&delete_records_params_arc)
            .delete_records_result(Ok(()));
        let logger = Logger::new(test_name);
        let mut subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
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
        let tx_block_2 = TxBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![sent_tx_1.clone(), sent_tx_2.clone()],
            },
            &logger,
        );

        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(
            *replace_records_params,
            vec![btreeset![sent_tx_1, sent_tx_2]]
        );
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        // assert_eq!(*delete_records_params, vec![hashset![tx_hash_1, tx_hash_2]]);
        assert_eq!(
            *delete_records_params,
            vec![BTreeSet::from([tx_hash_1, tx_hash_2])]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Reclaimed txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 4578989878), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 6789898789) as confirmed on-chain",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unable to proceed in a reclaim as the replacement of sent tx records \
    0x0000000000000000000000000000000000000000000000000000000000000123, \
    0x0000000000000000000000000000000000000000000000000000000000000567 \
    failed due to: NoChange"
    )]
    fn failure_reclaim_fails_on_replace_sent_tx_record() {
        let sent_payable_dao = SentPayableDaoMock::default()
            .replace_records_result(Err(SentPayableDaoError::NoChange));
        let mut subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
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
        let tx_block_2 = TxBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![sent_tx_1.clone(), sent_tx_2.clone()],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    #[should_panic(expected = "Unable to delete failed tx records \
    0x0000000000000000000000000000000000000000000000000000000000000123, \
    0x0000000000000000000000000000000000000000000000000000000000000567 \
    to finish the reclaims due to: EmptyInput")]
    fn failure_reclaim_fails_on_delete_failed_tx_record() {
        let sent_payable_dao = SentPayableDaoMock::default().replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default()
            .delete_records_result(Err(FailedPayableDaoError::EmptyInput));
        let mut subject = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
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
        let tx_block_2 = TxBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", make_block_hash(123)),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![sent_tx_1.clone(), sent_tx_2.clone()],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    #[should_panic(
        expected = "Processing a reclaim for tx 0x0000000000000000000000000000000000000000000000000\
        000000000000123 which isn't filled with the confirmation details"
    )]
    fn handle_failure_reclaim_meets_a_record_without_confirmation_details() {
        let mut subject = PendingPayableScannerBuilder::new().build();
        let tx_hash = make_tx_hash(0x123);
        let mut sent_tx = make_sent_tx(123_123);
        sent_tx.hash = tx_hash;
        // Here, it should be confirmed already in this status
        sent_tx.status = TxStatus::Pending(ValidationStatus::Waiting);

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![],
                reclaims: vec![sent_tx.clone()],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    fn handles_normal_confirmations_alone() {
        init_test_logging();
        let test_name = "handles_normal_confirmations_alone";
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let confirm_tx_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::default()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::default()
            .confirm_tx_params(&confirm_tx_params_arc)
            .confirm_tx_result(Ok(()));
        let logger = Logger::new(test_name);
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let tx_hash_1 = make_tx_hash(0x123);
        let tx_hash_2 = make_tx_hash(0x567);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
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
        let tx_block_2 = TxBlock {
            block_hash: make_block_hash(67),
            block_number: 6_789_898_789_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_2.block_hash),
            block_number: tx_block_2.block_number.as_u64(),
            detection: Detection::Normal,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![sent_tx_1.clone(), sent_tx_2.clone()],
                reclaims: vec![],
            },
            &logger,
        );

        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(
            *transactions_confirmed_params,
            vec![vec![sent_tx_1, sent_tx_2]]
        );
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(
            *confirm_tx_params,
            vec![hashmap![tx_hash_1 => tx_block_1, tx_hash_2 => tx_block_2]]
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Txs 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 4578989878), 0x0000000000000000000000000000000000000000000000000000000000000567 \
            (block 6789898789) were confirmed",
        ));
    }

    #[test]
    fn mixed_tx_confirmations_work() {
        init_test_logging();
        let test_name = "mixed_tx_confirmations_work";
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
        let tx_hash_2 = make_tx_hash(0x913);
        let mut sent_tx_1 = make_sent_tx(123_123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
            block_hash: make_block_hash(45),
            block_number: 4_578_989_878_u64.into(),
        };
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_1.block_hash),
            block_number: tx_block_1.block_number.as_u64(),
            detection: Detection::Normal,
        };
        let mut sent_tx_2 = make_sent_tx(567_567);
        sent_tx_2.hash = tx_hash_2;
        let tx_block_3 = TxBlock {
            block_hash: make_block_hash(78),
            block_number: 7_898_989_878_u64.into(),
        };
        sent_tx_2.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_3.block_hash),
            block_number: tx_block_3.block_number.as_u64(),
            detection: Detection::Reclaim,
        };

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![sent_tx_1.clone()],
                reclaims: vec![sent_tx_2.clone()],
            },
            &logger,
        );

        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        assert_eq!(*transactions_confirmed_params, vec![vec![sent_tx_1]]);
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(*confirm_tx_params, vec![hashmap![tx_hash_1 => tx_block_1]]);
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(*replace_records_params, vec![btreeset![sent_tx_2]]);
        let delete_records_params = delete_records_params_arc.lock().unwrap();
        // assert_eq!(*delete_records_params, vec![hashset![tx_hash_2]]);
        assert_eq!(*delete_records_params, vec![BTreeSet::from([tx_hash_2])]);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Reclaimed txs \
            0x0000000000000000000000000000000000000000000000000000000000000913 (block 7898989878) \
            as confirmed on-chain",
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {test_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 4578989878) was confirmed",
        ));
    }

    #[test]
    #[should_panic(
        expected = "Unable to update sent payable records 0x000000000000000000000000000000000000000\
        000000000000000000000021a, 0x0000000000000000000000000000000000000000000000000000000000000315 \
        by their tx blocks due to: SqlExecutionFailed(\"The database manager is \
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
                normal_confirmations: vec![sent_tx_1, sent_tx_2],
                reclaims: vec![],
            },
            &Logger::new("test"),
        );
    }

    #[test]
    #[should_panic(
        expected = "Unable to complete the tx confirmation by the adjustment of the payable accounts \
        0x000000000000000000000077616c6c6574343536 due to: \
        RusqliteError(\"record change not successful\")"
    )]
    fn handle_confirmed_transactions_panics_on_unchecking_payable_table() {
        let hash = make_tx_hash(0x315);
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
                normal_confirmations: vec![sent_tx],
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
            (block 1234502) were confirmed",
        ));
        log_handler.exists_log_containing(&format!(
            "INFO: {singular_case_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000123 \
            (block 1234501) was confirmed",
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
        let sent_payable_dao = SentPayableDaoMock::default()
            .confirm_tx_result(Ok(()))
            .replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::default().delete_records_result(Ok(()));
        let mut subject = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .build();
        let mut financial_statistics = subject.financial_statistics.borrow().clone();
        financial_statistics.total_paid_payable_wei += 1111;
        subject.financial_statistics.replace(financial_statistics);

        subject.handle_confirmed_transactions(
            DetectedConfirmations {
                normal_confirmations: vec![sent_tx_1, sent_tx_2],
                reclaims: vec![sent_tx_3],
            },
            &Logger::new(test_name),
        );

        let total_paid_payable = subject.financial_statistics.borrow().total_paid_payable_wei;
        assert_eq!(total_paid_payable, 1111 + 5478 + 3344 + 6543);
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            &format!("DEBUG: {test_name}: The total paid payables increased by 6,543 to 7,654 wei"),
            &format!(
                "DEBUG: {test_name}: The total paid payables increased by 8,822 to 16,476 wei"
            ),
        ]);
    }
}
