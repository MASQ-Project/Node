// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::utils::TxHash;
use crate::accountant::scanners::payable_scanner::msgs::{
    InitialTemplatesMessage, PricedTemplatesMessage,
};
use crate::accountant::scanners::payable_scanner::payment_adjuster_integration::{
    PreparedAdjustment, SolvencySensitivePaymentInstructor,
};
use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
use crate::accountant::scanners::payable_scanner::{MultistageDualPayableScanner, PayableScanner};
use crate::accountant::scanners::pending_payable_scanner::utils::{
    PendingPayableCache, PendingPayableScanResult,
};
use crate::accountant::scanners::pending_payable_scanner::{
    CachesEmptiableScanner, ExtendedPendingPayablePrivateScanner,
};
use crate::accountant::scanners::scan_schedulers::{
    NewPayableScanDynIntervalComputer, PayableSequenceScanner, RescheduleScanOnErrorResolver,
    ScanReschedulingAfterEarlyStop,
};
use crate::accountant::scanners::{
    PendingPayableScanner, PrivateScanner, RealScannerMarker, ReceivableScanner, Scanner,
    StartScanError, StartableScanner,
};
use crate::accountant::{
    ReceivedPayments, RequestTransactionReceipts, ResponseSkeleton, SentPayables, TxReceiptsMessage,
};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, OutboundPaymentsInstructions};
use crate::sub_lib::wallet::Wallet;
use actix::{Message, System};
use itertools::Either;
use masq_lib::logger::{Logger, TIME_FORMATTING_STRING};
use masq_lib::ui_gateway::NodeToUiMessage;
use regex::Regex;
use std::any::type_name;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{format_description, PrimitiveDateTime};

pub struct NullScanner {}

impl<TriggerMessage, StartMessage, EndMessage, ScanResult>
    PrivateScanner<TriggerMessage, StartMessage, EndMessage, ScanResult> for NullScanner
where
    TriggerMessage: Message,
    StartMessage: Message,
    EndMessage: Message,
{
}

impl<TriggerMessage, StartMessage> StartableScanner<TriggerMessage, StartMessage> for NullScanner
where
    TriggerMessage: Message,
    StartMessage: Message,
{
    fn start_scan(
        &mut self,
        _wallet: &Wallet,
        _timestamp: SystemTime,
        _response_skeleton_opt: Option<ResponseSkeleton>,
        _logger: &Logger,
    ) -> Result<StartMessage, StartScanError> {
        Err(StartScanError::CalledFromNullScanner)
    }
}

impl<EndMessage, ScanResult> Scanner<EndMessage, ScanResult> for NullScanner
where
    EndMessage: Message,
{
    fn finish_scan(&mut self, _message: EndMessage, _logger: &Logger) -> ScanResult {
        panic!("Called finish_scan() from NullScanner");
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        None
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        panic!("Called mark_as_started() from NullScanner");
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        panic!("Called mark_as_ended() from NullScanner");
    }

    as_any_ref_in_trait_impl!();
}

impl MultistageDualPayableScanner for NullScanner {}

impl SolvencySensitivePaymentInstructor for NullScanner {
    fn try_skipping_payment_adjustment(
        &self,
        _msg: PricedTemplatesMessage,
        _logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        intentionally_blank!()
    }

    fn perform_payment_adjustment(
        &self,
        _setup: PreparedAdjustment,
        _logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        intentionally_blank!()
    }
}

impl ExtendedPendingPayablePrivateScanner for NullScanner {}

impl CachesEmptiableScanner for NullScanner {
    fn empty_caches(&mut self, _logger: &Logger) {
        intentionally_blank!()
    }
}

impl Default for NullScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl NullScanner {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct ScannerMock<StartMessage, EndMessage, ScanResult> {
    start_scan_params:
        Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
    start_scan_results: RefCell<Vec<Result<StartMessage, StartScanError>>>,
    finish_scan_params: Arc<Mutex<Vec<(EndMessage, Logger)>>>,
    finish_scan_results: RefCell<Vec<ScanResult>>,
    scan_started_at_results: RefCell<Vec<Option<SystemTime>>>,
    stop_system_after_last_message: RefCell<bool>,
}

impl<TriggerMessage, StartMessage, EndMessage, ScanResult>
    PrivateScanner<TriggerMessage, StartMessage, EndMessage, ScanResult>
    for ScannerMock<StartMessage, EndMessage, ScanResult>
where
    TriggerMessage: Message,
    StartMessage: Message,
    EndMessage: Message,
{
}

impl<TriggerMessage, StartMessage, EndMessage, ScanResult>
    StartableScanner<TriggerMessage, StartMessage>
    for ScannerMock<StartMessage, EndMessage, ScanResult>
where
    TriggerMessage: Message,
    StartMessage: Message,
    EndMessage: Message,
{
    fn start_scan(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<StartMessage, StartScanError> {
        self.start_scan_params.lock().unwrap().push((
            wallet.clone(),
            timestamp,
            response_skeleton_opt,
            logger.clone(),
            // This serves for identification in scanners allowing different modes to start
            // them up through.
            type_name::<TriggerMessage>().to_string(),
        ));
        if self.is_allowed_to_stop_the_system() && self.is_last_message() {
            System::current().stop();
        }
        self.start_scan_results.borrow_mut().remove(0)
    }
}

impl<StartMessage, EndMessage, ScanResult> Scanner<EndMessage, ScanResult>
    for ScannerMock<StartMessage, EndMessage, ScanResult>
where
    StartMessage: Message,
    EndMessage: Message,
{
    fn finish_scan(&mut self, message: EndMessage, logger: &Logger) -> ScanResult {
        self.finish_scan_params
            .lock()
            .unwrap()
            .push((message, logger.clone()));
        if self.is_allowed_to_stop_the_system() && self.is_last_message() {
            System::current().stop();
        }
        self.finish_scan_results.borrow_mut().remove(0)
    }

    fn scan_started_at(&self) -> Option<SystemTime> {
        self.scan_started_at_results.borrow_mut().remove(0)
    }

    fn mark_as_started(&mut self, _timestamp: SystemTime) {
        intentionally_blank!()
    }

    fn mark_as_ended(&mut self, _logger: &Logger) {
        intentionally_blank!()
    }
}

impl<StartMessage, EndMessage, ScanResult> Default
    for ScannerMock<StartMessage, EndMessage, ScanResult>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<StartMessage, EndMessage, ScanResult> ScannerMock<StartMessage, EndMessage, ScanResult> {
    pub fn new() -> Self {
        Self {
            start_scan_params: Arc::new(Mutex::new(vec![])),
            start_scan_results: RefCell::new(vec![]),
            finish_scan_params: Arc::new(Mutex::new(vec![])),
            finish_scan_results: RefCell::new(vec![]),
            scan_started_at_results: RefCell::new(vec![]),
            stop_system_after_last_message: RefCell::new(false),
        }
    }

    pub fn start_scan_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, SystemTime, Option<ResponseSkeleton>, Logger, String)>>>,
    ) -> Self {
        self.start_scan_params = params.clone();
        self
    }

    pub fn start_scan_result(self, result: Result<StartMessage, StartScanError>) -> Self {
        self.start_scan_results.borrow_mut().push(result);
        self
    }

    pub fn scan_started_at_result(self, result: Option<SystemTime>) -> Self {
        self.scan_started_at_results.borrow_mut().push(result);
        self
    }

    pub fn finish_scan_params(mut self, params: &Arc<Mutex<Vec<(EndMessage, Logger)>>>) -> Self {
        self.finish_scan_params = params.clone();
        self
    }

    pub fn finish_scan_result(self, result: ScanResult) -> Self {
        self.finish_scan_results.borrow_mut().push(result);
        self
    }

    pub fn stop_the_system_after_last_msg(self) -> Self {
        self.stop_system_after_last_message.replace(true);
        self
    }

    pub fn is_allowed_to_stop_the_system(&self) -> bool {
        *self.stop_system_after_last_message.borrow()
    }

    pub fn is_last_message(&self) -> bool {
        self.is_last_message_from_start_scan() || self.is_last_message_from_end_scan()
    }

    pub fn is_last_message_from_start_scan(&self) -> bool {
        self.start_scan_results.borrow().len() == 1 && self.finish_scan_results.borrow().is_empty()
    }

    pub fn is_last_message_from_end_scan(&self) -> bool {
        self.finish_scan_results.borrow().len() == 1 && self.start_scan_results.borrow().is_empty()
    }
}

impl MultistageDualPayableScanner
    for ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>
{
}

impl SolvencySensitivePaymentInstructor
    for ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>
{
    fn try_skipping_payment_adjustment(
        &self,
        msg: PricedTemplatesMessage,
        _logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        // Always passes...
        // It would be quite inconvenient if we had to add specialized features to the generic
        // mock, plus this functionality can be tested better with the other components mocked,
        // not the scanner itself.
        Ok(Either::Left(OutboundPaymentsInstructions {
            priced_templates: msg.priced_templates,
            agent: msg.agent,
            response_skeleton_opt: msg.response_skeleton_opt,
        }))
    }

    fn perform_payment_adjustment(
        &self,
        _setup: PreparedAdjustment,
        _logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        intentionally_blank!()
    }
}

impl ExtendedPendingPayablePrivateScanner
    for ScannerMock<RequestTransactionReceipts, TxReceiptsMessage, PendingPayableScanResult>
{
}

impl CachesEmptiableScanner
    for ScannerMock<RequestTransactionReceipts, TxReceiptsMessage, PendingPayableScanResult>
{
    fn empty_caches(&mut self, _logger: &Logger) {
        intentionally_blank!()
    }
}

pub trait ScannerMockMarker {}

impl<StartMsg, EndMsg, ScanResult> ScannerMockMarker for ScannerMock<StartMsg, EndMsg, ScanResult> {}

#[derive(Default)]
pub struct NewPayableScanDynIntervalComputerMock {
    compute_interval_params: Arc<Mutex<Vec<(SystemTime, SystemTime, Duration)>>>,
    compute_interval_results: RefCell<Vec<Option<Duration>>>,
}

impl NewPayableScanDynIntervalComputer for NewPayableScanDynIntervalComputerMock {
    fn compute_interval(
        &self,
        now: SystemTime,
        last_new_payable_scan_timestamp: SystemTime,
        interval: Duration,
    ) -> Option<Duration> {
        self.compute_interval_params.lock().unwrap().push((
            now,
            last_new_payable_scan_timestamp,
            interval,
        ));
        self.compute_interval_results.borrow_mut().remove(0)
    }
}

impl NewPayableScanDynIntervalComputerMock {
    pub fn compute_interval_params(
        mut self,
        params: &Arc<Mutex<Vec<(SystemTime, SystemTime, Duration)>>>,
    ) -> Self {
        self.compute_interval_params = params.clone();
        self
    }

    pub fn compute_interval_result(self, result: Option<Duration>) -> Self {
        self.compute_interval_results.borrow_mut().push(result);
        self
    }
}

pub enum ReplacementType<ScannerReal, ScannerMock>
where
    ScannerReal: RealScannerMarker,
    ScannerMock: ScannerMockMarker,
{
    Real(ScannerReal),
    Mock(ScannerMock),
    Null,
}

// The scanners are categorized by types because we want them to become an abstract object
// represented by a private trait. Of course, such an object cannot be constructed directly in
// the outer world; therefore, we have to provide specific objects that will cast accordingly
// under the hood.
pub enum ScannerReplacement {
    Payable(
        ReplacementType<
            PayableScanner,
            ScannerMock<InitialTemplatesMessage, SentPayables, PayableScanResult>,
        >,
    ),
    PendingPayable(
        ReplacementType<
            PendingPayableScanner,
            ScannerMock<RequestTransactionReceipts, TxReceiptsMessage, PendingPayableScanResult>,
        >,
    ),
    Receivable(
        ReplacementType<
            ReceivableScanner,
            ScannerMock<RetrieveTransactions, ReceivedPayments, Option<NodeToUiMessage>>,
        >,
    ),
}

pub enum MarkScanner<'a> {
    Ended(&'a Logger),
    Started(SystemTime),
}

// Cautious: Don't compare to another timestamp on an exact match. This timestamp is trimmed in
// nanoseconds down to three digits. Works only for the format bound by TIME_FORMATTING_STRING
pub fn parse_system_time_from_str(examined_str: &str) -> Vec<SystemTime> {
    let regex = Regex::new(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})").unwrap();
    let captures = regex.captures_iter(examined_str);
    captures
        .map(|captures| {
            let captured_str_timestamp = captures.get(0).unwrap().as_str();
            let format = format_description::parse(TIME_FORMATTING_STRING).unwrap();
            let dt = PrimitiveDateTime::parse(captured_str_timestamp, &format).unwrap();
            let duration = Duration::from_secs(dt.assume_utc().unix_timestamp() as u64)
                + Duration::from_nanos(dt.nanosecond() as u64);
            UNIX_EPOCH + duration
        })
        .collect()
}

pub fn trim_expected_timestamp_to_three_digits_nanos(value: SystemTime) -> SystemTime {
    let duration = value.duration_since(UNIX_EPOCH).unwrap();
    let full_nanos = duration.subsec_nanos();
    let diffuser = 10_u32.pow(6);
    let trimmed_nanos = (full_nanos / diffuser) * diffuser;
    let duration = duration
        .checked_sub(Duration::from_nanos(full_nanos as u64))
        .unwrap()
        .checked_add(Duration::from_nanos(trimmed_nanos as u64))
        .unwrap();
    UNIX_EPOCH + duration
}

pub fn assert_timestamps_from_str(examined_str: &str, expected_timestamps: Vec<SystemTime>) {
    let parsed_timestamps = parse_system_time_from_str(examined_str);
    if parsed_timestamps.len() != expected_timestamps.len() {
        panic!(
            "You supplied {} expected timestamps, but the examined text contains only {}",
            expected_timestamps.len(),
            parsed_timestamps.len()
        )
    }
    let zipped = parsed_timestamps
        .into_iter()
        .zip(expected_timestamps.into_iter());
    zipped.for_each(|(parsed_timestamp, expected_timestamp)| {
        let expected_timestamp_trimmed =
            trim_expected_timestamp_to_three_digits_nanos(expected_timestamp);
        assert_eq!(
            parsed_timestamp, expected_timestamp_trimmed,
            "We expected this timestamp {:?} in this fragment '{}' but found {:?}",
            expected_timestamp_trimmed, examined_str, parsed_timestamp
        )
    })
}

#[derive(Default)]
pub struct RescheduleScanOnErrorResolverMock {
    resolve_rescheduling_on_error_params:
        Arc<Mutex<Vec<(PayableSequenceScanner, StartScanError, bool, Logger)>>>,
    resolve_rescheduling_on_error_results: RefCell<Vec<ScanReschedulingAfterEarlyStop>>,
}

impl RescheduleScanOnErrorResolver for RescheduleScanOnErrorResolverMock {
    fn resolve_rescheduling_on_error(
        &self,
        scanner: PayableSequenceScanner,
        error: &StartScanError,
        is_externally_triggered: bool,
        logger: &Logger,
    ) -> ScanReschedulingAfterEarlyStop {
        self.resolve_rescheduling_on_error_params
            .lock()
            .unwrap()
            .push((
                scanner,
                error.clone(),
                is_externally_triggered,
                logger.clone(),
            ));
        self.resolve_rescheduling_on_error_results
            .borrow_mut()
            .remove(0)
    }
}

impl RescheduleScanOnErrorResolverMock {
    pub fn resolve_rescheduling_on_error_params(
        mut self,
        params: &Arc<Mutex<Vec<(PayableSequenceScanner, StartScanError, bool, Logger)>>>,
    ) -> Self {
        self.resolve_rescheduling_on_error_params = params.clone();
        self
    }
    pub fn resolve_rescheduling_on_error_result(
        self,
        result: ScanReschedulingAfterEarlyStop,
    ) -> Self {
        self.resolve_rescheduling_on_error_results
            .borrow_mut()
            .push(result);
        self
    }
}

pub fn make_zeroed_consuming_wallet_balances() -> ConsumingWalletBalances {
    ConsumingWalletBalances::new(0.into(), 0.into())
}

pub struct PendingPayableCacheMock<Record> {
    load_cache_params: Arc<Mutex<Vec<Vec<Record>>>>,
    load_cache_results: RefCell<Vec<HashMap<TxHash, Record>>>,
    get_record_by_hash_params: Arc<Mutex<Vec<TxHash>>>,
    get_record_by_hash_results: RefCell<Vec<Option<Record>>>,
    ensure_empty_cache_params: Arc<Mutex<Vec<()>>>,
}

impl<Record> Default for PendingPayableCacheMock<Record> {
    fn default() -> Self {
        Self {
            load_cache_params: Arc::new(Mutex::new(vec![])),
            load_cache_results: RefCell::new(vec![]),
            get_record_by_hash_params: Arc::new(Mutex::new(vec![])),
            get_record_by_hash_results: RefCell::new(vec![]),
            ensure_empty_cache_params: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl<Record> PendingPayableCache<Record> for PendingPayableCacheMock<Record> {
    fn load_cache(&mut self, records: Vec<Record>) {
        self.load_cache_params.lock().unwrap().push(records);
        self.load_cache_results.borrow_mut().remove(0);
    }

    fn get_record_by_hash(&mut self, hash: TxHash) -> Option<Record> {
        self.get_record_by_hash_params.lock().unwrap().push(hash);
        self.get_record_by_hash_results.borrow_mut().remove(0)
    }

    fn ensure_empty_cache(&mut self, _logger: &Logger) {
        self.ensure_empty_cache_params.lock().unwrap().push(());
    }

    fn dump_cache(&mut self) -> HashMap<TxHash, Record> {
        unimplemented!("not needed yet")
    }
}

impl<Record> PendingPayableCacheMock<Record> {
    pub fn load_cache_params(mut self, params: &Arc<Mutex<Vec<Vec<Record>>>>) -> Self {
        self.load_cache_params = params.clone();
        self
    }

    pub fn load_cache_result(self, result: HashMap<TxHash, Record>) -> Self {
        self.load_cache_results.borrow_mut().push(result);
        self
    }

    pub fn get_record_by_hash_params(mut self, params: &Arc<Mutex<Vec<TxHash>>>) -> Self {
        self.get_record_by_hash_params = params.clone();
        self
    }

    pub fn get_record_by_hash_result(self, result: Option<Record>) -> Self {
        self.get_record_by_hash_results.borrow_mut().push(result);
        self
    }

    pub fn ensure_empty_cache_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.ensure_empty_cache_params = params.clone();
        self
    }
}
