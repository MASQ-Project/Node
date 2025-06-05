// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::scanners::local_test_utils::{ScannerMock, ScannerMockMarker};
use crate::accountant::scanners::payable_scanner_extension::msgs::QualifiedPayablesMessage;
use crate::accountant::scanners::scan_schedulers::NewPayableScanDynIntervalComputer;
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableScanResult;
use crate::accountant::scanners::scanners_utils::pending_payable_scanner_utils::PendingPayableScanResult;
use crate::accountant::scanners::{
    PayableScanner, PendingPayableScanner, RealScannerMarker, ReceivableScanner,
};
use crate::accountant::{
    ReceivedPayments, ReportTransactionReceipts, RequestTransactionReceipts, SentPayables,
};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use masq_lib::logger::{Logger, TIME_FORMATTING_STRING};
use masq_lib::ui_gateway::NodeToUiMessage;
use regex::Regex;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{format_description, PrimitiveDateTime};

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
            ScannerMock<QualifiedPayablesMessage, SentPayables, PayableScanResult>,
        >,
    ),
    PendingPayable(
        ReplacementType<
            PendingPayableScanner,
            ScannerMock<
                RequestTransactionReceipts,
                ReportTransactionReceipts,
                PendingPayableScanResult,
            >,
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

// Cautious: Don't compare to another timestamp on a full match; this timestamp is trimmed in
// nanoseconds down to three digits
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

fn trim_expected_timestamp_to_three_digits_nanos(value: SystemTime) -> SystemTime {
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
