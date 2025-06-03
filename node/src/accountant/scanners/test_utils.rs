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
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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
