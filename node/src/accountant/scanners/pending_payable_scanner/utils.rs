// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::PendingPayableId;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::time::SystemTime;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct PendingPayableScanReport {
    pub still_pending: Vec<PendingPayableId>,
    pub failures: Vec<PendingPayableId>,
    pub confirmed: Vec<PendingPayableFingerprint>,
}

impl PendingPayableScanReport {
    pub fn requires_payments_retry(&self) -> bool {
        todo!("complete my within GH-642")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PendingPayableScanResult {
    NoPendingPayablesLeft(Option<NodeToUiMessage>),
    PaymentRetryRequired,
}

pub fn elapsed_in_ms(timestamp: SystemTime) -> u128 {
    timestamp
        .elapsed()
        .expect("time calculation for elapsed failed")
        .as_millis()
}

pub fn handle_none_status(
    mut scan_report: PendingPayableScanReport,
    fingerprint: PendingPayableFingerprint,
    max_pending_interval: u64,
    logger: &Logger,
) -> PendingPayableScanReport {
    info!(
        logger,
        "Pending transaction {:?} couldn't be confirmed at attempt \
            {} at {}ms after its sending",
        fingerprint.hash,
        fingerprint.attempt,
        elapsed_in_ms(fingerprint.timestamp)
    );
    let elapsed = fingerprint
        .timestamp
        .elapsed()
        .expect("we should be older now");
    let elapsed = elapsed.as_secs();
    if elapsed > max_pending_interval {
        error!(
            logger,
            "Pending transaction {:?} has exceeded the maximum pending time \
                ({}sec) with the age {}sec and the confirmation process is going to be aborted now \
                at the final attempt {}; manual resolution is required from the \
                user to complete the transaction.",
            fingerprint.hash,
            max_pending_interval,
            elapsed,
            fingerprint.attempt
        );
        scan_report.failures.push(fingerprint.into())
    } else {
        scan_report.still_pending.push(fingerprint.into())
    }
    scan_report
}

pub fn handle_status_with_success(
    mut scan_report: PendingPayableScanReport,
    fingerprint: PendingPayableFingerprint,
    logger: &Logger,
) -> PendingPayableScanReport {
    info!(
        logger,
        "Transaction {:?} has been added to the blockchain; detected locally at attempt \
            {} at {}ms after its sending",
        fingerprint.hash,
        fingerprint.attempt,
        elapsed_in_ms(fingerprint.timestamp)
    );
    scan_report.confirmed.push(fingerprint);
    scan_report
}

//TODO: failures handling is going to need enhancement suggested by GH-693
pub fn handle_status_with_failure(
    mut scan_report: PendingPayableScanReport,
    fingerprint: PendingPayableFingerprint,
    logger: &Logger,
) -> PendingPayableScanReport {
    error!(
        logger,
        "Pending transaction {:?} announced as a failure, interpreting attempt \
            {} after {}ms from the sending",
        fingerprint.hash,
        fingerprint.attempt,
        elapsed_in_ms(fingerprint.timestamp)
    );
    scan_report.failures.push(fingerprint.into());
    scan_report
}

pub fn handle_none_receipt(
    mut scan_report: PendingPayableScanReport,
    payable: PendingPayableFingerprint,
    error_msg: &str,
    logger: &Logger,
) -> PendingPayableScanReport {
    debug!(
        logger,
        "Interpreting a receipt for transaction {:?} but {}; attempt {}, {}ms since sending",
        payable.hash,
        error_msg,
        payable.attempt,
        elapsed_in_ms(payable.timestamp)
    );

    scan_report
        .still_pending
        .push(PendingPayableId::new(payable.rowid, payable.hash));
    scan_report
}
