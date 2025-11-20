// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
use crate::accountant::scanners::{Scanner, StartScanError, StartableScanner};
use crate::accountant::{RequestTransactionReceipts, ResponseSkeleton, ScanForPendingPayables};
use crate::sub_lib::wallet::Wallet;
use masq_lib::logger::Logger;
use std::time::SystemTime;

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

        let tx_hashes = self.harvest_tables(logger).map_err(|e| {
            self.mark_as_ended(logger);
            e
        })?;

        Ok(RequestTransactionReceipts {
            tx_hashes,
            response_skeleton_opt,
        })
    }
}
