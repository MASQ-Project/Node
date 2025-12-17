// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::pending_payable_scanner::utils::PendingPayableScanResult;
use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
use crate::accountant::scanners::Scanner;
use crate::accountant::TxReceiptsMessage;
use crate::time_marking_methods;
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::time::SystemTime;

impl Scanner<TxReceiptsMessage, PendingPayableScanResult> for PendingPayableScanner {
    fn finish_scan(
        &mut self,
        message: TxReceiptsMessage,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        let response_skeleton_opt = message.response_skeleton_opt;

        let scan_report = self.interpret_tx_receipts(message, logger);

        let retry_opt = scan_report.requires_payments_retry();

        debug!(logger, "Payment retry requirement: {:?}", retry_opt);

        self.process_txs_by_state(scan_report, logger);

        self.mark_as_ended(logger);

        Self::compose_scan_result(retry_opt, response_skeleton_opt)
    }

    time_marking_methods!(PendingPayables);

    as_any_ref_in_trait_impl!();

    as_any_mut_in_trait_impl!();
}
