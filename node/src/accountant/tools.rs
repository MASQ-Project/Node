// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod accountant_tools {
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction,
        RequestTransactionReceipts, ScanForPayables, ScanForPendingPayable, ScanForReceivables,
    };
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use actix::Recipient;
    #[cfg(test)]
    use std::any::Any;

    pub struct Scanners {
        pub pending_payable: Box<dyn Scanner>,
        pub payables: Box<dyn Scanner>,
        pub receivables: Box<dyn Scanner>,
    }

    impl Default for Scanners {
        fn default() -> Self {
            Scanners {
                pending_payable: Box::new(PendingPaymentsScanner),
                payables: Box::new(PayablesScanner),
                receivables: Box::new(ReceivablesScanner),
            }
        }
    }

    pub trait Scanner {
        fn scan(&self, accountant: &Accountant);
        as_any_dcl!();
    }

    #[derive(Debug, PartialEq)]
    pub struct PendingPaymentsScanner;

    impl Scanner for PendingPaymentsScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_pending_payable()
        }
        as_any_impl!();
    }

    #[derive(Debug, PartialEq)]
    pub struct PayablesScanner;

    impl Scanner for PayablesScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_payables()
        }
        as_any_impl!();
    }

    #[derive(Debug, PartialEq)]
    pub struct ReceivablesScanner;

    impl Scanner for ReceivablesScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_received_payments();
            accountant.scan_for_delinquencies()
        }
        as_any_impl!();
    }

    //this is for when you want to turn off the certain scanner in your testing, giving you space for testing just a constrained area
    #[derive(Debug, PartialEq)]
    pub struct NullScanner;

    impl Scanner for NullScanner {
        fn scan(&self, _accountant: &Accountant) {}
        as_any_impl!();
    }

    #[derive(Default)]
    pub struct TransactionConfirmationTools {
        pub notify_later_handle_scan_for_pending_payable:
            Box<dyn NotifyLaterHandle<ScanForPendingPayable>>,
        pub notify_later_handle_scan_for_payable: Box<dyn NotifyLaterHandle<ScanForPayables>>,
        pub notify_later_handle_scan_for_receivable: Box<dyn NotifyLaterHandle<ScanForReceivables>>,
        pub request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
        pub notify_handle_confirm_transaction: Box<dyn NotifyHandle<ConfirmPendingTransaction>>,
        pub notify_handle_cancel_failed_transaction:
            Box<dyn NotifyHandle<CancelFailedPendingTransaction>>,
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::tools::accountant_tools::{
        PayablesScanner, PendingPaymentsScanner, ReceivablesScanner, Scanners,
    };

    #[test]
    fn scanners_are_properly_defaulted() {
        let subject = Scanners::default();

        assert_eq!(
            subject.pending_payable.as_any().downcast_ref(),
            Some(&PendingPaymentsScanner)
        );
        assert_eq!(
            subject.payables.as_any().downcast_ref(),
            Some(&PayablesScanner)
        );
        assert_eq!(
            subject.receivables.as_any().downcast_ref(),
            Some(&ReceivablesScanner)
        )
    }
}
