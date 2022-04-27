// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod accountant_tools {
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction,
        RequestTransactionReceipts, ScanForPayables, ScanForPendingPayable, ScanForReceivables,
    };
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use actix::{Context, Recipient};
    #[cfg(test)]
    use std::any::Any;

    pub struct Scanners {
        pub pending_payables: Box<dyn Scanner>,
        pub payables: Box<dyn Scanner>,
        pub receivables: Box<dyn Scanner>,
    }

    impl Default for Scanners {
        fn default() -> Self {
            Scanners {
                pending_payables: Box::new(PendingPayablesScanner),
                payables: Box::new(PayablesScanner),
                receivables: Box::new(ReceivablesScanner),
            }
        }
    }

    pub trait Scanner {
        fn scan(&self, accountant: &Accountant);
        fn notify_later_assertable(&self, accountant: &Accountant, ctx: &mut Context<Accountant>);
        as_any_dcl!();
    }

    #[derive(Debug, PartialEq)]
    pub struct PendingPayablesScanner;

    impl Scanner for PendingPayablesScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_pending_payable()
        }
        fn notify_later_assertable(&self, accountant: &Accountant, ctx: &mut Context<Accountant>) {
            let _ = accountant
                .tools
                .notify_later_scan_for_pending_payable
                .notify_later(
                    ScanForPendingPayable {},
                    accountant
                        .config
                        .scan_intervals
                        .pending_payable_scan_interval,
                    ctx,
                );
        }
        as_any_impl!();
    }

    #[derive(Debug, PartialEq)]
    pub struct PayablesScanner;

    impl Scanner for PayablesScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_payables()
        }

        fn notify_later_assertable(&self, accountant: &Accountant, ctx: &mut Context<Accountant>) {
            let _ = accountant.tools.notify_later_scan_for_payable.notify_later(
                ScanForPayables {},
                accountant.config.scan_intervals.payable_scan_interval,
                ctx,
            );
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

        fn notify_later_assertable(&self, accountant: &Accountant, ctx: &mut Context<Accountant>) {
            let _ = accountant
                .tools
                .notify_later_scan_for_receivable
                .notify_later(
                    ScanForReceivables {},
                    accountant.config.scan_intervals.receivable_scan_interval,
                    ctx,
                );
        }

        as_any_impl!();
    }

    //this is for turning off a certain scanner in testing to prevent it make "noise"
    #[derive(Debug, PartialEq)]
    pub struct NullScanner;

    impl Scanner for NullScanner {
        fn scan(&self, _accountant: &Accountant) {}
        fn notify_later_assertable(
            &self,
            _accountant: &Accountant,
            _ctx: &mut Context<Accountant>,
        ) {
        }
        as_any_impl!();
    }

    #[derive(Default)]
    pub struct TransactionConfirmationTools {
        pub notify_later_scan_for_pending_payable:
            Box<dyn NotifyLaterHandle<ScanForPendingPayable, Accountant>>,
        pub notify_later_scan_for_payable: Box<dyn NotifyLaterHandle<ScanForPayables, Accountant>>,
        pub notify_later_scan_for_receivable:
            Box<dyn NotifyLaterHandle<ScanForReceivables, Accountant>>,
        pub notify_confirm_transaction:
            Box<dyn NotifyHandle<ConfirmPendingTransaction, Accountant>>,
        pub notify_cancel_failed_transaction:
            Box<dyn NotifyHandle<CancelFailedPendingTransaction, Accountant>>,
        pub request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::tools::accountant_tools::{
        PayablesScanner, PendingPayablesScanner, ReceivablesScanner, Scanners,
    };

    #[test]
    fn scanners_are_properly_defaulted() {
        let subject = Scanners::default();

        assert_eq!(
            subject.pending_payables.as_any().downcast_ref(),
            Some(&PendingPayablesScanner)
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
