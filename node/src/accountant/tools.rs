// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod accountant_tools {
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction,
        RequestTransactionReceipts, ScanForPayables, ScanForPendingPayable, ScanForReceivables,
    };
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use actix::{AsyncContext, Context, Recipient};
    #[cfg(test)]
    use std::any::Any;
    use std::time::Duration;

    macro_rules! notify_later_assertable {
        ($accountant: expr, $ctx: expr, $message_type: ident, $notify_later_handle_field: ident,$scan_interval_field: ident) => {
            let closure =
                Box::new(|msg: $message_type, interval: Duration| $ctx.notify_later(msg, interval));
            let _ = $accountant.tools.$notify_later_handle_field.notify_later(
                $message_type {},
                $accountant.config.scan_intervals.$scan_interval_field,
                closure,
            );
        };
    }

    pub struct Scanners {
        pub pending_payables: Box<dyn Scanner>,
        pub payables: Box<dyn Scanner>,
        pub receivables: Box<dyn Scanner>,
    }

    impl Default for Scanners {
        fn default() -> Self {
            Scanners {
                pending_payables: Box::new(PendingPaymentsScanner),
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
    pub struct PendingPaymentsScanner;

    impl Scanner for PendingPaymentsScanner {
        fn scan(&self, accountant: &Accountant) {
            accountant.scan_for_pending_payable()
        }
        fn notify_later_assertable(&self, accountant: &Accountant, ctx: &mut Context<Accountant>) {
            notify_later_assertable!(
                accountant,
                ctx,
                ScanForPendingPayable,
                notify_later_scan_for_pending_payable,
                pending_payable_scan_interval
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
            notify_later_assertable!(
                accountant,
                ctx,
                ScanForPayables,
                notify_later_scan_for_payable,
                payable_scan_interval
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
            notify_later_assertable!(
                accountant,
                ctx,
                ScanForReceivables,
                notify_later_scan_for_receivable,
                receivable_scan_interval
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
            Box<dyn NotifyLaterHandle<ScanForPendingPayable>>,
        pub notify_later_scan_for_payable: Box<dyn NotifyLaterHandle<ScanForPayables>>,
        pub notify_later_scan_for_receivable: Box<dyn NotifyLaterHandle<ScanForReceivables>>,
        pub notify_confirm_transaction: Box<dyn NotifyHandle<ConfirmPendingTransaction>>,
        pub notify_cancel_failed_transaction: Box<dyn NotifyHandle<CancelFailedPendingTransaction>>,
        pub request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
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
            subject.pending_payables.as_any().downcast_ref(),
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
