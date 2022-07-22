// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod scanners {
    use crate::accountant::payable_dao::{PayableDao, PayableDaoReal};
    use crate::accountant::pending_payable_dao::PendingPayableDao;
    use crate::accountant::receivable_dao::ReceivableDao;
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction, ReceivedPayments,
        ReportTransactionReceipts, RequestTransactionReceipts, ResponseSkeleton, ScanForPayables,
        ScanForPendingPayables, ScanForReceivables, SentPayable,
    };
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use actix::dev::SendError;
    use actix::{Context, Message, Recipient};
    use masq_lib::logger::timestamp_as_string;
    use masq_lib::messages::ScanType;
    use masq_lib::messages::ScanType::PendingPayables;
    use std::any::Any;
    use std::cell::RefCell;
    use std::time::SystemTime;

    type Error = String;

    pub struct Scanners {
        pub payables: Box<dyn Scanner<ReportAccountsPayable, SentPayable>>,
        pub pending_payables:
            Box<dyn Scanner<RequestTransactionReceipts, ReportTransactionReceipts>>,
        pub receivables: Box<dyn Scanner<RetrieveTransactions, ReceivedPayments>>,
    }

    impl Scanners {
        pub fn new(
            payable_dao: Box<dyn PayableDao>,
            pending_payable_dao: Box<dyn PendingPayableDao>,
            receivable_dao: Box<dyn ReceivableDao>,
        ) -> Self {
            Scanners {
                payables: Box::new(PayableScanner::new(payable_dao)),
                pending_payables: Box::new(PendingPayableScanner::new(pending_payable_dao)),
                receivables: Box::new(ReceivableScanner::new(receivable_dao)),
            }
        }
    }

    // struct ScannerADao {}
    // struct ScannerBDao {}
    //
    // struct BeginScanAMessage{
    //
    // }
    //
    // impl Message for BeginScanAMessage{}
    //
    // struct FinishScanAMessage {
    //
    // }
    //
    // impl Message for FinishScanAMessage{}
    //
    // struct BeginScanBMessage {
    //
    // }
    //
    // impl Message for BeginScanBMessage{}
    //
    // struct FinishScanBMessage {
    //
    // }
    //
    // impl Message for FinishScanAMessage{}

    pub trait Scanner<BeginMessage, EndMessage>
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            ctx: &mut Context<Accountant>,
        ) -> Result<BeginMessage, Error>;
        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error>;
        fn scan_started_at(&self) -> Option<SystemTime>;
        as_any_dcl!();
    }

    struct ScannerCommon {
        initiated_at_opt: Option<SystemTime>,
    }

    impl Default for ScannerCommon {
        fn default() -> Self {
            Self {
                initiated_at_opt: None,
            }
        }
    }

    pub struct PayableScanner {
        common: ScannerCommon,
        dao: Box<dyn PayableDao>,
    }

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for PayableScanner
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            ctx: &mut Context<Accountant>,
        ) -> Result<BeginMessage, Error> {
            todo!("Begin Scan for PayableScanner");
            // common::start_scan_at(&mut self.common, timestamp);
            // let start_message = BeginScanAMessage {};
            // // Use the DAO, if necessary, to populate start_message
            // Ok(start_message)
        }

        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
            todo!()
            // Use the passed-in message and the internal DAO to finish the scan
            // Ok(())
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
            // common::scan_started_at(&self.common)
        }

        as_any_impl!();
    }

    impl PayableScanner {
        pub fn new(dao: Box<dyn PayableDao>) -> Self {
            Self {
                common: ScannerCommon::default(),
                dao,
            }
        }
    }

    pub struct PendingPayableScanner {
        common: ScannerCommon,
        dao: Box<dyn PendingPayableDao>,
    }

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for PendingPayableScanner
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            ctx: &mut Context<Accountant>,
        ) -> Result<BeginMessage, Error> {
            todo!()
        }

        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
        }

        as_any_impl!();
    }

    impl PendingPayableScanner {
        pub fn new(dao: Box<dyn PendingPayableDao>) -> Self {
            Self {
                common: ScannerCommon::default(),
                dao,
            }
        }
    }

    pub struct ReceivableScanner {
        common: ScannerCommon,
        dao: Box<dyn ReceivableDao>,
    }

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for ReceivableScanner
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            ctx: &mut Context<Accountant>,
        ) -> Result<BeginMessage, Error> {
            todo!()
        }

        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
        }

        as_any_impl!();
    }

    impl ReceivableScanner {
        pub fn new(dao: Box<dyn ReceivableDao>) -> Self {
            Self {
                common: ScannerCommon::default(),
                dao,
            }
        }
    }

    pub struct NullScanner {}

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for NullScanner
    where
        BeginMessage: Message + Send + 'static,
        BeginMessage::Result: Send,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            ctx: &mut Context<Accountant>,
        ) -> Result<BeginMessage, Error> {
            todo!()
        }

        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
        }

        as_any_impl!();
    }

    #[derive(Default)]
    pub struct NotifyLaterForScanners {
        pub scan_for_pending_payable:
            Box<dyn NotifyLaterHandle<ScanForPendingPayables, Accountant>>,
        pub scan_for_payable: Box<dyn NotifyLaterHandle<ScanForPayables, Accountant>>,
        pub scan_for_receivable: Box<dyn NotifyLaterHandle<ScanForReceivables, Accountant>>,
    }

    #[derive(Default)]
    pub struct TransactionConfirmationTools {
        pub notify_confirm_transaction:
            Box<dyn NotifyHandle<ConfirmPendingTransaction, Accountant>>,
        pub notify_cancel_failed_transaction:
            Box<dyn NotifyHandle<CancelFailedPendingTransaction, Accountant>>,
        pub request_transaction_receipts_subs_opt: Option<Recipient<RequestTransactionReceipts>>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::payable_dao::PayableDaoReal;
    use crate::accountant::scanners::scanners::{
        PayableScanner, PendingPayableScanner, ReceivableScanner, Scanners,
    };
    use crate::accountant::test_utils::{PayableDaoMock, PendingPayableDaoMock, ReceivableDaoMock};

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let scanners = Scanners::new(
            Box::new(PayableDaoMock::new()),
            Box::new(PendingPayableDaoMock::new()),
            Box::new(ReceivableDaoMock::new()),
        );

        scanners
            .payables
            .as_any()
            .downcast_ref::<PayableScanner>()
            .unwrap();
        scanners
            .pending_payables
            .as_any()
            .downcast_ref::<PendingPayableScanner>()
            .unwrap();
        scanners
            .receivables
            .as_any()
            .downcast_ref::<ReceivableScanner>()
            .unwrap();
    }
}
