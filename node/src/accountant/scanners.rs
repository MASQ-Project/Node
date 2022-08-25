// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod scanners {
    use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoReal};
    use crate::accountant::pending_payable_dao::PendingPayableDao;
    use crate::accountant::receivable_dao::ReceivableDao;
    use crate::accountant::tools::{investigate_debt_extremes, qualified_payables_and_summary};
    use crate::accountant::ReportAccountsPayable;
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction, ReceivedPayments,
        ReportTransactionReceipts, RequestTransactionReceipts, ResponseSkeleton, ScanForPayables,
        ScanForPendingPayables, ScanForReceivables, SentPayable,
    };
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::sub_lib::accountant::{AccountantConfig, PaymentThresholds};
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use actix::dev::SendError;
    use actix::{Context, Message, Recipient};
    use itertools::Itertools;
    use masq_lib::logger::{timestamp_as_string, Logger};
    use masq_lib::messages::ScanType;
    use masq_lib::messages::ScanType::PendingPayables;
    use std::any::Any;
    use std::borrow::BorrowMut;
    use std::cell::RefCell;
    use std::ops::Add;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

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
            payment_thresholds: Rc<PaymentThresholds>,
        ) -> Self {
            Scanners {
                payables: Box::new(PayableScanner::new(
                    payable_dao,
                    Rc::clone(&payment_thresholds),
                )),
                pending_payables: Box::new(PendingPayableScanner::new(
                    pending_payable_dao,
                    Rc::clone(&payment_thresholds),
                )),
                receivables: Box::new(ReceivableScanner::new(
                    receivable_dao,
                    Rc::clone(&payment_thresholds),
                )),
            }
        }
    }

    pub trait Scanner<BeginMessage, EndMessage>
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<BeginMessage, Error>;
        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error>;
        fn scan_started_at(&self) -> Option<SystemTime>;
        as_any_dcl!();
    }

    struct ScannerCommon {
        initiated_at_opt: Option<SystemTime>,
        payment_thresholds: Rc<PaymentThresholds>,
    }

    impl ScannerCommon {
        fn new(payment_thresholds: Rc<PaymentThresholds>) -> Self {
            Self {
                initiated_at_opt: None,
                payment_thresholds,
            }
        }
    }

    pub struct PayableScanner {
        common: ScannerCommon,
        dao: Box<dyn PayableDao>,
    }

    impl Scanner<ReportAccountsPayable, SentPayable> for PayableScanner {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<ReportAccountsPayable, Error> {
            todo!("Implement PayableScanner");
            // common::start_scan_at(&mut self.common, timestamp);
            // let start_message = BeginScanAMessage {};
            // // Use the DAO, if necessary, to populate start_message
            // Ok(start_message)

            info!(logger, "Scanning for payables");
            self.common.initiated_at_opt = Some(timestamp);
            let all_non_pending_payables = self.dao.non_pending_payables();
            debug!(
                logger,
                "{}",
                investigate_debt_extremes(&all_non_pending_payables)
            );
            let (qualified_payables, summary) = qualified_payables_and_summary(
                all_non_pending_payables,
                self.common.payment_thresholds.clone(),
            );
            info!(
                logger,
                "Chose {} qualified debts to pay",
                qualified_payables.len()
            );
            debug!(logger, "{}", summary);
            match qualified_payables.is_empty() {
                true => Err(summary),
                false => Ok(ReportAccountsPayable {
                    accounts: qualified_payables,
                    response_skeleton_opt,
                }),
            }
        }

        fn scan_finished(&mut self, message: SentPayable) -> Result<(), Error> {
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
        pub fn new(dao: Box<dyn PayableDao>, payment_thresholds: Rc<PaymentThresholds>) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
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
            logger: &Logger,
        ) -> Result<BeginMessage, Error> {
            todo!("Implement PendingPayableScanner")
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
        pub fn new(
            dao: Box<dyn PendingPayableDao>,
            payment_thresholds: Rc<PaymentThresholds>,
        ) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
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
            logger: &Logger,
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
        pub fn new(dao: Box<dyn ReceivableDao>, payment_thresholds: Rc<PaymentThresholds>) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
                dao,
            }
        }
    }

    // pub struct NullScanner {}
    //
    // impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for NullScanner
    // where
    //     BeginMessage: Message + Send + 'static,
    //     BeginMessage::Result: Send,
    //     EndMessage: Message,
    // {
    //     fn begin_scan(
    //         &mut self,
    //         timestamp: SystemTime,
    //         response_skeleton_opt: Option<ResponseSkeleton>,
    //         ctx: &mut Context<Accountant>,
    //     ) -> Result<BeginMessage, Error> {
    //         todo!("Implement NullScanner")
    //     }
    //
    //     fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
    //         todo!()
    //     }
    //
    //     fn scan_started_at(&self) -> Option<SystemTime> {
    //         todo!()
    //     }
    //
    //     as_any_impl!();
    // }

    pub struct ScannerMock<BeginMessage, EndMessage> {
        begin_scan_params: RefCell<Vec<(SystemTime, Option<ResponseSkeleton>)>>,
        begin_scan_results: Arc<Mutex<Vec<Result<Box<BeginMessage>, Error>>>>,
        end_scan_params: RefCell<Vec<EndMessage>>,
        end_scan_results: Arc<Mutex<Vec<Result<(), Error>>>>,
    }

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage>
        for ScannerMock<BeginMessage, EndMessage>
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<BeginMessage, Error> {
            self.begin_scan_params
                .borrow_mut()
                .push((timestamp, response_skeleton_opt));
            Err(String::from("Called from ScannerMock"))
        }

        fn scan_finished(&mut self, message: EndMessage) -> Result<(), Error> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
        }
    }

    impl<BeginMessage, EndMessage> ScannerMock<BeginMessage, EndMessage> {
        pub fn new() -> Self {
            Self {
                begin_scan_params: RefCell::new(vec![]),
                begin_scan_results: Arc::new(Mutex::new(vec![])),
                end_scan_params: RefCell::new(vec![]),
                end_scan_results: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn begin_scan_params(
            mut self,
            params: Vec<(SystemTime, Option<ResponseSkeleton>)>,
        ) -> Self {
            self.begin_scan_params = RefCell::new(params);
            self
        }

        pub fn begin_scan_result(self, result: Result<Box<BeginMessage>, Error>) -> Self {
            self.begin_scan_results
                .lock()
                .unwrap()
                .borrow_mut()
                .push(result);
            self
        }
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
    use crate::accountant::payable_dao::{PayableAccount, PayableDaoReal};
    use crate::accountant::scanners::scanners::{
        PayableScanner, PendingPayableScanner, ReceivableScanner, Scanners,
    };
    use crate::accountant::test_utils::{
        AccountantBuilder, PayableDaoMock, PendingPayableDaoMock, ReceivableDaoMock,
    };
    use crate::bootstrapper::BootstrapperConfig;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::{
        make_payment_thresholds_with_defaults, make_populated_accountant_config_with_defaults,
    };
    use std::rc::Rc;
    use std::time::SystemTime;

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payment_thresholds = Rc::new(make_payment_thresholds_with_defaults());
        let scanners = Scanners::new(
            Box::new(PayableDaoMock::new()),
            Box::new(PendingPayableDaoMock::new()),
            Box::new(ReceivableDaoMock::new()),
            Rc::clone(&payment_thresholds),
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
