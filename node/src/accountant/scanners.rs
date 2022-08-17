// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod scanners {
    use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoReal};
    use crate::accountant::pending_payable_dao::PendingPayableDao;
    use crate::accountant::receivable_dao::ReceivableDao;
    use crate::accountant::tools::{PayableExceedThresholdTools, PayableExceedThresholdToolsReal};
    use crate::accountant::ReportAccountsPayable;
    use crate::accountant::{
        Accountant, CancelFailedPendingTransaction, ConfirmPendingTransaction, ReceivedPayments,
        ReportTransactionReceipts, RequestTransactionReceipts, ResponseSkeleton, ScanForPayables,
        ScanForPendingPayables, ScanForReceivables, SentPayable,
    };
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::sub_lib::accountant::AccountantConfig;
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
        ) -> Self {
            Scanners {
                payables: Box::new(PayableScanner::new(payable_dao)),
                pending_payables: Box::new(PendingPayableScanner::new(pending_payable_dao)),
                receivables: Box::new(ReceivableScanner::new(receivable_dao)),
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
        payable_threshold_tools: Box<dyn PayableExceedThresholdTools>,
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
                Self::investigate_debt_extremes(&all_non_pending_payables)
            );
            let qualified_payables = all_non_pending_payables
                .into_iter()
                .filter(|account| self.should_pay(account))
                .collect::<Vec<PayableAccount>>();
            info!(
                logger,
                "Chose {} qualified debts to pay",
                qualified_payables.len()
            );
            debug!(
                logger,
                "{}",
                self.payables_debug_summary(&qualified_payables)
            );
            match qualified_payables.is_empty() {
                true => Err(String::from("No Qualified Payables found.")),
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
        pub fn new(dao: Box<dyn PayableDao>) -> Self {
            Self {
                common: ScannerCommon::default(),
                dao,
                payable_threshold_tools: Box::new(PayableExceedThresholdToolsReal::default()),
            }
        }

        //for debugging only
        pub fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
            if all_non_pending_payables.is_empty() {
                "Payable scan found no debts".to_string()
            } else {
                struct PayableInfo {
                    balance: i64,
                    age: Duration,
                }
                let now = SystemTime::now();
                let init = (
                    PayableInfo {
                        balance: 0,
                        age: Duration::ZERO,
                    },
                    PayableInfo {
                        balance: 0,
                        age: Duration::ZERO,
                    },
                );
                let (biggest, oldest) = all_non_pending_payables.iter().fold(init, |sofar, p| {
                    let (mut biggest, mut oldest) = sofar;
                    let p_age = now
                        .duration_since(p.last_paid_timestamp)
                        .expect("Payable time is corrupt");
                    {
                        //look at a test if not understandable
                        let check_age_parameter_if_the_first_is_the_same =
                            || -> bool { p.balance == biggest.balance && p_age > biggest.age };

                        if p.balance > biggest.balance
                            || check_age_parameter_if_the_first_is_the_same()
                        {
                            biggest = PayableInfo {
                                balance: p.balance,
                                age: p_age,
                            }
                        }

                        let check_balance_parameter_if_the_first_is_the_same =
                            || -> bool { p_age == oldest.age && p.balance > oldest.balance };

                        if p_age > oldest.age || check_balance_parameter_if_the_first_is_the_same()
                        {
                            oldest = PayableInfo {
                                balance: p.balance,
                                age: p_age,
                            }
                        }
                    }
                    (biggest, oldest)
                });
                format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                        all_non_pending_payables.len(), biggest.balance, biggest.age.as_secs(),
                        oldest.balance, oldest.age.as_secs())
            }
        }

        fn should_pay(&self, payable: &PayableAccount) -> bool {
            self.payable_exceeded_threshold(payable).is_some()
        }

        fn payable_exceeded_threshold(&self, payable: &PayableAccount) -> Option<u64> {
            // TODO: This calculation should be done in the database, if possible
            let time_since_last_paid = SystemTime::now()
                .duration_since(payable.last_paid_timestamp)
                .expect("Internal error")
                .as_secs();

            if self.payable_threshold_tools.is_innocent_age(
                time_since_last_paid,
                self.config.payment_thresholds.maturity_threshold_sec as u64,
            ) {
                return None;
            }

            if self.payable_threshold_tools.is_innocent_balance(
                payable.balance,
                self.config.payment_thresholds.permanent_debt_allowed_gwei,
            ) {
                return None;
            }

            let threshold = self
                .payable_threshold_tools
                .calculate_payout_threshold(self.config.payment_thresholds, time_since_last_paid);
            if payable.balance as f64 > threshold {
                Some(threshold as u64)
            } else {
                None
            }
        }

        fn payables_debug_summary(&self, qualified_payables: &[PayableAccount]) -> String {
            let now = SystemTime::now();
            let list = qualified_payables
                .iter()
                .map(|payable| {
                    let p_age = now
                        .duration_since(payable.last_paid_timestamp)
                        .expect("Payable time is corrupt");
                    let threshold = self
                        .payable_exceeded_threshold(payable)
                        .expect("Threshold suddenly changed!");
                    format!(
                        "{} owed for {}sec exceeds threshold: {}; creditor: {}",
                        payable.balance,
                        p_age.as_secs(),
                        threshold,
                        payable.wallet
                    )
                })
                .join("\n");
            String::from("Paying qualified debts:\n").add(&list)
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
        pub fn new(dao: Box<dyn ReceivableDao>) -> Self {
            Self {
                common: ScannerCommon::default(),
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
    use crate::accountant::payable_dao::PayableDaoReal;
    use crate::accountant::scanners::scanners::{
        PayableScanner, PendingPayableScanner, ReceivableScanner, Scanners,
    };
    use crate::accountant::test_utils::{PayableDaoMock, PendingPayableDaoMock, ReceivableDaoMock};

    // #[test]
    // fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
    //     let scanners = Scanners::new(
    //         Box::new(PayableDaoMock::new()),
    //         Box::new(PendingPayableDaoMock::new()),
    //         Box::new(ReceivableDaoMock::new()),
    //     );
    //
    //     scanners
    //         .payables
    //         .as_any()
    //         .downcast_ref::<PayableScanner>()
    //         .unwrap();
    //     scanners
    //         .pending_payables
    //         .as_any()
    //         .downcast_ref::<PendingPayableScanner>()
    //         .unwrap();
    //     scanners
    //         .receivables
    //         .as_any()
    //         .downcast_ref::<ReceivableScanner>()
    //         .unwrap();
    // }
}
