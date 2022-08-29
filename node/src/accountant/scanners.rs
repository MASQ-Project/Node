// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod scanners {
    use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoReal};
    use crate::accountant::pending_payable_dao::PendingPayableDao;
    use crate::accountant::receivable_dao::ReceivableDao;
    use crate::accountant::tools::payable_scanner_tools::{
        investigate_debt_extremes, qualified_payables_and_summary,
    };
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
            // common::start_scan_at(&mut self.common, timestamp);
            // let start_message = BeginScanAMessage {};
            // // Use the DAO, if necessary, to populate start_message
            // Ok(start_message)

            info!(logger, "Scanning for payables");
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

    impl Scanner<RequestTransactionReceipts, ReportTransactionReceipts> for PendingPayableScanner {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<RequestTransactionReceipts, Error> {
            info!(logger, "Scanning for pending payable");
            let filtered_pending_payable = self.dao.return_all_fingerprints();
            match filtered_pending_payable.is_empty() {
                true => {
                    debug!(
                        logger,
                        "Pending payable scan ended. No pending payable found."
                    );
                    Err(String::from("No pending payable found."))
                }
                false => {
                    debug!(
                        logger,
                        "Found {} pending payables to process",
                        filtered_pending_payable.len()
                    );
                    Ok(RequestTransactionReceipts {
                        pending_payable: filtered_pending_payable,
                        response_skeleton_opt,
                    })
                }
            }
        }

        fn scan_finished(&mut self, message: ReportTransactionReceipts) -> Result<(), Error> {
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
        PayableScanner, PendingPayableScanner, ReceivableScanner, Scanner, Scanners,
    };
    use crate::accountant::test_utils::{
        AccountantBuilder, PayableDaoMock, PendingPayableDaoMock, ReceivableDaoMock,
    };
    use crate::accountant::RequestTransactionReceipts;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::{
        make_payment_thresholds_with_defaults, make_populated_accountant_config_with_defaults,
    };
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
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

    #[test]
    fn payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let (qualified_payable_accounts, _, all_non_pending_payables) =
            make_payables(now, payment_thresholds.clone());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);

        let mut payable_scanner =
            PayableScanner::new(Box::new(payable_dao), Rc::new(payment_thresholds));

        let result = payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let expected_message = ReportAccountsPayable {
            accounts: qualified_payable_accounts.clone(),
            response_skeleton_opt: None,
        };
        assert_eq!(result, Ok(expected_message));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for payables", test_name),
            &format!(
                "INFO: {}: Chose {} qualified debts to pay",
                test_name,
                qualified_payable_accounts.len()
            ),
        ])
    }

    #[test]
    fn payable_scanner_throws_error_in_case_no_qualified_payable_is_found() {
        init_test_logging();
        let test_name = "payable_scanner_throws_error_in_case_no_qualified_payable_is_found";
        let now = SystemTime::now();
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let (_, unqualified_payable_accounts, _) = make_payables(now, payment_thresholds.clone());
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);

        let mut payable_scanner =
            PayableScanner::new(Box::new(payable_dao), Rc::new(payment_thresholds));

        let result = payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        assert_eq!(result, Err(String::from("No Qualified Payables found.")));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for payables", test_name),
            "Chose 0 qualified debts to pay",
        ]);
    }

    #[test]
    fn pending_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "pending_payable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let fingerprints = vec![PendingPayableFingerprint {
            rowid_opt: Some(1234),
            timestamp: SystemTime::now(),
            hash: Default::default(),
            attempt_opt: Some(1),
            amount: 1_000_000,
            process_error: None,
        }];
        let no_of_pending_payables = fingerprints.len();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(fingerprints.clone());
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let mut pending_payable_scanner =
            PendingPayableScanner::new(Box::new(pending_payable_dao), Rc::new(payment_thresholds));

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                pending_payable: fingerprints,
                response_skeleton_opt: None
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for pending payable", test_name),
            &format!(
                "DEBUG: {}: Found {} pending payables to process",
                test_name, no_of_pending_payables
            ),
        ])
    }

    #[test]
    fn pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found() {
        init_test_logging();
        let test_name = "pending_payable_scanner_throws_an_error_when_no_fingerprint_is_found";
        let now = SystemTime::now();
        let pending_payable_dao =
            PendingPayableDaoMock::new().return_all_fingerprints_result(vec![]);
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let mut pending_payable_scanner =
            PendingPayableScanner::new(Box::new(pending_payable_dao), Rc::new(payment_thresholds));

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        assert_eq!(result, Err(String::from("No pending payable found.")));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for pending payable", test_name),
            &format!(
                "DEBUG: {}: Pending payable scan ended. No pending payable found.",
                test_name
            ),
        ])
    }

    fn make_payables(
        now: SystemTime,
        payment_thresholds: PaymentThresholds,
    ) -> (
        Vec<PayableAccount>,
        Vec<PayableAccount>,
        Vec<PayableAccount>,
    ) {
        let mut unqualified_payable_accounts = vec![PayableAccount {
            wallet: make_wallet("wallet1"),
            balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec + 1,
            ),
            pending_payable_opt: None,
        }];
        let mut qualified_payable_accounts = vec![
            PayableAccount {
                wallet: make_wallet("wallet2"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1_000_000_000,
                last_paid_timestamp: from_time_t(
                    to_time_t(now) - payment_thresholds.maturity_threshold_sec - 1,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet3"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1_200_000_000,
                last_paid_timestamp: from_time_t(
                    to_time_t(now) - payment_thresholds.maturity_threshold_sec - 100,
                ),
                pending_payable_opt: None,
            },
        ];

        let mut all_non_pending_payables = Vec::new();
        all_non_pending_payables.extend(qualified_payable_accounts.clone());
        all_non_pending_payables.extend(unqualified_payable_accounts.clone());

        (
            qualified_payable_accounts,
            unqualified_payable_accounts,
            all_non_pending_payables,
        )
    }
}
