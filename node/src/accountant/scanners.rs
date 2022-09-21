// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub(in crate::accountant) mod scanners {
    use crate::accountant::payable_dao::{Payable, PayableDao, PayableDaoFactory};
    use crate::accountant::pending_payable_dao::{PendingPayableDao, PendingPayableDaoFactory};
    use crate::accountant::receivable_dao::ReceivableDao;
    use crate::accountant::tools::payable_scanner_tools::{
        investigate_debt_extremes, qualified_payables_and_summary, separate_early_errors,
    };
    use crate::accountant::tools::pending_payable_scanner_tools::{
        elapsed_in_ms, handle_none_status, handle_status_with_failure, handle_status_with_success,
    };
    use crate::accountant::tools::receivable_scanner_tools::balance_and_age;
    use crate::accountant::{
        Accountant, ConfirmPendingTransaction, ReceivedPayments, ReportTransactionReceipts,
        RequestTransactionReceipts, ResponseSkeleton, ScanForPayables, ScanForPendingPayables,
        ScanForReceivables, SentPayable,
    };
    use crate::accountant::{PendingPayableId, PendingTransactionStatus, ReportAccountsPayable};
    use crate::banned_dao::BannedDao;
    use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
    use crate::sub_lib::utils::{NotifyHandle, NotifyLaterHandle};
    use crate::sub_lib::wallet::Wallet;
    use actix::Message;
    use masq_lib::logger::Logger;
    use masq_lib::messages::{ToMessageBody, UiScanResponse};
    use masq_lib::ui_gateway::{MessageTarget, NodeToUiMessage};
    use masq_lib::utils::ExpectValue;
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::SystemTime;
    use web3::types::TransactionReceipt;

    #[derive(Debug, PartialEq, Eq)]
    pub enum ScannerError {
        NothingToProcess,
        ScanAlreadyRunning(SystemTime),
        CalledFromNullScanner, // Exclusive for tests
    }

    type Error = ScannerError;

    pub struct Scanners {
        pub payable: Box<dyn Scanner<ReportAccountsPayable, SentPayable>>,
        pub pending_payable:
            Box<dyn Scanner<RequestTransactionReceipts, ReportTransactionReceipts>>,
        pub receivable: Box<dyn Scanner<RetrieveTransactions, ReceivedPayments>>,
    }

    impl Scanners {
        pub fn new(
            payable_dao_factory: Box<dyn PayableDaoFactory>,
            pending_payable_dao_factory: Box<dyn PendingPayableDaoFactory>,
            receivable_dao: Box<dyn ReceivableDao>,
            banned_dao: Box<dyn BannedDao>,
            payment_thresholds: Rc<PaymentThresholds>,
            earning_wallet: Rc<Wallet>,
            when_pending_too_long_sec: u64,
            financial_statistics: Rc<RefCell<FinancialStatistics>>,
        ) -> Self {
            Scanners {
                payable: Box::new(PayableScanner::new(
                    payable_dao_factory.make(),
                    pending_payable_dao_factory.make(),
                    Rc::clone(&payment_thresholds),
                )),
                pending_payable: Box::new(PendingPayableScanner::new(
                    payable_dao_factory.make(),
                    pending_payable_dao_factory.make(),
                    Rc::clone(&payment_thresholds),
                    when_pending_too_long_sec,
                    financial_statistics,
                )),
                receivable: Box::new(ReceivableScanner::new(
                    receivable_dao,
                    banned_dao,
                    Rc::clone(&payment_thresholds),
                    earning_wallet,
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
        fn scan_finished(
            &mut self,
            message: EndMessage,
            logger: &Logger,
        ) -> Result<Option<NodeToUiMessage>, String>;
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
        payable_dao: Box<dyn PayableDao>,
        pending_payable_dao: Box<dyn PendingPayableDao>,
    }

    impl Scanner<ReportAccountsPayable, SentPayable> for PayableScanner {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<ReportAccountsPayable, Error> {
            if let Some(timestamp) = self.scan_started_at() {
                return Err(ScannerError::ScanAlreadyRunning(timestamp));
            }
            self.common.initiated_at_opt = Some(timestamp);
            info!(logger, "Scanning for payables");
            let all_non_pending_payables = self.payable_dao.non_pending_payables();
            debug!(
                logger,
                "{}",
                investigate_debt_extremes(timestamp, &all_non_pending_payables)
            );
            let (qualified_payables, summary) = qualified_payables_and_summary(
                timestamp,
                all_non_pending_payables,
                self.common.payment_thresholds.as_ref(),
            );
            info!(
                logger,
                "Chose {} qualified debts to pay",
                qualified_payables.len()
            );
            debug!(logger, "{}", summary);
            match qualified_payables.is_empty() {
                true => Err(ScannerError::NothingToProcess),
                false => Ok(ReportAccountsPayable {
                    accounts: qualified_payables,
                    response_skeleton_opt,
                }),
            }
        }

        fn scan_finished(
            &mut self,
            message: SentPayable,
            logger: &Logger,
        ) -> Result<Option<NodeToUiMessage>, String> {
            // Use the passed-in message and the internal DAO to finish the scan
            // Ok(())

            let (sent_payables, blockchain_errors) = separate_early_errors(&message, logger);
            debug!(
                logger,
                "We gathered these errors at sending transactions for payable: {:?}, out of the \
                total of {} attempts",
                blockchain_errors,
                sent_payables.len() + blockchain_errors.len()
            );

            self.handle_sent_payables(sent_payables, logger)?;
            self.handle_blockchain_errors(blockchain_errors, logger)?;

            let message_opt = match message.response_skeleton_opt {
                Some(response_skeleton) => Some(NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                }),
                None => None,
            };

            Ok(message_opt)
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        as_any_impl!();
    }

    impl PayableScanner {
        pub fn new(
            payable_dao: Box<dyn PayableDao>,
            pending_payable_dao: Box<dyn PendingPayableDao>,
            payment_thresholds: Rc<PaymentThresholds>,
        ) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
                payable_dao,
                pending_payable_dao,
            }
        }

        fn handle_sent_payables(
            &self,
            sent_payables: Vec<Payable>,
            logger: &Logger,
        ) -> Result<(), String> {
            for payable in sent_payables {
                if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(payable.tx_hash) {
                    if let Err(e) = self
                        .payable_dao
                        .as_ref()
                        .mark_pending_payable_rowid(&payable.to, rowid)
                    {
                        return Err(format!(
                            "Was unable to create a mark in payables for a new pending payable \
                            '{}' due to '{:?}'",
                            payable.tx_hash, e
                        ));
                    }
                } else {
                    return Err(format!(
                        "Payable fingerprint for {} doesn't exist but should by now; \
                        system unreliable",
                        payable.tx_hash
                    ));
                };

                debug!(
                    logger,
                    "Payable '{}' has been marked as pending in the payable table", payable.tx_hash
                )
            }

            Ok(())
        }

        fn handle_blockchain_errors(
            &self,
            blockchain_errors: Vec<BlockchainError>,
            logger: &Logger,
        ) -> Result<(), String> {
            for blockchain_error in blockchain_errors {
                if let Some(hash) = blockchain_error.carries_transaction_hash() {
                    if let Some(rowid) = self.pending_payable_dao.fingerprint_rowid(hash) {
                        debug!(
                            logger,
                            "Deleting an existing backup for a failed transaction {}", hash
                        );
                        if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                            return Err(format!(
                                "Database unmaintainable; payable fingerprint deletion for \
                                transaction {:?} has stayed undone due to {:?}",
                                hash, e
                            ));
                        };
                    };

                    warning!(
                        logger,
                        "Failed transaction with a hash '{}' but without the record - thrown out",
                        hash
                    )
                } else {
                    debug!(
                        logger,
                        "Forgetting a transaction attempt that even did not reach the signing stage"
                    )
                };
            }

            Ok(())
        }
    }

    pub struct PendingPayableScanner {
        common: ScannerCommon,
        payable_dao: Box<dyn PayableDao>,
        pending_payable_dao: Box<dyn PendingPayableDao>,
        when_pending_too_long_sec: u64,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    }

    impl Scanner<RequestTransactionReceipts, ReportTransactionReceipts> for PendingPayableScanner {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<RequestTransactionReceipts, Error> {
            if let Some(timestamp) = self.scan_started_at() {
                return Err(ScannerError::ScanAlreadyRunning(timestamp));
            }
            self.common.initiated_at_opt = Some(timestamp);
            info!(logger, "Scanning for pending payable");
            let filtered_pending_payable = self.pending_payable_dao.return_all_fingerprints();
            match filtered_pending_payable.is_empty() {
                true => {
                    debug!(
                        logger,
                        "Pending payable scan ended. No pending payable found."
                    );
                    Err(ScannerError::NothingToProcess)
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

        fn scan_finished(
            &mut self,
            message: ReportTransactionReceipts,
            logger: &Logger,
        ) -> Result<Option<NodeToUiMessage>, String> {
            // TODO: Make accountant to handle empty vector. Maybe log it as an error.
            debug!(
                logger,
                "Processing receipts for {} transactions",
                message.fingerprints_with_receipts.len()
            );
            let statuses = self.handle_pending_transaction_with_its_receipt(&message, logger);
            self.process_transaction_by_status(statuses, logger)?;

            let message_opt = match message.response_skeleton_opt {
                Some(response_skeleton) => Some(NodeToUiMessage {
                    target: MessageTarget::ClientId(response_skeleton.client_id),
                    body: UiScanResponse {}.tmb(response_skeleton.context_id),
                }),
                None => None,
            };

            Ok(message_opt)
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        as_any_impl!();
    }

    impl PendingPayableScanner {
        pub fn new(
            payable_dao: Box<dyn PayableDao>,
            pending_payable_dao: Box<dyn PendingPayableDao>,
            payment_thresholds: Rc<PaymentThresholds>,
            when_pending_too_long_sec: u64,
            financial_statistics: Rc<RefCell<FinancialStatistics>>,
        ) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
                payable_dao,
                pending_payable_dao,
                when_pending_too_long_sec,
                financial_statistics,
            }
        }

        pub(crate) fn handle_pending_transaction_with_its_receipt(
            &self,
            msg: &ReportTransactionReceipts,
            logger: &Logger,
        ) -> Vec<PendingTransactionStatus> {
            msg.fingerprints_with_receipts
                .iter()
                .map(|(receipt_opt, fingerprint)| match receipt_opt {
                    Some(receipt) => {
                        self.interpret_transaction_receipt(receipt, fingerprint, logger)
                    }
                    None => {
                        debug!(
                            logger,
                            "Interpreting a receipt for transaction '{}' but none was given; \
                            attempt {}, {}ms since sending",
                            fingerprint.hash,
                            fingerprint.attempt_opt.expectv("initialized attempt"),
                            elapsed_in_ms(fingerprint.timestamp)
                        );
                        PendingTransactionStatus::StillPending(PendingPayableId {
                            hash: fingerprint.hash,
                            rowid: fingerprint.rowid_opt.expectv("initialized rowid"),
                        })
                    }
                })
                .collect()
        }

        pub fn interpret_transaction_receipt(
            &self,
            receipt: &TransactionReceipt,
            fingerprint: &PendingPayableFingerprint,
            logger: &Logger,
        ) -> PendingTransactionStatus {
            match receipt.status {
                None => handle_none_status(fingerprint, self.when_pending_too_long_sec, logger),
                Some(status_code) =>
                    match status_code.as_u64() {
                        0 => handle_status_with_failure(fingerprint, logger),
                        1 => handle_status_with_success(fingerprint, logger),
                        other => unreachable!("tx receipt for pending '{}' - tx status: code other than 0 or 1 shouldn't be possible, but was {}", fingerprint.hash, other)
                    }
            }
        }

        fn process_transaction_by_status(
            &mut self,
            statuses: Vec<PendingTransactionStatus>,
            logger: &Logger,
        ) -> Result<(), String> {
            for status in statuses {
                match status {
                    PendingTransactionStatus::StillPending(transaction_id) => {
                        self.update_payable_fingerprint(transaction_id, logger)?;
                    }
                    PendingTransactionStatus::Failure(transaction_id) => {
                        self.order_cancel_failed_transaction(transaction_id, logger)?;
                    }
                    PendingTransactionStatus::Confirmed(fingerprint) => {
                        self.order_confirm_transaction(fingerprint, logger)?;
                    }
                }
            }

            Ok(())
        }

        pub(crate) fn update_payable_fingerprint(
            &self,
            pending_payable_id: PendingPayableId,
            logger: &Logger,
        ) -> Result<(), String> {
            match self
                .pending_payable_dao
                .update_fingerprint(pending_payable_id.rowid)
            {
                Ok(_) => {
                    trace!(
                        logger,
                        "Updated record for rowid: {} ",
                        pending_payable_id.rowid
                    );
                    Ok(())
                }
                Err(e) => Err(format!(
                    "Failure on updating payable fingerprint '{:?}' due to {:?}",
                    pending_payable_id.hash, e
                )),
            }
        }

        pub fn order_cancel_failed_transaction(
            &self,
            transaction_id: PendingPayableId,
            logger: &Logger,
        ) -> Result<(), String> {
            match self.pending_payable_dao.mark_failure(transaction_id.rowid) {
                Ok(_) => {
                    warning!(
                        logger,
                        "Broken transaction {} left with an error mark; you should take over the care \
                        of this transaction to make sure your debts will be paid because there is no \
                        automated process that can fix this without you", transaction_id.hash
                    );

                    Ok(())
                }
                Err(e) => Err(format!(
                    "Unsuccessful attempt for transaction {} to mark fatal error at payable \
                    fingerprint due to {:?}; database unreliable",
                    transaction_id.hash, e
                )),
            }
        }

        fn order_confirm_transaction(
            &mut self,
            pending_payable_fingerprint: PendingPayableFingerprint,
            logger: &Logger,
        ) -> Result<(), String> {
            let hash = pending_payable_fingerprint.hash;
            let amount = pending_payable_fingerprint.amount;
            let rowid = pending_payable_fingerprint
                .rowid_opt
                .expectv("initialized rowid");

            if let Err(e) = self
                .payable_dao
                .transaction_confirmed(&pending_payable_fingerprint)
            {
                Err(format!(
                    "Was unable to uncheck pending payable '{}' after confirmation due to '{:?}'",
                    hash, e
                ))
            } else {
                let mut financial_statistics = self.financial_statistics.as_ref().borrow().clone();
                financial_statistics.total_paid_payable += amount;
                self.financial_statistics.replace(financial_statistics);
                debug!(
                    logger,
                    "Confirmation of transaction {}; record for payable was modified", hash
                );
                if let Err(e) = self.pending_payable_dao.delete_fingerprint(rowid) {
                    Err(format!(
                        "Was unable to delete payable fingerprint '{}' after successful transaction \
                        due to '{:?}'", hash, e
                    ))
                } else {
                    info!(
                        logger,
                        "Transaction {:?} has gone through the whole confirmation process succeeding",
                        hash
                    );

                    Ok(())
                }
            }
        }
    }

    pub struct ReceivableScanner {
        common: ScannerCommon,
        dao: Box<dyn ReceivableDao>,
        banned_dao: Box<dyn BannedDao>,
        earning_wallet: Rc<Wallet>,
    }

    impl Scanner<RetrieveTransactions, ReceivedPayments> for ReceivableScanner {
        fn begin_scan(
            &mut self,
            timestamp: SystemTime,
            response_skeleton_opt: Option<ResponseSkeleton>,
            logger: &Logger,
        ) -> Result<RetrieveTransactions, Error> {
            if let Some(timestamp) = self.scan_started_at() {
                return Err(ScannerError::ScanAlreadyRunning(timestamp));
            }
            self.common.initiated_at_opt = Some(timestamp);
            info!(
                logger,
                "Scanning for receivables to {}", self.earning_wallet
            );
            info!(logger, "Scanning for delinquencies");
            self.dao
                .new_delinquencies(timestamp, self.common.payment_thresholds.as_ref())
                .into_iter()
                .for_each(|account| {
                    self.banned_dao.ban(&account.wallet);
                    let (balance, age) = balance_and_age(timestamp, &account);
                    info!(
                        logger,
                        "Wallet {} (balance: {} MASQ, age: {} sec) banned for delinquency",
                        account.wallet,
                        balance,
                        age.as_secs()
                    )
                });
            self.dao
                .paid_delinquencies(self.common.payment_thresholds.as_ref())
                .into_iter()
                .for_each(|account| {
                    self.banned_dao.unban(&account.wallet);
                    let (balance, age) = balance_and_age(timestamp, &account);
                    info!(
                        logger,
                        "Wallet {} (balance: {} MASQ, age: {} sec) is no longer delinquent: unbanned",
                        account.wallet,
                        balance,
                        age.as_secs()
                    )
                });

            Ok(RetrieveTransactions {
                recipient: self.earning_wallet.as_ref().clone(),
                response_skeleton_opt,
            })
        }

        fn scan_finished(
            &mut self,
            _message: ReceivedPayments,
            _logger: &Logger,
        ) -> Result<Option<NodeToUiMessage>, String> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        as_any_impl!();
    }

    impl ReceivableScanner {
        pub fn new(
            dao: Box<dyn ReceivableDao>,
            banned_dao: Box<dyn BannedDao>,
            payment_thresholds: Rc<PaymentThresholds>,
            earning_wallet: Rc<Wallet>,
        ) -> Self {
            Self {
                common: ScannerCommon::new(payment_thresholds),
                earning_wallet,
                dao,
                banned_dao,
            }
        }
    }

    pub struct NullScanner {}

    impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage> for NullScanner
    where
        BeginMessage: Message,
        EndMessage: Message,
    {
        fn begin_scan(
            &mut self,
            _timestamp: SystemTime,
            _response_skeleton_opt: Option<ResponseSkeleton>,
            _logger: &Logger,
        ) -> Result<BeginMessage, Error> {
            Err(ScannerError::CalledFromNullScanner)
        }

        fn scan_finished(
            &mut self,
            _message: EndMessage,
            _logger: &Logger,
        ) -> Result<Option<NodeToUiMessage>, String> {
            todo!()
        }

        fn scan_started_at(&self) -> Option<SystemTime> {
            todo!()
        }

        as_any_impl!();
    }

    impl NullScanner {
        pub fn new() -> Self {
            Self {}
        }
    }

    // pub struct ScannerMock<BeginMessage, EndMessage> {
    //     begin_scan_params: RefCell<Vec<(SystemTime, Option<ResponseSkeleton>)>>,
    //     begin_scan_results: Arc<Mutex<Vec<Result<Box<BeginMessage>, Error>>>>,
    //     end_scan_params: RefCell<Vec<EndMessage>>,
    //     end_scan_results: Arc<Mutex<Vec<Result<(), Error>>>>,
    // }
    //
    // impl<BeginMessage, EndMessage> Scanner<BeginMessage, EndMessage>
    //     for ScannerMock<BeginMessage, EndMessage>
    // where
    //     BeginMessage: Message,
    //     EndMessage: Message,
    // {
    //     fn begin_scan(
    //         &mut self,
    //         _timestamp: SystemTime,
    //         _response_skeleton_opt: Option<ResponseSkeleton>,
    //         _logger: &Logger,
    //     ) -> Result<BeginMessage, Error> {
    //         todo!("Implement ScannerMock")
    //     }
    //
    //     fn scan_finished(&mut self, _message: EndMessage) -> Result<(), Error> {
    //         todo!()
    //     }
    //
    //     fn scan_started_at(&self) -> Option<SystemTime> {
    //         todo!()
    //     }
    // }
    //
    // impl<BeginMessage, EndMessage> ScannerMock<BeginMessage, EndMessage> {
    //     pub fn new() -> Self {
    //         Self {
    //             begin_scan_params: RefCell::new(vec![]),
    //             begin_scan_results: Arc::new(Mutex::new(vec![])),
    //             end_scan_params: RefCell::new(vec![]),
    //             end_scan_results: Arc::new(Mutex::new(vec![])),
    //         }
    //     }
    //
    //     pub fn begin_scan_params(
    //         mut self,
    //         params: Vec<(SystemTime, Option<ResponseSkeleton>)>,
    //     ) -> Self {
    //         self.begin_scan_params = RefCell::new(params);
    //         self
    //     }
    //
    //     pub fn begin_scan_result(self, result: Result<Box<BeginMessage>, Error>) -> Self {
    //         self.begin_scan_results
    //             .lock()
    //             .unwrap()
    //             .borrow_mut()
    //             .push(result);
    //         self
    //     }
    // }

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
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::scanners::{
        PayableScanner, PendingPayableScanner, ReceivableScanner, Scanner, ScannerError, Scanners,
    };
    use crate::accountant::test_utils::{
        make_payables, make_pending_payable_fingerprint, make_receivable_account, BannedDaoMock,
        PayableDaoFactoryMock, PayableDaoMock, PendingPayableDaoFactoryMock, PendingPayableDaoMock,
        ReceivableDaoMock,
    };
    use crate::accountant::{
        PendingPayableId, PendingTransactionStatus, ReportTransactionReceipts,
        RequestTransactionReceipts, SentPayable, DEFAULT_PENDING_TOO_LONG_SEC,
    };
    use crate::blockchain::blockchain_bridge::{PendingPayableFingerprint, RetrieveTransactions};
    use std::cell::RefCell;
    use std::ops::Sub;

    use crate::accountant::payable_dao::{Payable, PayableDaoError};
    use crate::accountant::pending_payable_dao::PendingPayableDaoError;
    use crate::blockchain::blockchain_interface::BlockchainError;
    use crate::database::dao_utils::from_time_t;
    use crate::sub_lib::accountant::{FinancialStatistics, PaymentThresholds};
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::make_payment_thresholds_with_defaults;
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, SystemTime};
    use web3::types::{TransactionReceipt, H256, U256};

    impl Default for PendingPayableScanner {
        fn default() -> Self {
            PendingPayableScanner::new(
                Box::new(PayableDaoMock::new()),
                Box::new(PendingPayableDaoMock::new()),
                Rc::new(make_payment_thresholds_with_defaults()),
                DEFAULT_PENDING_TOO_LONG_SEC,
                Rc::new(RefCell::new(FinancialStatistics::default())),
            )
        }
    }

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payment_thresholds = Rc::new(make_payment_thresholds_with_defaults());
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_result(PayableDaoMock::new())
            .make_result(PayableDaoMock::new());
        let pending_payable_dao_factory = PendingPayableDaoFactoryMock::new()
            .make_result(PendingPayableDaoMock::new())
            .make_result(PendingPayableDaoMock::new());
        let scanners = Scanners::new(
            Box::new(payable_dao_factory),
            Box::new(pending_payable_dao_factory),
            Box::new(ReceivableDaoMock::new()),
            Box::new(BannedDaoMock::new()),
            Rc::clone(&payment_thresholds),
            Rc::new(make_wallet("earning")),
            0,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        );

        scanners
            .payable
            .as_any()
            .downcast_ref::<PayableScanner>()
            .unwrap();
        scanners
            .pending_payable
            .as_any()
            .downcast_ref::<PendingPayableScanner>()
            .unwrap();
        scanners
            .receivable
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
            make_payables(now, &payment_thresholds);
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(all_non_pending_payables);

        let mut payable_scanner = PayableScanner::new(
            Box::new(payable_dao),
            Box::new(PendingPayableDaoMock::new()),
            Rc::new(payment_thresholds),
        );

        let result = payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let timestamp = payable_scanner.scan_started_at();
        let run_again_result =
            payable_scanner.begin_scan(SystemTime::now(), None, &Logger::new(test_name));
        assert_eq!(
            result,
            Ok(ReportAccountsPayable {
                accounts: qualified_payable_accounts.clone(),
                response_skeleton_opt: None,
            })
        );
        assert_eq!(timestamp, Some(now));
        assert_eq!(run_again_result, Err(ScannerError::ScanAlreadyRunning(now)));
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
        let (_, unqualified_payable_accounts, _) = make_payables(now, &payment_thresholds);
        let payable_dao =
            PayableDaoMock::new().non_pending_payables_result(unqualified_payable_accounts);

        let mut payable_scanner = PayableScanner::new(
            Box::new(payable_dao),
            Box::new(PendingPayableDaoMock::new()),
            Rc::new(payment_thresholds),
        );

        let result = payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        assert_eq!(result, Err(ScannerError::NothingToProcess));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for payables", test_name),
            "Chose 0 qualified debts to pay",
        ]);
    }

    #[test]
    fn payable_scanner_throws_error_when_fingerprint_is_not_found() {
        init_test_logging();
        let now_system = SystemTime::now();
        let payment_hash = H256::from_uint(&U256::from(789));
        let payable = Payable::new(make_wallet("booga"), 6789, payment_hash, now_system);
        let payable_dao = PayableDaoMock::new().mark_pending_payable_rowid_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().fingerprint_rowid_result(None);
        let mut subject = PayableScanner::new(
            Box::new(payable_dao),
            Box::new(pending_payable_dao),
            Rc::new(make_payment_thresholds_with_defaults()),
        );
        let sent_payable = SentPayable {
            payable: vec![Ok(payable)],
            response_skeleton_opt: None,
        };

        let result = subject.scan_finished(sent_payable, &Logger::new("test"));

        assert_eq!(result, Err("Payable fingerprint for 0x0000…0315 doesn't exist but should by now; system unreliable".to_string()));
    }

    #[test]
    fn payable_scanner_throws_error_when_dealing_with_failed_payment_fails_to_delete_the_existing_pending_payable_fingerprint(
    ) {
        let rowid = 4;
        let hash = H256::from_uint(&U256::from(123));
        let sent_payable = SentPayable {
            payable: vec![Err(BlockchainError::TransactionFailed {
                msg: "blah".to_string(),
                hash_opt: Some(hash),
            })],
            response_skeleton_opt: None,
        };
        let pending_payable_dao = PendingPayableDaoMock::default()
            .fingerprint_rowid_result(Some(rowid))
            .delete_fingerprint_result(Err(PendingPayableDaoError::RecordDeletion(
                "we slept over, sorry".to_string(),
            )));
        let mut subject = PayableScanner::new(
            Box::new(PayableDaoMock::new()),
            Box::new(pending_payable_dao),
            Rc::new(make_payment_thresholds_with_defaults()),
        );

        let result = subject.scan_finished(sent_payable, &Logger::new("test"));

        assert_eq!(
            result,
            Err(
                "Database unmaintainable; payable fingerprint deletion for transaction \
                0x000000000000000000000000000000000000000000000000000000000000007b has stayed \
                undone due to RecordDeletion(\"we slept over, sorry\")"
                    .to_string()
            )
        );
    }

    #[test]
    fn payable_scanner_throws_error_when_it_fails_to_make_a_mark_in_payables() {
        let payable = Payable::new(
            make_wallet("blah"),
            6789,
            H256::from_uint(&U256::from(123)),
            SystemTime::now(),
        );
        let payable_dao = PayableDaoMock::new()
            .mark_pending_payable_rowid_result(Err(PayableDaoError::SignConversion(9999999999999)));
        let pending_payable_dao =
            PendingPayableDaoMock::default().fingerprint_rowid_result(Some(7879));
        let mut subject = PayableScanner::new(
            Box::new(payable_dao),
            Box::new(pending_payable_dao),
            Rc::new(make_payment_thresholds_with_defaults()),
        );
        let sent_payable = SentPayable {
            payable: vec![Ok(payable)],
            response_skeleton_opt: None,
        };

        let result = subject.scan_finished(sent_payable, &Logger::new("test"));

        assert_eq!(
            result,
            Err(
                "Was unable to create a mark in payables for a new pending payable '0x0000…007b' \
                due to 'SignConversion(9999999999999)'"
                    .to_string()
            )
        )
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
        let mut pending_payable_scanner = PendingPayableScanner::new(
            Box::new(PayableDaoMock::new()),
            Box::new(pending_payable_dao),
            Rc::new(payment_thresholds),
            0,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        );

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let timestamp = pending_payable_scanner.scan_started_at();
        let run_again_result =
            pending_payable_scanner.begin_scan(SystemTime::now(), None, &Logger::new(test_name));
        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                pending_payable: fingerprints,
                response_skeleton_opt: None
            })
        );
        assert_eq!(timestamp, Some(now));
        assert_eq!(run_again_result, Err(ScannerError::ScanAlreadyRunning(now)));
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
        let mut pending_payable_scanner = PendingPayableScanner::new(
            Box::new(PayableDaoMock::new()),
            Box::new(pending_payable_dao),
            Rc::new(payment_thresholds),
            0,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        );

        let result = pending_payable_scanner.begin_scan(now, None, &Logger::new(test_name));

        assert_eq!(result, Err(ScannerError::NothingToProcess));
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {}: Scanning for pending payable", test_name),
            &format!(
                "DEBUG: {}: Pending payable scan ended. No pending payable found.",
                test_name
            ),
        ])
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_outside_waiting_interval()
    {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent =
            SystemTime::now().sub(Duration::from_secs(DEFAULT_PENDING_TOO_LONG_SEC + 5)); //old transaction
        let subject = PendingPayableScanner::default();
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: when_sent,
            hash,
            attempt_opt: Some(10),
            amount: 123,
            process_error: None,
        };

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: receipt_check_logger: Pending transaction '0x0000…0237' has exceeded the maximum \
             pending time (21600sec) and the confirmation process is going to be aborted now at the final attempt 10; manual resolution is required from the user to \
               complete the transaction",
        );
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_none_and_within_waiting_interval() {
        init_test_logging();
        let hash = H256::from_uint(&U256::from(567));
        let rowid = 466;
        let tx_receipt = TransactionReceipt::default(); //status defaulted to None
        let when_sent = SystemTime::now().sub(Duration::from_millis(100));
        let subject = PendingPayableScanner::default();
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: when_sent,
            hash,
            attempt_opt: Some(1),
            amount: 123,
            process_error: None,
        };

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("none_within_waiting"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::StillPending(PendingPayableId { hash, rowid })
        );
        TestLogHandler::new().exists_log_containing(
            "INFO: none_within_waiting: Pending \
         transaction '0x0000…0237' couldn't be confirmed at attempt 1 at ",
        );
    }

    #[test]
    #[should_panic(
        expected = "tx receipt for pending '0x0000…007b' - tx status: code other than 0 or 1 shouldn't be possible, but was 456"
    )]
    fn interpret_transaction_receipt_panics_at_undefined_status_code() {
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(456));
        let mut fingerprint = make_pending_payable_fingerprint();
        fingerprint.hash = H256::from_uint(&U256::from(123));
        let subject = PendingPayableScanner::default();

        let _ = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );
    }

    #[test]
    fn interpret_transaction_receipt_when_transaction_status_is_a_failure() {
        init_test_logging();
        let subject = PendingPayableScanner::default();
        let mut tx_receipt = TransactionReceipt::default();
        tx_receipt.status = Some(U64::from(0)); //failure
        let hash = H256::from_uint(&U256::from(4567));
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(777777),
            timestamp: SystemTime::now().sub(Duration::from_millis(150000)),
            hash,
            attempt_opt: Some(5),
            amount: 2222,
            process_error: None,
        };

        let result = subject.interpret_transaction_receipt(
            &tx_receipt,
            &fingerprint,
            &Logger::new("receipt_check_logger"),
        );

        assert_eq!(
            result,
            PendingTransactionStatus::Failure(PendingPayableId {
                hash,
                rowid: 777777,
            })
        );
        TestLogHandler::new().exists_log_matching("ERROR: receipt_check_logger: Pending \
         transaction '0x0000…11d7' announced as a failure, interpreting attempt 5 after 1500\\d\\dms from the sending");
    }

    #[test]
    fn handle_pending_tx_handles_none_returned_for_transaction_receipt() {
        init_test_logging();
        let subject = PendingPayableScanner::default();
        let tx_receipt_opt = None;
        let rowid = 455;
        let hash = H256::from_uint(&U256::from(2323));
        let fingerprint = PendingPayableFingerprint {
            rowid_opt: Some(rowid),
            timestamp: SystemTime::now().sub(Duration::from_millis(10000)),
            hash,
            attempt_opt: Some(3),
            amount: 111,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![(tx_receipt_opt, fingerprint.clone())],
            response_skeleton_opt: None,
        };

        let result = subject
            .handle_pending_transaction_with_its_receipt(&msg, &Logger::new("Handle Pending Tx"));

        assert_eq!(
            result,
            vec![PendingTransactionStatus::StillPending(PendingPayableId {
                hash,
                rowid,
            })]
        );
        TestLogHandler::new()
            .exists_log_matching("DEBUG: Handle Pending Tx: Interpreting a receipt for transaction '0x0000…0913' but none was given; attempt 3, 100\\d\\dms since sending");
    }

    #[test]
    fn update_payable_fingerprint_happy_path() {
        let test_name = "update_payable_fingerprint_happy_path";
        let update_after_cycle_params_arc = Arc::new(Mutex::new(vec![]));
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default()
            .update_fingerprint_params(&update_after_cycle_params_arc)
            .update_fingerprint_results(Ok(()));
        let subject =
            make_pending_payable_scanner_from_daos(PayableDaoMock::new(), pending_payable_dao);
        let transaction_id = PendingPayableId { hash, rowid };

        let result = subject.update_payable_fingerprint(transaction_id, &Logger::new(test_name));

        let update_after_cycle_params = update_after_cycle_params_arc.lock().unwrap();
        assert_eq!(*update_after_cycle_params, vec![rowid])
    }

    #[test]
    fn update_payable_fingerprint_sad_path() {
        let test_name = "update_payable_fingerprint_sad_path";
        let hash = H256::from_uint(&U256::from(444888));
        let rowid = 3456;
        let pending_payable_dao = PendingPayableDaoMock::default().update_fingerprint_results(Err(
            PendingPayableDaoError::UpdateFailed("yeah, bad".to_string()),
        ));
        let subject =
            make_pending_payable_scanner_from_daos(PayableDaoMock::new(), pending_payable_dao);
        let transaction_id = PendingPayableId { hash, rowid };

        let result = subject.update_payable_fingerprint(transaction_id, &Logger::new(test_name));

        assert_eq!(
            result,
            Err("Failure on updating payable fingerprint \
                '0x000000000000000000000000000000000000000000000000000000000006c9d8' \
                due to UpdateFailed(\"yeah, bad\")"
                .to_string())
        )
    }

    #[test]
    fn order_cancel_pending_transaction_works() {
        init_test_logging();
        let mark_failure_params_arc = Arc::new(Mutex::new(vec![]));
        let pending_payable_dao = PendingPayableDaoMock::default()
            .mark_failure_params(&mark_failure_params_arc)
            .mark_failure_result(Ok(()));
        let subject =
            make_pending_payable_scanner_from_daos(PayableDaoMock::new(), pending_payable_dao);
        let tx_hash = H256::from("sometransactionhash".keccak256());
        let rowid = 2;
        let transaction_id = PendingPayableId {
            hash: tx_hash,
            rowid,
        };

        let result = subject
            .order_cancel_failed_transaction(transaction_id, &Logger::new("CancelPendingTxOk"));

        let mark_failure_params = mark_failure_params_arc.lock().unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(*mark_failure_params, vec![rowid]);
        TestLogHandler::new().exists_log_containing(
            "WARN: CancelPendingTxOk: Broken transaction 0x051a…8c19 left with an error \
            mark; you should take over the care of this transaction to make sure your debts will \
            be paid because there is no automated process that can fix this without you",
        );
    }

    #[test]
    fn order_cancel_pending_transaction_throws_error_when_it_fails_to_mark_failure() {
        let payable_dao = PayableDaoMock::default().transaction_canceled_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::default().mark_failure_result(Err(
            PendingPayableDaoError::UpdateFailed("no no no".to_string()),
        ));
        let subject = make_pending_payable_scanner_from_daos(payable_dao, pending_payable_dao);
        let rowid = 2;
        let hash = H256::from("sometransactionhash".keccak256());
        let transaction_id = PendingPayableId { hash, rowid };

        let result = subject
            .order_cancel_failed_transaction(transaction_id, &Logger::new("CancelPendingTxOk"));

        assert_eq!(
            result,
            Err(
                "Unsuccessful attempt for transaction 0x051a…8c19 to mark fatal error at payable \
                fingerprint due to UpdateFailed(\"no no no\"); database unreliable"
                    .to_string()
            )
        )
    }

    #[test]
    fn pending_payable_scanner_handles_report_transaction_receipts_message() {
        init_test_logging();
        let test_name = "accountant_receives_reported_transaction_receipts_and_processes_them_all";
        let transaction_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao = PayableDaoMock::new()
            .transaction_confirmed_params(&transaction_confirmed_params_arc)
            .transaction_confirmed_result(Ok(()))
            .transaction_confirmed_result(Ok(()));
        let pending_payable_dao = PendingPayableDaoMock::new()
            .delete_fingerprint_result(Ok(()))
            .delete_fingerprint_result(Ok(()));
        let mut subject = PendingPayableScanner::new(
            Box::new(payable_dao),
            Box::new(pending_payable_dao),
            Rc::new(make_payment_thresholds_with_defaults()),
            DEFAULT_PENDING_TOO_LONG_SEC,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        );
        let transaction_hash_1 = H256::from_uint(&U256::from(4545));
        let mut transaction_receipt_1 = TransactionReceipt::default();
        transaction_receipt_1.transaction_hash = transaction_hash_1;
        transaction_receipt_1.status = Some(U64::from(1)); //success
        let fingerprint_1 = PendingPayableFingerprint {
            rowid_opt: Some(5),
            timestamp: from_time_t(200_000_000),
            hash: transaction_hash_1,
            attempt_opt: Some(2),
            amount: 444,
            process_error: None,
        };
        let transaction_hash_2 = H256::from_uint(&U256::from(1234));
        let mut transaction_receipt_2 = TransactionReceipt::default();
        transaction_receipt_2.transaction_hash = transaction_hash_2;
        transaction_receipt_2.status = Some(U64::from(1)); //success
        let fingerprint_2 = PendingPayableFingerprint {
            rowid_opt: Some(10),
            timestamp: from_time_t(199_780_000),
            hash: transaction_hash_2,
            attempt_opt: Some(15),
            amount: 1212,
            process_error: None,
        };
        let msg = ReportTransactionReceipts {
            fingerprints_with_receipts: vec![
                (Some(transaction_receipt_1), fingerprint_1.clone()),
                (Some(transaction_receipt_2), fingerprint_2.clone()),
            ],
            response_skeleton_opt: None,
        };

        let result = subject.scan_finished(msg, &Logger::new(test_name));

        let transaction_confirmed_params = transaction_confirmed_params_arc.lock().unwrap();
        assert_eq!(result, Ok(None));
        assert_eq!(
            *transaction_confirmed_params,
            vec![fingerprint_1, fingerprint_2]
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!(
                "INFO: {}: Transaction {:?} has gone through the whole confirmation process succeeding",
                test_name, transaction_hash_1
            ),
            &format!(
                "INFO: {}: Transaction {:?} has gone through the whole confirmation process succeeding",
                test_name, transaction_hash_2
            ),
        ]);
    }

    #[test]
    fn receivable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "receivable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let banned_dao = BannedDaoMock::new();
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let earning_wallet = make_wallet("earning");
        let mut receivable_scanner = ReceivableScanner::new(
            Box::new(receivable_dao),
            Box::new(banned_dao),
            Rc::new(payment_thresholds),
            Rc::new(earning_wallet.clone()),
        );

        let result = receivable_scanner.begin_scan(now, None, &Logger::new(test_name));

        let timestamp = receivable_scanner.scan_started_at();
        let run_again_result =
            receivable_scanner.begin_scan(SystemTime::now(), None, &Logger::new(test_name));
        assert_eq!(
            result,
            Ok(RetrieveTransactions {
                recipient: earning_wallet.clone(),
                response_skeleton_opt: None
            })
        );
        assert_eq!(timestamp, Some(now));
        assert_eq!(run_again_result, Err(ScannerError::ScanAlreadyRunning(now)));
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {}: Scanning for receivables to {}",
            test_name, earning_wallet
        ));
    }

    #[test]
    fn receivable_scanner_scans_for_delinquencies() {
        init_test_logging();
        let newly_banned_1 = make_receivable_account(1234, true);
        let newly_banned_2 = make_receivable_account(2345, true);
        let newly_unbanned_1 = make_receivable_account(3456, false);
        let newly_unbanned_2 = make_receivable_account(4567, false);
        let new_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_parameters_arc)
            .new_delinquencies_result(vec![newly_banned_1.clone(), newly_banned_2.clone()])
            .paid_delinquencies_parameters(&paid_delinquencies_parameters_arc)
            .paid_delinquencies_result(vec![newly_unbanned_1.clone(), newly_unbanned_2.clone()]);
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let payment_thresholds = make_payment_thresholds_with_defaults();
        let mut receivable_scanner = ReceivableScanner::new(
            Box::new(receivable_dao),
            Box::new(banned_dao),
            Rc::new(payment_thresholds.clone()),
            Rc::new(make_wallet("earning")),
        );

        let _result = receivable_scanner.begin_scan(
            SystemTime::now(),
            None,
            &Logger::new("DELINQUENCY_TEST"),
        );

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentThresholds)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(
            payment_thresholds.clone(),
            new_delinquencies_parameters[0].1
        );
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentThresholds>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(payment_thresholds.clone(), paid_delinquencies_parameters[0]);
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet));
        assert!(ban_parameters.contains(&newly_banned_2.wallet));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching("INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743132333464 \\(balance: 1234 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743233343564 \\(balance: 2345 MASQ, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching("INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574333435366e \\(balance: 3456 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
        tlh.exists_log_matching("INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574343536376e \\(balance: 4567 MASQ, age: \\d+ sec\\) is no longer delinquent: unbanned");
    }

    fn make_pending_payable_scanner_from_daos(
        payable_dao: PayableDaoMock,
        pending_payable_dao: PendingPayableDaoMock,
    ) -> PendingPayableScanner {
        PendingPayableScanner::new(
            Box::new(payable_dao),
            Box::new(pending_payable_dao),
            Rc::new(make_payment_thresholds_with_defaults()),
            DEFAULT_PENDING_TOO_LONG_SEC,
            Rc::new(RefCell::new(FinancialStatistics::default())),
        )
    }
}
