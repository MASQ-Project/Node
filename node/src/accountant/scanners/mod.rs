// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod payable_scanner;
pub mod pending_payable_scanner;
pub mod receivable_scanner;
pub mod scan_schedulers;
pub mod test_utils;

use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::accountant::scanners::payable_scanner::finish_scan::PayableScannerCleanupArgs;
use crate::accountant::scanners::payable_scanner::msgs::{
    InitialTemplatesMessage, PricedTemplatesMessage,
};
use crate::accountant::scanners::payable_scanner::payment_adjuster_integration::PreparedAdjustment;
use crate::accountant::scanners::payable_scanner::utils::{NextScanToRun, PayableScanResult};
use crate::accountant::scanners::payable_scanner::{MultistageDualPayableScanner, PayableScanner};
use crate::accountant::scanners::pending_payable_scanner::utils::PendingPayableScanResult;
use crate::accountant::scanners::pending_payable_scanner::{
    PendingPayablePrivateScanner, PendingPayableScanner, PendingPayableScannerCleanupArgs,
};
use crate::accountant::scanners::receivable_scanner::{
    ReceivablePrivateScanner, ReceivableScanner, ReceivableScannerCleanupArgs,
};
use crate::accountant::{
    PayableScanType, ReceivedPayments, RequestTransactionReceipts, ResponseSkeleton, ScanError,
    ScanForNewPayables, ScanForReceivables, ScanForRetryPayables, SentPayables, TxReceiptsMessage,
};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::db_config::persistent_configuration::PersistentConfigurationReal;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
use crate::sub_lib::blockchain_bridge::{OutboundPaymentsInstructions, ScanErrorPayload};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;
use masq_lib::logger::TIME_FORMATTING_STRING;
use masq_lib::messages::ScanType;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::time::SystemTime;
use time::format_description::parse;
use time::OffsetDateTime;
use variant_count::VariantCount;

// Leave the individual scanner objects private!
pub struct Scanners {
    payable: Box<dyn MultistageDualPayableScanner>,
    aware_of_unresolved_pending_payable: bool,
    initial_pending_payable_scan: bool,
    pending_payable: Box<dyn PendingPayablePrivateScanner>,
    receivable: Box<dyn ReceivablePrivateScanner>,
}

impl Scanners {
    pub fn new(
        dao_factories: DaoFactories,
        payment_thresholds: Rc<PaymentThresholds>,
        financial_statistics: Rc<RefCell<FinancialStatistics>>,
    ) -> Self {
        let payable = Box::new(PayableScanner::new(
            dao_factories.payable_dao_factory.make(),
            dao_factories.sent_payable_dao_factory.make(),
            dao_factories.failed_payable_dao_factory.make(),
            Rc::clone(&payment_thresholds),
            Box::new(PaymentAdjusterReal::new()),
        ));

        let pending_payable = Box::new(PendingPayableScanner::new(
            dao_factories.payable_dao_factory.make(),
            dao_factories.sent_payable_dao_factory.make(),
            dao_factories.failed_payable_dao_factory.make(),
            Rc::clone(&payment_thresholds),
            Rc::clone(&financial_statistics),
        ));

        let persistent_configuration =
            PersistentConfigurationReal::from(dao_factories.config_dao_factory.make());

        let receivable = Box::new(ReceivableScanner::new(
            dao_factories.receivable_dao_factory.make(),
            dao_factories.banned_dao_factory.make(),
            Box::new(persistent_configuration),
            Rc::clone(&payment_thresholds),
            financial_statistics,
        ));

        Scanners {
            payable,
            aware_of_unresolved_pending_payable: false,
            initial_pending_payable_scan: true,
            pending_payable,
            receivable,
        }
    }

    pub fn start_new_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<InitialTemplatesMessage, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                ManulTriggerError::AutomaticScanConflict,
            ));
        }
        if let Some(started_at) = self.payable.scan_started_at() {
            return Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at,
            });
        }

        Self::start_correct_payable_scanner::<ScanForNewPayables>(
            &mut *self.payable,
            wallet,
            timestamp,
            response_skeleton_opt,
            logger,
        )
    }

    // Note: This scanner cannot be started on its own. It always runs after the pending payable
    // scan, but only if it is clear that a retry is needed.
    pub fn start_retry_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<InitialTemplatesMessage, StartScanError> {
        if let Some(started_at) = self.payable.scan_started_at() {
            unreachable!(
                "Guards should ensure that no payable scanner can run if the pending payable \
                 repetitive sequence is still ongoing. However, some other payable scan intruded \
                 at {} and is still running at {}",
                StartScanError::timestamp_as_string(started_at),
                StartScanError::timestamp_as_string(SystemTime::now())
            )
        }

        Self::start_correct_payable_scanner::<ScanForRetryPayables>(
            &mut *self.payable,
            wallet,
            timestamp,
            response_skeleton_opt,
            logger,
        )
    }

    pub fn start_pending_payable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<RequestTransactionReceipts, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        self.check_general_conditions_for_pending_payable_scan(
            triggered_manually,
            automatic_scans_enabled,
        )?;
        match (
            self.pending_payable.scan_started_at(),
            self.payable.scan_started_at(),
        ) {
            (Some(pp_timestamp), Some(p_timestamp)) =>
            // If you're wondering, then yes, this condition should be the sacred truth between
            // PendingPayableScanner and NewPayableScanner.
            {
                unreachable!(
                    "Any payable-related scanners should never be allowed to run in parallel. \
                    Scan for pending payables started at: {}, scan for payables started at: {}",
                    StartScanError::timestamp_as_string(pp_timestamp),
                    StartScanError::timestamp_as_string(p_timestamp)
                )
            }
            (Some(started_at), None) => {
                return Err(StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: None,
                    started_at,
                })
            }
            (None, Some(started_at)) => {
                return Err(StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: Some(ScanType::Payables),
                    started_at,
                })
            }
            (None, None) => (),
        }

        self.pending_payable
            .start_scan(wallet, timestamp, response_skeleton_opt, logger)
    }

    pub fn start_receivable_scan_guarded(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
        automatic_scans_enabled: bool,
    ) -> Result<RetrieveTransactions, StartScanError> {
        let triggered_manually = response_skeleton_opt.is_some();
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                ManulTriggerError::AutomaticScanConflict,
            ));
        }
        if let Some(started_at) = self.receivable.scan_started_at() {
            return Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at,
            });
        }

        self.receivable
            .start_scan(wallet, timestamp, response_skeleton_opt, logger)
    }

    pub fn finish_payable_scan(&mut self, msg: SentPayables, logger: &Logger) -> PayableScanResult {
        let scan_result = self.payable.finish_scan(msg, logger);
        if scan_result.result == NextScanToRun::PendingPayableScan {
            self.aware_of_unresolved_pending_payable = true
        }
        scan_result
    }

    pub fn finish_pending_payable_scan(
        &mut self,
        msg: TxReceiptsMessage,
        logger: &Logger,
    ) -> PendingPayableScanResult {
        self.pending_payable.finish_scan(msg, logger)
    }

    pub fn finish_receivable_scan(
        &mut self,
        msg: ReceivedPayments,
        logger: &Logger,
    ) -> Option<NodeToUiMessage> {
        self.receivable.finish_scan(msg, logger)
    }

    pub fn acknowledge_scan_error(&mut self, error: &ScanError, logger: &Logger) {
        debug!(logger, "Acknowledging a scan that couldn't finish");
        match &error.payload {
            // TODO refactor us two
            ScanErrorPayload::NewPayables(err) => self.payable.clean_up_after_error(
                PayableScannerCleanupArgs {
                    payable_scan_type: PayableScanType::New,
                    failed_txs: err.into(),
                },
                logger,
            ),
            ScanErrorPayload::RetryPayables(err) => self.payable.clean_up_after_error(
                PayableScannerCleanupArgs {
                    payable_scan_type: PayableScanType::Retry,
                    failed_txs: err.into(),
                },
                logger,
            ),
            ScanErrorPayload::PendingPayables { .. } => self
                .pending_payable
                .clean_up_after_error(PendingPayableScannerCleanupArgs {}, logger),
            ScanErrorPayload::Receivables { .. } => self
                .receivable
                .clean_up_after_error(ReceivableScannerCleanupArgs {}, logger),
        };
        // match error.payload {
        //     ScanErrorPayload::NewPayables(..) | ScanErrorPayload::RetryPayables(..) => {
        //         self.payable.mark_as_ended(logger)
        //     }
        //     ScanErrorPayload::PendingPayables{..} => {
        //         self.empty_caches(logger);
        //         self.pending_payable.mark_as_ended(logger);
        //     }
        //     ScanErrorPayload::Receivables{..} => {
        //         self.receivable.mark_as_ended(logger);
        //     }
        // };
    }

    pub fn try_skipping_payable_adjustment(
        &self,
        msg: PricedTemplatesMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String> {
        self.payable.try_skipping_payment_adjustment(msg, logger)
    }

    pub fn perform_payable_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        self.payable.perform_payment_adjustment(setup, logger)
    }

    pub fn initial_pending_payable_scan(&self) -> bool {
        self.initial_pending_payable_scan
    }

    pub fn unset_initial_pending_payable_scan(&mut self) {
        self.initial_pending_payable_scan = false
    }

    // This is a helper function reducing a boilerplate of complex trait resolving where
    // the compiler requires to specify which trigger message distinguishes the scan to run.
    // The payable scanner offers two modes through doubled implementations of StartableScanner
    // which uses the trigger message type as the only distinction between them.
    fn start_correct_payable_scanner<'a, TriggerMessage>(
        scanner: &'a mut (dyn MultistageDualPayableScanner + 'a),
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<InitialTemplatesMessage, StartScanError>
    where
        TriggerMessage: Message,
        (dyn MultistageDualPayableScanner + 'a):
            StartableScanner<TriggerMessage, InitialTemplatesMessage>,
    {
        <(dyn MultistageDualPayableScanner + 'a) as StartableScanner<
            TriggerMessage,
            InitialTemplatesMessage,
        >>::start_scan(scanner, wallet, timestamp, response_skeleton_opt, logger)
    }

    fn check_general_conditions_for_pending_payable_scan(
        &mut self,
        triggered_manually: bool,
        automatic_scans_enabled: bool,
    ) -> Result<(), StartScanError> {
        if triggered_manually && automatic_scans_enabled {
            return Err(StartScanError::ManualTriggerError(
                ManulTriggerError::AutomaticScanConflict,
            ));
        }
        if self.initial_pending_payable_scan {
            return Ok(());
        }
        if triggered_manually && !self.aware_of_unresolved_pending_payable {
            return Err(StartScanError::ManualTriggerError(
                ManulTriggerError::UnnecessaryRequest {
                    hint_opt: Some("Run the Payable scanner first.".to_string()),
                },
            ));
        }
        if !self.aware_of_unresolved_pending_payable {
            unreachable!(
                "Automatic pending payable scan should never start if there are no pending \
                payables to process."
            )
        }

        Ok(())
    }
}

pub(in crate::accountant::scanners) trait PrivateScanner<
    TriggerMessage,
    StartMessage,
    EndMessage,
    ScanResult,
    CleanupArgs,
>:
    StartableScanner<TriggerMessage, StartMessage> + Scanner<EndMessage, ScanResult, CleanupArgs> where
    TriggerMessage: Message,
    StartMessage: Message,
    EndMessage: Message,
{
}

trait StartableScanner<TriggerMessage, StartMessage>
where
    TriggerMessage: Message,
    StartMessage: Message,
{
    fn start_scan(
        &mut self,
        wallet: &Wallet,
        timestamp: SystemTime,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) -> Result<StartMessage, StartScanError>;
}

trait Scanner<EndMessage, ScanResult, CleanupArgs>
where
    EndMessage: Message,
{
    fn finish_scan(&mut self, message: EndMessage, logger: &Logger) -> ScanResult;
    fn clean_up_after_error(
        &mut self,
        args: CleanupArgs,
        logger: &Logger,
    ) -> Result<(), ScanCleanUpError>;
    fn scan_started_at(&self) -> Option<SystemTime>;
    fn mark_as_started(&mut self, timestamp: SystemTime);
    fn mark_as_ended(&mut self, logger: &Logger);
    as_any_ref_in_trait!();
    as_any_mut_in_trait!();
}

pub struct ScannerCommon {
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

    fn signal_scanner_completion(&mut self, scan_type: ScanType, now: SystemTime, logger: &Logger) {
        match self.initiated_at_opt.take() {
            Some(timestamp) => {
                let elapsed_time = now
                    .duration_since(timestamp)
                    .expect("Unable to calculate elapsed time for the scan.")
                    .as_millis();
                info!(
                    logger,
                    "The {:?} scan ended in {}ms.", scan_type, elapsed_time
                );
            }
            None => {
                error!(
                    logger,
                    "Called scan_finished() for {:?} scanner but could not find any timestamp",
                    scan_type
                );
            }
        };
    }
}

#[macro_export]
macro_rules! time_marking_methods {
    ($scan_type_variant: ident) => {
        fn scan_started_at(&self) -> Option<SystemTime> {
            self.common.initiated_at_opt
        }

        fn mark_as_started(&mut self, timestamp: SystemTime) {
            self.common.initiated_at_opt = Some(timestamp);
        }

        fn mark_as_ended(&mut self, logger: &Logger) {
            self.common.signal_scanner_completion(
                ScanType::$scan_type_variant,
                SystemTime::now(),
                logger,
            );
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, VariantCount)]
pub enum StartScanError {
    NothingToProcess,
    NoConsumingWalletFound,
    ScanAlreadyRunning {
        cross_scan_cause_opt: Option<ScanType>,
        started_at: SystemTime,
    },
    CalledFromNullScanner, // Exclusive for tests
    ManualTriggerError(ManulTriggerError),
}

impl StartScanError {
    pub fn log_error(&self, logger: &Logger, scan_type: ScanType, is_externally_triggered: bool) {
        enum ErrorType {
            Temporary(String),
            Permanent(String),
        }

        let log_message = match self {
            StartScanError::NothingToProcess => ErrorType::Temporary(format!(
                "There was nothing to process during {:?} scan.",
                scan_type
            )),
            StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt,
                started_at,
            } => ErrorType::Temporary(Self::scan_already_running_msg(
                scan_type,
                *cross_scan_cause_opt,
                *started_at,
            )),
            StartScanError::NoConsumingWalletFound => ErrorType::Permanent(format!(
                "Cannot initiate {:?} scan because no consuming wallet was found.",
                scan_type
            )),
            StartScanError::CalledFromNullScanner => match cfg!(test) {
                true => ErrorType::Permanent(format!(
                    "Called from NullScanner, not the {:?} scanner.",
                    scan_type
                )),
                false => panic!("Null Scanner shouldn't be running inside production code."),
            },
            StartScanError::ManualTriggerError(e) => match e {
                ManulTriggerError::AutomaticScanConflict => ErrorType::Permanent(format!(
                    "User requested {:?} scan was denied. Automatic mode prevents manual triggers.",
                    scan_type
                )),
                ManulTriggerError::UnnecessaryRequest { hint_opt } => {
                    ErrorType::Temporary(format!(
                        "User requested {:?} scan was denied expecting zero findings.{}",
                        scan_type,
                        match hint_opt {
                            Some(hint) => format!(" {}", hint),
                            None => "".to_string(),
                        }
                    ))
                }
            },
        };

        match log_message {
            ErrorType::Temporary(msg) => match is_externally_triggered {
                true => info!(logger, "{}", msg),
                false => debug!(logger, "{}", msg),
            },
            ErrorType::Permanent(msg) => warning!(logger, "{}", msg),
        }
    }

    fn timestamp_as_string(timestamp: SystemTime) -> String {
        let offset_date_time = OffsetDateTime::from(timestamp);
        offset_date_time
            .format(
                &parse(TIME_FORMATTING_STRING)
                    .expect("Error while parsing the time formatting string."),
            )
            .expect("Error while formatting timestamp as string.")
    }

    fn scan_already_running_msg(
        request_of: ScanType,
        cross_scan_cause_opt: Option<ScanType>,
        scan_started: SystemTime,
    ) -> String {
        let (blocking_scanner, request_spec) = if let Some(cross_scan_cause) = cross_scan_cause_opt
        {
            (cross_scan_cause, format!("the {:?}", request_of))
        } else {
            (request_of, "this".to_string())
        };

        format!(
            "{:?} scan was already initiated at {}. Hence, {} scan request will be ignored.",
            blocking_scanner,
            StartScanError::timestamp_as_string(scan_started),
            request_spec
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanCleanUpError {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ManulTriggerError {
    AutomaticScanConflict,
    UnnecessaryRequest { hint_opt: Option<String> },
}

pub trait RealScannerMarker {}

macro_rules! impl_real_scanner_marker {
    ($($t:ty),*) => {
        $(impl RealScannerMarker for $t {})*
    }
}

impl_real_scanner_marker!(PayableScanner, PendingPayableScanner, ReceivableScanner);

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{Detection, SentTx, TxStatus};
    use crate::accountant::db_access_objects::test_utils::{make_failed_tx, make_sent_tx};
    use crate::accountant::db_access_objects::utils::from_unix_timestamp;
    use crate::accountant::scanners::payable_scanner::finish_scan::PayableScannerCleanupArgs;
    use crate::accountant::scanners::payable_scanner::msgs::InitialTemplatesMessage;
    use crate::accountant::scanners::payable_scanner::test_utils::PayableScannerBuilder;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::new::NewTxTemplates;
    use crate::accountant::scanners::payable_scanner::tx_templates::initial::retry::{
        RetryTxTemplate, RetryTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::utils::PayableScanResult;
    use crate::accountant::scanners::payable_scanner::PayableScanner;
    use crate::accountant::scanners::pending_payable_scanner::utils::{
        CurrentPendingPayables, PendingPayableScanResult, RecheckRequiringFailures, TxHashByTable,
    };
    use crate::accountant::scanners::pending_payable_scanner::PendingPayableScanner;
    use crate::accountant::scanners::receivable_scanner::ReceivableScanner;
    use crate::accountant::scanners::test_utils::{
        assert_timestamps_from_str, parse_system_time_from_str,
        trim_expected_timestamp_to_three_digits_nanos, MarkScanner, NullScanner,
        PendingPayableCacheMock, ReplacementType, ScannerReplacement,
    };
    use crate::accountant::scanners::{
        ManulTriggerError, Scanner, ScannerCommon, Scanners, StartScanError, StartableScanner,
    };
    use crate::accountant::test_utils::{
        make_custom_payment_thresholds, make_qualified_and_unqualified_payables,
        make_receivable_account, BannedDaoFactoryMock, BannedDaoMock, ConfigDaoFactoryMock,
        FailedPayableDaoFactoryMock, FailedPayableDaoMock, PayableDaoFactoryMock, PayableDaoMock,
        PendingPayableScannerBuilder, ReceivableDaoFactoryMock, ReceivableDaoMock,
        ReceivableScannerBuilder, SentPayableDaoFactoryMock, SentPayableDaoMock,
    };
    use crate::accountant::{
        PayableScanType, ReceivedPayments, RequestTransactionReceipts, ResponseSkeleton, ScanError,
        SentPayables, TxReceiptsMessage,
    };
    use crate::blockchain::blockchain_bridge::{BlockMarker, RetrieveTransactions};
    use crate::blockchain::blockchain_interface::data_structures::{
        BatchResults, BlockchainTransaction, StatusReadFromReceiptCheck, TxBlock,
    };
    use crate::blockchain::errors::rpc_errors::{
        AppRpcError, AppRpcErrorKind, RemoteError, RemoteErrorKind,
    };
    use crate::blockchain::errors::validation_status::{PreviousAttempts, ValidationStatus};
    use crate::blockchain::errors::BlockchainErrorKind;
    use crate::blockchain::test_utils::{make_block_hash, make_tx_hash};
    use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::db_config::mocks::ConfigDaoMock;
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics, PaymentThresholds};
    use crate::sub_lib::blockchain_bridge::{DetailedScanType, PayableScanError, ScanErrorPayload};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use crate::test_utils::{make_paying_wallet, make_wallet};
    use actix::Message;
    use ethereum_types::U64;
    use itertools::Either;
    use masq_lib::logger::Logger;
    use masq_lib::messages::ScanType;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::simple_clock::SimpleClockMock;
    use masq_lib::ui_gateway::NodeToUiMessage;
    use regex::Regex;
    use rusqlite::{ffi, ErrorCode};
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::ops::Sub;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    impl Scanners {
        pub fn replace_scanner(&mut self, replacement: ScannerReplacement) {
            match replacement {
                ScannerReplacement::Payable(ReplacementType::Real(scanner)) => {
                    self.payable = Box::new(scanner)
                }
                ScannerReplacement::Payable(ReplacementType::Mock(scanner)) => {
                    self.payable = Box::new(scanner)
                }
                ScannerReplacement::Payable(ReplacementType::Null) => {
                    self.payable = Box::new(NullScanner::default())
                }
                ScannerReplacement::PendingPayable(ReplacementType::Real(scanner)) => {
                    self.pending_payable = Box::new(scanner)
                }
                ScannerReplacement::PendingPayable(ReplacementType::Mock(scanner)) => {
                    self.pending_payable = Box::new(scanner)
                }
                ScannerReplacement::PendingPayable(ReplacementType::Null) => {
                    self.pending_payable = Box::new(NullScanner::default())
                }
                ScannerReplacement::Receivable(ReplacementType::Real(scanner)) => {
                    self.receivable = Box::new(scanner)
                }
                ScannerReplacement::Receivable(ReplacementType::Mock(scanner)) => {
                    self.receivable = Box::new(scanner)
                }
                ScannerReplacement::Receivable(ReplacementType::Null) => {
                    self.receivable = Box::new(NullScanner::default())
                }
            }
        }

        pub fn reset_scan_started(&mut self, scan_type: ScanType, value: MarkScanner) {
            match scan_type {
                ScanType::Payables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.payable, value)
                }
                ScanType::PendingPayables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.pending_payable, value)
                }
                ScanType::Receivables => {
                    Self::simple_scanner_timestamp_treatment(&mut *self.receivable, value)
                }
            }
        }

        pub fn aware_of_unresolved_pending_payables(&self) -> bool {
            self.aware_of_unresolved_pending_payable
        }

        pub fn set_aware_of_unresolved_pending_payables(&mut self, value: bool) {
            self.aware_of_unresolved_pending_payable = value
        }

        fn simple_scanner_timestamp_treatment<Scanner, EndMessage, ScanResult, CleanupArgs>(
            scanner: &mut Scanner,
            value: MarkScanner,
        ) where
            Scanner: self::Scanner<EndMessage, ScanResult, CleanupArgs> + ?Sized,
            EndMessage: actix::Message,
        {
            match value {
                MarkScanner::Ended(logger) => scanner.mark_as_ended(logger),
                MarkScanner::Started(timestamp) => scanner.mark_as_started(timestamp),
            }
        }

        pub fn scan_started_at(&self, scan_type: ScanType) -> Option<SystemTime> {
            match scan_type {
                ScanType::Payables => self.payable.scan_started_at(),
                ScanType::PendingPayables => self.pending_payable.scan_started_at(),
                ScanType::Receivables => self.receivable.scan_started_at(),
            }
        }
    }

    #[test]
    fn scanners_struct_can_be_constructed_with_the_respective_scanners() {
        let payable_dao_factory = PayableDaoFactoryMock::new()
            .make_result(PayableDaoMock::new())
            .make_result(PayableDaoMock::new());
        let sent_payable_dao_factory = SentPayableDaoFactoryMock::new()
            .make_result(SentPayableDaoMock::new())
            .make_result(SentPayableDaoMock::new());
        let failed_payable_dao_factory = FailedPayableDaoFactoryMock::new()
            .make_result(FailedPayableDaoMock::new())
            .make_result(FailedPayableDaoMock::new());
        let receivable_dao = ReceivableDaoMock::new();
        let receivable_dao_factory = ReceivableDaoFactoryMock::new().make_result(receivable_dao);
        let banned_dao_factory = BannedDaoFactoryMock::new().make_result(BannedDaoMock::new());
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao_mock = ConfigDaoMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let config_dao_factory = ConfigDaoFactoryMock::new().make_result(config_dao_mock);
        let financial_statistics = FinancialStatistics {
            total_paid_payable_wei: 1,
            total_paid_receivable_wei: 2,
        };
        let payment_thresholds = make_custom_payment_thresholds();
        let payment_thresholds_rc = Rc::new(payment_thresholds);
        let initial_rc_count = Rc::strong_count(&payment_thresholds_rc);

        let mut scanners = Scanners::new(
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                sent_payable_dao_factory: Box::new(sent_payable_dao_factory),
                failed_payable_dao_factory: Box::new(failed_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
                config_dao_factory: Box::new(config_dao_factory),
            },
            Rc::clone(&payment_thresholds_rc),
            Rc::new(RefCell::new(financial_statistics.clone())),
        );

        let payable_scanner = scanners
            .payable
            .as_any()
            .downcast_ref::<PayableScanner>()
            .unwrap();
        let pending_payable_scanner = scanners
            .pending_payable
            .as_any_mut()
            .downcast_mut::<PendingPayableScanner>()
            .unwrap();
        let receivable_scanner = scanners
            .receivable
            .as_any_mut()
            .downcast_mut::<ReceivableScanner>()
            .unwrap();
        assert_eq!(
            payable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(payable_scanner.common.initiated_at_opt.is_some(), false);
        assert_eq!(scanners.aware_of_unresolved_pending_payable, false);
        assert_eq!(scanners.initial_pending_payable_scan, true);
        assert_eq!(
            *pending_payable_scanner.financial_statistics.borrow(),
            financial_statistics
        );
        assert_eq!(
            pending_payable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(
            pending_payable_scanner.common.initiated_at_opt.is_some(),
            false
        );
        let dumped_records = pending_payable_scanner
            .suspected_failed_payables
            .dump_cache();
        assert!(
            dumped_records.is_empty(),
            "There should be no suspected failures but found {:?}.",
            dumped_records
        );
        assert_eq!(
            receivable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(receivable_scanner.common.initiated_at_opt.is_some(), false);
        assert_eq!(
            *receivable_scanner.financial_statistics.borrow(),
            financial_statistics
        );
        assert_eq!(
            receivable_scanner.common.payment_thresholds.as_ref(),
            &payment_thresholds
        );
        assert_eq!(receivable_scanner.common.initiated_at_opt.is_some(), false);
        receivable_scanner
            .persistent_configuration
            .set_start_block(Some(136890))
            .unwrap();
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("start_block".to_string(), Some("136890".to_string()))]
        );
        assert_eq!(
            Rc::strong_count(&payment_thresholds_rc),
            initial_rc_count + 3
        );
    }

    #[test]
    fn new_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "new_payable_scanner_can_initiate_a_scan";
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let (qualified_payable_accounts, _, retrieved_payables) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let payable_dao = PayableDaoMock::new().retrieve_payables_result(retrieved_payables);
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let timestamp = subject.payable.scan_started_at();
        assert_eq!(timestamp, Some(now));
        let qualified_payables_count = qualified_payable_accounts.len();
        let expected_tx_templates = NewTxTemplates::from(&qualified_payable_accounts);
        assert_eq!(
            result,
            Ok(InitialTemplatesMessage {
                initial_templates: Either::Left(expected_tx_templates),
                consuming_wallet,
                response_skeleton_opt: None,
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for new payables"),
            &format!(
                "INFO: {test_name}: Chose {} qualified debts to pay",
                qualified_payables_count
            ),
        ])
    }

    #[test]
    fn new_payable_scanner_cannot_be_initiated_if_it_is_already_running() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let (_, _, retrieved_payables) = make_qualified_and_unqualified_payables(
            SystemTime::now(),
            &PaymentThresholds::default(),
        );
        let payable_dao = PayableDaoMock::new().retrieve_payables_result(retrieved_payables);
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);
        let previous_scan_started_at = SystemTime::now();
        let _ = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            previous_scan_started_at,
            None,
            &Logger::new("test"),
            true,
        );

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: previous_scan_started_at
            })
        );
    }

    #[test]
    fn new_payable_scanner_throws_error_in_case_no_qualified_payable_is_found() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let (_, unqualified_payable_accounts, _) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let payable_dao =
            PayableDaoMock::new().retrieve_payables_result(unqualified_payable_accounts);
        let mut subject = make_dull_subject();
        subject.payable = Box::new(
            PayableScannerBuilder::new()
                .payable_dao(payable_dao)
                .build(),
        );

        let result = subject.start_new_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.scan_started_at(ScanType::Payables).is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(result, Err(StartScanError::NothingToProcess));
    }

    #[test]
    fn retry_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "retry_payable_scanner_can_initiate_a_scan";
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let response_skeleton = ResponseSkeleton {
            client_id: 24,
            context_id: 42,
        };
        let (_, _, retrieved_payables) =
            make_qualified_and_unqualified_payables(now, &PaymentThresholds::default());
        let failed_tx = make_failed_tx(1);
        let payable_dao = PayableDaoMock::new().retrieve_payables_result(retrieved_payables);
        let failed_payable_dao =
            FailedPayableDaoMock::new().retrieve_txs_result(BTreeSet::from([failed_tx.clone()]));
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);

        let result = subject.start_retry_payable_scan_guarded(
            &consuming_wallet,
            now,
            Some(response_skeleton),
            &Logger::new(test_name),
        );

        let timestamp = subject.payable.scan_started_at();
        let expected_template = RetryTxTemplate::from(&failed_tx);
        assert_eq!(timestamp, Some(now));
        assert_eq!(
            result,
            Ok(InitialTemplatesMessage {
                initial_templates: Either::Right(RetryTxTemplates(vec![expected_template])),
                consuming_wallet,
                response_skeleton_opt: Some(response_skeleton),
            })
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!("INFO: {test_name}: Scanning for retry payables"));
    }

    #[test]
    fn retry_payable_scanner_panics_in_case_scan_is_already_running() {
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let (_, _, retrieved_payables) = make_qualified_and_unqualified_payables(
            SystemTime::now(),
            &PaymentThresholds::default(),
        );
        let payable_dao = PayableDaoMock::new().retrieve_payables_result(retrieved_payables);
        let failed_payable_dao =
            FailedPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let mut subject = make_dull_subject();
        let payable_scanner = PayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        subject.payable = Box::new(payable_scanner);
        let before = SystemTime::now();
        let _ = subject.start_retry_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
        );

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<InitialTemplatesMessage, StartScanError> = subject
                .start_retry_payable_scan_guarded(
                    &consuming_wallet,
                    SystemTime::now(),
                    None,
                    &Logger::new("test"),
                );
        }))
        .unwrap_err();

        let after = SystemTime::now();
        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        let expected_needle_1 = "internal error: entered unreachable code: \
        Guards should ensure that no payable scanner can run if the pending payable \
        repetitive sequence is still ongoing. However, some other payable scan intruded at";
        assert!(
            panic_msg.contains(expected_needle_1),
            "We looked for {} but the actual string doesn't contain it: {}",
            expected_needle_1,
            panic_msg
        );
        let expected_needle_2 = "and is still running at ";
        assert!(
            panic_msg.contains(expected_needle_2),
            "We looked for {} but the actual string doesn't contain it: {}",
            expected_needle_2,
            panic_msg
        );
        check_timestamps_in_panic_for_already_running_retry_payable_scanner(
            &panic_msg, before, after,
        )
    }

    fn check_timestamps_in_panic_for_already_running_retry_payable_scanner(
        panic_msg: &str,
        before: SystemTime,
        after: SystemTime,
    ) {
        let system_times = parse_system_time_from_str(panic_msg);
        let before = trim_expected_timestamp_to_three_digits_nanos(before);
        let first_actual = system_times[0];
        let second_actual = system_times[1];
        let after = trim_expected_timestamp_to_three_digits_nanos(after);

        assert!(
            before <= first_actual
                && first_actual <= second_actual
                && second_actual <= after,
            "We expected this relationship before({:?}) <= first_actual({:?}) <= second_actual({:?}) \
            <= after({:?}), but it does not hold true",
            before,
            first_actual,
            second_actual,
            after
        );
    }

    #[test]
    fn finish_payable_scan_keeps_the_aware_of_unresolved_pending_payable_flag_as_false_in_case_of_err(
    ) {
        test_finish_payable_scan_keeps_aware_flag_false_on_error(PayableScanType::New, "new_scan");
        test_finish_payable_scan_keeps_aware_flag_false_on_error(
            PayableScanType::Retry,
            "retry_scan",
        );
    }

    fn test_finish_payable_scan_keeps_aware_flag_false_on_error(
        payable_scan_type: PayableScanType,
        test_name_str: &str,
    ) {
        init_test_logging();
        let test_name = format!(
            "finish_payable_scan_keeps_the_aware_of_unresolved_\
             pending_payable_flag_as_false_in_case_of_err_for_\
             {test_name_str}"
        );
        let sent_payable = SentPayables {
            batch_results: BatchResults {
                sent_txs: vec![make_sent_tx(123)],
                failed_txs: vec![make_failed_tx(456)],
            },
            payable_scan_type,
            response_skeleton_opt: None,
        };
        let logger = Logger::new(&test_name);
        let payable_scanner = PayableScannerBuilder::new().build();
        let mut subject = make_dull_subject();
        subject.payable = Box::new(payable_scanner);
        let aware_of_unresolved_pending_payable_before =
            subject.aware_of_unresolved_pending_payable;

        subject.finish_payable_scan(sent_payable, &logger);

        let aware_of_unresolved_pending_payable_after = subject.aware_of_unresolved_pending_payable;
        assert_eq!(aware_of_unresolved_pending_payable_before, false);
        assert_eq!(aware_of_unresolved_pending_payable_after, false);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "WARN: {test_name}: Local error occurred before transaction signing. Error: Some error"
        ));
    }

    #[test]
    fn finish_payable_scan_changes_the_aware_of_unresolved_pending_payable_flag_as_true_when_pending_txs_found_in_retry_mode(
    ) {
        init_test_logging();
        let test_name = "finish_payable_scan_changes_the_aware_of_unresolved_pending_payable_flag_as_true_when_pending_txs_found_in_retry_mode";
        let sent_payable_dao = SentPayableDaoMock::default().insert_new_records_result(Ok(()));
        let failed_payable_dao =
            FailedPayableDaoMock::default().retrieve_txs_result(BTreeSet::new());
        let payable_scanner = PayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .build();
        let logger = Logger::new(test_name);
        let mut subject = make_dull_subject();
        subject.payable = Box::new(payable_scanner);
        let sent_payables = SentPayables {
            batch_results: BatchResults {
                sent_txs: vec![make_sent_tx(1)],
                failed_txs: vec![],
            },
            payable_scan_type: PayableScanType::Retry,
            response_skeleton_opt: None,
        };
        let aware_of_unresolved_pending_payable_before =
            subject.aware_of_unresolved_pending_payable;

        subject.finish_payable_scan(sent_payables, &logger);

        let aware_of_unresolved_pending_payable_after = subject.aware_of_unresolved_pending_payable;
        assert_eq!(aware_of_unresolved_pending_payable_before, false);
        assert_eq!(aware_of_unresolved_pending_payable_after, true);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Processed retried txs while sending to RPC: \
            Total: 1, Sent to RPC: 1, Failed to send: 0."
        ));
    }

    #[test]
    fn pending_payable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "pending_payable_scanner_can_initiate_a_scan";
        let consuming_wallet = make_paying_wallet(b"consuming wallet");
        let now = SystemTime::now();
        let sent_tx = make_sent_tx(456);
        let sent_tx_hash = sent_tx.hash;
        let failed_tx = make_failed_tx(789);
        let sent_payable_dao =
            SentPayableDaoMock::new().retrieve_txs_result(btreeset![sent_tx.clone()]);
        let failed_payable_dao =
            FailedPayableDaoMock::new().retrieve_txs_result(BTreeSet::from([failed_tx.clone()]));
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_cache(Box::new(CurrentPendingPayables::default()))
            .failed_payable_cache(Box::new(RecheckRequiringFailures::default()))
            .build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.payable = Box::new(payable_scanner);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Ok(RequestTransactionReceipts {
                tx_hashes: vec![
                    TxHashByTable::SentPayable(sent_tx_hash),
                    TxHashByTable::FailedPayable(failed_tx.hash)
                ],
                response_skeleton_opt: None
            })
        );
        TestLogHandler::new().assert_logs_match_in_order(vec![
            &format!("INFO: {test_name}: Scanning for pending payable"),
            &format!(
                "DEBUG: {test_name}: Found 1 pending payables and 1 suspected failures to process"
            ),
        ])
    }

    #[test]
    fn pending_payable_scanner_cannot_be_initiated_if_it_itself_is_already_running() {
        let now = SystemTime::now();
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let sent_payable_dao =
            SentPayableDaoMock::new().retrieve_txs_result(btreeset![make_sent_tx(123)]);
        let failed_payable_dao =
            FailedPayableDaoMock::new().retrieve_txs_result(BTreeSet::from([make_failed_tx(456)]));
        let pending_payable_scanner = PendingPayableScannerBuilder::new()
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_cache(Box::new(CurrentPendingPayables::default()))
            .failed_payable_cache(Box::new(RecheckRequiringFailures::default()))
            .build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.payable = Box::new(payable_scanner);
        let logger = Logger::new("test");
        let _ =
            subject.start_pending_payable_scan_guarded(&consuming_wallet, now, None, &logger, true);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &logger,
            true,
        );

        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: now
            })
        );
    }

    #[test]
    fn pending_payable_scanner_cannot_be_initiated_if_payable_scanner_is_still_running() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let payable_scanner = PayableScannerBuilder::new().build();
        // Important
        subject.aware_of_unresolved_pending_payable = true;
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.payable = Box::new(payable_scanner);
        let logger = Logger::new("test");
        let previous_scan_started_at = SystemTime::now();
        subject.payable.mark_as_started(previous_scan_started_at);

        let result = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &logger,
            true,
        );

        let is_scan_running = subject.pending_payable.scan_started_at().is_some();
        assert_eq!(is_scan_running, false);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: Some(ScanType::Payables),
                started_at: previous_scan_started_at
            })
        );
    }

    #[test]
    fn both_payable_scanners_cannot_be_detected_in_progress_at_the_same_time() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let payable_scanner = PayableScannerBuilder::new().build();
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.payable = Box::new(payable_scanner);
        let timestamp_pending_payable_start = SystemTime::now()
            .checked_sub(Duration::from_millis(12))
            .unwrap();
        let timestamp_payable_scanner_start = SystemTime::now();
        subject.aware_of_unresolved_pending_payable = true;
        subject
            .pending_payable
            .mark_as_started(timestamp_pending_payable_start);
        subject
            .payable
            .mark_as_started(timestamp_payable_scanner_start);

        let caught_panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = subject.start_pending_payable_scan_guarded(
                &consuming_wallet,
                SystemTime::now(),
                None,
                &Logger::new("test"),
                true,
            );
        }))
        .unwrap_err();

        let panic_msg = caught_panic.downcast_ref::<String>().unwrap();
        let expected_msg_fragment_1 = "internal error: entered unreachable code: Any payable-\
        related scanners should never be allowed to run in parallel. Scan for pending payables \
        started at: ";
        assert!(
            panic_msg.contains(expected_msg_fragment_1),
            "This fragment '{}' wasn't found in \
        '{}'",
            expected_msg_fragment_1,
            panic_msg
        );
        let expected_msg_fragment_2 = ", scan for payables started at: ";
        assert!(
            panic_msg.contains(expected_msg_fragment_2),
            "This fragment '{}' wasn't found in \
        '{}'",
            expected_msg_fragment_2,
            panic_msg
        );
        assert_timestamps_from_str(
            panic_msg,
            vec![
                timestamp_pending_payable_start,
                timestamp_payable_scanner_start,
            ],
        )
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Automatic pending payable \
    scan should never start if there are no pending payables to process."
    )]
    fn pending_payable_scanner_bumps_into_zero_pending_payable_awareness_in_the_automatic_mode() {
        let consuming_wallet = make_paying_wallet(b"consuming");
        let mut subject = make_dull_subject();
        let pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        subject.pending_payable = Box::new(pending_payable_scanner);
        subject.aware_of_unresolved_pending_payable = false;

        let _ = subject.start_pending_payable_scan_guarded(
            &consuming_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );
    }

    #[test]
    fn check_general_conditions_for_pending_payable_scan_if_it_is_initial_pending_payable_scan() {
        let mut subject = make_dull_subject();
        subject.initial_pending_payable_scan = true;

        let result = subject.check_general_conditions_for_pending_payable_scan(false, true);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.initial_pending_payable_scan, true);
    }

    #[test]
    fn pending_payable_scanner_handles_tx_receipts_message() {
        // Note: the choice of those hashes isn't random; I tried to make sure I will know the order,
        // in which these records will be processed, because they are in an ordered map.
        // It is important because otherwise preparation of results with the mocks would become
        // chaotic, as long as you care about the exact receiver of the mock call among these records
        init_test_logging();
        let test_name = "pending_payable_scanner_handles_tx_receipts_message";
        // Normal confirmation
        let transactions_confirmed_params_arc = Arc::new(Mutex::new(vec![]));
        let confirm_tx_params_arc = Arc::new(Mutex::new(vec![]));
        // FailedTx reclaim
        let replace_records_params_arc = Arc::new(Mutex::new(vec![]));
        // New tx failure
        let insert_new_records_params_arc = Arc::new(Mutex::new(vec![]));
        // Validation failures
        let update_statuses_pending_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let update_statuses_failed_payable_params_arc = Arc::new(Mutex::new(vec![]));
        let timestamp_a = SystemTime::now();
        let timestamp_b = SystemTime::now().sub(Duration::from_millis(12));
        let timestamp_c = SystemTime::now().sub(Duration::from_millis(1234));
        let payable_dao = PayableDaoMock::new()
            .transactions_confirmed_params(&transactions_confirmed_params_arc)
            .transactions_confirmed_result(Ok(()));
        let sent_payable_dao = SentPayableDaoMock::new()
            .confirm_tx_params(&confirm_tx_params_arc)
            .confirm_tx_result(Ok(()))
            .update_statuses_params(&update_statuses_pending_payable_params_arc)
            .update_statuses_result(Ok(()))
            .replace_records_result(Ok(()))
            .delete_records_result(Ok(()))
            .replace_records_params(&replace_records_params_arc)
            .replace_records_result(Ok(()));
        let failed_payable_dao = FailedPayableDaoMock::new()
            .insert_new_records_params(&insert_new_records_params_arc)
            .insert_new_records_result(Ok(()))
            .update_statuses_params(&update_statuses_failed_payable_params_arc)
            .update_statuses_result(Ok(()))
            .delete_records_result(Ok(()));
        let tx_hash_1 = make_tx_hash(0x111);
        let mut sent_tx_1 = make_sent_tx(123);
        sent_tx_1.hash = tx_hash_1;
        let tx_block_1 = TxBlock {
            block_hash: make_block_hash(333),
            block_number: U64::from(1234),
        };
        let tx_status_1 = StatusReadFromReceiptCheck::Succeeded(tx_block_1);
        let tx_hash_2 = make_tx_hash(0x222);
        let mut failed_tx_2 = make_failed_tx(789);
        failed_tx_2.hash = tx_hash_2;
        let tx_block_2 = TxBlock {
            block_hash: make_block_hash(222),
            block_number: U64::from(2345),
        };
        let tx_status_2 = StatusReadFromReceiptCheck::Succeeded(tx_block_2);
        let tx_hash_3 = make_tx_hash(0x333);
        let mut sent_tx_3 = make_sent_tx(456);
        sent_tx_3.hash = tx_hash_3;
        let tx_status_3 = StatusReadFromReceiptCheck::Pending;
        let tx_hash_4 = make_tx_hash(0x444);
        let mut sent_tx_4 = make_sent_tx(4567);
        sent_tx_4.hash = tx_hash_4;
        sent_tx_4.status = TxStatus::Pending(ValidationStatus::Waiting);
        let tx_receipt_rpc_error_4 = AppRpcError::Remote(RemoteError::Unreachable);
        let tx_hash_5 = make_tx_hash(0x555);
        let mut failed_tx_5 = make_failed_tx(888);
        failed_tx_5.hash = tx_hash_5;
        failed_tx_5.status =
            FailureStatus::RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(
                BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)),
                &SimpleClockMock::default().now_result(timestamp_c),
            )));
        let tx_receipt_rpc_error_5 =
            AppRpcError::Remote(RemoteError::InvalidResponse("game over".to_string()));
        let tx_hash_6 = make_tx_hash(0x666);
        let mut sent_tx_6 = make_sent_tx(789);
        sent_tx_6.hash = tx_hash_6;
        let tx_status_6 = StatusReadFromReceiptCheck::Reverted;
        let sent_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_result(Some(sent_tx_1.clone()))
            .get_record_by_hash_result(Some(sent_tx_3.clone()))
            .get_record_by_hash_result(Some(sent_tx_4))
            .get_record_by_hash_result(Some(sent_tx_6.clone()));
        let failed_payable_cache = PendingPayableCacheMock::default()
            .get_record_by_hash_result(Some(failed_tx_2.clone()))
            .get_record_by_hash_result(Some(failed_tx_5));
        let validation_failure_clock = SimpleClockMock::default()
            .now_result(timestamp_a)
            .now_result(timestamp_b);
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new()
            .payable_dao(payable_dao)
            .sent_payable_dao(sent_payable_dao)
            .failed_payable_dao(failed_payable_dao)
            .sent_payable_cache(Box::new(sent_payable_cache))
            .failed_payable_cache(Box::new(failed_payable_cache))
            .validation_failure_clock(Box::new(validation_failure_clock))
            .build();
        let msg = TxReceiptsMessage {
            results: btreemap![
                TxHashByTable::SentPayable(tx_hash_1) => Ok(tx_status_1),
                TxHashByTable::FailedPayable(tx_hash_2) => Ok(tx_status_2),
                TxHashByTable::SentPayable(tx_hash_3) => Ok(tx_status_3),
                TxHashByTable::SentPayable(tx_hash_4) => Err(tx_receipt_rpc_error_4),
                TxHashByTable::FailedPayable(tx_hash_5) => Err(tx_receipt_rpc_error_5),
                TxHashByTable::SentPayable(tx_hash_6) => Ok(tx_status_6),
            ],
            response_skeleton_opt: None,
        };
        pending_payable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.pending_payable = Box::new(pending_payable_scanner);

        let result = subject.finish_pending_payable_scan(msg, &Logger::new(test_name));

        assert_eq!(result, PendingPayableScanResult::PaymentRetryRequired(None));
        let transactions_confirmed_params = transactions_confirmed_params_arc.lock().unwrap();
        sent_tx_1.status = TxStatus::Confirmed {
            block_hash: format!("{:?}", tx_block_1.block_hash),
            block_number: tx_block_1.block_number.as_u64(),
            detection: Detection::Normal,
        };
        assert_eq!(*transactions_confirmed_params, vec![vec![sent_tx_1]]);
        let confirm_tx_params = confirm_tx_params_arc.lock().unwrap();
        assert_eq!(*confirm_tx_params, vec![hashmap![tx_hash_1 => tx_block_1]]);
        let sent_tx_2 = SentTx::from((failed_tx_2, tx_block_2));
        let replace_records_params = replace_records_params_arc.lock().unwrap();
        assert_eq!(*replace_records_params, vec![btreeset![sent_tx_2]]);
        let insert_new_records_params = insert_new_records_params_arc.lock().unwrap();
        let expected_failure_for_tx_3 = FailedTx::from((sent_tx_3, FailureReason::PendingTooLong));
        let expected_failure_for_tx_6 = FailedTx::from((sent_tx_6, FailureReason::Reverted));
        assert_eq!(
            *insert_new_records_params,
            vec![btreeset![
                expected_failure_for_tx_3,
                expected_failure_for_tx_6
            ]]
        );
        let update_statuses_pending_payable_params =
            update_statuses_pending_payable_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_pending_payable_params,
            vec![
                hashmap!(tx_hash_4 => TxStatus::Pending(ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)), &SimpleClockMock::default().now_result(timestamp_a)))))
            ]
        );
        let update_statuses_failed_payable_params =
            update_statuses_failed_payable_params_arc.lock().unwrap();
        assert_eq!(
            *update_statuses_failed_payable_params,
            vec![
                hashmap!(tx_hash_5 => FailureStatus::RecheckRequired(ValidationStatus::Reattempting(PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::Unreachable)), &SimpleClockMock::default().now_result(timestamp_c)).add_attempt(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Remote(RemoteErrorKind::InvalidResponse)), &SimpleClockMock::default().now_result(timestamp_b)))))
            ]
        );
        assert_eq!(subject.scan_started_at(ScanType::PendingPayables), None);
        let test_log_handler = TestLogHandler::new();
        test_log_handler.exists_log_containing(&format!(
            "DEBUG: {test_name}: Processing receipts for 6 txs"
        ));
        test_log_handler.exists_log_containing(&format!("WARN: {test_name}: Failed to retrieve tx receipt for SentPayable(0x0000000000000000000000000000000000000000000000000000000000000444): Remote(Unreachable). Will retry receipt retrieval next cycle"));
        test_log_handler.exists_log_containing(&format!("WARN: {test_name}: Failed to retrieve tx receipt for FailedPayable(0x0000000000000000000000000000000000000000000000000000000000000555): Remote(InvalidResponse(\"game over\")). Will retry receipt retrieval next cycle"));
        test_log_handler.exists_log_containing(&format!("INFO: {test_name}: Reclaimed txs 0x0000000000000000000000000000000000000000000000000000000000000222 (block 2345) as confirmed on-chain"));
        test_log_handler.exists_log_containing(&format!(
                "INFO: {test_name}: Tx 0x0000000000000000000000000000000000000000000000000000000000000111 (block 1234) recorded in local ledger",
            ));
        test_log_handler.exists_log_containing(&format!("INFO: {test_name}: Failed txs 0x0000000000000000000000000000000000000000000000000000000000000333, 0x0000000000000000000000000000000000000000000000000000000000000666 were processed in the db"));
    }

    #[test]
    #[should_panic(
        expected = "We should never receive an empty list of results. Even receipts that could not \
        be retrieved can be interpreted"
    )]
    fn pending_payable_scanner_handles_empty_report_transaction_receipts_message() {
        let mut pending_payable_scanner = PendingPayableScannerBuilder::new().build();
        let msg = TxReceiptsMessage {
            results: btreemap![],
            response_skeleton_opt: None,
        };
        pending_payable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.pending_payable = Box::new(pending_payable_scanner);

        let _ = subject.finish_pending_payable_scan(msg, &Logger::new("test"));
    }

    #[test]
    fn receivable_scanner_can_initiate_a_scan() {
        init_test_logging();
        let test_name = "receivable_scanner_can_initiate_a_scan";
        let now = SystemTime::now();
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let earning_wallet = make_wallet("earning");
        let mut subject = make_dull_subject();
        let receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .build();
        subject.receivable = Box::new(receivable_scanner);

        let result = subject.start_receivable_scan_guarded(
            &earning_wallet,
            now,
            None,
            &Logger::new(test_name),
            true,
        );

        let is_scan_running = subject.receivable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Ok(RetrieveTransactions {
                recipient: earning_wallet.clone(),
                response_skeleton_opt: None
            })
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: Scanning for receivables to {earning_wallet}"
        ));
    }

    #[test]
    fn receivable_scanner_throws_error_in_case_scan_is_already_running() {
        let now = SystemTime::now();
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_result(vec![])
            .paid_delinquencies_result(vec![]);
        let earning_wallet = make_wallet("earning");
        let mut subject = make_dull_subject();
        let receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .build();
        subject.receivable = Box::new(receivable_scanner);
        let _ = subject.start_receivable_scan_guarded(
            &earning_wallet,
            now,
            None,
            &Logger::new("test"),
            true,
        );

        let result = subject.start_receivable_scan_guarded(
            &earning_wallet,
            SystemTime::now(),
            None,
            &Logger::new("test"),
            true,
        );

        let is_scan_running = subject.receivable.scan_started_at().is_some();
        assert_eq!(is_scan_running, true);
        assert_eq!(
            result,
            Err(StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: now
            })
        );
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
        let payment_thresholds = make_custom_payment_thresholds();
        let earning_wallet = make_wallet("earning");
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .banned_dao(banned_dao)
            .payment_thresholds(payment_thresholds)
            .build();
        let logger = Logger::new("DELINQUENCY_TEST");
        let now = SystemTime::now();

        let result = receivable_scanner.start_scan(&earning_wallet, now, None, &logger);

        assert_eq!(
            result,
            Ok(RetrieveTransactions {
                recipient: earning_wallet,
                response_skeleton_opt: None
            })
        );
        let new_delinquencies_parameters = new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(new_delinquencies_parameters.len(), 1);
        let (timestamp_actual, payment_thresholds_actual) = new_delinquencies_parameters[0];
        assert_eq!(timestamp_actual, now);
        assert_eq!(payment_thresholds_actual, payment_thresholds);
        let paid_delinquencies_parameters = paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(paid_delinquencies_parameters.len(), 1);
        assert_eq!(payment_thresholds, paid_delinquencies_parameters[0]);
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet));
        assert!(ban_parameters.contains(&newly_banned_2.wallet));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743132333464 \
            \\(balance: 1,234 gwei, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c65743233343564 \
            \\(balance: 2,345 gwei, age: \\d+ sec\\) banned for delinquency",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574333435366e \
            \\(balance: 3,456 gwei, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
        tlh.exists_log_matching(
            "INFO: DELINQUENCY_TEST: Wallet 0x00000000000000000077616c6c6574343536376e \
            \\(balance: 4,567 gwei, age: \\d+ sec\\) is no longer delinquent: unbanned",
        );
    }

    #[test]
    fn receivable_scanner_handles_no_new_payments_found() {
        init_test_logging();
        let test_name = "receivable_scanner_handles_no_new_payments_found";
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let new_start_block = BlockMarker::Value(4321);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Ok(()));
        let receivable_scanner = ReceivableScannerBuilder::new()
            .persistent_configuration(persistent_config)
            .build();
        let msg = ReceivedPayments {
            timestamp: SystemTime::now(),
            new_start_block,
            response_skeleton_opt: None,
            transactions: vec![],
        };
        let mut subject = make_dull_subject();
        subject.receivable = Box::new(receivable_scanner);

        let ui_msg_opt = subject.finish_receivable_scan(msg, &Logger::new(test_name));

        assert_eq!(ui_msg_opt, None);
        let set_start_block_params = set_start_block_params_arc.lock().unwrap();
        assert_eq!(*set_start_block_params, vec![Some(4321)]);
        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: No newly received payments were detected during the scanning process."
        ));
    }

    #[test]
    #[should_panic(
        expected = "Attempt to advance the start block to 6709 failed due to: \
    UninterpretableValue(\"Illiterate database manager\")"
    )]
    fn no_transactions_received_but_start_block_setting_fails() {
        init_test_logging();
        let test_name = "no_transactions_received_but_start_block_setting_fails";
        let now = SystemTime::now();
        let set_start_block_params_arc = Arc::new(Mutex::new(vec![]));
        let new_start_block = BlockMarker::Value(6709u64);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_params(&set_start_block_params_arc)
            .set_start_block_result(Err(PersistentConfigError::UninterpretableValue(
                "Illiterate database manager".to_string(),
            )));
        let mut subject = ReceivableScannerBuilder::new()
            .persistent_configuration(persistent_config)
            .build();
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block,
            response_skeleton_opt: None,
            transactions: vec![],
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    fn receivable_scanner_handles_received_payments_message() {
        init_test_logging();
        let test_name = "receivable_scanner_handles_received_payments_message";
        let now = SystemTime::now();
        let more_money_received_params_arc = Arc::new(Mutex::new(vec![]));
        let set_start_block_from_txn_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction_id = ArbitraryIdStamp::new();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default()
            .commit_params(&commit_params_arc)
            .commit_result(Ok(()))
            .set_arbitrary_id_stamp(transaction_id);
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_params(&set_start_block_from_txn_params_arc)
            .set_start_block_from_txn_result(Ok(()));
        let receivable_dao = ReceivableDaoMock::new()
            .more_money_received_params(&more_money_received_params_arc)
            .more_money_received_result(transaction);
        let mut receivable_scanner = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let mut financial_statistics = receivable_scanner.financial_statistics.borrow().clone();
        financial_statistics.total_paid_receivable_wei += 2_222_123_123;
        receivable_scanner
            .financial_statistics
            .replace(financial_statistics);
        let receivables = vec![
            BlockchainTransaction {
                block_number: 4578910,
                from: make_wallet("wallet_1"),
                wei_amount: 45_780,
            },
            BlockchainTransaction {
                block_number: 4569898,
                from: make_wallet("wallet_2"),
                wei_amount: 3_333_345,
            },
        ];
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block: BlockMarker::Value(7890123),
            response_skeleton_opt: None,
            transactions: receivables.clone(),
        };
        receivable_scanner.mark_as_started(SystemTime::now());
        let mut subject = make_dull_subject();
        subject.receivable = Box::new(receivable_scanner);

        let ui_msg_opt = subject.finish_receivable_scan(msg, &Logger::new(test_name));

        let scanner_after = subject
            .receivable
            .as_any()
            .downcast_ref::<ReceivableScanner>()
            .unwrap();
        let total_paid_receivable = scanner_after
            .financial_statistics
            .borrow()
            .total_paid_receivable_wei;
        assert_eq!(ui_msg_opt, None);
        assert_eq!(scanner_after.scan_started_at(), None);
        assert_eq!(total_paid_receivable, 2_222_123_123 + 45_780 + 3_333_345);
        let more_money_received_params = more_money_received_params_arc.lock().unwrap();
        assert_eq!(*more_money_received_params, vec![(now, receivables)]);
        let set_by_guest_transaction_params = set_start_block_from_txn_params_arc.lock().unwrap();
        assert_eq!(
            *set_by_guest_transaction_params,
            vec![(Some(7890123u64), transaction_id)]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
        TestLogHandler::new().exists_log_matching(
            "INFO: receivable_scanner_handles_received_payments_message: The Receivables scan ended in \\d+ms.",
        );
    }

    #[test]
    #[should_panic(
        expected = "entered unreachable code: Failed to get start_block while transactions were present"
    )]
    fn receivable_scanner_panics_when_failing_to_get_start_block_after_receiving_transactions() {
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default();
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new().start_block_result(Ok(None));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("wallet_1"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: SystemTime::now(),
            new_start_block: BlockMarker::Uninitialized,
            response_skeleton_opt: None,
            transactions: receivables,
        };
        subject.mark_as_started(SystemTime::now());

        let _ = subject.finish_scan(msg, &Logger::new("test"));
    }

    #[test]
    #[should_panic(expected = "Attempt to set new start block to 7890123 failed due to: \
    DatabaseError(\"Fatigue\")")]
    fn received_transactions_processed_but_start_block_setting_fails() {
        init_test_logging();
        let test_name = "received_transactions_processed_but_start_block_setting_fails";
        let now = SystemTime::now();
        let txn_inner_builder = TransactionInnerWrapperMockBuilder::default();
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_result(Err(PersistentConfigError::DatabaseError(
                "Fatigue".to_string(),
            )));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("abc"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block: BlockMarker::Value(7890123),
            response_skeleton_opt: None,
            transactions: receivables,
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    #[should_panic(
        expected = "Commit of received transactions failed: SqliteFailure(Error { code: \
    InternalMalfunction, extended_code: 0 }, Some(\"blah\"))"
    )]
    fn transaction_for_balance_start_block_updates_fails_on_its_commit() {
        init_test_logging();
        let test_name = "transaction_for_balance_start_block_updates_fails_on_its_commit";
        let now = SystemTime::now();
        let commit_err = Err(rusqlite::Error::SqliteFailure(
            ffi::Error {
                code: ErrorCode::InternalMalfunction,
                extended_code: 0,
            },
            Some("blah".to_string()),
        ));
        let txn_inner_builder =
            TransactionInnerWrapperMockBuilder::default().commit_result(commit_err);
        let transaction = TransactionSafeWrapper::new_with_builder(txn_inner_builder);
        let persistent_config = PersistentConfigurationMock::new()
            .start_block_result(Ok(None))
            .set_start_block_from_txn_result(Ok(()));
        let receivable_dao = ReceivableDaoMock::new().more_money_received_result(transaction);
        let mut subject = ReceivableScannerBuilder::new()
            .receivable_dao(receivable_dao)
            .persistent_configuration(persistent_config)
            .build();
        let receivables = vec![BlockchainTransaction {
            block_number: 4578910,
            from: make_wallet("abc"),
            wei_amount: 45_780,
        }];
        let msg = ReceivedPayments {
            timestamp: now,
            new_start_block: BlockMarker::Value(0),
            response_skeleton_opt: None,
            transactions: receivables,
        };
        // Not necessary, rather for preciseness
        subject.mark_as_started(SystemTime::now());

        subject.finish_scan(msg, &Logger::new(test_name));
    }

    #[test]
    fn signal_scanner_completion_and_log_if_timestamp_is_correct() {
        init_test_logging();
        let test_name = "signal_scanner_completion_and_log_if_timestamp_is_correct";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        let start = from_unix_timestamp(1_000_000_000);
        let end = start.checked_add(Duration::from_millis(145)).unwrap();
        subject.initiated_at_opt = Some(start);

        subject.signal_scanner_completion(ScanType::Payables, end, &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "INFO: {test_name}: The Payables scan ended in 145ms."
        ));
    }

    #[test]
    fn signal_scanner_completion_and_log_if_timestamp_is_not_found() {
        init_test_logging();
        let test_name = "signal_scanner_completion_and_log_if_timestamp_is_not_found";
        let logger = Logger::new(test_name);
        let mut subject = ScannerCommon::new(Rc::new(make_custom_payment_thresholds()));
        subject.initiated_at_opt = None;

        subject.signal_scanner_completion(ScanType::Receivables, SystemTime::now(), &logger);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Called scan_finished() for Receivables scanner but could not find any timestamp"
        ));
    }

    fn assert_elapsed_time_in_mark_as_ended<EndMessage: Message, ScanResult, CleanupArgs>(
        subject: &mut dyn Scanner<EndMessage, ScanResult, CleanupArgs>,
        scanner_name: &str,
        test_name: &str,
        logger: &Logger,
        log_handler: &TestLogHandler,
    ) {
        let before = SystemTime::now();
        subject.mark_as_started(before);

        subject.mark_as_ended(&logger);

        let after = SystemTime::now();
        let idx = log_handler.exists_log_containing(&format!(
            "INFO: {}: The {} scan ended in ",
            test_name, scanner_name
        ));
        let our_log_msg = log_handler.get_log_at(idx);
        let captures = Regex::new(r#"scan ended in (\d*)ms"#)
            .unwrap()
            .captures(&our_log_msg)
            .unwrap();
        let millis_str = captures.get(1).unwrap().as_str();
        let actual_millis = millis_str.parse::<u128>().unwrap();
        let max_millis_elapsed = after.duration_since(before).unwrap().as_millis();
        assert!(
            actual_millis <= max_millis_elapsed,
            "We expected the time elapsed ({}) to be equal or shorter to {}",
            actual_millis,
            max_millis_elapsed
        )
    }

    #[test]
    fn mark_as_ended_computes_elapsed_time_properly_in_each_scanner() {
        init_test_logging();
        let test_name = "mark_as_ended_computes_elapsed_time_properly_in_each_scanner";
        let logger = Logger::new(test_name);
        let log_handler = TestLogHandler::new();

        assert_elapsed_time_in_mark_as_ended::<SentPayables, PayableScanResult, _>(
            &mut PayableScannerBuilder::new().build(),
            "Payables",
            test_name,
            &logger,
            &log_handler,
        );
        assert_elapsed_time_in_mark_as_ended::<TxReceiptsMessage, PendingPayableScanResult, _>(
            &mut PendingPayableScannerBuilder::new().build(),
            "PendingPayables",
            test_name,
            &logger,
            &log_handler,
        );
        assert_elapsed_time_in_mark_as_ended::<ReceivedPayments, Option<NodeToUiMessage>, _>(
            &mut ReceivableScannerBuilder::new().build(),
            "Receivables",
            test_name,
            &logger,
            &log_handler,
        );
    }

    #[test]
    fn scan_already_running_msg_displays_correctly_if_blocked_by_requested_scan() {
        test_scan_already_running_msg(
            ScanType::PendingPayables,
            None,
            "PendingPayables scan was already initiated at",
            ". Hence, this scan request will be ignored.",
        )
    }

    #[test]
    fn scan_already_running_msg_displays_correctly_if_blocked_by_other_scan_than_directly_requested(
    ) {
        test_scan_already_running_msg(
            ScanType::PendingPayables,
            Some(ScanType::Payables),
            "Payables scan was already initiated at",
            ". Hence, the PendingPayables scan request will be ignored.",
        )
    }

    fn test_scan_already_running_msg(
        requested_scan: ScanType,
        cross_scan_blocking_cause_opt: Option<ScanType>,
        expected_leading_msg_fragment: &str,
        expected_trailing_msg_fragment: &str,
    ) {
        let some_time = SystemTime::now();

        let result = StartScanError::scan_already_running_msg(
            requested_scan,
            cross_scan_blocking_cause_opt,
            some_time,
        );

        assert!(
            result.contains(expected_leading_msg_fragment),
            "We expected {} but the msg is: {}",
            expected_leading_msg_fragment,
            result
        );
        assert!(
            result.contains(expected_trailing_msg_fragment),
            "We expected {} but the msg is: {}",
            expected_trailing_msg_fragment,
            result
        );
        assert_timestamps_from_str(&result, vec![some_time]);
    }

    #[test]
    fn acknowledge_scan_error_works() {
        init_test_logging();
        let test_name = "acknowledge_scan_error_works";
        let inputs: Vec<(
            ScanErrorPayload,
            Box<dyn Fn(&mut Scanners)>,
            Box<dyn Fn(&Scanners) -> Option<SystemTime>>,
        )> = vec![
            (
                ScanErrorPayload::NewPayables(PayableScanError::PlainTextError(
                    "booga".to_string(),
                )),
                Box::new(|subject| subject.payable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.payable.scan_started_at()),
            ),
            (
                ScanErrorPayload::RetryPayables(PayableScanError::PlainTextError(
                    "booga".to_string(),
                )),
                Box::new(|subject| subject.payable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.payable.scan_started_at()),
            ),
            (
                ScanErrorPayload::PendingPayables("booga".to_string()),
                Box::new(|subject| subject.pending_payable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.pending_payable.scan_started_at()),
            ),
            (
                ScanErrorPayload::Receivables("booga".to_string()),
                Box::new(|subject| subject.receivable.mark_as_started(SystemTime::now())),
                Box::new(|subject| subject.receivable.scan_started_at()),
            ),
        ];
        let mut subject = make_dull_subject();
        subject.payable = Box::new(PayableScannerBuilder::new().build());
        subject.pending_payable = Box::new(PendingPayableScannerBuilder::new().build());
        subject.receivable = Box::new(ReceivableScannerBuilder::new().build());
        let logger = Logger::new(test_name);
        let test_log_handler = TestLogHandler::new();

        inputs
            .into_iter()
            .for_each(|(payload, set_started, get_started_at)| {
                set_started(&mut subject);
                let started_at_before = get_started_at(&subject);
                let err = ScanError {
                    payload,
                    response_skeleton_opt: None,
                };

                subject.acknowledge_scan_error(&err, &logger);

                let started_at_after = get_started_at(&subject);
                assert!(
                    started_at_before.is_some(),
                    "Should've been started for {:?}",
                    DetailedScanType::from(&err.payload)
                );
                assert_eq!(
                    started_at_after,
                    None,
                    "Should've been unset for {:?}",
                    DetailedScanType::from(&err.payload)
                );
                test_log_handler.exists_log_containing(&format!(
                    "INFO: {test_name}: The {:?} scan ended in",
                    ScanType::from(DetailedScanType::from(&err.payload))
                ));
            })
    }

    #[test]
    fn log_error_works_fine() {
        init_test_logging();
        let test_name = "log_error_works_fine";
        let now = SystemTime::now();
        let input: Vec<(StartScanError, Box<dyn Fn(&str) -> String>, &str, &str)> = vec![
            (
                StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: None,
                    started_at: now,
                },
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: Payables scan was already initiated at {}",
                        StartScanError::timestamp_as_string(now)
                    )
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::ManualTriggerError(ManulTriggerError::AutomaticScanConflict),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied. Automatic mode prevents manual triggers.")
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::ManualTriggerError(ManulTriggerError::UnnecessaryRequest {
                    hint_opt: Some("Wise words".to_string()),
                }),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied expecting zero findings. Wise words")
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::ManualTriggerError(ManulTriggerError::UnnecessaryRequest {
                    hint_opt: None,
                }),
                Box::new(|sev| {
                    format!("{sev}: {test_name}: User requested Payables scan was denied expecting zero findings.")
                }),
                "INFO",
                "DEBUG",
            ),
            (
                StartScanError::CalledFromNullScanner,
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: Called from NullScanner, not the Payables scanner."
                    )
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::NoConsumingWalletFound,
                Box::new(|sev| {
                    format!("{sev}: {test_name}: Cannot initiate Payables scan because no consuming wallet was found.")
                }),
                "WARN",
                "WARN",
            ),
            (
                StartScanError::NothingToProcess,
                Box::new(|sev| {
                    format!(
                        "{sev}: {test_name}: There was nothing to process during Payables scan."
                    )
                }),
                "INFO",
                "DEBUG",
            ),
        ];
        let logger = Logger::new(test_name);
        let test_log_handler = TestLogHandler::new();

        input.into_iter().for_each(
            |(
                err,
                form_expected_log_msg,
                log_severity_for_externally_triggered_scans,
                log_severity_for_automatic_scans,
            )| {
                let test_log_error_by_mode =
                    |is_externally_triggered: bool, expected_severity: &str| {
                        err.log_error(&logger, ScanType::Payables, is_externally_triggered);
                        let expected_log_msg = form_expected_log_msg(expected_severity);
                        test_log_handler.exists_log_containing(&expected_log_msg);
                    };

                test_log_error_by_mode(true, log_severity_for_externally_triggered_scans);

                test_log_error_by_mode(false, log_severity_for_automatic_scans);
            },
        );
    }

    fn make_dull_subject() -> Scanners {
        Scanners {
            payable: Box::new(NullScanner::new()),
            aware_of_unresolved_pending_payable: false,
            initial_pending_payable_scan: false,
            pending_payable: Box::new(NullScanner::new()),
            receivable: Box::new(NullScanner::new()),
        }
    }
}
