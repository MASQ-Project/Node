// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::scanners::StartScanError;
use crate::accountant::{
    Accountant, ResponseSkeleton, ScanForNewPayables, ScanForPendingPayables, ScanForReceivables,
    ScanForRetryPayables,
};
use crate::sub_lib::accountant::ScanIntervals;
use crate::sub_lib::utils::{
    NotifyHandle, NotifyHandleReal, NotifyLaterHandle, NotifyLaterHandleReal,
};
use actix::{Actor, Context, Handler};
use masq_lib::logger::Logger;
use masq_lib::messages::ScanType;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ScanSchedulers {
    pub payable: PayableScanScheduler,
    pub pending_payable: SimplePeriodicalScanScheduler<ScanForPendingPayables>,
    pub receivable: SimplePeriodicalScanScheduler<ScanForReceivables>,
    pub reschedule_on_error_resolver: Box<dyn RescheduleScanOnErrorResolver>,
    pub automatic_scans_enabled: bool,
}

impl ScanSchedulers {
    pub fn new(scan_intervals: ScanIntervals, automatic_scans_enabled: bool) -> Self {
        Self {
            payable: PayableScanScheduler::new(scan_intervals.payable_scan_interval),
            pending_payable: SimplePeriodicalScanScheduler::new(
                scan_intervals.pending_payable_scan_interval,
            ),
            receivable: SimplePeriodicalScanScheduler::new(scan_intervals.receivable_scan_interval),
            reschedule_on_error_resolver: Box::new(RescheduleScanOnErrorResolverReal::default()),
            automatic_scans_enabled,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PayableScanSchedulerError {
    ScanForNewPayableAlreadyScheduled,
}

#[derive(Debug, PartialEq)]
pub enum SchedulingAfterHaltedScan {
    Schedule(ScanType),
    DoNotSchedule,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PayableSequenceScanner {
    NewPayables,
    RetryPayables,
    PendingPayables { initial_pending_payable_scan: bool },
}

impl From<PayableSequenceScanner> for ScanType {
    fn from(scanner: PayableSequenceScanner) -> Self {
        match scanner {
            PayableSequenceScanner::NewPayables => ScanType::Payables,
            PayableSequenceScanner::RetryPayables => ScanType::Payables,
            PayableSequenceScanner::PendingPayables { .. } => ScanType::PendingPayables,
        }
    }
}

pub struct PayableScanScheduler {
    pub new_payable_notify_later: Box<dyn NotifyLaterHandle<ScanForNewPayables, Accountant>>,
    pub dyn_interval_computer: Box<dyn NewPayableScanDynIntervalComputer>,
    pub inner: Arc<Mutex<PayableScanSchedulerInner>>,
    pub new_payable_interval: Duration,
    pub new_payable_notify: Box<dyn NotifyHandle<ScanForNewPayables, Accountant>>,
    pub retry_payable_notify: Box<dyn NotifyHandle<ScanForRetryPayables, Accountant>>,
}

impl PayableScanScheduler {
    fn new(new_payable_interval: Duration) -> Self {
        Self {
            new_payable_notify_later: Box::new(NotifyLaterHandleReal::default()),
            dyn_interval_computer: Box::new(NewPayableScanDynIntervalComputerReal::default()),
            inner: Arc::new(Mutex::new(PayableScanSchedulerInner::default())),
            new_payable_interval,
            new_payable_notify: Box::new(NotifyHandleReal::default()),
            retry_payable_notify: Box::new(NotifyHandleReal::default()),
        }
    }

    pub fn schedule_new_payable_scan(&self, ctx: &mut Context<Accountant>, logger: &Logger) {
        let inner = self.inner.lock().expect("couldn't acquire inner");
        let last_new_payable_scan_timestamp = inner.last_new_payable_scan_timestamp;
        let new_payable_interval = self.new_payable_interval;
        let now = SystemTime::now();
        if let Some(interval) = self.dyn_interval_computer.compute_interval(
            now,
            last_new_payable_scan_timestamp,
            new_payable_interval,
        ) {
            debug!(
                logger,
                "Scheduling a new-payable scan in {}ms",
                interval.as_millis()
            );

            let _ = self.new_payable_notify_later.notify_later(
                ScanForNewPayables {
                    response_skeleton_opt: None,
                },
                interval,
                ctx,
            );
        } else {
            debug!(logger, "Scheduling a new-payable scan asap");

            let _ = self.new_payable_notify.notify(
                ScanForNewPayables {
                    response_skeleton_opt: None,
                },
                ctx,
            );
        }
    }

    // This message is always inserted into the Accountant's mailbox with no delay.
    // Can also be triggered by command, following up after the PendingPayableScanner that
    // requests it. That's why the response skeleton is possible to be used.
    pub fn schedule_retry_payable_scan(
        &self,
        ctx: &mut Context<Accountant>,
        response_skeleton_opt: Option<ResponseSkeleton>,
        logger: &Logger,
    ) {
        debug!(logger, "Scheduling a retry-payable scan asap");

        self.retry_payable_notify.notify(
            ScanForRetryPayables {
                response_skeleton_opt,
            },
            ctx,
        )
    }
}

pub struct PayableScanSchedulerInner {
    pub last_new_payable_scan_timestamp: SystemTime,
}

impl Default for PayableScanSchedulerInner {
    fn default() -> Self {
        Self {
            last_new_payable_scan_timestamp: UNIX_EPOCH,
        }
    }
}

pub trait NewPayableScanDynIntervalComputer {
    fn compute_interval(
        &self,
        now: SystemTime,
        last_new_payable_scan_timestamp: SystemTime,
        interval: Duration,
    ) -> Option<Duration>;
}

#[derive(Default)]
pub struct NewPayableScanDynIntervalComputerReal {}

impl NewPayableScanDynIntervalComputer for NewPayableScanDynIntervalComputerReal {
    fn compute_interval(
        &self,
        now: SystemTime,
        last_new_payable_scan_timestamp: SystemTime,
        interval: Duration,
    ) -> Option<Duration> {
        let elapsed = now
            .duration_since(last_new_payable_scan_timestamp)
            .unwrap_or_else(|_| {
                panic!(
                    "Unexpected now ({:?}) earlier than past timestamp ({:?})",
                    now, last_new_payable_scan_timestamp
                )
            });
        if elapsed >= interval {
            None
        } else {
            Some(interval - elapsed)
        }
    }
}

pub struct SimplePeriodicalScanScheduler<Message: Default> {
    pub handle: Box<dyn NotifyLaterHandle<Message, Accountant>>,
    pub interval: Duration,
}

impl<Message> SimplePeriodicalScanScheduler<Message>
where
    Message: actix::Message + Default + Debug + Send + 'static,
    Accountant: Actor + Handler<Message>,
{
    fn new(interval: Duration) -> Self {
        Self {
            handle: Box::new(NotifyLaterHandleReal::default()),
            interval,
        }
    }
    pub fn schedule(&self, ctx: &mut Context<Accountant>, logger: &Logger) {
        // The default of the message implies response_skeleton_opt to be None because scheduled
        // scans don't respond
        let msg = Message::default();

        debug!(
            logger,
            "Scheduling a scan via {:?} in {}ms",
            msg,
            self.interval.as_millis()
        );

        let _ = self.handle.notify_later(msg, self.interval, ctx);
    }
}

// Scanners that conclude by scheduling a later scan (usually different from this one) must handle
// StartScanErrors carefully to maintain continuity and periodicity. Poor handling could disrupt
// the entire scan chain. Where possible, a different type of scan may be scheduled (avoiding
// repetition of the erroneous scan) to prevent a full panic, while ensuring no unresolved issues
// are left for future scans. A panic is justified only if the error is deemed impossible by design
// within the broader context of that location.
pub trait RescheduleScanOnErrorResolver {
    fn resolve_rescheduling_for_given_error(
        &self,
        scanner: PayableSequenceScanner,
        error: &StartScanError,
        is_externally_triggered: bool,
    ) -> SchedulingAfterHaltedScan;
}

#[derive(Default)]
pub struct RescheduleScanOnErrorResolverReal {}

impl RescheduleScanOnErrorResolver for RescheduleScanOnErrorResolverReal {
    fn resolve_rescheduling_for_given_error(
        &self,
        scanner: PayableSequenceScanner,
        error: &StartScanError,
        is_externally_triggered: bool,
    ) -> SchedulingAfterHaltedScan {
        match scanner {
            PayableSequenceScanner::NewPayables => {
                Self::resolve_new_payables(error, is_externally_triggered)
            }
            PayableSequenceScanner::RetryPayables => {
                Self::resolve_retry_payables(error, is_externally_triggered)
            }
            PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan,
            } => Self::resolve_pending_payables(
                error,
                initial_pending_payable_scan,
                is_externally_triggered,
            ),
        }
    }
}

impl RescheduleScanOnErrorResolverReal {
    fn resolve_new_payables(
        err: &StartScanError,
        is_externally_triggered: bool,
    ) -> SchedulingAfterHaltedScan {
        if is_externally_triggered {
            SchedulingAfterHaltedScan::DoNotSchedule
        } else if matches!(err, StartScanError::ScanAlreadyRunning { .. }) {
            unreachable!(
                "an automatic scan of NewPayableScanner should never interfere with itself {:?}",
                err
            )
        } else {
            SchedulingAfterHaltedScan::Schedule(ScanType::Payables)
        }
    }

    // This looks paradoxical, but this scanner is meant to be shielded by the scanner right before
    // it. That should ensure this scanner will not be requested if there was already something
    // fishy. We can go strict.
    fn resolve_retry_payables(
        err: &StartScanError,
        is_externally_triggered: bool,
    ) -> SchedulingAfterHaltedScan {
        if is_externally_triggered {
            SchedulingAfterHaltedScan::DoNotSchedule
        } else {
            unreachable!(
                "{:?} should be impossible with RetryPayableScanner in automatic mode",
                err
            )
        }
    }

    fn resolve_pending_payables(
        err: &StartScanError,
        initial_pending_payable_scan: bool,
        is_externally_triggered: bool,
    ) -> SchedulingAfterHaltedScan {
        if is_externally_triggered {
            SchedulingAfterHaltedScan::DoNotSchedule
        } else if err == &StartScanError::NothingToProcess {
            if initial_pending_payable_scan {
                SchedulingAfterHaltedScan::Schedule(ScanType::Payables)
            } else {
                unreachable!(
                    "the automatic pending payable scan should always be requested only in need, \
                    which contradicts the current StartScanError::NothingToProcess"
                )
            }
        } else if err == &StartScanError::NoConsumingWalletFound {
            SchedulingAfterHaltedScan::Schedule(ScanType::Payables)
        } else {
            unreachable!(
                "{:?} should be impossible with PendingPayableScanner in automatic mode",
                err
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::scan_schedulers::{
        NewPayableScanDynIntervalComputer, NewPayableScanDynIntervalComputerReal,
        PayableSequenceScanner, ScanSchedulers, SchedulingAfterHaltedScan,
    };
    use crate::accountant::scanners::{MTError, StartScanError};
    use crate::sub_lib::accountant::ScanIntervals;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use masq_lib::messages::ScanType;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn scan_schedulers_are_initialized_correctly() {
        let scan_intervals = ScanIntervals {
            payable_scan_interval: Duration::from_secs(14),
            pending_payable_scan_interval: Duration::from_secs(2),
            receivable_scan_interval: Duration::from_secs(7),
        };
        let automatic_scans_enabled = true;

        let schedulers = ScanSchedulers::new(scan_intervals, automatic_scans_enabled);

        assert_eq!(
            schedulers.payable.new_payable_interval,
            scan_intervals.payable_scan_interval
        );
        let payable_scheduler_inner = schedulers.payable.inner.lock().unwrap();
        assert_eq!(
            payable_scheduler_inner.last_new_payable_scan_timestamp,
            UNIX_EPOCH
        );
        assert_eq!(
            schedulers.pending_payable.interval,
            scan_intervals.pending_payable_scan_interval
        );
        assert_eq!(
            schedulers.receivable.interval,
            scan_intervals.receivable_scan_interval
        );
        assert_eq!(schedulers.automatic_scans_enabled, automatic_scans_enabled)
    }

    #[test]
    fn scan_dyn_interval_computer_computes_remaining_time_to_standard_interval_correctly() {
        let now = SystemTime::now();
        let inputs = vec![
            (
                now.checked_sub(Duration::from_secs(32)).unwrap(),
                Duration::from_secs(100),
                Duration::from_secs(68),
            ),
            (
                now.checked_sub(Duration::from_millis(1111)).unwrap(),
                Duration::from_millis(3333),
                Duration::from_millis(2222),
            ),
            (
                now.checked_sub(Duration::from_secs(200)).unwrap(),
                Duration::from_secs(204),
                Duration::from_secs(4),
            ),
        ];
        let subject = NewPayableScanDynIntervalComputerReal::default();

        inputs
            .into_iter()
            .for_each(|(past_instant, standard_interval, expected_result)| {
                let result = subject.compute_interval(now, past_instant, standard_interval);
                assert_eq!(
                    result,
                    Some(expected_result),
                    "We expected Some({}) ms, but got {:?} ms",
                    expected_result.as_millis(),
                    result.map(|duration| duration.as_millis())
                )
            })
    }

    #[test]
    fn scan_dyn_interval_computer_realizes_the_standard_interval_has_been_exceeded() {
        let now = SystemTime::now();
        let inputs = vec![
            (
                now.checked_sub(Duration::from_millis(32001)).unwrap(),
                Duration::from_secs(32),
            ),
            (
                now.checked_sub(Duration::from_millis(1112)).unwrap(),
                Duration::from_millis(1111),
            ),
            (
                now.checked_sub(Duration::from_secs(200)).unwrap(),
                Duration::from_secs(123),
            ),
        ];
        let subject = NewPayableScanDynIntervalComputerReal::default();

        inputs
            .into_iter()
            .enumerate()
            .for_each(|(idx, (past_instant, standard_interval))| {
                let result = subject.compute_interval(now, past_instant, standard_interval);
                assert_eq!(
                    result,
                    None,
                    "We expected None ms, but got {:?} ms at idx {}",
                    result.map(|duration| duration.as_millis()),
                    idx
                )
            })
    }

    #[test]
    fn scan_dyn_interval_computer_realizes_standard_interval_just_met() {
        let now = SystemTime::now();
        let subject = NewPayableScanDynIntervalComputerReal::default();

        let result = subject.compute_interval(
            now,
            now.checked_sub(Duration::from_secs(32)).unwrap(),
            Duration::from_secs(32),
        );

        assert_eq!(
            result,
            None,
            "We expected None ms, but got {:?} ms",
            result.map(|duration| duration.as_millis())
        )
    }

    #[test]
    #[should_panic(
        expected = "Unexpected now (SystemTime { tv_sec: 999999, tv_nsec: 0 }) earlier than past \
        timestamp (SystemTime { tv_sec: 1000000, tv_nsec: 0 })"
    )]
    fn scan_dyn_interval_computer_panics() {
        let now = UNIX_EPOCH
            .checked_add(Duration::from_secs(1_000_000))
            .unwrap();
        let subject = NewPayableScanDynIntervalComputerReal::default();

        let _ = subject.compute_interval(
            now.checked_sub(Duration::from_secs(1)).unwrap(),
            now,
            Duration::from_secs(32),
        );
    }

    lazy_static! {
        static ref ALL_START_SCAN_ERRORS: Vec<StartScanError> = {

            let candidates = vec![
                StartScanError::NothingToProcess,
                StartScanError::NoConsumingWalletFound,
                StartScanError::ScanAlreadyRunning { cross_scan_cause_opt: None, started_at: SystemTime::now()},
                StartScanError::ManualTriggerError(MTError::AutomaticScanConflict),
                StartScanError::CalledFromNullScanner
            ];


            let mut check_vec = candidates
                .iter()
                .fold(vec![],|mut acc, current|{
                    acc.push(ListOfStartScanErrors::number_variant(current));
                    acc
            });
            // Making sure we didn't count in one variant multiple times
            check_vec.dedup();
            assert_eq!(check_vec.len(), StartScanError::VARIANT_COUNT, "The check on variant \
            exhaustiveness failed.");
            candidates
        };
    }

    struct ListOfStartScanErrors<'a> {
        errors: Vec<&'a StartScanError>,
    }

    impl<'a> Default for ListOfStartScanErrors<'a> {
        fn default() -> Self {
            Self {
                errors: ALL_START_SCAN_ERRORS.iter().collect_vec(),
            }
        }
    }

    impl<'a> ListOfStartScanErrors<'a> {
        fn eliminate_already_tested_variants(
            mut self,
            errors_to_eliminate: Vec<StartScanError>,
        ) -> Self {
            let error_variants_to_remove: Vec<_> = errors_to_eliminate
                .iter()
                .map(Self::number_variant)
                .collect();
            self.errors
                .retain(|err| !error_variants_to_remove.contains(&Self::number_variant(*err)));
            self
        }

        fn number_variant(error: &StartScanError) -> usize {
            match error {
                StartScanError::NothingToProcess => 1,
                StartScanError::NoConsumingWalletFound => 2,
                StartScanError::ScanAlreadyRunning { .. } => 3,
                StartScanError::CalledFromNullScanner => 4,
                StartScanError::ManualTriggerError(..) => 5,
            }
        }
    }

    #[test]
    fn resolve_rescheduling_for_given_error_works_for_pending_payables_if_externally_triggered() {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        test_what_if_externally_triggered(
            &subject,
            PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: false,
            },
        );
        test_what_if_externally_triggered(
            &subject,
            PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: true,
            },
        );
    }

    fn test_what_if_externally_triggered(
        subject: &ScanSchedulers,
        scanner: PayableSequenceScanner,
    ) {
        ALL_START_SCAN_ERRORS
            .iter()
            .enumerate()
            .for_each(|(idx, error)| {
                let result = subject
                    .reschedule_on_error_resolver
                    .resolve_rescheduling_for_given_error(scanner, error, true);

                assert_eq!(
                    result,
                    SchedulingAfterHaltedScan::DoNotSchedule,
                    "We expected DoNotSchedule but got {:?} at idx {} for {:?}",
                    result,
                    idx,
                    scanner
                );
            })
    }

    #[test]
    fn resolve_error_for_pending_payables_if_nothing_to_process_and_initial_pending_payable_scan_true(
    ) {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        let result = subject
            .reschedule_on_error_resolver
            .resolve_rescheduling_for_given_error(
                PayableSequenceScanner::PendingPayables {
                    initial_pending_payable_scan: true,
                },
                &StartScanError::NothingToProcess,
                false,
            );

        assert_eq!(
            result,
            SchedulingAfterHaltedScan::Schedule(ScanType::Payables),
            "We expected Schedule(Payables) but got {:?}",
            result,
        );
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: the automatic pending payable scan \
        should always be requested only in need, which contradicts the current \
        StartScanError::NothingToProcess"
    )]
    fn resolve_error_for_pending_payables_if_nothing_to_process_and_initial_pending_payable_scan_false(
    ) {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        let _ = subject
            .reschedule_on_error_resolver
            .resolve_rescheduling_for_given_error(
                PayableSequenceScanner::PendingPayables {
                    initial_pending_payable_scan: false,
                },
                &StartScanError::NothingToProcess,
                false,
            );
    }

    #[test]
    fn resolve_error_for_pending_payables_if_no_consuming_wallet_found() {
        fn test_no_consuming_wallet_found(
            subject: &ScanSchedulers,
            scanner: PayableSequenceScanner,
        ) {
            let result = subject
                .reschedule_on_error_resolver
                .resolve_rescheduling_for_given_error(
                    scanner,
                    &StartScanError::NoConsumingWalletFound,
                    false,
                );

            assert_eq!(
                result,
                SchedulingAfterHaltedScan::Schedule(ScanType::Payables),
                "We expected Schedule(Payables) but got {:?} for {:?}",
                result,
                scanner
            );
        }

        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        test_no_consuming_wallet_found(
            &subject,
            PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: false,
            },
        );
        test_no_consuming_wallet_found(
            &subject,
            PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: true,
            },
        );
    }

    #[test]
    fn resolve_error_for_pending_payables_forbidden_states() {
        fn test_forbidden_states(
            subject: &ScanSchedulers,
            inputs: &ListOfStartScanErrors,
            initial_pending_payable_scan: bool,
        ) {
            inputs.errors.iter().for_each(|error| {
                let panic = catch_unwind(AssertUnwindSafe(|| {
                    subject
                        .reschedule_on_error_resolver
                        .resolve_rescheduling_for_given_error(
                            PayableSequenceScanner::PendingPayables {
                                initial_pending_payable_scan,
                            },
                            *error,
                            false,
                        )
                }))
                .unwrap_err();

                let panic_msg = panic.downcast_ref::<String>().unwrap();
                let expected_msg = format!(
                    "internal error: entered unreachable code: {:?} should be impossible with \
                    PendingPayableScanner in automatic mode",
                    error
                );
                assert_eq!(
                    panic_msg, &expected_msg,
                    "We expected '{}' but got '{}' for initial_pending_payable_scan = {}",
                    expected_msg, panic_msg, initial_pending_payable_scan
                )
            })
        }

        let inputs = ListOfStartScanErrors::default().eliminate_already_tested_variants(vec![
            StartScanError::NothingToProcess,
            StartScanError::NoConsumingWalletFound,
        ]);
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        test_forbidden_states(&subject, &inputs, false);
        test_forbidden_states(&subject, &inputs, true);
    }

    #[test]
    fn resolve_rescheduling_for_given_error_works_for_retry_payables_if_externally_triggered() {
        let subject = ScanSchedulers::new(ScanIntervals::default(), false);

        test_what_if_externally_triggered(&subject, PayableSequenceScanner::RetryPayables {});
    }

    #[test]
    fn any_automatic_scan_with_start_scan_error_is_fatal_for_retry_payables() {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        ALL_START_SCAN_ERRORS.iter().for_each(|error| {
            let panic = catch_unwind(AssertUnwindSafe(|| {
                subject
                    .reschedule_on_error_resolver
                    .resolve_rescheduling_for_given_error(
                        PayableSequenceScanner::RetryPayables,
                        error,
                        false,
                    )
            }))
            .unwrap_err();

            let panic_msg = panic.downcast_ref::<String>().unwrap();
            let expected_msg = format!(
                "internal error: entered unreachable code: {:?} should be impossible \
                with RetryPayableScanner in automatic mode",
                error
            );
            assert_eq!(
                panic_msg, &expected_msg,
                "We expected '{}' but got '{}'",
                expected_msg, panic_msg,
            )
        })
    }

    #[test]
    fn resolve_rescheduling_for_given_error_works_for_new_payables_if_externally_triggered() {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        test_what_if_externally_triggered(&subject, PayableSequenceScanner::NewPayables {});
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: an automatic scan of NewPayableScanner \
        should never interfere with itself ScanAlreadyRunning { cross_scan_cause_opt: None, started_at:"
    )]
    fn resolve_hint_for_new_payables_if_scan_is_already_running_error_and_is_automatic_scan() {
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        let _ = subject
            .reschedule_on_error_resolver
            .resolve_rescheduling_for_given_error(
                PayableSequenceScanner::NewPayables,
                &StartScanError::ScanAlreadyRunning {
                    cross_scan_cause_opt: None,
                    started_at: SystemTime::now(),
                },
                false,
            );
    }

    #[test]
    fn resolve_hint_for_new_payables_with_error_cases_resulting_in_future_rescheduling() {
        let inputs = ListOfStartScanErrors::default().eliminate_already_tested_variants(vec![
            StartScanError::ScanAlreadyRunning {
                cross_scan_cause_opt: None,
                started_at: SystemTime::now(),
            },
        ]);
        let subject = ScanSchedulers::new(ScanIntervals::default(), true);

        inputs.errors.iter().for_each(|error| {
            let result = subject
                .reschedule_on_error_resolver
                .resolve_rescheduling_for_given_error(
                    PayableSequenceScanner::NewPayables,
                    *error,
                    false,
                );

            assert_eq!(
                result,
                SchedulingAfterHaltedScan::Schedule(ScanType::Payables),
                "We expected Schedule(Payables) but got '{:?}'",
                result,
            )
        })
    }

    #[test]
    fn conversion_between_hintable_scanner_and_scan_type_works() {
        assert_eq!(
            ScanType::from(PayableSequenceScanner::NewPayables),
            ScanType::Payables
        );
        assert_eq!(
            ScanType::from(PayableSequenceScanner::RetryPayables),
            ScanType::Payables
        );
        assert_eq!(
            ScanType::from(PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: false
            }),
            ScanType::PendingPayables
        );
        assert_eq!(
            ScanType::from(PayableSequenceScanner::PendingPayables {
                initial_pending_payable_scan: true
            }),
            ScanType::PendingPayables
        );
    }
}
