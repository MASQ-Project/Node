// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::{
    Accountant, ResponseSkeleton, ScanForNewPayables, ScanForPendingPayables, ScanForReceivables,
    ScanForRetryPayables,
};
use crate::sub_lib::accountant::ScanIntervals;
use crate::sub_lib::utils::{
    NotifyHandle, NotifyHandleReal, NotifyLaterHandle, NotifyLaterHandleReal,
};
use actix::{Actor, Context, Handler};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct ScanSchedulers {
    pub payable: PayableScanScheduler<Accountant>,
    pub pending_payable: SimplePeriodicalScanScheduler<ScanForPendingPayables, Accountant>,
    pub receivable: SimplePeriodicalScanScheduler<ScanForReceivables, Accountant>,
    pub pending_payable_sequence_in_process: bool,
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
            pending_payable_sequence_in_process: false,
            automatic_scans_enabled,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PayableScanSchedulerError {
    ScanForNewPayableAlreadyScheduled,
}

#[derive(Debug, PartialEq)]
pub enum ScanScheduleHint {
    Schedule,
    DoNotSchedule,
}

pub struct PayableScanScheduler<Actor> {
    pub new_payable_notify_later: Box<dyn NotifyLaterHandle<ScanForNewPayables, Actor>>,
    pub dyn_interval_computer: Box<dyn NewPayableScanDynIntervalComputer>,
    pub inner: Arc<Mutex<PayableScanSchedulerInner>>,
    pub nominal_interval: Duration,
    pub new_payable_notify: Box<dyn NotifyHandle<ScanForNewPayables, Actor>>,
    pub retry_payable_notify: Box<dyn NotifyHandle<ScanForRetryPayables, Actor>>,
}

impl<ActorType> PayableScanScheduler<ActorType>
where
    ActorType: Actor<Context = Context<ActorType>>
        + Handler<ScanForNewPayables>
        + Handler<ScanForRetryPayables>,
{
    fn new(nominal_interval: Duration) -> Self {
        Self {
            new_payable_notify_later: Box::new(NotifyLaterHandleReal::default()),
            dyn_interval_computer: Box::new(NewPayableScanDynIntervalComputerReal::default()),
            inner: Arc::new(Mutex::new(PayableScanSchedulerInner::default())),
            nominal_interval,
            new_payable_notify: Box::new(NotifyHandleReal::default()),
            retry_payable_notify: Box::new(NotifyHandleReal::default()),
        }
    }

    pub fn schedule_for_new_payable(
        &self,
        ctx: &mut Context<ActorType>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        let inner = self.inner.lock().expect("couldn't acquire inner");
        let last_new_payable_timestamp = inner.last_new_payable_scan_timestamp;
        let nominal_interval = self.nominal_interval;
        let now = SystemTime::now();
        if let Some(interval) = self.dyn_interval_computer.compute_interval(
            now,
            last_new_payable_timestamp,
            nominal_interval,
        ) {
            let _ = self.new_payable_notify_later.notify_later(
                ScanForNewPayables {
                    response_skeleton_opt: None,
                },
                interval,
                ctx,
            );
        } else {
            let _ = self.new_payable_notify.notify(
                ScanForNewPayables {
                    response_skeleton_opt: None,
                },
                ctx,
            );
        }
    }

    // Can be triggered by a command, whereas the finished pending payable scanner is followed up
    // by this scheduled message that can bear the response skeleton. This message is inserted into
    // the Accountant's mailbox with no delay
    pub fn schedule_for_retry_payable(
        &self,
        ctx: &mut Context<ActorType>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
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
    pub next_new_payable_scan_already_scheduled: bool,
}

impl Default for PayableScanSchedulerInner {
    fn default() -> Self {
        Self {
            last_new_payable_scan_timestamp: UNIX_EPOCH,
            next_new_payable_scan_already_scheduled: false,
        }
    }
}

pub trait AutomaticSchedulingAwareScanner<ScannerSpecification> {
    fn is_currently_automatically_scheduled(&self, spec: ScannerSpecification) -> bool;
    fn mark_as_automatically_scheduled(&self, spec: ScannerSpecification);
    fn mark_as_already_automatically_utilized(&self, spec: ScannerSpecification);
}

impl AutomaticSchedulingAwareScanner<PayableScannerMode> for PayableScanScheduler<Accountant> {
    fn is_currently_automatically_scheduled(&self, spec: PayableScannerMode) -> bool {
        todo!()
    }

    fn mark_as_automatically_scheduled(&self, spec: PayableScannerMode) {
        todo!()
    }

    fn mark_as_already_automatically_utilized(&self, spec: PayableScannerMode) {
        todo!()
    }
}

#[derive(Clone, Copy)]
pub enum PayableScannerMode {
    Retry,
    NewPayable,
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

pub struct SimplePeriodicalScanScheduler<Message: Default, ActorType> {
    phantom: PhantomData<ActorType>,
    pub is_currently_automatically_scheduled: RefCell<bool>,
    pub handle: Box<dyn NotifyLaterHandle<Message, ActorType>>,
    pub interval: Duration,
}

impl<Message, ActorType> SimplePeriodicalScanScheduler<Message, ActorType>
where
    Message: actix::Message + Default + 'static + Send,
    ActorType: Actor<Context = Context<ActorType>> + Handler<Message>,
{
    fn new(interval: Duration) -> Self {
        Self {
            phantom: PhantomData::default(),
            is_currently_automatically_scheduled: RefCell::new(false),
            handle: Box::new(NotifyLaterHandleReal::default()),
            interval,
        }
    }
    pub fn schedule(
        &self,
        ctx: &mut Context<ActorType>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) {
        // The default of the message implies response_skeleton_opt to be None because scheduled
        // scans don't respond
        let _ = self
            .handle
            .notify_later(Message::default(), self.interval, ctx);

        if response_skeleton_opt == None {
            self.mark_as_automatically_scheduled(())
        }
    }
}

impl<M: Default, A> AutomaticSchedulingAwareScanner<()> for SimplePeriodicalScanScheduler<M, A> {
    fn is_currently_automatically_scheduled(&self, _spec: ()) -> bool {
        *self.is_currently_automatically_scheduled.borrow()
    }

    fn mark_as_automatically_scheduled(&self, _spec: ()) {
        self.is_currently_automatically_scheduled.replace(true);
    }

    fn mark_as_already_automatically_utilized(&self, _spec: ()) {
        self.is_currently_automatically_scheduled.replace(false);
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::scan_schedulers::{
        AutomaticSchedulingAwareScanner, NewPayableScanDynIntervalComputer,
        NewPayableScanDynIntervalComputerReal, PayableScanScheduler, PayableScanSchedulerError,
        PayableScanSchedulerInner, PayableScannerMode, ScanSchedulers,
        SimplePeriodicalScanScheduler,
    };
    use crate::accountant::{
        ResponseSkeleton, ScanForNewPayables, ScanForPendingPayables, ScanForReceivables,
        ScanForRetryPayables, SkeletonOptHolder,
    };
    use crate::sub_lib::accountant::ScanIntervals;
    use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
    use actix::{Actor, Context, Handler, Message, System};
    use std::marker::PhantomData;
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
            schedulers.payable.nominal_interval,
            scan_intervals.payable_scan_interval
        );
        let payable_scheduler_inner = schedulers.payable.inner.lock().unwrap();
        assert_eq!(
            payable_scheduler_inner.last_new_payable_scan_timestamp,
            UNIX_EPOCH
        );
        assert_eq!(
            payable_scheduler_inner.next_new_payable_scan_already_scheduled,
            false
        );
        assert_eq!(
            schedulers.pending_payable.interval,
            scan_intervals.pending_payable_scan_interval
        );
        assert_eq!(
            *schedulers
                .pending_payable
                .is_currently_automatically_scheduled
                .borrow(),
            false
        );
        assert_eq!(
            schedulers.receivable.interval,
            scan_intervals.receivable_scan_interval
        );
        assert_eq!(
            *schedulers
                .receivable
                .is_currently_automatically_scheduled
                .borrow(),
            false
        );
        assert_eq!(schedulers.pending_payable_sequence_in_process, false);
        assert_eq!(schedulers.automatic_scans_enabled, true)
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
        expected = "Unexpected now (SystemTime { tv_sec: 999999, tv_nsec: 0 }) earlier \
    than past timestamp (SystemTime { tv_sec: 1000000, tv_nsec: 0 })"
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

    #[derive(Message)]
    struct TestSetupCarrierMsg<MessageToSchedule, Scheduler, ScheduleScanner, ScannerSpecs> {
        scheduler: Scheduler,
        automated_message: MessageToSchedule,
        user_triggered_message: MessageToSchedule,
        schedule_scanner: ScheduleScanner,
        scan_specs: ScannerSpecs,
    }

    struct ActixContextProvidingActor {}

    impl Actor for ActixContextProvidingActor {
        type Context = Context<Self>;
    }

    impl Handler<ScanForNewPayables> for ActixContextProvidingActor {
        type Result = ();

        fn handle(&mut self, _msg: ScanForNewPayables, _ctx: &mut Self::Context) -> Self::Result {
            intentionally_blank!()
        }
    }

    impl Handler<ScanForRetryPayables> for ActixContextProvidingActor {
        type Result = ();

        fn handle(&mut self, _msg: ScanForRetryPayables, _ctx: &mut Self::Context) -> Self::Result {
            intentionally_blank!()
        }
    }

    impl Handler<ScanForReceivables> for ActixContextProvidingActor {
        type Result = ();

        fn handle(&mut self, _msg: ScanForReceivables, _ctx: &mut Self::Context) -> Self::Result {
            intentionally_blank!()
        }
    }

    impl<MessageToSchedule, Scheduler, ScheduleScanner, ScannerSpecs>
        Handler<TestSetupCarrierMsg<MessageToSchedule, Scheduler, ScheduleScanner, ScannerSpecs>>
        for ActixContextProvidingActor
    where
        ScheduleScanner: Fn(&Scheduler, MessageToSchedule, &mut Self::Context),
        Scheduler: AutomaticSchedulingAwareScanner<ScannerSpecs>,
        ScannerSpecs: Copy,
    {
        type Result = ();

        fn handle(
            &mut self,
            msg: TestSetupCarrierMsg<MessageToSchedule, Scheduler, ScheduleScanner, ScannerSpecs>,
            ctx: &mut Self::Context,
        ) -> Self::Result {
            let scheduler = msg.scheduler;
            let scan_specs = msg.scan_specs;

            let first_state = scheduler.is_currently_automatically_scheduled(scan_specs);
            scheduler.mark_as_automatically_scheduled(scan_specs);
            let second_state = scheduler.is_currently_automatically_scheduled(scan_specs);
            scheduler.mark_as_already_automatically_utilized(scan_specs);
            let third_state = scheduler.is_currently_automatically_scheduled(scan_specs);
            (&msg.schedule_scanner)(&scheduler, msg.automated_message, ctx);
            let fourth_state = scheduler.is_currently_automatically_scheduled(scan_specs);
            scheduler.mark_as_already_automatically_utilized(scan_specs);
            let fifth_state = scheduler.is_currently_automatically_scheduled(scan_specs);
            (&msg.schedule_scanner)(&scheduler, msg.user_triggered_message, ctx);
            let sixth_state = scheduler.is_currently_automatically_scheduled(scan_specs);

            assert_eq!(first_state, false);
            assert_eq!(second_state, true);
            assert_eq!(third_state, false);
            assert_eq!(fourth_state, true);
            assert_eq!(fifth_state, false);
            assert_eq!(sixth_state, false);
            System::current().stop();
        }
    }

    #[test]
    fn scheduling_registration_on_simple_periodical_scanner_works() {
        let system = System::new("test");
        let system_killer = SystemKillerActor::new(Duration::from_secs(10));
        system_killer.start();
        let test_performer_addr = ActixContextProvidingActor {}.start();
        let duration = Duration::from_secs(1000);
        let scheduler = SimplePeriodicalScanScheduler::new(duration);
        let automated_message = ScanForReceivables {
            response_skeleton_opt: None,
        };
        let user_triggered_message = ScanForReceivables {
            response_skeleton_opt: Some(ResponseSkeleton {
                client_id: 12,
                context_id: 7,
            }),
        };
        let schedule_scanner =
            |scheduler: &SimplePeriodicalScanScheduler<
                ScanForReceivables,
                ActixContextProvidingActor,
            >,
             msg: ScanForReceivables,
             ctx: &mut Context<ActixContextProvidingActor>| {
                scheduler.schedule(ctx, msg.response_skeleton_opt);
            };
        let scan_specs = ();
        let msg = TestSetupCarrierMsg {
            scheduler,
            automated_message,
            user_triggered_message,
            schedule_scanner,
            scan_specs,
        };

        test_performer_addr.try_send(msg).unwrap();

        assert_eq!(system.run(), 0)
    }

    #[test]
    fn scheduling_registration_for_new_payable_on_notify_later_handle_works_in_complex_scheduler() {
        todo!(
            "maybe now first consider where it's gonna help you to know the current schedule state"
        )
        // let system = System::new("test");
        // let system_killer = SystemKillerActor::new(Duration::from_secs(10));
        // system_killer.start();
        // let test_performer_addr = ActixContextProvidingActor {}.start();
        // let duration = Duration::from_secs(1000);
        // let scheduler = PayableScanScheduler::new(duration);
        // let automated_message = ScanForNewPayables{ response_skeleton_opt: None };
        // let user_triggered_message = ScanForNewPayables{response_skeleton_opt: Some(ResponseSkeleton{ client_id: 12, context_id: 7 })};
        // let schedule_scanner = |scheduler: &PayableScanScheduler<ActixContextProvidingActor>, msg: ScanForReceivables, ctx: &mut Context<ActixContextProvidingActor>|{
        //     scheduler.schedule_for_new_payable(ctx, msg.response_skeleton_opt);
        // };
        // let scan_specs = PayableScannerMode::NewPayable;
        // let msg = TestSetupCarrierMsg {
        //     scheduler,
        //     automated_message,
        //     user_triggered_message,
        //     schedule_scanner,
        //     scan_specs,
        // };
        //
        // test_performer_addr.try_send(msg).unwrap();
        //
        // assert_eq!(system.run(), 0)
    }
}
