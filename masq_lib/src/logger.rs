// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::messages::{SerializableLogLevel, ToMessageBody, UiLogBroadcast};
use crate::ui_gateway::{MessageTarget, NodeToUiMessage};
use actix::Recipient;
use lazy_static::lazy_static;
use log::logger;
use log::Level;
#[allow(unused_imports)]
use log::Metadata;
#[allow(unused_imports)]
use log::Record;
use std::sync::Mutex;

lazy_static! {
    pub static ref LOG_RECIPIENT_OPT: LogRecipient = LogRecipient {
        recipient_mutex_opt: Mutex::new(None)
    };
}

pub struct LogRecipient {
    recipient_mutex_opt: Mutex<Option<Recipient<NodeToUiMessage>>>,
}

const UI_MESSAGE_LOG_LEVEL: Level = Level::Info;

impl LogRecipient {
    pub fn prepare_log_recipient(recipient: Recipient<NodeToUiMessage>) {
        todo!("put the recipient into the mutex")
    }

    fn transmit_log(&self, msg: String, log_level: SerializableLogLevel) {
        todo!("try acquire the lock on the mutex and check if the recipient is in place, if yes, send the log message")
    }
}

#[derive(Clone)]
pub struct Logger {
    name: String,
    #[cfg(not(feature = "no_test_share"))]
    level_limit: Level,
}

#[macro_export]
macro_rules! trace {
    ($logger: expr, $($arg:tt)*) => {
        $logger.trace(|| format!($($arg)*))
    };
}

#[macro_export]
macro_rules! debug {
    ($logger: expr, $($arg:tt)*) => {
        $logger.debug(|| format!($($arg)*))
    };
}

#[macro_export]
macro_rules! info {
    ($logger: expr, $($arg:tt)*) => {
        $logger.info(|| format!($($arg)*))
    };
}

#[macro_export]
macro_rules! warning {
    ($logger: expr, $($arg:tt)*) => {
        $logger.warning(|| format!($($arg)*))
    };
}

#[macro_export]
macro_rules! error {
    ($logger: expr, $($arg:tt)*) => {
        $logger.error(|| format!($($arg)*))
    };
}

#[macro_export]
macro_rules! fatal {
    ($logger: expr, $($arg:tt)*) => {
        $logger.fatal(|| format!($($arg)*))
    };
}

impl Logger {
    pub fn new(name: &str) -> Logger {
        Logger {
            name: String::from(name),
            #[cfg(not(feature = "no_test_share"))]
            level_limit: Level::Trace,
        }
    }

    pub fn trace<F>(&self, log_function: F)
    where
        F: FnOnce() -> String,
    {
        self.generic_log(Level::Trace, log_function);
    }

    pub fn debug<F>(&self, log_function: F)
    where
        F: FnOnce() -> String,
    {
        self.generic_log(Level::Debug, log_function);
    }

    pub fn info<F>(&self, log_function: F)
    where
        F: FnOnce() -> String,
    {
        self.generic_log(Level::Info, log_function);
    }

    pub fn warning<F>(&self, log_function: F)
    where
        F: FnOnce() -> String,
    {
        self.generic_log(Level::Warn, log_function);
    }

    pub fn error<F>(&self, log_function: F)
    where
        F: FnOnce() -> String,
    {
        self.generic_log(Level::Error, log_function);
    }

    pub fn fatal<F>(&self, log_function: F) -> !
    where
        F: FnOnce() -> String,
    {
        let msg = log_function();
        self.log(Level::Error, msg.clone());
        panic!("{}", msg);
    }

    pub fn trace_enabled(&self) -> bool {
        self.level_enabled(Level::Trace)
    }

    pub fn debug_enabled(&self) -> bool {
        self.level_enabled(Level::Debug)
    }

    pub fn info_enabled(&self) -> bool {
        self.level_enabled(Level::Info)
    }

    pub fn warning_enabled(&self) -> bool {
        self.level_enabled(Level::Warn)
    }

    pub fn error_enabled(&self) -> bool {
        self.level_enabled(Level::Error)
    }

    fn generic_log<F>(&self, level: Level, log_function: F)
    where
        F: FnOnce() -> String,
    {
        match (self.level_enabled(level), level.le(&UI_MESSAGE_LOG_LEVEL)) {
            // Log Levels         : Error < Warn < Info < Debug < Trace
            // Log only if        : self.level_enabled(level)        ~ level <= level_limit
            // Transmit only if   : level.le(&UI_MESSAGE_LOG_LEVEL)  ~ level <= UI_MESSAGE_LOG_LEVEL
            (true, true) => {
                let msg = log_function();
                Self::transmit(msg.clone(), level.into());
                self.log(level, msg);
            }
            (true, false) => self.log(level, log_function()),
            (false, true) => Self::transmit(log_function(), level.into()),
            _ => {
                return;
            }
        }
    }

    fn transmit(msg: String, log_level: SerializableLogLevel) {
        let recipient_mutex_log = unsafe { &LOG_RECIPIENT_OPT.recipient_mutex_opt };
        if let Some(recipient) = recipient_mutex_log
            .lock()
            .expect("log recipient mutex poisoned")
            .as_ref()
        {
            let actix_msg = NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiLogBroadcast { msg, log_level }.tmb(0),
            };
            recipient.try_send(actix_msg).expect("UiGateway is dead")
        }
    }

    pub fn log(&self, level: Level, msg: String) {
        logger().log(
            &Record::builder()
                .args(format_args!("{}", msg))
                .module_path(Some(&self.name))
                .level(level)
                .build(),
        );
    }
}

impl From<Level> for SerializableLogLevel {
    fn from(native_level: Level) -> Self {
        match native_level {
            Level::Error => SerializableLogLevel::Error,
            Level::Warn => SerializableLogLevel::Warn,
            Level::Info => SerializableLogLevel::Info,
            _ => panic!("The level you're converting is below log broadcast level."),
        }
    }
}

#[cfg(feature = "no_test_share")]
impl Logger {
    pub fn level_enabled(&self, level: Level) -> bool {
        logger().enabled(&Metadata::builder().level(level).target(&self.name).build())
    }
}

#[cfg(not(feature = "no_test_share"))]
impl Logger {
    pub fn level_enabled(&self, level: Level) -> bool {
        level <= self.level_limit
    }

    pub fn set_level_for_a_test(&mut self, level: Level) {
        self.level_limit = level
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ToMessageBody, UiLogBroadcast};
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::ui_gateway::{MessageBody, MessagePath};
    use actix::{Actor, AsyncContext, Context, Handler, Message, System};
    use chrono::format::StrftimeItems;
    use chrono::{DateTime, Local};
    use crossbeam_channel::{unbounded, Sender};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::thread::ThreadId;
    use std::time::{Duration, SystemTime};

    lazy_static! {
        static ref TEST_LOG_RECIPIENT_GUARD: Mutex<()> = Mutex::new(());
    }

    struct TestUiGateway {
        received_messages: Arc<Mutex<Vec<NodeToUiMessage>>>,
        expected_msg_count: usize,
    }

    impl TestUiGateway {
        fn new(msg_count: usize, recording_arc: &Arc<Mutex<Vec<NodeToUiMessage>>>) -> Self {
            Self {
                received_messages: recording_arc.clone(),
                expected_msg_count: msg_count,
            }
        }
    }

    impl Actor for TestUiGateway {
        type Context = Context<Self>;
    }

    impl Handler<NodeToUiMessage> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, msg: NodeToUiMessage, ctx: &mut Self::Context) -> Self::Result {
            let mut inner = self.received_messages.lock().unwrap();
            inner.push(msg);
            if inner.len() == self.expected_msg_count {
                System::current().stop();
            }
        }
    }

    #[derive(Message)]
    struct ScheduleStop {
        timeout: Duration,
    }

    #[derive(Message)]
    struct Stop {}

    impl Handler<ScheduleStop> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, msg: ScheduleStop, ctx: &mut Self::Context) -> Self::Result {
            ctx.set_mailbox_capacity(0); //this is important
            ctx.notify_later(Stop {}, msg.timeout);
        }
    }

    impl Handler<Stop> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, msg: Stop, ctx: &mut Self::Context) -> Self::Result {
            System::current().stop()
        }
    }

    static mut SENDER: Option<Sender<NodeToUiMessage>> = None;

    #[test]
    fn transmit_log_handles_overloading_by_sending_msgs_from_multiple_threads() {
        let _test_guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        let expected_msg_count = 10000;
        let factor = {
            let factor = f64::sqrt(expected_msg_count as f64);
            if factor.fract() != 0.0 {
                panic!("we expect pure square number")
            };
            factor as usize
        };
        let (tx, rx) = unbounded();
        unsafe { SENDER = Some(tx) }
        let before = SystemTime::now();
        overloading_function(
            move || {
                unsafe { SENDER.as_ref().unwrap().clone().send(create_msg()).unwrap() };
            },
            DoAllAtOnce { factor },
        );
        let mut counter = 0;
        loop {
            rx.recv().unwrap();
            counter += 1;
            if counter == expected_msg_count {
                break;
            }
        }
        let after = SystemTime::now();
        let labour_time_example = after.duration_since(before).unwrap();
        let recording_arc = Arc::new(Mutex::new(vec![]));
        let ui_gateway = TestUiGateway::new(expected_msg_count, &recording_arc);
        let addr = ui_gateway.start();
        let recipient = addr.clone().recipient();
        {
            LOG_RECIPIENT_OPT
                .recipient_mutex_opt
                .lock()
                .unwrap()
                .replace(recipient);
        }
        let system = System::new("test_system");
        addr.try_send(ScheduleStop {
            timeout: Duration::from_secs(8),
        })
        .unwrap();

        addr.try_send(DoAllAtOnce { factor }).unwrap();

        let start = SystemTime::now();
        system.run();
        let end = SystemTime::now();
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), expected_msg_count);
        let measured = end.duration_since(start).unwrap();
        let safe_estimation = labour_time_example * 5;
        eprintln!(
            "Measured: {}; estimation: {}",
            measured.as_micros(),
            safe_estimation.as_micros()
        );
        assert!(measured < safe_estimation) //this should pass even on slow machines
    }

    #[derive(Message)]
    struct DoAllAtOnce {
        factor: usize,
    }

    impl Handler<DoAllAtOnce> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, msg: DoAllAtOnce, ctx: &mut Self::Context) -> Self::Result {
            overloading_function(send_message_to_recipient, msg)
        }
    }

    fn overloading_function<C>(closure: C, msg: DoAllAtOnce)
    where
        C: Fn() + Send + 'static + Clone,
    {
        let barrier_arc = Arc::new(Barrier::new(msg.factor));
        let mut join_handle_vector = Vec::new();
        (0..msg.factor).for_each(|_| {
            let barrier_arc_clone = Arc::clone(&barrier_arc);
            let closure_clone = closure.clone();
            join_handle_vector.push(thread::spawn(move || {
                barrier_arc_clone.wait();
                (0..msg.factor).for_each(|_| closure_clone())
            }))
        });
    }

    fn create_msg() -> NodeToUiMessage {
        NodeToUiMessage {
            target: MessageTarget::AllClients,
            body: MessageBody {
                opcode: "whatever".to_string(),
                path: MessagePath::FireAndForget,
                payload: Ok(String::from("our message")),
            },
        }
    }
    fn send_message_to_recipient() {
        let recipient = LOG_RECIPIENT_OPT.recipient_mutex_opt.lock().unwrap();
        recipient.as_ref().unwrap().try_send(create_msg()).unwrap()
    }

    #[test]
    fn prepare_log_recipient_works() {
        // todo!("finish me");
        // first use the test-only guard invented here as an aid; it prevents other tests
        // using the production static variable to interfere with each other

        // set the production static variable to None inside the mutex (we have to be sure
        // it is always None when the test starts)

        // make sure that when you call this function the static variable gets
        // populated with the recipient with appropriate use of asser_eq!()

        // let _ = LogRecipient::prepare_log_recipient(recipient);

        // lazy_static! {
        //     static ref TEST_LOG_RECIPIENT_GUARD: Mutex<()> = Mutex::new(());
        // }

        // let recipient = LogRecipient {
        //     recipient_opt: Mutex::new(None),
        // };

        // let recipient = ();
        //
        // let _ = LogRecipient::prepare_log_recipient(recipient);
    }

    #[test]
    fn conversion_between_different_level_types_is_enabled() {
        assert_eq!(
            SerializableLogLevel::from(Level::Error),
            SerializableLogLevel::Error
        );
        assert_eq!(
            SerializableLogLevel::from(Level::Warn),
            SerializableLogLevel::Warn
        );
        assert_eq!(
            SerializableLogLevel::from(Level::Info),
            SerializableLogLevel::Info
        );
    }

    #[test]
    #[should_panic(expected = "The level you're converting is below log broadcast level.")]
    fn conversion_between_levels_below_log_broadcast_level_should_panic() {
        let level_below_broadcast_level = Level::Debug;
        let serializable_level_below_broadcast_level: SerializableLogLevel =
            level_below_broadcast_level.into();
    }

    #[test]
    fn transmit_fn_can_handle_no_recipients() {
        let system = System::new("Trying to transmit with no recipient");

        Logger::transmit("Some message".to_string(), Level::Warn.into());

        System::current().stop();
        system.run();
    }

    #[test]
    fn generic_log_when_neither_logging_nor_transmitting() {
        init_test_logging();
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        let logger = make_logger_at_level(Level::Debug);
        let system = System::new("Neither Logging, Nor Transmitting");
        let ui_gateway_recording_arc = Arc::new(Mutex::new(vec![]));
        let ui_gateway = TestUiGateway::new(0, &ui_gateway_recording_arc);
        let recipient = ui_gateway.start().recipient();
        unsafe {
            LOG_RECIPIENT_OPT
                .recipient_mutex_opt
                .lock()
                .unwrap()
                .replace(recipient);
        }
        let log_function = move || "This is a trace log.".to_string();

        logger.trace(log_function);

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(*ui_gateway_recording, vec![]);
        TestLogHandler::new().exists_no_log_containing("This is a trace log.");
    }

    #[test]
    fn generic_log_when_only_logging() {
        init_test_logging();
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        let logger = make_logger_at_level(Level::Debug);
        let system = System::new("Only Logging, Not Transmitting");
        let ui_gateway_recording_arc = Arc::new(Mutex::new(vec![]));
        let ui_gateway = TestUiGateway::new(0, &ui_gateway_recording_arc);
        let recipient = ui_gateway.start().recipient();
        unsafe {
            LOG_RECIPIENT_OPT
                .recipient_mutex_opt
                .lock()
                .unwrap()
                .replace(recipient);
        }
        let log_function = move || "This is a debug log.".to_string();

        logger.debug(log_function);

        System::current().stop();
        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(*ui_gateway_recording, vec![]);
        TestLogHandler::new().exists_log_containing("This is a debug log.");
    }

    #[test]
    fn generic_log_when_only_transmitting() {
        init_test_logging();
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        let logger = make_logger_at_level(Level::Warn);
        let system = System::new("transmitting but not logging");
        let ui_gateway_recording_arc = Arc::new(Mutex::new(vec![]));
        let ui_gateway = TestUiGateway::new(1, &ui_gateway_recording_arc);
        let recipient = ui_gateway.start().recipient();
        unsafe {
            LOG_RECIPIENT_OPT
                .recipient_mutex_opt
                .lock()
                .unwrap()
                .replace(recipient);
        }
        let log_function = move || "This is an info.".to_string();

        logger.info(log_function);

        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();

        assert_eq!(
            *ui_gateway_recording,
            vec![NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiLogBroadcast {
                    msg: "This is an info.".to_string(),
                    log_level: SerializableLogLevel::Info
                }
                .tmb(0)
            }]
        );

        TestLogHandler::new().exists_no_log_containing("This is an info.");
    }

    #[test]
    fn generic_log_when_both_logging_and_transmitting() {
        init_test_logging();
        let _guard = TEST_LOG_RECIPIENT_GUARD.lock().unwrap();
        let logger = make_logger_at_level(Level::Debug);
        let system = System::new("logging ang transmitting");
        let ui_gateway_recording_arc = Arc::new(Mutex::new(vec![]));
        let ui_gateway = TestUiGateway::new(1, &ui_gateway_recording_arc);
        let recipient = ui_gateway.start().recipient();
        unsafe {
            LOG_RECIPIENT_OPT
                .recipient_mutex_opt
                .lock()
                .unwrap()
                .replace(recipient);
        }
        let log_function = move || "This is a warning. Be careful.".to_string();

        logger.warning(log_function);

        system.run();
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            *ui_gateway_recording,
            vec![NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiLogBroadcast {
                    msg: "This is a warning. Be careful.".to_string(),
                    log_level: SerializableLogLevel::Warn
                }
                .tmb(0)
            }]
        );
        TestLogHandler::new().exists_log_containing("WARN: test: This is a warning. Be careful.");
    }

    #[test]
    fn logger_format_is_correct() {
        init_test_logging();
        let one_logger = Logger::new("logger_format_is_correct_one");
        let another_logger = Logger::new("logger_format_is_correct_another");

        let before = SystemTime::now();
        error!(one_logger, "one log");
        error!(another_logger, "another log");
        let after = SystemTime::now();

        let tlh = TestLogHandler::new();
        let prefix_len = "0000-00-00T00:00:00.000".len();
        let thread_id = thread::current().id();
        let one_log = tlh.get_log_at(tlh.exists_log_containing(&format!(
            " Thd{}: ERROR: logger_format_is_correct_one: one log",
            thread_id_as_string(thread_id)
        )));
        let another_log = tlh.get_log_at(tlh.exists_log_containing(&format!(
            " Thd{}: ERROR: logger_format_is_correct_another: another log",
            thread_id_as_string(thread_id)
        )));
        let before_str = timestamp_as_string(&before);
        let after_str = timestamp_as_string(&after);
        assert_between(&one_log[..prefix_len], &before_str, &after_str);
        assert_between(&another_log[..prefix_len], &before_str, &after_str);
    }

    #[test]
    fn trace_is_not_computed_when_log_level_is_debug() {
        let logger = make_logger_at_level(Level::Debug);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.trace(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&false));
    }

    #[test]
    fn debug_is_not_computed_when_log_level_is_info() {
        let logger = make_logger_at_level(Level::Info);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.debug(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&false));
    }

    #[test]
    fn info_is_not_computed_when_log_level_is_warn() {
        let logger = make_logger_at_level(Level::Warn);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.info(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&false));
    }

    #[test]
    fn warning_is_not_computed_when_log_level_is_error() {
        let logger = make_logger_at_level(Level::Error);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.warning(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&false));
    }

    #[test]
    fn trace_is_computed_when_log_level_is_trace() {
        let logger = make_logger_at_level(Level::Trace);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.trace(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&true));
    }

    #[test]
    fn debug_is_computed_when_log_level_is_debug() {
        let logger = make_logger_at_level(Level::Debug);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.debug(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&true));
    }

    #[test]
    fn info_is_computed_when_log_level_is_info() {
        let logger = make_logger_at_level(Level::Info);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.info(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&true));
    }

    #[test]
    fn warn_is_computed_when_log_level_is_warn() {
        let logger = make_logger_at_level(Level::Warn);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.warning(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&true));
    }

    #[test]
    fn error_is_computed_when_log_level_is_error() {
        let logger = make_logger_at_level(Level::Error);
        let signal = Arc::new(Mutex::new(Some(false)));
        let signal_c = signal.clone();

        let log_function = move || {
            let mut locked_signal = signal_c.lock().unwrap();
            locked_signal.replace(true);
            "blah".to_string()
        };

        logger.error(log_function);

        assert_eq!(signal.lock().unwrap().as_ref(), Some(&true));
    }

    #[test]
    fn macros_work() {
        init_test_logging();
        let logger = Logger::new("test");

        trace!(logger, "trace! {}", 42);
        debug!(logger, "debug! {}", 42);
        info!(logger, "info! {}", 42);
        warning!(logger, "warning! {}", 42);
        error!(logger, "error! {}", 42);

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("trace! 42");
        tlh.exists_log_containing("debug! 42");
        tlh.exists_log_containing("info! 42");
        tlh.exists_log_containing("warning! 42");
        tlh.exists_log_containing("error! 42");
    }

    fn timestamp_as_string(timestamp: &SystemTime) -> String {
        let date_time: DateTime<Local> = DateTime::from(timestamp.clone());
        let fmt = StrftimeItems::new("%Y-%m-%dT%H:%M:%S%.3f");
        date_time.format_with_items(fmt).to_string()
    }

    fn thread_id_as_string(thread_id: ThreadId) -> String {
        let thread_id_str = format!("{:?}", thread_id);
        String::from(&thread_id_str[9..(thread_id_str.len() - 1)])
    }

    fn assert_between(candidate: &str, before: &str, after: &str) {
        assert_eq!(
            candidate >= before,
            true,
            "{} is before the interval {} - {}",
            candidate,
            before,
            after,
        );
        assert_eq!(
            candidate <= after,
            true,
            "{} is after the interval {} - {}",
            candidate,
            before,
            after,
        );
    }

    fn make_logger_at_level(level: Level) -> Logger {
        Logger {
            name: "test".to_string(),
            #[cfg(not(feature = "no_test_share"))]
            level_limit: level,
        }
    }
}
