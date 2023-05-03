use std::fmt::{Debug, Formatter};
// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::constants::CURRENT_SCHEMA_VERSION;
use crate::constants::{
    CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION, CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION,
    DNS_RESOLVER_FAILURE_CURRENT_VERSION, GOSSIP_CURRENT_VERSION, GOSSIP_FAILURE_CURRENT_VERSION,
    NODE_RECORD_INNER_CURRENT_VERSION,
};
use crate::data_version::DataVersion;
use crate::messages::SerializableLogLevel;
#[cfg(not(feature = "log_recipient_test"))]
use crate::messages::{ToMessageBody, UiLogBroadcast};
#[cfg(feature = "log_recipient_test")]
use crate::test_utils::utils::MutexIncrementInset;
#[cfg(not(feature = "log_recipient_test"))]
use crate::ui_gateway::MessageTarget;
use crate::ui_gateway::NodeToUiMessage;
use actix::Recipient;
use lazy_static::lazy_static;
use log::logger;
use log::Level;
#[allow(unused_imports)]
use log::Metadata;
#[allow(unused_imports)]
use log::Record;
use std::sync::Mutex;
use std::{io, thread};
use time::format_description::parse;
use time::OffsetDateTime;

const UI_MESSAGE_LOG_LEVEL: Level = Level::Info;
pub const TIME_FORMATTING_STRING: &str =
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]";

lazy_static! {
    pub static ref LOG_RECIPIENT_OPT: Mutex<Option<Recipient<NodeToUiMessage>>> = Mutex::new(None);
}

#[cfg(not(feature = "log_recipient_test"))]
pub fn prepare_log_recipient(recipient: Recipient<NodeToUiMessage>) {
    if LOG_RECIPIENT_OPT
        .lock()
        .expect("log recipient poisoned")
        .replace(recipient)
        .is_some()
    {
        panic!("Log recipient should be initiated only once")
    }
}

#[derive(Clone)]
pub struct Logger {
    name: String,
    #[cfg(not(feature = "no_test_share"))]
    level_limit: Level,
}

impl Debug for Logger {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Logger{{ name: \"{}\" }}", self.name)
    }
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
            (true, true) => {
                let msg = log_function();
                self.log(level, msg.clone());
                Self::transmit(msg, level.into());
            }
            (true, false) => self.log(level, log_function()),
            (false, true) => Self::transmit(log_function(), level.into()),
            _ => {}
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

    pub fn log_plain_message(target: &str, msg: String) {
        logger().log(
            &Record::builder()
                .args(format_args!("{}", msg))
                // .module_path(Some(&self.name))
                .metadata(Metadata::builder().target(target).build())
                // .level(level)
                .build(),
        );
    }

    pub fn log_file_heading(test_name: &str) {
        let test_tag_opt = if cfg!(test) {
            format!("Printed in test enviroment for test: {}\n", test_name)
        } else {
            "".to_string()
        };
        let heading = format!(
            "\
        {}\
        Node Version: {}\n\
        Database Schema Version: {}\n\
        OS: {}\n\
        client_request_payload::MIGRATIONS {}\n\
        client_response_payload::MIGRATIONS {}\n\
        dns_resolve_failure::MIGRATIONS {}\n\
        gossip::MIGRATIONS {}\n\
        gossip_failure::MIGRATIONS {}\n\
        node_record_inner::MIGRATIONS {}",
            test_tag_opt,
            env!("CARGO_PKG_VERSION"),
            CURRENT_SCHEMA_VERSION,
            std::env::consts::OS,
            Logger::data_version_pretty_print(CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(DNS_RESOLVER_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(NODE_RECORD_INNER_CURRENT_VERSION)
        );

        Self::log_plain_message("plain_message", heading);
    }

    fn data_version_pretty_print(dv: DataVersion) -> String {
        format!("({}.{})", dv.major, dv.minor)
    }

    #[cfg(not(feature = "log_recipient_test"))]
    fn transmit(msg: String, log_level: SerializableLogLevel) {
        if let Some(recipient) = LOG_RECIPIENT_OPT
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
}

#[cfg(feature = "no_test_share")]
impl Logger {
    pub fn level_enabled(&self, level: Level) -> bool {
        logger().enabled(&Metadata::builder().level(level).target(&self.name).build())
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

pub fn real_format_function(
    write: &mut dyn io::Write,
    timestamp: OffsetDateTime,
    record: &Record,
) -> Result<(), io::Error> {
    let timestamp = timestamp
        .format(&parse(TIME_FORMATTING_STRING).expect("Unable to parse the formatting type."))
        .expect("Unable to format date and time.");
    let thread_id_str = format!("{:?}", thread::current().id());
    let thread_id = &thread_id_str[9..(thread_id_str.len() - 1)];
    let level = record.level();
    let name = record.module_path().unwrap_or("<unnamed>");
    write.write_fmt(format_args!(
        "{} Thd{}: {}: {}: ",
        timestamp, thread_id, level, name
    ))?;
    write.write_fmt(*record.args())
}

#[cfg(feature = "log_recipient_test")]
lazy_static! {
    pub static ref INITIALIZATION_COUNTER: Mutex<MutexIncrementInset> =
        Mutex::new(MutexIncrementInset(0));
}

#[cfg(feature = "log_recipient_test")]
impl Logger {
    pub fn transmit(_msg: String, _log_level: SerializableLogLevel) {}
}

#[cfg(feature = "log_recipient_test")]
pub fn prepare_log_recipient(_recipient: Recipient<NodeToUiMessage>) {
    INITIALIZATION_COUNTER.lock().unwrap().0 += 1;
}

#[cfg(not(feature = "no_test_share"))]
impl Logger {
    pub fn level_enabled(&self, level: Level) -> bool {
        level <= self.level_limit
    }

    pub fn set_level_for_test(&mut self, level: Level) {
        self.level_limit = level
    }
}

#[cfg(not(feature = "no_test_share"))]
lazy_static! {
    pub static ref TEST_LOG_RECIPIENT_GUARD: Mutex<()> = Mutex::new(());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION, CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION,
        DNS_RESOLVER_FAILURE_CURRENT_VERSION, GOSSIP_CURRENT_VERSION,
        GOSSIP_FAILURE_CURRENT_VERSION, NODE_RECORD_INNER_CURRENT_VERSION,
    };
    use crate::messages::{ToMessageBody, UiLogBroadcast};
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
    use actix::{Actor, AsyncContext, Context, Handler, Message, System};
    use crossbeam_channel::{unbounded, Sender};
    use regex::Regex;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread;
    use std::thread::{JoinHandle, ThreadId};
    use std::time::{Duration, SystemTime};
    use time::format_description::parse;
    use time::OffsetDateTime;

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

        fn started(&mut self, ctx: &mut Self::Context) {
            ctx.set_mailbox_capacity(0); //important
            ctx.notify_later(Stop {}, Duration::from_secs(10));
        }
    }

    impl Handler<NodeToUiMessage> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, msg: NodeToUiMessage, _ctx: &mut Self::Context) -> Self::Result {
            let mut inner = self.received_messages.lock().unwrap();
            inner.push(msg);
            if inner.len() == self.expected_msg_count {
                System::current().stop();
            }
        }
    }

    //to be used as a guarantee that the test cannot hang
    #[derive(Message)]
    struct Stop {}

    impl Handler<Stop> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, _msg: Stop, _ctx: &mut Self::Context) -> Self::Result {
            System::current().stop()
        }
    }

    fn overloading_function<C>(
        closure: C,
        join_handles_container: &mut Vec<JoinHandle<()>>,
        factor: usize,
    ) where
        C: Fn() + Send + 'static + Clone,
    {
        (0..factor).for_each(|_| {
            let closure_clone = closure.clone();
            join_handles_container.push(thread::spawn(move || {
                (0..factor).for_each(|_| {
                    thread::sleep(Duration::from_millis(10));
                    closure_clone()
                })
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
        let recipient = LOG_RECIPIENT_OPT
            .lock()
            .expect("SMTR: failed to lock LOG_RECIPIENT_OPT");
        recipient
            .as_ref()
            .expect("SMTR: failed to get ref for recipient")
            .try_send(create_msg())
            .expect("SMTR: failed to send message")
    }

    fn see_about_join_handles(container: Vec<JoinHandle<()>>) {
        container
            .into_iter()
            .for_each(|handle| handle.join().unwrap())
    }

    lazy_static! {
        static ref SENDER: Mutex<Option<Sender<NodeToUiMessage>>> = Mutex::new(None);
    }

    #[test]
    fn transmit_log_handles_overloading_by_sending_msgs_from_multiple_threads() {
        let _test_guard = TEST_LOG_RECIPIENT_GUARD
            .lock()
            .expect("Unable to lock TEST_LOG_RECIPIENT_GUARD");
        let msgs_in_total = 10000;
        let factor = match f64::sqrt(msgs_in_total as f64) {
            x if x.fract() == 0.0 => x as usize,
            _ => panic!("we expected a square number"),
        };
        //Starting an experiment to get a feeling for what might be a standard amount of time
        //to send the given number of messages, in this case using a crossbeam channel.
        //The outcome is going to be a template in the final assertion where we want to check
        //an efficiency of the overloaded actix recipient combined with a mutex
        let mut container_for_join_handles = Vec::new();
        let (tx, rx) = unbounded();
        {
            SENDER.lock().expect("Unable to lock SENDER").replace(tx);
        }
        let (template_before, template_after) = {
            let before = SystemTime::now();
            overloading_function(
                move || {
                    SENDER
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .send(create_msg())
                        .unwrap();
                },
                &mut container_for_join_handles,
                factor,
            );

            let mut counter = 0;
            loop {
                rx.recv().expect("Unable to call recv() on rx");
                counter += 1;
                if counter == msgs_in_total {
                    break;
                }
            }
            let after = SystemTime::now();
            (before, after)
        };
        see_about_join_handles(container_for_join_handles);
        let mut container_for_join_handles = vec![];
        let time_example_of_similar_labour = template_after
            .duration_since(template_before)
            .expect("Unable to unwrap the duration_sice for template after");
        let recording_arc = Arc::new(Mutex::new(vec![]));
        let fake_ui_gateway = TestUiGateway::new(msgs_in_total, &recording_arc);
        let system = System::new("test_system");
        let addr = fake_ui_gateway.start();
        let recipient = addr.clone().recipient();
        {
            LOG_RECIPIENT_OPT
                .lock()
                .expect("Unable to lock LOG_RECIPIENT_OPT")
                .replace(recipient);
        }

        overloading_function(
            send_message_to_recipient,
            &mut container_for_join_handles,
            factor,
        );

        let (actual_start, actual_end) = {
            let start = SystemTime::now();
            system.run();
            let end = SystemTime::now();
            (start, end)
        };
        see_about_join_handles(container_for_join_handles);
        //we have now two samples and can go to compare them
        let recording = recording_arc.lock().expect("Unable to lock recording arc");
        assert_eq!(recording.len(), msgs_in_total);
        let measured = actual_end
            .duration_since(actual_start)
            .expect("Unable to run duration_since on actual_end");
        let safe_estimation = (time_example_of_similar_labour / 2) * 5;
        eprintln!("measured {:?}, template {:?}", measured, safe_estimation);
        //a flexible requirement that should pass on a slow machine as well
        assert!(measured < safe_estimation)
    }

    fn prepare_test_environment<'a>() -> MutexGuard<'a, ()> {
        let guard = TEST_LOG_RECIPIENT_GUARD
            .lock()
            .expect("Unable to lock TEST_LOG_RECIPIENT_GUARD");
        LOG_RECIPIENT_OPT
            .lock()
            .expect("Unable to lock LOG_RECIPIENT_OPT")
            .take();
        guard
    }

    #[test]
    fn prepare_log_recipient_works() {
        let _guard = prepare_test_environment();
        let message_container_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new("prepare log recipient");
        let ui_gateway = TestUiGateway::new(0, &message_container_arc);
        let recipient: Recipient<NodeToUiMessage> = ui_gateway.start().recipient();

        prepare_log_recipient(recipient);

        LOG_RECIPIENT_OPT
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_send(create_msg())
            .unwrap();
        System::current().stop();
        system.run();
        let message_container = message_container_arc.lock().unwrap();
        assert_eq!(*message_container, vec![create_msg()]);
    }

    #[test]
    fn prepare_log_recipient_should_be_called_only_once_panic() {
        let _guard = prepare_test_environment();
        let ui_gateway = TestUiGateway::new(0, &Arc::new(Mutex::new(vec![])));
        let recipient: Recipient<NodeToUiMessage> = ui_gateway.start().recipient();
        prepare_log_recipient(recipient.clone());

        let caught_panic =
            catch_unwind(AssertUnwindSafe(|| prepare_log_recipient(recipient))).unwrap_err();

        let panic_message = caught_panic.downcast_ref::<&str>().unwrap();
        assert_eq!(
            *panic_message,
            "Log recipient should be initiated only once"
        )
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
    fn conversion_from_too_low_level_panics_for_debug() {
        let level_below_broadcast_level = Level::Debug;
        let _serializable_level_below_broadcast_level: SerializableLogLevel =
            level_below_broadcast_level.into();
    }

    #[test]
    #[should_panic(expected = "The level you're converting is below log broadcast level.")]
    fn conversion_from_too_low_level_panics_for_trace() {
        let level_below_broadcast_level = Level::Trace;
        let _serializable_level_below_broadcast_level: SerializableLogLevel =
            level_below_broadcast_level.into();
    }

    #[test]
    fn transmit_fn_can_handle_no_recipients() {
        let _guard = prepare_test_environment();
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
        {
            LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
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
        {
            LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
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
        {
            LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
        }
        let log_function = move || "This is an info log.".to_string();

        logger.info(log_function);

        system.run(); //shut down after receiving the expected count of messages
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            *ui_gateway_recording,
            vec![NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiLogBroadcast {
                    msg: "This is an info log.".to_string(),
                    log_level: SerializableLogLevel::Info
                }
                .tmb(0)
            }]
        );
        TestLogHandler::new().exists_no_log_containing("This is an info log.");
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
        {
            LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
        }
        let log_function = move || "This is a warn log.".to_string();

        logger.warning(log_function);

        system.run(); //shut down after receiving the expected count of messages
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            *ui_gateway_recording,
            vec![NodeToUiMessage {
                target: MessageTarget::AllClients,
                body: UiLogBroadcast {
                    msg: "This is a warn log.".to_string(),
                    log_level: SerializableLogLevel::Warn
                }
                .tmb(0)
            }]
        );
        TestLogHandler::new().exists_log_containing("WARN: test: This is a warn log.");
    }

    #[test]
    fn logger_prints_log_file_heading() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let subject = Logger::new("logger_prints_log_file_heading");

        subject.log_file_heading();

        // TODO Dont forget to wright an intergration test proving the first line is omitted, also make sure the end of the headding is properly followed by the first log.
        let expected_headding = format!(
            r#"Printed in test enviroment for logger: logger_prints_log_file_heading\n
Node Version: v\d\.\d\.\d\n
Database Schema Version: \d+\n
OS: {}\n
client_request_payload::MIGRATIONS {}\n
client_response_payload::MIGRATIONS {}\n
dns_resolve_failure::MIGRATIONS {}\n
gossip::MIGRATIONS {}\n
gossip_failure::MIGRATIONS {}\n
node_record_inner::MIGRATIONS {}"#,
            std::env::consts::OS,
            Logger::data_version_pretty_print(CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(DNS_RESOLVER_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(NODE_RECORD_INNER_CURRENT_VERSION)
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching(&expected_headding);
    }

    #[test]
    fn data_version_pretty_print_preductise_right_formatt() {
        let data_version = DataVersion { major: 0, minor: 1 };

        let result = Logger::data_version_pretty_print(data_version);

        assert_eq!(result, "(0.1)".to_string());
    }

    #[test]
    fn logger_format_is_correct() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let one_logger = Logger::new("logger_format_is_correct_one");
        let another_logger = Logger::new("logger_format_is_correct_another");

        let before = OffsetDateTime::now_utc();
        error!(one_logger, "one log");
        error!(another_logger, "another log");
        let after = OffsetDateTime::now_utc();

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
        let before_str = timestamp_as_string(before);
        let after_str = timestamp_as_string(after);
        assert_between(&one_log[..prefix_len], &before_str, &after_str);
        assert_between(&another_log[..prefix_len], &before_str, &after_str);
    }

    #[test]
    fn expermintal_format_test() {
        init_test_logging();

        let subject = Logger::new("logger");
        subject.log_file_heading();

        let tlh = TestLogHandler::new();
        tlh.exists_log_matching("blar");


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
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Warn);
        let log_function = move || "info 445566".to_string();

        logger.info(log_function);

        TestLogHandler::new().exists_no_log_containing("info 445566")
    }

    #[test]
    fn warning_is_not_computed_when_log_level_is_error() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Error);
        let log_function = move || "warning 335566".to_string();

        logger.warning(log_function);

        TestLogHandler::new().exists_no_log_containing("warning 335566")
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
        let _guard = prepare_test_environment();
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
        let _guard = prepare_test_environment();
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
        let _guard = prepare_test_environment();
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
        let _guard = prepare_test_environment();
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

    #[test]
    fn debug_for_logger() {
        let logger = Logger::new("my new logger");

        assert_eq!(format!("{:?}", logger), "Logger{ name: \"my new logger\" }")
    }

    fn timestamp_as_string(timestamp: OffsetDateTime) -> String {
        timestamp
            .format(&parse(TIME_FORMATTING_STRING).unwrap())
            .unwrap()
    }

    fn thread_id_as_string(thread_id: ThreadId) -> String {
        let thread_id_str = format!("{:?}", thread_id);
        String::from(&thread_id_str[9..(thread_id_str.len() - 1)])
    }

    fn assert_between(candidate: &str, before: &str, after: &str) {
        assert_eq!(
            candidate >= before && candidate <= after,
            true,
            "{} is outside the interval {} - {}",
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
