use std::fmt::{Debug, Formatter};
// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::constants::{
    CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION, CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION,
    CURRENT_SCHEMA_VERSION, DNS_RESOLVER_FAILURE_CURRENT_VERSION, GOSSIP_CURRENT_VERSION,
    GOSSIP_FAILURE_CURRENT_VERSION, NODE_RECORD_INNER_CURRENT_VERSION,
};
use crate::data_version::DataVersion;
use crate::messages::SerializableLogLevel;
use crate::messages::{ToMessageBody, UiLogBroadcast};
use crate::ui_gateway::MessageTarget;
use crate::ui_gateway::NodeToUiMessage;
use crate::utils::test_is_running;
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

pub static mut POINTER_TO_FORMAT_FUNCTION: fn(
    &mut dyn io::Write,
    OffsetDateTime,
    &Record,
) -> Result<(), io::Error> = heading_format_function;
const UI_MESSAGE_LOG_LEVEL: Level = Level::Info;
pub const TIME_FORMATTING_STRING: &str =
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]";

lazy_static! {
    pub static ref LOG_RECIPIENT_OPT: Mutex<Option<Recipient<NodeToUiMessage>>> = Mutex::new(None);
}

pub fn prepare_log_recipient(recipient: Recipient<NodeToUiMessage>) {
    if LOG_RECIPIENT_OPT
        .lock()
        .expect("log recipient poisoned")
        .replace(recipient)
        .is_some()
        && !test_is_running()
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

    pub fn log_file_heading() -> String {
        format!(
            "
          _____ ______  ________   ________   _______          Node Version: {}
        /   _  | _   /|/  __   /|/  ______/|/   __   /|        Database Schema Version: {}
       /  / /__///  / /  /|/  / /  /|_____|/  /|_/  / /        OS: {}
      /  / |__|//  / /  __   / /_____   /|/  / '/  / /         client_request_payload::MIGRATIONS {}
     /  / /    /  / /  / /  / |_____/  / /  /__/  / /          client_response_payload::MIGRATIONS {}
    /__/ /    /__/ /__/ /__/ /________/ /_____   / /           dns_resolve_failure::MIGRATIONS {}
    |__|/     |__|/|__|/|__|/|________|/|____/__/ /            gossip::MIGRATIONS {}
                                             |__|/             gossip_failure::MIGRATIONS {}
                                                               node_record_inner::MIGRATIONS {}\n",
            env!("CARGO_PKG_VERSION"),
            CURRENT_SCHEMA_VERSION,
            std::env::consts::OS,
            Logger::data_version_pretty_print(CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(DNS_RESOLVER_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(NODE_RECORD_INNER_CURRENT_VERSION)
        )
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
            // If there's an error sending to the UI Gateway, we're going to ignore it. Most likely
            // this error is because we're running in a test that hasn't set up the UI Gateway
            // or the Actor system properly. If we're running in production, somebody else will
            // presently notice that the UI Gateway is in trouble and panic for us.
            let _ = recipient.try_send(actix_msg);
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

pub fn heading_format_function(
    write: &mut dyn io::Write,
    _timestamp: OffsetDateTime,
    record: &Record,
) -> Result<(), io::Error> {
    write.write_fmt(*record.args())
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

// #[cfg(feature = "log_recipient_test")]
// lazy_static! {
//     pub static ref INITIALIZATION_COUNTER: Mutex<MutexIncrementInset> =
//         Mutex::new(MutexIncrementInset(0));
// }
//
// #[cfg(feature = "log_recipient_test")]
// impl Logger {
//     pub fn transmit(_msg: String, _log_level: SerializableLogLevel) {}
// }
//
// #[cfg(feature = "log_recipient_test")]
// pub fn prepare_log_recipient(_recipient: Recipient<NodeToUiMessage>) {
//     INITIALIZATION_COUNTER.lock().unwrap().0 += 1;
// }

// #[cfg(not(feature = "no_test_share"))]
impl Logger {
    pub fn level_enabled(&self, level: Level) -> bool {
        level <= self.level_limit
    }

    pub fn set_level_for_test(&mut self, level: Level) {
        self.level_limit = level
    }
}

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
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::ui_gateway::{MessageBody, MessagePath, MessageTarget};
    use actix::{Actor, Context, Handler, Message, System};
    use crossbeam_channel::{unbounded, Sender};
    use lazy_static::lazy_static;
    use regex::Regex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread;
    use std::thread::{JoinHandle, ThreadId};
    use std::time::{Duration, Instant, SystemTime};
    use time::format_description::parse;
    use time::OffsetDateTime;

    lazy_static! {
        static ref START_TIMESTAMP: Instant = Instant::now();
    }

    struct TestUiGateway {
        expected_msg_count: u32,
        received_message_count: Arc<AtomicU32>,
        _seconds_to_live: usize,
    }

    impl TestUiGateway {
        fn new(msg_count: u32, received_message_count: Arc<AtomicU32>) -> Self {
            Self {
                expected_msg_count: msg_count,
                received_message_count,
                _seconds_to_live: 10,
            }
        }
    }

    impl Actor for TestUiGateway {
        type Context = Context<Self>;

        fn started(&mut self, ctx: &mut Self::Context) {
            ctx.set_mailbox_capacity(0); //important
                                         // ctx.notify_later(Stop {}, Duration::from_secs(self.seconds_to_live as u64));
        }
    }

    impl Handler<NodeToUiMessage> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, _msg: NodeToUiMessage, _ctx: &mut Self::Context) -> Self::Result {
            let prev_count = self.received_message_count.fetch_add(1, Ordering::Relaxed);
            if prev_count + 1 == self.expected_msg_count {
                System::current().stop();
            }
        }
    }

    //to be used as a guarantee that the test cannot hang
    #[derive(Message)]
    #[rtype(result = "()")]
    struct Stop {}

    impl Handler<Stop> for TestUiGateway {
        type Result = ();

        fn handle(&mut self, _msg: Stop, _ctx: &mut Self::Context) -> Self::Result {
            System::current().stop()
        }
    }

    lazy_static! {
        static ref SENDER: Mutex<Option<Sender<NodeToUiMessage>>> = Mutex::new(None);
    }

    #[test]
    fn transmit_log_handles_overloading_by_sending_msgs_from_multiple_threads() {
        let _test_guard = prepare_test_environment();
        let thread_count = 100;
        let msgs_per_thread = 100;
        let total_msg_count = thread_count * msgs_per_thread;
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
                move |thread_idx, msg_idx| {
                    SENDER
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .send(create_msg(thread_idx, msg_idx))
                        .unwrap();
                },
                &mut container_for_join_handles,
                thread_count,
                msgs_per_thread,
            );

            let mut counter = 0;
            loop {
                rx.recv().expect("Unable to call recv() on rx");
                let limit = total_msg_count;
                counter += 1;
                if counter == limit {
                    break;
                }
            }
            let after = SystemTime::now();
            (before, after)
        };
        see_about_join_handles(container_for_join_handles);
        let time_example_of_similar_labour = template_after
            .duration_since(template_before)
            .expect("Unable to unwrap the duration_since for template after");
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let container_for_join_handles_arc: Arc<Mutex<Vec<JoinHandle<()>>>> =
            Arc::new(Mutex::new(vec![]));
        let container_for_join_handles_arc_inner = container_for_join_handles_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let fake_ui_gateway =
                TestUiGateway::new(total_msg_count as u32, received_message_count_arc_inner);
            let addr = fake_ui_gateway.start();
            let recipient = addr.clone().recipient();
            {
                LOG_RECIPIENT_OPT
                    .lock()
                    .expect("Unable to lock LOG_RECIPIENT_OPT")
                    .replace(recipient);
            }
            let mut container_for_join_handles = vec![];

            overloading_function(
                send_message_to_recipient,
                &mut container_for_join_handles,
                thread_count,
                msgs_per_thread,
            );

            container_for_join_handles_arc_inner
                .lock()
                .as_mut()
                .unwrap()
                .extend(container_for_join_handles);
        });

        let (actual_start, actual_end) = {
            let start = SystemTime::now();
            system.run().unwrap();
            let end = SystemTime::now();
            (start, end)
        };
        let mut container_for_join_handles = vec![];
        {
            let mut mutex_guard = container_for_join_handles_arc.lock().unwrap();
            while mutex_guard.len() > 0 {
                container_for_join_handles.push(mutex_guard.remove(0));
            }
        }
        see_about_join_handles(container_for_join_handles);
        //we have now two samples and can go to compare them
        assert_eq!(
            received_message_count_arc.load(Ordering::Relaxed),
            total_msg_count as u32
        );
        let measured = actual_end
            .duration_since(actual_start)
            .expect("Unable to run duration_since on actual_end");
        let safe_estimation = (time_example_of_similar_labour / 2) * 5;
        eprintln!("measured {:?}, template {:?}", measured, safe_estimation);
        // a flexible requirement that should pass on a slow machine as well
        assert!(
            measured < safe_estimation,
            "measured = {:?}, safe_estimation = {:?}",
            measured,
            safe_estimation
        )
    }

    #[test]
    fn prepare_log_recipient_works() {
        let _guard = prepare_test_environment();
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(0, received_message_count_arc_inner);
            let recipient: Recipient<NodeToUiMessage> = ui_gateway.start().recipient();

            prepare_log_recipient(recipient);

            LOG_RECIPIENT_OPT
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_send(create_msg(0, 0))
                .unwrap();
            System::current().stop();
        });
        system.run().unwrap();
        assert_eq!(received_message_count_arc.load(Ordering::Relaxed), 1);
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
        let system = System::new();

        Logger::transmit("Some message 1".to_string(), Level::Warn.into());

        System::current().stop();
        system.run().unwrap();
    }

    #[test]
    fn transmit_fn_does_not_panic_when_ui_gateway_or_system_is_missing() {
        let _guard = prepare_test_environment();

        Logger::transmit("Some message 2".to_string(), Level::Warn.into());

        // No panic: test passes
    }

    #[test]
    fn generic_log_when_neither_logging_nor_transmitting() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Debug);
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(0, received_message_count_arc_inner);
            let recipient = ui_gateway.start().recipient();
            {
                LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
            }
            let log_function = move || "This is a trace log.".to_string();

            logger.trace(log_function);

            System::current().stop();
        });
        system.run().unwrap();
        assert_eq!(received_message_count_arc.load(Ordering::Relaxed), 0);
        TestLogHandler::new().exists_no_log_containing("This is a trace log.");
    }

    #[test]
    fn generic_log_when_only_logging() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Debug);
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(0, received_message_count_arc_inner);
            let recipient = ui_gateway.start().recipient();
            {
                LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
            }
            let log_function = move || "This is a debug log.".to_string();

            logger.debug(log_function);

            System::current().stop();
        });
        system.run().unwrap();
        assert_eq!(received_message_count_arc.load(Ordering::Relaxed), 0);
        TestLogHandler::new().exists_log_containing("This is a debug log.");
    }

    #[test]
    fn generic_log_when_only_transmitting() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Warn);
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(1, received_message_count_arc_inner);
            let recipient = ui_gateway.start().recipient();
            {
                LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
            }
            let log_function = move || "This is an info log.".to_string();

            logger.info(log_function);
        });
        system.run().unwrap(); //shut down after receiving the expected count of messages
        assert_eq!(received_message_count_arc.load(Ordering::Relaxed), 1);
        TestLogHandler::new().exists_no_log_containing("This is an info log.");
    }

    #[test]
    fn generic_log_when_both_logging_and_transmitting() {
        init_test_logging();
        let _guard = prepare_test_environment();
        let logger = make_logger_at_level(Level::Debug);
        let received_message_count_arc = Arc::new(AtomicU32::new(0));
        let received_message_count_arc_inner = received_message_count_arc.clone();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(1, received_message_count_arc_inner);
            let recipient = ui_gateway.start().recipient();
            {
                LOG_RECIPIENT_OPT.lock().unwrap().replace(recipient);
            }
            let log_function = move || "This is a warn log.".to_string();

            logger.warning(log_function);
        });
        system.run().unwrap(); //shut down after receiving the expected count of messages
        assert_eq!(received_message_count_arc.load(Ordering::Relaxed), 1);
        TestLogHandler::new().exists_log_containing("WARN: test: This is a warn log.");
    }

    #[test]
    fn log_file_heading_print_right_format() {
        let heading_result = Logger::log_file_heading();

        let mut expected_heading_regex = format!(
            r#"^
          _____ ______  ________   ________   _______          Node Version: \d\.\d\.\d
        /   _  | _   /|/  __   /|/  ______/|/   __   /|        Database Schema Version: \d+
       /  / /__///  / /  /|/  / /  /|_____|/  /|_/  / /        OS: {}
      /  / |__|//  / /  __   / /_____   /|/  / '/  / /         client_request_payload::MIGRATIONS {}
     /  / /    /  / /  / /  / |_____/  / /  /__/  / /          client_response_payload::MIGRATIONS {}
    /__/ /    /__/ /__/ /__/ /________/ /_____   / /           dns_resolve_failure::MIGRATIONS {}
    |__|/     |__|/|__|/|__|/|________|/|____/__/ /            gossip::MIGRATIONS {}
                                             |__|/             gossip_failure::MIGRATIONS {}
                                                               node_record_inner::MIGRATIONS {}\n"#,
            std::env::consts::OS,
            Logger::data_version_pretty_print(CLIENT_REQUEST_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(CLIENT_RESPONSE_PAYLOAD_CURRENT_VERSION),
            Logger::data_version_pretty_print(DNS_RESOLVER_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_CURRENT_VERSION),
            Logger::data_version_pretty_print(GOSSIP_FAILURE_CURRENT_VERSION),
            Logger::data_version_pretty_print(NODE_RECORD_INNER_CURRENT_VERSION)
        );

        let replace_rules = vec![("(", "\\("), (")", "\\)"), ("|", "\\|")];
        replace_rules.into_iter().for_each(|x| {
            expected_heading_regex = expected_heading_regex.replace(x.0, x.1);
        });

        let regex = Regex::new(&expected_heading_regex).unwrap();
        assert!(
            regex.is_match(&heading_result),
            "We expected this regex to match: {} but we got this text output {}",
            expected_heading_regex,
            heading_result
        );
    }

    #[test]
    fn data_version_pretty_print_preductise_right_format() {
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

    // If this test suddenly starts failing, but only when other tests are run with it, it's probably
    // because one or more of those other tests uses running_test(). When running_test() is active,
    // prepare_log_recipient() won't panic properly.
    #[test]
    #[should_panic(expected = "Log recipient should be initiated only once")]
    fn prepare_log_recipient_should_be_called_only_once_panic() {
        let _guard = prepare_test_environment();
        let system = System::new();
        system.block_on(async move {
            let ui_gateway = TestUiGateway::new(0, Arc::new(AtomicU32::new(0)));
            let recipient: Recipient<NodeToUiMessage> = ui_gateway.start().recipient();
            prepare_log_recipient(recipient.clone());

            prepare_log_recipient(recipient);
        });
    }

    fn overloading_function<C>(
        closure: C,
        join_handles_container: &mut Vec<JoinHandle<()>>,
        thread_count: usize,
        msgs_per_thread: usize,
    ) where
        C: Fn(usize, usize) + Send + 'static + Clone,
    {
        (0..thread_count).for_each(|thread_idx| {
            let closure_clone = closure.clone();
            let builder = thread::Builder::new().name(format!("Worker {}", thread_idx));
            join_handles_container.push(
                builder
                    .spawn(move || {
                        (0..msgs_per_thread).for_each(|i| {
                            thread::sleep(Duration::from_millis(10));
                            closure_clone(thread_idx, i)
                        })
                    })
                    .unwrap(),
            )
        });
    }

    fn create_msg(thread_idx: usize, msg_idx: usize) -> NodeToUiMessage {
        NodeToUiMessage {
            target: MessageTarget::AllClients,
            body: MessageBody {
                opcode: "whatever".to_string(),
                path: MessagePath::FireAndForget,
                payload: Ok(format!("({}, {})", thread_idx, msg_idx)),
            },
        }
    }

    fn send_message_to_recipient(thread_idx: usize, iteration_idx: usize) {
        {
            let recipient_opt = LOG_RECIPIENT_OPT.lock().expect(&format!(
                "({}, {}) at {}: SMTR: failed to lock LOG_RECIPIENT_OPT",
                thread_idx,
                iteration_idx,
                ts()
            ));
            let recipient_ref = recipient_opt.as_ref().expect(&format!(
                "({}, {}): SMTR: failed to get ref for recipient",
                thread_idx, iteration_idx
            ));
            let msg = create_msg(thread_idx, iteration_idx);
            recipient_ref.try_send(msg).expect(&format!(
                "({}, {}) at {}: SMTR: failed to send message",
                thread_idx,
                iteration_idx,
                ts()
            ));
        }
    }

    fn see_about_join_handles(container: Vec<JoinHandle<()>>) {
        container
            .into_iter()
            .enumerate()
            .for_each(|(index, handle)| {
                let join_result = handle.join();
                if let Err(err) = join_result {
                    match err.downcast_ref::<String>() {
                        Some(msg) => panic!("Thread {} failed at {}: {}", index, ts(), msg),
                        None => panic!("Thread {} failed, but reason is unprintable", index),
                    }
                }
            })
    }

    fn prepare_test_environment<'a>() -> MutexGuard<'a, ()> {
        let guard = match TEST_LOG_RECIPIENT_GUARD.lock() {
            Ok(g) => g,
            Err(poison_error) => poison_error.into_inner(),
        };
        let _ = LOG_RECIPIENT_OPT
            .lock()
            .expect("Unable to lock LOG_RECIPIENT_OPT")
            .take();
        guard
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

    fn ts() -> String {
        format!(
            "{:012}",
            Instant::now().duration_since(*START_TIMESTAMP).as_micros()
        )
    }
}
