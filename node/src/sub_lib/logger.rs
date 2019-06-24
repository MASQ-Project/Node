// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use log::Level;
use log::Record;
use log::{logger, Metadata};

#[derive(Clone)]
pub struct Logger {
    name: String,
}

impl Logger {
    pub fn new(name: &str) -> Logger {
        Logger {
            name: String::from(name),
        }
    }

    pub fn trace(&self, string: String) {
        self.generic_log(Level::Trace, string);
    }

    pub fn debug(&self, string: String) {
        self.generic_log(Level::Debug, string);
    }

    pub fn info(&self, string: String) {
        self.generic_log(Level::Info, string);
    }

    pub fn warning(&self, string: String) {
        self.generic_log(Level::Warn, string);
    }

    pub fn error(&self, string: String) {
        self.generic_log(Level::Error, string);
    }

    fn generic_log(&self, level: Level, string: String) {
        let logger = logger();
        logger.log(
            &Record::builder()
                .args(format_args!("{}", string))
                .module_path(Some(&self.name))
                .level(level)
                .build(),
        );
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

    pub fn level_enabled(&self, level: Level) -> bool {
        logger().enabled(&Metadata::builder().level(level).target(&self.name).build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use chrono::format::StrftimeItems;
    use chrono::{DateTime, Local};
    use std::thread;
    use std::thread::ThreadId;
    use std::time::SystemTime;

    #[test]
    fn logger_format_is_correct() {
        init_test_logging();
        let one_logger = Logger::new("logger_format_is_correct_one");
        let another_logger = Logger::new("logger_format_is_correct_another");

        let before = SystemTime::now();
        one_logger.error(String::from("one log"));
        another_logger.error(String::from("another log"));
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
}
