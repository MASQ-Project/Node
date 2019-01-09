// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use chrono::format::strftime::StrftimeItems;
use chrono::NaiveDateTime;
use log::logger;
use log::Level;
use log::Record;
use std::thread;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

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

    pub fn log(&self, string: String) {
        self.error(string);
    }

    pub fn debug(&self, string: String) {
        self.generic_log(Level::Debug, string);
    }

    pub fn trace(&self, string: String) {
        self.generic_log(Level::Trace, string);
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

    pub fn fatal(&self, string: String) {
        self.generic_log(Level::Error, string);
    }

    pub fn timestamp_as_string(timestamp: &SystemTime) -> String {
        let time_t = timestamp
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!");
        let naive_date_time =
            NaiveDateTime::from_timestamp(time_t.as_secs() as i64, time_t.subsec_nanos());
        let fmt = StrftimeItems::new("%Y-%m-%d %H:%M:%S%.3f");
        naive_date_time.format_with_items(fmt).to_string()
    }

    fn generic_log(&self, level: Level, string: String) {
        let logger = logger();
        logger.log(
            &Record::builder()
                .args(format_args!(
                    "{} {:?}: {}: {}: {}",
                    Logger::timestamp_as_string(&SystemTime::now()),
                    thread::current().id(),
                    level,
                    self.name,
                    string
                ))
                .build(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;

    #[test]
    fn logger_format_is_correct() {
        init_test_logging();
        let one_logger = Logger::new("logger_format_is_correct_one");
        let another_logger = Logger::new("logger_format_is_correct_another");

        let before = SystemTime::now();
        one_logger.log(String::from("one log"));
        another_logger.log(String::from("another log"));
        let after = SystemTime::now();

        let tlh = TestLogHandler::new();
        let prefix_len = "0000-00-00 00:00:00.000".len();
        let thread_id = thread::current().id();
        let one_log = tlh.get_log_at(tlh.exists_log_containing(&format!(
            " {:?}: ERROR: logger_format_is_correct_one: one log",
            thread_id
        )));
        let another_log = tlh.get_log_at(tlh.exists_log_containing(&format!(
            " {:?}: ERROR: logger_format_is_correct_another: another log",
            thread_id
        )));
        let before_str = Logger::timestamp_as_string(&before);
        let after_str = Logger::timestamp_as_string(&after);
        assert_between(&one_log[..prefix_len], &before_str, &after_str);
        assert_between(&another_log[..prefix_len], &before_str, &after_str);
    }

    fn assert_between(candidate: &str, before: &str, after: &str) {
        assert_eq!(
            candidate >= before,
            true,
            "{} is not equal to or after {}",
            candidate,
            before
        );
        assert_eq!(
            candidate <= after,
            true,
            "{} is not before or equal to {}",
            candidate,
            after
        );
    }
}
