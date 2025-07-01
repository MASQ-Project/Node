// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::logger::real_format_function;
use crate::test_utils::utils::to_millis;
use lazy_static::lazy_static;
use log::set_logger;
use log::Log;
use log::Metadata;
use log::Record;
use regex::Regex;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use test_utilities::byte_array_reader_writer::ByteArrayWriter;
use time::OffsetDateTime;

lazy_static! {
    static ref TEST_LOGS_ARC: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
}

static TEST_LOGGER: TestLogger = TestLogger {};

#[derive(Default)]
pub struct TestLog {
    ref_log: RefCell<Vec<String>>,
}

unsafe impl Sync for TestLog {}
unsafe impl Send for TestLog {}

impl TestLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn log(&self, log: String) {
        self.ref_log.borrow_mut().push(log);
    }

    pub fn dump(&self) -> Vec<String> {
        self.ref_log.borrow().clone()
    }
}

#[derive(Default)]
pub struct TestLogHandler {}

impl TestLogHandler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_log(&self, log: String) {
        TEST_LOGS_ARC
            .lock()
            .expect("TestLogHandler is poisoned in add_log")
            .push(log)
    }

    pub fn exists_log_matching(&self, pattern: &str) -> usize {
        match self.find_first_log_matching(pattern) {
            Some(index) => index,
            None => panic!(
                "No existing logs match '{}':\n------\n{}\n------",
                pattern,
                self.list_logs()
            ),
        }
    }

    pub fn await_log_matching(&self, pattern: &str, millis: u64) -> usize {
        let began_at = Instant::now();
        while to_millis(&began_at.elapsed()) < millis {
            match self.find_first_log_matching(pattern) {
                Some(index) => return index,
                None => thread::sleep(Duration::from_millis(50)),
            }
        }
        panic!(
            "Waited {}ms for log matching '{}':\n------\n{}\n------",
            millis,
            pattern,
            self.list_logs()
        );
    }

    pub fn exists_no_log_matching(&self, pattern: &str) {
        if let Some(index) = self.logs_match(pattern) {
            panic!(
                "Log at index {} matches '{}':\n------\n{}\n------",
                index,
                pattern,
                self.get_log_at(index)
            )
        }
    }

    pub fn exists_log_containing(&self, fragment: &str) -> usize {
        match self.find_first_log_containing(fragment) {
            Some(index) => index,
            None => panic!(
                "No existing logs contain '{}':\n------\n{}\n------",
                fragment,
                self.list_logs()
            ),
        }
    }

    pub fn exists_no_log_containing(&self, fragment: &str) {
        if let Some(index) = self.logs_contain(fragment) {
            panic!(
                "Log at index {} contains '{}':\n------\n{}\n------",
                index,
                fragment,
                self.get_log_at(index)
            )
        }
    }

    pub fn await_log_containing(&self, fragment: &str, millis: u64) -> usize {
        let began_at = Instant::now();
        while to_millis(&began_at.elapsed()) < millis {
            match self.find_first_log_containing(fragment) {
                Some(index) => return index,
                None => thread::sleep(Duration::from_millis(50)),
            }
        }
        panic!(
            "Waited {}ms for log containing '{}':\n------\n{}\n------",
            millis,
            fragment,
            self.list_logs()
        );
    }

    pub fn assert_logs_match_in_order(&self, patterns: Vec<&str>) {
        let indexes: Vec<usize> = patterns
            .iter()
            .map(|pattern| self.exists_log_matching(*pattern))
            .collect();
        if self.in_order(&indexes) {
            return;
        }
        self.complain_about_order(&indexes, &patterns)
    }

    pub fn assert_logs_contain_in_order(&self, fragments: Vec<&str>) {
        let indexes: Vec<usize> = fragments
            .iter()
            .map(|fragment| self.exists_log_containing(*fragment))
            .collect();
        if self.in_order(&indexes) {
            return;
        }
        self.complain_about_order(&indexes, &fragments)
    }

    pub fn get_log_at(&self, index: usize) -> String {
        self.get_logs()[index].clone()
    }

    fn get_logs(&self) -> MutexGuard<'_, Vec<String>> {
        TEST_LOGS_ARC
            .lock()
            .expect("TestLogHandler is poisoned in get_logs")
    }

    fn list_logs(&self) -> String {
        self.get_logs().join("\n")
    }

    fn find_first_log_matching(&self, pattern: &str) -> Option<usize> {
        let logs = self.get_logs();
        let regex = Regex::new(pattern).unwrap();
        for index in 0..logs.len() {
            if regex.is_match(&logs[index][..]) {
                return Some(index);
            }
        }
        None
    }

    fn find_first_log_containing(&self, fragment: &str) -> Option<usize> {
        let logs = self.get_logs();
        for index in 0..logs.len() {
            if logs[index].contains(fragment) {
                return Some(index);
            }
        }
        None
    }

    fn in_order(&self, indexes: &[usize]) -> bool {
        let mut prev_index: &usize = &0;
        for index in indexes {
            if index < prev_index {
                return false;
            }
            prev_index = index;
        }
        true
    }

    fn complain_about_order(&self, indexes: &[usize], matchers: &[&str]) {
        let mut msg = String::from("Logs were found, but not in specified order:\n");
        for index in 0..indexes.len() {
            msg.push_str(&format!("  {}: '{}'\n", indexes[index], matchers[index])[..])
        }
        panic!("{}\nGot:\n{}", msg, self.list_logs());
    }

    fn logs_match(&self, pattern: &str) -> Option<usize> {
        let logs = self.get_logs();
        let regex = Regex::new(pattern).unwrap();
        for index in 0..logs.len() {
            if regex.is_match(&logs[index][..]) {
                return Some(index);
            }
        }
        None
    }

    fn logs_contain(&self, fragment: &str) -> Option<usize> {
        let logs = self.get_logs();
        for index in 0..logs.len() {
            if logs[index].contains(fragment) {
                return Some(index);
            }
        }
        None
    }
}

pub fn init_test_logging() -> bool {
    set_logger(&TEST_LOGGER).is_ok()
}

#[derive(Clone, Default)]
pub struct TestLogger {}

impl Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        let mut buffer = ByteArrayWriter::new();
        let now = OffsetDateTime::now_utc();
        real_format_function(&mut buffer, now, record).unwrap();
        TestLogHandler::new().add_log(buffer.get_string());
    }

    fn flush(&self) {}
}

impl TestLogger {
    pub fn new() -> TestLogger {
        TestLogger {}
    }
}
