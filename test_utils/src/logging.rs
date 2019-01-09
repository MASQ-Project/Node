// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use log::set_logger;
use log::Log;
use log::Metadata;
use log::Record;
use regex::Regex;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use test_utils::to_millis;

static mut TEST_LOGS_ARC: Option<Arc<Mutex<Vec<String>>>> = None;
static TEST_LOGGER: TestLogger = TestLogger {};

pub struct TestLog {
    ref_log: RefCell<Vec<String>>,
}

unsafe impl Sync for TestLog {}
unsafe impl Send for TestLog {}

impl TestLog {
    pub fn new() -> TestLog {
        TestLog {
            ref_log: RefCell::new(vec![]),
        }
    }

    pub fn log(&self, log: String) {
        self.ref_log.borrow_mut().push(log);
    }

    pub fn dump(&self) -> Vec<String> {
        self.ref_log.borrow().clone()
    }
}

pub struct TestLogHandler {}

impl TestLogHandler {
    pub fn new() -> TestLogHandler {
        TestLogHandler {}
    }

    pub fn add_log(&self, log: String) {
        unsafe {
            TEST_LOGS_ARC
                .as_ref()
                .unwrap()
                .lock()
                .expect("TestLogHandler is poisoned in add_log")
                .push(log)
        }
    }

    pub fn exists_log_matching(&self, pattern: &str) -> usize {
        match self.find_first_log_matching(pattern) {
            Some(index) => index,
            None => panic!(
                "No existing logs match '{}':\n{}",
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
            "Waited {}ms for log matching '{}':\n{}",
            millis,
            pattern,
            self.list_logs()
        );
    }

    pub fn exists_no_log_matching(&self, pattern: &str) {
        match self.logs_match(pattern) {
            Some(index) => panic!(
                "Log at index {} matches '{}':\n{}",
                index,
                pattern,
                self.get_log_at(index)
            ),
            None => (),
        }
    }

    pub fn exists_log_containing(&self, fragment: &str) -> usize {
        match self.find_first_log_containing(fragment) {
            Some(index) => index,
            None => panic!(
                "No existing logs contain '{}':\n{}",
                fragment,
                self.list_logs()
            ),
        }
    }

    pub fn exists_no_log_containing(&self, fragment: &str) {
        match self.logs_contain(fragment) {
            Some(index) => panic!(
                "Log at index {} contains '{}':\n{}",
                index,
                fragment,
                self.get_log_at(index)
            ),
            None => (),
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
            "Waited {}ms for log containing '{}':\n{}",
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

    pub fn logs_initialized(&self) -> bool {
        unsafe { TEST_LOGS_ARC.is_some() }
    }

    pub fn initialize_logs(&self) {
        unsafe { TEST_LOGS_ARC = Some(Arc::new(Mutex::new(vec![]))) }
    }

    fn get_logs(&self) -> MutexGuard<Vec<String>> {
        unsafe {
            TEST_LOGS_ARC
                .as_ref()
                .unwrap()
                .lock()
                .expect("TestLogHandler is poisoned in get_logs")
        }
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

    fn in_order(&self, indexes: &Vec<usize>) -> bool {
        let mut prev_index: usize = 0;
        for index in indexes.clone() {
            if index < prev_index {
                return false;
            }
            prev_index = index;
        }
        true
    }

    fn complain_about_order(&self, indexes: &Vec<usize>, matchers: &Vec<&str>) {
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
    let tlh = TestLogHandler::new();
    let result = if tlh.logs_initialized() {
        true
    } else {
        tlh.initialize_logs();
        match set_logger(&TEST_LOGGER) {
            Ok(_) => true,
            Err(_) => false,
        }
    };
    result
}

#[derive(Clone)]
pub struct TestLogger {}

impl Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let string = format!("{}", record.args());
        TestLogHandler::new().add_log(string);
    }

    fn flush(&self) {}
}

impl TestLogger {
    pub fn new() -> TestLogger {
        TestLogger {}
    }
}
