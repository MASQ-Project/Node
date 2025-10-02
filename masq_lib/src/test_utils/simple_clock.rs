// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::simple_clock::SimpleClock;
use std::cell::RefCell;
use std::time::SystemTime;

#[derive(Default)]
pub struct SimpleClockMock {
    now_results: RefCell<Vec<SystemTime>>,
}

impl SimpleClock for SimpleClockMock {
    fn now(&self) -> SystemTime {
        self.now_results.borrow_mut().remove(0)
    }
}

impl SimpleClockMock {
    pub fn now_result(self, result: SystemTime) -> Self {
        self.now_results.borrow_mut().push(result);
        self
    }
}
