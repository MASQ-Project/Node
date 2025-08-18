// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::validation_status::ValidationFailureClock;
use std::cell::RefCell;
use std::time::SystemTime;

#[derive(Default)]
pub struct ValidationFailureClockMock {
    now_results: RefCell<Vec<SystemTime>>,
}

impl ValidationFailureClock for ValidationFailureClockMock {
    fn now(&self) -> SystemTime {
        self.now_results.borrow_mut().remove(0)
    }
}

impl ValidationFailureClockMock {
    pub fn now_result(self, result: SystemTime) -> Self {
        self.now_results.borrow_mut().push(result);
        self
    }
}
