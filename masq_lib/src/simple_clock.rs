// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::time::SystemTime;

pub trait SimpleClock {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct SimpleClockReal {}

impl SimpleClock for SimpleClockReal {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
