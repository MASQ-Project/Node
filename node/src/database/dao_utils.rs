// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::jackass_unsigned_to_signed;
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => jackass_unsigned_to_signed(d.as_secs()).expect("MASQNode has expired"),
    }
}

pub fn now_time_t() -> i64 {
    to_time_t(SystemTime::now())
}

pub fn from_time_t(time_t: i64) -> SystemTime {
    let interval = Duration::from_secs(time_t as u64);
    SystemTime::UNIX_EPOCH + interval
}
