// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.
#![cfg(test)]
use crate::server_initializer::LoggerInitializerWrapperReal;
use lazy_static::lazy_static;
use masq_lib::test_utils::environment_guard::ConcurrencyPreventer;
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref LOGFILE_NAME_GUARD_MUTEX: Mutex<()> = Mutex::new(());
}

pub struct LogfileNameGuard<'a> {
    _preventer: ConcurrencyPreventer<'a>,
    logfile_name: PathBuf,
}

impl<'a> Drop for LogfileNameGuard<'a> {
    fn drop(&mut self) {
        LoggerInitializerWrapperReal::set_logfile_name(self.logfile_name.clone());
    }
}

impl<'a> LogfileNameGuard<'a> {
    pub fn new(logfile_name: &PathBuf) -> LogfileNameGuard<'a> {
        let guard = LogfileNameGuard {
            _preventer: ConcurrencyPreventer::new(&LOGFILE_NAME_GUARD_MUTEX),
            logfile_name: LoggerInitializerWrapperReal::get_logfile_name(),
        };
        LoggerInitializerWrapperReal::set_logfile_name(logfile_name.clone());
        guard
    }
}
