// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use lazy_static::lazy_static;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

lazy_static! {
    static ref ENVIRONMENT_GUARD_MUTEX: Mutex<()> = Mutex::new(());
    static ref CLAP_GUARD_MUTEX: Mutex<()> = Mutex::new(());
    static ref LOGFILE_NAME_GUARD_MUTEX: Mutex<()> = Mutex::new(());
}

pub struct ConcurrencyPreventer<'a> {
    _lock: MutexGuard<'a, ()>,
}

impl<'a> ConcurrencyPreventer<'a> {
    pub fn new(mutex: &'a Mutex<()>) -> ConcurrencyPreventer<'a> {
        ConcurrencyPreventer {
            _lock: match mutex.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            },
        }
    }
}

/// Create one of these at the beginning of a test scope that manipulates the environment, with a variable name beginning
/// with an underscore. (Not just underscore, else the compiler will emit code to instantly reclaim it after creation.)
/// It will store a copy of the environment when it is created; then at the end of the scope when it is destroyed, it
/// will restore the environment to the state it was in when the EnvironmentGuard was created.
///
/// Also, if all your test scopes that manipulate the environment protect themselves with EnvironmentGuards, the
/// EnvironmentGuards will use a Mutex to prevent the test scopes from competing with each other over the environment.
pub struct EnvironmentGuard<'a> {
    _preventer: ConcurrencyPreventer<'a>,
    environment: Vec<(OsString, OsString)>,
}

impl<'a> Drop for EnvironmentGuard<'a> {
    fn drop(&mut self) {
        std::env::vars_os().for_each(|(name, _)| std::env::remove_var(name));
        self.environment
            .iter()
            .for_each(|(name, value)| std::env::set_var(name, value));
    }
}

impl<'a> EnvironmentGuard<'a> {
    pub fn new() -> EnvironmentGuard<'a> {
        EnvironmentGuard {
            _preventer: ConcurrencyPreventer::new(&ENVIRONMENT_GUARD_MUTEX),
            environment: std::env::vars_os().collect(),
        }
    }
}

impl<'a> Default for EnvironmentGuard<'a> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ClapGuard<'a> {
    _preventer: ConcurrencyPreventer<'a>,
}

impl<'a> Default for ClapGuard<'a> {
    fn default() -> ClapGuard<'a> {
        ClapGuard::new()
    }
}

impl<'a> ClapGuard<'a> {
    pub fn new() -> ClapGuard<'a> {
        ClapGuard {
            _preventer: ConcurrencyPreventer::new(&CLAP_GUARD_MUTEX),
        }
    }
}
