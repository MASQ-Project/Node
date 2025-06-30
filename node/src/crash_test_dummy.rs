// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use futures::Async;
use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use tokio::prelude::future::Future;

pub struct CrashTestDummy<C> {
    // TODO: This does not appear to be used. Can it be removed?
    pub configuration: C,
    crash_point: CrashPoint,
    message: String,
    logger: Logger,
}

impl<C> CrashTestDummy<C>
where
    C: Send,
{
    pub fn new(crash_point: CrashPoint, configuration: C) -> CrashTestDummy<C> {
        CrashTestDummy {
            configuration,
            crash_point,
            message: "CrashTestDummy".to_owned(),
            logger: Logger::new("CrashTestDummy"),
        }
    }

    #[cfg(test)]
    pub fn panic(message: String, configuration: C) -> CrashTestDummy<C> {
        CrashTestDummy {
            configuration,
            crash_point: CrashPoint::Panic,
            message,
            logger: Logger::new("CrashTestDummy"),
        }
    }
}

impl<C> Future for CrashTestDummy<C>
where
    C: Send,
{
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        match self.crash_point {
            CrashPoint::None => Ok(Async::Ready(())),
            CrashPoint::Message => Ok(Async::Ready(())),
            CrashPoint::Panic => {
                error!(self.logger, "Intercepted instruction to panic.");
                panic!("{}", self.message);
            }
            CrashPoint::Error => {
                error!(self.logger, "Intercepted instruction to return error.");
                Err(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "CrashTestDummy")]
    fn create_a_future_that_panics() {
        let crash_future = CrashTestDummy::new(CrashPoint::Panic, ());
        crash_future.wait().unwrap();
    }

    #[test]
    fn create_a_future_that_returns_an_error() {
        let crash_future = CrashTestDummy::new(CrashPoint::Error, ());

        let result = crash_future.wait();

        assert!(result.is_err());
    }

    #[test]
    fn should_not_crash_if_no_crash_point_is_set() {
        let crash_future = CrashTestDummy::new(CrashPoint::None, ());

        let result = crash_future.wait();

        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "CrashTestDummy Mmm Mmm Mmm Mmm")]
    fn should_panic_with_provided_message() {
        let crash_future =
            CrashTestDummy::panic(String::from("CrashTestDummy Mmm Mmm Mmm Mmm"), ());

        crash_future.wait().ok();
    }
}
