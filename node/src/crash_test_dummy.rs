// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::crash_point::CrashPoint;
use masq_lib::logger::Logger;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use crate::sub_lib::socket_server::SpawnableConfiguredByPrivilege;

pub struct CrashTestDummy<C> {
    pub configuration: C,
    crash_point: CrashPoint,
    message: String,
    logger: Logger,
}

impl<C> Future for CrashTestDummy<C>
where
    C: Send,
{
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.crash_point {
            CrashPoint::None => Poll::Ready(Ok(())),
            CrashPoint::Message => Poll::Ready(Ok(())),
            CrashPoint::Panic => {
                error!(self.logger, "Intercepted instruction to panic.");
                panic!("{}", self.message);
            }
            CrashPoint::Error => {
                error!(self.logger, "Intercepted instruction to return error.");
                Poll::Ready(Err(()))
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    #[should_panic(expected = "CrashTestDummy")]
    fn create_a_future_that_panics() {
        let crash_future = CrashTestDummy::new(CrashPoint::Panic, ());
        Runtime::new().unwrap().block_on(crash_future).unwrap();
    }

    #[test]
    fn create_a_future_that_returns_an_error() {
        let crash_future = CrashTestDummy::new(CrashPoint::Error, ());

        let result = Runtime::new().unwrap().block_on(crash_future);

        assert!(result.is_err());
    }

    #[test]
    fn should_not_crash_if_no_crash_point_is_set() {
        let crash_future = CrashTestDummy::new(CrashPoint::None, ());

        let result = Runtime::new().unwrap().block_on(crash_future);

        assert!(result.is_ok());
    }

    #[test]
    #[should_panic(expected = "CrashTestDummy Mmm Mmm Mmm Mmm")]
    fn should_panic_with_provided_message() {
        let crash_future =
            CrashTestDummy::panic(String::from("CrashTestDummy Mmm Mmm Mmm Mmm"), ());

        Runtime::new().unwrap().block_on(crash_future).unwrap();
    }
}
