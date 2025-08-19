// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::blockchain_db_error::BlockchainDbError;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Waiting,
    Reattempting(PreviousAttempts),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousAttempts {
    #[serde(flatten)]
    inner: HashMap<Box<dyn BlockchainDbError>, ErrorStats>,
}

impl PreviousAttempts {
    pub fn new(error: Box<dyn BlockchainDbError>, clock: &dyn ValidationFailureClock) -> Self {
        Self {
            inner: hashmap!(error => ErrorStats::now(clock)),
        }
    }

    pub fn add_attempt(
        mut self,
        error: Box<dyn BlockchainDbError>,
        clock: &dyn ValidationFailureClock,
    ) -> Self {
        self.inner
            .entry(error)
            .and_modify(|stats| stats.increment())
            .or_insert_with(|| ErrorStats::now(clock));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorStats {
    #[serde(rename = "firstSeen")]
    pub first_seen: SystemTime,
    pub attempts: u16,
}

impl ErrorStats {
    pub fn now(clock: &dyn ValidationFailureClock) -> Self {
        Self {
            first_seen: clock.now(),
            attempts: 1,
        }
    }

    pub fn increment(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }
}

pub trait ValidationFailureClock {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct ValidationFailureClockReal;

impl ValidationFailureClock for ValidationFailureClockReal {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;

    #[test]
    fn previous_attempts_and_validation_failure_clock_work_together_fine() {
        let validation_failure_clock = ValidationFailureClockReal::default();
        // new()
        let timestamp_a = SystemTime::now();
        let subject = PreviousAttempts::new(
            Box::new(AppRpcWeb3ErrorKind::Decoder),
            &validation_failure_clock,
        );
        // add_attempt()
        let timestamp_b = SystemTime::now();
        let subject = subject.add_attempt(
            Box::new(AppRpcWeb3ErrorKind::Internal),
            &validation_failure_clock,
        );
        let timestamp_c = SystemTime::now();
        let subject =
            subject.add_attempt(Box::new(AppRpcWeb3ErrorKind::IO), &validation_failure_clock);
        let timestamp_d = SystemTime::now();
        let subject = subject.add_attempt(
            Box::new(AppRpcWeb3ErrorKind::Decoder),
            &validation_failure_clock,
        );
        let subject =
            subject.add_attempt(Box::new(AppRpcWeb3ErrorKind::IO), &validation_failure_clock);

        let decoder_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcWeb3ErrorKind::Decoder) as Box<dyn BlockchainDbError>))
            .expect("Failed to get decoder error stats");
        assert!(
            timestamp_a <= decoder_error_stats.first_seen
                && decoder_error_stats.first_seen <= timestamp_b,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_a,
            timestamp_b,
            decoder_error_stats.first_seen
        );
        assert_eq!(decoder_error_stats.attempts, 2);
        let internal_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcWeb3ErrorKind::Internal) as Box<dyn BlockchainDbError>))
            .expect("Failed to get internal error stats");
        assert!(
            timestamp_b <= internal_error_stats.first_seen
                && internal_error_stats.first_seen <= timestamp_c,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_b,
            timestamp_c,
            internal_error_stats.first_seen
        );
        assert_eq!(internal_error_stats.attempts, 1);
        let io_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcWeb3ErrorKind::IO) as Box<dyn BlockchainDbError>))
            .expect("Failed to get IO error stats");
        assert!(
            timestamp_c <= io_error_stats.first_seen && io_error_stats.first_seen <= timestamp_d,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_c,
            timestamp_d,
            io_error_stats.first_seen
        );
        assert_eq!(io_error_stats.attempts, 2);
        let other_error_stats = subject
            .inner
            .get(&(Box::new(AppRpcWeb3ErrorKind::Signing) as Box<dyn BlockchainDbError>));
        assert_eq!(other_error_stats, None);
    }
}
