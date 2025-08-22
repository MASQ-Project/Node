// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::rpc_errors::AppRpcErrorKind;
use crate::blockchain::errors::BlockchainErrorKind;
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Waiting,
    Reattempting(PreviousAttempts),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviousAttempts {
    #[serde(flatten)]
    inner: HashMap<BlockchainErrorKind, ErrorStats>,
}

impl Hash for PreviousAttempts {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for (key, value) in &self.inner {
            key.hash(state);
            value.hash(state);
        }
    }
}

impl PartialOrd for PreviousAttempts {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for PreviousAttempts {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_first_seen = self.inner.iter().map(|(_, stats)| &stats.first_seen).max();
        let other_first_seen = other.inner.iter().map(|(_, stats)| &stats.first_seen).max();

        self_first_seen.cmp(&other_first_seen)
    }
}

impl PreviousAttempts {
    pub fn new(error: BlockchainErrorKind, clock: &dyn ValidationFailureClock) -> Self {
        Self {
            inner: hashmap!(error => ErrorStats::now(clock)),
        }
    }

    pub fn add_attempt(
        mut self,
        error: BlockchainErrorKind,
        clock: &dyn ValidationFailureClock,
    ) -> Self {
        self.inner
            .entry(error)
            .and_modify(|stats| stats.increment())
            .or_insert_with(|| ErrorStats::now(clock));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
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
        self.attempts += 1;
    }
}

pub trait ValidationFailureClock {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct ValidationFailureClockReal {}

impl ValidationFailureClock for ValidationFailureClockReal {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::internal_errors::InternalErrorKind;
    use crate::blockchain::test_utils::ValidationFailureClockMock;
    use std::collections::hash_map::DefaultHasher;
    use std::time::Duration;

    #[test]
    fn previous_attempts_and_validation_failure_clock_work_together_fine() {
        let validation_failure_clock = ValidationFailureClockReal::default();
        // new()
        let timestamp_a = SystemTime::now();
        let subject = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder),
            &validation_failure_clock,
        );
        // add_attempt()
        let timestamp_b = SystemTime::now();
        let subject = subject.add_attempt(
            BlockchainErrorKind::Internal(InternalErrorKind::PendingTooLongNotReplaced),
            &validation_failure_clock,
        );
        let timestamp_c = SystemTime::now();
        let subject = subject.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::IO),
            &validation_failure_clock,
        );
        let timestamp_d = SystemTime::now();
        let subject = subject.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder),
            &validation_failure_clock,
        );
        let subject = subject.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::IO),
            &validation_failure_clock,
        );

        let decoder_error_stats = subject
            .inner
            .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder))
            .unwrap();
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
            .get(&BlockchainErrorKind::Internal(
                InternalErrorKind::PendingTooLongNotReplaced,
            ))
            .unwrap();
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
            .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::IO))
            .unwrap();
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
            .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::Signing));
        assert_eq!(other_error_stats, None);
    }

    #[test]
    fn previous_attempts_hash_works_correctly() {
        let now = SystemTime::now();
        let clock = ValidationFailureClockMock::default()
            .now_result(now)
            .now_result(now)
            .now_result(now + Duration::from_secs(2));
        let attempts1 = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder),
            &clock,
        );
        let attempts2 = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder),
            &clock,
        );
        let attempts3 =
            PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::IO), &clock);
        let hash1 = {
            let mut hasher = DefaultHasher::new();
            attempts1.hash(&mut hasher);
            hasher.finish()
        };
        let hash2 = {
            let mut hasher = DefaultHasher::new();
            attempts2.hash(&mut hasher);
            hasher.finish()
        };
        let hash3 = {
            let mut hasher = DefaultHasher::new();
            attempts3.hash(&mut hasher);
            hasher.finish()
        };

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn previous_attempts_ordering_works_correctly_with_mock() {
        let now = SystemTime::now();
        let clock = ValidationFailureClockMock::default()
            .now_result(now)
            .now_result(now + Duration::from_secs(1))
            .now_result(now + Duration::from_secs(2))
            .now_result(now + Duration::from_secs(3));
        let mut attempts1 = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Decoder),
            &clock,
        );
        let mut attempts2 =
            PreviousAttempts::new(BlockchainErrorKind::AppRpc(AppRpcErrorKind::IO), &clock);
        attempts1 = attempts1.add_attempt(
            BlockchainErrorKind::Internal(InternalErrorKind::PendingTooLongNotReplaced),
            &clock,
        );
        attempts2 = attempts2.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Signing),
            &clock,
        );

        assert_eq!(attempts2.partial_cmp(&attempts1), Some(Ordering::Greater));
    }
}
