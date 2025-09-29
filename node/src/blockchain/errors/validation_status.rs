// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::errors::BlockchainErrorKind;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{
    Deserialize as ManualDeserialize, Deserializer, Serialize as ManualSerialize, Serializer,
};
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::Formatter;
use std::hash::Hash;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    Waiting,
    Reattempting(PreviousAttempts),
}

impl PartialOrd for ValidationStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Manual impl of Ord for enums makes sense because the derive macro determines the ordering
// by the order of the enum variants in its declaration, not only alphabetically. Swiping
// the position of the variants makes a difference, which is counter-intuitive. Structs are not
// implemented the same way and are safe to be used with derive.
impl Ord for ValidationStatus {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (ValidationStatus::Reattempting(..), ValidationStatus::Waiting) => Ordering::Less,
            (ValidationStatus::Waiting, ValidationStatus::Reattempting(..)) => Ordering::Greater,
            (ValidationStatus::Waiting, ValidationStatus::Waiting) => Ordering::Equal,
            (ValidationStatus::Reattempting(prev1), ValidationStatus::Reattempting(prev2)) => {
                prev1.cmp(prev2)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PreviousAttempts {
    inner: BTreeMap<BlockchainErrorKind, ErrorStats>,
}

// had to implement it manually in an array JSON layout, as the original, default HashMap
// serialization threw errors because the values of keys were represented by nested enums that
// serde doesn't translate into a complex JSON value (unlike the plain string required for a key)
impl ManualSerialize for PreviousAttempts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Entry<'a> {
            #[serde(rename = "error")]
            error_kind: &'a BlockchainErrorKind,
            #[serde(flatten)]
            stats: &'a ErrorStats,
        }

        let mut seq = serializer.serialize_seq(Some(self.inner.len()))?;
        for (error_kind, stats) in self.inner.iter() {
            seq.serialize_element(&Entry { error_kind, stats })?;
        }
        seq.end()
    }
}

impl<'de> ManualDeserialize<'de> for PreviousAttempts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(PreviousAttemptsVisitor)
    }
}

struct PreviousAttemptsVisitor;

impl<'de> Visitor<'de> for PreviousAttemptsVisitor {
    type Value = PreviousAttempts;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("PreviousAttempts")
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        #[derive(Deserialize)]
        struct EntryOwned {
            #[serde(rename = "error")]
            error_kind: BlockchainErrorKind,
            #[serde(flatten)]
            stats: ErrorStats,
        }

        let mut error_stats_map: BTreeMap<BlockchainErrorKind, ErrorStats> = btreemap!();
        while let Some(entry) = seq.next_element::<EntryOwned>()? {
            error_stats_map.insert(entry.error_kind, entry.stats);
        }
        Ok(PreviousAttempts {
            inner: error_stats_map,
        })
    }
}

impl PreviousAttempts {
    pub fn new(error: BlockchainErrorKind, clock: &dyn ValidationFailureClock) -> Self {
        Self {
            inner: btreemap!(error => ErrorStats::now(clock)),
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    use crate::accountant::scanners::pending_payable_scanner::test_utils::ValidationFailureClockMock;
    use crate::blockchain::errors::internal_errors::InternalErrorKind;
    use crate::blockchain::errors::rpc_errors::{AppRpcErrorKind, LocalErrorKind};
    use crate::test_utils::serde_serializer_mock::{SerdeSerializerMock, SerializeSeqMock};
    use serde::ser::Error as SerdeError;
    use std::collections::BTreeSet;
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    #[test]
    fn previous_attempts_and_validation_failure_clock_work_together_fine() {
        let validation_failure_clock = ValidationFailureClockReal::default();
        // new()
        let timestamp_a = SystemTime::now();
        let subject = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
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
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Io)),
            &validation_failure_clock,
        );
        let timestamp_d = SystemTime::now();
        let subject = subject.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
            &validation_failure_clock,
        );
        let subject = subject.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Io)),
            &validation_failure_clock,
        );

        let decoder_error_stats = subject
            .inner
            .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                LocalErrorKind::Decoder,
            )))
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
            .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                LocalErrorKind::Io,
            )))
            .unwrap();
        assert!(
            timestamp_c <= io_error_stats.first_seen && io_error_stats.first_seen <= timestamp_d,
            "Was expected from {:?} to {:?} but was {:?}",
            timestamp_c,
            timestamp_d,
            io_error_stats.first_seen
        );
        assert_eq!(io_error_stats.attempts, 2);
        let other_error_stats =
            subject
                .inner
                .get(&BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(
                    LocalErrorKind::Signing,
                )));
        assert_eq!(other_error_stats, None);
    }

    // #[test]
    // fn previous_attempts_hash_works_correctly() {
    //     let now = SystemTime::now();
    //     let clock = ValidationFailureClockMock::default()
    //         .now_result(now)
    //         .now_result(now)
    //         .now_result(now + Duration::from_secs(2));
    //     let attempts1 = PreviousAttempts::new(
    //         BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
    //         &clock,
    //     );
    //     let attempts2 = PreviousAttempts::new(
    //         BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
    //         &clock,
    //     );
    //     let attempts3 = PreviousAttempts::new(
    //         BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Io)),
    //         &clock,
    //     );
    //     let hash1 = {
    //         let mut hasher = DefaultHasher::new();
    //         attempts1.hash(&mut hasher);
    //         hasher.finish()
    //     };
    //     let hash2 = {
    //         let mut hasher = DefaultHasher::new();
    //         attempts2.hash(&mut hasher);
    //         hasher.finish()
    //     };
    //     let hash3 = {
    //         let mut hasher = DefaultHasher::new();
    //         attempts3.hash(&mut hasher);
    //         hasher.finish()
    //     };
    //
    //     assert_eq!(hash1, hash2);
    //     assert_ne!(hash1, hash3);
    // }

    #[test]
    fn previous_attempts_ordering_works_correctly_with_mock() {
        let now = SystemTime::now();
        let clock = ValidationFailureClockMock::default()
            .now_result(now)
            .now_result(now + Duration::from_secs(1))
            .now_result(now + Duration::from_secs(2))
            .now_result(now + Duration::from_secs(3));
        let mut attempts1 = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
            &clock,
        );
        attempts1 = attempts1.add_attempt(
            BlockchainErrorKind::Internal(InternalErrorKind::PendingTooLongNotReplaced),
            &clock,
        );
        let mut attempts2 = PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Io)),
            &clock,
        );
        attempts2 = attempts2.add_attempt(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Signing)),
            &clock,
        );

        assert_eq!(attempts2.partial_cmp(&attempts1), Some(Ordering::Greater));
    }

    #[test]
    fn previous_attempts_custom_serialize_seq_happy_path() {
        let err = BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal));
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(1234567890))
            .unwrap();
        let clock = ValidationFailureClockMock::default().now_result(timestamp);

        let result = serde_json::to_string(&PreviousAttempts::new(err, &clock)).unwrap();

        assert_eq!(
            result,
            r#"[{"error":{"AppRpc":{"Local":"Internal"}},"firstSeen":{"secs_since_epoch":1234567890,"nanos_since_epoch":0},"attempts":1}]"#
        );
    }

    #[test]
    fn previous_attempts_custom_serialize_seq_initialization_err() {
        let mock = SerdeSerializerMock::default()
            .serialize_seq_result(Err(serde_json::Error::custom("lethally acid bobbles")));
        let err = BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal));
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(1234567890))
            .unwrap();
        let clock = ValidationFailureClockMock::default().now_result(timestamp);

        let result = PreviousAttempts::new(err, &clock).serialize(mock);

        assert_eq!(result.unwrap_err().to_string(), "lethally acid bobbles");
    }

    #[test]
    fn previous_attempts_custom_serialize_seq_element_err() {
        let mock = SerdeSerializerMock::default()
            .serialize_seq_result(Ok(SerializeSeqMock::default().serialize_element_result(
                Err(serde_json::Error::custom("jelly gummies gone off")),
            )));
        let err = BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal));
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(1234567890))
            .unwrap();
        let clock = ValidationFailureClockMock::default().now_result(timestamp);

        let result = PreviousAttempts::new(err, &clock).serialize(mock);

        assert_eq!(result.unwrap_err().to_string(), "jelly gummies gone off");
    }

    #[test]
    fn previous_attempts_custom_serialize_end_err() {
        let mock =
            SerdeSerializerMock::default().serialize_seq_result(Ok(SerializeSeqMock::default()
                .serialize_element_result(Ok(()))
                .end_result(Err(serde_json::Error::custom("funny belly ache")))));
        let err = BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal));
        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(1234567890))
            .unwrap();
        let clock = ValidationFailureClockMock::default().now_result(timestamp);

        let result = PreviousAttempts::new(err, &clock).serialize(mock);

        assert_eq!(result.unwrap_err().to_string(), "funny belly ache");
    }

    #[test]
    fn previous_attempts_custom_deserialize_happy_path() {
        let str = r#"[{"error":{"AppRpc":{"Local":"Internal"}},"firstSeen":{"secs_since_epoch":1234567890,"nanos_since_epoch":0},"attempts":1}]"#;

        let result = serde_json::from_str::<PreviousAttempts>(str);

        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_secs(1234567890))
            .unwrap();
        let clock = ValidationFailureClockMock::default().now_result(timestamp);
        assert_eq!(
            result.unwrap().inner,
            btreemap!(BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Internal)) => ErrorStats::now(&clock))
        );
    }

    #[test]
    fn previous_attempts_custom_deserialize_sad_path() {
        let str =
            r#"[{"error":{"AppRpc":{"Local":"Internal"}},"firstSeen":"Yesterday","attempts":1}]"#;

        let result = serde_json::from_str::<PreviousAttempts>(str);

        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid type: string \"Yesterday\", expected struct SystemTime at line 1 column 79"
        );
    }

    #[test]
    fn validation_status_ordering_works_correctly() {
        let now = SystemTime::now();
        let clock = ValidationFailureClockMock::default()
            .now_result(now)
            .now_result(now + Duration::from_secs(1));

        let waiting = ValidationStatus::Waiting;
        let reattempting_early = ValidationStatus::Reattempting(PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Decoder)),
            &clock,
        ));
        let reattempting_late = ValidationStatus::Reattempting(PreviousAttempts::new(
            BlockchainErrorKind::AppRpc(AppRpcErrorKind::Local(LocalErrorKind::Io)),
            &clock,
        ));
        let waiting_identical = waiting.clone();
        let reattempting_early_identical = reattempting_early.clone();

        let mut set = BTreeSet::new();
        vec![
            reattempting_early.clone(),
            waiting.clone(),
            reattempting_late.clone(),
            waiting_identical.clone(),
            reattempting_early_identical.clone(),
        ]
        .into_iter()
        .for_each(|tx| {
            set.insert(tx);
        });

        let expected_order = vec![
            reattempting_early.clone(),
            reattempting_late,
            waiting.clone(),
        ];
        assert_eq!(set.into_iter().collect::<Vec<_>>(), expected_order);
        assert_eq!(waiting.cmp(&waiting_identical), Ordering::Equal);
        assert_eq!(
            reattempting_early.cmp(&reattempting_early_identical),
            Ordering::Equal
        );
    }
}
