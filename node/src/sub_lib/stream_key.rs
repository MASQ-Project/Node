// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;
use uuid::Uuid;

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct StreamKey {
    hash: HashType,
}

impl fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let string = base64::encode_config(&self.hash, base64::STANDARD_NO_PAD);
        write!(f, "{}", string)
    }
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let debug: &dyn fmt::Debug = self;
        debug.fmt(f)
    }
}

impl Serialize for StreamKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.hash[..])
    }
}

impl<'de> Deserialize<'de> for StreamKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(StreamKeyVisitor)
    }
}

struct StreamKeyVisitor;

impl<'a> Visitor<'a> for StreamKeyVisitor {
    type Value = StreamKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a StreamKey struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() != sha1::DIGEST_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "can't deserialize bytes from {:?}",
                v
            )));
        }

        let mut x: HashType = [0; sha1::DIGEST_LENGTH];
        x.copy_from_slice(v); // :(

        Ok(StreamKey { hash: x })
    }
}

impl Default for StreamKey {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamKey {
    pub fn new() -> StreamKey {
        let mut hash = sha1::Sha1::new();
        let uuid = Uuid::new_v4();
        let uuid_bytes: &[u8] = uuid.as_bytes();
        hash.update(uuid_bytes);
        StreamKey {
            hash: hash.digest().bytes(),
        }
    }

    pub fn make_meaningless_stream_key() -> StreamKey {
        StreamKey {
            hash: [0; sha1::DIGEST_LENGTH],
        }
    }

    pub fn make_meaningful_stream_key(phrase: &str) -> StreamKey {
        let mut hash = sha1::Sha1::new();
        hash.update(phrase.as_bytes());
        StreamKey {
            hash: hash.digest().bytes(),
        }
    }
}

type HashType = [u8; sha1::DIGEST_LENGTH];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn stream_keys_are_unique() {
        let mut stream_keys_set = HashSet::new();

        for i in 1..=1_000 {
            let stream_key = StreamKey::default();
            let is_unique = stream_keys_set.insert(stream_key);

            assert!(is_unique, "{}", &format!("Stream key {i} is not unique"));
        }
    }

    #[test]
    fn debug_implementation() {
        let subject = StreamKey::make_meaningful_stream_key("These are the times");

        let result = format!("{:?}", subject);

        assert_eq!(result, "HNksM7Mqjxr34GiUscSNeixMFzg".to_string());
    }

    #[test]
    fn display_implementation() {
        let subject = StreamKey::make_meaningful_stream_key("These are the times");

        let result = format!("{}", subject);

        assert_eq!(result, "HNksM7Mqjxr34GiUscSNeixMFzg".to_string());
    }

    #[test]
    fn serialization_and_deserialization_can_talk() {
        let subject = StreamKey::make_meaningful_stream_key(
            "Chancellor on brink of second bailout for banks",
        );

        let serial = serde_cbor::ser::to_vec(&subject).unwrap();

        let result = serde_cbor::de::from_slice::<StreamKey>(serial.as_slice()).unwrap();

        assert_eq!(result, subject);
    }
}
