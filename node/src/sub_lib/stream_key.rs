// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PublicKey;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
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

impl StreamKey {
    pub fn new() -> StreamKey {
        let mut hash = sha1::Sha1::new();
        let uuid = Uuid::new_v4();
        eprintln!("This is how UUID looks: {}", uuid);
        let uuid_bytes: &[u8] = uuid.as_bytes();
        hash.update(uuid_bytes);
        // match peer_addr.ip() {
        //     IpAddr::V4(ipv4) => hash.update(&ipv4.octets()),
        //     IpAddr::V6(_ipv6) => unimplemented!(),
        // }
        // hash.update(&[
        //     (peer_addr.port() >> 8) as u8,
        //     (peer_addr.port() & 0xFF) as u8,
        // ]);
        // hash.update(public_key.as_slice());
        StreamKey {
            hash: hash.digest().bytes(),
        }
    }
}

type HashType = [u8; sha1::DIGEST_LENGTH];

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn matching_keys_and_matching_addrs_make_matching_stream_keys() {
        let one = StreamKey::new();
        let another = StreamKey::new();

        assert_eq!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_addrs_make_mismatched_stream_keys() {
        let one = StreamKey::new();
        let another = StreamKey::new();

        assert_ne!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_port_numbers_make_mismatched_stream_keys() {
        let one = StreamKey::new();
        let another = StreamKey::new();

        assert_ne!(one, another);
    }

    #[test]
    fn mismatched_keys_and_matching_addrs_make_mismatched_stream_keys() {
        let one = StreamKey::new();
        let another = StreamKey::new();

        assert_ne!(one, another);
    }

    #[test]
    fn debug_implementation() {
        let subject = StreamKey::new();

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("X4SEhZulE9WrmSolWqKFErYBVgI"));
    }

    #[test]
    fn display_implementation() {
        let subject = StreamKey::new();

        let result = format!("{}", subject);

        assert_eq!(result, String::from("X4SEhZulE9WrmSolWqKFErYBVgI"));
    }

    #[test]
    fn serialization_and_deserialization_can_talk() {
        let subject = StreamKey::new();

        let serial = serde_cbor::ser::to_vec(&subject).unwrap();

        let result = serde_cbor::de::from_slice::<StreamKey>(serial.as_slice()).unwrap();

        assert_eq!(result, subject);
    }
}
