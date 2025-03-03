// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PublicKey;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use sha1::{Digest, Sha1};
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;

const SHA1_DIGEST_LENGTH: usize = 20;

// TODO: Stop using SHA1 here: it's cryptographically broken. Use something more secure.
// Also: find out whether we actually do need a hash here. If we don't, a UUID would be
// shorter and more secure.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct StreamKey {
    hash: HashType,
}

impl fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let string = BASE64_STANDARD_NO_PAD.encode(&self.hash);
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
        if v.len() != SHA1_DIGEST_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "can't deserialize bytes from {:?}",
                v
            )));
        }

        let mut x: HashType = [0; SHA1_DIGEST_LENGTH];
        x.copy_from_slice(v); // :(

        Ok(StreamKey { hash: x })
    }
}

impl StreamKey {
    pub fn new(_public_key: PublicKey, peer_addr: SocketAddr) -> StreamKey {
        let mut hash = Sha1::new();
        match peer_addr.ip() {
            IpAddr::V4(ipv4) => hash.update(&ipv4.octets()),
            IpAddr::V6(_ipv6) => unimplemented!(),
        }
        sha1::digest::Update::update(
            &mut hash,
            &[
                (peer_addr.port() >> 8) as u8,
                (peer_addr.port() & 0xFF) as u8,
            ],
        );
        let output = hash.finalize();
        StreamKey {
            hash: output.as_slice().try_into().expect(&format!(
                "Hash length should be {}, not {}",
                SHA1_DIGEST_LENGTH,
                output.len()
            )),
        }
    }
}

type HashType = [u8; SHA1_DIGEST_LENGTH];

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn matching_keys_and_matching_addrs_make_matching_stream_keys() {
        let key = PublicKey::new(&b"These are the times"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();

        let one = StreamKey::new(key.clone(), addr);
        let another = StreamKey::new(key, addr);

        assert_eq!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_addrs_make_mismatched_stream_keys() {
        let key = PublicKey::new(&b"These are the times"[..]);
        let one_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let another_addr = SocketAddr::from_str("3.4.5.6:6789").unwrap();

        let one = StreamKey::new(key.clone(), one_addr);
        let another = StreamKey::new(key, another_addr);

        assert_ne!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_port_numbers_make_mismatched_stream_keys() {
        let key = PublicKey::new(&b"These are the times"[..]);
        let one_addr = SocketAddr::from_str("3.4.5.6:6789").unwrap();
        let another_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();

        let one = StreamKey::new(key.clone(), one_addr);
        let another = StreamKey::new(key, another_addr);

        assert_ne!(one, another);
    }

    #[test]
    fn mismatched_keys_and_matching_addrs_make_mismatched_stream_keys() {
        let one_key = PublicKey::new(&b"These are the times"[..]);
        let another_key = PublicKey::new(&b"that try men's souls"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();

        let one = StreamKey::new(one_key.clone(), addr);
        let another = StreamKey::new(another_key, addr);

        assert_ne!(one, another);
    }

    #[test]
    fn debug_implementation() {
        let key = PublicKey::new(&b"These are the times"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let subject = StreamKey::new(key, addr);

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("X4SEhZulE9WrmSolWqKFErYBVgI"));
    }

    #[test]
    fn display_implementation() {
        let key = PublicKey::new(&b"These are the times"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let subject = StreamKey::new(key, addr);

        let result = format!("{}", subject);

        assert_eq!(result, String::from("X4SEhZulE9WrmSolWqKFErYBVgI"));
    }

    #[test]
    fn serialization_and_deserialization_can_talk() {
        let subject = StreamKey::new(
            PublicKey::new(&b"booga"[..]),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        );

        let serial = serde_cbor::ser::to_vec(&subject).unwrap();

        let result = serde_cbor::de::from_slice::<StreamKey>(serial.as_slice()).unwrap();

        assert_eq!(result, subject);
    }
}
