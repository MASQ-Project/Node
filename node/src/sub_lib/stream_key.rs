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
        let string = BASE64_STANDARD_NO_PAD.encode(self.hash);
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
    pub fn new(public_key: &PublicKey, client_addr: SocketAddr) -> StreamKey {
        let mut hash = sha1::Sha1::new();
        hash.update(public_key.as_ref());
        hash = add_socket_addr_to_hash(hash, client_addr);
        hash.update(STREAM_KEY_SALT.as_slice());
        StreamKey {
            hash: hash.digest().bytes(),
        }
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[u8]) -> StreamKey {
        let mut hash = [0xA; sha1::DIGEST_LENGTH];
        for i in 0..std::cmp::min(sha1::DIGEST_LENGTH, bytes.len()) {
            hash[i] = bytes[i];
        }
        StreamKey { hash }
    }
}

impl StreamKey {
    pub fn make_meaningless_stream_key() -> StreamKey {
        let mut bytes = [0; sha1::DIGEST_LENGTH];
        randombytes_into(&mut bytes);
        StreamKey { hash: bytes }
    }

    pub fn make_meaningful_stream_key(phrase: &str) -> StreamKey {
        let mut hash = sha1::Sha1::new();
        hash.update(phrase.as_bytes());
        StreamKey {
            hash: output.as_slice().try_into().unwrap_or_else(|_| panic!(
                "Hash length should be {}, not {}",
                SHA1_DIGEST_LENGTH,
                output.len()
            )),
        }
    }
}

type HashType = [u8; SHA1_DIGEST_LENGTH];

fn add_socket_addr_to_hash(mut hash: sha1::Sha1, client_addr: SocketAddr) -> sha1::Sha1 {
    match client_addr {
        SocketAddr::V4(v4_addr) => {
            hash.update(&v4_addr.ip().octets());
            hash.update(&[(v4_addr.port() & 0xFF) as u8, (v4_addr.port() >> 8) as u8]);
        }
        SocketAddr::V6(v6_addr) => {
            hash.update(&v6_addr.ip().octets());
            hash.update(&[(v6_addr.port() & 0xFF) as u8, (v6_addr.port() >> 8) as u8]);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrapper::CryptDEPair;
    use itertools::Itertools;
    use std::net::IpAddr;
    use std::str::FromStr;

    lazy_static! {
        static ref CRYPTDE_PAIR: CryptDEPair = CryptDEPair::null();
    }

    #[test]
    fn stream_keys_with_different_host_names_are_different() {
        let public_key = CRYPTDE_PAIR.main.public_key();
        let stream_key_count = 100;
        let ip_addr = IpAddr::from_str("1.2.3.4").unwrap();
        let client_addrs = (0..stream_key_count).map(|i| SocketAddr::new(ip_addr, 1024 + i as u16));

        let stream_keys = client_addrs
            .map(|client_addr| StreamKey::new(&public_key, client_addr))
            .collect_vec();

        (0..(stream_key_count - 1)).for_each(|a| {
            ((a + 1)..stream_key_count).for_each(|b| {
                assert_ne!(stream_keys[a], stream_keys[b]);
            });
        });
    }

    #[test]
    fn stream_keys_from_different_public_keys_are_different() {
        let client_addr = SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 1024);

        let stream_keys = vec![PublicKey::new(&[1, 2, 3]), PublicKey::new(&[1, 2, 2])]
            .iter()
            .map(|public_key| StreamKey::new(public_key, client_addr))
            .collect_vec();

        assert_ne!(stream_keys[0], stream_keys[1]);
    }

    #[test]
    fn stream_keys_are_salted() {
        let public_key = CRYPTDE_PAIR.main.public_key();
        let client_addr = SocketAddr::new(IpAddr::from_str("1.2.3.4").unwrap(), 1024);

        let result = StreamKey::new(&public_key, client_addr);

        let mut hash = sha1::Sha1::new();
        hash.update(public_key.as_ref());
        hash = add_socket_addr_to_hash(hash, client_addr);
        let attack = StreamKey {
            hash: hash.digest().bytes(),
        };
        assert_ne!(attack, result)
    }

    #[test]
    fn debug_implementation() {
        let subject = StreamKey::make_meaningful_stream_key("These are the times");

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("W04FRbN1aMPvV3OpztUzpUj6BTw"));
    }

    #[test]
    fn display_implementation() {
        let subject = StreamKey::make_meaningful_stream_key("These are the times");

        let result = format!("{}", subject);

        assert_eq!(result, String::from("W04FRbN1aMPvV3OpztUzpUj6BTw"));
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
