// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use base64;
use cryptde::Key;
use sha1;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;

#[derive(Hash, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct StreamKey {
    hash: HashType,
}

impl fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let string = base64::encode_config(&self.hash, base64::STANDARD_NO_PAD);
        write!(f, "{}", string)
    }
}

impl StreamKey {
    pub fn new(public_key: Key, peer_addr: SocketAddr) -> StreamKey {
        let mut hash = sha1::Sha1::new();
        match peer_addr.ip() {
            IpAddr::V4(ipv4) => hash.update(&ipv4.octets()),
            IpAddr::V6(_ipv6) => unimplemented!(),
        }
        hash.update(&[
            (peer_addr.port() >> 8) as u8,
            (peer_addr.port() & 0xFF) as u8,
        ]);
        hash.update(&public_key.data[..]);
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
        let key = Key::new(&b"These are the times"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();

        let one = StreamKey::new(key.clone(), addr);
        let another = StreamKey::new(key, addr);

        assert_eq!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_addrs_make_mismatched_stream_keys() {
        let key = Key::new(&b"These are the times"[..]);
        let one_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let another_addr = SocketAddr::from_str("3.4.5.6:6789").unwrap();

        let one = StreamKey::new(key.clone(), one_addr);
        let another = StreamKey::new(key, another_addr);

        assert_ne!(one, another);
    }

    #[test]
    fn matching_keys_and_mismatched_port_numbers_make_mismatched_stream_keys() {
        let key = Key::new(&b"These are the times"[..]);
        let one_addr = SocketAddr::from_str("3.4.5.6:6789").unwrap();
        let another_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();

        let one = StreamKey::new(key.clone(), one_addr);
        let another = StreamKey::new(key, another_addr);

        assert_ne!(one, another);
    }

    #[test]
    fn mismatched_keys_and_matching_addrs_make_mismatched_stream_keys() {
        let one_key = Key::new(&b"These are the times"[..]);
        let another_key = Key::new(&b"that try men's souls"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();

        let one = StreamKey::new(one_key.clone(), addr);
        let another = StreamKey::new(another_key, addr);

        assert_ne!(one, another);
    }

    #[test]
    fn debug_implementation() {
        let key = Key::new(&b"These are the times"[..]);
        let addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let subject = StreamKey::new(key, addr);

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("X4SEhZulE9WrmSolWqKFErYBVgI"));
    }
}
