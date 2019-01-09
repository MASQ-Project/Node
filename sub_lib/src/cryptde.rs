// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use base64;
use serde;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;

// TODO: Consider generating each of these three with a single macro

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub data: Vec<u8>,
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.data[..])
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(KeyVisitor)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl Key {
    pub fn new(data: &[u8]) -> Key {
        Key {
            data: Vec::from(data),
        }
    }
}

struct KeyVisitor;

impl<'a> Visitor<'a> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Key struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Key::new(v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CryptData {
    pub data: Vec<u8>,
}

impl Serialize for CryptData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.data[..])
    }
}

impl<'de> Deserialize<'de> for CryptData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(CryptDataVisitor)
    }
}

impl CryptData {
    pub fn new(data: &[u8]) -> CryptData {
        CryptData {
            data: Vec::from(data),
        }
    }
}

struct CryptDataVisitor;

impl<'a> Visitor<'a> for CryptDataVisitor {
    type Value = CryptData;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CryptData struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(CryptData::new(v))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlainData {
    pub data: Vec<u8>,
}

impl Serialize for PlainData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.data[..])
    }
}

impl<'de> Deserialize<'de> for PlainData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PlainDataVisitor)
    }
}

impl PlainData {
    pub fn new(data: &[u8]) -> PlainData {
        PlainData {
            data: Vec::from(data),
        }
    }
}

struct PlainDataVisitor;

impl<'a> Visitor<'a> for PlainDataVisitor {
    type Value = PlainData;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a PlainData struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(PlainData::new(v))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum CryptdecError {
    EmptyKey,
    EmptyData,
    InvalidKey(String),
}

pub trait CryptDE: Send + Sync {
    fn generate_key_pair(&mut self);
    fn encode(&self, public_key: &Key, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError>;
    fn random(&self, dest: &mut [u8]);
    // TODO: Would be really nice if these could return &Key instead of Key
    fn private_key(&self) -> Key;
    fn public_key(&self) -> Key;
    // This is dup instead of clone because making a trait Clone has unpleasant consequences.
    fn dup(&self) -> Box<CryptDE>;
    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn verify_signature(&self, data: &PlainData, signature: &CryptData, public_key: &Key) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor;

    #[test]
    fn key_constructor_works_as_expected() {
        let subject = Key::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn crypt_data_constructor_works_as_expected() {
        let subject = CryptData::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn plain_data_constructor_works_as_expected() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn key_serializer_and_deserializer_talk_to_each_other() {
        let input = Key::new(b"The quick brown fox jumps over the lazy dog");

        let data = serde_cbor::ser::to_vec(&input).unwrap();
        let output = serde_cbor::de::from_slice::<Key>(&data[..]).unwrap();

        assert_eq!(output, input);
    }

    #[test]
    fn crypt_data_serializer_and_deserializer_talk_to_each_other() {
        let input = CryptData::new(b"The quick brown fox jumps over the lazy dog");

        let data = serde_cbor::ser::to_vec(&input).unwrap();
        let output = serde_cbor::de::from_slice::<CryptData>(&data[..]).unwrap();

        assert_eq!(output, input);
    }

    #[test]
    fn plain_data_serializer_and_deserializer_talk_to_each_other() {
        let input = PlainData::new(b"The quick brown fox jumps over the lazy dog");

        let data = serde_cbor::ser::to_vec(&input).unwrap();
        let output = serde_cbor::de::from_slice::<PlainData>(&data[..]).unwrap();

        assert_eq!(output, input);
    }

    #[test]
    fn key_can_be_formatted_as_base_64() {
        let subject = Key::new(&b"Now is the time for all good men"[..]);

        let result = format!("{} {:?}", subject, subject);

        assert_eq! (result, String::from ("Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4 Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4"));
    }
}
