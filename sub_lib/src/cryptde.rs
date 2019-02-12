// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use base64;
use serde;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::fmt;

#[derive(Clone, PartialEq)]
pub struct PrivateKey {
    data: Vec<u8>,
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl From<&[u8]> for PrivateKey {
    fn from(slice: &[u8]) -> Self {
        PrivateKey::new(slice)
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(data: Vec<u8>) -> Self {
        PrivateKey { data }
    }
}

impl Into<Vec<u8>> for PrivateKey {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

impl PrivateKey {
    pub fn new(data: &[u8]) -> PrivateKey {
        PrivateKey {
            data: Vec::from(data),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

// TODO: Consider generating each of these three with a single macro

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    data: Vec<u8>,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.data[..])
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(KeyVisitor)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl From<&[u8]> for PublicKey {
    fn from(slice: &[u8]) -> Self {
        PublicKey::new(slice)
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(data: Vec<u8>) -> Self {
        PublicKey { data }
    }
}

impl Into<Vec<u8>> for PublicKey {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

impl PublicKey {
    pub fn new(data: &[u8]) -> PublicKey {
        PublicKey {
            data: Vec::from(data),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

struct KeyVisitor;

impl<'a> Visitor<'a> for KeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a PublicKey struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(PublicKey::new(v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CryptData {
    data: Vec<u8>,
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

impl From<&[u8]> for CryptData {
    fn from(slice: &[u8]) -> Self {
        CryptData::new(slice)
    }
}

impl From<Vec<u8>> for CryptData {
    fn from(data: Vec<u8>) -> Self {
        CryptData { data }
    }
}

impl Into<Vec<u8>> for CryptData {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

impl CryptData {
    pub fn new(data: &[u8]) -> CryptData {
        CryptData {
            data: Vec::from(data),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

struct CryptDataVisitor;

impl<'a> Visitor<'a> for CryptDataVisitor {
    type Value = CryptData;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    data: Vec<u8>,
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

impl From<&[u8]> for PlainData {
    fn from(slice: &[u8]) -> Self {
        PlainData::new(slice)
    }
}

impl From<Vec<u8>> for PlainData {
    fn from(data: Vec<u8>) -> Self {
        PlainData { data }
    }
}

impl Into<Vec<u8>> for PlainData {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

impl PlainData {
    pub fn new(data: &[u8]) -> PlainData {
        PlainData {
            data: Vec::from(data),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

struct PlainDataVisitor;

impl<'a> Visitor<'a> for PlainDataVisitor {
    type Value = PlainData;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn encode(&self, public_key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError>;
    fn random(&self, dest: &mut [u8]);
    // TODO: Would be really nice if these could return &XxxKey instead of XxxKey
    fn private_key(&self) -> PrivateKey;
    fn public_key(&self) -> PublicKey;
    // This is dup instead of clone because making a trait Clone has unpleasant consequences.
    fn dup(&self) -> Box<dyn CryptDE>;
    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn verify_signature(
        &self,
        data: &PlainData,
        signature: &CryptData,
        public_key: &PublicKey,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor;

    #[test]
    fn private_key_constructor_works_as_expected() {
        let subject = PrivateKey::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn private_key_from_slice() {
        let data: &[u8] = &[1, 2, 3, 4];
        let subject = PrivateKey::from(data);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn private_key_from_vec() {
        let subject = PrivateKey::from(vec![1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn private_key_to_vec() {
        let subject = PrivateKey::new(&[1, 2, 3, 4]);

        let result: Vec<u8> = subject.into();

        assert_eq!(result, vec!(1, 2, 3, 4));
    }

    #[test]
    fn private_key_as_slice() {
        let subject = PrivateKey::new(&[1, 2, 3, 4]);

        let result = subject.as_slice();

        assert_eq!(result, &[1, 2, 3, 4]);
    }

    #[test]
    fn private_key_len() {
        let subject = PrivateKey::new(&[1, 2, 3, 4]);

        let result = subject.len();

        assert_eq!(result, 4);
    }

    #[test]
    fn private_key_is_empty() {
        let a = PrivateKey::new(&[1, 2, 3, 4]);
        let b = PrivateKey::new(&[]);

        assert_eq!(a.is_empty(), false);
        assert_eq!(b.is_empty(), true);
    }

    #[test]
    fn public_key_constructor_works_as_expected() {
        let subject = PublicKey::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn public_key_from_slice() {
        let data: &[u8] = &[1, 2, 3, 4];
        let subject = PublicKey::from(data);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn public_key_from_vec() {
        let subject = PublicKey::from(vec![1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn public_key_to_vec() {
        let subject = PublicKey::new(&[1, 2, 3, 4]);

        let result: Vec<u8> = subject.into();

        assert_eq!(result, vec!(1, 2, 3, 4));
    }

    #[test]
    fn public_key_as_slice() {
        let subject = PublicKey::new(&[1, 2, 3, 4]);

        let result = subject.as_slice();

        assert_eq!(result, &[1, 2, 3, 4]);
    }

    #[test]
    fn public_key_len() {
        let subject = PublicKey::new(&[1, 2, 3, 4]);

        let result = subject.len();

        assert_eq!(result, 4);
    }

    #[test]
    fn public_key_is_empty() {
        let a = PublicKey::new(&[1, 2, 3, 4]);
        let b = PublicKey::new(&[]);

        assert_eq!(a.is_empty(), false);
        assert_eq!(b.is_empty(), true);
    }

    #[test]
    fn crypt_data_constructor_works_as_expected() {
        let subject = CryptData::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn crypt_data_from_slice() {
        let data: &[u8] = &[1, 2, 3, 4];
        let subject = CryptData::from(data);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn crypt_data_from_vec() {
        let subject = CryptData::from(vec![1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn crypt_data_to_vec() {
        let subject = CryptData::new(&[1, 2, 3, 4]);

        let result: Vec<u8> = subject.into();

        assert_eq!(result, vec!(1, 2, 3, 4));
    }

    #[test]
    fn crypt_data_as_slice() {
        let subject = CryptData::new(&[1, 2, 3, 4]);

        let result = subject.as_slice();

        assert_eq!(result, &[1, 2, 3, 4]);
    }

    #[test]
    fn crypt_data_len() {
        let subject = CryptData::new(&[1, 2, 3, 4]);

        let result = subject.len();

        assert_eq!(result, 4);
    }

    #[test]
    fn crypt_data_is_empty() {
        let a = CryptData::new(&[1, 2, 3, 4]);
        let b = CryptData::new(&[]);

        assert_eq!(a.is_empty(), false);
        assert_eq!(b.is_empty(), true);
    }

    #[test]
    fn plain_data_constructor_works_as_expected() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn plain_data_from_slice() {
        let data: &[u8] = &[1, 2, 3, 4];
        let subject = PlainData::from(data);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn plain_data_from_vec() {
        let subject = PlainData::from(vec![1, 2, 3, 4]);

        assert_eq!(subject.data, vec!(1, 2, 3, 4));
    }

    #[test]
    fn plain_data_to_vec() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        let result: Vec<u8> = subject.into();

        assert_eq!(result, vec!(1, 2, 3, 4));
    }

    #[test]
    fn plain_data_as_slice() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        let result = subject.as_slice();

        assert_eq!(result, &[1, 2, 3, 4]);
    }

    #[test]
    fn plain_data_len() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        let result = subject.len();

        assert_eq!(result, 4);
    }

    #[test]
    fn plain_data_is_empty() {
        let a = PlainData::new(&[1, 2, 3, 4]);
        let b = PlainData::new(&[]);

        assert_eq!(a.is_empty(), false);
        assert_eq!(b.is_empty(), true);
    }

    #[test]
    fn public_key_serializer_and_deserializer_talk_to_each_other() {
        let input = PublicKey::new(b"The quick brown fox jumps over the lazy dog");

        let data = serde_cbor::ser::to_vec(&input).unwrap();
        let output = serde_cbor::de::from_slice::<PublicKey>(&data[..]).unwrap();

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
    fn public_key_can_be_formatted_as_base_64() {
        let subject = PublicKey::new(&b"Now is the time for all good men"[..]);

        let result = format!("{} {:?}", subject, subject);

        assert_eq! (result, String::from ("Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4 Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4"));
    }
}
