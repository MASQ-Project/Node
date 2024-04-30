// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::route::RouteError;
use ethsign_crypto::Keccak256;
use rustc_hex::{FromHex, ToHex};
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::any::Any;
use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq)]
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
            "0x{}",
            self.data.as_slice().to_hex::<String>().to_uppercase()
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

impl From<PrivateKey> for Vec<u8> {
    fn from(key: PrivateKey) -> Self {
        key.data
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
            "0x{}",
            self.data.as_slice().to_hex::<String>().to_uppercase()
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

impl From<PublicKey> for Vec<u8> {
    fn from(key: PublicKey) -> Self {
        key.data
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
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
        Ok(Self::Value::from(v))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SymmetricKey {
    data: Vec<u8>,
}

impl Serialize for SymmetricKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.data[..])
    }
}

impl<'de> Deserialize<'de> for SymmetricKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SymmetricKeyVisitor)
    }
}

impl fmt::Display for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            base64::encode_config(&self.data, base64::STANDARD_NO_PAD)
        )
    }
}

impl From<&[u8]> for SymmetricKey {
    fn from(slice: &[u8]) -> Self {
        SymmetricKey::new(slice)
    }
}

impl From<Vec<u8>> for SymmetricKey {
    fn from(data: Vec<u8>) -> Self {
        SymmetricKey { data }
    }
}

impl From<SymmetricKey> for Vec<u8> {
    fn from(key: SymmetricKey) -> Self {
        key.data
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl SymmetricKey {
    pub fn new(data: &[u8]) -> SymmetricKey {
        SymmetricKey {
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

struct SymmetricKeyVisitor;

impl<'a> Visitor<'a> for SymmetricKeyVisitor {
    type Value = SymmetricKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a SymmetricKey struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Self::Value::from(v))
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

impl From<CryptData> for Vec<u8> {
    fn from(crypt_data: CryptData) -> Self {
        crypt_data.data
    }
}

impl ToHex for CryptData {
    fn to_hex<T: FromIterator<char>>(&self) -> T {
        self.data.to_hex()
    }
}

impl AsRef<[u8]> for CryptData {
    fn as_ref(&self) -> &[u8] {
        &self.data
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainData {
    pub(crate) data: Vec<u8>,
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

impl FromStr for PlainData {
    type Err = String;

    #[allow(clippy::manual_strip)]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = if value.starts_with("0x") {
            &value[2..]
        } else {
            value
        };
        match hex.from_hex::<Vec<u8>>() {
            Ok(bytes) => Ok(PlainData::from(bytes)),
            Err(e) => Err(format!("{:?}", e)),
        }
    }
}

impl From<PlainData> for Vec<u8> {
    fn from(plain_data: PlainData) -> Self {
        plain_data.data
    }
}

impl AsRef<[u8]> for PlainData {
    fn as_ref(&self) -> &[u8] {
        &self.data
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

    pub fn get_u8(&self, idx: usize) -> Option<u8> {
        if idx >= self.data.len() {
            None
        } else {
            Some(self.data[idx])
        }
    }

    // If you're thinking of optimizing these using unsafe code to play with pointers, remember
    // that you don't know whether this system is big-endian or little-endian.
    pub fn get_u16(&self, idx: usize) -> Option<u16> {
        if (idx + 1) >= self.data.len() {
            None
        } else {
            Some((u16::from(self.data[idx]) << 8) | u16::from(self.data[idx + 1]))
        }
    }

    pub fn get_u24(&self, idx: usize) -> Option<u32> {
        if (idx + 2) >= self.data.len() {
            None
        } else {
            Some(
                (u32::from(self.data[idx]) << 16)
                    | (u32::from(self.data[idx + 1]) << 8)
                    | u32::from(self.data[idx + 2]),
            )
        }
    }

    pub fn get_u32(&self, idx: usize) -> Option<u32> {
        if (idx + 3) >= self.data.len() {
            None
        } else {
            Some(
                (u32::from(self.data[idx]) << 24)
                    | (u32::from(self.data[idx + 1]) << 16)
                    | (u32::from(self.data[idx + 2]) << 8)
                    | u32::from(self.data[idx + 3]),
            )
        }
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

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum CryptdecError {
    EmptyKey,
    EmptyData,
    InvalidKey(String),
    InvalidSignature(String),
    OpeningFailed,
    OtherError(String),
}

#[allow(clippy::upper_case_acronyms)]
pub trait CryptDE: Send + Sync {
    fn encode(&self, public_key: &PublicKey, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn decode(&self, data: &CryptData) -> Result<PlainData, CryptdecError>;
    fn encode_sym(&self, key: &SymmetricKey, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn decode_sym(&self, key: &SymmetricKey, data: &CryptData) -> Result<PlainData, CryptdecError>;
    fn gen_key_sym(&self) -> SymmetricKey;
    fn random(&self, dest: &mut [u8]);
    fn private_key(&self) -> &PrivateKey;
    fn public_key(&self) -> &PublicKey;
    // This is dup instead of clone because making a trait Clone has unpleasant consequences.
    fn dup(&self) -> Box<dyn CryptDE>;
    fn sign(&self, data: &PlainData) -> Result<CryptData, CryptdecError>;
    fn verify_signature(
        &self,
        data: &PlainData,
        signature: &CryptData,
        public_key: &PublicKey,
    ) -> bool;
    fn hash(&self, data: &PlainData) -> CryptData;
    fn public_key_to_descriptor_fragment(&self, public_key: &PublicKey) -> String;
    fn descriptor_fragment_to_first_contact_public_key(
        &self,
        descriptor_fragment: &str,
    ) -> Result<PublicKey, String>;
    fn digest(&self) -> [u8; 32];
    fn as_any(&self) -> &dyn Any;
}

pub struct SerdeCborError {
    pub delegate: serde_cbor::error::Error,
}

impl fmt::Debug for SerdeCborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        self.delegate.fmt(f)
    }
}

impl PartialEq for SerdeCborError {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.delegate) == format!("{:?}", other.delegate)
    }
}

impl SerdeCborError {
    fn new(delegate: serde_cbor::error::Error) -> SerdeCborError {
        SerdeCborError { delegate }
    }
}

#[derive(PartialEq, Debug)]
pub enum CodexError {
    SerializationError(SerdeCborError),
    DeserializationError(SerdeCborError),
    EncryptionError(CryptdecError),
    DecryptionError(CryptdecError),
    RoutingError(RouteError),
}

pub fn encodex<T>(
    cryptde: &dyn CryptDE,
    public_key: &PublicKey,
    item: &T,
) -> Result<CryptData, CodexError>
where
    T: Serialize,
{
    let serialized = match serde_cbor::ser::to_vec(item) {
        Ok(s) => s,
        Err(e) => return Err(CodexError::SerializationError(SerdeCborError::new(e))),
    };
    match cryptde.encode(public_key, &PlainData::from(serialized)) {
        Ok(c) => Ok(c),
        Err(e) => Err(CodexError::EncryptionError(e)),
    }
}

pub fn decodex<T>(cryptde: &dyn CryptDE, data: &CryptData) -> Result<T, CodexError>
where
    for<'de> T: Deserialize<'de>,
{
    let decrypted = match cryptde.decode(data) {
        Ok(d) => d,
        Err(e) => return Err(CodexError::DecryptionError(e)),
    };
    match serde_cbor::de::from_slice(decrypted.as_slice()) {
        Ok(t) => Ok(t),
        Err(e) => Err(CodexError::DeserializationError(SerdeCborError::new(e))),
    }
}

pub fn create_digest(msg: &dyn AsRef<[u8]>, address: &dyn AsRef<[u8]>) -> [u8; 32] {
    [msg.as_ref(), address.as_ref()].concat().keccak256()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::main_cryptde;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use rustc_hex::{FromHex, FromHexError};
    use serde::de;
    use serde::ser;
    use serde_cbor;
    use serde_derive::{Deserialize, Serialize};

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
    fn crypt_data_to_hex_and_from_hex() {
        let subject = CryptData::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let hex_str: String = subject.to_hex();

        assert_eq!(hex_str, "0102030405060708090a0b0c0d0e0f");

        let actual_result: Result<Vec<u8>, FromHexError> = hex_str.from_hex();
        assert!(actual_result.is_ok());

        match actual_result {
            Ok(actual_crypt_data) => assert_eq!(actual_crypt_data, subject.data),
            Err(e) => panic!("crypt_data_to_hex failed {}", e),
        }
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
    fn plain_data_try_from_str_good_bare() {
        let subject = PlainData::from_str("0123456789ABCDEF").unwrap();

        assert_eq!(
            subject,
            PlainData::new(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        );
    }

    #[test]
    fn plain_data_try_from_str_good_prefixed() {
        let subject = PlainData::from_str("0x0123456789ABCDEF").unwrap();

        assert_eq!(
            subject,
            PlainData::new(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        );
    }

    #[test]
    fn plain_data_try_from_str_bad() {
        let result = PlainData::from_str("Not a hexadecimal value");

        assert_eq!(
            result,
            Err("Invalid character 'N' at position 0".to_string())
        );
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
    fn plain_data_get_u8() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        assert_eq!(Some(1), subject.get_u8(0));
        assert_eq!(Some(3), subject.get_u8(2));
        assert_eq!(None, subject.get_u8(4));
    }

    #[test]
    fn plain_data_get_u16() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        assert_eq!(Some(0x0102), subject.get_u16(0));
        assert_eq!(Some(0x0304), subject.get_u16(2));
        assert_eq!(None, subject.get_u16(3));
    }

    #[test]
    fn plain_data_get_u24() {
        let subject = PlainData::new(&[1, 2, 3, 4]);

        assert_eq!(Some(0x010203), subject.get_u24(0));
        assert_eq!(Some(0x020304), subject.get_u24(1));
        assert_eq!(None, subject.get_u24(2));
    }

    #[test]
    fn plain_data_get_u32() {
        let subject = PlainData::new(&[1, 2, 3, 4, 5]);

        assert_eq!(Some(0x01020304), subject.get_u32(0));
        assert_eq!(Some(0x02030405), subject.get_u32(1));
        assert_eq!(None, subject.get_u32(2));
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
    fn public_key_is_displayed_as_base64_and_debugged_as_hex() {
        let subject = PublicKey::new(&b"Now is the time for all good men"[..]);

        let result = format!("{} {:?}", subject, subject);

        assert_eq!(result, String::from ("Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4 0x4E6F77206973207468652074696D6520666F7220616C6C20676F6F64206D656E"));
    }

    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct TestStruct {
        string: String,
        number: u32,
        flag: bool,
    }
    impl TestStruct {
        pub fn make() -> TestStruct {
            TestStruct {
                string: String::from("booga"),
                number: 42,
                flag: true,
            }
        }
    }

    #[test]
    fn encodex_and_decodex_communicate() {
        let cryptde = main_cryptde();
        let start = TestStruct::make();

        let intermediate = encodex(cryptde, &cryptde.public_key(), &start).unwrap();
        let end = decodex::<TestStruct>(cryptde, &intermediate).unwrap();

        assert_eq!(end, start);
    }

    #[test]
    fn encodex_produces_expected_data() {
        let cryptde = main_cryptde();
        let start = TestStruct::make();

        let intermediate = super::encodex(cryptde, &cryptde.public_key(), &start).unwrap();

        let decrypted = cryptde.decode(&intermediate).unwrap();
        let deserialized: TestStruct = serde_cbor::de::from_slice(decrypted.as_slice()).unwrap();

        assert_eq!(deserialized, start);
    }

    #[test]
    fn decodex_produces_expected_structure() {
        let cryptde = main_cryptde();
        let serialized = serde_cbor::ser::to_vec(&TestStruct::make()).unwrap();
        let encrypted = cryptde
            .encode(&cryptde.public_key(), &PlainData::from(serialized))
            .unwrap();

        let end = super::decodex::<TestStruct>(cryptde, &encrypted).unwrap();

        assert_eq!(end, TestStruct::make());
    }

    #[test]
    fn encodex_handles_encryption_error() {
        let cryptde = main_cryptde();
        let item = TestStruct::make();

        let result = encodex(cryptde, &PublicKey::new(&[]), &item);

        assert_eq!(
            format!("{:?}", result),
            "Err(EncryptionError(EmptyKey))".to_string()
        );
    }

    #[test]
    fn decodex_handles_decryption_error() {
        let mut cryptde = CryptDENull::new(TEST_DEFAULT_CHAIN);
        cryptde.set_key_pair(&PublicKey::new(&[]), TEST_DEFAULT_CHAIN);
        let data = CryptData::new(&b"booga"[..]);

        let result = decodex::<TestStruct>(&cryptde, &data);

        assert_eq!(
            format!("{:?}", result),
            "Err(DecryptionError(EmptyKey))".to_string()
        );
    }

    #[derive(PartialEq, Eq, Debug)]
    struct BadSerStruct {
        flag: bool,
    }
    impl serde::Serialize for BadSerStruct {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(ser::Error::custom("booga"))
        }
    }
    impl<'de> serde::Deserialize<'de> for BadSerStruct {
        fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            Err(de::Error::custom("booga"))
        }
    }

    #[test]
    fn encodex_handles_serialization_error() {
        let cryptde = main_cryptde();
        let item = BadSerStruct { flag: true };

        let result = encodex(cryptde, &cryptde.public_key(), &item);

        assert_eq!(
            format!("{:?}", result),
            "Err(SerializationError(ErrorImpl { code: Message(\"booga\"), offset: 0 }))"
                .to_string()
        );
    }

    #[test]
    fn decodex_handles_deserialization_error() {
        let cryptde = main_cryptde();
        let data = cryptde
            .encode(&cryptde.public_key(), &PlainData::new(b"whompem"))
            .unwrap();

        let result = decodex::<BadSerStruct>(cryptde, &data);

        assert_eq!(
            format!("{:?}", result),
            "Err(DeserializationError(ErrorImpl { code: Message(\"booga\"), offset: 0 }))"
                .to_string()
        );
    }
}
