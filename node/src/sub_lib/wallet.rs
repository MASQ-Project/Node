// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::payer::Payer;
use crate::sub_lib::cryptde::PublicKey as SubPublicKey;
use ethsign::{PublicKey, Signature};
use ethsign_crypto::{self, Keccak256};
use rusqlite::types::{FromSql, FromSqlError, ToSqlOutput, Value, ValueRef};
use rusqlite::ToSql;
use rustc_hex::ToHex;
use serde::Serialize;
use serde::{ser::SerializeStruct, Serializer};
use std::convert::TryInto;
use std::fmt;
use std::fmt::{Debug, Display, Error, Formatter};
use std::hash::{Hash, Hasher};
use std::result::Result;
use std::str::FromStr;
use web3::types::{Address, H256};

pub const DEFAULT_CONSUMING_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
pub const DEFAULT_EARNING_DERIVATION_PATH: &str = "m/44'/60'/0'/0/1";

#[derive(Debug, PartialEq)]
pub enum WalletError {
    InvalidAddress,
    Signature(String),
}

impl std::error::Error for WalletError {}

impl Display for WalletError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::InvalidAddress => write!(f, "Invalid address"),
            WalletError::Signature(msg) => write!(f, "{}", msg),
        }
    }
}

#[derive(Debug)]
pub enum WalletKind {
    Address(Address),
    KeyPair(Bip32ECKeyPair),
    PublicKey(PublicKey),
    Uninitialized,
}

impl Clone for WalletKind {
    fn clone(&self) -> Self {
        match self {
            WalletKind::Address(address) => WalletKind::Address(Address { 0: address.0 }),
            WalletKind::KeyPair(keypair) => {
                WalletKind::KeyPair(Bip32ECKeyPair::from(keypair.clone_secret()))
            }
            WalletKind::PublicKey(public) => WalletKind::PublicKey(
                PublicKey::from_slice(public.bytes()).expect("Failed to clone from PublicKey"),
            ),
            WalletKind::Uninitialized => WalletKind::Uninitialized,
        }
    }
}

impl PartialEq<WalletKind> for WalletKind {
    fn eq(&self, other: &Self) -> bool {
        match other {
            WalletKind::Address(other_address) => match self {
                WalletKind::Address(self_address) => self_address == other_address,
                _ => false,
            },
            WalletKind::KeyPair(other_keypair) => match self {
                WalletKind::KeyPair(self_keypair) => self_keypair == other_keypair,
                _ => false,
            },
            WalletKind::PublicKey(other_public) => match self {
                WalletKind::PublicKey(self_public) => {
                    self_public.bytes().to_hex::<String>()
                        == other_public.bytes().to_hex::<String>()
                }
                _ => false,
            },
            WalletKind::Uninitialized => match self {
                WalletKind::Uninitialized => true,
                _ => false,
            },
        }
    }
}

impl Eq for WalletKind {}

impl Hash for WalletKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            WalletKind::Address(address) => address.hash(state),
            WalletKind::KeyPair(keypair) => keypair.hash(state),
            WalletKind::PublicKey(public) => public.bytes().hash(state),
            WalletKind::Uninitialized => b"Uninitialized".hash(state),
        }
    }
}

#[derive(Clone, Eq, Hash)]
pub struct Wallet {
    kind: WalletKind,
}

impl Wallet {
    pub fn new(address: &str) -> Self {
        match Self::from_str(address) {
            Ok(wallet) => wallet,
            Err(_) => Self {
                kind: WalletKind::Uninitialized,
            },
        }
    }

    pub fn address(&self) -> Address {
        match &self.kind {
            WalletKind::Address(address) => Address { 0: address.0 },
            WalletKind::PublicKey(public) => Address {
                0: *public.address(),
            },
            WalletKind::KeyPair(key_pair) => key_pair.address(),
            WalletKind::Uninitialized => panic!("No address for an uninitialized wallet!"),
        }
    }

    pub fn sign(&self, msg: &dyn AsRef<[u8]>) -> Result<Signature, WalletError> {
        match self.kind {
            WalletKind::KeyPair(ref key_pair) => {
                let digest = msg.keccak256();
                key_pair
                    .sign(&digest)
                    .map_err(|e| WalletError::Signature(format!("{:?}", e)))
            }
            _ => Err(WalletError::Signature(format!(
                "Cannot sign with non-keypair wallet: {:?}.",
                self.kind
            ))),
        }
    }

    pub fn verify(&self, signature: &Signature, msg: &dyn AsRef<[u8]>) -> bool {
        match self.kind {
            WalletKind::KeyPair(ref key_pair) => {
                let digest = msg.keccak256();
                match &key_pair.verify(signature, &digest) {
                    Ok(result) => *result,
                    Err(_log_this) => false,
                }
            }
            _ => panic!("Keypair wallet required"),
        }
    }

    pub fn as_payer(&self, public_key: &SubPublicKey) -> Payer {
        match self.sign(public_key) {
            Ok(proof) => Payer::new(self, &proof),
            Err(e) => panic!("Trying to sign for {:?} encountered {:?}", public_key, e),
        }
    }
}

impl PartialEq for Wallet {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            || (self.kind != WalletKind::Uninitialized
                && other.kind != WalletKind::Uninitialized
                && self.address() == other.address())
    }
}

impl FromStr for Wallet {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match serde_json::from_str::<Address>(&format!("{:?}", s)) {
            Ok(address) => Ok(Self {
                kind: WalletKind::Address(address),
            }),
            Err(_) => Err(WalletError::InvalidAddress),
        }
    }
}

impl From<H256> for Wallet {
    fn from(address: H256) -> Self {
        Self {
            kind: WalletKind::Address(Address::from(address)),
        }
    }
}

impl From<Address> for Wallet {
    fn from(address: Address) -> Self {
        Self {
            kind: WalletKind::Address(address),
        }
    }
}
impl From<PublicKey> for Wallet {
    fn from(public: PublicKey) -> Self {
        Self {
            kind: WalletKind::PublicKey(public),
        }
    }
}

impl From<Bip32ECKeyPair> for Wallet {
    fn from(keypair: Bip32ECKeyPair) -> Self {
        Self {
            kind: WalletKind::KeyPair(keypair),
        }
    }
}

impl Display for Wallet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:#x}", self.address())
    }
}

impl Debug for Wallet {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{{ address: \"{:#x}\" }}", self.address())
    }
}

impl ToSql for Wallet {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Text(format!(
            "{:#x}",
            self.address()
        ))))
    }
}

impl FromSql for Wallet {
    fn column_result(value: ValueRef) -> Result<Self, FromSqlError> {
        match value.as_str() {
            Ok(address) => Wallet::from_str(address).map_err(|e| FromSqlError::Other(Box::new(e))),
            Err(e) => Err(e),
        }
    }
}

impl TryInto<Bip32ECKeyPair> for Wallet {
    type Error = String;

    fn try_into(self) -> Result<Bip32ECKeyPair, Self::Error> {
        match self.kind {
            WalletKind::KeyPair(keypair) => Ok(keypair),
            _ => Err("Wallet contains no secret key: can't convert to Bip32KeyPair".to_string()),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Wallet {
    fn deserialize<D>(deserializer: D) -> serde::export::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        enum WalletField {
            Address,
            __Ignore,
        }
        struct WalletFieldVisitor;
        impl<'de> serde::de::Visitor<'de> for WalletFieldVisitor {
            type Value = WalletField;
            fn expecting(
                &self,
                formatter: &mut serde::export::Formatter,
            ) -> serde::export::fmt::Result {
                serde::export::Formatter::write_str(formatter, "field identifier")
            }
            fn visit_u64<E>(self, value: u64) -> serde::export::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    0u64 => serde::export::Ok(WalletField::Address),
                    _ => serde::export::Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(value),
                        &"field index 0 <= i < 1",
                    )),
                }
            }
            fn visit_str<E>(self, value: &str) -> serde::export::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "address" => serde::export::Ok(WalletField::Address),
                    _ => serde::export::Ok(WalletField::__Ignore),
                }
            }
            fn visit_bytes<E>(self, value: &[u8]) -> serde::export::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    b"address" => serde::export::Ok(WalletField::Address),
                    _ => serde::export::Ok(WalletField::__Ignore),
                }
            }
        }
        impl<'de> serde::Deserialize<'de> for WalletField {
            #[inline]
            fn deserialize<D>(deserializer: D) -> serde::export::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                serde::Deserializer::deserialize_identifier(deserializer, WalletFieldVisitor)
            }
        }
        struct WalletVisitor<'de> {
            marker: serde::export::PhantomData<Wallet>,
            lifetime: serde::export::PhantomData<&'de ()>,
            human_readable: bool,
        }
        impl<'de> serde::de::Visitor<'de> for WalletVisitor<'de> {
            type Value = Wallet;
            fn expecting(
                &self,
                formatter: &mut serde::export::Formatter,
            ) -> serde::export::fmt::Result {
                serde::export::Formatter::write_str(formatter, "struct Wallet")
            }
            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> serde::export::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let address = match serde::de::SeqAccess::next_element::<Address>(&mut seq)? {
                    serde::export::Some(address) => address,
                    serde::export::None => {
                        return serde::export::Err(serde::de::Error::invalid_length(
                            0usize,
                            &"struct Wallet with 1 element",
                        ));
                    }
                };
                serde::export::Ok(Wallet {
                    kind: WalletKind::Address(address),
                })
            }
            #[inline]
            fn visit_map<A>(self, mut map: A) -> serde::export::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut possible_address: serde::export::Option<Address> = serde::export::None;
                while let serde::export::Some(key) =
                    serde::de::MapAccess::next_key::<WalletField>(&mut map)?
                {
                    match key {
                        WalletField::Address => {
                            if serde::export::Option::is_some(&possible_address) {
                                return serde::export::Err(
                                    <A::Error as serde::de::Error>::duplicate_field("address"),
                                );
                            }
                            possible_address = match &self.human_readable {
                                true => {
                                    serde::export::Some(
                                        serde::de::MapAccess::next_value::<Address>(&mut map)?,
                                    )
                                }
                                false => {
                                    let bytes =
                                        serde::de::MapAccess::next_value::<Vec<u8>>(&mut map)?;
                                    let mut address = [0u8; 20];
                                    address.copy_from_slice(bytes.as_slice());
                                    serde::export::Some(Address { 0: address })
                                }
                            }
                        }
                        _ => {
                            let _ = serde::de::MapAccess::next_value::<serde::de::IgnoredAny>(
                                &mut map,
                            )?;
                        }
                    }
                }
                let address = match possible_address {
                    serde::export::Some(address) => address,
                    serde::export::None => serde::private::de::missing_field("address")?,
                };
                serde::export::Ok(Wallet {
                    kind: WalletKind::Address(address),
                })
            }
        }
        const FIELDS: &'static [&'static str] = &["address"];
        let human_readable = deserializer.is_human_readable();
        serde::Deserializer::deserialize_struct(
            deserializer,
            "Wallet",
            FIELDS,
            WalletVisitor {
                marker: serde::export::PhantomData::<Wallet>,
                lifetime: serde::export::PhantomData,
                human_readable,
            },
        )
    }
}

impl Serialize for Wallet {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let human_readable = serializer.is_human_readable();
        let mut wallet_serializer: <S as Serializer>::SerializeStruct =
            serializer.serialize_struct("Wallet", 1)?;
        if human_readable {
            wallet_serializer.serialize_field("address", &self.address())?;
        } else {
            wallet_serializer.serialize_field("address", &self.address().0.to_vec())?;
        }
        wallet_serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::{make_paying_wallet, make_wallet};
    use bip39::{Language, Mnemonic, Seed};
    use rusqlite::Connection;
    use rustc_hex::FromHex;
    use serde_cbor;
    use serde_json;
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn can_create_with_str_address() {
        let subject =
            Wallet::from_str(format!("0x{}", &b"A valid eth address!".to_hex::<String>()).as_str())
                .unwrap();

        assert_eq!(
            "0x412076616c696420657468206164647265737321".to_string(),
            format!("{:#x}", subject.address())
        );
    }

    #[test]
    fn can_create_from_an_h256() {
        let result = Wallet::from(H256::from(
            "0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc",
        ));

        assert_eq!(
            String::from("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            format!("{:#x}", result.address())
        );
    }

    #[test]
    fn display_works() {
        let subject = Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap();

        let result = format!("|{}|", subject);

        assert_eq!(
            "|0xcafedeadbeefbabefacecafedeadbeefbabeface|".to_string(),
            result
        );
    }

    #[test]
    fn serialization_roundtrips_wallet_by_address_with_cbor_successfully() {
        let expected_wallet = make_wallet("A valid eth address!");
        let serialized_data = serde_cbor::to_vec(&expected_wallet).unwrap();
        let actual_wallet = serde_cbor::from_slice::<Wallet>(serialized_data.as_slice()).unwrap();

        assert_eq!(actual_wallet, expected_wallet);
    }

    #[test]
    fn serialization_roundtrips_wallet_by_address_with_json_successfully() {
        let expected_wallet = make_wallet("A valid eth address!");
        let serialized_data = serde_json::to_string(&expected_wallet).unwrap();
        let actual_wallet = serde_json::from_str::<Wallet>(&serialized_data).unwrap();

        assert_eq!(actual_wallet, expected_wallet);
    }

    #[test]
    fn serialization_with_cbor_asymmetrically_roundtrips_keypair_to_address_only() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH)).unwrap();

        let expected = Wallet::from(keypair);
        let serialized = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&serialized[..]).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert_eq!(actual, expected);
    }

    #[test]
    fn serialization_with_json_asymmetrically_roundtrips_keypair_to_address_only() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH)).unwrap();

        let expected = Wallet::from(keypair);
        let result = serde_json::to_string(&expected).unwrap();
        let actual = serde_json::from_str::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert_eq!(actual, expected);
    }

    #[test]
    fn serialization_with_json_asymmetrically_roundtrips_public_key_to_address_only() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected = Wallet::from(key);

        let result = serde_json::to_string(&expected).unwrap();
        let actual = serde_json::from_str::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert_eq!(actual, expected);
    }

    #[test]
    fn serialization_with_cbor_asymmetrically_roundtrips_public_key_to_address_only() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected = Wallet::from(key);

        let result = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&result).unwrap();

        assert_ne!(actual.kind, expected.kind);
        assert_eq!(actual, expected);
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn serialization_with_json_to_roundtrip_wallet_uninitialized() {
        let expected_wallet = Wallet::new(&"");
        let result = serde_json::to_string(&expected_wallet).unwrap();

        let actual_wallet = serde_json::from_str(&result).unwrap();

        assert_eq!(expected_wallet, actual_wallet);
        expected_wallet.address();
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn serialization_with_cbor_to_roundtrip_wallet_uninitialized() {
        let expected_wallet = Wallet::new(&"");
        let serialized_data = serde_cbor::to_vec(&expected_wallet).unwrap();

        let actual_wallet = serde_cbor::from_slice(&serialized_data[..]).unwrap();

        assert_eq!(expected_wallet, actual_wallet);
        expected_wallet.address();
    }

    #[test]
    fn roundtrip_rusqlite_works() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE foo(wallet TEXT)").unwrap();
        let wallet = Wallet::from_str("0xcafedeadbeefbabefacecafedeadbeefbabeface").unwrap();
        db.execute(
            "
            INSERT INTO foo(wallet) VALUES (?)",
            &[&wallet],
        )
        .unwrap();

        let mut stmt = db
            .prepare("SELECT wallet FROM foo WHERE wallet = ?")
            .unwrap();

        let result = stmt
            .query_map(&[&wallet], |row| match row.get::<usize, Wallet>(0) {
                Ok(wallet) => Ok(wallet),
                Err(e) => Err(e),
            })
            .unwrap()
            .collect::<Result<Vec<Wallet>, _>>()
            .unwrap();

        assert_eq!(result, vec![wallet]);
    }

    #[test]
    fn can_convert_to_keypair_if_came_from_keypair() {
        let secret_key_text = "0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let keypair =
            Bip32ECKeyPair::from_raw_secret(&secret_key_text.from_hex::<Vec<u8>>().unwrap())
                .unwrap();
        let expected_keypair =
            Bip32ECKeyPair::from_raw_secret(&secret_key_text.from_hex::<Vec<u8>>().unwrap())
                .unwrap();
        let subject = Wallet::from(keypair);

        let result: Bip32ECKeyPair = subject.try_into().unwrap();

        assert_eq!(result, expected_keypair);
    }

    #[test]
    fn cant_convert_to_keypair_if_didnt_come_from_keypair() {
        let subject = Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result: Result<Bip32ECKeyPair, String> = subject.try_into();

        assert_eq!(
            result,
            Err("Wallet contains no secret key: can't convert to Bip32KeyPair".to_string())
        );
    }

    #[test]
    #[should_panic(
        expected = r#"Trying to sign for AQID encountered Signature("Cannot sign with non-keypair wallet: Uninitialized.")"#
    )]
    fn sign_with_uninitialized_wallets_panic() {
        Wallet::new("").as_payer(&SubPublicKey::new(&[1, 2, 3]));
    }

    #[test]
    fn roundtrip_wallets_do_not_leak_secret_key() {
        let expected = make_paying_wallet(b"this is quite some secret");

        let serialized = serde_cbor::to_vec(&expected).unwrap();
        let actual = serde_cbor::from_slice::<Wallet>(&serialized[..]).unwrap();

        assert_eq!(actual, expected);
        assert_ne!(actual.kind, expected.kind);
        match actual.kind {
            WalletKind::Address(address) => assert_eq!(address, expected.address()),
            _ => assert!(false, "Failed to match expected WalletKind::Address"),
        }
    }
}
