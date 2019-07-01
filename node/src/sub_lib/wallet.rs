// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use ethsign::PublicKey;
use rusqlite::types::{FromSql, FromSqlError, ToSqlOutput, Value, ValueRef};
use rusqlite::ToSql;
use rustc_hex::ToHex;
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Error, Formatter};
use std::hash::{Hash, Hasher};
use std::result::Result;
use std::str::FromStr;
use web3::types::{Address, H256};

pub const DEFAULT_CONSUMING_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
pub const DEFAULT_EARNING_DERIVATION_PATH: &str = "m/44'/60'/0'/0/1";

#[derive(Debug, PartialEq)]
pub enum WalletError {
    InvalidAddress,
}

impl std::error::Error for WalletError {}

impl Display for WalletError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            WalletError::InvalidAddress => write!(f, "Invalid address"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum WalletKind {
    Address(Address),
    #[serde(skip)] // Deliberate. Don't leak the secret key
    KeyPair(Bip32ECKeyPair),
    #[serde(skip)] // 3rd party crate doesn't implement Serialize
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

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::make_wallet;
    use bip39::{Language, Mnemonic, Seed};
    use rusqlite::Connection;
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
    fn serialization_with_cbor_fails_to_roundtrip_wallet_with_keypair() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH)).unwrap();

        let expected_wallet = Wallet::from(keypair);
        let error = serde_cbor::to_vec(&expected_wallet).unwrap_err();
        assert!(error.is_data());
        assert_eq!(
            error.to_string(),
            "the enum variant WalletKind::KeyPair cannot be serialized",
        );
    }

    #[test]
    fn serialization_with_json_fails_to_roundtrip_wallet_with_keypair() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let keypair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH)).unwrap();

        let expected_wallet = Wallet::from(keypair);
        let error = serde_json::to_string(&expected_wallet).unwrap_err();
        assert!(error.is_data());
        assert_eq!(
            error.to_string(),
            "the enum variant WalletKind::KeyPair cannot be serialized",
        );
    }

    #[test]
    fn serialization_with_json_fails_to_roundtrip_wallet_with_public_key() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected_wallet = Wallet::from(key);

        let error = serde_json::to_string(&expected_wallet).unwrap_err();

        assert!(error.is_data());
        assert_eq!(
            error.to_string(),
            "the enum variant WalletKind::PublicKey cannot be serialized",
        );
    }

    #[test]
    fn serialization_with_cbor_fails_to_roundtrip_wallet_with_public_key() {
        let slice = [0u8; 64];
        let key = PublicKey::from_slice(&slice[..]).unwrap();
        let expected_wallet = Wallet::from(key);

        let error = serde_cbor::to_vec(&expected_wallet).unwrap_err();

        assert!(error.is_data());
        assert_eq!(
            error.to_string(),
            "the enum variant WalletKind::PublicKey cannot be serialized",
        );
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn serialization_with_json_to_roundtrip_wallet_uninitialized() {
        let expected_wallet = Wallet::new(&"");
        let serialized_data = serde_json::to_string(&expected_wallet).unwrap();

        let actual_wallet = serde_json::from_str(&serialized_data).unwrap();

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
}
