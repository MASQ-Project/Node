// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use bip39::Seed;
use ethsign::keyfile::Crypto;
use ethsign::{Protected, PublicKey, SecretKey, Signature};
use serde::de;
use serde::ser;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;
use tiny_hderive::bip32::ExtendedPrivKey;
use web3::types::Address;

#[derive(Debug)]
pub struct Bip32ECKeyPair {
    public: PublicKey,
    secret: SecretKey,
}

impl Bip32ECKeyPair {
    pub fn from_raw(seed: &[u8], derivation_path: &str) -> Result<Self, String> {
        match ExtendedPrivKey::derive(seed, derivation_path) {
            Ok(extended_priv_key) => match SecretKey::from_raw(&extended_priv_key.secret()) {
                Ok(secret) => Ok(Self::from(secret)),
                Err(e) => Err(format!("{:?}", e)),
            },
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub fn extended_private_key(seed: &Seed, derivation_path: &str) -> ExtendedPrivKey {
        ExtendedPrivKey::derive(seed.as_bytes(), derivation_path).expect("Expected a valid path")
    }

    pub fn from_raw_secret(secret: &[u8]) -> Result<Self, String> {
        match SecretKey::from_raw(secret) {
            Ok(secret) => Ok(Bip32ECKeyPair {
                public: secret.public(),
                secret,
            }),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    pub fn from_key(extended_private_key: ExtendedPrivKey) -> Result<Bip32ECKeyPair, String> {
        Self::from_raw_secret(&extended_private_key.secret())
    }

    pub fn address(&self) -> Address {
        Address {
            0: *self.public.address(),
        }
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        self.secret.sign(msg).map_err(|e| format!("{:?}", e))
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<bool, String> {
        self.public
            .verify(signature, msg)
            .map_err(|e| format!("{:?}", e))
    }

    pub fn clone_secret(&self) -> SecretKey {
        match self.secret.to_crypto(
            &Protected::from("secret"),
            NonZeroU32::new(1).expect("Could not create"),
        ) {
            Ok(crypto) => match SecretKey::from_crypto(&crypto, &Protected::from("secret")) {
                Ok(secret) => secret,
                Err(e) => panic!("{:?}", e),
            },
            Err(e) => panic!("{:?}", e),
        }
    }
}

impl TryFrom<(&[u8], &str)> for Bip32ECKeyPair {
    type Error = String;

    fn try_from(seed_path: (&[u8], &str)) -> Result<Self, Self::Error> {
        let (seed, derivation_path) = seed_path;
        if seed.len() != 64 {
            Err(format!("Invalid Seed Length: {}", seed.len()))
        } else {
            match ExtendedPrivKey::derive(seed, derivation_path) {
                Ok(extended_priv_key) => match SecretKey::from_raw(&extended_priv_key.secret()) {
                    Ok(secret) => Ok(Self::from(secret)),
                    Err(e) => Err(format!("{:?}", e)),
                },
                Err(e) => Err(format!("{:?}", e)),
            }
        }
    }
}

impl From<SecretKey> for Bip32ECKeyPair {
    fn from(secret: SecretKey) -> Self {
        Self {
            public: secret.public(),
            secret,
        }
    }
}

impl<'de> Deserialize<'de> for Bip32ECKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        let crypto = Crypto::deserialize(deserializer)?;
        let raw_secret = crypto
            .decrypt(&Protected::from("secret"))
            .map_err(de::Error::custom)?;
        Self::from_raw_secret(&raw_secret).map_err(de::Error::custom)
    }
}

impl Serialize for Bip32ECKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let result = self
            .secret
            .to_crypto(
                &Protected::from("secret"),
                NonZeroU32::new(1).expect("Could not create"),
            )
            .map_err(ser::Error::custom)?;
        result.serialize(serializer)
    }
}

impl PartialEq<Bip32ECKeyPair> for Bip32ECKeyPair {
    fn eq(&self, other: &Bip32ECKeyPair) -> bool {
        self.public.bytes().as_ref() == other.public.bytes().as_ref()
    }
}

impl Eq for Bip32ECKeyPair {}

impl Hash for Bip32ECKeyPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public.bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masq_lib::utils::{
        DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
    };
    use bip39::{Language, Mnemonic};
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn bip32_derivation_path_0_produces_a_keypair_with_correct_address() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let bip32eckey_pair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH.as_str()))
                .unwrap();
        let address: Address = bip32eckey_pair.address();
        let expected_address: Address =
            serde_json::from_str::<Address>("\"0x2DCfb0B4c2515Ae04dCB2A36e9d7d4251B3611BC\"")
                .unwrap();
        assert_eq!(expected_address, address);
    }

    #[test]
    fn bip32_derivation_path_1_produces_a_keypair_with_correct_address() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let bip32eckey_pair =
            Bip32ECKeyPair::try_from((seed.as_ref(), DEFAULT_EARNING_DERIVATION_PATH.as_str()))
                .unwrap();
        let address: Address = bip32eckey_pair.address();
        let expected_address: Address =
            serde_json::from_str::<Address>("\"0x20eF925bBbFca786bd426BaED8c6Ae45e4284e12\"")
                .unwrap();
        assert_eq!(expected_address, address);
    }

    #[test]
    fn bip39_to_address() {
        let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";

        let expected_secret_key = b"\xff\x1e\x68\xeb\x7b\xf2\xf4\x86\x51\xc4\x7e\xf0\x17\x7e\xb8\x15\x85\x73\x22\x25\x7c\x58\x94\xbb\x4c\xfd\x11\x76\xc9\x98\x93\x14";
        let expected_address: &[u8] =
            b"\x63\xF9\xA9\x2D\x8D\x61\xb4\x8a\x9f\xFF\x8d\x58\x08\x04\x25\xA3\x01\x2d\x05\xC8";

        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let key_pair =
            Bip32ECKeyPair::try_from((seed.as_bytes(), DEFAULT_CONSUMING_DERIVATION_PATH.as_str()))
                .unwrap();

        assert_eq!(
            format!("{:?}", SecretKey::from_raw(expected_secret_key).unwrap()),
            format!("{:?}", key_pair.secret)
        );

        let account =
            ExtendedPrivKey::derive(seed.as_bytes(), DEFAULT_CONSUMING_DERIVATION_PATH.as_str())
                .unwrap();

        assert_eq!(
            expected_secret_key,
            &account.secret(),
            "Secret key is invalid"
        );

        let secret = SecretKey::from_raw(&account.secret()).unwrap();
        let public = secret.public();

        assert_eq!(expected_address, public.address(), "Address is invalid");
    }

    #[test]
    fn bip32_try_from_errors_with_empty_derivation_path() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        assert_eq!(
            Bip32ECKeyPair::try_from((seed.as_ref(), "")).unwrap_err(),
            "InvalidDerivationPath".to_string()
        );
    }

    #[test]
    fn bip32_try_from_errors_with_empty_seed() {
        assert_eq!(
            Bip32ECKeyPair::try_from(("".as_ref(), DEFAULT_CONSUMING_DERIVATION_PATH.as_str()))
                .unwrap_err(),
            "Invalid Seed Length: 0".to_string()
        );
    }

    fn keypair_a() -> Bip32ECKeyPair {
        let numbers = (0u8..32u8).collect::<Vec<u8>>();
        Bip32ECKeyPair::from_raw_secret(&numbers).unwrap()
    }

    fn keypair_b() -> Bip32ECKeyPair {
        let numbers = (1u8..33u8).collect::<Vec<u8>>();
        Bip32ECKeyPair::from_raw_secret(&numbers).unwrap()
    }

    fn hash(keypair: &Bip32ECKeyPair) -> u64 {
        let mut hasher = DefaultHasher::new();
        keypair.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn hash_test() {
        let a1 = keypair_a();
        let a2 = keypair_a();
        let b1 = keypair_b();

        assert_eq!(hash(&a1), hash(&a1));
        assert_eq!(hash(&a1), hash(&a2));
        assert_ne!(hash(&a1), hash(&b1));
    }

    #[test]
    fn partial_eq_test() {
        let a1 = keypair_a();
        let a2 = keypair_a();
        let b1 = keypair_b();

        assert_eq!(&a1, &a1);
        assert_eq!(&a1, &a2);
        assert_ne!(&a1, &b1);
    }
}
