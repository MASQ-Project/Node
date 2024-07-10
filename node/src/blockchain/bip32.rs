// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use ethereum_types::{Address, H160};
use ethsign::keyfile::Crypto;
use ethsign::{Protected, PublicKey, SecretKey as EthsignSecretKey, Signature};
use secp256k1secrets::SecretKey as Secp256k1SecretKey;
use serde::de;
use serde::ser;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;
use tiny_hderive::bip32::ExtendedPrivKey;

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub struct Bip32EncryptionKeyProvider {
    secret_raw: Vec<u8>,
}

#[allow(clippy::from_over_into)]
impl Into<Secp256k1SecretKey> for &Bip32EncryptionKeyProvider {
    fn into(self) -> Secp256k1SecretKey {
        secp256k1secrets::SecretKey::from_slice(&self.secret_raw).expect("internal error")
    }
}

#[allow(clippy::from_over_into)]
impl Into<EthsignSecretKey> for &Bip32EncryptionKeyProvider {
    fn into(self) -> EthsignSecretKey {
        EthsignSecretKey::from_raw(self.secret_raw.as_ref()).expect("internal error")
    }
}

impl Bip32EncryptionKeyProvider {
    const SECRET_KEY_LENGTH: usize = 32;

    pub fn from_raw_secret(secret_raw: &[u8]) -> Result<Self, String> {
        Self::validate_raw_input(secret_raw)?;
        Ok(Bip32EncryptionKeyProvider {
            secret_raw: secret_raw.to_vec(),
        })
    }

    pub fn from_key(extended_private_key: ExtendedPrivKey) -> Self {
        Self {
            secret_raw: extended_private_key.secret().to_vec(),
        }
    }

    pub fn address(&self) -> Address {
        H160(*self.public_key().address())
    }

    pub fn public_key(&self) -> PublicKey {
        let secret: EthsignSecretKey = self.into();
        secret.public()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let secret: EthsignSecretKey = self.into();
        secret.sign(msg).map_err(|e| format!("{:?}", e))
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<bool, String> {
        self.public_key()
            .verify(signature, msg)
            .map_err(|e| format!("{:?}", e))
    }

    pub fn clone_secret(&self) -> Vec<u8> {
        self.secret_raw.clone()
    }

    fn validate_raw_input(raw_secret: &[u8]) -> Result<(), String> {
        if raw_secret.len() == Self::SECRET_KEY_LENGTH {
            Ok(())
        } else {
            Err(format!(
                "Number of bytes of the secret differs from 32: {}",
                raw_secret.len()
            ))
        }
    }
}

impl TryFrom<(&[u8], &str)> for Bip32EncryptionKeyProvider {
    type Error = String;

    fn try_from(seed_path: (&[u8], &str)) -> Result<Self, Self::Error> {
        let (seed, derivation_path) = seed_path;
        if seed.len() != 64 {
            Err(format!("Invalid Seed Length: {}", seed.len()))
        } else {
            match ExtendedPrivKey::derive(seed, derivation_path) {
                Ok(extended_priv_key) => Ok(Self::from_key(extended_priv_key)),
                Err(e) => Err(format!("{:?}", e)),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Bip32EncryptionKeyProvider {
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

impl Serialize for Bip32EncryptionKeyProvider {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let secret: EthsignSecretKey = self.into();
        let result = secret
            .to_crypto(
                &Protected::from("secret"),
                u32::from(NonZeroU32::new(1).expect("Could not create")),
            )
            .map_err(ser::Error::custom)?;
        result.serialize(serializer)
    }
}

impl PartialEq<Bip32EncryptionKeyProvider> for Bip32EncryptionKeyProvider {
    fn eq(&self, other: &Bip32EncryptionKeyProvider) -> bool {
        self.public_key().bytes().as_ref() == other.public_key().bytes().as_ref()
    }
}

impl Eq for Bip32EncryptionKeyProvider {}

impl Hash for Bip32EncryptionKeyProvider {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key().bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masq_lib::utils::{
        DEFAULT_CONSUMING_DERIVATION_PATH, DEFAULT_EARNING_DERIVATION_PATH,
    };
    use bip39::{Language, Mnemonic, Seed};
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(Bip32EncryptionKeyProvider::SECRET_KEY_LENGTH, 32);
    }

    #[test]
    fn bip32_derivation_path_0_produces_a_key_with_correct_address() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let bip32eckey_provider = Bip32EncryptionKeyProvider::try_from((
            seed.as_ref(),
            DEFAULT_CONSUMING_DERIVATION_PATH.as_str(),
        ))
        .unwrap();
        let address: Address = bip32eckey_provider.address();
        let expected_address: Address =
            serde_json::from_str::<Address>("\"0x2DCfb0B4c2515Ae04dCB2A36e9d7d4251B3611BC\"")
                .unwrap();
        assert_eq!(expected_address, address);
    }

    #[test]
    fn bip32_derivation_path_1_produces_a_key_with_correct_address() {
        let mnemonic = Mnemonic::from_phrase(
            "timber cage wide hawk phone shaft pattern movie army dizzy hen tackle lamp \
             absent write kind term toddler sphere ripple idle dragon curious hold",
            Language::English,
        )
        .unwrap();
        let seed = Seed::new(&mnemonic, "Test123!");
        let bip32eckey_provider = Bip32EncryptionKeyProvider::try_from((
            seed.as_ref(),
            DEFAULT_EARNING_DERIVATION_PATH.as_str(),
        ))
        .unwrap();
        let address: Address = bip32eckey_provider.address();
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

        let key_provider = Bip32EncryptionKeyProvider::try_from((
            seed.as_bytes(),
            DEFAULT_CONSUMING_DERIVATION_PATH.as_str(),
        ))
        .unwrap();

        let secret: EthsignSecretKey = (&key_provider).into();
        assert_eq!(
            format!(
                "{:?}",
                EthsignSecretKey::from_raw(expected_secret_key).unwrap()
            ),
            format!("{:?}", secret)
        );

        let account =
            ExtendedPrivKey::derive(seed.as_bytes(), DEFAULT_CONSUMING_DERIVATION_PATH.as_str())
                .unwrap();

        assert_eq!(
            expected_secret_key,
            &account.secret(),
            "Secret key is invalid"
        );

        let secret = EthsignSecretKey::from_raw(&account.secret()).unwrap();
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
            Bip32EncryptionKeyProvider::try_from((seed.as_ref(), "")).unwrap_err(),
            "InvalidDerivationPath".to_string()
        );
    }

    #[test]
    fn bip32_try_from_errors_with_empty_seed() {
        assert_eq!(
            Bip32EncryptionKeyProvider::try_from((
                "".as_ref(),
                DEFAULT_CONSUMING_DERIVATION_PATH.as_str()
            ))
            .unwrap_err(),
            "Invalid Seed Length: 0".to_string()
        );
    }

    fn keypair_a() -> Bip32EncryptionKeyProvider {
        let numbers = (0u8..32u8).collect::<Vec<u8>>();
        Bip32EncryptionKeyProvider::from_raw_secret(&numbers).unwrap()
    }

    fn keypair_b() -> Bip32EncryptionKeyProvider {
        let numbers = (1u8..33u8).collect::<Vec<u8>>();
        Bip32EncryptionKeyProvider::from_raw_secret(&numbers).unwrap()
    }

    fn hash(keypair: &Bip32EncryptionKeyProvider) -> u64 {
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

    #[test]
    fn from_raw_secret_validates_correct_length_happy_path() {
        let secret_raw: Vec<u8> = (0..32u8).collect();

        let result = Bip32EncryptionKeyProvider::from_raw_secret(secret_raw.as_slice()).unwrap();

        assert_eq!(result.secret_raw, secret_raw)
    }

    #[test]
    fn from_raw_secret_complains_about_input_too_long() {
        let secret_raw: Vec<u8> = (0..33u8).collect();

        let result = Bip32EncryptionKeyProvider::from_raw_secret(secret_raw.as_slice());

        assert_eq!(
            result,
            Err("Number of bytes of the secret differs from 32: 33".to_string())
        )
    }

    #[test]
    fn from_raw_secret_complains_about_input_too_short() {
        let secret_raw: Vec<u8> = (0..31u8).collect();

        let result = Bip32EncryptionKeyProvider::from_raw_secret(secret_raw.as_slice());

        assert_eq!(
            result,
            Err("Number of bytes of the secret differs from 32: 31".to_string())
        )
    }
}
