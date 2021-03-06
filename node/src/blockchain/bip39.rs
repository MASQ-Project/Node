// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::PlainData;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ethsign::keyfile::Crypto;
use ethsign::Protected;
use rustc_hex::{FromHex, ToHex};
use std::num::NonZeroU32;

#[derive(Debug, PartialEq, Clone)]
pub enum Bip39Error {
    ConversionError(String),
    EncryptionFailure(String),
    DecryptionFailure(String),
    NotPresent,
    SerializationFailure(String),
    DeserializationFailure(String),
}

pub struct Bip39 {}

impl Bip39 {
    pub fn mnemonic(mnemonic_type: MnemonicType, language: Language) -> Mnemonic {
        // create a new randomly generated mnemonic phrase
        Mnemonic::new(mnemonic_type, language)
    }

    pub fn seed(mnemonic: &Mnemonic, passphrase: &str) -> Seed {
        // get the HD wallet seed
        Seed::new(mnemonic, passphrase)
    }

    pub fn encrypt_bytes(seed: &dyn AsRef<[u8]>, db_password: &str) -> Result<String, Bip39Error> {
        match Crypto::encrypt(
            seed.as_ref(),
            &Protected::new(db_password.as_bytes()),
            NonZeroU32::new(10240).expect("Internal error"),
        ) {
            Ok(crypto) => match serde_cbor::to_vec(&crypto) {
                Ok(cipher_seed) => Ok(cipher_seed.to_hex()),
                Err(e) => Err(Bip39Error::SerializationFailure(format!(
                    "Failed to serialize: {:?}",
                    e
                ))),
            },
            Err(e) => Err(Bip39Error::EncryptionFailure(format!(
                "Failed to encrypt: {:?}",
                e
            ))),
        }
    }

    pub fn decrypt_bytes(crypt_string: &str, db_password: &str) -> Result<PlainData, Bip39Error> {
        match crypt_string.from_hex::<Vec<u8>>() {
            Ok(cipher_seed_slice) => match serde_cbor::from_slice::<Crypto>(&cipher_seed_slice) {
                Ok(crypto) => match crypto.decrypt(&Protected::new(db_password)) {
                    Ok(mnemonic_seed) => Ok(PlainData::new(&mnemonic_seed)),
                    Err(e) => Err(Bip39Error::DecryptionFailure(format!("{:?}", e))),
                },
                Err(e) => Err(Bip39Error::DeserializationFailure(format!("{}", e))),
            },
            Err(e) => Err(Bip39Error::ConversionError(format!("{:?}", e))),
        }
    }

    pub fn language_from_name(name: &str) -> Language {
        match name.to_lowercase().as_str() {
            "english" => Language::English,
            "??????(??????)" | "??????" => Language::ChineseSimplified,
            "??????(??????)" | "??????" => Language::ChineseTraditional,
            "fran??ais" => Language::French,
            "italiano" => Language::Italian,
            "?????????" => Language::Japanese,
            "?????????" => Language::Korean,
            "espa??ol" => Language::Spanish,
            _ => panic!("Unsupported language: {}", name),
        }
    }

    pub fn name_from_language(language: Language) -> &'static str {
        match language {
            Language::English => "English",
            Language::ChineseSimplified => "??????(??????)",
            Language::ChineseTraditional => "??????(??????)",
            Language::French => "Fran??ais",
            Language::Italian => "Italiano",
            Language::Japanese => "?????????",
            Language::Korean => "?????????",
            Language::Spanish => "Espa??ol",
        }
    }

    pub fn possible_language_values() -> Vec<&'static str> {
        vec![
            Language::English,
            Language::ChineseSimplified,
            Language::ChineseTraditional,
            Language::French,
            Language::Italian,
            Language::Japanese,
            Language::Korean,
            Language::Spanish,
        ]
        .iter()
        .map(|language| Self::name_from_language(*language))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_conversion_error_for_odd_number_of_hex_digits_appropriately() {
        let result = Bip39::decrypt_bytes("123", "");

        assert_eq!(
            result,
            Err(Bip39Error::ConversionError(
                "Invalid input length".to_string()
            ))
        );
    }

    #[test]
    fn round_trip_languages_and_names() {
        for l in &[
            Language::English,
            Language::ChineseSimplified,
            Language::ChineseTraditional,
            Language::French,
            Language::Italian,
            Language::Japanese,
            Language::Korean,
            Language::Spanish,
            super::Bip39::language_from_name("??????"),
            super::Bip39::language_from_name("??????"),
        ] {
            assert_eq!(
                super::Bip39::name_from_language(*l),
                super::Bip39::name_from_language(super::Bip39::language_from_name(
                    super::Bip39::name_from_language(*l)
                ))
            );
        }
    }
}
