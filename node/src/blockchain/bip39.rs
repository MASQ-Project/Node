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

    pub fn encrypt_bytes(
        seed: &dyn AsRef<[u8]>,
        wallet_password: &str,
    ) -> Result<String, Bip39Error> {
        match Crypto::encrypt(
            seed.as_ref(),
            &Protected::new(wallet_password.as_bytes()),
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

    pub fn decrypt_bytes(
        crypt_string: &str,
        wallet_password: &str,
    ) -> Result<PlainData, Bip39Error> {
        match crypt_string.from_hex::<Vec<u8>>() {
            Ok(cipher_seed_slice) => match serde_cbor::from_slice::<Crypto>(&cipher_seed_slice) {
                Ok(crypto) => match crypto.decrypt(&Protected::new(wallet_password)) {
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
            "中文(简体)" | "简体" => Language::ChineseSimplified,
            "中文(繁體)" | "繁體" => Language::ChineseTraditional,
            "français" => Language::French,
            "italiano" => Language::Italian,
            "日本語" => Language::Japanese,
            "한국어" => Language::Korean,
            "español" => Language::Spanish,
            _ => panic!("Unsupported language: {}", name),
        }
    }

    pub fn name_from_language(language: Language) -> &'static str {
        match language {
            Language::English => "English",
            Language::ChineseSimplified => "中文(简体)",
            Language::ChineseTraditional => "中文(繁體)",
            Language::French => "Français",
            Language::Italian => "Italiano",
            Language::Japanese => "日本語",
            Language::Korean => "한국어",
            Language::Spanish => "Español",
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
    use crate::config_dao::ConfigDaoReal;
    use crate::config_dao::{ConfigDao, ConfigDaoError};
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
    use crate::test_utils::config_dao_mock::ConfigDaoMock;
    use crate::test_utils::{ensure_node_home_directory_exists, DEFAULT_CHAIN_ID};
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_seed_store_and_read() {
        let home_dir = ensure_node_home_directory_exists("blockchain", "test-seed-store-and-read");
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        ));
        let persistent_config = PersistentConfigurationReal::from(config_dao);
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let mnemonic_value = Bip39::mnemonic(MnemonicType::Words12, Language::English);
        let expected_seed = Bip39::seed(&mnemonic_value, "Test123!Test456!");

        persistent_config.set_mnemonic_seed(&expected_seed, password);

        let actual_seed_plain_data: PlainData = persistent_config.mnemonic_seed(password).unwrap();
        assert_eq!(expected_seed.as_bytes(), actual_seed_plain_data.as_slice());
    }

    #[test]
    #[should_panic(
        expected = r#"Can't continue; mnemonic seed configuration is inaccessible: DatabaseError("one two three")"#
    )]
    fn storing_mnemonic_seed_panics_when_database_is_inaccessible() {
        let set_string_params_arc =
            Arc::new(Mutex::new(vec![("seed".to_string(), "".to_string())]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .set_string_params(&set_string_params_arc)
                .set_string_result(Err(ConfigDaoError::DatabaseError(
                    "one two three".to_string(),
                ))),
        );
        let persistent_config = PersistentConfigurationReal::from(config_dao);
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        persistent_config.set_mnemonic_seed(
            &Bip39::seed(
                &Bip39::mnemonic(MnemonicType::Words12, Language::English),
                password,
            ),
            password,
        );
    }

    #[test]
    fn returns_conversion_error_for_odd_number_of_hex_digits_appropriately() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().get_string_result(Ok("123".to_string())));
        let persistent_config = PersistentConfigurationReal::from(config_dao);

        let result = persistent_config.mnemonic_seed("");

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
            super::Bip39::language_from_name("简体"),
            super::Bip39::language_from_name("繁體"),
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
