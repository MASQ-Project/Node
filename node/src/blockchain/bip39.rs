// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::PlainData;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ethsign::keyfile::Crypto;
use ethsign::Protected;
use rustc_hex::{FromHex, ToHex};
use std::num::NonZeroU32;

#[derive(Debug, PartialEq)]
pub enum Bip39Error {
    ConversionError(String),
    EncryptionFailure(String),
    DecryptionFailure(String),
    NotPresent,
    SerializationFailure(String),
    DeserializationFailure(String),
}

pub struct Bip39 {
    config: Box<dyn PersistentConfiguration>,
}

impl Bip39 {
    pub fn new(config: Box<dyn PersistentConfiguration>) -> Self {
        Self { config }
    }

    pub fn mnemonic(&self, mnemonic_type: MnemonicType, language: Language) -> Mnemonic {
        // create a new randomly generated mnemonic phrase
        Mnemonic::new(mnemonic_type, language)
    }

    pub fn seed(&self, mnemonic: &Mnemonic, passphrase: &str) -> Seed {
        // get the HD wallet seed
        Seed::new(mnemonic, passphrase)
    }

    pub fn read(&self, password: Vec<u8>) -> Result<PlainData, Bip39Error> {
        match self.config.mnemonic_seed() {
            Some(serialized_cipher_seed) => match serialized_cipher_seed.from_hex::<Vec<u8>>() {
                Ok(cipher_seed_slice) => {
                    match serde_cbor::from_slice::<Crypto>(&cipher_seed_slice) {
                        Ok(crypto) => match crypto.decrypt(&Protected::new(password)) {
                            Ok(mnemonic_seed) => Ok(PlainData::new(&mnemonic_seed)),
                            Err(e) => Err(Bip39Error::DecryptionFailure(format!("{:?}", e))),
                        },
                        Err(e) => Err(Bip39Error::DeserializationFailure(format!("{:?}", e))),
                    }
                }
                Err(e) => Err(Bip39Error::ConversionError(format!("{:?}", e))),
            },
            None => Err(Bip39Error::NotPresent),
        }
    }

    pub fn store(&self, seed: &Seed, password: Vec<u8>) -> Result<(), Bip39Error> {
        match Crypto::encrypt(
            seed.as_bytes(),
            &Protected::new(password),
            NonZeroU32::new(10240).expect("Internal error"),
        ) {
            Ok(crypto) => match serde_cbor::to_vec(&crypto) {
                Ok(cipher_seed) => {
                    self.config.set_mnemonic_seed(cipher_seed.to_hex());
                    Ok(())
                }
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

    pub fn language_from_name(name: &str) -> Language {
        match name.to_lowercase().as_str() {
            "english" => Language::English,
            "中文(简体)" => Language::ChineseSimplified,
            "简体" => Language::ChineseSimplified,
            "中文(繁體)" => Language::ChineseTraditional,
            "繁體" => Language::ChineseTraditional,
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
    use crate::config_dao::ConfigDaoError;
    use crate::config_dao::ConfigDaoReal;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::test_utils::config_dao_mock::ConfigDaoMock;
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use ethsign::keyfile::Crypto;
    use ethsign::Protected;
    use rustc_hex::{FromHexError, ToHex};
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_seed_store_and_read() {
        let home_dir = ensure_node_home_directory_exists("blockchain", "test-seed-store-and-read");
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap()),
        ))));
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let mnemonic_value = subject.mnemonic(MnemonicType::Words12, Language::English);
        let expected_seed = subject.seed(&mnemonic_value, "Test123!Test456!");

        assert!(subject
            .store(&expected_seed, password.as_bytes().to_vec())
            .is_ok());

        let actual_seed_plain_data: PlainData = subject.read(password.as_bytes().to_vec()).unwrap();
        assert_eq!(expected_seed.as_bytes(), actual_seed_plain_data.as_slice());
    }

    #[test]
    #[should_panic(
        expected = r#"Can't continue; mnemonic seed configuration is inaccessible: DatabaseError("one two three")"#
    )]
    fn storing_mnemonic_seed_panics_when_database_is_inaccessible() {
        let set_string_params_arc =
            Arc::new(Mutex::new(vec![("seed".to_string(), "".to_string())]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Err(ConfigDaoError::DatabaseError(
                "one two three".to_string(),
            )));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        subject
            .store(
                &subject.seed(
                    &subject.mnemonic(MnemonicType::Words12, Language::English),
                    &password,
                ),
                password.as_bytes().to_vec(),
            )
            .unwrap();
    }

    #[test]
    fn test_seed_read_before_store() {
        let home_dir =
            ensure_node_home_directory_exists("blockchain", "test-seed-read-before-store");
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(
                ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap()),
            ))),
        };
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        assert!(result.is_err());
        assert_eq!(Bip39Error::NotPresent, result.unwrap_err());
    }

    #[test]
    fn returns_error_for_missing_seed_value() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::DatabaseError(
                "could be the source of your troubles".to_string(),
            )));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
    }

    #[test]
    fn returns_conversion_error_for_invalid_hex_character_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));

        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("this is not hex".to_string()));
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
        };
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);

        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            Bip39Error::ConversionError(format!("{:?}", FromHexError::InvalidHexCharacter('t', 0))),
            e
        );
    }

    #[test]
    fn returns_deserialization_failure_for_empty_data_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("".to_string()));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            e,
            Bip39Error::DeserializationFailure(
                "ErrorImpl { code: EofWhileParsingValue, offset: 0 }".to_string()
            )
        );
    }

    #[test]
    fn returns_conversion_error_for_bad_seed_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("0x123".to_string()));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));

        let result = subject.read(vec![]);

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            e,
            Bip39Error::ConversionError("Invalid character 'x' at position 1".to_string())
        );
    }

    #[test]
    fn returns_conversion_error_for_odd_number_of_hex_digits_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("123".to_string()));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));

        let result = subject.read(vec![]);

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            e,
            Bip39Error::ConversionError("Invalid input length".to_string())
        );
    }

    #[test]
    fn returns_decryption_failure_for_invalid_password_appropriately() {
        let crypto = Crypto::encrypt(
            b"One small step for man, one giant leap for mankind!",
            &Protected::new(b"Test123!456!".to_vec()),
            NonZeroU32::new(10240).unwrap(),
        )
        .unwrap();
        let mnemonic_seed = serde_cbor::to_vec(&crypto).unwrap().to_hex::<String>();
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok(mnemonic_seed));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));

        let result = subject.read(b"Invalid password".to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            e,
            Bip39Error::DecryptionFailure("InvalidPassword".to_string())
        );
    }

    #[test]
    fn returns_conversion_error_for_invalid_length_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("123".to_string()));
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
        };
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            Bip39Error::ConversionError("Invalid input length".to_string()),
            e
        );
    }

    #[test]
    fn returns_not_present_appropriately() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));
        let result = subject.read(password.to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
    }

    #[test]
    fn returns_not_present_upon_database_error_appropriately() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::DatabaseError(
                "this here's your problem".to_string(),
            )));

        let subject = Bip39::new(Box::new(PersistentConfigurationReal::new(Box::new(
            config_dao,
        ))));
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.read(password.as_bytes().to_vec());

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
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
