// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![allow(dead_code)]

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rustc_hex::{FromHex, FromHexError, ToHex};

use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData};

#[derive(Debug, PartialEq)]
pub enum Bip39Error {
    ConversionError(String),
    EncryptionFailure(String),
    DecryptionFailure(String),
    NotPresent,
}

pub struct Bip39<'a> {
    config: Box<dyn PersistentConfiguration>,
    cryptde: &'a CryptDE,
}

impl<'a> Bip39<'a> {
    pub fn new(config: Box<dyn PersistentConfiguration>, cryptde: &'a CryptDE) -> Self {
        Self { config, cryptde }
    }

    pub fn mnemonic(&self, mnemonic_type: MnemonicType, language: Language) -> Mnemonic {
        // create a new randomly generated mnemonic phrase
        Mnemonic::new(mnemonic_type, language)
    }

    pub fn seed(&self, mnemonic: &Mnemonic, passphrase: &str) -> Seed {
        // get the HD wallet seed
        Seed::new(mnemonic, passphrase)
    }

    pub fn read(&self) -> Result<PlainData, Bip39Error> {
        match self.config.mnemonic_seed() {
            Some(seed_crypt_data) => {
                let result: Result<Vec<u8>, FromHexError> = seed_crypt_data.from_hex();
                match result {
                    Ok(hex) => match self.cryptde.decode(&CryptData::from(hex)) {
                        Ok(plain_data) => Ok(plain_data),
                        Err(e) => Err(Bip39Error::DecryptionFailure(format!("{:?}", e))),
                    },
                    Err(e) => Err(Bip39Error::ConversionError(format!("{}", e))),
                }
            }
            None => Err(Bip39Error::NotPresent),
        }
    }

    pub fn store(&self, seed: &Seed) -> Result<(), Bip39Error> {
        // accept the HD wallet seed

        let plain_data = PlainData::new(seed.as_bytes());
        match self.cryptde.encode(self.cryptde.public_key(), &plain_data) {
            Ok(crypt_data) => Ok(self.config.set_mnemonic_seed(crypt_data.to_hex())),
            Err(e) => Err(Bip39Error::EncryptionFailure(format!(
                "Failed to encrypt: {:?}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_dao::ConfigDaoError;
    use crate::config_dao::ConfigDaoReal;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::persistent_configuration::PersistentConfigurationReal;
    use crate::sub_lib::cryptde::{CryptdecError, PrivateKey, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::config_dao_mock::ConfigDaoMock;
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use std::sync::{Arc, Mutex};

    pub struct FailingCryptDEMock {
        private_key: PrivateKey,
        public_key: PublicKey,
        error: CryptdecError,
    }

    impl CryptDE for FailingCryptDEMock {
        fn generate_key_pair(&mut self) {
            unimplemented!()
        }

        fn encode(
            &self,
            _public_key: &PublicKey,
            _data: &PlainData,
        ) -> Result<CryptData, CryptdecError> {
            Err(self.error.clone())
        }

        fn decode(&self, _data: &CryptData) -> Result<PlainData, CryptdecError> {
            Err(self.error.clone())
        }

        fn random(&self, _dest: &mut [u8]) {
            unimplemented!()
        }

        fn private_key(&self) -> &PrivateKey {
            &self.private_key
        }

        fn public_key(&self) -> &PublicKey {
            &self.public_key
        }

        fn dup(&self) -> Box<CryptDE> {
            unimplemented!()
        }

        fn sign(&self, _data: &PlainData) -> Result<CryptData, CryptdecError> {
            unimplemented!()
        }

        fn verify_signature(
            &self,
            _data: &PlainData,
            _signature: &CryptData,
            _public_key: &PublicKey,
        ) -> bool {
            unimplemented!()
        }

        fn hash(&self, _data: &PlainData) -> CryptData {
            unimplemented!()
        }
    }

    #[test]
    fn test_seed_store_and_read() {
        let home_dir = ensure_node_home_directory_exists("blockchain", "test-seed-store-and-read");
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(
                ConfigDaoReal::new(
                    dbg!(DbInitializerReal::new().initialize(&dbg!(home_dir))).unwrap(),
                ),
            ))),
            cryptde,
        );
        let mnemonic_value = subject.mnemonic(MnemonicType::Words12, Language::English);

        let expected_seed = subject.seed(&mnemonic_value, "Test123!Test456!");

        assert!(subject.store(&expected_seed).is_ok());

        let actual_seed_plain_data: PlainData = subject.read().unwrap();
        assert_eq!(expected_seed.as_bytes(), actual_seed_plain_data.as_slice());
    }

    #[test]
    fn encryption_failure_for_storing_empty_data() {
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";
        let cryptde: &CryptDE = &FailingCryptDEMock {
            private_key: PrivateKey::new(b""),
            public_key: PublicKey::new(b""),
            error: CryptdecError::EmptyData,
        };
        let config_dao = ConfigDaoMock::new();
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.store(&subject.seed(
            &subject.mnemonic(MnemonicType::Words12, Language::English),
            &password,
        ));

        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            Bip39Error::EncryptionFailure("Failed to encrypt: EmptyData".to_string()),
            e
        );
    }

    #[test]
    fn encryption_failure_for_storing_with_empty_key() {
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";
        let cryptde: &CryptDE = &FailingCryptDEMock {
            private_key: PrivateKey::new(b""),
            public_key: PublicKey::new(b""),
            error: CryptdecError::EmptyKey,
        };
        let config_dao = ConfigDaoMock::new();
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.store(&subject.seed(
            &subject.mnemonic(MnemonicType::Words12, Language::English),
            &password,
        ));

        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            Bip39Error::EncryptionFailure("Failed to encrypt: EmptyKey".to_string()),
            e
        );
    }

    #[test]
    fn encryption_failure_for_storing_with_invalid_key() {
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";
        let cryptde: &CryptDE = &FailingCryptDEMock {
            private_key: PrivateKey::new(b""),
            public_key: PublicKey::new(b"This Key is Invalid"),
            error: CryptdecError::InvalidKey("This Key is Invalid".to_string()),
        };
        let config_dao = ConfigDaoMock::new();
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.store(&subject.seed(
            &subject.mnemonic(MnemonicType::Words12, Language::English),
            &password,
        ));

        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(
            Bip39Error::EncryptionFailure(
                r#"Failed to encrypt: InvalidKey("This Key is Invalid")"#.to_string()
            ),
            e
        );
    }

    #[test]
    fn test_seed_read_before_store() {
        let home_dir =
            ensure_node_home_directory_exists("blockchain", "test-seed-read-before-store");
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(
                ConfigDaoReal::new(
                    dbg!(DbInitializerReal::new().initialize(&dbg!(home_dir))).unwrap(),
                ),
            ))),
            cryptde,
        };

        let result = subject.read();

        assert!(result.is_err());
        assert_eq!(Bip39Error::NotPresent, result.unwrap_err());
    }

    #[test]
    fn returns_error_for_missing_seed_value() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::DatabaseError(
                "could be the source of your troubles".to_string(),
            )));

        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.read();

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
    }

    #[test]
    fn returns_conversion_error_for_invalid_hex_character_appropriately() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);

        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));

        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("this is not hex".to_string()));
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        };
        let result = subject.read();

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
    fn returns_decryption_failure_for_empty_data_appropriately() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("".to_string()));
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.read();

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(e, Bip39Error::DecryptionFailure("EmptyData".to_string()));
    }

    #[test]
    fn returns_decryption_failure_for_empty_key_appropriately() {
        let cryptde: &CryptDE = &FailingCryptDEMock {
            private_key: PrivateKey::new(b""),
            public_key: PublicKey::new(b""),
            error: CryptdecError::EmptyKey,
        };
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("".to_string()));
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.read();

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(e, Bip39Error::DecryptionFailure("EmptyKey".to_string()));
    }

    #[test]
    fn returns_conversion_error_for_invalid_length_appropriately() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("123".to_string()));
        let subject = Bip39 {
            config: Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        };
        let result = subject.read();

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
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );
        let result = subject.read();

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
    }

    #[test]
    fn returns_not_present_upon_database_error_appropriately() {
        let password = b"You-Sh0uld-Ch4nge-Me-Now!!";
        let public_key = dbg!(PublicKey::from(CryptDENull::other_key_data(password)));
        let cryptde: &CryptDE = &CryptDENull::from(&public_key);
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::DatabaseError(
                "this here's your problem".to_string(),
            )));

        let subject = Bip39::new(
            Box::new(PersistentConfigurationReal::new(Box::new(config_dao))),
            cryptde,
        );

        let result = subject.read();

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("seed".to_string(), get_string_params[0]);
        assert!(result.is_err());
        let e = result.unwrap_err();
        assert_eq!(Bip39Error::NotPresent, e);
    }
}
