// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::config_dao::ConfigDaoError;
use crate::config_dao::{ConfigDao, ConfigDaoReal};
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::wallet::Wallet;
use rusqlite::Transaction;
use rustc_hex::ToHex;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_RANDOM_CLANDESTINE_PORT: u16 = 9999;
pub const HIGHEST_USABLE_PORT: u16 = 65535;
pub const HTTP_PORT: u16 = 80;
pub const TLS_PORT: u16 = 443;

pub trait PersistentConfiguration: Send {
    fn current_schema_version(&self) -> String;
    fn clandestine_port(&self) -> u16;
    fn set_clandestine_port(&self, port: u16);
    fn gas_price(&self) -> u64;
    fn set_gas_price(&self, gas_price: u64);
    fn encrypted_mnemonic_seed(&self) -> Option<String>;
    fn mnemonic_seed(&self, wallet_password: &str) -> Result<PlainData, Bip39Error>;
    fn set_mnemonic_seed(&self, seed: &dyn AsRef<[u8]>, wallet_password: &str);
    fn consuming_wallet_public_key(&self) -> Option<String>;
    fn consuming_wallet_derivation_path(&self) -> Option<String>;
    fn set_consuming_wallet_derivation_path(&self, derivation_path: &str, wallet_password: &str);
    fn set_consuming_wallet_public_key(&self, public_key: &PlainData);
    fn earning_wallet_from_address(&self) -> Option<Wallet>;
    fn earning_wallet_address(&self) -> Option<String>;
    fn set_earning_wallet_address(&self, address: &str);
    fn start_block(&self) -> u64;
    fn set_start_block_transactionally(&self, tx: &Transaction, value: u64) -> Result<(), String>;
}

pub struct PersistentConfigurationReal {
    dao: Box<dyn ConfigDao>,
}

impl PersistentConfiguration for PersistentConfigurationReal {
    fn current_schema_version(&self) -> String {
        match self.dao.get_string("schema_version") {
            Ok(s) => s,
            Err(e) => panic!(
                "Can't continue; current schema version is inaccessible: {:?}",
                e
            ),
        }
    }

    fn clandestine_port(&self) -> u16 {
        let unchecked_port = match self.dao.get_u64("clandestine_port") {
            Ok(n) => n,
            Err(e) => panic!(
                "Can't continue; clandestine port configuration is inaccessible: {:?}",
                e
            ),
        };
        if (unchecked_port < u64::from(LOWEST_USABLE_INSECURE_PORT))
            || (unchecked_port > u64::from(HIGHEST_USABLE_PORT))
        {
            panic!("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine-port <p> where <p> is an unused port.",
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
                unchecked_port
            );
        }
        let port = unchecked_port as u16;
        match TcpListener::bind (SocketAddrV4::new (Ipv4Addr::from (0), port)) {
            Ok (_) => port,
            Err (_) => panic!("Can't continue; clandestine port {} is in use. Specify --clandestine-port <p> where <p> is an unused port between {} and {}.",
                port,
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
            )
        }
    }

    fn set_clandestine_port(&self, port: u16) {
        if port < LOWEST_USABLE_INSECURE_PORT {
            panic!("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine-port <p> where <p> is an unused port.",
                    LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, port);
        }
        match self.dao.set_u64("clandestine_port", u64::from(port)) {
            Ok(_) => (),
            Err(e) => panic!(
                "Can't continue; clandestine port configuration is inaccessible: {:?}",
                e
            ),
        }
    }

    fn gas_price(&self) -> u64 {
        self.dao.get_u64("gas_price").unwrap_or_else(|e| {
            panic!(
                "Can't continue; gas price configuration is inaccessible: {:?}",
                e
            )
        })
    }

    fn set_gas_price(&self, gas_price: u64) {
        self.dao
            .set_u64("gas_price", gas_price)
            .unwrap_or_else(|e| {
                panic!(
                    "Can't continue; gas price configuration is inaccessible: {:?}",
                    e
                )
            });
    }

    fn encrypted_mnemonic_seed(&self) -> Option<String> {
        match self.dao.get_string("seed") {
            Ok(ems) => Some(ems),
            Err(ConfigDaoError::NotPresent) => None,
            Err(e) => panic!("Database corruption error seeking mnemonic seed: {:?}", e),
        }
    }

    fn mnemonic_seed(&self, wallet_password: &str) -> Result<PlainData, Bip39Error> {
        match self.encrypted_mnemonic_seed() {
            None => Err(Bip39Error::NotPresent),
            Some(ems) => Ok(Bip39::decrypt_bytes(&ems, wallet_password)?),
        }
    }

    fn set_mnemonic_seed(&self, seed: &dyn AsRef<[u8]>, wallet_password: &str) {
        let encrypted_mnemonic_seed = Bip39::encrypt_bytes(seed, wallet_password)
            .expect("Can't continue; encryption of mnemonic seed failed");
        match self.dao.set_string("seed", &encrypted_mnemonic_seed) {
            Ok(_) => (),
            Err(e) => panic!(
                "Can't continue; mnemonic seed configuration is inaccessible: {:?}",
                e
            ),
        }
    }

    fn consuming_wallet_public_key(&self) -> Option<String> {
        match (
            self.dao.get_string("consuming_wallet_public_key"),
            self.dao.get_string("consuming_wallet_derivation_path"),
        ) {
            (Err(ConfigDaoError::NotPresent), Err(ConfigDaoError::NotPresent)) => None,
            (Ok(key_enc), Err(ConfigDaoError::NotPresent)) => Some(key_enc),
            (Err(ConfigDaoError::NotPresent), Ok(_)) => None,
            (key_err, path_err) => Self::handle_config_pair_result(
                key_err,
                path_err,
                "consuming wallet public key",
                "consuming wallet derivation path",
            ),
        }
    }

    fn consuming_wallet_derivation_path(&self) -> Option<String> {
        match (
            self.dao.get_string("consuming_wallet_public_key"),
            self.dao.get_string("consuming_wallet_derivation_path"),
        ) {
            (Err(ConfigDaoError::NotPresent), Err(ConfigDaoError::NotPresent)) => None,
            (Ok(_), Err(ConfigDaoError::NotPresent)) => None,
            (Err(ConfigDaoError::NotPresent), Ok(path)) => Some(path),
            (key_err, path_err) => Self::handle_config_pair_result(
                key_err,
                path_err,
                "consuming wallet public key",
                "consuming wallet derivation path",
            ),
        }
    }

    fn set_consuming_wallet_derivation_path(&self, derivation_path: &str, wallet_password: &str) {
        match (
            self.dao.get_string("consuming_wallet_public_key"),
            self.dao.get_string("consuming_wallet_derivation_path"),
        ) {
            (Err(ConfigDaoError::NotPresent), Err(ConfigDaoError::NotPresent)) => self
                .dao
                .set_string("consuming_wallet_derivation_path", derivation_path)
                .expect("Database is corrupt"),
            (Ok(private_public_key), Err(ConfigDaoError::NotPresent)) => {
                let seed = match self.mnemonic_seed(wallet_password) {
                    Ok(seed) => seed,
                    Err(Bip39Error::NotPresent) => {
                        panic!("Can't set consuming wallet derivation path without a mnemonic seed")
                    }
                    Err(e) => panic!("Can't read mnemonic seed: {:?}", e),
                };
                let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), derivation_path)
                    .unwrap_or_else(|_| {
                        panic!("Bad consuming derivation path: {}", derivation_path)
                    });
                let existing_public_key = keypair.secret().public().bytes().to_hex::<String>();
                if private_public_key == existing_public_key {
                    return;
                }
                panic!(
                    "Cannot set consuming wallet derivation path: consuming private key is already set"
                )
            }
            (Err(ConfigDaoError::NotPresent), Ok(existing_path)) => {
                if derivation_path == existing_path {
                } else {
                    panic!(
                        "Cannot set consuming wallet derivation path: already set to {}",
                        existing_path
                    )
                }
            }
            (key_err, path_err) => Self::handle_config_pair_result(
                key_err,
                path_err,
                "consuming wallet public key",
                "consuming wallet derivation path",
            ),
        }
    }

    fn set_consuming_wallet_public_key(&self, public_key: &PlainData) {
        let public_key_text: String = public_key.as_slice().to_hex();
        match (self.dao.get_string("consuming_wallet_public_key"), self.dao.get_string ("consuming_wallet_derivation_path")) {
            (Err(ConfigDaoError::NotPresent), Err(ConfigDaoError::NotPresent)) => self.dao.set_string("consuming_wallet_public_key", &public_key_text).expect ("Database is corrupt"),
            (Ok(existing_public_key_text), Err(ConfigDaoError::NotPresent)) =>  {
                if public_key_text != existing_public_key_text {
                    panic!("Cannot set consuming wallet public key: already set")
                }
            },
            (Err(ConfigDaoError::NotPresent), Ok(path)) => panic!("Cannot set consuming wallet public key: consuming derivation path is already set to {}", path),
            (key_err, path_err) => Self::handle_config_pair_result(key_err, path_err, "consuming wallet public key", "consuming wallet derivation path")
        }
    }

    fn earning_wallet_from_address(&self) -> Option<Wallet> {
        match self.dao.get_string("earning_wallet_address") {
            Ok(address) => Some(Wallet::from_str(&address).unwrap_or_else(|_| {
                panic!(
                    "Database corrupt: invalid earning wallet address: '{}'",
                    address
                )
            })),
            Err(ConfigDaoError::NotPresent) => None,
            Err(e) => panic!("Error trying to retrieve earning wallet address: {:?}", e),
        }
    }

    fn earning_wallet_address(&self) -> Option<String> {
        match self.dao.get_string("earning_wallet_address") {
            Ok(address) => Some(address),
            Err(ConfigDaoError::NotPresent) => None,
            Err(e) => panic!("Error trying to retrieve earning wallet address: {:?}", e),
        }
    }

    fn set_earning_wallet_address(&self, address: &str) {
        match Wallet::from_str(address) {
            Ok(_) => (),
            Err(_) => panic!("Invalid earning wallet address '{}'", address),
        }
        if let Ok(existing_address) = self.dao.get_string("earning_wallet_address") {
            if address.to_lowercase() != existing_address.to_lowercase() {
                panic!(
                    "Can't overwrite existing earning wallet address '{}'",
                    existing_address
                )
            } else {
                return;
            }
        }
        match self.dao.set_string("earning_wallet_address", address) {
            Ok(_) => (),
            Err(e) => panic!("Error setting earning wallet address: {:?}", e),
        }
    }

    fn start_block(&self) -> u64 {
        self.dao.get_u64("start_block").unwrap_or_else(|e| {
            panic!(
                "Can't continue; start_block configuration is inaccessible: {:?}",
                e
            )
        })
    }

    fn set_start_block_transactionally(&self, tx: &Transaction, value: u64) -> Result<(), String> {
        self.dao
            .set_u64_transactional(tx, "start_block", value)
            .map_err(|e| match e {
                ConfigDaoError::DatabaseError(_) => format!("{:?}", e),
                ConfigDaoError::NotPresent => {
                    panic!("Unable to update start_block, maybe missing from the database")
                }
                ConfigDaoError::TypeError => panic!("Unknown error: TypeError"),
            })
    }
}

impl From<Box<dyn ConnectionWrapper>> for PersistentConfigurationReal {
    fn from(conn: Box<dyn ConnectionWrapper>) -> Self {
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::from(conn));
        Self::from(config_dao)
    }
}

impl From<Box<dyn ConfigDao>> for PersistentConfigurationReal {
    fn from(config_dao: Box<dyn ConfigDao>) -> Self {
        Self::new(config_dao)
    }
}

impl PersistentConfigurationReal {
    pub fn new(config_dao: Box<dyn ConfigDao>) -> PersistentConfigurationReal {
        PersistentConfigurationReal { dao: config_dao }
    }

    fn handle_config_pair_result(
        one: Result<String, ConfigDaoError>,
        another: Result<String, ConfigDaoError>,
        one_msg: &str,
        another_msg: &str,
    ) -> ! {
        match (one, another) {
            (Ok(_), Ok(_)) => panic!(
                "Database is corrupt: both {} and {} are set",
                one_msg, another_msg
            ),
            (Err(one_err), Err(another_err)) => panic!(
                "Database is corrupt: error retrieving both {} ({:?}) and {} ({:?})",
                one_msg, one_err, another_msg, another_err
            ),
            (Err(one_err), _) => panic!(
                "Database is corrupt: error retrieving {}: {:?}",
                one_msg, one_err
            ),
            (_, Err(another_err)) => panic!(
                "Database is corrupt: error retrieving {}: {:?}",
                another_msg, another_err
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::test_utils::make_meaningless_seed;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::config_dao_mock::ConfigDaoMock;
    use crate::test_utils::{ensure_node_home_directory_exists, find_free_port, DEFAULT_CHAIN_ID};
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use ethsign::keyfile::Crypto;
    use ethsign::Protected;
    use rustc_hex::FromHex;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
    use std::num::NonZeroU32;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    #[test]
    #[should_panic(expected = "Can't continue; current schema version is inaccessible: NotPresent")]
    fn current_schema_version_panics_if_unsuccessful() {
        let config_dao = ConfigDaoMock::new().get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.current_schema_version();
    }

    #[test]
    fn current_schema_version() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("1.2.3".to_string()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.current_schema_version();

        assert_eq!("1.2.3".to_string(), result);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!("schema_version".to_string(), get_string_params[0]);
        assert_eq!(1, get_string_params.len());
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is inaccessible: NotPresent"
    )]
    fn clandestine_port_panics_if_dao_error() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 65536. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_high() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(65536));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(1024));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port();
    }

    #[test]
    #[should_panic(
        expected = " is in use. Specify --clandestine-port <p> where <p> is an unused port between 1025 and 65535."
    )]
    fn clandestine_port_panics_if_configured_port_is_in_use() {
        let port = find_free_port();
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(port as u64));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let _listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port))).unwrap();

        subject.clandestine_port();
    }

    #[test]
    fn clandestine_port_success() {
        let get_u64_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_u64_params(&get_u64_params_arc)
            .get_u64_result(Ok(4747));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.clandestine_port();

        assert_eq!(4747, result);
        let get_u64_params = get_u64_params_arc.lock().unwrap();
        assert_eq!("clandestine_port".to_string(), get_u64_params[0]);
        assert_eq!(1, get_u64_params.len());
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is inaccessible: NotPresent"
    )]
    fn set_clandestine_port_panics_if_dao_error() {
        let config_dao = ConfigDaoMock::new().set_u64_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_clandestine_port(1234);
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn set_clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new().set_u64_result(Ok(()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_clandestine_port(1024);
    }

    #[test]
    fn set_clandestine_port_success() {
        let set_u64_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .set_u64_params(&set_u64_params_arc)
            .set_u64_result(Ok(()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_clandestine_port(4747);

        let set_u64_params = set_u64_params_arc.lock().unwrap();
        assert_eq!(("clandestine_port".to_string(), 4747), set_u64_params[0]);
        assert_eq!(1, set_u64_params.len());
    }

    #[test]
    fn mnemonic_seed_success() {
        let seed = PlainData::new(b"example seed");
        let encrypted_seed = Bip39::encrypt_bytes(&seed, "booga").unwrap();
        let config_dao = ConfigDaoMock::new().get_string_result(Ok(encrypted_seed));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let possible_seed = subject.mnemonic_seed("booga");

        assert_eq!(possible_seed, Ok(seed));
    }

    #[test]
    fn mnemonic_seed_none_when_not_present() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Err(ConfigDaoError::NotPresent))
            .get_string_params(&get_string_params_arc);
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.mnemonic_seed("booga");

        assert_eq!(result, Err(Bip39Error::NotPresent));
    }

    #[test]
    fn returns_deserialization_failure_for_empty_data_appropriately() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().get_string_result(Ok("".to_string())));
        let subject = PersistentConfigurationReal::from(config_dao);
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = subject.mnemonic_seed(password);

        assert_eq!(
            result,
            Err(Bip39Error::DeserializationFailure(
                "EOF while parsing a value".to_string()
            ))
        );
    }

    #[test]
    fn returns_conversion_error_for_bad_seed_appropriately() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().get_string_result(Ok("0x123".to_string())));
        let subject = PersistentConfigurationReal::from(config_dao);

        let result = subject.mnemonic_seed("");

        assert_eq!(
            result,
            Err(Bip39Error::ConversionError(
                "Invalid character 'x' at position 1".to_string()
            ))
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
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Ok(mnemonic_seed)),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        let result = subject.mnemonic_seed("Invalid password");

        assert_eq!(
            result,
            Err(Bip39Error::DecryptionFailure("InvalidPassword".to_string()))
        );
    }

    #[test]
    fn returns_conversion_error_for_invalid_length_appropriately() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().get_string_result(Ok("123".to_string())));
        let persistent_config = PersistentConfigurationReal::from(config_dao);
        let password = "You-Sh0uld-Ch4nge-Me-Now!!";

        let result = persistent_config.mnemonic_seed(password);

        assert_eq!(
            result,
            Err(Bip39Error::ConversionError(
                "Invalid input length".to_string()
            ))
        );
    }

    #[test]
    #[should_panic(
        expected = r#"Can't continue; mnemonic seed configuration is inaccessible: DatabaseError("Here\'s your problem")"#
    )]
    fn set_mnemonic_seed_panics_if_dao_error() {
        let config_dao = ConfigDaoMock::new().set_string_result(Err(
            ConfigDaoError::DatabaseError("Here's your problem".to_string()),
        ));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        subject.set_mnemonic_seed(&make_meaningless_seed(), "password");
    }

    #[test]
    fn set_mnemonic_seed_succeeds() {
        let seed = make_meaningless_seed();
        let wallet_password = "seed password";
        let encrypted_seed = Bip39::encrypt_bytes(&seed, wallet_password).unwrap();
        let expected_params = ("seed".to_string(), encrypted_seed);
        let set_string_params_arc = Arc::new(Mutex::new(vec![expected_params.clone()]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Ok(()));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        subject.set_mnemonic_seed(&seed, wallet_password);

        let set_string_params = set_string_params_arc.lock().unwrap();

        assert_eq!(set_string_params[0], expected_params);
    }

    #[test]
    fn start_block_success() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(6u64));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let start_block = subject.start_block();

        assert_eq!(6u64, start_block);
    }

    #[test]
    #[should_panic(
        expected = r#"Can't continue; start_block configuration is inaccessible: DatabaseError("Here\'s your problem")"#
    )]
    fn start_block_panics_when_not_set() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Err(ConfigDaoError::DatabaseError(
            "Here's your problem".to_string(),
        )));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.start_block();
    }

    #[test]
    fn set_start_block_transactionally_success() {
        let config_dao = ConfigDaoMock::new().set_u64_transactional_result(Ok(()));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_success",
        );
        let mut conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let result = subject.set_start_block_transactionally(&transaction, 1234);

        assert!(result.is_ok());
    }

    #[test]
    fn gas_price() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(3u64));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        assert_eq!(3u64, subject.gas_price());
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; gas price configuration is inaccessible: NotPresent"
    )]
    fn gas_price_fails() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.gas_price();
    }

    #[test]
    fn set_gas_price_succeeds() {
        let expected_params = ("gas_price".to_string(), 11u64);
        let set_params_arc = Arc::new(Mutex::new(vec![expected_params.clone()]));
        let config_dao = ConfigDaoMock::new()
            .set_u64_params(&set_params_arc)
            .set_u64_result(Ok(()));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        subject.set_gas_price(11u64);

        let set_params = set_params_arc.lock().unwrap();

        assert_eq!(set_params[0], expected_params);
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; gas price configuration is inaccessible: NotPresent"
    )]
    fn set_gas_price_fails() {
        let config_dao = ConfigDaoMock::new().set_u64_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_gas_price(3);
    }

    #[test]
    fn set_start_block_transactionally_returns_err_when_transaction_fails() {
        let config_dao = ConfigDaoMock::new()
            .set_u64_transactional_result(Err(ConfigDaoError::DatabaseError("nah".to_string())));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_returns_err_when_transaction_fails",
        );
        let mut conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        let transaction = conn.transaction().unwrap();
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.set_start_block_transactionally(&transaction, 1234);

        assert_eq!(Err(r#"DatabaseError("nah")"#.to_string()), result);
    }

    #[test]
    fn consuming_wallet_public_key_works_if_key_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("encrypted private key".to_string()))
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_public_key();

        assert_eq!(result, Some("encrypted private key".to_string()));
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn consuming_wallet_public_key_works_if_neither_key_nor_path_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent))
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_public_key();

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn consuming_wallet_public_key_works_if_path_but_not_key_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent))
            .get_string_result(Ok("derivation path".to_string()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_public_key();

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    )]
    fn consuming_wallet_public_key_complains_if_both_key_and_path_are_set() {
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Ok("public key".to_string()))
            .get_string_result(Ok("derivation path".to_string()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.consuming_wallet_public_key();
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_path_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent))
            .get_string_result(Ok("derivation path".to_string()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_derivation_path();

        assert_eq!(result, Some("derivation path".to_string()));
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_neither_key_nor_path_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent))
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_derivation_path();

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_key_but_not_path_is_set() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok("private key".to_string()))
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_derivation_path();

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    )]
    fn consuming_wallet_derivation_path_complains_if_both_key_and_path_are_set() {
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Ok("private key".to_string()))
            .get_string_result(Ok("derivation path".to_string()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.consuming_wallet_derivation_path();
    }

    #[test]
    fn set_consuming_wallet_derivation_path_works_if_no_preexisting_info() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path("derivation path", "password");

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(
            *set_string_params,
            vec![(
                "consuming_wallet_derivation_path".to_string(),
                "derivation path".to_string()
            )]
        );
    }

    #[test]
    fn set_consuming_wallet_derivation_path_works_if_path_is_already_set_to_same() {
        let consuming_path = "m/44'/60'/1'/2/3";
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Ok(consuming_path.to_string()))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path(consuming_path, "password");

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(set_string_params.len(), 0)
    }

    #[test]
    fn set_consuming_wallet_derivation_path_works_if_key_is_already_set_to_same() {
        let consuming_path = "m/44'/60'/1'/2/3";
        let password = "password";
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let seed = Seed::new(&mnemonic, "passphrase");
        let encrypted_seed = Bip39::encrypt_bytes(&seed, password).unwrap();
        let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), consuming_path).unwrap();
        let private_public_key = keypair.secret().public().bytes().to_hex::<String>();
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Ok(private_public_key))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Ok(encrypted_seed))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path(consuming_path, password);

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "consuming_wallet_derivation_path".to_string(),
                "seed".to_string(),
            ]
        );
        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(set_string_params.len(), 0)
    }

    #[test]
    #[should_panic(
        expected = "Cannot set consuming wallet derivation path: consuming private key is already set"
    )]
    fn set_consuming_wallet_derivation_path_complains_if_key_is_already_set() {
        let consuming_path = "m/44'/60'/1'/2/3";
        let password = "password";
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let seed = Seed::new(&mnemonic, "passphrase");
        let encrypted_seed = Bip39::encrypt_bytes(&seed, password).unwrap();
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("consuming private key".to_string()))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Ok(encrypted_seed.to_string())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path(consuming_path, password);
    }

    #[test]
    #[should_panic(
        expected = "Cannot set consuming wallet derivation path: already set to existing derivation path"
    )]
    fn set_consuming_wallet_derivation_path_complains_if_path_is_already_set() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Ok("existing derivation path".to_string())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path("derivation path", "password");
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    )]
    fn set_consuming_wallet_derivation_path_complains_if_both_are_already_set() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("existing private key".to_string()))
                .get_string_result(Ok("existing derivation path".to_string())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_derivation_path("derivation path", "password");
    }

    #[test]
    fn set_consuming_wallet_public_key_works_if_no_preexisting_info() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);
        let public_key = PlainData::new(b"public key");

        subject.set_consuming_wallet_public_key(&public_key);

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let set_string_params = set_string_params_arc.lock().unwrap();
        let (name, public_key_text) = &set_string_params[0];
        assert_eq!(name, "consuming_wallet_public_key");
        let public_key_bytes: Vec<u8> = public_key_text.from_hex().unwrap();
        assert_eq!(public_key_bytes, b"public key".to_vec());
    }

    #[test]
    #[should_panic(expected = "Cannot set consuming wallet public key: already set")]
    fn set_consuming_wallet_public_key_complains_if_key_is_already_set_to_different_value() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("consuming public key".to_string()))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    }

    #[test]
    fn set_consuming_wallet_public_key_does_not_complain_if_key_is_already_set_to_same_value() {
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let private_public_key_text = b"public key".to_hex::<String>();
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok(private_public_key_text.clone()))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));

        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(*set_string_params, vec![]); // no changes
    }

    #[test]
    #[should_panic(
        expected = "Cannot set consuming wallet public key: consuming derivation path is already set to existing derivation path"
    )]
    fn set_consuming_wallet_public_key_complains_if_path_is_already_set() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Ok("existing derivation path".to_string())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    )]
    fn set_consuming_wallet_public_key_complains_if_both_are_already_set() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("existing private key".to_string()))
                .get_string_result(Ok("existing derivation path".to_string())),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    }

    #[test]
    fn earning_wallet_from_address_handles_no_address() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Err(ConfigDaoError::NotPresent)),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.earning_wallet_from_address();

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec!["earning_wallet_address".to_string()]
        )
    }

    #[test]
    fn earning_wallet_from_address_handles_existing_address() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Ok("0x0123456789ABCDEF0123456789ABCDEF01234567".to_string())),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.earning_wallet_from_address();

        assert_eq!(
            result,
            Some(Wallet::from_str("0x0123456789ABCDEF0123456789ABCDEF01234567").unwrap())
        );
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec!["earning_wallet_address".to_string()]
        )
    }

    #[test]
    fn set_earning_wallet_address_happy_path() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        subject.set_earning_wallet_address("0xcafedeadbeefbabefacecafedeadbeefbabeface");

        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(
            *get_string_params,
            vec!["earning_wallet_address".to_string(),]
        );
        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(
            *set_string_params,
            vec![(
                "earning_wallet_address".to_string(),
                "0xcafedeadbeefbabefacecafedeadbeefbabeface".to_string()
            )]
        );
    }

    #[test]
    #[should_panic(expected = "Invalid earning wallet address 'booga'")]
    fn set_earning_wallet_address_bad_address() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().set_string_result(Ok(())));
        let subject = PersistentConfigurationReal::new(config_dao);

        subject.set_earning_wallet_address("booga");
    }

    #[test]
    #[should_panic(expected = "Can't overwrite existing earning wallet address 'booga'")]
    fn set_earning_wallet_address_existing_unequal_address() {
        let config_dao: Box<dyn ConfigDao> =
            Box::new(ConfigDaoMock::new().get_string_result(Ok("booga".to_string())));
        let subject = PersistentConfigurationReal::new(config_dao);

        subject.set_earning_wallet_address("0xcafedeadbeefbabefacecafedeadbeefbabeface");
    }

    #[test]
    fn set_earning_wallet_address_existing_equal_address() {
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("0xcafedeadbeefbabefacecafedeadbeefBABEFACE".to_string()))
                .set_string_params(&set_string_params_arc)
                .set_string_result(Ok(())),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        subject.set_earning_wallet_address("0xcafeDEADBEEFbabefacecafedeadbeefbabeface");

        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(set_string_params.len(), 0);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: error retrieving one: TypeError")]
    fn handle_config_pair_result_handles_first_error() {
        PersistentConfigurationReal::handle_config_pair_result(
            Err(ConfigDaoError::TypeError),
            Ok("blah".to_string()),
            "one",
            "another",
        );
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: error retrieving another: TypeError")]
    fn handle_config_pair_result_handles_second_error() {
        PersistentConfigurationReal::handle_config_pair_result(
            Ok("blah".to_string()),
            Err(ConfigDaoError::TypeError),
            "one",
            "another",
        );
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: error retrieving both one (TypeError) and another (TypeError)"
    )]
    fn handle_config_pair_result_handles_both_errors() {
        PersistentConfigurationReal::handle_config_pair_result(
            Err(ConfigDaoError::TypeError),
            Err(ConfigDaoError::TypeError),
            "one",
            "another",
        );
    }

    #[test]
    #[should_panic(expected = "Unable to update start_block, maybe missing from the database")]
    fn set_start_block_transactionally_panics_for_not_present_error() {
        let config_dao =
            ConfigDaoMock::new().set_u64_transactional_result(Err(ConfigDaoError::NotPresent));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_panics_for_not_present_error",
        );
        let mut conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_start_block_transactionally(&transaction, 1234)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "Unknown error: TypeError")]
    fn set_start_block_transactionally_panics_for_type_error() {
        let config_dao =
            ConfigDaoMock::new().set_u64_transactional_result(Err(ConfigDaoError::TypeError));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_panics_for_type_error",
        );
        let mut conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID)
            .unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_start_block_transactionally(&transaction, 1234)
            .unwrap();
    }
}
