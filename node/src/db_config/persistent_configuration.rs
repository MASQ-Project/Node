// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::{Bip39};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use rustc_hex::ToHex;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;
use crate::database::connection_wrapper::{ConnectionWrapper};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoReal};
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError, SecureConfigLayerReal};
use crate::db_config::typed_config_layer::{decode_u64, TypedConfigLayerError, encode_u64, decode_bytes, encode_bytes};

#[derive(Clone, PartialEq, Debug)]
pub enum PersistentConfigError {
    NotPresent,
    PasswordError,
    TransactionError,
    DatabaseError(String),
    BadNumberFormat (String),
    BadHexFormat (String),
}

impl From<TypedConfigLayerError> for PersistentConfigError {
    fn from(input: TypedConfigLayerError) -> Self {
        unimplemented!()
    }
}

impl From<SecureConfigLayerError> for PersistentConfigError {
    fn from(input: SecureConfigLayerError) -> Self {
        match input {
            SecureConfigLayerError::NotPresent => PersistentConfigError::NotPresent,
            SecureConfigLayerError::PasswordError => PersistentConfigError::PasswordError,
            SecureConfigLayerError::TransactionError => PersistentConfigError::TransactionError,
            SecureConfigLayerError::DatabaseError(msg) => PersistentConfigError::DatabaseError(msg),
        }
    }
}

impl From<ConfigDaoError> for PersistentConfigError {
    fn from(input: ConfigDaoError) -> Self {
        PersistentConfigError::from (SecureConfigLayerError::from (input))
    }
}

pub trait PersistentConfiguration {
    fn current_schema_version(&self) -> Result<String, PersistentConfigError>;
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError>;
    fn change_password(&self, old_password_opt: Option<&str>, new_password: &str) -> Result<(), PersistentConfigError>;
    fn clandestine_port(&self) -> Result<Option<u16>, PersistentConfigError>;
    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError>;
    fn gas_price(&self) -> Result<Option<u64>, PersistentConfigError>;
    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError>;
    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError>;
    fn set_mnemonic_seed(
        &mut self,
        seed: &dyn AsRef<[u8]>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn consuming_wallet_public_key(&self) -> Result<Option<String>, PersistentConfigError>;
    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_consuming_wallet_derivation_path(&mut self, derivation_path: &str, db_password: &str) -> Result<(), PersistentConfigError>;
    fn set_consuming_wallet_public_key(&mut self, public_key: &PlainData) -> Result<(), PersistentConfigError>;
    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError>;
    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_earning_wallet_address(&mut self, address: &str) -> Result<(), PersistentConfigError>;
    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>;
    fn set_past_neighbors(
        &mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError>;
    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError>;
}

pub struct PersistentConfigurationReal<'a> {
    dao: Box<dyn ConfigDao<'a>>,
    scl: Box<dyn SecureConfigLayer>,
}

impl<'a> PersistentConfiguration for PersistentConfigurationReal<'a> {
    fn current_schema_version(&self) -> String {
        match self.dao.get_string("schema_version") {
            Ok(s) => s,
            Err(e) => panic!(
                "Can't continue; current schema version is inaccessible: {:?}",
                e
            ),
        }
    }

    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError> {
        Ok(self.scl.check_password (db_password_opt, &self.dao)?)
    }

    fn change_password (&mut self, old_password_opt: Option<&str>, new_password: &str) -> Result<(), PersistentConfigError> {
        Ok(self.scl.change_password (old_password_opt, new_password, &mut self.dao)?)
    }

    fn clandestine_port(&self) -> u16 {
        let unchecked_port = decode_u64(self.dao.get ("clandestine_port")?.value_opt)?;
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
            Err (e) => panic!("Can't continue; clandestine port {} is in use. ({:?}) Specify --clandestine-port <p> where <p> is an unused port between {} and {}.",
                port,
                e,
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
            )
        }
    }

    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError> {
        if port < LOWEST_USABLE_INSECURE_PORT {
            panic!("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine-port <p> where <p> is an unused port.",
                    LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, port);
        }
        let mut writer = self.dao.start_transaction()?;
        writer.set ("clandestine_port", encode_u64(Some (u64::from (port)))?)?;
        Ok(writer.commit()?)
    }

    fn gas_price(&self) -> Result<Option<u64>, PersistentConfigError> {
        Ok(decode_u64(self.dao.get ("gas_price")?.value_opt)?)
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set ("gas_price", encode_u64 (Some (gas_price))?)?;
        Ok(writer.commit()?)
    }

    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError> {
        Ok(decode_bytes (self.scl.decrypt (self.dao.get ("seed")?, Some (db_password), &self.dao)?)?)
    }

    fn set_mnemonic_seed(
        &mut self,
        seed: &dyn AsRef<[u8]>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        let encoded_seed = encode_bytes(Some (PlainData::from (seed)))?.expect ("Value disappeared");
        writer.set ("seed", self.scl.encrypt ("seed", Some (encoded_seed), Some (db_password), &self.dao)?)?;
        Ok(writer.commit()?)
    }

    fn consuming_wallet_public_key(&self) -> Result<Option<String>, PersistentConfigError> {
        let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        match (key_rec.value_opt, path_rec.value_opt) {
            (None, None) => Ok(None),
            (Some(key), None) => Ok(Some(key)),
            (None, Some(_)) => Ok(None),
            (Some (_), Some (_)) => panic!(
                "Database is corrupt: both consuming wallet public key and wallet are set",
            ),
        }
    }

    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError> {
        let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        match (key_rec.value_opt, path_rec.value_opt) {
            (None, None) => Ok(None),
            (Some(_), None) => Ok(None),
            (None, Some(path)) => Ok(Some(path)),
            (Some (_), Some (_)) => panic!(
                "Database is corrupt: both consuming wallet public key and wallet are set",
            ),
        }
    }

    fn set_consuming_wallet_derivation_path(&mut self, derivation_path: &str, db_password: &str) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        match (key_rec.value_opt, path_rec.value_opt) {
            (None, None) => Ok (writer
                .set("consuming_wallet_derivation_path", Some (derivation_path.to_string()))?),
            (Some (key), None) => {
                let seed = match self.mnemonic_seed(db_password)? {
                    Some(seed) => seed,
                    None => {
                        panic!("Can't set consuming wallet derivation path without a mnemonic seed")
                    }
                };
                let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), derivation_path)
                    .unwrap_or_else(|_| {
                        panic!("Bad consuming derivation path: {}", derivation_path)
                    });
                let existing_public_key = keypair.secret().public().bytes().to_hex::<String>();
                if key == existing_public_key {
                    return Ok(());
                }
                panic!(
                    "Cannot set consuming wallet derivation path: consuming private key is already set"
                )
            }
            (None, Some(existing_path)) => {
                if derivation_path != existing_path {
                    panic!(
                        "Cannot set consuming wallet derivation path: already set to {}",
                        existing_path
                    )
                }
            }
            (Some (_), Some (_)) => panic!(
                "Database is corrupt: both consuming wallet public key and wallet are set",
            ),
        }
    }

    fn set_consuming_wallet_public_key(&mut self, public_key: &PlainData) -> Result<(), PersistentConfigError> {
        let public_key_text: String = public_key.as_slice().to_hex();
        let mut writer = self.dao.start_transaction()?;
        let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        match (key_rec.value_opt, path_rec.value_opt) {
            (None, None) => Ok(writer.set("consuming_wallet_public_key", Some (public_key_text))?),
            (Some(existing_public_key_text), None) =>  {
                if public_key_text != existing_public_key_text {
                    panic!("Cannot set consuming wallet public key: already set")
                }
                else {
                    Ok(())
                }
            },
            (None, Some(path)) => panic!("Cannot set consuming wallet public key: consuming derivation path is already set to {}", path),
            (Some (_), Some (_)) => panic!(
                "Database is corrupt: both consuming wallet public key and wallet are set",
            ),
        }
    }

    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError> {
        match self.earning_wallet_address()? {
            None => Ok(None),
            Some(address) => match Wallet::from_str(&address) {
                Err(e) => panic!("Database corrupt: invalid earning wallet address '{}': {:?}", address, e),
                Ok(wallet) => Ok (Some(wallet)),
            }
        }
    }

    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError> {
        Ok(self.dao.get ("earning_wallet_address")?.value_opt)
    }

    fn set_earning_wallet_address(&mut self, address: &str) -> Result<(), PersistentConfigError> {
        match Wallet::from_str(address) {
            Ok(_) => (),
            Err(e) => panic!("Invalid earning wallet address '{}': {:?}", address, e),
        }
        if let Ok(existing_address) = self.dao.get("earning_wallet_address")? {
            if address.to_lowercase() != existing_address.to_lowercase() {
                panic!(
                    "Can't overwrite existing earning wallet address '{}'",
                    existing_address
                )
            } else {
                return Ok(());
            }
        }
        let mut writer = self.dao.start_transaction()?;
        writer.set ("earning_wallet_address", Some (address.to_string()))?;
        Ok(writer.commit()?)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        let bytes_opt = decode_bytes (self.scl.decrypt (self.dao.get ("past_neighbors")?, Some (db_password))?)?;
        match bytes_opt {
            None => Ok (None),
            Some (bytes) => Ok(Some(serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(&bytes.as_slice())
                .expect ("Can't continue; past neighbors configuration is corrupt and cannot be deserialized."))),
        }
    }

    fn set_past_neighbors(
        &mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        let plain_data_opt = node_descriptors_opt.map (|node_descriptors| {
            PlainData::new (&serde_cbor::ser::to_vec(&node_descriptors).expect ("Serialization failed"))
        });
        let mut writer = self.dao.start_transaction()?;
        writer.set ("past_neighbors", self.scl.encrypt ("past_neighbors", encode_bytes (plain_data_opt)?, Some (db_password), &writer)?);
        Ok (writer.commit()?)
    }

    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError> {
        Ok(decode_u64(self.dao.get ("start_block")?.value_opt)?)
    }

    fn set_start_block(&mut self, value: u64) -> Result<(), String> {
        let mut writer = self.dao.start_transaction()?;
        writer.set ("start_block", encode_u64 (Some (value))?)?;
        Ok (writer.commit()?)
    }
}

impl<'a> From<Box<dyn ConnectionWrapper>> for PersistentConfigurationReal<'a> {
    fn from(conn: Box<dyn ConnectionWrapper>) -> Self {
        let config_dao: Box<dyn ConfigDao<'a>> = Box::new(ConfigDaoReal::new(conn));
        Self::from(config_dao)
    }
}

impl<'a> From<Box<dyn ConfigDao<'a>>> for PersistentConfigurationReal<'a> {
    fn from(config_dao: Box<dyn ConfigDao<'a>>) -> Self {
        Self::new(config_dao)
    }
}

impl<'a> PersistentConfigurationReal<'a> {
    pub fn new(config_dao: Box<dyn ConfigDao>) -> PersistentConfigurationReal<'a> {
        PersistentConfigurationReal { dao: config_dao, scl: Box::new(SecureConfigLayerReal::new()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use crate::blockchain::test_utils::make_meaningless_seed;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::main_cryptde;
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, DEFAULT_CHAIN_ID};
    use masq_lib::utils::find_free_port;
    use rustc_hex::FromHex;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use crate::db_config::mocks::ConfigDaoMock;

    #[test]
    fn from_config_dao_error() {
        vec![
            (ConfigDaoError::DatabaseError("booga".to_string()), PersistentConfigError::DatabaseError("booga".to_string())),
            (ConfigDaoError::TransactionError, PersistentConfigError::TransactionError),
            (ConfigDaoError::NotPresent, PersistentConfigError::NotPresent),
        ].into_iter ().for_each (|(cde, pce)|
            assert_eq! (PersistentConfigError::from (cde), pce)
        )
    }

    #[test]
    fn from_secure_config_layer_error() {
        vec![
            (SecureConfigLayerError::PasswordError, PersistentConfigError::PasswordError),
            (SecureConfigLayerError::DatabaseError("booga".to_string()), PersistentConfigError::DatabaseError("booga".to_string())),
            (SecureConfigLayerError::TransactionError, PersistentConfigError::TransactionError),
            (SecureConfigLayerError::NotPresent, PersistentConfigError::NotPresent),
        ].into_iter ().for_each (|(scle, pce)|
            assert_eq! (PersistentConfigError::from (scle), pce)
        )
    }

    #[test]
    fn from_typed_config_layer_error() {
        vec![
            (TypedConfigLayerError::BadHexFormat("booga".to_string()), PersistentConfigError::BadHexFormat("booga".to_string())),
            (TypedConfigLayerError::BadNumberFormat("booga".to_string()), PersistentConfigError::BadNumberFormat("booga".to_string())),
        ].into_iter ().for_each (|(tcle, pce)|
            assert_eq! (PersistentConfigError::from (tcle), pce)
        )
    }

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
        assert_eq!(get_string_params[0], "schema_version".to_string());
        assert_eq!(1, get_string_params.len());
    }

    #[test]
    fn set_password_works_if_set_string_succeeds() {
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Ok(()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_password("password");

        let set_string_params = set_string_params_arc.lock().unwrap();
        assert_eq!(set_string_params[0].0, "example_encrypted".to_string());
        let encrypted_string = set_string_params[0].1.clone();
        // If this doesn't panic, the test passes
        Bip39::decrypt_bytes(&encrypted_string, "password").unwrap();
    }

    #[test]
    #[should_panic(expected = "Can't continue; example_encrypted could not be set")]
    fn set_password_panics_if_set_string_fails() {
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Err(ConfigDaoError::DatabaseError("booga".to_string())));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_password("password");
    }

    #[test]
    fn check_password_works_if_there_is_none() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.check_password("password");

        assert_eq!(result, None);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(get_string_params[0], "example_encrypted".to_string());
        assert_eq!(1, get_string_params.len());
    }

    #[test]
    fn check_password_works_if_password_is_wrong() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let data = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_data = Bip39::encrypt_bytes(&data, "password").unwrap();
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok(encrypted_data));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.check_password("drowssap");

        assert_eq!(result, Some(false));
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(get_string_params[0], "example_encrypted".to_string());
        assert_eq!(1, get_string_params.len());
    }

    #[test]
    fn check_password_works_if_password_is_right() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let data = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_data = Bip39::encrypt_bytes(&data, "password").unwrap();
        let config_dao = ConfigDaoMock::new()
            .get_string_params(&get_string_params_arc)
            .get_string_result(Ok(encrypted_data));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.check_password("password");

        assert_eq!(result, Some(true));
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(get_string_params[0], "example_encrypted".to_string());
        assert_eq!(1, get_string_params.len());
    }

    #[test]
    #[should_panic(expected = "Can't continue; example_encrypted could not be read")]
    fn check_password_panics_if_get_string_fails() {
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Err(ConfigDaoError::DatabaseError("booga".to_string())));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.check_password("password");
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
        expected = "Specify --clandestine-port <p> where <p> is an unused port between 1025 and 65535."
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
        let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_bytes_e_params(&get_bytes_e_params_arc)
            .get_bytes_e_result(Ok(seed.clone()));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let possible_seed = subject.mnemonic_seed("booga");

        assert_eq!(possible_seed, Ok(Some(seed)));
        let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
        assert_eq!(
            *get_bytes_e_params,
            vec![("seed".to_string(), "booga".to_string())]
        )
    }

    #[test]
    fn mnemonic_seed_none_when_not_present() {
        let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_bytes_e_result(Err(ConfigDaoError::NotPresent))
            .get_bytes_e_params(&get_bytes_e_params_arc);
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.mnemonic_seed("booga");

        assert_eq!(result, Ok(None));
        let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
        assert_eq!(
            *get_bytes_e_params,
            vec![("seed".to_string(), "booga".to_string())]
        )
    }

    #[test]
    fn returns_database_error_for_seed_appropriately() {
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_bytes_e_result(Err(ConfigDaoError::DatabaseError("blah".to_string()))),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        let result = subject.mnemonic_seed("");

        assert_eq!(
            result,
            Err(PersistentConfigError::DatabaseError(
                "DatabaseError(\"blah\")".to_string()
            ))
        );
    }

    #[test]
    fn returns_decryption_failure_for_invalid_password_appropriately() {
        let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_bytes_e_params(&get_bytes_e_params_arc)
                .get_bytes_e_result(Err(ConfigDaoError::PasswordError)),
        );
        let subject = PersistentConfigurationReal::from(config_dao);

        let result = subject.mnemonic_seed("Invalid password");

        assert_eq!(result, Err(PersistentConfigError::PasswordError));
        let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
        assert_eq!(
            *get_bytes_e_params,
            vec![("seed".to_string(), "Invalid password".to_string())]
        )
    }

    #[test]
    fn set_mnemonic_seed_reports_dao_error() {
        let config_dao = ConfigDaoMock::new().set_string_result(Err(
            ConfigDaoError::DatabaseError("Here's your problem".to_string()),
        ));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.set_mnemonic_seed(&make_meaningless_seed(), "password");

        assert_eq! (result, Err(PersistentConfigError::DatabaseError("Can't continue; mnemonic seed configuration is inaccessible: DatabaseError(\"Here\\'s your problem\")".to_string())));
    }

    #[test]
    fn set_mnemonic_seed_succeeds() {
        let seed = make_meaningless_seed();
        let db_password = "seed password";
        let encrypted_seed = Bip39::encrypt_bytes(&seed, db_password).unwrap();
        let expected_params = ("seed".to_string(), encrypted_seed);
        let set_string_params_arc = Arc::new(Mutex::new(vec![expected_params.clone()]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Ok(()));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        subject.set_mnemonic_seed(&seed, db_password).unwrap();

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
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
    fn past_neighbors_reports_dao_error() {
        let config_dao = ConfigDaoMock::new().get_bytes_e_result(Err(ConfigDaoError::TypeError));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.past_neighbors("password");

        assert_eq!(
            result,
            Err(PersistentConfigError::DatabaseError(
                "Can't continue; past neighbors configuration is inaccessible: TypeError"
                    .to_string()
            ))
        );
    }

    #[test]
    fn past_neighbors_reports_crypto_error() {
        let config_dao = ConfigDaoMock::new()
            .get_bytes_e_result(Err(ConfigDaoError::CryptoError("blah".to_string())));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.past_neighbors("password");

        assert_eq! (result, Err(PersistentConfigError::DatabaseError("Can't continue; past neighbors configuration is inaccessible: CryptoError(\"blah\")".to_string())))
    }

    #[test]
    fn past_neighbors_success() {
        let node_descriptors = vec![
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA@1.2.3.4:1234").unwrap(),
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap(),
        ];
        let node_descriptors_bytes =
            PlainData::new(&serde_cbor::ser::to_vec(&node_descriptors).unwrap());
        let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_bytes_e_params(&get_bytes_e_params_arc)
            .get_bytes_e_result(Ok(node_descriptors_bytes));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.past_neighbors("password");

        assert_eq!(result, Ok(Some(node_descriptors)));
        let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
        assert_eq!(
            ("past_neighbors".to_string(), "password".to_string()),
            get_bytes_e_params[0]
        );
        assert_eq!(get_bytes_e_params.len(), 1);
    }

    #[test]
    fn set_past_neighbors_reports_dao_error() {
        let config_dao = ConfigDaoMock::new().set_bytes_e_result(Err(ConfigDaoError::TypeError));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.set_past_neighbors(Some(vec![]), "password");

        assert_eq!(
            result,
            Err(PersistentConfigError::DatabaseError(
                "Can't continue; past neighbors configuration is inaccessible: TypeError"
                    .to_string()
            ))
        )
    }

    #[test]
    fn set_past_neighbors_reports_password_error() {
        let config_dao =
            ConfigDaoMock::new().set_bytes_e_result(Err(ConfigDaoError::PasswordError));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.set_past_neighbors(Some(vec![]), "password");

        assert_eq!(result, Err(PersistentConfigError::PasswordError))
    }

    #[test]
    fn set_past_neighbors_none_success() {
        let clear_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .clear_params(&clear_params_arc)
            .clear_result(Ok(()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_past_neighbors(None, "password").unwrap();

        let clear_params = clear_params_arc.lock().unwrap();
        assert_eq!(clear_params[0], "past_neighbors".to_string());
        assert_eq!(1, clear_params.len());
    }

    #[test]
    fn set_past_neighbors_some_success() {
        let node_descriptors = vec![
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA@1.2.3.4:1234").unwrap(),
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap(),
        ];
        let set_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .set_bytes_e_params(&set_bytes_e_params_arc)
            .set_bytes_e_result(Ok(()));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_past_neighbors(Some(node_descriptors.clone()), "password")
            .unwrap();

        let set_bytes_e_params = set_bytes_e_params_arc.lock().unwrap();
        assert_eq!(set_bytes_e_params[0].0, "past_neighbors".to_string());
        let serialized_node_descriptors = set_bytes_e_params[0].1.clone();
        let actual_node_descriptors = serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(
            &serialized_node_descriptors.as_slice(),
        )
        .unwrap();
        assert_eq!(actual_node_descriptors, node_descriptors);
        assert_eq!(set_bytes_e_params.len(), 1);
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
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
        let seed = PlainData::from(Seed::new(&mnemonic, "passphrase").as_bytes());
        let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), consuming_path).unwrap();
        let private_public_key = keypair.secret().public().bytes().to_hex::<String>();
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
        let set_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_params(&get_string_params_arc)
                .get_string_result(Ok(private_public_key))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_bytes_e_params(&get_bytes_e_params_arc)
                .get_bytes_e_result(Ok(seed))
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
            ]
        );
        let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
        assert_eq!(
            *get_bytes_e_params,
            vec![("seed".to_string(), password.to_string())]
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
        let config_dao: Box<dyn ConfigDao> = Box::new(
            ConfigDaoMock::new()
                .get_string_result(Ok("consuming private key".to_string()))
                .get_string_result(Err(ConfigDaoError::NotPresent))
                .get_bytes_e_result(Ok(PlainData::from(seed.as_bytes()))),
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
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_start_block_transactionally(&transaction, 1234)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "TypeError")]
    fn set_start_block_transactionally_panics_for_type_error() {
        let config_dao =
            ConfigDaoMock::new().set_u64_transactional_result(Err(ConfigDaoError::TypeError));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_panics_for_type_error",
        );
        let mut conn = DbInitializerReal::new()
            .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
            .unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_start_block_transactionally(&transaction, 1234)
            .unwrap();
    }
}
