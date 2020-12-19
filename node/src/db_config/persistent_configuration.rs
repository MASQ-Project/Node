// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoReadWrite, ConfigDaoReal};
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::db_config::typed_config_layer::{
    decode_bytes, decode_u64, encode_bytes, encode_u64, TypedConfigLayerError,
};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use rustc_hex::ToHex;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;

#[derive(Clone, PartialEq, Debug)]
pub enum PersistentConfigError {
    NotPresent,
    PasswordError,
    TransactionError,
    DatabaseError(String),
    BadNumberFormat(String),
    BadHexFormat(String),
    BadDerivationPathFormat(String),
    BadAddressFormat(String),
    Collision(String),
}

impl From<TypedConfigLayerError> for PersistentConfigError {
    fn from(input: TypedConfigLayerError) -> Self {
        match input {
            TypedConfigLayerError::BadHexFormat(msg) => PersistentConfigError::BadHexFormat(msg),
            TypedConfigLayerError::BadNumberFormat(msg) => {
                PersistentConfigError::BadNumberFormat(msg)
            }
        }
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
        PersistentConfigError::from(SecureConfigLayerError::from(input))
    }
}

impl PersistentConfigError {
    pub fn into_configurator_error(self, parameter: &str) -> ConfiguratorError {
        ConfiguratorError {
            param_errors: vec![ParamError::new(parameter, &format!("{:?}", self))],
        }
    }
}

pub trait PersistentConfiguration {
    fn current_schema_version(&self) -> String;
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError>;
    fn change_password(
        &mut self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn clandestine_port(&self) -> Result<Option<u16>, PersistentConfigError>;
    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError>;
    fn gas_price(&self) -> Result<Option<u64>, PersistentConfigError>;
    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError>;
    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError>;
    fn mnemonic_seed_exists(&self) -> Result<bool, PersistentConfigError>;
    fn set_mnemonic_seed(
        &mut self,
        seed: &dyn AsRef<[u8]>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn consuming_wallet_public_key(&self) -> Result<Option<PlainData>, PersistentConfigError>;
    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_consuming_wallet_derivation_path(
        &mut self,
        derivation_path: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn set_consuming_wallet_public_key(
        &mut self,
        public_key: &PlainData,
    ) -> Result<(), PersistentConfigError>;
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

pub struct PersistentConfigurationReal {
    dao: Box<dyn ConfigDao>,
    scl: SecureConfigLayer,
}

impl PersistentConfiguration for PersistentConfigurationReal {
    fn current_schema_version(&self) -> String {
        match self.dao.get("schema_version") {
            Ok(record) => match record.value_opt {
                None => panic!("Can't continue; current schema version is missing"),
                Some(csv) => csv,
            },
            Err(e) => panic!(
                "Can't continue; current schema version is inaccessible: {:?}",
                e
            ),
        }
    }

    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError> {
        Ok(self.scl.check_password(db_password_opt, &self.dao)?)
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        self.scl
            .change_password(old_password_opt, new_password, &mut writer)?;
        Ok(writer.commit()?)
    }

    fn clandestine_port(&self) -> Result<Option<u16>, PersistentConfigError> {
        let unchecked_port = match decode_u64(self.dao.get("clandestine_port")?.value_opt)? {
            None => return Ok(None),
            Some(port) => port,
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
            Ok (_) => Ok(Some(port)),
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
        writer.set("clandestine_port", encode_u64(Some(u64::from(port)))?)?;
        Ok(writer.commit()?)
    }

    fn gas_price(&self) -> Result<Option<u64>, PersistentConfigError> {
        Ok(decode_u64(self.dao.get("gas_price")?.value_opt)?)
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set("gas_price", encode_u64(Some(gas_price))?)?;
        Ok(writer.commit()?)
    }

    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError> {
        Ok(decode_bytes(self.scl.decrypt(
            self.dao.get("seed")?,
            Some(db_password),
            &self.dao,
        )?)?)
    }

    fn mnemonic_seed_exists(&self) -> Result<bool, PersistentConfigError> {
        Ok(self.dao.get("seed")?.value_opt.is_some())
    }

    fn set_mnemonic_seed<'b, 'c>(
        &mut self,
        seed: &'b dyn AsRef<[u8]>,
        db_password: &'c str,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        let encoded_seed =
            encode_bytes(Some(PlainData::new(seed.as_ref())))?.expect("Value disappeared"); //the question mark here is useless, look inside the function
        writer.set(
            "seed",
            self.scl
                .encrypt("seed", Some(encoded_seed), Some(db_password), &writer)?,
        )?;
        Ok(writer.commit()?)
    }

    fn consuming_wallet_public_key(&self) -> Result<Option<PlainData>, PersistentConfigError> {
        let key_rec = self.dao.get("consuming_wallet_public_key")?;
        let path_rec = self.dao.get("consuming_wallet_derivation_path")?;
        if key_rec.value_opt.is_some() && path_rec.value_opt.is_some() {
            panic!(
                "Database is corrupt: both consuming wallet public key and derivation path are set"
            )
        }
        Ok(decode_bytes(key_rec.value_opt)?)
    }

    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError> {
        let key_rec = self.dao.get("consuming_wallet_public_key")?;
        let path_rec = self.dao.get("consuming_wallet_derivation_path")?;
        if path_rec.value_opt.is_some() && key_rec.value_opt.is_some() {
            panic!(
                "Database is corrupt: both consuming wallet public key and derivation path are set"
            )
        }
        Ok(path_rec.value_opt)
    }

    fn set_consuming_wallet_derivation_path<'b, 'c>(
        &mut self,
        derivation_path: &'b str,
        db_password: &'c str,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        let key_rec = writer.get("consuming_wallet_public_key")?;
        let seed_opt = decode_bytes(self.scl.decrypt(
            writer.get("seed")?,
            Some(db_password),
            &writer,
        )?)?;
        let path_rec = writer.get("consuming_wallet_derivation_path")?;
        let check_and_set = |writer: &mut Box<dyn ConfigDaoReadWrite>, seed: PlainData| {
            if Bip32ECKeyPair::from_raw(seed.as_ref(), derivation_path).is_ok() {
                writer.set(
                    "consuming_wallet_derivation_path",
                    Some(derivation_path.to_string()),
                )?;
                Ok(writer.commit()?)
            } else {
                Err(PersistentConfigError::BadDerivationPathFormat(
                    derivation_path.to_string(),
                ))
            }
        };
        match (key_rec.value_opt, seed_opt, path_rec.value_opt) {
            (None, Some (seed), None) => {
                check_and_set (&mut writer, seed)
            },
            (None, Some (seed), Some (existing_path)) if existing_path == derivation_path => {
                check_and_set (&mut writer, seed)
            },
            (None, Some (_), Some (_)) => Err (PersistentConfigError::Collision("Cannot change existing consuming wallet derivation path".to_string())),
            (None, None, _) => Err (PersistentConfigError::DatabaseError("Can't set consuming wallet derivation path without a mnemonic seed".to_string())),
            (Some (_), _, None) => Err (PersistentConfigError::Collision("Cannot set consuming wallet derivation path: consuming wallet public key is already set".to_string())),
            (Some (_), _, Some(_)) => panic!("Database is corrupt: both consuming wallet public key and derivation path are set")
        }
    }

    fn set_consuming_wallet_public_key<'b>(
        &mut self,
        public_key: &'b PlainData,
    ) -> Result<(), PersistentConfigError> {
        let public_key_text: String = public_key.as_slice().to_hex();
        let mut writer = self.dao.start_transaction()?;
        let key_rec = writer.get("consuming_wallet_public_key")?;
        let path_rec = writer.get("consuming_wallet_derivation_path")?;
        match (decode_bytes(key_rec.value_opt)?, public_key, path_rec.value_opt) {
            (None, _, Some (_)) => return Err (PersistentConfigError::Collision("Cannot set consuming wallet public key: consuming wallet derivation path is already set".to_string())),
            (Some(_), _, Some (_)) => panic! ("Database is corrupt: both consuming wallet public key and derivation path are set"),
            (Some (existing), new_ref, _) if &existing == new_ref => return Ok(()),
            (Some (_), _, _) => return Err (PersistentConfigError::Collision("Cannot change existing consuming wallet key".to_string())),
            _ => ()
        }
        writer.set("consuming_wallet_public_key", Some(public_key_text))?;
        Ok(writer.commit()?)
    }

    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError> {
        match self.earning_wallet_address()? {
            None => Ok(None),
            Some(address) => match Wallet::from_str(&address) {
                Ok(w) => Ok(Some(w)),
                Err(error) => panic!(
                    "Database corrupt: invalid earning wallet address '{}': {:?}",
                    address, error
                ),
            },
        }
    }

    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError> {
        Ok(self.dao.get("earning_wallet_address")?.value_opt)
    }

    fn set_earning_wallet_address<'b>(
        &mut self,
        new_address: &'b str,
    ) -> Result<(), PersistentConfigError> {
        if Wallet::from_str(new_address).is_err() {
            return Err(PersistentConfigError::BadAddressFormat(
                new_address.to_string(),
            ));
        }
        let mut writer = self.dao.start_transaction()?;
        let existing_address_opt = writer.get("earning_wallet_address")?.value_opt;
        match existing_address_opt {
            None => {
                writer.set("earning_wallet_address", Some(new_address.to_string()))?;
                Ok(writer.commit()?)
            }
            Some(existing_address) if new_address == existing_address => Ok(()),
            Some(_) => Err(PersistentConfigError::Collision(
                "Cannot change existing earning wallet address".to_string(),
            )),
        }
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        let bytes_opt = decode_bytes(self.scl.decrypt(
            self.dao.get("past_neighbors")?,
            Some(db_password),
            &self.dao,
        )?)?;
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
        let plain_data_opt = node_descriptors_opt.map(|node_descriptors| {
            PlainData::new(
                &serde_cbor::ser::to_vec(&node_descriptors).expect("Serialization failed"),
            )
        });
        let mut writer = self.dao.start_transaction()?;
        writer.set(
            "past_neighbors",
            self.scl.encrypt(
                "past_neighbors",
                encode_bytes(plain_data_opt)?,
                Some(db_password),
                &writer,
            )?,
        )?;
        Ok(writer.commit()?)
    }

    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError> {
        Ok(decode_u64(self.dao.get("start_block")?.value_opt)?)
    }

    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set("start_block", encode_u64(Some(value))?)?;
        Ok(writer.commit()?)
    }
}

impl From<Box<dyn ConnectionWrapper>> for PersistentConfigurationReal {
    fn from(conn: Box<dyn ConnectionWrapper>) -> Self {
        let config_dao: Box<dyn ConfigDao> = Box::new(ConfigDaoReal::new(conn));
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
        PersistentConfigurationReal {
            dao: config_dao,
            scl: SecureConfigLayer::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::db_config::config_dao::ConfigDaoRecord;
    use crate::db_config::mocks::{ConfigDaoMock, ConfigDaoWriteableMock};
    use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
    use crate::test_utils::main_cryptde;
    use masq_lib::utils::find_free_port;
    use rustc_hex::FromHex;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    #[test]
    fn from_config_dao_error() {
        vec![
            (
                ConfigDaoError::DatabaseError("booga".to_string()),
                PersistentConfigError::DatabaseError("booga".to_string()),
            ),
            (
                ConfigDaoError::TransactionError,
                PersistentConfigError::TransactionError,
            ),
            (
                ConfigDaoError::NotPresent,
                PersistentConfigError::NotPresent,
            ),
        ]
        .into_iter()
        .for_each(|(cde, pce)| assert_eq!(PersistentConfigError::from(cde), pce))
    }

    #[test]
    fn from_secure_config_layer_error() {
        vec![
            (
                SecureConfigLayerError::PasswordError,
                PersistentConfigError::PasswordError,
            ),
            (
                SecureConfigLayerError::DatabaseError("booga".to_string()),
                PersistentConfigError::DatabaseError("booga".to_string()),
            ),
            (
                SecureConfigLayerError::TransactionError,
                PersistentConfigError::TransactionError,
            ),
            (
                SecureConfigLayerError::NotPresent,
                PersistentConfigError::NotPresent,
            ),
        ]
        .into_iter()
        .for_each(|(scle, pce)| assert_eq!(PersistentConfigError::from(scle), pce))
    }

    #[test]
    fn from_typed_config_layer_error() {
        vec![
            (
                TypedConfigLayerError::BadHexFormat("booga".to_string()),
                PersistentConfigError::BadHexFormat("booga".to_string()),
            ),
            (
                TypedConfigLayerError::BadNumberFormat("booga".to_string()),
                PersistentConfigError::BadNumberFormat("booga".to_string()),
            ),
        ]
        .into_iter()
        .for_each(|(tcle, pce)| assert_eq!(PersistentConfigError::from(tcle), pce))
    }

    #[test]
    #[should_panic(expected = "Can't continue; current schema version is inaccessible: NotPresent")]
    fn current_schema_version_panics_if_record_is_missing() {
        let config_dao = ConfigDaoMock::new().get_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.current_schema_version();
    }

    #[test]
    #[should_panic(expected = "Can't continue; current schema version is missing")]
    fn current_schema_version_panics_if_record_is_empty() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "schema_version",
            None,
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.current_schema_version();
    }

    #[test]
    fn current_schema_version() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "schema_version",
                Some("1.2.3"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.current_schema_version();

        assert_eq!("1.2.3".to_string(), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["schema_version".to_string()]);
    }

    #[test]
    fn set_password_is_passed_through_to_secure_config_layer<'a>() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Err(ConfigDaoError::NotPresent)),
        );
        let dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(dao);

        let result = subject.change_password(None, "password");

        assert_eq!(Err(PersistentConfigError::NotPresent), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()])
    }

    #[test]
    fn check_password_delegates_properly() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_string_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.check_password(None).unwrap();

        assert_eq!(result, true);
        let get_string_params = get_string_params_arc.lock().unwrap();
        assert_eq!(*get_string_params, [EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 65536. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_high() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "clandestine_port",
            Some("65536"),
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port().unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "clandestine_port",
            Some("1024"),
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port().unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Specify --clandestine-port <p> where <p> is an unused port between 1025 and 65535."
    )]
    fn clandestine_port_panics_if_configured_port_is_in_use() {
        let port = find_free_port();
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "clandestine_port",
            Some(&format!("{}", port)),
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let _listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port))).unwrap();

        subject.clandestine_port().unwrap();
    }

    #[test]
    fn clandestine_port_success() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "clandestine_port",
                Some("4747"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.clandestine_port().unwrap();

        assert_eq!(Some(4747), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["clandestine_port".to_string()]);
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn set_clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new();
        let mut subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.set_clandestine_port(1024).unwrap();
    }

    #[test]
    fn set_clandestine_port_success() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "clandestine_port",
                    Some("1234"),
                    false,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_clandestine_port(4747);

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("clandestine_port".to_string(), Some("4747".to_string()))]
        );
    }

    #[test]
    fn mnemonic_seed_success() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let seed = PlainData::new(b"example seed");
        let encoded_seed = encode_bytes(Some(seed.clone())).unwrap().unwrap();
        let encrypted_seed = Bip39::encrypt_bytes(&encoded_seed, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.mnemonic_seed("password").unwrap();

        assert_eq!(result, Some(seed));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec!["seed".to_string(), EXAMPLE_ENCRYPTED.to_string(),]
        )
    }

    #[test]
    fn mnemonic_seed_exists_true() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new("seed", Some("irrelevant"), true))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.mnemonic_seed_exists().unwrap();

        assert_eq!(result, true);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["seed".to_string()]);
    }

    #[test]
    fn mnemonic_seed_exists_false() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.mnemonic_seed_exists().unwrap();

        assert_eq!(result, false);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["seed".to_string()]);
    }

    #[test]
    fn start_block_success() {
        let config_dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "start_block",
            Some("6"),
            false,
        ))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let start_block = subject.start_block().unwrap();

        assert_eq!(start_block, Some(6));
    }

    #[test]
    fn set_start_block_success() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new("start_block", Some("1234"), false)))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_start_block(1234);

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("start_block".to_string(), Some("1234".to_string()))]
        )
    }

    #[test]
    fn gas_price() {
        let config_dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "gas_price",
            Some("3"),
            false,
        ))));

        let subject = PersistentConfigurationReal::new(config_dao);
        let gas_price = subject.gas_price().unwrap();

        assert_eq!(gas_price, Some(3));
    }

    #[test]
    fn set_gas_price_succeeds() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new("gas_price", Some("1234"), false)))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_gas_price(1234);

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("gas_price".to_string(), Some("1234".to_string()))]
        )
    }

    #[test]
    fn past_neighbors_success() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let node_descriptors = vec![
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA@1.2.3.4:1234").unwrap(),
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap(),
        ];
        let node_descriptors_bytes =
            PlainData::new(&serde_cbor::ser::to_vec(&node_descriptors).unwrap());
        let node_descriptors_string = encode_bytes(Some(node_descriptors_bytes)).unwrap().unwrap();
        let node_descriptors_enc =
            Bip39::encrypt_bytes(&node_descriptors_string.as_bytes(), "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "past_neighbors",
                    Some(&node_descriptors_enc),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.past_neighbors("password").unwrap();

        assert_eq!(result, Some(node_descriptors));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec!["past_neighbors".to_string(), EXAMPLE_ENCRYPTED.to_string()]
        );
    }

    #[test]
    fn set_past_neighbors_success() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let node_descriptors = vec![
            NodeDescriptor::from_str(main_cryptde(), "AQIDBA@1.2.3.4:1234").unwrap(),
            NodeDescriptor::from_str(main_cryptde(), "AgMEBQ:2.3.4.5:2345").unwrap(),
        ];
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "past_neighbors",
                    Some("irrelevant"),
                    true,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        subject
            .set_past_neighbors(Some(node_descriptors.clone()), "password")
            .unwrap();

        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(set_params[0].0, "past_neighbors".to_string());
        let encrypted_serialized_node_descriptors = set_params[0].1.clone().unwrap();
        let encoded_serialized_node_descriptors =
            Bip39::decrypt_bytes(&encrypted_serialized_node_descriptors, "password").unwrap();
        let serialized_node_descriptors = decode_bytes(Some(
            String::from_utf8(encoded_serialized_node_descriptors.into()).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let actual_node_descriptors = serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(
            &serialized_node_descriptors.as_slice(),
        )
        .unwrap();
        assert_eq!(actual_node_descriptors, node_descriptors);
        assert_eq!(set_params.len(), 1);
    }

    #[test]
    fn consuming_wallet_public_key_retrieves_existing_key() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let public_key = PlainData::from("My first test".as_bytes());
        let encoded_public_key = encode_bytes(Some(public_key)).unwrap().unwrap();
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some(&encoded_public_key),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_public_key().unwrap();

        assert_eq!(result, Some(PlainData::from("My first test".as_bytes())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and derivation path are set"
    )]
    fn consuming_wallet_public_key_panics_if_both_are_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some("My first test"),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("derivation path"),
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.consuming_wallet_public_key();
    }

    #[test]
    fn consuming_wallet_public_key_retrieves_nonexisting_key_if_derivation_path_is_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("Here we are"),
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_public_key().unwrap();

        assert_eq!(result, None);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_key_is_not_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("My_path"),
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_derivation_path().unwrap();

        assert_eq!(result, Some("My_path".to_string()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and derivation path are set"
    )]
    fn consuming_wallet_derivation_path_panics_if_both_are_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some("public_key"),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("My_path"),
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.consuming_wallet_derivation_path();
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_key_is_set_and_path_is_not() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some("Look_at_me_I_am_public_key"),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_derivation_path().unwrap();

        assert_eq!(result, None);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key",
                "consuming_wallet_derivation_path"
            ]
        )
    }

    #[test]
    fn set_consuming_wallet_public_key_works_if_no_preexisting_info() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_params(&commit_params_arc)
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let public_key = PlainData::new(b"public key");

        let result = subject.set_consuming_wallet_public_key(&public_key);

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let mut set_params = set_params_arc.lock().unwrap();
        let (name, public_key_text_opt) = set_params.remove(0);
        assert_eq!(name, "consuming_wallet_public_key");
        let public_key_bytes: Vec<u8> = public_key_text_opt.unwrap().from_hex().unwrap();
        assert_eq!(public_key_bytes, b"public key".to_vec());
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_consuming_wallet_public_key_complains_if_key_is_already_set_to_different_value() {
        let existing_public_key = PlainData::from("existing public key".as_bytes());
        let encoded_existing_public_key = encode_bytes(Some(existing_public_key)).unwrap().unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some(&encoded_existing_public_key),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let public_key = PlainData::new(b"new public key");

        let result = subject.set_consuming_wallet_public_key(&public_key);

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Cannot change existing consuming wallet key".to_string()
            ))
        );
    }

    #[test]
    fn set_consuming_wallet_public_key_does_not_complain_if_key_is_already_set_to_same_value() {
        let existing_public_key = PlainData::from("existing public key".as_bytes());
        let encoded_existing_public_key = encode_bytes(Some(existing_public_key)).unwrap().unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some(&encoded_existing_public_key),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let public_key = PlainData::new(b"existing public key");

        let result = subject.set_consuming_wallet_public_key(&public_key);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn set_consuming_wallet_public_key_complains_if_path_is_already_set_and_key_is_not() {
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("existing path"),
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let public_key = PlainData::new(b"public key");

        let result = subject.set_consuming_wallet_public_key(&public_key);

        assert_eq! (result, Err (PersistentConfigError::Collision("Cannot set consuming wallet public key: consuming wallet derivation path is already set".to_string())));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and derivation path are set"
    )]
    fn set_consuming_wallet_public_key_panics_if_key_and_path_are_both_already_set() {
        let existing_public_key = PlainData::from("existing public key".as_bytes());
        let encoded_existing_public_key = encode_bytes(Some(existing_public_key)).unwrap().unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some(&encoded_existing_public_key),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("existing path"),
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let public_key = PlainData::new(b"public key");

        subject
            .set_consuming_wallet_public_key(&public_key)
            .unwrap();
    }

    #[test]
    fn set_consuming_wallet_derivation_path_works_if_seed_but_no_other_preexisting_info() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_params(&commit_params_arc)
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/2", "password");

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "seed".to_string(),
                EXAMPLE_ENCRYPTED.to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "consuming_wallet_derivation_path".to_string(),
                Some("m/44'/0'/0'/1/2".to_string())
            )]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_consuming_wallet_derivation_path_works_if_path_is_already_set_to_same_value() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("m/44'/0'/0'/1/2"),
                    false,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_params(&commit_params_arc)
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/2", "password");

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_public_key".to_string(),
                "seed".to_string(),
                EXAMPLE_ENCRYPTED.to_string(),
                "consuming_wallet_derivation_path".to_string()
            ]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "consuming_wallet_derivation_path".to_string(),
                Some("m/44'/0'/0'/1/2".to_string())
            )]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_consuming_wallet_derivation_path_complains_if_path_is_already_set_to_different_value() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("m/44'/0'/0'/1/0"),
                    false,
                )))
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/2", "password");

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Cannot change existing consuming wallet derivation path".to_string()
            ))
        );
    }

    #[test]
    fn set_consuming_wallet_derivation_path_complains_if_seed_is_not_set() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/0", "password");

        assert_eq!(
            result,
            Err(PersistentConfigError::DatabaseError(
                "Can't set consuming wallet derivation path without a mnemonic seed".to_string()
            ))
        );
    }

    #[test]
    fn set_consuming_wallet_derivation_path_complains_about_invalid_derivation_path() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("invalid path", "password");

        assert_eq!(
            result,
            Err(PersistentConfigError::BadDerivationPathFormat(
                "invalid path".to_string()
            ))
        );
    }

    #[test]
    fn set_consuming_wallet_derivation_path_complains_if_key_is_already_set_and_path_is_not() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some("existing key"),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/0", "password");

        assert_eq! (result, Err(PersistentConfigError::Collision("Cannot set consuming wallet derivation path: consuming wallet public key is already set".to_string())));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: both consuming wallet public key and derivation path are set"
    )]
    fn set_consuming_wallet_derivation_path_panics_if_key_and_path_are_both_already_set() {
        let from_hex: Vec<u8> = FromHex::from_hex("3f91d24bb4279747c807cc791a0794b6e509e4a8df1f28ece6090d8bef226199cb20256210243209b11c650d08fa4f1ff9a218e263d45d689699f0a01bbe6d3b").unwrap();
        let seed = PlainData::new(&from_hex);
        let encoded_seed = encode_bytes(Some(seed)).unwrap().unwrap();
        let encrypted_encoded_seed =
            Bip39::encrypt_bytes(&encoded_seed.as_bytes(), "password").unwrap();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_public_key",
                    Some("existing key"),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&encrypted_encoded_seed),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some("existing_path"),
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.set_consuming_wallet_derivation_path("m/44'/0'/0'/1/0", "password");
    }

    #[test]
    fn earning_wallet_address() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                Some("existing_address"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.earning_wallet_address().unwrap().unwrap();

        assert_eq!(result, "existing_address".to_string());
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
    }

    #[test]
    fn earning_wallet_from_address_if_address_is_missing() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                None,
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.earning_wallet_from_address().unwrap();

        assert_eq!(result, None);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: invalid earning wallet address '123456invalid': InvalidAddress"
    )]
    fn earning_wallet_from_address_if_address_is_set_and_invalid() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                Some("123456invalid"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let _ = subject.earning_wallet_from_address();
    }

    #[test]
    fn earning_wallet_from_address_if_address_is_set_and_valid() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                Some("0x7d6dabd6b5c75291a3258c29b418f5805792a875"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.earning_wallet_from_address().unwrap();

        assert_eq!(
            result,
            Some(Wallet::from_str("0x7d6dabd6b5c75291a3258c29b418f5805792a875").unwrap())
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
    }

    #[test]
    fn set_earning_wallet_address_works_if_no_address_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                )))
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_params(&commit_params_arc)
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result =
            subject.set_earning_wallet_address("0x7d6dabd6b5c75291a3258c29b418f5805792a875");

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "earning_wallet_address".to_string(),
                Some("0x7d6dabd6b5c75291a3258c29b418f5805792a875".to_string())
            )]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_earning_wallet_address_works_if_new_address_equals_old_address() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    Some("0x7d6dabd6b5c75291a3258c29b418f5805792a875"),
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result =
            subject.set_earning_wallet_address("0x7d6dabd6b5c75291a3258c29b418f5805792a875");

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn set_earning_wallet_address_complains_if_new_address_is_different_from_old_address() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    Some("0x8e6dabd6b5c75291a3258c29b418f5805792a886"),
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result =
            subject.set_earning_wallet_address("0x7d6dabd6b5c75291a3258c29b418f5805792a875");

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Cannot change existing earning wallet address".to_string()
            ))
        );
    }

    #[test]
    fn set_earning_wallet_address_complains_if_new_address_is_invalid() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                ))),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_earning_wallet_address("invalid address");

        assert_eq!(
            result,
            Err(PersistentConfigError::BadAddressFormat(
                "invalid address".to_string()
            ))
        );
    }
}
