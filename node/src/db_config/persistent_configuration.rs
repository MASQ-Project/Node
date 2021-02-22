// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::bip39::Bip39;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoReal};
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::db_config::typed_config_layer::{
    decode_bytes, decode_u64, encode_bytes, encode_u64, TypedConfigLayerError,
};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use bip39::{Language, MnemonicType};
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;

#[derive(Clone, PartialEq, Debug)]
pub enum PersistentConfigError {
    NotPresent,
    PasswordError,
    TransactionError,
    DatabaseError(String),
    BadPortNumber(String),
    BadNumberFormat(String),
    BadHexFormat(String),
    BadMnemonicSeed(PlainData),
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
    fn check_password(
        &self,
        db_password_opt: Option<String>,
    ) -> Result<bool, PersistentConfigError>;
    fn change_password(
        &mut self,
        old_password_opt: Option<String>,
        new_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn clandestine_port(&self) -> Result<u16, PersistentConfigError>;
    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError>;
    fn gas_price(&self) -> Result<u64, PersistentConfigError>;
    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError>;
    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError>;
    fn mnemonic_seed_exists(&self) -> Result<bool, PersistentConfigError>;
    // WARNING: Actors should get consuming-wallet information from their startup config, not from here
    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError>;
    // WARNING: Actors should get earning-wallet information from their startup config, not from here
    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError>;
    // WARNING: Actors should get earning-wallet information from their startup config, not from here
    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError>;

    fn set_wallet_info(
        &mut self,
        mnemonic_seed: &dyn AsRef<[u8]>,
        consuming_wallet_derivation_path: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>;
    fn set_past_neighbors(
        &mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn start_block(&self) -> Result<u64, PersistentConfigError>;
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

    fn check_password(
        &self,
        db_password_opt: Option<String>,
    ) -> Result<bool, PersistentConfigError> {
        Ok(self.scl.check_password(db_password_opt, &self.dao)?)
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<String>,
        new_password: &str,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        self.scl
            .change_password(old_password_opt, new_password, &mut writer)?;
        Ok(writer.commit()?)
    }

    fn clandestine_port(&self) -> Result<u16, PersistentConfigError> {
        let unchecked_port = match decode_u64(self.dao.get("clandestine_port")?.value_opt)? {
            None => panic!("ever-supplied value missing; database is corrupt!"),
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
        Ok(port)
    }

    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError> {
        if port < LOWEST_USABLE_INSECURE_PORT {
            return Err(PersistentConfigError::BadPortNumber(format!(
                "Must be greater than 1024; not {}",
                port
            )));
        }
        if TcpListener::bind(SocketAddrV4::new(Ipv4Addr::from(0), port)).is_err() {
            return Err(PersistentConfigError::BadPortNumber(format!(
                "Must be open port: {} is in use",
                port
            )));
        }
        let mut writer = self.dao.start_transaction()?;
        writer.set("clandestine_port", encode_u64(Some(u64::from(port)))?)?;
        Ok(writer.commit()?)
    }

    fn gas_price(&self) -> Result<u64, PersistentConfigError> {
        match decode_u64(self.dao.get("gas_price")?.value_opt) {
            Ok(val) => Ok(val.expect("ever-supplied value missing; database is corrupt!")),
            Err(e) => Err(PersistentConfigError::from(e)),
        }
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set("gas_price", encode_u64(Some(gas_price))?)?;
        Ok(writer.commit()?)
    }

    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError> {
        Ok(decode_bytes(self.scl.decrypt(
            self.dao.get("seed")?,
            Some(db_password.to_string()),
            &self.dao,
        )?)?)
    }

    fn mnemonic_seed_exists(&self) -> Result<bool, PersistentConfigError> {
        Ok(self.dao.get("seed")?.value_opt.is_some())
    }

    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError> {
        let path_rec = self.dao.get("consuming_wallet_derivation_path")?;
        Ok(path_rec.value_opt)
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

    fn set_wallet_info(
        &mut self,
        mnemonic_seed: &dyn AsRef<[u8]>,
        consuming_wallet_derivation_path: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        match self.mnemonic_seed(db_password)? {
            None => (),
            Some(existing_mnemonic_seed) => {
                if PlainData::new(mnemonic_seed.as_ref()) != existing_mnemonic_seed {
                    return Err(PersistentConfigError::Collision(
                        "Mnemonic seed already populated; cannot replace".to_string(),
                    ));
                }
            }
        }
        match self.consuming_wallet_derivation_path()? {
            None => (),
            Some(existing_consuming_wallet_derivation_path) => {
                if consuming_wallet_derivation_path != existing_consuming_wallet_derivation_path {
                    return Err(PersistentConfigError::Collision(
                        "Consuming wallet derivation path already populated; cannot replace"
                            .to_string(),
                    ));
                }
            }
        }
        match self.earning_wallet_address()? {
            None => (),
            Some(existing_earning_wallet_address) => {
                if earning_wallet_address != existing_earning_wallet_address {
                    return Err(PersistentConfigError::Collision(
                        "Earning wallet address already populated; cannot replace".to_string(),
                    ));
                }
            }
        }
        if !Self::validate_mnemonic_seed(mnemonic_seed) {
            return Err(PersistentConfigError::BadMnemonicSeed(PlainData::new(
                mnemonic_seed.as_ref(),
            )));
        }
        if !Self::validate_derivation_path(consuming_wallet_derivation_path) {
            return Err(PersistentConfigError::BadDerivationPathFormat(
                consuming_wallet_derivation_path.to_string(),
            ));
        }
        if !Self::validate_wallet_address(earning_wallet_address) {
            return Err(PersistentConfigError::BadAddressFormat(
                earning_wallet_address.to_string(),
            ));
        }
        let encoded_seed_opt = encode_bytes(Some(PlainData::new(mnemonic_seed.as_ref())))?;
        let encrypted_seed_opt = self.scl.encrypt(
            "seed",
            encoded_seed_opt,
            Some(db_password.to_string()),
            &self.dao,
        )?;
        let mut writer = self.dao.start_transaction()?;
        writer.set("seed", encrypted_seed_opt)?;
        writer.set(
            "consuming_wallet_derivation_path",
            Some(consuming_wallet_derivation_path.to_string()),
        )?;
        writer.set(
            "earning_wallet_address",
            Some(earning_wallet_address.to_string()),
        )?;
        Ok(writer.commit()?)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        let bytes_opt = decode_bytes(self.scl.decrypt(
            self.dao.get("past_neighbors")?,
            Some(db_password.to_string()),
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
                Some(db_password.to_string()),
                &writer,
            )?,
        )?;
        Ok(writer.commit()?)
    }

    fn start_block(&self) -> Result<u64, PersistentConfigError> {
        match decode_u64(self.dao.get("start_block")?.value_opt) {
            Ok(val) => Ok(val.expect("ever-supplied value missing; database is corrupt!")),
            Err(e) => Err(PersistentConfigError::from(e)),
        }
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

    fn validate_mnemonic_seed(mnemonic_seed: &dyn AsRef<[u8]>) -> bool {
        mnemonic_seed.as_ref().len() == 64
    }

    fn validate_derivation_path(derivation_path: &str) -> bool {
        let mnemonic = Bip39::mnemonic(MnemonicType::Words24, Language::English);
        let seed = Bip39::seed(&mnemonic, "");
        Bip32ECKeyPair::from_raw(seed.as_bytes(), derivation_path).is_ok()
    }

    fn validate_wallet_address(address: &str) -> bool {
        Wallet::from_str(address).is_ok()
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
    use bip39::{Language, MnemonicType};
    use masq_lib::utils::{derivation_path, find_free_port};
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
    #[should_panic(expected = "ever-supplied value missing; database is corrupt!")]
    fn clandestine_port_panics_if_none_got_from_database() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "clandestine_port",
            None,
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port().unwrap();
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

        assert_eq!(result, 4747);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["clandestine_port".to_string()]);
    }

    #[test]
    fn set_clandestine_port_complains_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new();
        let mut subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.set_clandestine_port(1024);

        assert_eq!(
            result,
            Err(PersistentConfigError::BadPortNumber(
                "Must be greater than 1024; not 1024".to_string()
            ))
        )
    }

    #[test]
    fn set_clandestine_port_complains_if_configured_port_is_in_use() {
        let config_dao = ConfigDaoMock::new();
        let mut subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let port = find_free_port();
        let _listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), port))).unwrap();

        let result = subject.set_clandestine_port(port);

        assert_eq!(
            result,
            Err(PersistentConfigError::BadPortNumber(format!(
                "Must be open port: {} is in use",
                port
            )))
        );
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
    fn consuming_wallet_derivation_path_works_if_path_is_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
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
        assert_eq!(*get_params, vec!["consuming_wallet_derivation_path"])
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_path_is_not_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
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
        assert_eq!(*get_params, vec!["consuming_wallet_derivation_path"])
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

    fn make_seed_info(db_password: &str) -> (PlainData, String) {
        let mnemonic = Bip39::mnemonic(MnemonicType::Words24, Language::English);
        let mnemonic_seed = Bip39::seed(&mnemonic, "");
        let seed_bytes = PlainData::new(mnemonic_seed.as_ref());
        let encoded_seed = encode_bytes(Some(seed_bytes.clone())).unwrap().unwrap();
        let encrypted_seed = Bip39::encrypt_bytes(&encoded_seed.as_bytes(), db_password).unwrap();
        (seed_bytes, encrypted_seed)
    }

    fn make_wallet_info(db_password: &str) -> (PlainData, String, String, String) {
        let (seed_bytes, encrypted_seed) = make_seed_info(db_password);
        let consuming_wallet_derivation_path = "m/66'/40'/0'/0/0".to_string();
        let key_pair = Bip32ECKeyPair::from_raw(seed_bytes.as_slice(), "m/66'/40'/0'/0/1").unwrap();
        let earning_wallet = Wallet::from(key_pair);
        let earning_wallet_address = earning_wallet.to_string();
        (
            seed_bytes,
            encrypted_seed,
            consuming_wallet_derivation_path,
            earning_wallet_address,
        )
    }

    #[test]
    fn set_wallet_info_success() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .set_result(Ok(()))
                .set_result(Ok(()))
                .commit_params(&commit_params_arc)
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
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
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .start_transaction_result(Ok(writer)),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (seed_plain, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "seed".to_string(),
                EXAMPLE_ENCRYPTED.to_string(),
                "consuming_wallet_derivation_path".to_string(),
                "earning_wallet_address".to_string(),
                EXAMPLE_ENCRYPTED.to_string(),
                "seed".to_string(),
            ]
        );
        let mut set_params = set_params_arc.lock().unwrap();
        let (_, encrypted_seed) = set_params.remove(0);
        let encoded_seed_bytes =
            Bip39::decrypt_bytes(&encrypted_seed.unwrap(), "password").unwrap();
        let encoded_seed_string = String::from_utf8(encoded_seed_bytes.into()).unwrap();
        let actual_seed_plain = decode_bytes(Some(encoded_seed_string)).unwrap().unwrap();
        assert_eq!(actual_seed_plain, seed_plain);
        assert_eq!(
            *set_params,
            vec![
                (
                    "consuming_wallet_derivation_path".to_string(),
                    Some(consuming_wallet_derivation_path)
                ),
                (
                    "earning_wallet_address".to_string(),
                    Some(earning_wallet_address)
                )
            ]
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_wallet_info_fails_if_mnemonic_seed_already_exists() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let (_, encrypted_seed) = make_seed_info("password");
        let config_dao = Box::new(
            ConfigDaoMock::new()
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
        let (seed_plain, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Mnemonic seed already populated; cannot replace".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_fails_if_consuming_wallet_derivation_path_exists() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let (seed_plain, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some(&derivation_path(4, 4)),
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Consuming wallet derivation path already populated; cannot replace".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_fails_if_earning_wallet_address_exists() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let config_dao = Box::new(
            ConfigDaoMock::new()
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
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    Some(&derivation_path(4, 5)),
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (seed_plain, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Earning wallet address already populated; cannot replace".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_works_okay_if_incoming_values_are_same_as_existing_values() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .set_result(Ok(()))
                .set_result(Ok(()))
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let (seed_plain, seed_encrypted, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&seed_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_derivation_path",
                    Some(&consuming_wallet_derivation_path),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    Some(&earning_wallet_address),
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "seed",
                    Some(&seed_encrypted),
                    true,
                )))
                .start_transaction_result(Ok(writer)),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn set_wallet_info_fails_if_mnemonic_seed_is_invalid() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
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
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (_, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &PlainData::new(b"invalid"),
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::BadMnemonicSeed(PlainData::new(
                b"invalid"
            )))
        );
    }

    #[test]
    fn set_wallet_info_fails_if_consuming_derivation_path_is_invalid() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
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
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (plain_seed, _, _, earning_wallet_address) = make_wallet_info("password");

        let result =
            subject.set_wallet_info(&plain_seed, "invalid", &earning_wallet_address, "password");

        assert_eq!(
            result,
            Err(PersistentConfigError::BadDerivationPathFormat(
                "invalid".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_fails_if_earning_wallet_address_is_invalid() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
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
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (seed_plain, _, consuming_wallet_derivation_path, _) = make_wallet_info("password");

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            "invalid",
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::BadAddressFormat(
                "invalid".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_rolls_back_on_failure() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .set_result(Ok(()))
                .set_result(Ok(()))
                .set_result(Err(ConfigDaoError::NotPresent))
                .commit_params(&commit_params_arc),
        );
        let config_dao = Box::new(
            ConfigDaoMock::new()
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
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new("seed", None, true)))
                .start_transaction_result(Ok(writer)),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (seed_plain, _, consuming_wallet_derivation_path, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &seed_plain,
            &consuming_wallet_derivation_path,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(result, Err(PersistentConfigError::NotPresent));
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![]);
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

        assert_eq!(start_block, 6);
    }

    #[test]
    #[should_panic(expected = "ever-supplied value missing; database is corrupt!")]
    fn start_block_does_not_tolerate_optional_output() {
        let config_dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "start_block",
            None,
            false,
        ))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.start_block();
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

        assert_eq!(gas_price, 3);
    }

    #[test]
    #[should_panic(expected = "ever-supplied value missing; database is corrupt!")]
    fn gas_price_does_not_tolerate_optional_output() {
        let config_dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "gas_price",
            None,
            false,
        ))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.gas_price();
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
}
