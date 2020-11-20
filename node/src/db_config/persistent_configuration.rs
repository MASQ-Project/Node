// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use rustc_hex::ToHex;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;
use crate::database::connection_wrapper::{ConnectionWrapper};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoReal};
use crate::db_config::secure_config_layer::{SecureConfigLayerError, SecureConfigLayer};
use crate::db_config::typed_config_layer::{decode_u64, TypedConfigLayerError, encode_u64, decode_bytes, encode_bytes};

#[derive(Clone, PartialEq, Debug)]
pub enum PersistentConfigError {
    NotPresent,
    PasswordError,
    TransactionError,
    DatabaseError(String),
    BadNumberFormat (String),
    BadHexFormat (String),
    Collision (String),
}

impl From<TypedConfigLayerError> for PersistentConfigError {
    fn from(input: TypedConfigLayerError) -> Self {
        match input {
            TypedConfigLayerError::BadHexFormat(msg) => PersistentConfigError::BadHexFormat(msg),
            TypedConfigLayerError::BadNumberFormat(msg) => PersistentConfigError::BadNumberFormat(msg),
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
        PersistentConfigError::from (SecureConfigLayerError::from (input))
    }
}

pub trait PersistentConfiguration<'a> {
    fn current_schema_version(&self) -> String;
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError>;
    fn change_password<'b, 'c>(&'a mut self, old_password_opt: Option<&'b str>, new_password: &'c str) -> Result<(), PersistentConfigError>;
    fn clandestine_port(&self) -> Result<Option<u16>, PersistentConfigError>;
    fn set_clandestine_port(&'a mut self, port: u16) -> Result<(), PersistentConfigError>;
    fn gas_price(&self) -> Result<Option<u64>, PersistentConfigError>;
    fn set_gas_price(&'a mut self, gas_price: u64) -> Result<(), PersistentConfigError>;
    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError>;
    fn set_mnemonic_seed(
        &'a mut self,
        seed: &dyn AsRef<[u8]>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn consuming_wallet_public_key(&self) -> Result<Option<String>, PersistentConfigError>;
    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_consuming_wallet_derivation_path<'b, 'c>(&'a mut self, derivation_path: &'b str, db_password: &'c str) -> Result<(), PersistentConfigError>;
    fn set_consuming_wallet_public_key<'b>(&'a mut self, public_key: &'b PlainData) -> Result<(), PersistentConfigError>;
    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError>;
    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_earning_wallet_address(&'a mut self, address: &str) -> Result<(), PersistentConfigError>;
    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>;
    fn set_past_neighbors(
        &'a mut self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError>;
    fn set_start_block(&'a mut self, value: u64) -> Result<(), PersistentConfigError>;
}

pub struct PersistentConfigurationReal {
    dao: Box<dyn ConfigDao>,
    scl: SecureConfigLayer,
}

impl PersistentConfiguration<'_> for PersistentConfigurationReal {
    fn current_schema_version(&self) -> String {
        match self.dao.get("schema_version") {
            Ok(record) => match record.value_opt {
                None => panic!("Can't continue; current schema version is missing"),
                Some (csv) => csv,
            },
            Err(e) => panic!(
                "Can't continue; current schema version is inaccessible: {:?}",
                e
            ),
        }
    }

    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, PersistentConfigError> {
        Ok(self.scl.check_password (db_password_opt, &self.dao)?)
    }

    fn change_password(&mut self, old_password_opt: Option<&str>, new_password: &str) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        self.scl.change_password (old_password_opt, new_password, &mut writer)?;
        Ok (writer.commit()?)
    }

    fn clandestine_port(&self) -> Result<Option<u16>, PersistentConfigError> {
        let unchecked_port = match decode_u64(self.dao.get ("clandestine_port")?.value_opt)? {
            None => return Ok(None),
            Some (port) => port,
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

    fn set_mnemonic_seed<'b, 'c>(&mut self, seed: &'b dyn AsRef<[u8]>, db_password: &'c str) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        let encoded_seed = encode_bytes(Some (PlainData::new (seed.as_ref())))?.expect ("Value disappeared");
        writer.set ("seed", self.scl.encrypt ("seed", Some (encoded_seed), Some (db_password), &writer)?)?;
        Ok(writer.commit()?)
    }

    fn consuming_wallet_public_key(&self) -> Result<Option<String>, PersistentConfigError> {
        let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        if key_rec.value_opt.is_some() && path_rec.value_opt.is_some() {
            panic!("Database is corrupt: both consuming wallet public key and derivation path are set")
        }
        Ok(key_rec.value_opt)
    }

    fn consuming_wallet_derivation_path(&self) -> Result<Option<String>, PersistentConfigError> {
        unimplemented!()
        // let key_rec = self.dao.get ("consuming_wallet_public_key")?;
        // let path_rec = self.dao.get ("consuming_wallet_derivation_path")?;
        // match (key_rec.value_opt, path_rec.value_opt) {
        //     (None, None) => Ok(None),
        //     (Some(_), None) => Ok(None),
        //     (None, Some(path)) => Ok(Some(path)),
        //     (Some (_), Some (_)) => panic!(
        //         "Database is corrupt: both consuming wallet public key and wallet are set",
        //     ),
        // }
    }

    fn set_consuming_wallet_derivation_path<'b, 'c>(&mut self, derivation_path: &'b str, db_password: &'c str) -> Result<(), PersistentConfigError> {
        unimplemented!()
        // let mut writer = self.dao.start_transaction()?;
        // let key_rec = writer.get ("consuming_wallet_public_key")?;
        // let path_rec = writer.get ("consuming_wallet_derivation_path")?;
        // match (key_rec.value_opt, path_rec.value_opt) {
        //     (None, None) => {
        //         writer.set("consuming_wallet_derivation_path", Some (derivation_path.to_string()))?;
        //     },
        //     (Some (key), None) => {
        //         let seed = match decode_bytes (self.scl.decrypt (writer.get ("seed")?, Some (db_password), &writer)?)? {
        //             Some(seed) => seed,
        //             None => {
        //                 panic!("Can't set consuming wallet derivation path without a mnemonic seed")
        //             }
        //         };
        //         let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), derivation_path)
        //             .unwrap_or_else(|_| {
        //                 panic!("Bad consuming derivation path: {}", derivation_path)
        //             });
        //         let existing_public_key = keypair.secret().public().bytes().to_hex::<String>();
        //         if key != existing_public_key {
        //             panic!(
        //                 "Cannot set consuming wallet derivation path: consuming private key is already set"
        //             )
        //         }
        //     }
        //     (None, Some(existing_path)) => {
        //         if derivation_path != existing_path {
        //             panic!(
        //                 "Cannot set consuming wallet derivation path: already set to {}",
        //                 existing_path
        //             )
        //         }
        //         else {
        //             writer.set("consuming_wallet_derivation_path", Some(derivation_path.to_string()))?
        //         }
        //     }
        //     (Some (_), Some (_)) => panic!(
        //         "Database is corrupt: both consuming wallet public key and wallet are set",
        //     ),
        // };
        // Ok (writer.commit()?)
    }

    fn set_consuming_wallet_public_key<'b>(&mut self, public_key: &'b PlainData) -> Result<(), PersistentConfigError> {
        unimplemented!()
        // let public_key_text: String = public_key.as_slice().to_hex();
        // let mut writer = self.dao.start_transaction()?;
        // let key_rec = writer.get ("consuming_wallet_public_key")?;
        // let path_rec = writer.get ("consuming_wallet_derivation_path")?;
        // match (key_rec.value_opt, path_rec.value_opt) {
        //     (None, None) => writer.set("consuming_wallet_public_key", Some (public_key_text))?,
        //     (Some(existing_public_key_text), None) =>  {
        //         if public_key_text != existing_public_key_text {
        //             panic!("Cannot set consuming wallet public key: already set")
        //         }
        //     },
        //     (None, Some(path)) => panic!("Cannot set consuming wallet public key: consuming derivation path is already set to {}", path),
        //     (Some (_), Some (_)) => panic!(
        //         "Database is corrupt: both consuming wallet public key and wallet are set",
        //     ),
        // };
        // Ok(writer.commit()?)
    }

    fn earning_wallet_from_address(&self) -> Result<Option<Wallet>, PersistentConfigError> {
        unimplemented!()
        // match self.earning_wallet_address()? {
        //     None => Ok(None),
        //     Some(address) => match Wallet::from_str(&address) {
        //         Err(e) => panic!("Database corrupt: invalid earning wallet address '{}': {:?}", address, e),
        //         Ok(wallet) => Ok (Some(wallet)),
        //     }
        // }
    }

    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError> {
        unimplemented!()
        // Ok(self.dao.get ("earning_wallet_address")?.value_opt)
    }

    fn set_earning_wallet_address<'b>(&mut self, address: &'b str) -> Result<(), PersistentConfigError> {
        unimplemented!()
        // match Wallet::from_str(address) {
        //     Ok(_) => (),
        //     Err(e) => panic!("Invalid earning wallet address '{}': {:?}", address, e),
        // }
        // if let Some(existing_address) = self.dao.get("earning_wallet_address")?.value_opt {
        //     if address.to_lowercase() != existing_address.to_lowercase() {
        //         panic!(
        //             "Can't overwrite existing earning wallet address '{}'",
        //             existing_address
        //         )
        //     } else {
        //         return Ok(());
        //     }
        // }
        // let mut writer = self.dao.start_transaction()?;
        // writer.set ("earning_wallet_address", Some (address.to_string()))?;
        // Ok(writer.commit()?)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        let bytes_opt = decode_bytes (self.scl.decrypt (self.dao.get ("past_neighbors")?, Some (db_password), &self.dao)?)?;
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
        writer.set ("past_neighbors", self.scl.encrypt ("past_neighbors", encode_bytes (plain_data_opt)?, Some (db_password), &writer)?)?;
        Ok (writer.commit()?)
    }

    fn start_block(&self) -> Result<Option<u64>, PersistentConfigError> {
        Ok(decode_u64(self.dao.get ("start_block")?.value_opt)?)
    }

    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set ("start_block", encode_u64 (Some (value))?)?;
        Ok (writer.commit()?)
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
        PersistentConfigurationReal { dao: config_dao, scl: SecureConfigLayer::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use crate::db_config::mocks::{ConfigDaoMock, ConfigDaoWriteableMock};
    use crate::db_config::config_dao::ConfigDaoRecord;
    use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
    use masq_lib::utils::find_free_port;
    use std::net::SocketAddr;
    use crate::blockchain::bip39::Bip39;
    use crate::test_utils::main_cryptde;

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
    fn current_schema_version_panics_if_record_is_missing() {
        let config_dao = ConfigDaoMock::new().get_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.current_schema_version();
    }

    #[test]
    #[should_panic(expected = "Can't continue; current schema version is missing")]
    fn current_schema_version_panics_if_record_is_empty() {
        let config_dao = ConfigDaoMock::new().get_result(Ok (ConfigDaoRecord::new ("schema_version", None, false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.current_schema_version();
    }

    #[test]
    fn current_schema_version() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new ("schema_version", Some ("1.2.3"), false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.current_schema_version();

        assert_eq!("1.2.3".to_string(), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["schema_version".to_string()]);
    }

    #[test]
    fn set_password_is_passed_through_to_secure_config_layer<'a>() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new (ConfigDaoWriteableMock::new()
            .get_params (&get_params_arc)
            .get_result (Err(ConfigDaoError::NotPresent)));
        let dao = Box::new (ConfigDaoMock::new()
            .start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new (dao);

        let result = subject.change_password(None, "password");

        assert_eq! (Err(PersistentConfigError::NotPresent), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq! (*get_params, vec![EXAMPLE_ENCRYPTED.to_string()])
    }

    #[test]
    fn check_password_delegates_properly() {
        let get_string_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_string_params_arc)
            .get_result(Ok(ConfigDaoRecord::new (EXAMPLE_ENCRYPTED, None, true)));
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
        let config_dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new("clandestine_port", Some ("65536"), false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port().unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine-port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new("clandestine_port", Some ("1024"), false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port().unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Specify --clandestine-port <p> where <p> is an unused port between 1025 and 65535."
    )]
    fn clandestine_port_panics_if_configured_port_is_in_use() {
        let port = find_free_port();
        let config_dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new("clandestine_port", Some (&format!("{}", port)), false)));
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
            .get_result(Ok(ConfigDaoRecord::new ("clandestine_port", Some ("4747"), false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.clandestine_port().unwrap();

        assert_eq!(Some (4747), result);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq! (*get_params, vec!["clandestine_port".to_string()]);
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
        let writer = Box::new (ConfigDaoWriteableMock::new()
            .get_result(Ok(ConfigDaoRecord::new ("clandestine_port", Some ("1234"), false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result(Ok(())));
        let config_dao = Box::new (ConfigDaoMock::new()
            .start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_clandestine_port(4747);

        assert_eq! (result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params, vec![("clandestine_port".to_string(), Some ("4747".to_string()))]);
    }

    #[test]
    fn mnemonic_seed_success() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let seed = PlainData::new(b"example seed");
        let encoded_seed = encode_bytes(Some (seed.clone())).unwrap().unwrap();
        let encrypted_seed = Bip39::encrypt_bytes (&encoded_seed, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new ("seed", Some (&encrypted_seed), true)))
            .get_result(Ok(ConfigDaoRecord::new (EXAMPLE_ENCRYPTED, Some (&example_encrypted), true))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.mnemonic_seed("password").unwrap();

        assert_eq!(result, Some(seed));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "seed".to_string(),
                EXAMPLE_ENCRYPTED.to_string(),
            ]
        )
    }

    #[test]
    fn start_block_success() {
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new("start_block", Some ("6"), false))));

        let subject = PersistentConfigurationReal::new(config_dao);
        let start_block = subject.start_block().unwrap();

        assert_eq!(start_block, Some (6));
    }

    #[test]
    fn set_start_block_success() {
        let set_params_arc = Arc::new (Mutex::new (vec![]));
        let writer = Box::new (ConfigDaoWriteableMock::new()
            .get_result(Ok(ConfigDaoRecord::new ("start_block", Some ("1234"), false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result (Ok(())));
        let config_dao = Box::new (ConfigDaoMock::new ()
            .start_transaction_result(Ok (writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_start_block(1234).unwrap();

        let set_params = set_params_arc.lock().unwrap();
        assert_eq! (*set_params, vec![("start_block".to_string(), Some ("1234".to_string()))])
    }

    #[test]
    fn gas_price() {
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new("gas_price", Some ("3"), false))));

        let subject = PersistentConfigurationReal::new(config_dao);
        let gas_price = subject.gas_price().unwrap();

        assert_eq!(gas_price, Some (3));
    }

    #[test]
    fn set_gas_price_succeeds() {
        let set_params_arc = Arc::new (Mutex::new (vec![]));
        let writer = Box::new (ConfigDaoWriteableMock::new()
            .get_result(Ok(ConfigDaoRecord::new ("gas_price", Some ("1234"), false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result (Ok(())));
        let config_dao = Box::new (ConfigDaoMock::new ()
            .start_transaction_result(Ok (writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_gas_price(1234).unwrap();

        let set_params = set_params_arc.lock().unwrap();
        assert_eq! (*set_params, vec![("gas_price".to_string(), Some ("1234".to_string()))])
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
        let node_descriptors_string = encode_bytes (Some (node_descriptors_bytes)).unwrap().unwrap();
        let node_descriptors_enc = Bip39::encrypt_bytes(&node_descriptors_string.as_bytes(), "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new(ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new ("past_neighbors", Some(&node_descriptors_enc), true)))
            .get_result(Ok(ConfigDaoRecord::new (EXAMPLE_ENCRYPTED, Some(&example_encrypted), true))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.past_neighbors("password").unwrap();

        assert_eq!(result, Some(node_descriptors));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq! (*get_params, vec!["past_neighbors".to_string(), EXAMPLE_ENCRYPTED.to_string()]);
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
        let writer = Box::new(ConfigDaoWriteableMock::new()
            .get_result(Ok(ConfigDaoRecord::new (EXAMPLE_ENCRYPTED, Some(&example_encrypted), true)))
            .get_result(Ok(ConfigDaoRecord::new ("past_neighbors", Some ("irrelevant"), true)))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result(Ok(())));
        let config_dao = Box::new (ConfigDaoMock::new()
            .start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        subject
            .set_past_neighbors(Some(node_descriptors.clone()), "password")
            .unwrap();

        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(set_params[0].0, "past_neighbors".to_string());
        let encrypted_serialized_node_descriptors = set_params[0].1.clone().unwrap();
        let encoded_serialized_node_descriptors = Bip39::decrypt_bytes(&encrypted_serialized_node_descriptors, "password").unwrap();
        let serialized_node_descriptors = decode_bytes (Some(String::from_utf8(encoded_serialized_node_descriptors.into()).unwrap())).unwrap().unwrap();
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
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_public_key", Some("My first test"), false)))
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_derivation_path", None, false))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_public_key().unwrap();

        assert_eq!(result, Some("My first test".to_string()));
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
    #[should_panic (expected = "Database is corrupt: both consuming wallet public key and derivation path are set")]
    fn consuming_wallet_public_key_panics_if_both_are_set() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_public_key",Some("My first test"),false)))
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_derivation_path",Some("derivation path"),false))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let _ = subject.consuming_wallet_public_key();
    }

    #[test]
    fn consuming_wallet_public_key_retrieves_nonexisting_key_if_derivation_path_is_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = Box::new (ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_public_key",None,false)))
            .get_result(Ok(ConfigDaoRecord::new("consuming_wallet_derivation_path",Some("Here we are"),false))));
        let subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.consuming_wallet_public_key().unwrap();

        assert_eq!(result,None);
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
        unimplemented!();
    }

    #[test]
    #[should_panic (expected = "Database is corrupt: both consuming wallet public key and derivation path are set")]
    fn consuming_wallet_derivation_path_panics_if_both_are_set() {
        unimplemented!();
    }

    #[test]
    fn consuming_wallet_derivation_path_works_if_key_is_set_and_path_is_not() {
        unimplemented!();
    }

    // #[test]
    // fn set_consuming_wallet_derivation_path_works_if_no_preexisting_info() {
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path("derivation path", "password");
    //
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec![
    //             "consuming_wallet_public_key".to_string(),
    //             "consuming_wallet_derivation_path".to_string()
    //         ]
    //     );
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_string_params,
    //         vec![(
    //             "consuming_wallet_derivation_path".to_string(),
    //             "derivation path".to_string()
    //         )]
    //     );
    // }
    //
    // #[test]
    // fn set_consuming_wallet_derivation_path_works_if_path_is_already_set_to_same() {
    //     let consuming_path = "m/44'/60'/1'/2/3";
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Ok(consuming_path.to_string()))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path(consuming_path, "password");
    //
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec![
    //             "consuming_wallet_public_key".to_string(),
    //             "consuming_wallet_derivation_path".to_string()
    //         ]
    //     );
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(set_string_params.len(), 0)
    // }
    //
    // #[test]
    // fn set_consuming_wallet_derivation_path_works_if_key_is_already_set_to_same() {
    //     let consuming_path = "m/44'/60'/1'/2/3";
    //     let password = "password";
    //     let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    //     let seed = PlainData::from(Seed::new(&mnemonic, "passphrase").as_bytes());
    //     let keypair = Bip32ECKeyPair::from_raw(seed.as_ref(), consuming_path).unwrap();
    //     let private_public_key = keypair.secret().public().bytes().to_hex::<String>();
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let get_bytes_e_params_arc = Arc::new(Mutex::new(vec![]));
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Ok(private_public_key))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_bytes_e_params(&get_bytes_e_params_arc)
    //             .get_bytes_e_result(Ok(seed))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path(consuming_path, password);
    //
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec![
    //             "consuming_wallet_public_key".to_string(),
    //             "consuming_wallet_derivation_path".to_string(),
    //         ]
    //     );
    //     let get_bytes_e_params = get_bytes_e_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_bytes_e_params,
    //         vec![("seed".to_string(), password.to_string())]
    //     );
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(set_string_params.len(), 0)
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Cannot set consuming wallet derivation path: consuming private key is already set"
    // )]
    // fn set_consuming_wallet_derivation_path_complains_if_key_is_already_set() {
    //     let consuming_path = "m/44'/60'/1'/2/3";
    //     let password = "password";
    //     let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    //     let seed = Seed::new(&mnemonic, "passphrase");
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok("consuming private key".to_string()))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_bytes_e_result(Ok(PlainData::from(seed.as_bytes()))),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path(consuming_path, password);
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Cannot set consuming wallet derivation path: already set to existing derivation path"
    // )]
    // fn set_consuming_wallet_derivation_path_complains_if_path_is_already_set() {
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Ok("existing derivation path".to_string())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path("derivation path", "password");
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    // )]
    // fn set_consuming_wallet_derivation_path_complains_if_both_are_already_set() {
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok("existing private key".to_string()))
    //             .get_string_result(Ok("existing derivation path".to_string())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_derivation_path("derivation path", "password");
    // }
    //
    // #[test]
    // fn set_consuming_wallet_public_key_works_if_no_preexisting_info() {
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //     let public_key = PlainData::new(b"public key");
    //
    //     subject.set_consuming_wallet_public_key(&public_key);
    //
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec![
    //             "consuming_wallet_public_key".to_string(),
    //             "consuming_wallet_derivation_path".to_string()
    //         ]
    //     );
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     let (name, public_key_text) = &set_string_params[0];
    //     assert_eq!(name, "consuming_wallet_public_key");
    //     let public_key_bytes: Vec<u8> = public_key_text.from_hex().unwrap();
    //     assert_eq!(public_key_bytes, b"public key".to_vec());
    // }
    //
    // #[test]
    // #[should_panic(expected = "Cannot set consuming wallet public key: already set")]
    // fn set_consuming_wallet_public_key_complains_if_key_is_already_set_to_different_value() {
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok("consuming public key".to_string()))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    // }
    //
    // #[test]
    // fn set_consuming_wallet_public_key_does_not_complain_if_key_is_already_set_to_same_value() {
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let private_public_key_text = b"public key".to_hex::<String>();
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok(private_public_key_text.clone()))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    //
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(*set_string_params, vec![]); // no changes
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Cannot set consuming wallet public key: consuming derivation path is already set to existing derivation path"
    // )]
    // fn set_consuming_wallet_public_key_complains_if_path_is_already_set() {
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Ok("existing derivation path".to_string())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Database is corrupt: both consuming wallet public key and consuming wallet derivation path are set"
    // )]
    // fn set_consuming_wallet_public_key_complains_if_both_are_already_set() {
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok("existing private key".to_string()))
    //             .get_string_result(Ok("existing derivation path".to_string())),
    //     );
    //     let mut subject = PersistentConfigurationReal::from(config_dao);
    //
    //     subject.set_consuming_wallet_public_key(&PlainData::new(b"public key"));
    // }
    //
    // #[test]
    // fn earning_wallet_from_address_handles_no_address() {
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Err(ConfigDaoError::NotPresent)),
    //     );
    //     let subject = PersistentConfigurationReal::new(config_dao);
    //
    //     let result = subject.earning_wallet_from_address();
    //
    //     assert_eq!(result, None);
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec!["earning_wallet_address".to_string()]
    //     )
    // }
    //
    // #[test]
    // fn earning_wallet_from_address_handles_existing_address() {
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Ok("0x0123456789ABCDEF0123456789ABCDEF01234567".to_string())),
    //     );
    //     let subject = PersistentConfigurationReal::new(config_dao);
    //
    //     let result = subject.earning_wallet_from_address();
    //
    //     assert_eq!(
    //         result,
    //         Some(Wallet::from_str("0x0123456789ABCDEF0123456789ABCDEF01234567").unwrap())
    //     );
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec!["earning_wallet_address".to_string()]
    //     )
    // }
    //
    // #[test]
    // fn set_earning_wallet_address_happy_path() {
    //     let get_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_params(&get_string_params_arc)
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .get_string_result(Err(ConfigDaoError::NotPresent))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::new(config_dao);
    //
    //     subject.set_earning_wallet_address("0xcafedeadbeefbabefacecafedeadbeefbabeface");
    //
    //     let get_string_params = get_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_string_params,
    //         vec!["earning_wallet_address".to_string(),]
    //     );
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_string_params,
    //         vec![(
    //             "earning_wallet_address".to_string(),
    //             "0xcafedeadbeefbabefacecafedeadbeefbabeface".to_string()
    //         )]
    //     );
    // }
    //
    // #[test]
    // #[should_panic(expected = "Invalid earning wallet address 'booga'")]
    // fn set_earning_wallet_address_bad_address() {
    //     let config_dao: Box<dyn ConfigDao> =
    //         Box::new(ConfigDaoMock::new().set_string_result(Ok(())));
    //     let mut subject = PersistentConfigurationReal::new(config_dao);
    //
    //     subject.set_earning_wallet_address("booga");
    // }
    //
    // #[test]
    // #[should_panic(expected = "Can't overwrite existing earning wallet address 'booga'")]
    // fn set_earning_wallet_address_existing_unequal_address() {
    //     let config_dao: Box<dyn ConfigDao> =
    //         Box::new(ConfigDaoMock::new().get_string_result(Ok("booga".to_string())));
    //     let mut subject = PersistentConfigurationReal::new(config_dao);
    //
    //     subject.set_earning_wallet_address("0xcafedeadbeefbabefacecafedeadbeefbabeface");
    // }
    //
    // #[test]
    // fn set_earning_wallet_address_existing_equal_address() {
    //     let set_string_params_arc = Arc::new(Mutex::new(vec![]));
    //     let config_dao: Box<dyn ConfigDao> = Box::new(
    //         ConfigDaoMock::new()
    //             .get_string_result(Ok("0xcafedeadbeefbabefacecafedeadbeefBABEFACE".to_string()))
    //             .set_string_params(&set_string_params_arc)
    //             .set_string_result(Ok(())),
    //     );
    //     let mut subject = PersistentConfigurationReal::new(config_dao);
    //
    //     subject.set_earning_wallet_address("0xcafeDEADBEEFbabefacecafedeadbeefbabeface");
    //
    //     let set_string_params = set_string_params_arc.lock().unwrap();
    //     assert_eq!(set_string_params.len(), 0);
    // }
    //
    // #[test]
    // #[should_panic(expected = "Database is corrupt: error retrieving one: TypeError")]
    // fn handle_config_pair_result_handles_first_error() {
    //     PersistentConfigurationReal::handle_config_pair_result(
    //         Err(ConfigDaoError::TypeError),
    //         Ok("blah".to_string()),
    //         "one",
    //         "another",
    //     );
    // }
    //
    // #[test]
    // #[should_panic(expected = "Database is corrupt: error retrieving another: TypeError")]
    // fn handle_config_pair_result_handles_second_error() {
    //     PersistentConfigurationReal::handle_config_pair_result(
    //         Ok("blah".to_string()),
    //         Err(ConfigDaoError::TypeError),
    //         "one",
    //         "another",
    //     );
    // }
    //
    // #[test]
    // #[should_panic(
    //     expected = "Database is corrupt: error retrieving both one (TypeError) and another (TypeError)"
    // )]
    // fn handle_config_pair_result_handles_both_errors() {
    //     PersistentConfigurationReal::handle_config_pair_result(
    //         Err(ConfigDaoError::TypeError),
    //         Err(ConfigDaoError::TypeError),
    //         "one",
    //         "another",
    //     );
    // }
    //
    // #[test]
    // #[should_panic(expected = "Unable to update start_block, maybe missing from the database")]
    // fn set_start_block_transactionally_panics_for_not_present_error() {
    //     let config_dao =
    //         ConfigDaoMock::new().set_u64_transactional_result(Err(ConfigDaoError::NotPresent));
    //
    //     let home_dir = ensure_node_home_directory_exists(
    //         "persistent_configuration",
    //         "set_start_block_transactionally_panics_for_not_present_error",
    //     );
    //     let mut conn = DbInitializerReal::new()
    //         .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
    //         .unwrap();
    //     let transaction = conn.transaction().unwrap();
    //
    //     let subject = PersistentConfigurationReal::new(Box::new(config_dao));
    //
    //     subject
    //         .set_start_block_transactionally(&transaction, 1234)
    //         .unwrap();
    // }
    //
    // #[test]
    // #[should_panic(expected = "TypeError")]
    // fn set_start_block_transactionally_panics_for_type_error() {
    //     let config_dao =
    //         ConfigDaoMock::new().set_u64_transactional_result(Err(ConfigDaoError::TypeError));
    //
    //     let home_dir = ensure_node_home_directory_exists(
    //         "persistent_configuration",
    //         "set_start_block_transactionally_panics_for_type_error",
    //     );
    //     let mut conn = DbInitializerReal::new()
    //         .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
    //         .unwrap();
    //     let transaction = conn.transaction().unwrap();
    //
    //     let subject = PersistentConfigurationReal::new(Box::new(config_dao));
    //
    //     subject
    //         .set_start_block_transactionally(&transaction, 1234)
    //         .unwrap();
    // }
}
