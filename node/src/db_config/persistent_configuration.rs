// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::bip32::Bip32ECKeyProvider;
use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoReal, ConfigDaoRecord};
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::db_config::typed_config_layer::{
    decode_bytes, decode_u64, encode_bytes, encode_u64, TypedConfigLayerError,
};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use masq_lib::constants::{HIGHEST_USABLE_PORT, LOWEST_USABLE_INSECURE_PORT};
use masq_lib::shared_schema::{ConfiguratorError, ParamError};
use masq_lib::utils::AutomapProtocol;
use masq_lib::utils::NeighborhoodModeLight;
use rustc_hex::{FromHex, ToHex};
#[cfg(test)]
use std::any::Any;
use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::str::FromStr;
use websocket::url::Url;

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
    InvalidUrl(String),
    Collision(String),
    UninterpretableValue(String),
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
    fn balance_decreases_for_sec(&self) -> Result<u64, PersistentConfigError>;
    fn set_balance_decreases_for_sec(&mut self, interval: u64)
        -> Result<(), PersistentConfigError>;
    fn balance_to_decrease_from_gwei(&self) -> Result<u64, PersistentConfigError>;
    fn set_balance_to_decrease_from_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError>;
    fn blockchain_service_url(&self) -> Result<Option<String>, PersistentConfigError>;
    fn set_blockchain_service_url(&mut self, url: &str) -> Result<(), PersistentConfigError>;
    fn current_schema_version(&self) -> String;
    fn chain_name(&self) -> String;
    fn check_password(
        &self,
        db_password_opt: Option<String>,
    ) -> Result<bool, PersistentConfigError>;
    fn change_password(
        &mut self,
        old_password_opt: Option<String>,
        new_password: &str,
    ) -> Result<(), PersistentConfigError>;
    // WARNING: Actors should get consuming-wallet information from their startup config, not from here
    fn consuming_wallet(&self, db_password: &str) -> Result<Option<Wallet>, PersistentConfigError>;
    // WARNING: Actors should get consuming-wallet information from their startup config, not from here
    fn consuming_wallet_private_key(
        &self,
        db_password: &str,
    ) -> Result<Option<String>, PersistentConfigError>;
    fn clandestine_port(&self) -> Result<u16, PersistentConfigError>;
    fn set_clandestine_port(&mut self, port: u16) -> Result<(), PersistentConfigError>;
    // WARNING: Actors should get earning-wallet information from their startup config, not from here
    fn earning_wallet(&self) -> Result<Option<Wallet>, PersistentConfigError>;
    // WARNING: Actors should get earning-wallet information from their startup config, not from here
    fn earning_wallet_address(&self) -> Result<Option<String>, PersistentConfigError>;
    fn exit_byte_rate(&self) -> Result<u64, PersistentConfigError>;
    fn set_exit_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError>;
    fn exit_service_rate(&self) -> Result<u64, PersistentConfigError>;
    fn set_exit_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError>;
    fn gas_price(&self) -> Result<u64, PersistentConfigError>;
    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError>;
    fn mapping_protocol(&self) -> Result<Option<AutomapProtocol>, PersistentConfigError>;
    fn set_mapping_protocol(
        &mut self,
        value: Option<AutomapProtocol>,
    ) -> Result<(), PersistentConfigError>;
    fn neighborhood_mode(&self) -> Result<NeighborhoodModeLight, PersistentConfigError>;
    fn set_neighborhood_mode(
        &mut self,
        value: NeighborhoodModeLight,
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
    fn payable_scan_interval(&self) -> Result<u64, PersistentConfigError>;
    fn set_payable_scan_interval(&mut self, interval_sec: u64)
        -> Result<(), PersistentConfigError>;
    fn payment_grace_before_ban_sec(&self) -> Result<u64, PersistentConfigError>;
    fn set_payment_grace_before_ban_sec(
        &mut self,
        period_sec: u64,
    ) -> Result<(), PersistentConfigError>;
    fn payment_suggested_after_sec(&self) -> Result<u64, PersistentConfigError>;
    fn set_payment_suggested_after_sec(&mut self, period: u64)
        -> Result<(), PersistentConfigError>;
    fn pending_payment_scan_interval(&self) -> Result<u64, PersistentConfigError>;
    fn set_pending_payment_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError>;
    fn permanent_debt_allowed_gwei(&self) -> Result<u64, PersistentConfigError>;
    fn set_permanent_debt_allowed_gwei(
        &mut self,
        debt_amount: u64,
    ) -> Result<(), PersistentConfigError>;
    fn receivable_scan_interval(&self) -> Result<u64, PersistentConfigError>;
    fn set_receivable_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError>;
    fn routing_byte_rate(&self) -> Result<u64, PersistentConfigError>;
    fn set_routing_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError>;
    fn routing_service_rate(&self) -> Result<u64, PersistentConfigError>;
    fn set_routing_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError>;
    fn start_block(&self) -> Result<u64, PersistentConfigError>;
    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError>;
    fn unban_when_balance_below_gwei(&self) -> Result<u64, PersistentConfigError>;
    fn set_unban_when_balance_below_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError>;
    fn set_wallet_info(
        &mut self,
        consuming_wallet_private_key: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError>;
    as_any_dcl!();
}

pub struct PersistentConfigurationReal {
    dao: Box<dyn ConfigDao>,
    scl: SecureConfigLayer,
}

impl PersistentConfiguration for PersistentConfigurationReal {
    fn balance_decreases_for_sec(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "balance_decreases_for_sec")
    }

    fn set_balance_decreases_for_sec(
        &mut self,
        interval: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("balance_decreases_for_sec", interval)
    }

    fn balance_to_decrease_from_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "balance_to_decrease_from_gwei")
    }

    fn set_balance_to_decrease_from_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("balance_to_decrease_from_gwei", level)
    }

    fn blockchain_service_url(&self) -> Result<Option<String>, PersistentConfigError> {
        match self.get("blockchain_service_url")? {
            None => Ok(None),
            Some(url) => Ok(Some(url)),
        }
    }

    fn set_blockchain_service_url(&mut self, url: &str) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        Url::parse(url).map_err(|e| PersistentConfigError::InvalidUrl(e.to_string()))?;
        writer.set("blockchain_service_url", Some(url.to_string()))?;
        Ok(writer.commit()?)
    }

    fn current_schema_version(&self) -> String {
        match self.get("schema_version") {
            Ok(record_opt) => match record_opt {
                None => panic!("Can't continue; current schema version is missing"),
                Some(csv) => csv,
            },
            Err(e) => panic!(
                "Can't continue; current schema version is inaccessible: {:?}",
                e
            ),
        }
    }

    fn chain_name(&self) -> String {
        match self.get("chain_name") {
            Ok(record_opt) => match record_opt {
                None => panic!("Can't continue; chain name is missing"),
                Some(chn) => chn,
            },
            Err(e) => panic!("Can't continue; chain name is inaccessible: {:?}", e),
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

    fn consuming_wallet(&self, db_password: &str) -> Result<Option<Wallet>, PersistentConfigError> {
        self.consuming_wallet_private_key(db_password)
            .map(|key_opt| {
                key_opt.map(|key| match key.from_hex::<Vec<u8>>() {
                    Err(e) => panic!(
                        "Database corruption {:?}: consuming private key is not hex, but '{}'",
                        e, key
                    ),
                    Ok(bytes) => match Bip32ECKeyProvider::from_raw_secret(bytes.as_slice()) {
                        Err(e) => panic!(
                            "Database corruption {:?}: consuming private key is invalid",
                            e
                        ),
                        Ok(pair) => Wallet::from(pair),
                    },
                })
            })
    }

    fn consuming_wallet_private_key(
        &self,
        db_password: &str,
    ) -> Result<Option<String>, PersistentConfigError> {
        let encrypted_value_opt = self.get_record("consuming_wallet_private_key")?.value_opt;
        if let Some(encrypted_value) = encrypted_value_opt {
            match Bip39::decrypt_bytes(&encrypted_value, db_password) {
                Ok(decrypted_bytes) => Ok(Some(decrypted_bytes.as_slice().to_hex())),
                Err(Bip39Error::DecryptionFailure(_)) => Err(PersistentConfigError::PasswordError),
                Err(e) => panic!(
                    "Database corruption {:?}: consuming private key can't be decrypted",
                    e
                ),
            }
        } else {
            Ok(None)
        }
    }

    fn clandestine_port(&self) -> Result<u16, PersistentConfigError> {
        let unchecked_port = match decode_u64(self.get("clandestine_port")?)? {
            None => Self::missing_value_panic("clandestine_port"),
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

    fn earning_wallet(&self) -> Result<Option<Wallet>, PersistentConfigError> {
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
        Ok(self.get("earning_wallet_address")?)
    }

    fn exit_byte_rate(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "exit_byte_rate")
    }

    fn set_exit_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("exit_byte_rate", rate)
    }

    fn exit_service_rate(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "exit_service_rate")
    }

    fn set_exit_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("exit_service_rate", rate)
    }

    fn gas_price(&self) -> Result<u64, PersistentConfigError> {
        match decode_u64(self.get("gas_price")?) {
            Ok(val) => {
                Ok(val.expect("ever-supplied gas_price value missing; database is corrupt!"))
            }
            Err(e) => Err(PersistentConfigError::from(e)),
        }
    }

    fn set_gas_price(&mut self, gas_price: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("gas_price", gas_price)
    }

    fn mapping_protocol(&self) -> Result<Option<AutomapProtocol>, PersistentConfigError> {
        let result = self
            .get("mapping_protocol")?
            .map(|val| AutomapProtocol::from_str(&val));
        match result {
            None => Ok(None),
            Some(Ok(protocol)) => Ok(Some(protocol)),
            Some(Err(msg)) => Err(PersistentConfigError::DatabaseError(msg)),
        }
    }

    fn set_mapping_protocol(
        &mut self,
        value: Option<AutomapProtocol>,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set("mapping_protocol", value.map(|v| v.to_string()))?;
        Ok(writer.commit()?)
    }

    fn neighborhood_mode(&self) -> Result<NeighborhoodModeLight, PersistentConfigError> {
        NeighborhoodModeLight::from_str(
            self.get("neighborhood_mode")?
                .expect("ever-supplied value is missing: neighborhood-mode; database is corrupt!")
                .as_str(),
        )
        .map_err(PersistentConfigError::UninterpretableValue)
    }

    fn set_neighborhood_mode(
        &mut self,
        value: NeighborhoodModeLight,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("neighborhood_mode", value)
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        let bytes_opt = decode_bytes(self.scl.decrypt(
            self.get_record("past_neighbors")?,
            Some(db_password.to_string()),
            &self.dao,
        )?)?;
        match bytes_opt {
            None => Ok (None),
            Some (bytes) => Ok(Some(serde_cbor::de::from_slice::<Vec<NodeDescriptor>>(bytes.as_slice())
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

    fn payable_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "payable_scan_interval")
    }

    fn set_payable_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("payable_scan_interval", interval_sec)
    }

    fn payment_grace_before_ban_sec(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "payment_grace_before_ban_sec")
    }

    fn set_payment_grace_before_ban_sec(
        &mut self,
        interval: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("payment_grace_before_ban_sec", interval)
    }

    fn payment_suggested_after_sec(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "payment_suggested_after_sec")
    }

    fn set_payment_suggested_after_sec(
        &mut self,
        interval: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("payment_suggested_after_sec", interval)
    }

    fn pending_payment_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "pending_payment_scan_interval")
    }

    fn set_pending_payment_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("pending_payment_scan_interval", interval_sec)
    }

    fn permanent_debt_allowed_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "permanent_debt_allowed_gwei")
    }

    fn set_permanent_debt_allowed_gwei(
        &mut self,
        amount: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("permanent_debt_allowed_gwei", amount)
    }

    fn receivable_scan_interval(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "receivable_scan_interval")
    }

    fn set_receivable_scan_interval(
        &mut self,
        interval_sec: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("receivable_scan_interval", interval_sec)
    }

    fn routing_byte_rate(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "routing_byte_rate")
    }

    fn set_routing_byte_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("routing_byte_rate", rate)
    }

    fn routing_service_rate(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "routing_service_rate")
    }

    fn set_routing_service_rate(&mut self, rate: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("routing_service_rate", rate)
    }

    fn start_block(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "start_block")
    }

    fn set_start_block(&mut self, value: u64) -> Result<(), PersistentConfigError> {
        self.simple_set_method("start_block", value)
    }

    fn unban_when_balance_below_gwei(&self) -> Result<u64, PersistentConfigError> {
        self.simple_get_method(decode_u64, "unban_when_balance_below_gwei")
    }

    fn set_unban_when_balance_below_gwei(
        &mut self,
        level: u64,
    ) -> Result<(), PersistentConfigError> {
        self.simple_set_method("unban_when_balance_below_gwei", level)
    }

    fn set_wallet_info(
        &mut self,
        consuming_wallet_private_key: &str,
        earning_wallet_address: &str,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        let consuming_wallet_private_key_opt = self.consuming_wallet_private_key(db_password)?;
        match consuming_wallet_private_key_opt {
            None => (),
            Some(existing_consuming_wallet_private_key) => {
                if consuming_wallet_private_key.to_uppercase()
                    != existing_consuming_wallet_private_key.to_uppercase()
                {
                    return Err(PersistentConfigError::Collision(
                        "Consuming wallet private key already populated; cannot replace"
                            .to_string(),
                    ));
                }
            }
        }
        let earning_wallet_address_opt = self.earning_wallet_address()?;
        match earning_wallet_address_opt {
            None => (),
            Some(existing_earning_wallet_address) => {
                if earning_wallet_address != existing_earning_wallet_address {
                    return Err(PersistentConfigError::Collision(
                        "Earning wallet address already populated; cannot replace".to_string(),
                    ));
                }
            }
        }
        let encrypted_consuming_wallet_private_key =
            Self::encrypt_private_key(consuming_wallet_private_key, db_password)?;
        if !Self::validate_wallet_address(earning_wallet_address) {
            return Err(PersistentConfigError::BadAddressFormat(
                earning_wallet_address.to_string(),
            ));
        }
        let mut writer = self.dao.start_transaction()?;
        writer.set(
            "consuming_wallet_private_key",
            Some(encrypted_consuming_wallet_private_key),
        )?;
        writer.set(
            "earning_wallet_address",
            Some(earning_wallet_address.to_string()),
        )?;
        Ok(writer.commit()?)
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
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

    fn encrypt_private_key(
        private_key: &str,
        db_password: &str,
    ) -> Result<String, PersistentConfigError> {
        let private_key_bytes = match private_key.from_hex::<Vec<u8>>() {
            Ok(bytes) => bytes,
            Err(_) => return Err(PersistentConfigError::BadHexFormat(private_key.to_string())),
        };
        Bip39::encrypt_bytes(&private_key_bytes, db_password)
            .map_err(|e| panic!("Failure to encrypt consuming private key: {:?}", e))
    }

    fn validate_wallet_address(address: &str) -> bool {
        Wallet::from_str(address).is_ok()
    }

    fn get(&self, name: &str) -> Result<Option<String>, ConfigDaoError> {
        self.get_record(name).map(|record| record.value_opt)
    }

    fn get_record(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        self.dao.get (name).map (|record| if record.name.as_str() == name {
            record
        }
        else {
            panic! ("ConfigDao (or more likely ConfigDaoMock) returned record for '{}' when asked for '{}'",
                    record.name, name)
        })
    }

    fn simple_set_method<T: Display>(
        &mut self,
        parameter_name: &str,
        value: T,
    ) -> Result<(), PersistentConfigError> {
        let mut writer = self.dao.start_transaction()?;
        writer.set(parameter_name, Some(value.to_string()))?;
        Ok(writer.commit()?)
    }

    fn simple_get_method<T>(
        &self,
        decoder: fn(Option<String>) -> Result<Option<T>, TypedConfigLayerError>,
        parameter: &str,
    ) -> Result<T, PersistentConfigError> {
        match decoder(self.get(parameter)?)? {
            None => Self::missing_value_panic(parameter),
            Some(rate) => Ok(rate),
        }
    }

    fn missing_value_panic(parameter_name: &str) -> ! {
        panic!(
            "ever-supplied value missing: {}; database is corrupt!",
            parameter_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::database::db_migrations::MigratorConfig;
    use crate::db_config::config_dao::ConfigDaoRecord;
    use crate::db_config::mocks::{ConfigDaoMock, ConfigDaoWriteableMock};
    use crate::db_config::secure_config_layer::EXAMPLE_ENCRYPTED;
    use crate::test_utils::main_cryptde;
    use bip39::{Language, MnemonicType};
    use lazy_static::lazy_static;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::{derivation_path, find_free_port};
    use paste::paste;
    use std::convert::TryFrom;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tiny_hderive::bip32::ExtendedPrivKey;

    lazy_static! {
        static ref CONFIG_TABLE_PARAMETERS: Vec<String> = list_of_config_parameters();
    }

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

        assert_eq!(result, "1.2.3".to_string());
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["schema_version".to_string()]);
    }

    #[test]
    fn chain_name() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "chain_name",
                Some("mainnet"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.chain_name();

        assert_eq!(result, "mainnet".to_string(),);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["chain_name".to_string()]);
    }

    #[test]
    #[should_panic(expected = "Can't continue; chain name is inaccessible: NotPresent")]
    fn chain_name_panics_if_record_is_missing() {
        let config_dao = ConfigDaoMock::new().get_result(Err(ConfigDaoError::NotPresent));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.chain_name();
    }

    #[test]
    #[should_panic(expected = "Can't continue; chain name is missing")]
    fn chain_name_panics_if_record_is_empty() {
        let config_dao =
            ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new("chain_name", None, false)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.chain_name();
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
        expected = "ever-supplied value missing: clandestine_port; database is corrupt!"
    )]
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
    fn blockchain_service_success() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "blockchain_service_url",
            Some("https://ifura.io/ID"),
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.blockchain_service_url().unwrap();

        assert_eq!(result, Some("https://ifura.io/ID".to_string()));
    }

    #[test]
    fn blockchain_service_allows_none_value() {
        let config_dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            "blockchain_service_url",
            None,
            false,
        )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.blockchain_service_url().unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn set_blockchain_service_works() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .set_params(&set_params_arc)
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_blockchain_service_url("https://ifura.io/ID");

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "blockchain_service_url".to_string(),
                Some("https://ifura.io/ID".to_string())
            )]
        );
    }

    #[test]
    fn set_blockchain_service_complains_if_invalid_url() {
        let writer = Box::new(
            ConfigDaoWriteableMock::new()
                .set_result(Ok(()))
                .commit_result(Ok(())),
        );
        let config_dao = Box::new(ConfigDaoMock::new().start_transaction_result(Ok(writer)));
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_blockchain_service_url("https.ifura.io");

        assert_eq!(
            result,
            Err(PersistentConfigError::InvalidUrl(
                "relative URL without a base".to_string()
            ))
        );
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
    fn consuming_wallet_private_key_when_password_is_wrong() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let consuming_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "consuming_wallet_private_key",
                Some(
                    &Bip39::encrypt_bytes(
                        &consuming_private_key
                            .from_hex::<Vec<u8>>()
                            .unwrap()
                            .as_slice(),
                        "password",
                    )
                    .unwrap(),
                ),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new("example_encrypted", None, true)));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet_private_key("incorrect");

        assert_eq!(result, Err(PersistentConfigError::PasswordError));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec!["consuming_wallet_private_key".to_string()]
        );
    }

    #[test]
    fn consuming_wallet_private_key_when_password_is_right() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let example_encrypted = Bip39::encrypt_bytes(
            b"Aside from that, Mrs. Lincoln, how was the play?",
            "password",
        )
        .unwrap();
        let consuming_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "consuming_wallet_private_key",
                Some(
                    &Bip39::encrypt_bytes(
                        &consuming_private_key
                            .from_hex::<Vec<u8>>()
                            .unwrap()
                            .as_slice(),
                        "password",
                    )
                    .unwrap(),
                ),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "example_encrypted",
                Some(&example_encrypted),
                true,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject
            .consuming_wallet_private_key("password")
            .unwrap()
            .unwrap();

        assert_eq!(
            result.to_uppercase(),
            consuming_private_key.to_string().to_uppercase()
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec!["consuming_wallet_private_key".to_string()]
        );
    }

    #[test]
    fn consuming_wallet() {
        let example_encrypted = Bip39::encrypt_bytes(
            b"Aside from that, Mrs. Lincoln, how was the play?",
            "password",
        )
        .unwrap();
        let consuming_private_key =
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let consuming_wallet = Wallet::from(
            Bip32ECKeyProvider::from_raw_secret(
                consuming_private_key
                    .from_hex::<Vec<u8>>()
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
        );
        let config_dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                "consuming_wallet_private_key",
                Some(
                    &Bip39::encrypt_bytes(
                        &consuming_private_key
                            .from_hex::<Vec<u8>>()
                            .unwrap()
                            .as_slice(),
                        "password",
                    )
                    .unwrap(),
                ),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "example_encrypted",
                Some(&example_encrypted),
                true,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.consuming_wallet("password").unwrap().unwrap();

        assert_eq!(result.address(), consuming_wallet.address());
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
    fn earning_wallet_if_address_is_missing() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                None,
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.earning_wallet().unwrap();

        assert_eq!(result, None);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
    }

    #[test]
    #[should_panic(
        expected = "Database corrupt: invalid earning wallet address '123456invalid': InvalidAddress"
    )]
    fn earning_wallet_if_address_is_set_and_invalid() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                Some("123456invalid"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let _ = subject.earning_wallet();
    }

    #[test]
    fn earning_wallet_if_address_is_set_and_valid() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "earning_wallet_address",
                Some("0x7d6dabd6b5c75291a3258c29b418f5805792a875"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.earning_wallet().unwrap();

        assert_eq!(
            result,
            Some(Wallet::from_str("0x7d6dabd6b5c75291a3258c29b418f5805792a875").unwrap())
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["earning_wallet_address".to_string()]);
    }

    fn make_seed_info(db_password: &str) -> (PlainData, String) {
        let mnemonic = Bip39::mnemonic(MnemonicType::Words12, Language::English);
        let mnemonic_seed = Bip39::seed(&mnemonic, "");
        let seed_bytes = PlainData::new(mnemonic_seed.as_ref());
        let encoded_seed = encode_bytes(Some(seed_bytes.clone())).unwrap().unwrap();
        let encrypted_seed = Bip39::encrypt_bytes(&encoded_seed.as_bytes(), db_password).unwrap();
        (seed_bytes, encrypted_seed)
    }

    fn make_wallet_info(db_password: &str) -> (String, String, String) {
        let (seed_bytes, _) = make_seed_info(db_password);
        let derivation_path = derivation_path(0, 1);
        let consuming_epk =
            ExtendedPrivKey::derive(seed_bytes.as_slice(), derivation_path.as_str()).unwrap();
        let consuming_wallet_private_key = consuming_epk.secret().to_hex::<String>().to_uppercase();
        let consuming_wallet_private_key_encrypted =
            make_encrypted_consuming_wallet_private_key(&consuming_wallet_private_key, db_password);
        let earning_private_key =
            ExtendedPrivKey::derive(seed_bytes.as_slice(), derivation_path.as_str()).unwrap();
        let earning_key_pair =
            Bip32ECKeyProvider::from_raw_secret(&earning_private_key.secret()).unwrap();
        let earning_wallet = Wallet::from(earning_key_pair);
        let earning_wallet_address = earning_wallet.to_string();
        (
            consuming_wallet_private_key,
            consuming_wallet_private_key_encrypted,
            earning_wallet_address,
        )
    }

    fn make_encrypted_consuming_wallet_private_key(
        consuming_wallet_private_key: &str,
        db_password: &str,
    ) -> String {
        Bip39::encrypt_bytes(
            &consuming_wallet_private_key
                .from_hex::<Vec<u8>>()
                .unwrap()
                .as_slice(),
            db_password,
        )
        .unwrap()
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
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    None,
                    true,
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
                .start_transaction_result(Ok(writer)),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (consuming_wallet_private_key, _, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &consuming_wallet_private_key,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![
                "consuming_wallet_private_key".to_string(),
                "earning_wallet_address".to_string(),
            ]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(set_params[0].0, "consuming_wallet_private_key".to_string());
        let cwpk_decrypted = Bip39::decrypt_bytes(set_params[0].1.as_ref().unwrap(), "password")
            .unwrap()
            .as_slice()
            .to_hex::<String>()
            .to_uppercase();
        assert_eq!(cwpk_decrypted, consuming_wallet_private_key);
        assert_eq!(
            set_params[1],
            (
                "earning_wallet_address".to_string(),
                Some(earning_wallet_address)
            )
        );
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![()]);
    }

    #[test]
    fn set_wallet_info_fails_if_consuming_wallet_private_key_exists() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let example_encrypted = Bip39::encrypt_bytes(&example, "password").unwrap();
        let old_cwpk_encrypted = make_encrypted_consuming_wallet_private_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "password",
        );
        let (consuming_wallet_private_key, _, earning_wallet_address) =
            make_wallet_info("password");

        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    Some(&old_cwpk_encrypted),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&example_encrypted),
                    true,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_wallet_info(
            &consuming_wallet_private_key,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(
            result,
            Err(PersistentConfigError::Collision(
                "Consuming wallet private key already populated; cannot replace".to_string()
            ))
        );
    }

    #[test]
    fn set_wallet_info_fails_if_earning_wallet_address_exists() {
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    None,
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    Some("0x0123456789012345678901234567890123456789"),
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (consuming_wallet_private_key, _, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &consuming_wallet_private_key,
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
        let (
            consuming_wallet_private_key,
            consuming_wallet_private_key_encrypted,
            earning_wallet_address,
        ) = make_wallet_info("password");
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    Some(&consuming_wallet_private_key_encrypted),
                    true,
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
                .start_transaction_result(Ok(writer)),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);

        let result = subject.set_wallet_info(
            &consuming_wallet_private_key,
            &earning_wallet_address,
            "password",
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn set_wallet_info_fails_if_earning_wallet_address_is_invalid() {
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    None,
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "earning_wallet_address",
                    None,
                    false,
                ))),
        );
        let mut subject = PersistentConfigurationReal::new(config_dao);
        let (consuming_wallet_private_key, _, _) = make_wallet_info("password");

        let result = subject.set_wallet_info(&consuming_wallet_private_key, "invalid", "password");

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
                .set_result(Err(ConfigDaoError::NotPresent))
                .commit_params(&commit_params_arc),
        );
        let config_dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(
                    "consuming_wallet_private_key",
                    None,
                    true,
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
        let (consuming_wallet_private_key, _, earning_wallet_address) =
            make_wallet_info("password");

        let result = subject.set_wallet_info(
            &consuming_wallet_private_key,
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
    #[should_panic(expected = "ever-supplied value missing: start_block; database is corrupt!")]
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
    #[should_panic(expected = "ever-supplied gas_price value missing; database is corrupt!")]
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
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AQIDBA@1.2.3.4:1234"))
                .unwrap(),
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"))
                .unwrap(),
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
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-mainnet:AQIDBA@1.2.3.4:1234"))
                .unwrap(),
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-ropsten:AgMEBQ@2.3.4.5:2345"))
                .unwrap(),
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
    fn mapping_protocol_works() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "mapping_protocol",
                Some("PCP"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.mapping_protocol().unwrap();

        assert_eq!(result.unwrap(), AutomapProtocol::Pcp);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["mapping_protocol".to_string()]);
    }

    #[test]
    fn set_mapping_protocol_to_some() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoWriteableMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result(Ok(()));
        let mut subject = PersistentConfigurationReal::new(Box::new(
            ConfigDaoMock::new().start_transaction_result(Ok(Box::new(config_dao))),
        ));

        let result = subject.set_mapping_protocol(Some(AutomapProtocol::Pmp));

        assert!(result.is_ok());
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("mapping_protocol".to_string(), Some("PMP".to_string()))]
        );
    }

    #[test]
    fn set_mapping_protocol_to_none() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoWriteableMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result(Ok(()));
        let mut subject = PersistentConfigurationReal::new(Box::new(
            ConfigDaoMock::new().start_transaction_result(Ok(Box::new(config_dao))),
        ));

        let result = subject.set_mapping_protocol(None);

        assert!(result.is_ok());
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params, vec![("mapping_protocol".to_string(), None)]);
    }

    #[test]
    fn neighborhood_mode_works() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                "neighborhood_mode",
                Some("standard"),
                false,
            )));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        let result = subject.neighborhood_mode().unwrap();

        assert_eq!(result, NeighborhoodModeLight::Standard);
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec!["neighborhood_mode".to_string()]);
    }

    #[test]
    fn set_neighborhood_mode_works() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let config_dao = ConfigDaoWriteableMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .commit_result(Ok(()));
        let mut subject = PersistentConfigurationReal::new(Box::new(
            ConfigDaoMock::new().start_transaction_result(Ok(Box::new(config_dao))),
        ));

        let result = subject.set_neighborhood_mode(NeighborhoodModeLight::ConsumeOnly);

        assert!(result.is_ok());
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "neighborhood_mode".to_string(),
                Some("consume-only".to_string())
            )]
        );
    }

    macro_rules! persistent_config_plain_data_assertions_for_simple_get_method {
        ($parameter_name: literal,$expected_value: expr) => {
            paste! {
                let get_params_arc = Arc::new(Mutex::new(vec![]));
                let config_dao = ConfigDaoMock::new()
                    .get_params(&get_params_arc)
                    .get_result(Ok(ConfigDaoRecord::new(
                        $parameter_name,
                        Some($expected_value.to_string().as_str()),
                        false,
                    )));
                let subject = PersistentConfigurationReal::new(Box::new(config_dao));

                let result = subject.[<$parameter_name>]().unwrap();

                assert_eq!(result, $expected_value);
                let get_params = get_params_arc.lock().unwrap();
                assert_eq!(*get_params, vec![$parameter_name.to_string()]);
            }
            assert_eq!(
                CONFIG_TABLE_PARAMETERS
                    .iter()
                    .filter(|parameter_name| parameter_name.as_str() == $parameter_name)
                    .count(),
                1
            )
        };
    }

    macro_rules! persistent_config_plain_data_assertions_for_simple_set_method {
        ($parameter_name: literal,$set_value: expr) => {
            paste! {
                let set_params_arc = Arc::new(Mutex::new(vec![]));
                let config_dao = ConfigDaoWriteableMock::new()
                    .set_params(&set_params_arc)
                    .set_result(Ok(()))
                    .commit_result(Ok(()));
                let mut subject = PersistentConfigurationReal::new(Box::new(
                    ConfigDaoMock::new().start_transaction_result(Ok(Box::new(config_dao))),
                ));

                let result = subject.[<set_ $parameter_name>]($set_value);

                assert!(result.is_ok());
                let set_params = set_params_arc.lock().unwrap();
                assert_eq!(
                    *set_params,
                    vec![(
                        $parameter_name.to_string(),
                        Some($set_value.to_string())
                    )]
                );
            }
        };
    }

    macro_rules! getter_method_plain_data_does_not_tolerate_none_value {
        ($parameter_name: literal) => {
            paste! {
                let config_dao = ConfigDaoMock::new()
                    .get_result(Ok(ConfigDaoRecord::new(
                        $parameter_name,
                        None,
                        false,
                    )));
                let subject = PersistentConfigurationReal::new(Box::new(config_dao));

                let _ = subject.[<$parameter_name>]();
            }
        };
    }

    #[test]
    fn routing_byte_rate_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!("routing_byte_rate", 1234);
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: routing_byte_rate; database is corrupt!"
    )]
    fn routing_byte_rate_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("routing_byte_rate");
    }

    #[test]
    fn set_routing_byte_rate_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!("routing_byte_rate", 4321);
    }

    #[test]
    fn routing_service_rate_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "routing_service_rate",
            1212
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: routing_service_rate; database is corrupt!"
    )]
    fn routing_service_rate_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("routing_service_rate");
    }

    #[test]
    fn set_routing_service_rate_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "routing_service_rate",
            4444
        );
    }

    #[test]
    fn exit_byte_rate_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!("exit_byte_rate", 5);
    }

    #[test]
    #[should_panic(expected = "ever-supplied value missing: exit_byte_rate; database is corrupt!")]
    fn exit_byte_rate_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("exit_byte_rate");
    }

    #[test]
    fn set_exit_byte_rate_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!("exit_byte_rate", 6);
    }

    #[test]
    fn exit_service_rate_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!("exit_service_rate", 9);
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: exit_service_rate; database is corrupt!"
    )]
    fn exit_service_rate_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("exit_service_rate");
    }

    #[test]
    fn set_exit_service_rate_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!("exit_service_rate", 8);
    }

    #[test]
    fn balance_decreases_for_sec_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "balance_decreases_for_sec",
            1234
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: balance_decreases_for_sec; database is corrupt!"
    )]
    fn balance_decreases_for_sec_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("balance_decreases_for_sec");
    }

    #[test]
    fn set_balance_decreases_for_sec_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "balance_decreases_for_sec",
            3333
        );
    }

    #[test]
    fn balance_to_decrease_from_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "balance_to_decrease_from_gwei",
            1234
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: balance_to_decrease_from_gwei; database is corrupt!"
    )]
    fn balance_to_decrease_from_gwei_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("balance_to_decrease_from_gwei");
    }

    #[test]
    fn set_balance_to_decrease_from_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "balance_to_decrease_from_gwei",
            2222
        );
    }

    #[test]
    fn payable_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "payable_scan_interval",
            3600
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: payable_scan_interval; database is corrupt!"
    )]
    fn payable_scan_interval_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("payable_scan_interval");
    }

    #[test]
    fn set_payable_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "payable_scan_interval",
            2255
        );
    }

    #[test]
    fn pending_payment_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "pending_payment_scan_interval",
            3600
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: pending_payment_scan_interval; database is corrupt!"
    )]
    fn pending_payment_scan_interval_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("pending_payment_scan_interval");
    }

    #[test]
    fn set_pending_payment_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "pending_payment_scan_interval",
            1133
        );
    }

    #[test]
    fn receivable_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "receivable_scan_interval",
            3600
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: receivable_scan_interval; database is corrupt!"
    )]
    fn receivable_scan_interval_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("receivable_scan_interval");
    }

    #[test]
    fn set_receivable_scan_interval_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "receivable_scan_interval",
            2222
        );
    }

    #[test]
    fn payment_grace_before_ban_sec_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "payment_grace_before_ban_sec",
            10000
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: payment_grace_before_ban_sec; database is corrupt!"
    )]
    fn payment_grace_before_ban_sec_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("payment_grace_before_ban_sec");
    }

    #[test]
    fn set_payment_grace_before_ban_sec_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "payment_grace_before_ban_sec",
            3444
        );
    }

    #[test]
    fn permanent_debt_allowed_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "permanent_debt_allowed_gwei",
            100000
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: permanent_debt_allowed_gwei; database is corrupt!"
    )]
    fn permanent_debt_allowed_gwei_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("permanent_debt_allowed_gwei");
    }

    #[test]
    fn set_permanent_debt_allowed_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "permanent_debt_allowed_gwei",
            3333
        );
    }

    #[test]
    fn unban_when_balance_below_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "unban_when_balance_below_gwei",
            100000
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: unban_when_balance_below_gwei; database is corrupt!"
    )]
    fn unban_when_balance_below_gwei_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("unban_when_balance_below_gwei");
    }

    #[test]
    fn set_unban_when_balance_below_gwei_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "unban_when_balance_below_gwei",
            111111
        );
    }

    #[test]
    fn payment_suggested_after_sec_works() {
        persistent_config_plain_data_assertions_for_simple_get_method!(
            "payment_suggested_after_sec",
            7200
        );
    }

    #[test]
    #[should_panic(
        expected = "ever-supplied value missing: payment_suggested_after_sec; database is corrupt!"
    )]
    fn payment_suggested_after_sec_panics_at_none_value() {
        getter_method_plain_data_does_not_tolerate_none_value!("payment_suggested_after_sec");
    }

    #[test]
    fn set_payment_suggested_after_sec_works() {
        persistent_config_plain_data_assertions_for_simple_set_method!(
            "payment_suggested_after_sec",
            8000
        );
    }

    fn list_of_config_parameters() -> Vec<String> {
        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "current_config_table_schema",
        );
        let db_conn = DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::test_default())
            .unwrap();
        let mut statement = db_conn.prepare("select name from config").unwrap();
        statement
            .query_map([], |row| Ok(row.get(0).unwrap()))
            .unwrap()
            .flatten()
            .collect()
    }
}
