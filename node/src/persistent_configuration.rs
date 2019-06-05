// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::config_dao::ConfigDao;
use crate::config_dao::ConfigDaoError;
use rusqlite::Transaction;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

pub const LOWEST_USABLE_INSECURE_PORT: u16 = 1025;
pub const HIGHEST_RANDOM_CLANDESTINE_PORT: u16 = 9999;
pub const HIGHEST_USABLE_PORT: u16 = 65535;
pub const HTTP_PORT: u16 = 80;
pub const TLS_PORT: u16 = 443;

pub trait PersistentConfiguration {
    fn current_schema_version(&self) -> String;
    fn clandestine_port(&self) -> u16;
    fn set_clandestine_port(&self, port: u16);
    fn mnemonic_seed(&self) -> Option<String>;
    fn set_mnemonic_seed(&self, seed: String);
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
        if (unchecked_port < LOWEST_USABLE_INSECURE_PORT as u64)
            || (unchecked_port > HIGHEST_USABLE_PORT as u64)
        {
            panic! ("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine-port <p> where <p> is an unused port.",
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
                unchecked_port
            );
        }
        let port = unchecked_port as u16;
        match TcpListener::bind (SocketAddrV4::new (Ipv4Addr::from (0), port)) {
            Ok (_) => port,
            Err (_) => panic! ("Can't continue; clandestine port {} is in use. Specify --clandestine-port <p> where <p> is an unused port between {} and {}.",
                port,
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
            )
        }
    }

    fn set_clandestine_port(&self, port: u16) {
        if port < LOWEST_USABLE_INSECURE_PORT {
            panic! ("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine-port <p> where <p> is an unused port.",
                    LOWEST_USABLE_INSECURE_PORT, HIGHEST_USABLE_PORT, port);
        }
        match self.dao.set_u64("clandestine_port", port as u64) {
            Ok(_) => (),
            Err(e) => panic!(
                "Can't continue; clandestine port configuration is inaccessible: {:?}",
                e
            ),
        }
    }

    fn mnemonic_seed(&self) -> Option<String> {
        match self.dao.get_string("seed") {
            Ok(mnemonic_seed) => Some(mnemonic_seed),
            Err(_) => None,
        }
    }

    fn set_mnemonic_seed(&self, seed: String) {
        match self.dao.set_string("seed", &seed.as_str()) {
            Ok(_) => (),
            Err(e) => panic!(
                "Can't continue; mnemonic seed configuration is inaccessible: {:?}",
                e
            ),
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

impl PersistentConfigurationReal {
    pub fn new(config_dao: Box<ConfigDao>) -> PersistentConfigurationReal {
        PersistentConfigurationReal { dao: config_dao }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::test_utils::config_dao_mock::ConfigDaoMock;
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
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
        expected = "Can't continue; clandestine port 5333 is in use. Specify --clandestine-port <p> where <p> is an unused port between 1025 and 65535."
    )]
    fn clandestine_port_panics_if_configured_port_is_in_use() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(5333));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let _listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), 5333))).unwrap();

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
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Ok("Some encrypted data string".to_string()))
            .get_string_params(&get_string_params_arc);

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let possible_seed = subject.mnemonic_seed();

        assert!(possible_seed.is_some());

        assert_eq!(
            Some("Some encrypted data string".to_string()),
            possible_seed
        );
    }

    #[test]
    fn mnemonic_seed_none_on_error() {
        let get_string_params_arc = Arc::new(Mutex::new(vec!["seed".to_string()]));
        let config_dao = ConfigDaoMock::new()
            .get_string_result(Err(ConfigDaoError::DatabaseError(
                "Invalid column type Null at index: 0".to_string(),
            )))
            .get_string_params(&get_string_params_arc);

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        assert!(subject.mnemonic_seed().is_none());
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
        subject.set_mnemonic_seed("".to_string());
    }

    #[test]
    fn set_mnemonic_seed_succeeds() {
        let expected_params = (
            "seed".to_string(),
            "this is an encrypted string".to_string(),
        );
        let set_string_params_arc = Arc::new(Mutex::new(vec![expected_params.clone()]));
        let config_dao = ConfigDaoMock::new()
            .set_string_params(&set_string_params_arc)
            .set_string_result(Ok(()));

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        subject.set_mnemonic_seed("this is an encrypted string".to_string());

        let set_string_params = set_string_params_arc.lock().unwrap();

        assert_eq!(expected_params, set_string_params[0]);
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
        let mut conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let result = subject.set_start_block_transactionally(&transaction, 1234);

        assert!(result.is_ok());
    }

    #[test]
    fn set_start_block_transactionally_returns_err_when_transaction_fails() {
        let config_dao = ConfigDaoMock::new()
            .set_u64_transactional_result(Err(ConfigDaoError::DatabaseError("nah".to_string())));

        let home_dir = ensure_node_home_directory_exists(
            "persistent_configuration",
            "set_start_block_transactionally_returns_err_when_transaction_fails",
        );
        let mut conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));
        let result = subject.set_start_block_transactionally(&transaction, 1234);

        assert_eq!(Err(r#"DatabaseError("nah")"#.to_string()), result);
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
        let mut conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
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
        let mut conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
        let transaction = conn.transaction().unwrap();

        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject
            .set_start_block_transactionally(&transaction, 1234)
            .unwrap();
    }
}
