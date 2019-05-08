// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::config_dao::ConfigDao;
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
}

pub struct PersistentConfigurationReal {
    dao: Box<ConfigDao>,
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
            panic! ("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine_port <p> where <p> is an unused port.",
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
                unchecked_port
            );
        }
        let port = unchecked_port as u16;
        match TcpListener::bind (SocketAddrV4::new (Ipv4Addr::from (0), port)) {
            Ok (_) => port,
            Err (_) => panic! ("Can't continue; clandestine port {} is in use. Specify --clandestine_port <p> where <p> is an unused port between {} and {}.",
                port,
                LOWEST_USABLE_INSECURE_PORT,
                HIGHEST_USABLE_PORT,
            )
        }
    }

    fn set_clandestine_port(&self, port: u16) {
        if port < LOWEST_USABLE_INSECURE_PORT {
            panic! ("Can't continue; clandestine port configuration is incorrect. Must be between {} and {}, not {}. Specify --clandestine_port <p> where <p> is an unused port.",
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
}

impl PersistentConfigurationReal {
    pub fn new(config_dao: Box<ConfigDao>) -> PersistentConfigurationReal {
        PersistentConfigurationReal { dao: config_dao }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_dao::ConfigDaoError;
    use std::cell::RefCell;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
    use std::sync::{Arc, Mutex};

    pub struct ConfigDaoMock {
        get_string_params: Arc<Mutex<Vec<String>>>,
        get_string_results: RefCell<Vec<Result<String, ConfigDaoError>>>,
        set_string_params: Arc<Mutex<Vec<(String, String)>>>,
        set_string_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
        get_u64_params: Arc<Mutex<Vec<String>>>,
        get_u64_results: RefCell<Vec<Result<u64, ConfigDaoError>>>,
        set_u64_params: Arc<Mutex<Vec<(String, u64)>>>,
        set_u64_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    }

    impl ConfigDao for ConfigDaoMock {
        fn get_string(&self, name: &str) -> Result<String, ConfigDaoError> {
            self.get_string_params
                .lock()
                .unwrap()
                .push(String::from(name));
            self.get_string_results.borrow_mut().remove(0)
        }

        fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError> {
            self.set_string_params
                .lock()
                .unwrap()
                .push((String::from(name), String::from(value)));
            self.set_string_results.borrow_mut().remove(0)
        }

        fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError> {
            self.get_u64_params.lock().unwrap().push(String::from(name));
            self.get_u64_results.borrow_mut().remove(0)
        }

        fn set_u64(&self, name: &str, value: u64) -> Result<(), ConfigDaoError> {
            self.set_u64_params
                .lock()
                .unwrap()
                .push((String::from(name), value));
            self.set_u64_results.borrow_mut().remove(0)
        }
    }

    impl ConfigDaoMock {
        pub fn new() -> ConfigDaoMock {
            ConfigDaoMock {
                get_string_params: Arc::new(Mutex::new(vec![])),
                get_string_results: RefCell::new(vec![]),
                set_string_params: Arc::new(Mutex::new(vec![])),
                set_string_results: RefCell::new(vec![]),
                get_u64_params: Arc::new(Mutex::new(vec![])),
                get_u64_results: RefCell::new(vec![]),
                set_u64_params: Arc::new(Mutex::new(vec![])),
                set_u64_results: RefCell::new(vec![]),
            }
        }

        pub fn get_string_params(mut self, params_arc: &Arc<Mutex<Vec<String>>>) -> ConfigDaoMock {
            self.get_string_params = params_arc.clone();
            self
        }

        pub fn get_string_result(self, result: Result<String, ConfigDaoError>) -> ConfigDaoMock {
            self.get_string_results.borrow_mut().push(result);
            self
        }

        #[allow(dead_code)]
        pub fn set_string_params(
            mut self,
            params_arc: &Arc<Mutex<Vec<(String, String)>>>,
        ) -> ConfigDaoMock {
            self.set_string_params = params_arc.clone();
            self
        }

        #[allow(dead_code)]
        pub fn set_string_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
            self.set_string_results.borrow_mut().push(result);
            self
        }

        pub fn get_u64_params(mut self, params_arc: &Arc<Mutex<Vec<String>>>) -> ConfigDaoMock {
            self.get_u64_params = params_arc.clone();
            self
        }

        pub fn get_u64_result(self, result: Result<u64, ConfigDaoError>) -> ConfigDaoMock {
            self.get_u64_results.borrow_mut().push(result);
            self
        }

        pub fn set_u64_params(
            mut self,
            params_arc: &Arc<Mutex<Vec<(String, u64)>>>,
        ) -> ConfigDaoMock {
            self.set_u64_params = params_arc.clone();
            self
        }

        pub fn set_u64_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
            self.set_u64_results.borrow_mut().push(result);
            self
        }
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
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 65536. Specify --clandestine_port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_high() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(65536));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine_port <p> where <p> is an unused port."
    )]
    fn clandestine_port_panics_if_configured_port_is_too_low() {
        let config_dao = ConfigDaoMock::new().get_u64_result(Ok(1024));
        let subject = PersistentConfigurationReal::new(Box::new(config_dao));

        subject.clandestine_port();
    }

    #[test]
    #[should_panic(
        expected = "Can't continue; clandestine port 5333 is in use. Specify --clandestine_port <p> where <p> is an unused port between 1025 and 65535."
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
        expected = "Can't continue; clandestine port configuration is incorrect. Must be between 1025 and 65535, not 1024. Specify --clandestine_port <p> where <p> is an unused port."
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
}
