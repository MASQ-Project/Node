#![cfg(test)]
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{DbInitializationConfig, ExternalData, InitializationMode};
use crate::database::db_initializer::{DbInitializer, InitializationError};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use masq_lib::constants::TEST_DEFAULT_CHAIN;
use masq_lib::utils::NeighborhoodModeLight;
use rusqlite::Transaction;
use rusqlite::{Error, Statement};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};

impl DbInitializationConfig {
    pub fn test_default() -> Self {
        Self {
            mode: InitializationMode::CreationAndMigration {
                external_data: ExternalData {
                    chain: TEST_DEFAULT_CHAIN,
                    neighborhood_mode: NeighborhoodModeLight::Standard,
                    db_password_opt: None,
                },
            },
            special_conn_configuration: vec![],
        }
    }
}

#[derive(Debug, Default)]
pub struct ConnectionWrapperMock<'b, 'a: 'b> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
    transaction_results: RefCell<Vec<Result<Transaction<'b>, Error>>>,
    arbitrary_id_stamp_opt: RefCell<Option<ArbitraryIdStamp>>,
}

unsafe impl<'a: 'b, 'b> Send for ConnectionWrapperMock<'a, 'b> {}

impl<'a: 'b, 'b> ConnectionWrapperMock<'a, 'b> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
        self.prepare_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_result(self, result: Result<Transaction<'b>, Error>) -> Self {
        self.transaction_results.borrow_mut().push(result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

impl<'a: 'b, 'b> ConnectionWrapper for ConnectionWrapperMock<'a, 'b> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(String::from(query));
        self.prepare_results.borrow_mut().remove(0)
    }

    fn transaction<'_a: '_b, '_b>(&'_a mut self) -> Result<Transaction<'_b>, Error> {
        self.transaction_results.borrow_mut().remove(0)
    }

    arbitrary_id_stamp_in_trait_impl!();
}

#[derive(Default)]
pub struct DbInitializerMock {
    pub initialize_params: Arc<Mutex<Vec<(PathBuf, DbInitializationConfig)>>>,
    pub initialize_results: RefCell<Vec<Result<Box<dyn ConnectionWrapper>, InitializationError>>>,
}

impl DbInitializer for DbInitializerMock {
    fn initialize(
        &self,
        path: &Path,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        self.initialize_params
            .lock()
            .unwrap()
            .push((path.to_path_buf(), init_config));
        self.initialize_results.borrow_mut().remove(0)
    }

    fn initialize_to_version(
        &self,
        _path: &Path,
        _target_version: usize,
        _init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        intentionally_blank!()
        /* all existing tests call only initialize() in the mocked version,
        but we need to call initialize_to_version() for the real object
        in order to carry out some important tests too */
    }
}

impl DbInitializerMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize_parameters(
        mut self,
        parameters: Arc<Mutex<Vec<(PathBuf, DbInitializationConfig)>>>,
    ) -> DbInitializerMock {
        self.initialize_params = parameters;
        self
    }

    pub fn initialize_result(
        self,
        result: Result<Box<dyn ConnectionWrapper>, InitializationError>,
    ) -> DbInitializerMock {
        self.initialize_results.borrow_mut().push(result);
        self
    }
}
