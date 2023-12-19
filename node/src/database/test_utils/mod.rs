// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]
pub mod transaction_wrapper_mock;

use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, SecureTransactionWrapper};
use rusqlite::{Error, Statement};
use std::cell::RefCell;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct ConnectionWrapperMock<'conn> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: RefCell<Vec<Result<Statement<'conn>, Error>>>,
    transaction_results: RefCell<Vec<Result<SecureTransactionWrapper<'conn>, Error>>>,
}

unsafe impl<'a> Send for ConnectionWrapperMock<'a> {}

impl<'conn> ConnectionWrapperMock<'conn> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_result(self, result: Result<Statement<'conn>, Error>) -> Self {
        self.prepare_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_result(
        self,
        result: Result<SecureTransactionWrapper<'conn>, Error>,
    ) -> Self {
        self.transaction_results.borrow_mut().push(result);
        self
    }
}

impl ConnectionWrapper for ConnectionWrapperMock<'_> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(String::from(query));
        self.prepare_results.borrow_mut().remove(0)
    }

    fn transaction(&mut self) -> Result<SecureTransactionWrapper, Error> {
        self.transaction_results.borrow_mut().remove(0)
    }
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

    #[allow(unused_variables)]
    fn initialize_to_version(
        &self,
        path: &Path,
        target_version: usize,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        intentionally_blank!()
        /*all existing test calls only initialize() in the mocked version,
        but we need to call initialize_to_version() for the real object
        in order to carry out some important tests too*/
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
