// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]
pub mod transaction_wrapper_mock;

use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionSafeWrapper};
use rusqlite::{Error, Statement};
use std::cell::RefCell;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SQL_ATTRIBUTES_FOR_CREATING_SENT_PAYABLE: &[&[&str]] = &[
    &["rowid", "integer", "primary", "key"],
    &["tx_hash", "text", "not", "null"],
    &["receiver_address", "text", "not", "null"],
    &["amount_high_b", "integer", "not", "null"],
    &["amount_low_b", "integer", "not", "null"],
    &["timestamp", "integer", "not", "null"],
    &["gas_price_wei_high_b", "integer", "not", "null"],
    &["gas_price_wei_low_b", "integer", "not", "null"],
    &["nonce", "integer", "not", "null"],
    &["block_hash", "text", "null"],
    &["block_number", "integer", "null"],
];

pub const SQL_ATTRIBUTES_FOR_CREATING_FAILED_PAYABLE: &[&[&str]] = &[
    &["rowid", "integer", "primary", "key"],
    &["tx_hash", "text", "not", "null"],
    &["receiver_address", "text", "not", "null"],
    &["amount_high_b", "integer", "not", "null"],
    &["amount_low_b", "integer", "not", "null"],
    &["timestamp", "integer", "not", "null"],
    &["gas_price_wei_high_b", "integer", "not", "null"],
    &["gas_price_wei_low_b", "integer", "not", "null"],
    &["nonce", "integer", "not", "null"],
    &["reason", "text", "not", "null"],
    &["checked", "integer", "not", "null"],
];

#[derive(Debug, Default)]
pub struct ConnectionWrapperMock<'conn> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: RefCell<Vec<Result<Statement<'conn>, Error>>>,
    transaction_results: RefCell<Vec<Result<TransactionSafeWrapper<'conn>, Error>>>,
}

// We don't know better how to deal with the third-party code for `Statement` that inherits
// attributes from `Connection` that lacks the Send marker. This unsafe block instructs the compiler
// we want to enforce it because it is a test utility and as far as we know it hasn't bitten us

unsafe impl<'conn> Send for ConnectionWrapperMock<'conn> {}

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

    pub fn transaction_result(self, result: Result<TransactionSafeWrapper<'conn>, Error>) -> Self {
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

    fn transaction(&mut self) -> Result<TransactionSafeWrapper, Error> {
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
