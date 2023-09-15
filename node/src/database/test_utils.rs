// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::connection_wrapper::{ConnectionWrapper, TransactionWrapper};
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use rusqlite::{Connection, Error, Statement, ToSql};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct ConnectionWrapperMock<'a> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
    transaction_results: RefCell<Vec<Result<Box<dyn TransactionWrapper + 'a>, Error>>>,
}

unsafe impl<'a> Send for ConnectionWrapperMock<'a> {}

impl<'a> ConnectionWrapperMock<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
        self.prepare_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_result(
        self,
        result: Result<Box<dyn TransactionWrapper + 'a>, Error>,
    ) -> Self {
        self.transaction_results.borrow_mut().push(result);
        self
    }
}

impl<'a> ConnectionWrapper for ConnectionWrapperMock<'a> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(String::from(query));
        self.prepare_results.borrow_mut().remove(0)
    }

    fn transaction<'b>(&'b mut self) -> Result<Box<dyn TransactionWrapper + 'b>, Error> {
        self.transaction_results.borrow_mut().remove(0)
    }
}

#[derive(Debug)]
pub struct StatementWithLivingConn {
    conn: Connection,
    statement: Statement<'static>,
}

impl StatementWithLivingConn {
    pub fn new((conn, statement): (Connection, Statement<'static>)) -> Self {
        Self { conn, statement }
    }
}

#[derive(Debug, Default)]
pub struct TransactionWrapperMock<'a> {
    prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
}

impl<'a> TransactionWrapperMock<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    // pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
    //     self.prepare_params = params.clone();
    //     self
    // }
    //
    pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
        self.prepare_results.borrow_mut().push(result);
        self
    }
    //
    pub fn commit_result(self, result: Result<(), Error>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}

impl<'a> TransactionWrapper for TransactionWrapperMock<'a> {
    fn prepare(&self, _query: &str) -> Result<Statement, Error> {
        todo!() // Ok(self.prepare_results.borrow_mut().get(0).unwrap().unwrap().statement)
    }

    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        todo!()
    }

    fn commit(&mut self) -> Result<(), Error> {
        todo!()
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
