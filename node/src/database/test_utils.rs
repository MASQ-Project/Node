// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionWrapper};
use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use rusqlite::{Connection, Error, Statement, ToSql};
use std::cell::RefCell;
use std::fmt::{Debug, Formatter};
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

pub trait StatementProducer: Debug {
    fn statement(&self) -> Statement;
}

impl StatementProducer for ActiveStatementProducer {
    fn statement(&self) -> Statement {
        self.conn.prepare(&self.sql_stm).unwrap()
    }
}

pub struct ActiveStatementProducer {
    conn: Connection,
    sql_stm: String,
}

impl Debug for ActiveStatementProducer {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        unimplemented!("not needed yet")
    }
}

impl ActiveStatementProducer {
    pub fn new(conn: Connection, sql_stm: String) -> Self {
        Self { conn, sql_stm }
    }
}

#[derive(Default)]
struct PrepareResults {
    producers: Vec<(ActiveStatementProducer, usize)>,
    errors: RefCell<Vec<(Error, usize)>>,
    idx_during_filling: usize,
    next_result_idx: RefCell<usize>,
}

#[derive(Default)]
pub struct TransactionWrapperMock {
    prepare_results: PrepareResults,
    commit_results: RefCell<Vec<Result<(), Error>>>,
}

impl Debug for TransactionWrapperMock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unimplemented!("not needed yet")
    }
}

impl TransactionWrapperMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_result(mut self, result: Result<ActiveStatementProducer, Error>) -> Self {
        let current_idx = self.prepare_results.idx_during_filling;
        match result {
            Ok(producer) => {
                self.prepare_results.producers.push((producer, current_idx));
                self.prepare_results.idx_during_filling += 1
            }
            Err(e) => {
                self.prepare_results
                    .errors
                    .borrow_mut()
                    .push((e, current_idx));
                self.prepare_results.idx_during_filling += 1;
            }
        };
        self
    }

    pub fn commit_result(self, result: Result<(), Error>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}

impl TransactionWrapper for TransactionWrapperMock {
    fn prepare(&self, _query: &str) -> Result<Statement, Error> {
        let next_result_idx = *self.prepare_results.next_result_idx.borrow();
        *self.prepare_results.next_result_idx.borrow_mut() += 1;
        match self
            .prepare_results
            .producers
            .iter()
            .find(|(_, idx)| *idx == next_result_idx)
        {
            Some((producer, _)) => Ok(producer.statement()),
            None => {
                let current_idx = self
                    .prepare_results
                    .errors
                    .borrow()
                    .iter()
                    .position(|(_, idx)| *idx == next_result_idx)
                    .expect("call of TransactionWrapperMock without a prepared result");
                Err(self
                    .prepare_results
                    .errors
                    .borrow_mut()
                    .remove(current_idx)
                    .0)
            }
        }
    }

    fn execute(&self, _query: &str, _params: &[&dyn ToSql]) -> Result<usize, Error> {
        unimplemented!("not needed yet")
    }

    fn commit(&mut self) -> Result<(), Error> {
        self.commit_results.borrow_mut().remove(0)
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
