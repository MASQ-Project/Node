// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::sync::{Arc, Mutex};
use crate::database::connection_wrapper::TransactionWrapper;
use rusqlite::{Statement, Error};
use std::cell::RefCell;
use crate::db_config::config_dao::{ConfigDaoRecord, ConfigDaoError, ConfigDaoRead, ConfigDao, ConfigDaoReadWrite, ConfigDaoWrite};
use std::borrow::BorrowMut;

#[derive(Debug)]
pub struct TransactionWrapperMock {
    committed: Arc<Mutex<Option<bool>>>,
}

impl<'a> TransactionWrapper<'a> for TransactionWrapperMock {
    fn commit(&mut self) {
        let _ = self.committed.lock().unwrap().replace(true);
    }

    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        unimplemented!()
    }
}

impl Drop for TransactionWrapperMock {
    fn drop(&mut self) {
        let mut locked_wrapper = self.committed.lock().unwrap();
        if locked_wrapper.is_none() {
            (*locked_wrapper).replace(false);
        }
    }
}

impl TransactionWrapperMock {
    pub fn new() -> Self {
        Self {
            committed: Arc::new(Mutex::new(None)),
        }
    }

    pub fn committed_arc(&self) -> Arc<Mutex<Option<bool>>> {
        self.committed.clone()
    }
}

pub struct ConfigDaoMock {
    get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
    get_params: Arc<Mutex<Vec<String>>>,
    get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
    start_transaction_results: RefCell<Vec<Result<ConfigDaoWriteableMock, ConfigDaoError>>>,
}

impl ConfigDaoRead for ConfigDaoMock {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        self.get_all_results.borrow_mut().remove(0)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        self.get_params.lock().unwrap().push(name.to_string());
        self.get_results.borrow_mut().remove(0)
    }
}

impl ConfigDao for ConfigDaoMock {
    fn start_transaction<'a>(&mut self) -> Result<Box<dyn ConfigDaoReadWrite<'a> + 'a>, ConfigDaoError> {
        self.start_transaction_results.borrow_mut().remove(0).map (|r| Box::new(r))
    }
}

impl ConfigDaoMock {
    pub fn new() -> Self {
        Self {
            get_all_results: RefCell::new(vec![]),
            get_params: Arc::new(Mutex::new(vec![])),
            get_results: RefCell::new(vec![]),
            start_transaction_results: RefCell::new(vec![]),
        }
    }

    pub fn get_all_result(self, result: Result<Vec<ConfigDaoRecord>, ConfigDaoError>) -> Self {
        self.get_all_results.borrow_mut().push(result);
        self
    }

    pub fn get_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.get_params = params.clone();
        self
    }

    pub fn get_result(self, result: Result<ConfigDaoRecord, ConfigDaoError>) -> Self {
        self.get_results.borrow_mut().push(result);
        self
    }

    pub fn start_transaction_result(self, result: Result<ConfigDaoWriteableMock, ConfigDaoError>) -> Self {
        self.start_transaction_results.borrow_mut().push(result);
        self
    }
}

pub struct ConfigDaoWriteableMock {
    get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
    get_params: Arc<Mutex<Vec<String>>>,
    get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
    set_params: Arc<Mutex<Vec<(String, Option<String>)>>>,
    set_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
}

impl ConfigDaoRead for ConfigDaoWriteableMock {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        self.get_all_results.borrow_mut().remove(0)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        self.get_params.lock().unwrap().push(name.to_string());
        self.get_results.borrow_mut().remove(0)
    }
}

impl ConfigDaoWrite for ConfigDaoWriteableMock {
    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError> {
        self.set_params
            .lock()
            .unwrap()
            .push((name.to_string(), value.map(|x| x.to_string())));
        self.set_results.borrow_mut().remove(0)
    }

    fn commit(&mut self) -> Result<(), ConfigDaoError> {
        self.commit_params.lock().unwrap().push(());
        self.commit_results.borrow_mut().remove(0)
    }
}

impl ConfigDaoWriteableMock {
    pub fn new() -> Self {
        Self {
            get_all_results: RefCell::new(vec![]),
            get_params: Arc::new(Mutex::new(vec![])),
            get_results: RefCell::new(vec![]),
            set_params: Arc::new(Mutex::new(vec![])),
            set_results: RefCell::new(vec![]),
            commit_params: Arc::new(Mutex::new(vec![])),
            commit_results: RefCell::new(vec![]),
        }
    }

    pub fn get_all_result(self, result: Result<Vec<ConfigDaoRecord>, ConfigDaoError>) -> Self {
        self.get_all_results.borrow_mut().push(result);
        self
    }

    pub fn get_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.get_params = params.clone();
        self
    }

    pub fn get_result(self, result: Result<ConfigDaoRecord, ConfigDaoError>) -> Self {
        self.get_results.borrow_mut().push(result);
        self
    }

    pub fn set_params(mut self, params: &Arc<Mutex<Vec<(String, Option<String>)>>>) -> Self {
        self.set_params = params.clone();
        self
    }

    pub fn set_result(self, result: Result<(), ConfigDaoError>) -> Self {
        self.set_results.borrow_mut().push(result);
        self
    }

    pub fn commit_params(mut self, params: &Arc<Mutex<Vec<(())>>>) -> Self {
        self.commit_params = params.clone();
        self
    }

    pub fn commit_result(self, result: Result<(), ConfigDaoError>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}
