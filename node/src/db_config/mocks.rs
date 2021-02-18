// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoRecord, ConfigDaoWrite,
};
use rusqlite::Transaction;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

pub struct ConfigDaoMock {
    get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
    get_params: Arc<Mutex<Vec<String>>>,
    get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
    start_transaction_results: RefCell<Vec<Result<Box<dyn ConfigDaoReadWrite>, ConfigDaoError>>>,
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
    fn start_transaction<'b, 'c: 'b>(
        &'c mut self,
    ) -> Result<Box<dyn ConfigDaoReadWrite + 'b>, ConfigDaoError> {
        self.start_transaction_results.borrow_mut().remove(0)
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

    pub fn start_transaction_result(
        self,
        result: Result<Box<dyn ConfigDaoReadWrite>, ConfigDaoError>,
    ) -> Self {
        self.start_transaction_results.borrow_mut().push(result);
        self
    }
}

#[derive(Clone)]
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
    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError> {
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

    fn extract(&mut self) -> Result<Transaction, ConfigDaoError> {
        unimplemented!()
    }
}

impl ConfigDaoReadWrite for ConfigDaoWriteableMock {}

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

    pub fn commit_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.commit_params = params.clone();
        self
    }

    pub fn commit_result(self, result: Result<(), ConfigDaoError>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}
