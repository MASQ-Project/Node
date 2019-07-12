// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::config_dao::{ConfigDao, ConfigDaoError};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct ConfigDaoMock {
    get_string_params: Arc<Mutex<Vec<String>>>,
    get_string_results: RefCell<Vec<Result<String, ConfigDaoError>>>,
    set_string_params: Arc<Mutex<Vec<(String, String)>>>,
    set_string_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    get_u64_params: Arc<Mutex<Vec<String>>>,
    get_u64_results: RefCell<Vec<Result<u64, ConfigDaoError>>>,
    set_u64_params: Arc<Mutex<Vec<(String, u64)>>>,
    set_u64_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    set_u64_transactional_params: Arc<Mutex<Vec<(String, u64)>>>,
    set_u64_transactional_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
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

    fn set_u64_transactional(
        &self,
        _transaction: &rusqlite::Transaction,
        name: &str,
        value: u64,
    ) -> Result<(), ConfigDaoError> {
        self.set_u64_transactional_params
            .lock()
            .unwrap()
            .push((String::from(name), value));
        self.set_u64_transactional_results.borrow_mut().remove(0)
    }
}

impl ConfigDaoMock {
    pub fn new() -> ConfigDaoMock {
        Self::default()
    }

    pub fn get_string_params(mut self, params_arc: &Arc<Mutex<Vec<String>>>) -> ConfigDaoMock {
        self.get_string_params = params_arc.clone();
        self
    }

    pub fn get_string_result(self, result: Result<String, ConfigDaoError>) -> ConfigDaoMock {
        self.get_string_results.borrow_mut().push(result);
        self
    }

    pub fn set_string_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<(String, String)>>>,
    ) -> ConfigDaoMock {
        self.set_string_params = params_arc.clone();
        self
    }

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

    pub fn set_u64_params(mut self, params_arc: &Arc<Mutex<Vec<(String, u64)>>>) -> ConfigDaoMock {
        self.set_u64_params = params_arc.clone();
        self
    }

    pub fn set_u64_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
        self.set_u64_results.borrow_mut().push(result);
        self
    }

    pub fn set_u64_transactional_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<(String, u64)>>>,
    ) -> ConfigDaoMock {
        self.set_u64_transactional_params = params_arc.clone();
        self
    }

    pub fn set_u64_transactional_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
        self.set_u64_transactional_results.borrow_mut().push(result);
        self
    }
}
