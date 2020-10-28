// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::config_dao_old::{ConfigDaoError, ConfigDaoOld};
use crate::sub_lib::cryptde::PlainData;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct ConfigDaoMock {
    get_string_params: Arc<Mutex<Vec<String>>>,
    get_string_results: RefCell<Vec<Result<String, ConfigDaoError>>>,
    set_string_params: Arc<Mutex<Vec<(String, String)>>>,
    set_string_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    get_bytes_e_params: Arc<Mutex<Vec<(String, String)>>>,
    get_bytes_e_results: RefCell<Vec<Result<PlainData, ConfigDaoError>>>,
    set_bytes_e_params: Arc<Mutex<Vec<(String, PlainData, String)>>>,
    set_bytes_e_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    get_u64_params: Arc<Mutex<Vec<String>>>,
    get_u64_results: RefCell<Vec<Result<u64, ConfigDaoError>>>,
    set_u64_params: Arc<Mutex<Vec<(String, u64)>>>,
    set_u64_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    set_u64_transactional_params: Arc<Mutex<Vec<(String, u64)>>>,
    set_u64_transactional_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    clear_params: Arc<Mutex<Vec<String>>>,
    clear_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
}

impl ConfigDaoOld for ConfigDaoMock {
    fn get_all(
        &self,
        _db_password: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, ConfigDaoError> {
        unimplemented!()
    }

    fn check_password(&self, _db_password: &str) -> Result<bool, ConfigDaoError> {
        unimplemented!()
    }

    fn change_password(
        &self,
        _old_password_opt: Option<&str>,
        _new_password: &str,
    ) -> Result<(), ConfigDaoError> {
        unimplemented!()
    }

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

    fn get_bytes_e(&self, name: &str, db_password: &str) -> Result<PlainData, ConfigDaoError> {
        self.get_bytes_e_params
            .lock()
            .unwrap()
            .push((String::from(name), String::from(db_password)));
        self.get_bytes_e_results.borrow_mut().remove(0)
    }

    fn set_bytes_e(
        &self,
        name: &str,
        value: &PlainData,
        db_password: &str,
    ) -> Result<(), ConfigDaoError> {
        self.set_bytes_e_params.lock().unwrap().push((
            String::from(name),
            value.clone(),
            String::from(db_password),
        ));
        self.set_bytes_e_results.borrow_mut().remove(0)
    }

    fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError> {
        self.get_u64_params.lock().unwrap().push(String::from(name));
        self.get_u64_results.borrow_mut().remove(0)
    }

    fn clear(&self, name: &str) -> Result<(), ConfigDaoError> {
        self.clear_params.lock().unwrap().push(String::from(name));
        self.clear_results.borrow_mut().remove(0)
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

    pub fn get_bytes_e_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<(String, String)>>>,
    ) -> ConfigDaoMock {
        self.get_bytes_e_params = params_arc.clone();
        self
    }

    pub fn get_bytes_e_result(self, result: Result<PlainData, ConfigDaoError>) -> ConfigDaoMock {
        self.get_bytes_e_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_bytes_e_params(
        mut self,
        params_arc: &Arc<Mutex<Vec<(String, PlainData, String)>>>,
    ) -> ConfigDaoMock {
        self.set_bytes_e_params = params_arc.clone();
        self
    }

    pub fn set_bytes_e_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
        self.set_bytes_e_results.borrow_mut().push(result);
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

    pub fn clear_params(mut self, params_arc: &Arc<Mutex<Vec<String>>>) -> ConfigDaoMock {
        self.clear_params = params_arc.clone();
        self
    }

    pub fn clear_result(self, result: Result<(), ConfigDaoError>) -> ConfigDaoMock {
        self.clear_results.borrow_mut().push(result);
        self
    }
}
