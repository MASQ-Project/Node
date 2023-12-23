// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, ConfigDaoRecord};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ConfigDaoMock {
    get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
    get_params: Arc<Mutex<Vec<String>>>,
    get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
    set_params: Arc<Mutex<Vec<(String, Option<String>)>>>,
    set_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
    set_by_guest_transaction_params: Arc<Mutex<Vec<(ArbitraryIdStamp, String, Option<String>)>>>,
    set_by_guest_transaction_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
}

impl ConfigDao for ConfigDaoMock {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        self.get_all_results.borrow_mut().remove(0)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        self.get_params.lock().unwrap().push(name.to_string());
        self.get_results.borrow_mut().remove(0)
    }

    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError> {
        self.set_params
            .lock()
            .unwrap()
            .push((name.to_string(), value));
        self.set_results.borrow_mut().remove(0)
    }

    fn set_by_guest_transaction(
        &self,
        txn: &mut TransactionSafeWrapper,
        name: &str,
        value: Option<String>,
    ) -> Result<(), ConfigDaoError> {
        self.set_by_guest_transaction_params.lock().unwrap().push((
            txn.arbitrary_id_stamp(),
            name.to_string(),
            value,
        ));
        self.set_by_guest_transaction_results.borrow_mut().remove(0)
    }
}

impl ConfigDaoMock {
    pub fn new() -> Self {
        Self {
            get_all_results: RefCell::new(vec![]),
            get_params: Arc::new(Mutex::new(vec![])),
            get_results: RefCell::new(vec![]),
            set_params: Arc::new(Mutex::new(vec![])),
            set_results: RefCell::new(vec![]),
            set_by_guest_transaction_params: Arc::new(Mutex::new(vec![])),
            set_by_guest_transaction_results: RefCell::new(vec![]),
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

    pub fn set_by_guest_transaction_params(
        mut self,
        params: &Arc<Mutex<Vec<(ArbitraryIdStamp, String, Option<String>)>>>,
    ) -> Self {
        self.set_by_guest_transaction_params = params.clone();
        self
    }

    pub fn set_by_guest_transaction_result(self, result: Result<(), ConfigDaoError>) -> Self {
        self.set_by_guest_transaction_results
            .borrow_mut()
            .push(result);
        self
    }
}
