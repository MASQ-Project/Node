// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::sync::{Arc, Mutex};
use crate::database::connection_wrapper::TransactionWrapper;
use rusqlite::{Statement, Error};
use std::cell::RefCell;
use crate::db_config::config_dao::{ConfigDaoRecord, ConfigDaoError, ConfigDaoRead, ConfigDao, ConfigDaoReadWrite, ConfigDaoWrite};
use crate::db_config::secure_config_layer::{SecureConfigLayerError, SecureConfigLayer};

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

pub struct ConfigDaoMock<'a> {
    get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
    get_params: Arc<Mutex<Vec<String>>>,
    get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
    start_transaction_results: RefCell<Vec<Result<Box<dyn ConfigDaoReadWrite<'a>+'a>, ConfigDaoError>>>,
}

impl ConfigDaoRead for ConfigDaoMock<'_> {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        self.get_all_results.borrow_mut().remove(0)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        self.get_params.lock().unwrap().push(name.to_string());
        self.get_results.borrow_mut().remove(0)
    }
}

impl<'a> ConfigDao<'a> for ConfigDaoMock<'a> {
    fn start_transaction<'b:'a>(&'b mut self) -> Result<Box<dyn ConfigDaoReadWrite<'b> + 'b>, ConfigDaoError> {
        self.start_transaction_results.borrow_mut().remove(0)
    }
}

impl <'a>ConfigDaoMock<'a> {
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

    pub fn start_transaction_result(self, result: Result<Box<dyn ConfigDaoReadWrite<'a>+'a>, ConfigDaoError>) -> Self {
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

impl<'a> ConfigDaoWrite<'a> for ConfigDaoWriteableMock {
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
}

impl<'a> ConfigDaoReadWrite<'a> for ConfigDaoWriteableMock {}

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

pub struct SecureConfigLayerMock {
    check_password_params: Arc<Mutex<Vec<Option<String>>>>,
    check_password_results: RefCell<Vec<Result<bool, SecureConfigLayerError>>>,
    change_password_params: Arc<Mutex<Vec<(Option<String>, String)>>>,
    change_password_results: RefCell<Vec<Result<(), SecureConfigLayerError>>>,
    encrypt_params: Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>,
    encrypt_results: RefCell<Vec<Result<Option<String>, SecureConfigLayerError>>>,
    decrypt_params: Arc<Mutex<Vec<(ConfigDaoRecord, Option<String>)>>>,
    decrypt_results: RefCell<Vec<Result<Option<String>, SecureConfigLayerError>>>,
}

impl SecureConfigLayer for SecureConfigLayerMock {
    fn check_password<T: ConfigDaoRead + ?Sized>(&self, db_password_opt: Option<&str>, _dao: &Box<T>) -> Result<bool, SecureConfigLayerError> {
        self.check_password_params.lock().unwrap().push (
            db_password_opt.map (|s| s.to_string())
        );
        self.check_password_results.borrow_mut().remove(0)
    }

    fn change_password<'a, T: ConfigDaoReadWrite<'a>>(&mut self, old_password_opt: Option<&str>, new_password: &str, _dao: &'a mut Box<T>) -> Result<(), SecureConfigLayerError> {
        self.change_password_params.lock().unwrap().push ((
            old_password_opt.map (|s| s.to_string()),
            new_password.to_string(),
        ));
        self.change_password_results.borrow_mut().remove(0)
    }

    fn encrypt<T: ConfigDaoRead + ?Sized>(&self, name: &str, plain_value_opt: Option<String>, password_opt: Option<&str>, _dao: &Box<T>) -> Result<Option<String>, SecureConfigLayerError> {
        self.encrypt_params.lock().unwrap().push ((
            name.to_string(),
            plain_value_opt,
            password_opt.map (|s| s.to_string()),
        ));
        self.encrypt_results.borrow_mut().remove(0)
    }

    fn decrypt<T: ConfigDaoRead + ?Sized>(&self, record: ConfigDaoRecord, password_opt: Option<&str>, _dao: &Box<T>) -> Result<Option<String>, SecureConfigLayerError> {
        self.decrypt_params.lock().unwrap().push ((
            record.clone(),
            password_opt.map (|s| s.to_string()),
        ));
        self.decrypt_results.borrow_mut().remove(0)
    }
}

impl SecureConfigLayerMock {
    pub fn new() -> Self {
        Self {
            check_password_params: Arc::new(Mutex::new(vec![])),
            check_password_results: RefCell::new(vec![]),
            change_password_params: Arc::new(Mutex::new(vec![])),
            change_password_results: RefCell::new(vec![]),
            encrypt_params: Arc::new(Mutex::new(vec![])),
            encrypt_results: RefCell::new(vec![]),
            decrypt_params: Arc::new(Mutex::new(vec![])),
            decrypt_results: RefCell::new(vec![]),
        }
    }

    pub fn check_password_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
        self.check_password_params = params.clone();
        self
    }

    pub fn check_password_result(self, result: Result<bool, SecureConfigLayerError>) -> Self {
        self.check_password_results.borrow_mut().push (result);
        self
    }

    pub fn change_password_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<String>, String)>>>,
    ) -> Self {
        self.change_password_params = params.clone();
        self
    }

    pub fn change_password_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
        self.change_password_results.borrow_mut().push (result);
        self
    }

    pub fn encrypt_params(mut self, params: &Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>) -> Self {
        self.encrypt_params = params.clone();
        self
    }

    pub fn encrypt_result(self, result: Result<Option<String>, SecureConfigLayerError>) -> Self {
        self.encrypt_results.borrow_mut().push (result);
        self
    }

    pub fn decrypt_params(mut self, params: &Arc<Mutex<Vec<(ConfigDaoRecord, Option<String>)>>>) -> Self {
        self.decrypt_params = params.clone();
        self
    }

    pub fn decrypt_result(self, result: Result<Option<String>, SecureConfigLayerError>) -> Self {
        self.decrypt_results.borrow_mut().push (result);
        self
    }
}
