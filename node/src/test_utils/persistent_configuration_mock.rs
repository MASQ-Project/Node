// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::persistent_configuration::{PersistentConfigError, PersistentConfiguration};
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::wallet::Wallet;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use rusqlite::Transaction;

type MnemonicSeedParam = (Vec<u8>, String);

#[allow(clippy::type_complexity)]
#[derive(Clone, Default)]
pub struct PersistentConfigurationMock {
    current_schema_version_results: RefCell<Vec<String>>,
    set_password_params: Arc<Mutex<Vec<String>>>,
    check_password_params: Arc<Mutex<Vec<String>>>,
    check_password_results: RefCell<Vec<Option<bool>>>,
    clandestine_port_results: RefCell<Vec<u16>>,
    set_clandestine_port_params: Arc<Mutex<Vec<u16>>>,
    mnemonic_seed_params: Arc<Mutex<Vec<String>>>,
    mnemonic_seed_results: RefCell<Vec<Result<Option<PlainData>, PersistentConfigError>>>,
    set_mnemonic_seed_params: Arc<Mutex<Vec<MnemonicSeedParam>>>,
    set_mnemonic_seed_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
    consuming_wallet_public_key_results: RefCell<Vec<Option<String>>>,
    consuming_wallet_public_key_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_derivation_path_results: RefCell<Vec<Option<String>>>,
    set_consuming_wallet_derivation_path_params: Arc<Mutex<Vec<(String, String)>>>,
    set_consuming_wallet_public_key_params: Arc<Mutex<Vec<PlainData>>>,
    earning_wallet_from_address_results: RefCell<Vec<Option<Wallet>>>,
    earning_wallet_address_results: RefCell<Vec<Option<String>>>,
    set_earning_wallet_address_params: Arc<Mutex<Vec<String>>>,
    start_block_results: RefCell<Vec<u64>>,
    set_start_block_transactionally_results: RefCell<Vec<Result<(), String>>>,
    set_gas_price_params: Arc<Mutex<Vec<u64>>>,
    gas_price_results: RefCell<Vec<u64>>,
    past_neighbors_params: Arc<Mutex<Vec<String>>>,
    past_neighbors_results:
        RefCell<Vec<Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>>>,
    set_past_neighbors_params: Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    set_past_neighbors_results: RefCell<Vec<Result<(), PersistentConfigError>>>,
}

impl PersistentConfiguration for PersistentConfigurationMock {
    fn current_schema_version(&self) -> String {
        Self::result_from(&self.current_schema_version_results)
    }

    fn set_password(&self, db_password: &str) {
        self.set_password_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
    }

    fn check_password(&self, db_password: &str) -> Option<bool> {
        self.check_password_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        self.check_password_results.borrow_mut().remove(0)
    }

    fn clandestine_port(&self) -> u16 {
        Self::result_from(&self.clandestine_port_results)
    }

    fn set_clandestine_port(&self, port: u16) {
        self.set_clandestine_port_params.lock().unwrap().push(port);
    }

    fn gas_price(&self) -> u64 {
        Self::result_from(&self.gas_price_results)
    }

    fn set_gas_price(&self, gas_price: u64) {
        self.set_gas_price_params.lock().unwrap().push(gas_price);
    }

    fn mnemonic_seed(&self, db_password: &str) -> Result<Option<PlainData>, PersistentConfigError> {
        self.mnemonic_seed_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        Self::result_from(&self.mnemonic_seed_results)
    }

    fn set_mnemonic_seed(
        &self,
        seed: &dyn AsRef<[u8]>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_mnemonic_seed_params
            .lock()
            .unwrap()
            .push((seed.as_ref().to_vec(), db_password.to_string()));
        self.set_mnemonic_seed_results.borrow_mut().remove(0)
    }

    fn consuming_wallet_public_key(&self) -> Option<String> {
        Self::result_from(&self.consuming_wallet_public_key_results)
    }

    fn consuming_wallet_derivation_path(&self) -> Option<String> {
        Self::result_from(&self.consuming_wallet_derivation_path_results)
    }

    fn set_consuming_wallet_derivation_path(&self, derivation_path: &str, db_password: &str) {
        self.set_consuming_wallet_derivation_path_params
            .lock()
            .unwrap()
            .push((derivation_path.to_string(), db_password.to_string()));
    }

    fn set_consuming_wallet_public_key(&self, public_key: &PlainData) {
        self.set_consuming_wallet_public_key_params
            .lock()
            .unwrap()
            .push(public_key.clone());
    }

    fn earning_wallet_from_address(&self) -> Option<Wallet> {
        Self::result_from(&self.earning_wallet_from_address_results)
    }

    fn earning_wallet_address(&self) -> Option<String> {
        Self::result_from(&self.earning_wallet_address_results)
    }

    fn set_earning_wallet_address(&self, address: &str) {
        self.set_earning_wallet_address_params
            .lock()
            .unwrap()
            .push(address.to_string());
    }

    fn past_neighbors(
        &self,
        db_password: &str,
    ) -> Result<Option<Vec<NodeDescriptor>>, PersistentConfigError> {
        self.past_neighbors_params
            .lock()
            .unwrap()
            .push(db_password.to_string());
        self.past_neighbors_results.borrow_mut().remove(0)
    }

    fn set_past_neighbors(
        &self,
        node_descriptors_opt: Option<Vec<NodeDescriptor>>,
        db_password: &str,
    ) -> Result<(), PersistentConfigError> {
        self.set_past_neighbors_params
            .lock()
            .unwrap()
            .push((node_descriptors_opt, db_password.to_string()));
        self.set_past_neighbors_results.borrow_mut().remove(0)
    }

    fn start_block(&self) -> u64 {
        if self.start_block_results.borrow().is_empty() {
            return 0;
        }
        Self::result_from(&self.start_block_results)
    }

    fn set_start_block_transactionally(
        &self,
        _tx: &Transaction,
        _value: u64,
    ) -> Result<(), String> {
        Self::result_from(&self.set_start_block_transactionally_results)
    }
}

impl PersistentConfigurationMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_schema_version_result(self, result: String) -> PersistentConfigurationMock {
        self.current_schema_version_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_password_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.set_password_params = params.clone();
        self
    }

    pub fn check_password_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.check_password_params = params.clone();
        self
    }

    pub fn check_password_result(self, result: Option<bool>) -> PersistentConfigurationMock {
        self.check_password_results.borrow_mut().push(result);
        self
    }

    pub fn clandestine_port_result(self, result: u16) -> PersistentConfigurationMock {
        self.clandestine_port_results.borrow_mut().push(result);
        self
    }

    pub fn set_clandestine_port_params(
        mut self,
        params: &Arc<Mutex<Vec<u16>>>,
    ) -> PersistentConfigurationMock {
        self.set_clandestine_port_params = params.clone();
        self
    }

    pub fn mnemonic_seed_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.mnemonic_seed_params = params.clone();
        self
    }

    pub fn mnemonic_seed_result(
        self,
        result: Result<Option<PlainData>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.mnemonic_seed_results.borrow_mut().push(result);
        self
    }

    pub fn set_mnemonic_seed_params(
        mut self,
        params: &Arc<Mutex<Vec<MnemonicSeedParam>>>,
    ) -> PersistentConfigurationMock {
        self.set_mnemonic_seed_params = params.clone();
        self
    }

    pub fn set_mnemonic_seed_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_mnemonic_seed_results.borrow_mut().push(result);
        self
    }

    pub fn consuming_wallet_public_key_result(
        self,
        result: Option<String>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_public_key_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn consuming_wallet_public_key_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_public_key_params = params.clone();
        self
    }

    pub fn consuming_wallet_derivation_path_result(
        self,
        result: Option<String>,
    ) -> PersistentConfigurationMock {
        self.consuming_wallet_derivation_path_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn gas_price_result(self, result: u64) -> Self {
        self.gas_price_results.borrow_mut().push(result);
        self
    }

    pub fn set_gas_price_params(
        mut self,
        params: &Arc<Mutex<Vec<u64>>>,
    ) -> PersistentConfigurationMock {
        self.set_gas_price_params = params.clone();
        self
    }

    pub fn past_neighbors_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.past_neighbors_params = params.clone();
        self
    }

    pub fn past_neighbors_result(
        self,
        result: Result<Option<Vec<NodeDescriptor>>, PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.past_neighbors_results.borrow_mut().push(result);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn set_past_neighbors_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<Vec<NodeDescriptor>>, String)>>>,
    ) -> PersistentConfigurationMock {
        self.set_past_neighbors_params = params.clone();
        self
    }

    pub fn set_past_neighbors_result(
        self,
        result: Result<(), PersistentConfigError>,
    ) -> PersistentConfigurationMock {
        self.set_past_neighbors_results.borrow_mut().push(result);
        self
    }

    pub fn set_consuming_wallet_derivation_path_params(
        mut self,
        params: &Arc<Mutex<Vec<(String, String)>>>,
    ) -> PersistentConfigurationMock {
        self.set_consuming_wallet_derivation_path_params = params.clone();
        self
    }

    pub fn set_consuming_wallet_public_key_params(
        mut self,
        params: &Arc<Mutex<Vec<PlainData>>>,
    ) -> PersistentConfigurationMock {
        self.set_consuming_wallet_public_key_params = params.clone();
        self
    }

    pub fn earning_wallet_from_address_result(
        self,
        result: Option<Wallet>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_from_address_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn earning_wallet_address_result(
        self,
        result: Option<String>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_address_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_earning_wallet_address_params(
        mut self,
        params: &Arc<Mutex<Vec<String>>>,
    ) -> PersistentConfigurationMock {
        self.set_earning_wallet_address_params = params.clone();
        self
    }

    pub fn start_block_result(self, start_block: u64) -> Self {
        self.start_block_results.borrow_mut().push(start_block);
        self
    }

    pub fn set_start_block_transactionally_result(self, result: Result<(), String>) -> Self {
        self.set_start_block_transactionally_results
            .borrow_mut()
            .push(result);
        self
    }

    fn result_from<T: Clone>(results: &RefCell<Vec<T>>) -> T {
        let mut borrowed = results.borrow_mut();
        if borrowed.is_empty() {
            panic!("No mock results prepared")
        } else if borrowed.len() == 1 {
            borrowed[0].clone()
        } else {
            borrowed.remove(0)
        }
    }
}
