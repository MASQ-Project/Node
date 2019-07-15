use crate::blockchain::bip39::Bip39Error;
use crate::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::wallet::Wallet;
use rusqlite::Transaction;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

type MnemonicSeedParam = (Vec<u8>, String);

#[derive(Clone, Default)]
pub struct PersistentConfigurationMock {
    current_schema_version_results: RefCell<Vec<String>>,
    clandestine_port_results: RefCell<Vec<u16>>,
    set_clandestine_port_params: Arc<Mutex<Vec<u16>>>,
    encrypted_mnemonic_seed_results: RefCell<Vec<Option<String>>>,
    mnemonic_seed_params: Arc<Mutex<Vec<String>>>,
    mnemonic_seed_results: RefCell<Vec<Result<PlainData, Bip39Error>>>,
    set_mnemonic_seed_params: Arc<Mutex<Vec<MnemonicSeedParam>>>,
    consuming_wallet_public_key_results: RefCell<Vec<Option<String>>>,
    consuming_wallet_public_key_params: Arc<Mutex<Vec<String>>>,
    consuming_wallet_derivation_path_results: RefCell<Vec<Option<String>>>,
    set_consuming_wallet_derivation_path_params: Arc<Mutex<Vec<(String, String)>>>,
    set_consuming_wallet_public_key_params: Arc<Mutex<Vec<PlainData>>>,
    earning_wallet_from_derivation_path_params: Arc<Mutex<Vec<String>>>,
    earning_wallet_from_derivation_path_results: RefCell<Vec<Option<Wallet>>>,
    earning_wallet_from_address_results: RefCell<Vec<Option<Wallet>>>,
    earning_wallet_derivation_path_results: RefCell<Vec<Option<String>>>,
    earning_wallet_address_results: RefCell<Vec<Option<String>>>,
    set_earning_wallet_derivation_path_params: Arc<Mutex<Vec<(String, String)>>>,
    set_earning_wallet_address_params: Arc<Mutex<Vec<String>>>,
    start_block_results: RefCell<Vec<u64>>,
    set_start_block_transactionally_results: RefCell<Vec<Result<(), String>>>,
}

impl PersistentConfiguration for PersistentConfigurationMock {
    fn current_schema_version(&self) -> String {
        Self::result_from(&self.current_schema_version_results)
    }

    fn clandestine_port(&self) -> u16 {
        Self::result_from(&self.clandestine_port_results)
    }

    fn set_clandestine_port(&self, port: u16) {
        self.set_clandestine_port_params.lock().unwrap().push(port);
    }

    fn encrypted_mnemonic_seed(&self) -> Option<String> {
        Self::result_from(&self.encrypted_mnemonic_seed_results)
    }

    fn mnemonic_seed(&self, wallet_password: &str) -> Result<PlainData, Bip39Error> {
        self.mnemonic_seed_params
            .lock()
            .unwrap()
            .push(wallet_password.to_string());
        Self::result_from(&self.mnemonic_seed_results)
    }

    fn set_mnemonic_seed(&self, seed: &AsRef<[u8]>, wallet_password: &str) {
        self.set_mnemonic_seed_params
            .lock()
            .unwrap()
            .push((seed.as_ref().to_vec(), wallet_password.to_string()));
    }

    fn consuming_wallet_public_key(&self) -> Option<String> {
        Self::result_from(&self.consuming_wallet_public_key_results)
    }

    fn consuming_wallet_derivation_path(&self) -> Option<String> {
        Self::result_from(&self.consuming_wallet_derivation_path_results)
    }

    fn set_consuming_wallet_derivation_path(&self, derivation_path: &str, wallet_password: &str) {
        self.set_consuming_wallet_derivation_path_params
            .lock()
            .unwrap()
            .push((derivation_path.to_string(), wallet_password.to_string()));
    }

    fn set_consuming_wallet_public_key(&self, public_key: &PlainData) {
        self.set_consuming_wallet_public_key_params
            .lock()
            .unwrap()
            .push(public_key.clone());
    }

    fn earning_wallet_from_derivation_path(&self, wallet_password: &str) -> Option<Wallet> {
        self.earning_wallet_from_derivation_path_params
            .lock()
            .unwrap()
            .push(wallet_password.to_string());
        Self::result_from(&self.earning_wallet_from_derivation_path_results)
    }

    fn earning_wallet_from_address(&self) -> Option<Wallet> {
        Self::result_from(&self.earning_wallet_from_address_results)
    }

    fn earning_wallet_derivation_path(&self) -> Option<String> {
        Self::result_from(&self.earning_wallet_derivation_path_results)
    }

    fn earning_wallet_address(&self) -> Option<String> {
        Self::result_from(&self.earning_wallet_address_results)
    }

    fn set_earning_wallet_derivation_path(&self, derivation_path: &str, wallet_password: &str) {
        self.set_earning_wallet_derivation_path_params
            .lock()
            .unwrap()
            .push((derivation_path.to_string(), wallet_password.to_string()));
    }

    fn set_earning_wallet_address(&self, address: &str) {
        self.set_earning_wallet_address_params
            .lock()
            .unwrap()
            .push(address.to_string());
    }

    fn start_block(&self) -> u64 {
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

    pub fn encrypted_mnemonic_seed_result(
        self,
        result: Option<String>,
    ) -> PersistentConfigurationMock {
        self.encrypted_mnemonic_seed_results
            .borrow_mut()
            .push(result);
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
        result: Result<PlainData, Bip39Error>,
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

    pub fn earning_wallet_from_derivation_path_result(
        self,
        result: Option<Wallet>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_from_derivation_path_results
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

    pub fn earning_wallet_derivation_path_result(
        self,
        result: Option<String>,
    ) -> PersistentConfigurationMock {
        self.earning_wallet_derivation_path_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn set_earning_wallet_derivation_path_params(
        mut self,
        params: &Arc<Mutex<Vec<(String, String)>>>,
    ) -> PersistentConfigurationMock {
        self.set_earning_wallet_derivation_path_params = params.clone();
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
