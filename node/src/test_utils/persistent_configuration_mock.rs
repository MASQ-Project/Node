use crate::persistent_configuration::PersistentConfiguration;
use rusqlite::Transaction;
use std::cell::RefCell;

#[derive(Clone, Default)]
pub struct PersistentConfigurationMock {
    start_block_results: RefCell<Vec<u64>>,
    set_start_block_transactionally_results: RefCell<Vec<Result<(), String>>>,
    mnemonic_seed_results: RefCell<Vec<Option<String>>>,
}

impl PersistentConfigurationMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start_block_result(self, start_block: u64) -> Self {
        self.start_block_results.borrow_mut().push(start_block);
        self
    }

    pub fn mnemonic_seed_result(self, result: Option<String>) -> Self {
        self.mnemonic_seed_results.borrow_mut().push(result);
        self
    }

    pub fn set_start_block_transactionally_result(self, result: Result<(), String>) -> Self {
        self.set_start_block_transactionally_results
            .borrow_mut()
            .push(result);
        self
    }
}

impl PersistentConfiguration for PersistentConfigurationMock {
    fn current_schema_version(&self) -> String {
        unimplemented!()
    }

    fn clandestine_port(&self) -> u16 {
        unimplemented!()
    }

    fn set_clandestine_port(&self, _port: u16) {
        unimplemented!()
    }

    fn mnemonic_seed(&self) -> Option<String> {
        self.mnemonic_seed_results.borrow_mut().remove(0)
    }

    fn set_mnemonic_seed(&self, _seed: String) {
        unimplemented!()
    }

    fn start_block(&self) -> u64 {
        self.start_block_results.borrow_mut().remove(0)
    }

    fn set_start_block_transactionally(
        &self,
        _tx: &Transaction,
        _value: u64,
    ) -> Result<(), String> {
        self.set_start_block_transactionally_results
            .borrow_mut()
            .remove(0)
    }
}
