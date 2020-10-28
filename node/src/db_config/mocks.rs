// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::sync::{Mutex, Arc};
use crate::db_config::config_dao::TransactionWrapper;

#[derive (Debug)]
pub struct TransactionWrapperMock {
    committed: Arc<Mutex<Option<bool>>>
}

impl TransactionWrapper for TransactionWrapperMock {
    fn commit(&mut self) {
        let _ = self.committed.lock().unwrap().replace (true);
    }
}

impl Drop for TransactionWrapperMock {
    fn drop(&mut self) {
        let mut locked_wrapper = self.committed.lock().unwrap();
        if locked_wrapper.is_none() {
            (*locked_wrapper).replace (false);
        }
    }
}

impl TransactionWrapperMock {
    pub fn new () -> Self {
        Self {
            committed: Arc::new (Mutex::new (None)),
        }
    }

    pub fn committed_arc (&self) -> Arc<Mutex<Option<bool>>> {
        self.committed.clone()
    }
}
