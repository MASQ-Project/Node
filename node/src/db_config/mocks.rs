// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::sync::{Arc, Mutex};
use crate::database::connection_wrapper::TransactionWrapper;
use rusqlite::{Statement, Error};

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
