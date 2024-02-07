// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(test)]

use crate::database::db_initializer::ExternalData;
use crate::database::db_migrations::migrator_utils::{DBMigDeclarator, StatementObject};
use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
use masq_lib::logger::Logger;
use masq_lib::utils::to_string;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct DBMigDeclaratorMock {
    db_password_results: RefCell<Vec<Option<String>>>,
    execute_upon_transaction_params: Arc<Mutex<Vec<Vec<String>>>>,
    execute_upon_transaction_results: RefCell<Vec<rusqlite::Result<()>>>,
}

impl DBMigDeclaratorMock {
    pub fn db_password_result(self, result: Option<String>) -> Self {
        self.db_password_results.borrow_mut().push(result);
        self
    }

    pub fn execute_upon_transaction_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<String>>>>,
    ) -> Self {
        self.execute_upon_transaction_params = params.clone();
        self
    }

    pub fn execute_upon_transaction_result(self, result: rusqlite::Result<()>) -> Self {
        self.execute_upon_transaction_results
            .borrow_mut()
            .push(result);
        self
    }
}

impl DBMigDeclarator for DBMigDeclaratorMock {
    fn db_password(&self) -> Option<String> {
        self.db_password_results.borrow_mut().remove(0)
    }

    fn transaction(&self) -> &TransactionSafeWrapper {
        unimplemented!("Not needed so far")
    }

    fn execute_upon_transaction<'a>(
        &self,
        sql_statements: &[&'a dyn StatementObject],
    ) -> rusqlite::Result<()> {
        self.execute_upon_transaction_params.lock().unwrap().push(
            sql_statements
                .iter()
                .map(to_string)
                .collect::<Vec<String>>(),
        );
        self.execute_upon_transaction_results.borrow_mut().remove(0)
    }

    fn external_parameters(&self) -> &ExternalData {
        unimplemented!("Not needed so far")
    }

    fn logger(&self) -> &Logger {
        unimplemented!("Not needed so far")
    }
}
