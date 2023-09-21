// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionWrapper};
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct ConnectionWrapperMock<'a> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: RefCell<Vec<Result<Statement<'a>, Error>>>,
    transaction_results: RefCell<Vec<Result<Box<dyn TransactionWrapper + 'a>, Error>>>,
}

unsafe impl<'a> Send for ConnectionWrapperMock<'a> {}

impl<'a> ConnectionWrapperMock<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_result(self, result: Result<Statement<'a>, Error>) -> Self {
        self.prepare_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_result(
        self,
        result: Result<Box<dyn TransactionWrapper + 'a>, Error>,
    ) -> Self {
        self.transaction_results.borrow_mut().push(result);
        self
    }
}

impl<'a> ConnectionWrapper for ConnectionWrapperMock<'a> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(String::from(query));
        self.prepare_results.borrow_mut().remove(0)
    }

    fn transaction<'b>(&'b mut self) -> Result<Box<dyn TransactionWrapper + 'b>, Error> {
        self.transaction_results.borrow_mut().remove(0)
    }
}

#[derive(Default, Debug)]
pub struct TransactionWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_opt: Option<TransactionPrepareMethodResults>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
}

impl TransactionWrapperMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_results(mut self, results: TransactionPrepareMethodResults) -> Self {
        self.prepare_results_opt = Some(results);
        self
    }

    pub fn commit_result(self, result: Result<(), Error>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}

impl TransactionWrapper for TransactionWrapperMock {
    fn prepare(&self, prod_code_query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(prod_code_query.to_string());

        let prepared_results = self.prepare_results_opt.as_ref().unwrap();
        let idx_info_opt = prepared_results.stubbed_call_idx_info_opt();
        prepared_results.produce_statement(idx_info_opt, prod_code_query)
    }

    fn execute(&self, _query: &str, _params: &[&dyn ToSql]) -> Result<usize, Error> {
        unimplemented!("not needed yet")
    }

    fn commit(&mut self) -> Result<(), Error> {
        self.commit_results.borrow_mut().remove(0)
    }
}

// To store a Statement in the TransactionWrapperMock and, as one piece, put it into
// the ConnectionWrapperMock turned out not working out well. It allured lifetime issues. There were
// a couple of attempts to get those right but it was conditioned by a creation of lot of new
// explicit lifetimes that sometimes called for strict hierarchical relations between one and another.
// Giving up, the only practicable way to make this mock do what it should was to simplify the overuse
// of borrows.
// In order to achieve that, we necessarily had to have the mock much smarter and give it its own
// DB connection thanks to which we would be able to spawn a native rusqlite Statement, because there
// really isn't an option left than having the rusqlite library construct the Statement according to
// their standard API, and secondly, because all our attempts to write a StatementWrapper had failed
// for compilation issues where (static) generic arguments that are widespread across the original
// implementation of the Statement were not replicable on our wrapper. The reason is
// a trait object with such methods isn't valid.

// That having said, we are happy to have at least something. The hardest part of the mock below,
// though, is the 'prepare' method. Most of time, if not always, you're not going to need an error
// in there. That's because our production code usually treats the returned results from 'prepare'
// by the use of 'expect'. As you may know, we don't consider 'expect' calls a requirement for
// writing extra tests. There is therefore little to none value in stimulating an error which would
// in turn stimulate a panic on the 'expect'.

// The previous paragraph explains that we do not need a mechanism to incorporate errors directly in
// the 'prepare' method. The place that should draw our interest, though, is in fact the **produced
// Statement** from this method. Even though maybe counter-intuitive at first, the 'prepare' method
// can affect the result of the next, upstream function call, happening upon the given Statement that,
// luckily for us and despite certain uneasiness, can be made shaped according to our needs. This
// carefully prepared Statement then can cause a useful error, easing test writing. For example at
// the following methods 'execute', 'query_row' or 'query_map'.

#[derive(Default, Debug)]
pub struct TransactionPrepareMethodResults {
    calls_counter: RefCell<usize>,
    prod_code_calls_conn_shared_for_both: bool,
    // Prod code setup
    prod_code_conn_opt: Option<Box<dyn ConnectionWrapper>>,
    requested_preceding_prod_code_calls: usize,
    // Stubbed calls setup
    // Optional only because of the builder pattern
    stubbed_calls_conn_opt: Option<Box<dyn ConnectionWrapper>>,
    stubbed_calls_optional_statements_literals: Vec<Option<String>>,
}

impl TransactionPrepareMethodResults {
    pub fn prod_code_calls_conn(mut self, conn: Box<dyn ConnectionWrapper>) -> Self {
        if self.prod_code_conn_opt.is_none() {
            self.prod_code_conn_opt = Some(conn)
        } else {
            panic!("Use only single call of \"prod_code_calls_conn!\"")
        }
        self
    }

    pub fn preceding_prod_code_calls(mut self, total_of_prod_code_calls: usize) -> Self {
        if self.requested_preceding_prod_code_calls == 0 {
            self.requested_preceding_prod_code_calls = total_of_prod_code_calls
        } else {
            panic!("Use only single call of \"number_of_prod_code_calls!\"")
        }
        self
    }

    pub fn prod_code_calls_conn_shared_for_both(mut self) -> Self {
        self.prod_code_calls_conn_shared_for_both = true;
        self
    }

    pub fn stubbed_calls_conn(mut self, conn: Box<dyn ConnectionWrapper>) -> Self {
        if self.stubbed_calls_conn_opt.is_none() {
            self.stubbed_calls_conn_opt = Some(conn)
        } else {
            panic!("Use only single call of \"stubbed_calls_conn!\"")
        }
        self
    }

    pub fn add_single_stubbed_call_from_prod_code_statement(mut self) -> Self {
        self.stubbed_calls_optional_statements_literals.push(None);
        self
    }

    pub fn add_single_stubbed_call_statement(mut self, statement: &str) -> Self {
        self.stubbed_calls_optional_statements_literals
            .push(Some(statement.to_string()));
        self
    }

    fn stubbed_call_idx_info_opt(&self) -> Option<StubbedCallIndexInfo> {
        let upcoming_call_idx = *self.calls_counter.borrow();

        if self.prod_code_conn_opt.is_some() && self.requested_preceding_prod_code_calls > 0 {
            let preceding_prod_code_calls = self.requested_preceding_prod_code_calls;
            if preceding_prod_code_calls > upcoming_call_idx {
                None
            } else {
                Some(StubbedCallIndexInfo::new(preceding_prod_code_calls))
            }
        } else {
            Some(StubbedCallIndexInfo::new(0))
        }
    }

    fn produce_statement(
        &self,
        idx_info_opt: Option<StubbedCallIndexInfo>,
        prod_code_query: &str,
    ) -> Result<Statement, Error> {
        match idx_info_opt {
            None => {
                let result = self
                    .prod_code_conn_opt
                    .as_ref()
                    .expect("Conn for the requested initial prod code calls was not prepared")
                    .prepare(prod_code_query);
                self.increment_counter();
                result
            }
            Some(stabbed_call_idx_info) => {
                let upcoming_call_idx = *self.calls_counter.borrow_mut();
                let idx = stabbed_call_idx_info.calculate_idx(upcoming_call_idx);
                let query = match self
                    .stubbed_calls_optional_statements_literals
                    .get(idx)
                    .unwrap()
                {
                    Some(stubbed_query) => stubbed_query,
                    None => prod_code_query,
                };
                let conn = self.resolve_choice_of_stubbed_conn();
                let result = conn.prepare(query);
                self.increment_counter();
                result
            }
        }
    }

    fn increment_counter(&self) {
        *self.calls_counter.borrow_mut() += 1
    }

    fn resolve_choice_of_stubbed_conn(&self) -> &dyn ConnectionWrapper {
        if self.prod_code_calls_conn_shared_for_both {
            &**self
                .prod_code_conn_opt
                .as_ref()
                .expect("Conn for prod code calls not available")
        } else {
            &**self
                .stubbed_calls_conn_opt
                .as_ref()
                .expect("Conn for the requested stubbed calls was not prepared")
        }
    }
}

struct StubbedCallIndexInfo {
    preceding_prod_code_calls: usize,
}

impl StubbedCallIndexInfo {
    fn new(preceding_prod_code_calls: usize) -> Self {
        Self {
            preceding_prod_code_calls,
        }
    }

    fn calculate_idx(&self, upcoming_call_absolute_idx: usize) -> usize {
        upcoming_call_absolute_idx - self.preceding_prod_code_calls
    }
}

#[derive(Default)]
pub struct DbInitializerMock {
    pub initialize_params: Arc<Mutex<Vec<(PathBuf, DbInitializationConfig)>>>,
    pub initialize_results: RefCell<Vec<Result<Box<dyn ConnectionWrapper>, InitializationError>>>,
}

impl DbInitializer for DbInitializerMock {
    fn initialize(
        &self,
        path: &Path,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        self.initialize_params
            .lock()
            .unwrap()
            .push((path.to_path_buf(), init_config));
        self.initialize_results.borrow_mut().remove(0)
    }

    #[allow(unused_variables)]
    fn initialize_to_version(
        &self,
        path: &Path,
        target_version: usize,
        init_config: DbInitializationConfig,
    ) -> Result<Box<dyn ConnectionWrapper>, InitializationError> {
        intentionally_blank!()
        /*all existing test calls only initialize() in the mocked version,
        but we need to call initialize_to_version() for the real object
        in order to carry out some important tests too*/
    }
}

impl DbInitializerMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize_parameters(
        mut self,
        parameters: Arc<Mutex<Vec<(PathBuf, DbInitializationConfig)>>>,
    ) -> DbInitializerMock {
        self.initialize_params = parameters;
        self
    }

    pub fn initialize_result(
        self,
        result: Result<Box<dyn ConnectionWrapper>, InitializationError>,
    ) -> DbInitializerMock {
        self.initialize_results.borrow_mut().push(result);
        self
    }
}
