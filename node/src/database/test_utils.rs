// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::db_initializer::DbInitializationConfig;
use crate::database::db_initializer::{DbInitializer, InitializationError};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionWrapper};
use itertools::Either;
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
pub struct TransactionWrapperMock<'a> {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results: Option<TransactionPrepareMethodResults<'a>>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
}

impl<'a> TransactionWrapperMock<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_results(mut self, results: TransactionPrepareMethodResults<'a>) -> Self {
        self.prepare_results = Some(results);
        self
    }

    pub fn commit_params(mut self, params: &Arc<Mutex<Vec<()>>>)->Self{
        self.commit_params = params.clone();
        self
    }

    pub fn commit_result(self, result: Result<(), Error>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }
}

impl TransactionWrapper for TransactionWrapperMock<'_> {
    fn prepare(&self, prod_code_query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(prod_code_query.to_string());

        let prepared_results = self.prepare_results.as_ref().unwrap();
        let idx_info_opt = prepared_results.stubbed_call_idx_info_opt();
        prepared_results.produce_statement(idx_info_opt, prod_code_query)
    }

    fn execute(&self, _query: &str, _params: &[&dyn ToSql]) -> Result<usize, Error> {
        unimplemented!("not needed yet")
    }

    fn commit(&mut self) -> Result<(), Error> {
        let next_result = self.commit_results.borrow_mut().remove(0);
        if next_result.is_ok() {
            if let Some(results) = self.prepare_results.as_mut() {
                if let Some(realistic_transaction) =
                    results.prod_code_calls_transaction_opt.as_mut()
                {
                    return realistic_transaction.commit();
                }
            }
            next_result
        } else {
            next_result
        }
    }
}

// The idea to store a rusqlite 'Statement' in the TransactionWrapperMock and put this compound into
// the ConnectionWrapperMock did not turn out well. It allured lifetime issues. A fair amount of
// attempts was made to get those right but a success was conditioned by a creation of lot of new
// explicit lifetimes out of which some were calling for strict hierarchical relations between one
// and another.
// Having given up, the only practicable way to make this mock do what it should was to simplify
// the high usage of borrows.
// In order to see it done we necessarily had to have the mock much smarter and give it its own
// DB connection serving as a future on-demand producer of a native rusqlite Statement, because
// there really hasn't been an option left than having the rusqlite library construct the Statement
// by itself, using their standard API, and secondly, because all our attempts to write
// a StatementWrapper had failed for solid compilation issues where (statically determined) generic
// arguments lies spread across the original implementation of the Statement which could not be
// replicable with our wrapper, and we also could not avoid them. A trait using generics in its
// methods isn't valid in Rust, while trait objects are the technology we otherwise exclusively use.

// That having said, we are glad to finally have at least something to use. The most difficult part
// of the mocking system below, though, is in the 'prepare' method. Notice that most of time, if not
// always, you're not going to need an error to turn up in there. That's because the production code
// usually treats the returned results by 'prepare' with the use of 'expect'. As you may know, we
// do not consider 'expect' usages a requirement for writing new tests. There is therefore little to
// none value in stimulating an error which would only stimulate a panic on that 'expect'.

// The previous paragraph clears up that we do not need to care about a mechanism to deliver errors
// on the return of the 'prepare' method. The place worth our interest, though, is the produced
// Statement coming out from this method. Even though looking perhaps a little nonsensical at first,
// the 'prepare' method can have a strong impact on the result returned from the next, upstream
// function call, to happen on top of this Statement, and which, luckily for us (despite certain
// difficulties), can be indirectly shaped this way towards our requirements.
// This distantly prepared Statement can then cause a certainly useful error, easing our test
// writing. For some examples let's consider the following methods 'execute', 'query_row' or
// 'query_map'.

#[derive(Default, Debug)]
pub struct TransactionPrepareMethodResults<'a> {
    calls_counter: RefCell<usize>,
    prod_code_calls_conn_shared_for_both: bool,
    // Prod code calls setup
    prod_code_calls_transaction_opt: Option<Box<dyn TransactionWrapper + 'a>>,
    requested_preceding_prod_code_calls: usize,
    // Stubbed calls setup
    // Optional only because of the builder pattern
    stubbed_calls_conn_opt: Option<Box<dyn ConnectionWrapper>>,
    stubbed_calls_optional_statements_literals: Vec<Option<String>>,
}

impl<'a> TransactionPrepareMethodResults<'a> {
    pub fn prod_code_calls_transaction(mut self, txn: Box<dyn TransactionWrapper + 'a>) -> Self {
        if self.prod_code_calls_transaction_opt.is_none() {
            self.prod_code_calls_transaction_opt = Some(txn);
        } else {
            panic!("Use only single call of \"prod_code_calls_transaction_opt!\"")
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

        if self.prod_code_calls_transaction_opt.is_some()
            && self.requested_preceding_prod_code_calls > 0
        {
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
                    .prod_code_calls_transaction_opt
                    .as_ref()
                    .expect("Prod code call with uninitialized txn")
                    .prepare(prod_code_query);
                self.increment_counter();
                result
            }
            Some(stubbed_call_idx_info) => {
                let stm = self.bring_out_stubbed_statement(stubbed_call_idx_info, prod_code_query);
                self.increment_counter();
                Ok(stm)
            }
        }
    }

    fn bring_out_stubbed_statement(
        &self,
        idx_info: StubbedCallIndexInfo,
        prod_code_query: &str,
    ) -> Statement {
        let upcoming_call_idx = *self.calls_counter.borrow_mut();
        let idx = idx_info.calculate_idx(upcoming_call_idx);
        let query = match self
            .stubbed_calls_optional_statements_literals
            .get(idx)
            .unwrap()
        {
            Some(stubbed_query) => stubbed_query,
            None => prod_code_query,
        };
        let result = match self.resolve_choice_of_stubbed_conn() {
            Either::Left(txn) => txn.prepare(query),
            Either::Right(conn) => conn.prepare(query),
        };
        result.unwrap()
    }

    fn increment_counter(&self) {
        *self.calls_counter.borrow_mut() += 1
    }

    fn resolve_choice_of_stubbed_conn(
        &self,
    ) -> Either<&dyn TransactionWrapper, &dyn ConnectionWrapper> {
        if self.prod_code_calls_conn_shared_for_both {
            Either::Left(
                self.prod_code_calls_transaction_opt
                    .as_ref()
                    .expect("Conn for prod code calls not available")
                    .as_ref(),
            )
        } else {
            Either::Right(
                self.stubbed_calls_conn_opt
                    .as_ref()
                    .expect("Conn for the requested stubbed calls was not prepared")
                    .as_ref(),
            )
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

    fn calculate_idx(&self, upcoming_call_idx: usize) -> usize {
        upcoming_call_idx - self.preceding_prod_code_calls
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
