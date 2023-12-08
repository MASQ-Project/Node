// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{
    ConnectionWrapper, TransactionWrapper, TransactionInnerWrapper,
};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

#[derive(Default, Debug)]
pub struct TransactionInnerWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_dispatcher_opt: Option<PrepareResultsDispatcher>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapperMock {
    pub fn new() -> Self {
        Self::default()
    }

    fn has_dual_setup_in_results_dispatcher(&self) -> bool {
        if let Some(dispatcher) = self.prepare_results_dispatcher_opt.as_ref() {
            dispatcher.setup.is_right()
        } else {
            false
        }
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_results(mut self, results: PrepareResultsDispatcher) -> Self {
        self.prepare_results_dispatcher_opt = Some(results);
        self
    }

    pub fn commit_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.commit_params = params.clone();
        self
    }

    pub fn commit_result(self, result: Result<(), Error>) -> Self {
        self.commit_results.borrow_mut().push(result);
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

impl TransactionInnerWrapper for TransactionInnerWrapperMock {
    fn prepare(&self, prod_code_query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(prod_code_query.to_string());

        self.prepare_results_dispatcher_opt
            .as_ref()
            .unwrap()
            .produce_statement(prod_code_query)
    }

    fn execute(&self, _query: &str, _params: &[&dyn ToSql]) -> Result<usize, Error> {
        unimplemented!("not needed yet")
    }

    fn commit(&mut self) -> Result<(), Error> {
        self.commit_params.lock().unwrap().push(());

        let next_result = self.commit_results.borrow_mut().remove(0);
        // If the commit is meant to succeed we check for the transaction we may keep
        // in the `PrepareResultsDispatcher` (design allowing for the initial database interactions
        // in the test to be run with the genuine prod code statements), and thus all data changes these
        // statements may claim to introduce (if called) will be recorded in the database and
        // visible at the end of the test.
        if next_result.is_ok() && self.has_dual_setup_in_results_dispatcher() {
            self.prepare_results_dispatcher_opt
                .as_mut()
                .expect("presence just checked")
                .setup
                .as_mut()
                .expect_right("dual setup just checked")
                .commit_prod_code_stmts()
        } else {
            next_result
        }
    }

    arbitrary_id_stamp_in_trait_impl!();
}

// TODO curate this text (probably not up to date)
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

#[derive(Debug)]
struct SQLsStubbedOnly {
    conn: Box<dyn ConnectionWrapper>,
    queue_of_statements_to_execute: RefCell<Vec<String>>,
}

#[derive(Debug)]
struct SQLsProdCodeAndStubbed {
    prod_code_conn: Box<dyn ConnectionWrapper>,
    // This transaction must be here because otherwise all those
    // successful SQL operations would not be written into the database
    // persistently, even though some tests might expect those changes
    // to be findable in the database
    prod_code_transaction_opt: Option<TransactionWrapper<'static>>,
    queue_determining_use_of_prod_code_stm_or_stubbed_stmts: RefCell<Vec<Option<StubbedStatement>>>,
    // This connection is usually the most important, but using just the primarily
    // prod code conn should be also possible. Strategies are either to provide
    // a connection pointing to an unrelated database, usually very simple, allowing
    // a more straightforward way of producing a very specific error that our tested
    // code is supposed to respond to, or another situation often found handy
    // for asserting general errors can be achieved by a read-only connection used
    // in statements that are supposed to change the state of the database
    diff_conn_for_stubbed_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
}

impl SQLsProdCodeAndStubbed {
    fn commit_prod_code_stmts(&mut self) -> Result<(), Error> {
        self.prod_code_transaction_opt
            .take()
            .expect("dual setup in TransactionWrapperInnerMock without txn")
            .commit()
    }
}

impl Drop for SQLsProdCodeAndStubbed {
    fn drop(&mut self) {
        // The real transaction binds a reference that doesn't comply with safeness, it was made by
        // a backward cast from a raw pointer, which breaks checks for referencing an invalid memory.
        // We must make sure that this transaction deconstructs earlier than the database
        // Connection it has been derived from, avoiding the OS segmentation error.
        drop(self.prod_code_transaction_opt.take())
    }
}

#[derive(Debug)]
pub struct PrepareResultsDispatcher {
    setup: Either<SQLsStubbedOnly, SQLsProdCodeAndStubbed>,
}

impl PrepareResultsDispatcher {
    pub fn new_with_stubbed_only(
        conn: Box<dyn ConnectionWrapper>,
        stubbed_stmts_queue: Vec<String>,
    ) -> Self {
        let setup = SQLsStubbedOnly {
            conn,
            queue_of_statements_to_execute: RefCell::new(stubbed_stmts_queue),
        };

        Self {
            setup: Either::Left(setup),
        }
    }

    pub fn new_with_prod_code_and_stubbed(
        prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
        stubbed_conn_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
        stubbed_stmts_opt_queue: Vec<Option<StubbedStatement>>,
    ) -> Self {
        let setup = {
            let ptr = Box::into_raw(prod_code_stmts_conn);
            let conn = unsafe { Box::from_raw(ptr) };

            let mut setup = SQLsProdCodeAndStubbed {
                prod_code_conn: conn,
                prod_code_transaction_opt: None,
                queue_determining_use_of_prod_code_stm_or_stubbed_stmts: RefCell::new(
                    stubbed_stmts_opt_queue,
                ),
                diff_conn_for_stubbed_stmts_opt: stubbed_conn_stmts_opt,
            };

            let conn = unsafe { ptr.as_mut().unwrap() };
            let txn = conn.transaction().unwrap();

            setup.prod_code_transaction_opt = Some(txn);

            setup
        };

        Self {
            setup: Either::Right(setup),
        }
    }

    fn produce_statement(&self, prod_code_original_stm: &str) -> Result<Statement, Error> {
        match self.setup.as_ref() {
            Either::Left(setup) => Self::handle_stm_for_stubbed_only(setup),
            Either::Right(setup) => {
                Self::handle_stm_for_prod_code_or_stubbed(setup, prod_code_original_stm)
            }
        }
    }

    fn handle_stm_for_stubbed_only(setup: &SQLsStubbedOnly) -> Result<Statement, Error> {
        let stm = setup.queue_of_statements_to_execute.borrow_mut().remove(0);
        setup.conn.prepare(&stm)
    }

    fn handle_stm_for_prod_code_or_stubbed<'conn>(
        setup: &'conn SQLsProdCodeAndStubbed,
        prod_code_original_stm: &str,
    ) -> Result<Statement<'conn>, Error> {
        let stm_opt = setup
            .queue_determining_use_of_prod_code_stm_or_stubbed_stmts
            .borrow_mut()
            .remove(0);
        match stm_opt {
            None => setup.prod_code_conn.prepare(prod_code_original_stm),
            Some(stubbed_stm) => {
                let stm = match &stubbed_stm {
                    StubbedStatement::ProdCodeOriginal => prod_code_original_stm,
                    StubbedStatement::ProdCodeSubstitution { incident_statement } => {
                        incident_statement.as_str()
                    }
                };
                match setup.diff_conn_for_stubbed_stmts_opt.as_ref() {
                    None => setup
                        .prod_code_transaction_opt
                        .as_ref()
                        .expect("txn must be present")
                        .prepare(stm),
                    Some(special_conn) => special_conn.prepare(stm),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum StubbedStatement {
    // Used when you have an injected connection pointing to a different db
    // and you don't want to devise a new statement but use the same as
    // intended for the prod code
    ProdCodeOriginal,
    ProdCodeSubstitution { incident_statement: String },
}
