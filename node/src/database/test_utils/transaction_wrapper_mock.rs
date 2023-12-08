// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{
    ConnectionWrapper, TransactionInnerWrapper, TransactionWrapper,
};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

// This builder is the only interface you should use

#[derive(Default)]
pub struct TransactionInnerWrapperMockBuilder {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_dispatcher_opt: Option<PrepareResultsDispatcher>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapperMockBuilder {
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

    pub fn build(self) -> Box<dyn TransactionInnerWrapper> {
        Box::new(TransactionInnerWrapperMock::new(
            self.prepare_params,
            self.prepare_results_dispatcher_opt,
            self.commit_params,
            self.commit_results,
            self.arbitrary_id_stamp_opt,
        ))
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

// Don't change the visibility to `pub`!
#[derive(Debug)]
struct TransactionInnerWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_dispatcher_opt: Option<PrepareResultsDispatcher>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapperMock {
    // Don't use this method with `pub`!
    fn new(
        prepare_params: Arc<Mutex<Vec<String>>>,
        prepare_results_dispatcher_opt: Option<PrepareResultsDispatcher>,
        commit_params: Arc<Mutex<Vec<()>>>,
        commit_results: RefCell<Vec<Result<(), Error>>>,
        arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
    ) -> Self {
        Self {
            prepare_params,
            prepare_results_dispatcher_opt,
            commit_params,
            commit_results,
            arbitrary_id_stamp_opt,
        }
    }

    fn has_dual_setup_in_results_dispatcher(&self) -> bool {
        if let Some(dispatcher) = self.prepare_results_dispatcher_opt.as_ref() {
            dispatcher.setup.is_right()
        } else {
            false
        }
    }
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
struct OnlyForgedStmts {
    conn: Box<dyn ConnectionWrapper>,
    queue_of_statements: RefCell<Vec<String>>,
}

#[derive(Debug)]
struct BothProdCodeAndForgedStmts {
    prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
    // This transaction must be here because otherwise all those
    // successful SQL operations would not be written into the database
    // persistently, even though some tests might expect those changes
    // to be findable in the database
    transaction_bearing_prod_code_stmts_opt: Option<TransactionWrapper<'static>>,
    queue_with_either_prod_code_or_forged_stmt: RefCell<Vec<Option<ForgedStmtByOrigin>>>,
    // This connection is usually the most important, but using just the primarily
    // prod code conn should be also possible. Strategies are either to provide
    // a connection pointing to an unrelated database, usually very simple, allowing
    // a more straightforward way of producing a very specific error that our tested
    // code is supposed to respond to, or another situation often found handy
    // for asserting general errors can be achieved by a read-only connection used
    // in statements that are supposed to change the state of the database
    unique_conn_for_forged_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
}

impl BothProdCodeAndForgedStmts {
    fn commit_prod_code_stmts(&mut self) -> Result<(), Error> {
        self.transaction_bearing_prod_code_stmts_opt
            .take()
            .expect("Dual setup in PrepareResultsDispatcher with missing txn; how possible?")
            .commit()
    }
}

impl Drop for BothProdCodeAndForgedStmts {
    fn drop(&mut self) {
        // The real transaction binds a reference that doesn't comply with safeness, it was made by
        // a backward cast from a raw pointer, which breaks checks for referencing an invalid memory.
        // We must make sure that this transaction deconstructs earlier than the database
        // Connection it has been derived from, avoiding the OS segmentation error.
        drop(self.transaction_bearing_prod_code_stmts_opt.take())
    }
}

#[derive(Debug)]
pub struct PrepareResultsDispatcher {
    setup: Either<OnlyForgedStmts, BothProdCodeAndForgedStmts>,
}

impl PrepareResultsDispatcher {
    pub fn new_with_forged_stmts_only(
        conn: Box<dyn ConnectionWrapper>,
        forged_stmts_queue: Vec<String>,
    ) -> Self {
        let setup = OnlyForgedStmts {
            conn,
            queue_of_statements: RefCell::new(forged_stmts_queue),
        };

        Self {
            setup: Either::Left(setup),
        }
    }

    pub fn new_with_prod_code_and_forged_stmts(
        prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
        forged_stmts_conn_opt: Option<Box<dyn ConnectionWrapper>>,
        stm_choice_determining_queue: Vec<Option<ForgedStmtByOrigin>>,
    ) -> Self {
        let setup = {
            let ptr = Box::into_raw(prod_code_stmts_conn);
            let conn = unsafe { Box::from_raw(ptr) };

            let mut setup = BothProdCodeAndForgedStmts {
                prod_code_stmts_conn: conn,
                transaction_bearing_prod_code_stmts_opt: None,
                queue_with_either_prod_code_or_forged_stmt: RefCell::new(
                    stm_choice_determining_queue,
                ),
                unique_conn_for_forged_stmts_opt: forged_stmts_conn_opt,
            };

            let conn = unsafe { ptr.as_mut().unwrap() };
            let txn = conn.transaction().unwrap();

            setup.transaction_bearing_prod_code_stmts_opt = Some(txn);

            setup
        };

        Self {
            setup: Either::Right(setup),
        }
    }

    fn produce_statement(&self, prod_code_original_stm: &str) -> Result<Statement, Error> {
        match self.setup.as_ref() {
            Either::Left(setup) => Self::handle_stm_for_forged_only(setup),
            Either::Right(setup) => {
                Self::handle_stm_for_prod_code_or_forged(setup, prod_code_original_stm)
            }
        }
    }

    fn handle_stm_for_forged_only(setup: &OnlyForgedStmts) -> Result<Statement, Error> {
        let stm = setup.queue_of_statements.borrow_mut().remove(0);
        setup.conn.prepare(&stm)
    }

    fn handle_stm_for_prod_code_or_forged<'conn>(
        setup: &'conn BothProdCodeAndForgedStmts,
        prod_code_original_stm: &str,
    ) -> Result<Statement<'conn>, Error> {
        let stm_opt = setup
            .queue_with_either_prod_code_or_forged_stmt
            .borrow_mut()
            .remove(0);
        match stm_opt {
            None => setup.prod_code_stmts_conn.prepare(prod_code_original_stm),
            Some(forged_stm) => {
                let stm = match &forged_stm {
                    ForgedStmtByOrigin::FromProdCode => prod_code_original_stm,
                    ForgedStmtByOrigin::ProdCodeSubstitution {
                        new_statement: incident_statement,
                    } => incident_statement.as_str(),
                };
                match setup.unique_conn_for_forged_stmts_opt.as_ref() {
                    None => setup
                        .transaction_bearing_prod_code_stmts_opt
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
pub enum ForgedStmtByOrigin {
    // Used when you have an injected connection pointing to a different db
    // and you don't want to devise a new statement but use the same as
    // intended for the prod code
    FromProdCode,
    ProdCodeSubstitution { new_statement: String },
}
