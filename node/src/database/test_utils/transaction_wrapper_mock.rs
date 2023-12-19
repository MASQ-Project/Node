// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{
    ConnectionWrapper, SecureTransactionWrapper, TransactionInnerWrapper,
};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

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

#[derive(Debug)]
struct TransactionInnerWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    // This field hosts a logical unit able to make the correct
    // result that seems to be requested to go out based on
    // the test's setup instructions where the programmer may
    // have decided to use this advanced test procedure
    prepare_results_dispatcher_opt: Option<PrepareResultsDispatcher>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapperMock {
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

// Trying to store a rusqlite 'Statement' inside the TransactionWrapperMock and then placing this
// combination into the ConnectionWrapperMock was a difficult test of our Rust knowledge. This
// approach led to complex problems related to object lifetimes. We tried many times to fix these
// issues, but success, yet not guaranteed, seemed to depend on introducing numerous new explicit
// lifetimes. Some of these lifetimes required strict hierarchical relationships with others.
// There is also a hypothesis that the language may not let you maintain such relationships between
// objects at all.

// Eventually, we decided to take a different approach. The only solution that sparked some chance,
// even though by brute force, was to reduce the excessive use of borrowed references. To achieve
// this, we had to make the mock smarter by giving it its own database connection. This connection
// acts as a source for creating native rusqlite Statements. This was necessary because we couldn't
// find any alternative to letting the rusqlite library build the 'Statement' using their methods
// unexposed to the public interface. Additionally, our attempts to create StatementWrapper failed
// due to solid compilation problems. These problems arose from the way generic arguments were
// spread across the original 'Statement' implementation, which we couldn't replicate in our
// wrapper. Also, we couldn't bypass these generics. In Rust, a trait with generics in its methods
// isn't valid as long as we insist on using a trait object.

// With that said, we're relieved to have a working solution now. The most challenging aspect of
// this mock system is the 'prepare' method. Usually, you won't need an error to occur in this
// method because the production code often handles the results from 'prepare' using 'expect'. As
// you might know, we don't require using 'expect' for writing new tests. Therefore, there's nearly
// no point in causing an error that would only trigger a panic due to 'expect'.

// From the above, it's clear that we don't need to worry about generating errors in the 'prepare'
// method's return. Our focus should be on the Statement produced by this method. Although it might
// seem trivial at first, the 'prepare' method can significantly influence the result of the next
// function call made using this Statement. Fortunately, despite some challenges, we can indirectly
// shape this to meet our requirements.
// This indirectly prepared Statement can then lead to a useful error, simplifying our test writing.
// For instance, consider how this applies to methods like 'execute', 'query_row', or 'query_map'.

#[derive(Debug)]
struct SetupForOnlyAlteredStmts {
    conn: Box<dyn ConnectionWrapper>,
    queue_of_statements: RefCell<Vec<AlteredStmtByOrigin>>,
}

#[derive(Debug)]
struct SetupForProdCodeAndAlteredStmts {
    prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
    // This transaction must be here because otherwise all those
    // successful SQL operations would not be written into the database
    // persistently, even though some tests might expect those changes
    // to be findable in the database
    txn_aggregating_prod_code_stmts_opt: Option<SecureTransactionWrapper<'static>>,
    queue_with_prod_code_and_altered_stmts: RefCell<Vec<Option<AlteredStmtByOrigin>>>,
    // This connection is usually the most important, but using just the primary
    // connection used in executing the prod-code should be also possible.
    //
    // Common strategies for this additional connection:
    //
    // a) provide a connection pointing to an unrelated database,
    //    usually very simple, allowing a clearer way of provoking
    //    a very specific error that our tested code is supposed to respond to,
    //
    // b) asserting general errors from a read-only connection used during
    //    running statements whose purpose is changing the state of the database
    unique_conn_for_altered_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
}

impl SetupForProdCodeAndAlteredStmts {
    fn commit_prod_code_stmts(&mut self) -> Result<(), Error> {
        self.txn_aggregating_prod_code_stmts_opt
            .take()
            .expect("Dual setup in PrepareResultsDispatcher with missing txn; how possible?")
            .commit()
    }

    fn make_altered_stmt(&self, altered_stm: &str) -> Result<Statement, Error> {
        match self.unique_conn_for_altered_stmts_opt.as_ref() {
            None => self
                .txn_aggregating_prod_code_stmts_opt
                .as_ref()
                .expect("txn must be present")
                .prepare(altered_stm),
            Some(special_conn) => special_conn.prepare(altered_stm),
        }
    }
}

impl Drop for SetupForProdCodeAndAlteredStmts {
    fn drop(&mut self) {
        // The real transaction binds a reference that doesn't comply with safeness, it was made by
        // a backward cast from a raw pointer, which breaks checks for referencing an invalid memory.
        // We must make sure that this transaction deconstructs earlier than the database
        // Connection it has been derived from, avoiding the OS segmentation error.
        drop(self.txn_aggregating_prod_code_stmts_opt.take())
    }
}

#[derive(Debug)]
pub struct PrepareResultsDispatcher {
    setup: Either<SetupForOnlyAlteredStmts, SetupForProdCodeAndAlteredStmts>,
}

impl PrepareResultsDispatcher {
    pub fn new_with_altered_stmts_only(
        conn: Box<dyn ConnectionWrapper>,
        altered_stmts_queue: Vec<AlteredStmtByOrigin>,
    ) -> Self {
        let setup = SetupForOnlyAlteredStmts {
            conn,
            queue_of_statements: RefCell::new(altered_stmts_queue),
        };

        Self {
            setup: Either::Left(setup),
        }
    }

    pub fn new_with_prod_code_and_altered_stmts(
        prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
        altered_stmts_conn_opt: Option<Box<dyn ConnectionWrapper>>,
        stm_determining_queue: Vec<Option<AlteredStmtByOrigin>>,
    ) -> Self {
        let setup = {
            let ptr = Box::into_raw(prod_code_stmts_conn);
            let conn = unsafe { Box::from_raw(ptr) };

            let mut setup = SetupForProdCodeAndAlteredStmts {
                prod_code_stmts_conn: conn,
                txn_aggregating_prod_code_stmts_opt: None,
                queue_with_prod_code_and_altered_stmts: RefCell::new(stm_determining_queue),
                unique_conn_for_altered_stmts_opt: altered_stmts_conn_opt,
            };

            let conn = unsafe { ptr.as_mut().unwrap() };
            let txn = conn.transaction().unwrap();

            setup.txn_aggregating_prod_code_stmts_opt = Some(txn);

            setup
        };

        Self {
            setup: Either::Right(setup),
        }
    }

    fn produce_statement(&self, prod_code_stmt: &str) -> Result<Statement, Error> {
        match self.setup.as_ref() {
            Either::Left(setup) => Self::handle_stmt_for_only_altered(setup, prod_code_stmt),
            Either::Right(setup) => {
                Self::handle_stmt_for_prod_code_and_altered(setup, prod_code_stmt)
            }
        }
    }

    fn handle_stmt_for_only_altered<'conn>(
        setup: &'conn SetupForOnlyAlteredStmts,
        prod_code_stmt: &str,
    ) -> Result<Statement<'conn>, Error> {
        let stmt_by_origin = setup.queue_of_statements.borrow_mut().remove(0);
        let altered_stmt = stmt_by_origin.resolve_stm_to_use(prod_code_stmt);
        setup.conn.prepare(altered_stmt)
    }

    fn handle_stmt_for_prod_code_and_altered<'conn>(
        setup: &'conn SetupForProdCodeAndAlteredStmts,
        prod_code_stmt: &str,
    ) -> Result<Statement<'conn>, Error> {
        let altered_stmt_opt = setup
            .queue_with_prod_code_and_altered_stmts
            .borrow_mut()
            .remove(0);

        match altered_stmt_opt {
            None => setup.prod_code_stmts_conn.prepare(prod_code_stmt),
            Some(altered_stm) => {
                let altered_stm_str = altered_stm.resolve_stm_to_use(prod_code_stmt);
                setup.make_altered_stmt(altered_stm_str)
            }
        }
    }
}

#[derive(Debug)]
pub enum AlteredStmtByOrigin {
    // Used when you have an injected connection pointing to a different db
    // and you don't want to devise a new statement but use the same as
    // intended for the prod code
    IdenticalWithProdCode,
    FromSubstitution { new_stmt: String },
}

impl AlteredStmtByOrigin {
    fn resolve_stm_to_use<'a>(&'a self, prod_code_stm: &'a str) -> &'a str {
        match self {
            AlteredStmtByOrigin::IdenticalWithProdCode => prod_code_stm,
            AlteredStmtByOrigin::FromSubstitution {
                new_stmt: incident_statement,
            } => incident_statement.as_str(),
        }
    }
}
