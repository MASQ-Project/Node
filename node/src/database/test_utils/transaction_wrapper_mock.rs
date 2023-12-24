// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{
    ConnectionWrapper, TransactionInnerWrapper, TransactionSafeWrapper,
};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

// The qualities of this builder are in its own unrestricted usability contrasting with how it
// creates an encapsulated environment in which it configures and eventually builds the mock. All
// that in order to minimize the exposure of the mock
// to the outer scope. While a wrapped transaction is being created, and we need it to be tamed in
// a test, this mock is supposed to become its inner wrapper of the supposed real world transaction.
// The inner wrapper ever needs to stay private. Then there is the outer, public one, that anyone
// can manipulate with.
//
// You can read more about the safeness reasons for this onion structure in comments nearby these
// wrappers.

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

// Keep as a private class, seek a builder of it instead

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
        if next_result.is_ok() {
            if let Some(prepared_results) = self.prepare_results_dispatcher_opt.as_mut() {
                if let Either::Right(for_both) = &mut prepared_results.setup {
                    return for_both.commit_prod_code_stmts();
                }
            }
        }

        next_result
    }

    arbitrary_id_stamp_in_trait_impl!();
}

// Trying to store a rusqlite 'Statement' inside the TransactionWrapperMock and then placing this
// combination into the ConnectionWrapperMock became a thorough test of our Rust knowledge. This
// approach led to complex problems related to object lifetimes. We tried many times to fix these
// issues, but success, while never guaranteed, seemed to depend on introduction of numerous new
// explicit lifetimes. Some of these lifetimes required strict hierarchical relationships with
// others. A hypothesis exists that the way the language is designed maintaining such relationships
// between objects cannot be achieved.

// Eventually, we decided to take a different approach. The only solution that sparked some chances
// was to radically reduce the excessive use of borrowed references. We had to make the mock much
// smarter by giving it its own database connection, or sometimes even two. This connection acts as
// a source for creating native rusqlite Statements. This was unavoidable because we couldn't
// find any alternative to having the rusqlite library build the 'Statement' using their internal
// methods. Additionally, our attempts to create a StatementWrapper failed due to solid compilation
// problems. These problems arose from the way generic arguments were spread across the methods
// in the 'Statement' implementation, of which there is quite a lot of those that we use too.
// We couldn't replicate that in our wrapper. In Rust, no one can write a trait with generics in
// the methods as long as it is meant to be used as a trait object.

// With that said, we're relieved to have at least one working solution now. The most challenging
// aspect of this mock is the 'prepare' method. Usually, you won't need an error to occur in this
// method because the production code often handles the results using simply 'expect'. As you might
// know, we don't require writing new tests for using 'expect'. There's nearly no point
// in exercising an error that would only trigger a panic due to 'expect' in a place where,
// fundamentally, we'd never expect an error.

// Our focus must be on the Statement produced by this method. It needs to be understood that
// the 'prepare' method has a crucial influence to the result of the following function call taking
// the Statement as an argument. Fortunately, despite some challenges being always around, we can
// indirectly steer the course of that future procedure to have the very result we want to happen
// in the test. This approach can be applied to various methods such as 'execute', 'query_row',
// or 'query_map'.

#[derive(Debug)]
struct SetupForOnlyAlteredStmts {
    conn: Box<dyn ConnectionWrapper>,
    queue_of_statements: RefCell<Vec<AlteredStmtByOrigin>>,
}

#[derive(Debug)]
struct SetupForProdCodeAndAlteredStmts {
    prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
    // This transaction must be carried along because otherwise all those
    // successful SQL operations would be written into the database right away,
    // which is not how the reality works. On the other hand we do want them to
    // affect the database persistently if the commit point is reached, so that
    // the test can laid assertions that can be faithful to the expected changes
    // happening inside the database.
    txn_bearing_prod_code_stmts_opt: Option<TransactionSafeWrapper<'static>>,
    queue_with_prod_code_and_altered_stmts: RefCell<Vec<Option<AlteredStmtByOrigin>>>,
    // This connection is usually the most important, but using just the prod code
    // connection meant primarily for the prod-code statements should be also possible.
    //
    // Common strategies to use this additional connection:
    //
    // a) provide a connection pointing to another database, usually declared
    //    very simple, that allows a simplified, more direct way of stimulation
    //    of a special and often quite unusual error that our tested code should
    //    respond to,
    //
    // b) assert on general, unspecific errors while using a connection with
    //    only the read rights for statements whose task is to change the state
    //    of the database
    unique_conn_for_altered_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
}

impl SetupForProdCodeAndAlteredStmts {
    fn commit_prod_code_stmts(&mut self) -> Result<(), Error> {
        self.txn_bearing_prod_code_stmts_opt
            .take()
            .expect("Dual setup with a missing txn should never happen")
            .commit()
    }

    fn make_altered_stmt(&self, altered_stm: &str) -> Result<Statement, Error> {
        match self.unique_conn_for_altered_stmts_opt.as_ref() {
            None => self
                .txn_bearing_prod_code_stmts_opt
                .as_ref()
                .expect("The txn must be present")
                .prepare(altered_stm),
            Some(special_conn) => special_conn.prepare(altered_stm),
        }
    }
}

impl Drop for SetupForProdCodeAndAlteredStmts {
    fn drop(&mut self) {
        // The real transaction borne in this object binds to a reference that doesn't comply with
        // safeness anymore, it has gone through backward cast from a raw pointer, which
        // automatically breaks the check mechanism for referencing an invalid memory. We must make
        // sure by having this Drop implementation that this transaction deconstructs earlier than
        // the database Connection by which it was produced, avoiding an OS segmentation error.
        drop(self.txn_bearing_prod_code_stmts_opt.take())
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
                txn_bearing_prod_code_stmts_opt: None,
                queue_with_prod_code_and_altered_stmts: RefCell::new(stm_determining_queue),
                unique_conn_for_altered_stmts_opt: altered_stmts_conn_opt,
            };

            let conn = unsafe { ptr.as_mut().unwrap() };
            let txn = conn.transaction().unwrap();

            setup.txn_bearing_prod_code_stmts_opt = Some(txn);

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
        let altered_stmt = stmt_by_origin.str_stmt(prod_code_stmt);
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
                let altered_stm_str = altered_stm.str_stmt(prod_code_stmt);
                setup.make_altered_stmt(altered_stm_str)
            }
        }
    }
}

#[derive(Debug)]
pub enum AlteredStmtByOrigin {
    // Use this when you plan to have a connection pointing to a different db, but at the same time,
    // you don't want to go through devising a new statement but to use the same one as in the prod
    // code
    IdenticalWithProdCode,
    FromSubstitution { new_stmt: String },
}

impl AlteredStmtByOrigin {
    fn str_stmt<'a>(&'a self, prod_code_stm: &'a str) -> &'a str {
        match self {
            AlteredStmtByOrigin::IdenticalWithProdCode => prod_code_stm,
            AlteredStmtByOrigin::FromSubstitution {
                new_stmt: incident_statement,
            } => incident_statement.as_str(),
        }
    }
}
