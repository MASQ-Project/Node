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

// The qualities of this builder are given by its wide usability contrasting with how it
// enables creating encapsulated environment, inside which it configures and eventually builds
// the otherwise inaccessible mock. It minimizes the exposure of the special internal mock
// to such an extend, that any developer should come to understand that the insulation
// was done on purpose and should be respected. It's important to prevent use of the inner
// transaction wrapper without its outer counterpart, because only that one gives it the needed
// safeness.
//
// Read more about the improved safeness in this layered structure in comments near to these
// wrappers.

#[derive(Default)]
pub struct TransactionInnerWrapperMockBuilder {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_producer_opt: Option<PrepareMethodResultsProducer>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapperMockBuilder {
    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_results(mut self, results: PrepareMethodResultsProducer) -> Self {
        self.prepare_results_producer_opt = Some(results);
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
        Box::new(TransactionInnerWrapperMock {
            prepare_params: self.prepare_params,
            prepare_results_producer_opt: self.prepare_results_producer_opt,
            commit_params: self.commit_params,
            commit_results: self.commit_results,
            arbitrary_id_stamp_opt: self.arbitrary_id_stamp_opt,
        })
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

// Keep as a private class, seek a builder of it instead

#[derive(Debug)]
struct TransactionInnerWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    // This field holds an object that can produce a requested result based on the configuration
    // of this mock (from the setup of the test) reflecting the programmer's decision that he needs
    // control over the results coming out of the 'prepare' method
    prepare_results_producer_opt: Option<PrepareMethodResultsProducer>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionInnerWrapper for TransactionInnerWrapperMock {
    fn prepare(&self, prod_code_query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(prod_code_query.to_string());

        self.prepare_results_producer_opt
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
        // If we pull out a result that says success, we check for a transaction inside `PrepareMethodResultsProducer`
        // that would belong with a connection meant for keeping the real prod code statements, if we find one, we will
        // commit it now. This design enables to make writes to the database that would've happened in the real life
        // scenario anyway. The database then will be reliable for assertions in the test, not omitting any steps that
        // could somehow modify it.
        if next_result.is_ok() {
            if let Some(prepared_results) = self.prepare_results_producer_opt.as_mut() {
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
// combination into the ConnectionWrapperMock placed us before complex lifetime issues. A hypothesis
// is that because of the design of the language maintaining such relationships between objects
// may be unachievable.

// Eventually, we decided to take a different approach: radically reduce the excessive use of
// borrowed references. We had to make the mock much smarter by giving it its own db connection,
// or in some cases two. This connection acts as a source for creating native rusqlite Statements.
// This was unavoidable because we couldn't find any alternative to having the rusqlite library
// build the 'Statement' using their internal methods. Additionally, our attempts to create
// a StatementWrapper failed due to solid compilation problems. These problems were caused by
// the way generic arguments are spread across the methods in the 'Statement' implementation,
// out of which quite a lot of them are being used by us. It couldn't be replicated in our wrapper.
// In Rust, no one may write a trait with generic arguments in its methods as long as a trait object
// is to be formed.

// With that said, we're relieved to have at least one working solution now. Speaking of the 'prepare'
// method, an error would hardly be needed because the production code simply unwraps the results by
// using 'expect'. That is a function excluded from the requirement of writing tests for.

// The 'Statement' produced by this method must be better understood. The 'prepare' method has
// a crucial influence on the result of the following function, executing such prepared 'Statement'.
// Luckily, we can steer the course of events that this next function call will have to go through,
// able to anticipate, and therefore count on an exact result to happen during the test. This approach
// can be applied for every related method such as 'execute', 'query_row', or 'query_map'.

#[derive(Debug)]
struct SetupForOnlyAlteredStmts {
    conn: Box<dyn ConnectionWrapper>,
    queue_of_statements: RefCell<Vec<String>>,
}

#[derive(Debug)]
struct SetupForProdCodeAndAlteredStmts {
    prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
    // This transaction must be carried along because otherwise all those
    // successful SQL operations would be written into the database right away,
    // which is not how the reality works. On the other hand we do want them to
    // affect the database persistently if the commit point is reached, so that
    // the test can laid down assertions that test the database with maximally
    // realistic conditions.
    txn_bearing_prod_code_stmts_opt: Option<TransactionSafeWrapper<'static>>,
    queue_with_prod_code_and_altered_stmts: RefCell<Vec<StmtTypeDirective>>,
    // This connection is usually the most important, but using just the prod code
    // connection, meant primarily for non-altered statements, should be also possible.
    //
    // Common strategies to use this additional connection:
    //
    // a) as a connection pointing to another database, usually declared as simple as possible,
    //    that allows the same kind of error we want to see in the test (often an unusual, corner
    //    case error), but with a database and carefully arranged situation in which
    //    the substituted parameters to come into the SQL statement (if any at all), need to
    //    participate in our arrangement too (rusqlite code would complain otherwise), and that
    //    combination will cause the error,
    //
    // b) to tickle the database while exercising statements that attempt to change the state of
    //    the database. Since this connection will be read only, it'll generate an error. Thereby,
    //    we can assert on this error. Usually used when all we need is any kind of error.
    separate_conn_for_altered_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
}

impl SetupForProdCodeAndAlteredStmts {
    fn commit_prod_code_stmts(&mut self) -> Result<(), Error> {
        self.txn_bearing_prod_code_stmts_opt
            .take()
            .expect("Dual setup with a missing txn should never happen")
            .commit()
    }

    fn make_altered_stmt(&self, altered_stm: &str) -> Result<Statement, Error> {
        match self.separate_conn_for_altered_stmts_opt.as_ref() {
            Some(special_conn) => special_conn.prepare(altered_stm),
            None =>
            // In the prod code, all the db operations would've happened on a single wrapped txn,
            // that's why we strive to manipulate a txn also here, not the conn directly. Most
            // importantly, sometimes multiple subsequent operations take each the previous one as
            // necessary base. If the continuity is broken the later statement might not work. If
            // we record some changes on the transaction, other changes tried to be done from
            // a different connection might meet a different state of the database and thwart the
            // efforts. (This behavior probably depends on the global setup of the db).
            //
            //
            // Also imagine a 'Statement' that wouldn't cause an error whereupon any potential
            // rollback of this txn should best drag off both the prod code and altered statements
            // all together, disappearing. If we did not use this txn some changes would stay.
            {
                self.txn_bearing_prod_code_stmts_opt
                    .as_ref()
                    .expect("The txn is always created and should be present")
                    .prepare(altered_stm)
            }
        }
    }
}

impl Drop for SetupForProdCodeAndAlteredStmts {
    fn drop(&mut self) {
        // The self contains a reference that doesn't comply with Rust safeness anymore as it has gone
        // through backward cast from a raw pointer. We're making sure by this Drop impl that one
        // part of 'self', the borne txn will deconstruct earlier than what it is referencing, that
        // is the DB Connection held by one of the other fields in the same struct. Failing that, we'll
        // have to do with a segmentation error from the OS.
        drop(self.txn_bearing_prod_code_stmts_opt.take())
    }
}

#[derive(Debug)]
pub struct PrepareMethodResultsProducer {
    setup: Either<SetupForOnlyAlteredStmts, SetupForProdCodeAndAlteredStmts>,
}

impl PrepareMethodResultsProducer {
    pub fn construct_with_altered_stmts_only(
        conn: Box<dyn ConnectionWrapper>,
        altered_stmts_queue: Vec<String>,
    ) -> Self {
        let setup = SetupForOnlyAlteredStmts {
            conn,
            queue_of_statements: RefCell::new(altered_stmts_queue),
        };

        Self {
            setup: Either::Left(setup),
        }
    }

    pub fn construct_with_prod_code_and_altered_stmts(
        prod_code_stmts_conn: Box<dyn ConnectionWrapper>,
        separate_conn_for_altered_stmts_opt: Option<Box<dyn ConnectionWrapper>>,
        stm_determining_queue: Vec<StmtTypeDirective>,
    ) -> Self {
        let setup = {
            let ptr = Box::into_raw(prod_code_stmts_conn);
            let conn = unsafe { Box::from_raw(ptr) };

            let mut setup = SetupForProdCodeAndAlteredStmts {
                prod_code_stmts_conn: conn,
                txn_bearing_prod_code_stmts_opt: None,
                queue_with_prod_code_and_altered_stmts: RefCell::new(stm_determining_queue),
                separate_conn_for_altered_stmts_opt,
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
            Either::Left(setup) => Self::handle_stmt_for_only_altered(setup),
            Either::Right(setup) => {
                Self::handle_stmt_for_prod_code_and_altered(setup, prod_code_stmt)
            }
        }
    }

    fn handle_stmt_for_only_altered(setup: &SetupForOnlyAlteredStmts) -> Result<Statement, Error> {
        let stmt = setup.queue_of_statements.borrow_mut().remove(0);
        setup.conn.prepare(&stmt)
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
            StmtTypeDirective::ExecuteProdCode => {
                setup.prod_code_stmts_conn.prepare(prod_code_stmt)
            }
            StmtTypeDirective::UseAlteredStmt(altered_stmt) => {
                let altered_stm_str = match &altered_stmt {
                    AlteredStmtBySQLOrigin::SQLIdenticalWithProdCode => prod_code_stmt,
                    AlteredStmtBySQLOrigin::Substitution { new_stmt } => new_stmt.as_str(),
                };
                setup.make_altered_stmt(altered_stm_str)
            }
        }
    }
}

#[derive(Debug)]
pub enum StmtTypeDirective {
    ExecuteProdCode,
    UseAlteredStmt(AlteredStmtBySQLOrigin),
}

#[derive(Debug)]
pub enum AlteredStmtBySQLOrigin {
    // Use this on planning to have a conn pointing to a different db. This will eliminate having to
    // think up a new stmt, instead, the same one as in the prod code will be used.
    SQLIdenticalWithProdCode,
    Substitution { new_stmt: String },
}
