// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::database::rusqlite_wrappers::{
    ConnectionWrapper, SQLiteTransactionWrapper, TransactionInnerWrapper,
};
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use crate::{arbitrary_id_stamp_in_trait_impl, set_arbitrary_id_stamp_in_mock_impl};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use std::cell::RefCell;
use std::ptr::drop_in_place;
use std::sync::{Arc, Mutex};

#[derive(Default, Debug)]
pub struct TransactionWrapperMock {
    already_committed: bool,

    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_opt: Option<PrepareMethodResults>,
    commit_params: Arc<Mutex<Vec<()>>>,
    commit_results: RefCell<Vec<Result<(), Error>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

impl TransactionWrapperMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn can_be_used_only_before_commit(&self) {
        if !self.already_committed {
            ()
        } else {
            panic!("Something got terribly wrong ")
        }
    }

    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn prepare_results(mut self, results: PrepareMethodResults) -> Self {
        self.prepare_results_opt = Some(results);
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

impl TransactionInnerWrapper for TransactionWrapperMock {
    fn prepare(&self, prod_code_query: &str) -> Result<Statement, Error> {
        self.prepare_params
            .lock()
            .unwrap()
            .push(prod_code_query.to_string());

        self.prepare_results_opt
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
        let result = match (next_result.is_ok(), self.prepare_results_opt.as_mut()) {
            (true, Some(prepared_results)) => match &mut prepared_results.setup {
                Either::Left(for_both) => for_both.commit_prod_calls(),
                Either::Right(_) => next_result,
            },
            _ => next_result,
        };

        self.already_committed = true;

        result
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
struct SetupForStubbed<S> {
    stubbed_calls_conn: Box<dyn ConnectionWrapper>,
    stubbed_calls_optional_statements_literals: Vec<S>,
}

#[derive(Debug)]
struct SetupForBoth {
    prod_code_calls_conn_used_for_both: bool,
    prod_code_calls_conn: Box<dyn ConnectionWrapper>,
    prod_code_calls_transaction_opt: Option<SQLiteTransactionWrapper<'static>>,
    requested_preceding_prod_code_calls: usize,
    stubbed: SetupForStubbed<Option<String>>,
}

impl SetupForBoth {
    fn commit_prod_calls(&mut self) -> Result<(), Error> {
        let txn_opt = self.prod_code_calls_transaction_opt.take();
        let txn = txn_opt
            .expect("Error: missing transaction in setup for both prod code and stubbed calls");
        txn.commit()
    }
}

impl Drop for SetupForBoth {
    fn drop(&mut self) {
        // The real transaction ties up a safeness plain reference as made by casting
        // from a raw pointer - which breaks the check mechanism for pointing to an invalid
        // memory segment. We must make sure that this transactions deconstruct before
        // the database Connection it was originally pointing to is gone
        drop(self.prod_code_calls_transaction_opt.take())
    }
}

#[derive(Debug)]
pub struct PrepareMethodResults {
    calls_counter: RefCell<usize>,
    setup: Either<SetupForBoth, SetupForStubbed<String>>,
}

impl PrepareMethodResults {
    pub fn new_with_both_prod_code_and_stubbed_calls(
        prod_code_calls_conn: Box<dyn ConnectionWrapper>,
        stubbed_calls_conn: Box<dyn ConnectionWrapper>,
    ) -> Self {
        let setup = {
            let ptr = Box::into_raw(prod_code_calls_conn);
            let conn = unsafe { Box::from_raw(ptr) };

            let mut setup = SetupForBoth {
                prod_code_calls_conn_used_for_both: false,
                prod_code_calls_conn: conn,
                prod_code_calls_transaction_opt: None,
                requested_preceding_prod_code_calls: 0,
                stubbed: SetupForStubbed {
                    stubbed_calls_conn,
                    stubbed_calls_optional_statements_literals: vec![],
                },
            };

            let conn = unsafe { ptr.as_mut().unwrap() };
            let txn = conn.transaction().unwrap();

            setup.prod_code_calls_transaction_opt = Some(txn);

            Either::Left(setup)
        };

        Self {
            calls_counter: RefCell::new(0),
            setup,
        }
    }

    pub fn new_for_only_stubbed(stubbed_calls_conn: Box<dyn ConnectionWrapper>) -> Self {
        let setup = Either::Right(SetupForStubbed {
            stubbed_calls_conn,
            stubbed_calls_optional_statements_literals: vec![],
        });

        Self {
            calls_counter: RefCell::new(0),
            setup,
        }
    }

    pub fn count_of_initial_prod_code_calls(mut self, prod_code_calls: usize) -> Self {
        let dual_setup = self.setup_for_both_or_panic_ref_mut();
        if dual_setup.requested_preceding_prod_code_calls == 0 {
            dual_setup.requested_preceding_prod_code_calls = prod_code_calls
        } else {
            panic!("Use only single call of \"number_of_prod_code_calls!\"")
        }
        self
    }

    pub fn prod_code_calls_conn_used_for_both(mut self) -> Self {
        let dual_setup = self.setup_for_both_or_panic_ref_mut();
        dual_setup.prod_code_calls_conn_used_for_both = true;
        self
    }

    pub fn add_single_stubbed_call_from_prod_code_statement(mut self) -> Self {
        let single_setup = self.setup_for_both_or_panic_ref_mut();
        single_setup
            .stubbed
            .stubbed_calls_optional_statements_literals
            .push(None);
        self
    }

    pub fn add_single_stubbed_call_statement(mut self, statement: &str) -> Self {
        let single_setup = self.setup_for_both_or_panic_ref_mut();
        single_setup
            .stubbed
            .stubbed_calls_optional_statements_literals
            .push(Some(statement.to_string()));
        self
    }

    fn dual_setup_mismatch() -> ! {
        panic!(
            "{}",
            "This mock was construct as intended for the setup with both prod code and stubbed \
            calls. Reconsider that step, if you think you will be using only the stubbed calls"
        )
    }

    fn setup_for_both_or_panic_ref(&self) -> &SetupForBoth {
        match self.setup.as_ref() {
            Either::Left(both) => both,
            Either::Right(_) => Self::dual_setup_mismatch(),
        }
    }

    fn setup_for_both_or_panic_ref_mut(&mut self) -> &mut SetupForBoth {
        match self.setup.as_mut() {
            Either::Left(both) => both,
            Either::Right(_) => Self::dual_setup_mismatch(),
        }
    }

    fn determine_stubbed_queue_idx_opt(&self) -> Option<StubbedCallIndexInfo> {
        let upcoming_call_idx = *self.calls_counter.borrow();
        if let Either::Left(for_both) = &self.setup {
            if for_both.requested_preceding_prod_code_calls != 0 {
                let preceding_prod_code_calls = for_both.requested_preceding_prod_code_calls;

                if preceding_prod_code_calls > upcoming_call_idx {
                    None
                } else {
                    Some(StubbedCallIndexInfo::new(preceding_prod_code_calls))
                }
            } else {
                panic!(
                    "You're using the dual setup but have ordered 0 preceding prod code calls. \
                You should be using the single setup then"
                )
            }
        } else {
            Some(StubbedCallIndexInfo::new(0))
        }
    }

    fn produce_statement(&self, prod_code_stm: &str) -> Result<Statement, Error> {
        let idx_opt = self.determine_stubbed_queue_idx_opt();

        match idx_opt {
            None => self.handle_prod_code_call(prod_code_stm),
            Some(idx_info) => {
                let stm = idx_info.handle_setup_for_stubbed_only(self, prod_code_stm);
                Ok(stm)
            }
        }
    }

    fn handle_prod_code_call(&self, prod_code_stm: &str) -> Result<Statement, Error> {
        if let Either::Left(for_both) = &self.setup {
            let result = for_both.prod_code_calls_conn.prepare(prod_code_stm);
            self.increment_counter();
            result
        } else {
            panic!(
                "Idx info (on the left: for both) diverges from the setup variant (on the right: \
            stubbed only), design mistake"
            )
        }
    }

    fn get_stubbed_statement(
        &self,
        idx_info: StubbedCallIndexInfo,
        prod_code_stm: &str,
    ) -> Statement {
        let upcoming_call_idx = *self.calls_counter.borrow();
        let absolute_idx = idx_info.calculate_idx(upcoming_call_idx);
        match &self.setup {
            Either::Left(for_both) => self.get_from_for_both(for_both, absolute_idx, prod_code_stm),
            Either::Right(stubbed_only) => Self::get_from_stubbed_only(stubbed_only, absolute_idx),
        }
    }

    fn get_from_for_both(
        &self,
        setup: &SetupForBoth,
        absolute_idx: usize,
        prod_code_stm: &str,
    ) -> Statement {
        let stm = match setup
            .stubbed
            .stubbed_calls_optional_statements_literals
            .get(absolute_idx)
            .unwrap()
        {
            Some(stubbed_stm) => stubbed_stm,
            None => prod_code_stm,
        };

        let result = match self.resolve_choice_of_stubbed_conn() {
            Either::Left(txn) => txn.prepare(stm),
            Either::Right(conn) => conn.prepare(stm),
        };
        result.unwrap()
    }

    fn get_from_stubbed_only(setup: &SetupForStubbed<String>, absolute_idx: usize) -> Statement {
        let stm = setup
            .stubbed_calls_optional_statements_literals
            .get(absolute_idx)
            .unwrap();
        setup.stubbed_calls_conn.prepare(stm).unwrap()
    }

    fn increment_counter(&self) {
        *self.calls_counter.borrow_mut() += 1
    }

    fn resolve_choice_of_stubbed_conn(
        &self,
    ) -> Either<&SQLiteTransactionWrapper, &dyn ConnectionWrapper> {
        let setup = self.setup_for_both_or_panic_ref();

        if setup.prod_code_calls_conn_used_for_both {
            Either::Left(
                setup
                    .prod_code_calls_transaction_opt
                    .as_ref()
                    .expect("Conn for prod code calls not available"),
            )
        } else {
            Either::Right(setup.stubbed.stubbed_calls_conn.as_ref())
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

    fn handle_setup_for_stubbed_only<'a>(
        self,
        super_setup_structure: &'a PrepareMethodResults,
        prod_code_query: &str,
    ) -> Statement<'a> {
        let stm = super_setup_structure.get_stubbed_statement(self, prod_code_query);
        super_setup_structure.increment_counter();
        stm
    }
}
