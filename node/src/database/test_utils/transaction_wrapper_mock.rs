// Copyright (c) 2023, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use itertools::Either;
use rusqlite::{Error, Statement, ToSql};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionWrapper};

#[derive(Default, Debug)]
pub struct TransactionWrapperMock {
    prepare_params: Arc<Mutex<Vec<String>>>,
    prepare_results_opt: Option<PrepareMethodResults>,
    commit_params: Arc<Mutex<Vec<()>>>,
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
        let next_result = self.commit_results.borrow_mut().remove(0);
        if next_result.is_ok() {
            match &mut self.prepare_results_opt.as_mut().unwrap().setup {
                Either::Left(for_both) => {
                    return for_both.prod_code_calls_transaction_opt.take()
                        .expect("Error: missing transaction in the setup for both prod code and stubbed calls")
                        .commit();
                }
                Either::Right(_) => next_result,
            }
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

#[derive(Debug)]
struct SetupForStubbed<S> {
    stubbed_calls_conn: Box<dyn ConnectionWrapper>,
    stubbed_calls_optional_statements_literals: Vec<S>,
}

#[derive(Debug)]
struct SetupForBoth {
    prod_code_calls_conn_used_for_both: bool,
    prod_code_calls_conn: Box<dyn ConnectionWrapper>,
    prod_code_calls_transaction_opt: Option<Box<dyn TransactionWrapper>>,
    requested_preceding_prod_code_calls: usize,
    stubbed: SetupForStubbed<Option<String>>,
}

impl Drop for SetupForBoth {
    fn drop(&mut self) {
        // Making sure that the referenced transaction will deconstruct
        // before the connection it was pointing to
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

    pub fn preceding_prod_code_calls(mut self, total_of_prod_code_calls: usize) -> Self {
        let dual_setup = self.setup_for_both_or_panic_ref_mut();
        if dual_setup.requested_preceding_prod_code_calls == 0 {
            dual_setup.requested_preceding_prod_code_calls = total_of_prod_code_calls
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

    const DUAL_SETUP_MISMATCH: &'static str = "This mock was construct as intended for the setup \
    with both prod code and stubbed calls. Reconsider that step, if you think you will be using \
    only the stubbed calls";

    fn setup_for_both_or_panic_ref(&self) -> &SetupForBoth {
        match self.setup.as_ref() {
            Either::Left(both) => both,
            Either::Right(_) => panic!("{}", Self::DUAL_SETUP_MISMATCH),
        }
    }

    fn setup_for_both_or_panic_ref_mut(&mut self) -> &mut SetupForBoth {
        match self.setup.as_mut() {
            Either::Left(both) => both,
            Either::Right(_) => panic!("{}", Self::DUAL_SETUP_MISMATCH),
        }
    }

    fn stubbed_call_idx_info_opt(
        &self,
    ) -> Either<Option<StubbedCallIndexInfo>, StubbedCallIndexInfo> {
        let upcoming_call_idx = *self.calls_counter.borrow();
        if let Either::Left(for_both) = &self.setup {
            if for_both.requested_preceding_prod_code_calls > 0 {
                let preceding_prod_code_calls = for_both.requested_preceding_prod_code_calls;
                let res = if preceding_prod_code_calls > upcoming_call_idx {
                    None
                } else {
                    Some(StubbedCallIndexInfo::new(preceding_prod_code_calls))
                };
                Either::Left(res)
            } else {
                Either::Left(Some(StubbedCallIndexInfo::new(0)))
            }
        } else {
            Either::Right(StubbedCallIndexInfo::new(0))
        }
    }

    fn produce_statement(
        &self,
        idx_info: Either<Option<StubbedCallIndexInfo>, StubbedCallIndexInfo>,
        prod_code_query: &str,
    ) -> Result<Statement, Error> {
        match idx_info {
            Either::Left(idx_info_opt) => match idx_info_opt {
                None => {
                    if let Either::Left(for_both) = &self.setup {
                        let result = for_both.prod_code_calls_conn.prepare(prod_code_query);
                        self.increment_counter();
                        result
                    } else {
                        panic!("Idx info (on the left: for both) diverges from the setup variant \
                        (on the right: stubbed only), design mistake")
                    }
                }
                Some(idx_info) => {
                    let stm = idx_info.handle_setup_for_stubbed_only(self, prod_code_query);
                    Ok(stm)
                }
            },
            Either::Right(idx_info) => {
                let stm = idx_info.handle_setup_for_stubbed_only(self, prod_code_query);
                Ok(stm)
            }
        }
    }

    fn bring_out_stubbed_statement(
        &self,
        idx_info: StubbedCallIndexInfo,
        prod_code_query: &str,
    ) -> Statement {
        let upcoming_call_idx = *self.calls_counter.borrow();
        let idx = idx_info.calculate_idx(upcoming_call_idx);
        match &self.setup {
            Either::Left(for_both) => {
                let query = match for_both
                    .stubbed
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
            Either::Right(stubbed_only) => {
                let query = stubbed_only
                    .stubbed_calls_optional_statements_literals
                    .get(idx)
                    .unwrap();
                stubbed_only.stubbed_calls_conn.prepare(query).unwrap()
            }
        }
    }

    fn increment_counter(&self) {
        *self.calls_counter.borrow_mut() += 1
    }

    fn resolve_choice_of_stubbed_conn(
        &self,
    ) -> Either<&dyn TransactionWrapper, &dyn ConnectionWrapper> {
        let setup = self.setup_for_both_or_panic_ref();

        if setup.prod_code_calls_conn_used_for_both {
            Either::Left(
                setup
                    .prod_code_calls_transaction_opt
                    .as_ref()
                    .expect("Conn for prod code calls not available")
                    .as_ref(),
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
        let stm = super_setup_structure.bring_out_stubbed_statement(self, prod_code_query);
        super_setup_structure.increment_counter();
        stm
    }
}