// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// We were challenged multiple times to device mocks for testing some stubborn, hard to tame, data
// structures from the 'rusqlite' library. After all, we've adopted two of them, the Connection,
// that came first, and the Transaction to be drawn in much later. Of these, only the former
// complies with the standard policy we follow for mock designs.
//
// The delay until the second one, even though we would've been glad having it available earlier,
// was caused by vacuum of ideas on how we could create a mock of these parameters and have it
// accepted by the compiler. Passing a lot of time, we came up with a hybrid at least. That said,
// it's involved a considerably high price of giving up on simplicity.
//
// The firmest blocker of the design has always rooted in a hardly relationships of serialized
// lifetimes affecting each other that has been so hard to maintain right. Yet the choices made
// within the third-party library can be found reasonable, like that the database connection must
// stay alive as long as there are any active 'Transactions' or 'Statements'.
//
// The truth is the use of an explicit, object-like, transaction from 'rusqlite' is rare for our code.
// That might be why we'd managed to live so long without being much constrained by absence of
// the mock. While we did write some code using that kind of a transaction, we always acknowledged
// only that we had to make and exception and leave that piece of code untested. The problem
// with a mocked transaction has been that we often need to combine it with also a mocked connection.
// Then the transaction springs from the connection. The upcoming nontrivial issues with lifetimes
// have been briefly mentioned.
//
// The interface a transaction needs have three methods of which 'prepare' causes the troubles.
// It returns `Statement`, a 'rusqlite' structure that always keeps a reference to the connection.
//
// There is now no decent vision of how to stop using that method, despite how much temptation it
// provides. In theory, we could replace it by the existing 'execute' method, able to circumvent
// any places where we now need to manipulate with the 'Statement', that is because 'execute'
// returns, in contrary, only simple data structures, easy to be stored in a mock. Going that way,
// other issues may be anticipated.
//
// One may think about creating another class to wrap up the `Statement` to have a better control.
// Tested, but its interface requires even more methods and so obstacles, whereupon the steeply
// increasing difficulty ended the efforts.
//
// Fair to admit the mock is poor at elegance and simplicity. The more the more complex tests it
// takes. The compensation for that needs to be seen in the portion of possibilities it opens up
// for thorough testing in those less and less rare places where we do rely on an explicit 'rusqlite'
// transaction. Yet this kind of thing used to seem completely undoable not so far ago.
//
// (See more explanation near the mock itself)

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction(&mut self) -> Result<TransactionSafeWrapper, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction(&mut self) -> Result<TransactionSafeWrapper, Error> {
        self.conn.transaction().map(TransactionSafeWrapper::new)
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

// Whole point of this outer wrapper, that is common to both the real and mock transactions, is to
// make a chance to deconstruct all components of a transaction in place. It plays a crucial role
// during the final commit. Note that an usual mock based on the direct use of a trait object
// cannot be consumed by any of its methods because of the Rust rules for trait objects. They say
// clearly that we can access it via '&self', '&mut self' but not 'self'. However, to have a thing
// consume itself we need to be provided with the full ownership.
//
// Leaving remains of an already committed transaction around would expose us to a risk. Let's
// imagine somebody trying to make use of it the second time, while the inner element providing
// the connection has already been swallowed by a third-party function call, yet our wrapper would
// be able to live on. An error situation would've arisen.
//
// Second, caution is much desirable (while relevant only for the test tree, not production code)
// because the wrapper hides a potential hard-to-debug segmentation error that the OS might raise
// if the timing of deconstruct of the transaction we created and put inside isn't done correctly.
// The mock has an unsafe reference attached at a database transaction on one side and pointing
// back in to another field holding an exclusive connection that can be freely carried around as
// the whole mock moves. We must prevent the connection from being deconstructed before
// the transaction was.

// The wrapper has a lifetime possibly having much different parameters depending on the use in
// the production code or if constructed as a mock inside a test.
//
// Real -> refers to an outer Connection
// Mock -> 'static
#[derive(Debug)]
pub struct TransactionSafeWrapper<'conn> {
    inner: Box<dyn TransactionInnerWrapper + 'conn>,
}

impl<'conn> TransactionSafeWrapper<'conn> {
    pub fn new(txn: Transaction<'conn>) -> Self {
        Self {
            inner: Box::new(TransactionInnerWrapperReal::new(txn)),
        }
    }

    pub fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.inner.prepare(query)
    }

    pub fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.inner.execute(query, params)
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.inner.commit()
    }
}

pub trait TransactionInnerWrapper: Debug {
    fn prepare(&self, query: &str) -> Result<Statement, Error>;
    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error>;
    fn commit(&mut self) -> Result<(), Error>;

    arbitrary_id_stamp_in_trait!();
}

// Please note that this structure is meant to stay private

#[derive(Debug)]
struct TransactionInnerWrapperReal<'conn> {
    txn_opt: Option<Transaction<'conn>>,
}

impl<'conn> TransactionInnerWrapperReal<'conn> {
    fn new(transaction: Transaction<'conn>) -> TransactionInnerWrapperReal<'conn> {
        Self {
            txn_opt: Some(transaction),
        }
    }
}

impl<'a> TransactionInnerWrapper for TransactionInnerWrapperReal<'a> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.txn_opt.as_ref().expectv("rusqlite txn").prepare(query)
    }

    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.txn_opt
            .as_ref()
            .expectv("rusqlite txn")
            .execute(query, params)
    }

    fn commit(&mut self) -> Result<(), Error> {
        let transaction = self.txn_opt.take();
        transaction.expectv("rusqlite txn").commit()
    }
}

#[cfg(test)]
pub mod transaction_wrapper_test_only {
    use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;

    impl<'conn> TransactionSafeWrapper<'conn> {
        pub fn new_with_builder(inner_wrapper_builder: TransactionInnerWrapperMockBuilder) -> Self {
            Self {
                inner: inner_wrapper_builder.build(),
            }
        }

        pub fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
            self.inner.arbitrary_id_stamp()
        }
    }
}
