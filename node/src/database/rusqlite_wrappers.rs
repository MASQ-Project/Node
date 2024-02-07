// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// We were challenged multiple times to device mocks for testing stubborn, hard to tame, data
// structures from the 'rusqlite' library. After all, we've adopted two of them, the Connection,
// that came first, and the Transaction to come much later. Of these, only the former complies
// with the standard policy we follow for mock designs.
//
// The delay until the second one became a thing, even though we would've been glad having it
// on hand much earlier, was caused by vacuum of ideas on how we could create a mock of these
// parameters and have it accepted by the compiler. Passing a lot of time, we came up with a hybrid,
// at least. That said, it has costed us a considerably high price of giving up on simplicity.
//
// The firmest blocker of the design has always rooted in a relationship of serialized lifetimes,
// affecting each other, that has been so hard to maintain right. Yet the choices made
// within the third-party library have good reasoning, like that the database connection must
// stay alive as long as there are any active 'Transactions' or 'Statements'.
//
// It's a fact, though, that the use of an explicit, object-like transaction from the 'rusqlite'
// library is rare in our code. That might explain why we managed to live so long without feeling
// much constrained by absence of this mock. While we did write some code using that kind of
// transaction, we always acknowledged that we had to make an exception and leave that piece
// of code untested. The problem with a mocked transaction has been that we often need to combine
// it with a connection also needs to be a mock. Then the transaction springs from the connection.
// The following nontrivial issues with lifetimes have been briefly mentioned.
//
// The interface a transaction uses consists of three methods. Only 'prepare' causes troubles.
// It returns a `Statement`, keeping a reference to the parent connection.
//
// There is now no decent vision of how to cut back on this method, despite how large temptation
// surrounds it. Theoretically, we could make a replacement by the existing 'execute' method and
// so circumvent all the places where we now need to manipulate with 'Statement'. That is because
// 'execute' returns only simple data structures, easy to be stored in a mock. Even going that
// way, other issues would take place inevitably.
//
// One may consider creating another class to wrap up the `Statement` and acquire a full control.
// It's been tested. The interface requires even more methods and so obstacles. The steeply
// increasing difficulty ended the efforts.
//
// Critically speaking, this mock does not win with either simplicity or sparkling elegance. Its
// setup must also be expected to become harder the more complex tests it takes. The excuse for
// this is that it also opens up possibilities for thorough tests in progressively less rare
// occurrences where we need to be able to use an explicit 'rusqlite' transaction. Note that
// testing such situations used to seem undoable not so far ago.
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
