// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

test_only_use!(
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;,
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
);
use crate::arbitrary_id_stamp_in_trait;
use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// We've come across new challenges to device mocks for testing stubborn, hard to tame, data
// structures originated in the 'rusqlite' library. There are two of them, the Connection, that came
// first, and the Transaction, drawn in much later. Only the former, though, is aligned with our
// standard policy for mocks design.
//
// The delay until the creation of the second one, even though we would've appreciated to have it
// earlier, was caused by a vacuum of ideas on how we could write a mock of these parameters and
// have it accepted by the compiler. Passing a lot of time, we were finally able to come up with
// a hybrid at least. In change for a considerably high price of having to give up on simplicity.
//
// The actual blocker has always rooted in the hardly graspable relationships of serialized
// lifetimes affecting each other. The choices made beyond the third-party library can be found
// reasonable, like those ensuring that the database connection must stay alive as long as there
// are any active 'Transactions' or 'Statements'.
//
// The use of an explicit, object-like transaction from 'rusqlite' is rare in our code. That's
// probably why we'd managed to live so long without feeling the need for this new mock. While we
// did write some code using it, we always acknowledged we had to leave that piece of logic untested.
// The actual problem with a mocked transaction has been that we usually need to combine it with
// an also mocked connection. The transaction is springs from the connection. The need to put
// this object, strictly depending on a reference, into another mock makes us face a nontrivial
// relationship of lifetimes, growing in their count as a chase after what the compiler asks of is
// unwinding.
//
// The interface have three methods of which the one causing troubles is 'prepare'. It returns
// `Statement`, a 'rusqlite' original structure always referenced back to the connection.
//
// There isn't any vision of how we could put an end to using this method, despite how much tempting
// it is. In theory, we could replace it fully by the existing 'execute' method, able to circumvent
// any places where we are forced to manipulate with the 'Statement' because 'execute' returns only
// simple data structures, instead, easily to be stored in a mock. Regardless the boldness of this
// plan, new design issues, from smaller to larger, are anticipated.
//
// One may think of a potential solution if another class existed to wrap the `Statement` up, that
// we've said about that it causes these serious troubles. Also that's been tested out but we've
// met insurmountable obstacles, whereupon the steeply increasing difficulty ended the efforts.
//
// It is fair to admit our mock is poor at elegance and simplicity. Especially when it takes more
// complex tests. However, compensation for that needs to be seen in the good portion of
// possibilities it opens up for advance, thorough testing in those rare places where we do rely on
// an explicit 'rusqlite' transaction and also let's keep in mind it used to seem undoable not so
// far ago.
//
// (See more explanation at the code of the mock)

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

// Whole point of this outer wrapper that is common in both the real and mock transactions is to
// make a chance to deconstruct this whole code structure in place. It plays a crucial role in
// the call of 'commit'. Note that a normally written mock with the direct use of a trait object
// doesn't allow to be consumed by any of its methods because of the rules declared for trait
// objects in Rust. They say clearly that we can never access one otherwise than via a reference.
// However, to have a thing be consumed by itself we need to be possessing the full ownership.
//
// Leaving an already enclosed, committed, transaction around would expose us to a risk. Let's
// imagine somebody trying to use it the second time, while the actual element providing
// the connection has been taken away and deconstructed, then this wrapper could still live on,
// having noting to use inside.
//
// Second, caution is much desirable here because the wrapper hides a potential, hard-to-debug,
// segmentation error that might the OS might raise if we fail to be early deconstructing
// the transaction we created and put inside. It has an unsafe reference pointing back in to
// the same object, to a field that hosts its own, extra, database connection that it can freely
// carry around. If the connection deconstructs and is gone before the transaction does, troubles
// come.
//
// The bottom line is that this outer wrapper is designed so that it deconstructs immediately and
// with its every bit when a commit of the transaction processes.

#[derive(Debug)]
pub struct TransactionSafeWrapper<'conn_if_real_or_static_if_mock> {
    inner: Box<dyn TransactionInnerWrapper + 'conn_if_real_or_static_if_mock>,
}

impl<'conn> TransactionSafeWrapper<'conn> {
    pub fn new(txn: Transaction<'conn>) -> Self {
        Self {
            inner: Box::new(TransactionInnerWrapperReal::new(txn)),
        }
    }

    #[cfg(test)]
    pub fn new_with_builder(inner_wrapper_builder: TransactionInnerWrapperMockBuilder) -> Self {
        Self {
            inner: inner_wrapper_builder.build(),
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

    #[cfg(test)]
    pub fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
        self.inner.arbitrary_id_stamp()
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
