// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;
use crate::masq_lib::utils::ExpectValue;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// We've had to prepare us mocks in order to tame two testing complicating data structures taken over
// from the `rusqlite`, the Connection, that came first, and Transaction, much later added. Of these
// only the former follows our standard policy for mock making.
//
// The time delay until getting the second one, even though we'd needed it earlier, was caused by
// absence of ideas about how to write such code to be accepted by the compiler. Finally, we've
// been able to come up with a hybrid at least. However, for the price of giving up on simplicity.
//
// The actual blocker has always stood rooted in the hard-to-understand relationships in a series
// of lifetimes affecting each other, found reasonable for the third-party code, ensuring that the
// database connection will always be around as long as any of the active `Transactions` or
// `Statements` derived from it.
//
// The use of an explicit `rusqlite` transaction, an object, is very rare in our code. That's why
// we probably didn't have large troubles avoiding tests where we would've needed to make
// the transaction operations go exactly the way we need. If we did write some, we acknowledged
// leaving the piece of code untested. The actual problem with mocking this transaction is that we
// will usually need to combine it with the connection being mocked as well. Because the transaction
// originates in the connection. The need to stick this by-nature strictly reference dependent
// object into another mock leads in a mess of lifetimes, growing in their count in your chase after
// that what the compiler wants from you.
//
// It's safe to say that any mock is hard to write if it is supposed to gain a lifetime from its
// inside stored results: the lifetime causes the mock to be timely more restricted, what is more,
// any object that comes into contact with this mockable object will have a responsibility to deal
// with the vexing lifetime its own way. Plus, there are still more troubles to come.
//
// The transaction interface is a set of three methods of which the devil sits on `prepare()`.
// This method returns `Statement`, a rusqlite original structure, also referenced back to
// the connection.
//
// There isn't any good vision for managing to stop using this method, even though it is tempting.
// In theory, we could substitute it fully by the existing `execute()` method, perhaps then being
// able to circumvent any place where we currently have to manipulate the `Statement`, the fairly
// hard controllable structure, because `execute()`, unlike to `prepare()`, returns such a simple
// data structures containing result to have in a mock. Whatever bold this plan would be, new, from
// smaller to larger, design issues can be anticipated.
//
// Someone may also think that it would be convenient if another class existed, wrapping
// the `Statement` as we've said it causes the serious troubles. It's been tested out but we've
// found insurmountable obstacles, whereupon the steeply increasing difficulty ended the efforts.
//
// The wrapped transaction we have is poor at elegance and simplicity, especially when it meets
// more complex tests, but the outbalancing positive needs to be seen in the good portion of
// possibilities for thorough and advance testing for those places where we do rely on explicit
// SQLite transactions, despite of that this used to be nearly unthinkable.
//
// (See an additional explanation at the code of the mock)

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction(&mut self) -> Result<TransactionWrapper, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction(&mut self) -> Result<TransactionWrapper, Error> {
        self.conn.transaction().map(TransactionWrapper::new)
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

// Whole point of this outer wrapper common for both the real and mock transaction ( named as
// TransactionInnerWrapper ) is to give us a chance to deconstruct the whole structure when we're
// finishing the call of `commit()`. The classical mockable structure compounded of a trait object
// doesn't allow to be consumed by itself because of the rules given to trait objects saying clearly
// we can ever access one only by a reference, while for consuming of anything we need to have the
// full ownership.
//
// Leaving around an already used, committed, transaction would expose us to risks as in somebody
// trying to use it again, while the actual transaction is gone (but the trait object wrapper lives
// on) and nothing usable has been left there.
//
// Second, we want to be exact and careful about the mock version because it hides a hard-to-debug
// segmentation error raised from the OS if we don't deconstruct the unsafely kept reference pointing
// back inside the same `struct` where we also cater an extra, but identical to the original one,
// connection to the database.
//
// All this is a bit dirty trick to avoid difficulties at writing a system of gradually referenced
// mocks like here:
// [supposed db conn origin] --> WrappedConnectionMock<'a> -> WrappedTransactionMock<'a>.

#[derive(Debug)]
pub struct TransactionWrapper<'conn_in_real_or_static_in_mock> {
    wrapped_inner: Box<dyn TransactionInnerWrapper + 'conn_in_real_or_static_in_mock>,
}

impl<'a> TransactionWrapper<'a> {
    pub fn new(txn: Transaction<'a>) -> Self {
        Self {
            wrapped_inner: Box::new(TransactionInnerWrapperReal::new(txn)),
        }
    }

    #[cfg(test)]
    pub fn new_test_only(inner_wrapper_builder: TransactionInnerWrapperMockBuilder) -> Self {
        Self {
            wrapped_inner: inner_wrapper_builder.build(),
        }
    }

    pub fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.wrapped_inner.prepare(query)
    }

    pub fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.wrapped_inner.execute(query, params)
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.wrapped_inner.commit()
    }

    #[cfg(test)]
    pub fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
        self.wrapped_inner.arbitrary_id_stamp()
    }
}

pub trait TransactionInnerWrapper: Debug {
    fn prepare(&self, query: &str) -> Result<Statement, Error>;
    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error>;
    fn commit(&mut self) -> Result<(), Error>;

    arbitrary_id_stamp_in_trait!();
}

#[derive(Debug)]
pub struct TransactionInnerWrapperReal<'a> {
    txn_opt: Option<Transaction<'a>>,
}

impl<'a> TransactionInnerWrapperReal<'a> {
    fn new(transaction: Transaction<'a>) -> TransactionInnerWrapperReal<'a> {
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
