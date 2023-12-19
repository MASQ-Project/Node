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
    fn transaction(&mut self) -> Result<SecureTransactionWrapper, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction(&mut self) -> Result<SecureTransactionWrapper, Error> {
        self.conn.transaction().map(SecureTransactionWrapper::new)
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

// Whole point of this outer wrapper that is common for both real and mock transactions is to give
// us a chance to deconstruct this whole code structure in place when we've called `commit()` on it.
// The standard sort of mock that embraces the use of trait objects doesn't allow to be consumed
// by calling self because of the rules surrounding trait objects that say clearly we can never
// access one otherwise but via a reference, while for consuming anything in Rust we need to possess
// the full ownership of it.
//
// Leaving around an already enclosed, committed, transaction would expose us to a risk. Let's
// imagine somebody trying to use the second time, while the actual connective element was took
// away and deconstructed, the trait object wrapper, the interface we approach it through, still
// lives on, having noting usable inside.
//
// Second, we want to go about carefully about the mock because it hides a potential, hard-to-debug
// segmentation error that might be raised from the OS if we fail to be early deconstructing
// the transaction kept inside. It has an unsafe reference pointing back inside the same object where
// another field hosts an extra connection to the database. If the connection deconstructs
// and disappears before the transaction does, we are in trouble.
//
// This whole thing is a slightly dirty trick, thanks to which, however, we can actually avoid
// difficulties that we would've been given by a series of gradually referenced mocks like:
//
// [supposed db conn origin]<'a> --> WrappedConnectionMock<'a> -> WrappedTransactionMock<'a>.

#[derive(Debug)]
pub struct SecureTransactionWrapper<'conn_if_real_or_static_if_mock> {
    inner: Box<dyn TransactionInnerWrapper + 'conn_if_real_or_static_if_mock>,
}

impl<'a> SecureTransactionWrapper<'a> {
    pub fn new(txn: Transaction<'a>) -> Self {
        Self {
            inner: Box::new(TransactionInnerWrapperReal::new(txn)),
        }
    }

    #[cfg(test)]
    pub fn new_test_only(inner_wrapper_builder: TransactionInnerWrapperMockBuilder) -> Self {
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

// Should be only understood as an internal component to the 'TransactionWrapper',
// therefore keep the visibility constrained to this file

#[derive(Debug)]
struct TransactionInnerWrapperReal<'a> {
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
