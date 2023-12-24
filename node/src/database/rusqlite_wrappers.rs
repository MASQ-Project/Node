// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

test_only_use!(
    use crate::database::test_utils::transaction_wrapper_mock::TransactionInnerWrapperMockBuilder;,
    use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
);
use crate::arbitrary_id_stamp_in_trait;
use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// We've had tasks to device mocks allowing us to two testing complicated data structures leaping
// in our lap from `rusqlite`, the Connection, that came first, and Transaction, added much later.
// Of these two only the former follows the standard policy we've developed for mocks design.
//
// The delay up to launching the second one, even though we would've needed it earlier, was caused
// by vacuum of ideas on how we could write a mock of this kind to be accepted by the compiler.
// Finally, we've been able to come up with at least a hybrid. Paying the considerably high price
// of having to give up on simplicity heavily.
//
// The actual blocker has always rooted in the hardly understandable relationships of a series
// of lifetimes affecting each other. While the choices can be found reasonable for the third-party
// code, ensuring that the database connection will always be around as long as anything depending
// on it stays usable, practically related to Transactions` and `Statements` exclusively.
//
// The use of an explicit, object-like `rusqlite` transaction is very rare in our code. That's
// probably why we managed to live so long without bumping into this a lot. If we did write some
// code using it, we acknowledged we must have left that piece of logic untested. The actual problem
// with a mocked transaction has been that we usually need to combine it with the connection while
// that one is mocked as well. The transaction is split off from the connection. The need to stick
// this object strictly depending on a reference into another mock leads into a fragile relationship
// of lifetimes, growing in a count during one's chase after what the compiler asks for.
//
// It's safe to say that any mock is hard to deal with if it is supposed to wear a lifetime from its
// inside stored results: the lifetime causes the mock to be more restricted, what is more,
// any object that comes into contact with this mock will have gain a responsibility to deal
// with the vexing lifetime as well and its own way. While there still may be more troubles to come.
//
// The interface is a set of three methods of which the devil sits astride on `prepare()`.
// That method returns `Statement`, a `rusqlite` original structure, also keeping a reference back
// to the connection.
//
// There isn't any good vision of how we could manage to stop using this method, even though it
// is tempting. In theory, we could substitute it fully by the existing `execute()` method,
// able to circumvent any place where we are now forced to manipulate the `Statement`, a fairly
// hard controllable structure, because `execute()`, unlike to `prepare()`, returns only simple
// data structures easily to be stored in a mock. Whatever bold this plan would be, new design
// issues, from smaller to larger, can be anticipated.
//
// One may also think that there may be a solution if another class existed, wrapping the `Statement`
// about which we've said it causes serious troubles. It's been tested out but we've found
// insurmountable obstacles, whereupon steeply increasing difficulty ended the efforts.
//
// It is okay to admit the mock wrapper we have is poor at elegance and simplicity. Especially when
// it takes more complex tests. However, the compensation needs to be seen in the good portion of
// possibilities created for thorough, advance testing in those rare places where we do rely on
// an explicit SQLite transaction, keeping in mind that this used to seem undoable.
//
// (See an additional explanation at the code of the mock)

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

// Whole point of this outer wrapper that is shard between both the real and mock transactions is to
// give one a chance to deconstruct this whole code structure in place, receiving a call of
// `commit()` on it. A normally written mock with the direct use of a trait object doesn't allow to
// be consumed by one of its methods because of the rules declared for trait objects that say
// clearly that we can never access one otherwise than via a reference. However, to let a thing be
// consumed by itself we need to be possessing the full ownership of it.
//
// Leaving around an already enclosed, committed, transaction would expose us to a risk. Let's
// imagine somebody trying to use the second time, while the actual connective element was took
// away and deconstructed, the trait object wrapper, the interface we approach it through, still
// lives on, having noting usable inside.
//
// Second, we want to go about carefully because it hides a potential, hard-to-debug segmentation
// error that might be raised from the OS if we fail to be early deconstructing the transaction
// kept inside. It has an unsafe reference pointing back inside the same object whose another field
// hosts an extra connection to a database. If the connection deconstructs and disappears before
// the transaction does, we are in trouble.
//
// This whole thing converges to dirty tricks, true, however it can be also a big help as we can
// actually avoid difficulties that we would've been given by a series of gradually referenced mocks
// like:
//
// [supposed db conn origin]<'a> --> WrappedConnectionMock<'a> -> WrappedTransactionMock<'a>.

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

// Should be understood as an internal component to the 'TransactionWrapper'.
// Please keep the visibility constrained to this file

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
