// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::arbitrary_id_stamp_in_trait;
use crate::masq_lib::utils::ExpectValue;
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// The maximum we could devise for mocks for the rusqlite library has covered the Connection first
// and quite later also the Transaction. The delay was caused because we long did not know how to
// do it but then we at least were able to create a hybrid. Not a standard, simply looking mock.
// The actual blocker has always been the nontrivial relationship of different lifetimes ensuring
// that any transaction, statement, etc., live as long as the initiated relation with the database.
//
// This made arrangements for a mocked transaction, trying to store results for the methods it
// has (respectively, only those we use and need), extremely hard or maybe even not possible to put
// together. It is a set of three methods of which the devilish one is `prepare()`. This method
// returns the Statement (rusqlite native) structure. There isn't a good way to avoid using this
// method even though it is tempting to scratch it off and implement only the execute() method
// circumventing the place where we need to deal with the Statement structure because the other
// method returns very simple data structures for a mock but it might result in smaller to bigger
// design issues.
//
// It would be highly convenient if we could have another wrapper for the Statement structure too
// but there we've already found insurmountable obstacles. The difficulty increased so much that
// we left the effort. (See more explanations at the code of the mock)
//
// The wrapped transaction is not elegant and simple either, especially when it concerns more
// complex tests but the good side of it is that we have a good portion of possibilities for advance
// testing that used to be nearly unthinkable.

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction<'a>(&'a mut self) -> Result<SqliteTransactionWrapper<'a>, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction<'a>(&'a mut self) -> Result<SqliteTransactionWrapper<'a>, Error> {
        self.conn
            .transaction()
            .map(|tx| SqliteTransactionWrapper::new(Box::new(TransactionWrapperReal::new(tx))))
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

pub trait TransactionWrapper: Debug {
    fn prepare(&self, query: &str) -> Result<Statement, Error>;
    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error>;
    fn commit(&mut self) -> Result<(), Error>;

    arbitrary_id_stamp_in_trait!();
}

#[derive(Debug)]
pub struct TransactionWrapperReal<'a> {
    rusqlite_txn_opt: Option<Transaction<'a>>,
}

impl<'a> TransactionWrapperReal<'a> {
    fn new(transaction: Transaction<'a>) -> TransactionWrapperReal<'a> {
        Self {
            rusqlite_txn_opt: Some(transaction),
        }
    }
}

impl<'a> TransactionWrapper for TransactionWrapperReal<'a> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.rusqlite_txn_opt
            .as_ref()
            .expectv("rusqlite txn")
            .prepare(query)
    }

    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.rusqlite_txn_opt
            .as_ref()
            .expectv("rusqlite txn")
            .execute(query, params)
    }

    fn commit(&mut self) -> Result<(), Error> {
        let transaction = self.rusqlite_txn_opt.take();
        transaction.expectv("rusqlite txn").commit()
    }
}

// Whole point of this outer wrapper common for both the real and mock transaction is to give us
// a chance to deconstruct the whole thing when we call `commit()`. A classical mockable structure
// compounded of a trait object doesn't allow to consume itself because of the rules about trait
// objects clearly saying we can ever access it only by a reference and for consuming it we need
// to have an ownership.
//
// Leaving around an already used, committed, transaction would expose us to risks as in somebody
// trying to use it again, while the actual transaction is gone and nothing usable has left. Second,
// we want to be exact and careful about the mock version because it hides a possible segmentation
// error raised from the OS if we don't deconstruct the unsafely kept reference pointing back inside
// to the same structure where we also hold an extra created connection to the database.
//
// (That is a trick to avoid difficulties with writing a mock for a gradually referenced object,
// here the later transaction located inside a mocked connection with its own wrapper. This way we
// can construct a separate transaction but pointing to the same database so the effect of operations
// done upon this transaction will appear as if it was done through the original connection we can
// find in the production code. We can do without referring to the outside world, having
// a connection between which and the transaction there always must be a reference, but we keep them
// both inside an owned object we can move around without obstacles, meaning we can put it into
// a queue of results of another mock, in this case the prod. code connection, but mocked itself,
// comes naturally to one's mind.)

#[derive(Debug)]
pub struct SqliteTransactionWrapper<'conn_in_real_or_static_in_mock> {
    wrapped_guts: Box<dyn TransactionWrapper + 'conn_in_real_or_static_in_mock>,
}

impl<'a> SqliteTransactionWrapper<'a> {
    pub fn new(inner: Box<dyn TransactionWrapper + 'a>) -> Self {
        Self {
            wrapped_guts: inner,
        }
    }

    pub fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.wrapped_guts.prepare(query)
    }

    pub fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.wrapped_guts.execute(query, params)
    }

    pub fn commit(mut self) -> Result<(), Error> {
        self.wrapped_guts.commit()
    }

    #[cfg(test)]
    pub fn arbitrary_id_stamp(&self) -> ArbitraryIdStamp {
        self.wrapped_guts.arbitrary_id_stamp()
    }
}
