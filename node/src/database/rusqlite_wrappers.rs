// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

// The maximum we could devise in the mocked forms are the Connection and Transaction provided
// by the rusqlite library. The implementation of Transaction got complex, where we had to
// drift away from a dull mock to a much smarter one, because of a nontrivial coexistence
// of lifetimes, which can make the storage of prepared results inside the mock hard or even
// impossible. Of course, it would be highly convenient if we could have also a wrapper for
// the rusqlite's Statement but there we found insurmountable obstacles.
// Those are generic args (defined by the trait Params), but more seriously,
// returned types from many of the provided methods of which some are used really frequently by us.
// If not clear enough, we depend on the ability to define the mock as a trait object, however,
// the generics we would have to take over into our trait defining the wrapper stand in our way
// to compile because of the rules of Trait Object Safeness.
//
// Even the WrappedTransaction doesn't come with easiness if it concerns more complex test scenarios.
// On the other hand, it makes advanced testing at least possible, which wasn't the case before.

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction<'a>(&'a mut self) -> Result<Box<dyn TransactionWrapper + 'a>, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction<'a>(&'a mut self) -> Result<Box<dyn TransactionWrapper + 'a>, Error> {
        self.conn
            .transaction()
            .map(|tx| Box::new(TransactionWrapperReal::new(tx)) as Box<dyn TransactionWrapper + 'a>)
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
}

#[derive(Debug)]
pub struct TransactionWrapperReal<'a> {
    transaction: Option<Transaction<'a>>,
}

impl<'a> TransactionWrapperReal<'a> {
    fn new(transaction: Transaction<'a>) -> TransactionWrapperReal<'a> {
        Self {
            transaction: Some(transaction),
        }
    }
}

impl<'a> TransactionWrapper for TransactionWrapperReal<'a> {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.transaction
            .as_ref()
            .expectv("rusqlite transaction")
            .prepare(query)
    }

    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error> {
        self.transaction
            .as_ref()
            .expectv("rusqlite transaction")
            .execute(query, params)
    }

    fn commit(&mut self) -> Result<(), Error> {
        let transaction = self.transaction.take();
        transaction.expectv("rusqlite transaction").commit()
    }
}
