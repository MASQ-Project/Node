// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::masq_lib::utils::ExpectValue;
use rusqlite::{Connection, Error, Statement, ToSql, Transaction};
use std::fmt::Debug;

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

pub trait TransactionWrapper: Debug {
    fn prepare(&self, query: &str) -> Result<Statement, Error>;
    fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<usize, Error>;
    fn commit(&mut self) -> Result<(), Error>;
}
