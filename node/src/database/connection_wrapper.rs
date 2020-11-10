// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use std::fmt::Debug;
use rusqlite::{Statement, Transaction, Connection, Error};

pub trait TransactionWrapper<'a>: Drop {
    fn commit(&mut self);
    fn prepare(& self, query: &str) -> Result<Statement, rusqlite::Error>;
}

pub struct TransactionWrapperReal<'a> {
    transaction: Transaction<'a>,
}

impl<'a> TransactionWrapper<'a> for TransactionWrapperReal<'a> {
    fn commit(&mut self) {
        unimplemented!()
    }

    fn prepare(& self, query: &str) -> Result<Statement, Error> {
        unimplemented!()
    }
}

impl<'a> Drop for TransactionWrapperReal<'a> {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl<'a> From<Transaction<'a>> for TransactionWrapperReal<'a> {
    fn from(transaction: Transaction<'a>) -> Self {
        Self{
            transaction
        }
    }
}

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction<'a: 'b, 'b>(&'a mut self) -> Result<Transaction<'b>, rusqlite::Error>;
}

#[derive(Debug)]
pub struct ConnectionWrapperReal {
    conn: Connection,
}

impl ConnectionWrapper for ConnectionWrapperReal {
    fn prepare(&self, query: &str) -> Result<Statement, Error> {
        self.conn.prepare(query)
    }
    fn transaction<'a: 'b, 'b>(&'a mut self) -> Result<Transaction<'b>, Error> {
        Ok(self.conn.transaction()?)
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}
