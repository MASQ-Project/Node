// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use rusqlite::{Connection, Error, Statement, Transaction};
use std::fmt::Debug;

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
        self.conn.transaction()
    }
}

impl ConnectionWrapperReal {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}
