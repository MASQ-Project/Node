// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[cfg(test)]
use crate::arbitrary_id_stamp_in_trait;
#[cfg(test)]
use crate::test_utils::unshared_test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use rusqlite::{Connection, Error, Statement, Transaction};
use std::fmt::Debug;

pub trait ConnectionWrapper: Debug + Send {
    fn prepare(&self, query: &str) -> Result<Statement, rusqlite::Error>;
    fn transaction<'a: 'b, 'b>(&'a mut self) -> Result<Transaction<'b>, rusqlite::Error>;

    #[cfg(test)]
    arbitrary_id_stamp_in_trait!();
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
