// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_migrations::DbMigrator;
use crate::sub_lib::logger::Logger;
use rusqlite::{Connection, NO_PARAMS};
use std::cell::RefCell;
use std::fs::remove_file;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

//the only difference to the original is that we create the db in every call anew
pub fn revive_tables_of_the_version_0_and_return_the_connection_to_the_db(
    db_path: &PathBuf,
) -> Connection {
    match remove_file(db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!("Unexpected but serious error: {}", e),
        _ => (),
    };
    let connection = Connection::open(&db_path).unwrap();
    [
        "create table config (
            name text not null,
            value text,
            encrypted integer not null )",
        "create unique index idx_config_name on config (name)",
        "insert into config (name, value, encrypted) values ('example_encrypted', null, 1)",
        "insert into config (name, value, encrypted) values ('clandestine_port', '2897', 0)",
        "insert into config (name, value, encrypted) values ('consuming_wallet_derivation_path', null, 0)",
        "insert into config (name, value, encrypted) values ('consuming_wallet_public_key', null, 0)",
        "insert into config (name, value, encrypted) values ('earning_wallet_address', null, 0)",
        "insert into config (name, value, encrypted) values ('schema_version', '0', 0)",
        "insert into config (name, value, encrypted) values ('seed', null, 0)",
        "insert into config (name, value, encrypted) values ('start_block', 8688171, 0)",
        "insert into config (name, value, encrypted) values ('gas_price', '1', 0)",
        "insert into config (name, value, encrypted) values ('past_neighbors', null, 1)",
        "create table payable (
                wallet_address text primary key,
                balance integer not null,
                last_paid_timestamp integer not null,
                pending_payment_transaction text null
            )",
        "create unique index idx_payable_wallet_address on payable (wallet_address)",
        "create table receivable (
                wallet_address text primary key,
                balance integer not null,
                last_received_timestamp integer not null
            )",
        "create unique index idx_receivable_wallet_address on receivable (wallet_address)",
        "create table banned ( wallet_address text primary key )",
        "create unique index idx_banned_wallet_address on banned (wallet_address)"
    ].iter().for_each(|statement|{connection.execute(statement,NO_PARAMS).unwrap();});
    connection
}

#[derive(Default)]
pub struct DbMigratorMock {
    logger: Option<Logger>,
    migrate_database_result: RefCell<Vec<Result<(), String>>>,
    migrate_database_params: Arc<Mutex<Vec<(usize, usize, Box<dyn ConnectionWrapper>)>>>,
}

impl DbMigratorMock {
    pub fn migrate_database_result(self, result: Result<(), String>) -> Self {
        self.migrate_database_result.borrow_mut().push(result);
        self
    }
    pub fn migrate_database_params(
        mut self,
        params: &Arc<Mutex<Vec<(usize, usize, Box<dyn ConnectionWrapper>)>>>,
    ) -> Self {
        self.migrate_database_params = params.clone();
        self
    }

    pub fn inject_logger(mut self) -> Self {
        self.logger = Some(Logger::new("DbMigrator"));
        self
    }
}

impl DbMigrator for DbMigratorMock {
    fn migrate_database(
        &self,
        outdated_schema: usize,
        target_version: usize,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        self.migrate_database_params
            .lock()
            .unwrap()
            .push((outdated_schema, target_version, conn));
        self.migrate_database_result.borrow_mut().pop().unwrap()
    }
}

pub fn assurance_query_for_config_table(
    conn: &dyn ConnectionWrapper,
    stm: &str,
) -> (String, Option<String>, u16) {
    let mut statement = conn.prepare(stm).unwrap();
    statement
        .query_row(NO_PARAMS, |r| {
            Ok((r.get(0).unwrap(), r.get(1).unwrap(), r.get(2).unwrap()))
        })
        .unwrap()
}
