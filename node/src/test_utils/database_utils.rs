// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_migrations::DbMigrator;
use crate::sub_lib::logger::Logger;
use rusqlite::{Connection, NO_PARAMS};
use std::cell::RefCell;
use std::env::current_dir;
use std::fs::{remove_file, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub fn bring_db_of_version_0_back_to_life_and_return_connection(db_path: &PathBuf) -> Connection {
    match remove_file(db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => panic!("Unexpected but serious error: {}", e),
        _ => (),
    };
    let conn = Connection::open(&db_path).unwrap();
    let file_path = current_dir()
        .unwrap()
        .join("src")
        .join("test_utils")
        .join("database_version_0_sql.txt");
    let mut file = File::open(file_path).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    buffer.lines().for_each(|stm| {
        conn.execute(stm, NO_PARAMS).unwrap();
    });
    conn
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
        .unwrap_or_else(|e| panic!("panicked at {} for statement: {}", e, stm))
}
