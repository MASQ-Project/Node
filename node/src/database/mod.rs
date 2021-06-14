// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
pub mod config_dumper;
pub mod connection_wrapper;
pub mod dao_utils;
pub mod db_initializer;
pub mod db_migrations;

#[cfg(test)]
pub mod test_utils {
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::database::db_migrations::DbMigrator;
    use masq_lib::test_utils::fake_stream_holder::ByteArrayReader;
    use rusqlite::{Connection, NO_PARAMS};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct DbMigratorMock {
        logger: Option<ByteArrayReader>,
        migrate_database_result: RefCell<Vec<Result<(), String>>>,
        migrate_database_params: RefCell<Arc<Mutex<Vec<(String, Box<dyn ConnectionWrapper>)>>>>,
    }

    impl DbMigratorMock {
        pub fn migrate_database_result(self, result: Result<(), String>) -> Self {
            self.migrate_database_result.borrow_mut().push(result);
            self
        }
        pub fn migrate_database_params(
            self,
            result: Arc<Mutex<Vec<(String, Box<dyn ConnectionWrapper>)>>>,
        ) -> Self {
            self.migrate_database_params.replace(result);
            self
        }

        pub fn inject_logger(mut self, reader: ByteArrayReader) {
            self.logger = Some(reader)
        }
    }

    impl DbMigrator for DbMigratorMock {
        fn migrate_database(
            &self,
            outdated_schema: &str,
            conn: Box<dyn ConnectionWrapper>,
        ) -> Result<(), String> {
            self.migrate_database_params
                .borrow_mut()
                .lock()
                .unwrap()
                .push((outdated_schema.to_string(), conn));
            self.migrate_database_result.borrow_mut().pop().unwrap()
        }

        fn log_warn(&self, _msg: &str) {
            ()
        }
    }

    pub fn assurance_query_for_config_table(
        conn: &Connection,
        stm: &str,
    ) -> (String, Option<String>, u16) {
        conn.query_row(stm, NO_PARAMS, |r| {
            Ok((r.get(0).unwrap(), r.get(1).unwrap(), r.get(2).unwrap()))
        })
        .unwrap()
    }
}
