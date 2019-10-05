// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::config_dao::ConfigDaoError::DatabaseError;
use crate::database::db_initializer::ConnectionWrapper;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Rows, NO_PARAMS};

#[derive(Debug, PartialEq)]
pub enum ConfigDaoError {
    NotPresent,
    TypeError,
    DatabaseError(String),
}

pub trait ConfigDao: Send {
    fn get_all(&self) -> Result<Vec<(String, Option<String>)>, ConfigDaoError>;
    fn get_string(&self, name: &str) -> Result<String, ConfigDaoError>;
    fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError>;
    fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError>;
    fn set_u64(&self, name: &str, value: u64) -> Result<(), ConfigDaoError>;
    fn set_u64_transactional(
        &self,
        transaction: &rusqlite::Transaction,
        name: &str,
        value: u64,
    ) -> Result<(), ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
    fn get_all(&self) -> Result<Vec<(String, Option<String>)>, ConfigDaoError> {
        let mut stmt = self
            .conn
            .prepare("select name, value from config")
            .expect("Schema error: couldn't compose query for config table");
        let mut rows: Rows = stmt
            .query(NO_PARAMS)
            .expect("Schema error: couldn't dump config table");
        let mut results = Vec::new();
        loop {
            match rows.next() {
                Err(e) => return Err(DatabaseError(format!("{}", e))),
                Ok(Some(row)) => {
                    let name: String = row.get(0).expect("Schema error: no name column");
                    let value: Option<String> = row.get(1).expect("Schema error: no value column");
                    results.push((name, value))
                }
                Ok(None) => break,
            }
        }
        Ok(results)
    }

    fn get_string(&self, name: &str) -> Result<String, ConfigDaoError> {
        self.try_get(name)
    }

    fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError> {
        self.try_update(name, value)
    }

    fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError> {
        let str_value = match self.get_string(name) {
            Err(e) => return Err(e),
            Ok(s) => s,
        };
        match str_value.parse::<u64>() {
            Err(_) => Err(ConfigDaoError::TypeError),
            Ok(v) => Ok(v),
        }
    }

    fn set_u64(&self, name: &str, value: u64) -> Result<(), ConfigDaoError> {
        let str_value = format!("{}", value);
        self.set_string(name, &str_value)
    }

    fn set_u64_transactional(
        &self,
        transaction: &rusqlite::Transaction,
        name: &str,
        value: u64,
    ) -> Result<(), ConfigDaoError> {
        let mut statement = match transaction.prepare("update config set value = ? where name = ?")
        {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&value.to_string(), &name];
        handle_update_execution(statement.execute(params))
    }
}

impl From<Box<dyn ConnectionWrapper>> for ConfigDaoReal {
    fn from(conn: Box<dyn ConnectionWrapper>) -> Self {
        ConfigDaoReal::new(conn)
    }
}

impl ConfigDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }

    fn try_get(&self, name: &str) -> Result<String, ConfigDaoError> {
        let mut stmt = match self.conn.prepare("select value from config where name = ?") {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        match stmt.query_row(&[name], |row| row.get(0)).optional() {
            Ok(Some(Some(value))) => Ok(value),
            Ok(Some(None)) => Err(ConfigDaoError::NotPresent),
            Ok(None) => Err(ConfigDaoError::DatabaseError(format!(
                "Bad schema: config row for '{}' not present",
                name
            ))),
            Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))), // Don't know how to trigger this
        }
    }

    fn try_update(&self, name: &str, value: &str) -> Result<(), ConfigDaoError> {
        let mut stmt = match self
            .conn
            .prepare("update config set value = ? where name = ?")
        {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&value, &name];
        handle_update_execution(stmt.execute(params))
    }
}

fn handle_update_execution(result: rusqlite::Result<usize>) -> Result<(), ConfigDaoError> {
    match result {
        Ok(0) => Err(ConfigDaoError::NotPresent),
        Ok(_) => Ok(()),
        Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))), // Don't know how to trigger this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::ROPSTEN_CONTRACT_CREATION_BLOCK;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
    };
    use crate::test_utils::{assert_contains, ensure_node_home_directory_exists, DEFAULT_CHAIN_ID};
    use rusqlite::NO_PARAMS;

    #[test]
    fn get_all_returns_multiple_results() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_all_returns_multiple_results");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_all().unwrap();

        assert_contains(
            &result,
            &(
                "schema_version".to_string(),
                Some(CURRENT_SCHEMA_VERSION.to_string()),
            ),
        );
        assert_contains(
            &result,
            &(
                "start_block".to_string(),
                Some(ROPSTEN_CONTRACT_CREATION_BLOCK.to_string()),
            ),
        );
        assert_contains(&result, &("seed".to_string(), None));
    }

    #[test]
    fn get_string_complains_about_nonexistent_row() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_complains_about_nonexistent_row");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_string("booga");

        assert_eq!(
            Err(ConfigDaoError::DatabaseError(
                "Bad schema: config row for 'booga' not present".to_string()
            )),
            result
        );
    }

    #[test]
    fn get_string_does_not_find_null_value() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_does_not_find_null_value");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_string("seed");

        assert_eq!(Err(ConfigDaoError::NotPresent), result);
    }

    #[test]
    fn get_string_passes_along_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_passes_along_database_error");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let mut stmt = subject
            .conn
            .prepare("drop table config")
            .expect("Internal error");
        stmt.execute(NO_PARAMS).unwrap();

        let result = subject.get_string("booga");

        assert_eq!(
            Err(ConfigDaoError::DatabaseError(
                "no such table: config".to_string()
            )),
            result
        );
    }

    #[test]
    fn get_string_finds_existing_string() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_finds_existing_string");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_string("schema_version");

        assert_eq!(Ok(CURRENT_SCHEMA_VERSION.to_string()), result);
    }

    #[test]
    fn set_string_passes_along_update_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_string_passes_along_database_error");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let mut stmt = subject
            .conn
            .prepare("drop table config")
            .expect("Internal error");
        stmt.execute(NO_PARAMS).unwrap();

        let result = subject.set_string("version", CURRENT_SCHEMA_VERSION);

        assert_eq!(
            Err(ConfigDaoError::DatabaseError(
                "no such table: config".to_string()
            )),
            result
        );
    }

    #[test]
    fn set_string_complains_about_nonexistent_entry() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "set_string_complains_about_nonexistent_entry",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.set_string("booga", "whop");

        assert_eq!(Err(ConfigDaoError::NotPresent), result);
    }

    #[test]
    fn set_string_updates_existing_string() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_string_updates_existing_string");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        subject.set_string("clandestine_port", "4096").unwrap();

        let actual = subject.get_string("clandestine_port");
        assert_eq!(Ok("4096".to_string()), actual);
    }

    #[test]
    fn get_u64_complains_about_string_value() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_u64_complains_about_string_value");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_u64("schema_version");

        assert_eq!(Err(ConfigDaoError::TypeError), result);
    }

    #[test]
    fn set_u64_and_get_u64_communicate() {
        let home_dir = ensure_node_home_directory_exists("node", "set_u64_and_get_u64_communicate");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject.set_u64("clandestine_port", 4096).unwrap();

        let result = subject.get_u64("clandestine_port");

        assert_eq!(Ok(4096), result);
    }

    #[test]
    fn set_u64_transaction_updates_start_block() {
        let home_dir = ensure_node_home_directory_exists("node", "rename_me");
        let key = "start_block";
        let value = 99u64;

        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        {
            let mut db = DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap();
            let transaction = db.transaction().unwrap();

            subject
                .set_u64_transactional(&transaction, &key, value)
                .unwrap();
            transaction.commit().unwrap();
        }

        let result = subject.get_u64(key);

        assert_eq!(Ok(99u64), result);
    }
}
