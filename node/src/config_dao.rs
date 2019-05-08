// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::database::db_initializer::ConnectionWrapper;
use rusqlite::types::ToSql;
use rusqlite::OptionalExtension;

#[derive(Debug, PartialEq)]
pub enum ConfigDaoError {
    NotPresent,
    TypeError,
    DatabaseError(String),
}

pub trait ConfigDao {
    fn get_string(&self, name: &str) -> Result<String, ConfigDaoError>;
    fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError>;
    fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError>;
    fn set_u64(&self, name: &str, value: u64) -> Result<(), ConfigDaoError>;
    // Add getters and setters for other types as they become necessary
}

pub struct ConfigDaoReal {
    conn: Box<ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
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
}

impl ConfigDaoReal {
    pub fn new(conn: Box<ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }

    fn try_get(&self, name: &str) -> Result<String, ConfigDaoError> {
        let mut stmt = match self.conn.prepare("select value from config where name = ?") {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        match stmt.query_row(&[name], |row| row.get(0)).optional() {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(ConfigDaoError::NotPresent),
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
        let params: &[&ToSql] = &[&value, &name];
        match stmt.execute(params) {
            Ok(0) => Err(ConfigDaoError::NotPresent),
            Ok(_) => Ok(()),
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))), // Don't know how to trigger this
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
    };
    use crate::test_utils::test_utils::ensure_node_home_directory_exists;
    use rusqlite::NO_PARAMS;

    #[test]
    fn get_string_does_not_find_nonexistent_string() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "get_string_does_not_find_nonexistent_string",
        );
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.get_string("booga");

        assert_eq!(Err(ConfigDaoError::NotPresent), result);
    }

    #[test]
    fn get_string_passes_along_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_passes_along_database_error");
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());
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
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.get_string("schema_version");

        assert_eq!(Ok(CURRENT_SCHEMA_VERSION.to_string()), result);
    }

    #[test]
    fn set_string_passes_along_update_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_string_passes_along_database_error");
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());
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
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.set_string("booga", "whop");

        assert_eq!(Err(ConfigDaoError::NotPresent), result);
    }

    #[test]
    fn set_string_updates_existing_string() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_string_updates_existing_string");
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        subject.set_string("clandestine_port", "4096").unwrap();

        let actual = subject.get_string("clandestine_port");
        assert_eq!(Ok("4096".to_string()), actual);
    }

    #[test]
    fn get_u64_complains_about_string_value() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_u64_complains_about_string_value");
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());

        let result = subject.get_u64("schema_version");

        assert_eq!(Err(ConfigDaoError::TypeError), result);
    }

    #[test]
    fn set_u64_and_get_u64_communicate() {
        let home_dir = ensure_node_home_directory_exists("node", "set_u64_and_get_u64_communicate");
        let subject = ConfigDaoReal::new(DbInitializerReal::new().initialize(&home_dir).unwrap());
        subject.set_u64("clandestine_port", 4096).unwrap();

        let result = subject.get_u64("clandestine_port");

        assert_eq!(Ok(4096), result);
    }
}
