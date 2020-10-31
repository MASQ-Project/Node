// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use rusqlite::types::ToSql;
use rusqlite::{Rows, NO_PARAMS, Row};
use crate::database::connection_wrapper::{ConnectionWrapper, TransactionWrapper};

#[derive(Debug, PartialEq, Clone)]
pub enum ConfigDaoError {
    NotPresent,
    TransactionError,
    DatabaseError(String),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfigDaoRecord {
    pub name: String,
    pub value_opt: Option<String>,
    pub encrypted: bool,
}

impl ConfigDaoRecord {
    pub(crate) fn new(name: &str, value: Option<&str>, encrypted: bool) -> Self {
        Self {
            name: name.to_string(),
            value_opt: value.map(|x| x.to_string()),
            encrypted,
        }
    }
}

pub trait ConfigDao: Send {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError>;
    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError>;
    fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a>;
    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let mut stmt = self.conn
            .prepare("select name, value, encrypted from config")
            .expect("Schema error: couldn't compose query for config table");
        let mut rows: Rows = stmt
            .query(NO_PARAMS)
            .expect("Schema error: couldn't dump config table");
        let mut results = vec![];
        loop {
            match rows.next() {
                Ok(Some(row)) => results.push (Self::row_to_config_dao_record(row)),
                Ok(None) => break,
                // The following line is untested, because we don't know how to trigger it.
                Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
            }
        }
        Ok(results)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        let mut stmt = match self.conn.prepare("select name, value, encrypted from config where name = ?") {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        match stmt.query_row(&[name], |row| Ok(Self::row_to_config_dao_record(row))) {
            Ok(record) => Ok(record),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(ConfigDaoError::NotPresent),
            // The following line is untested, because we don't know how to trigger it.
            Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        }
    }

    fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a> {
        self.conn.transaction().expect("Creating transaction failed")
    }

    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError> {
        let mut stmt = match self.conn
            .prepare("update config set value = ? where name = ?")
        {
            Ok(stmt) => stmt,
            // The following line is untested, because we don't know how to trigger it.
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&value, &name];
        Self::handle_update_execution(stmt.execute(params))
    }
}

impl ConfigDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }

    fn row_to_config_dao_record(row: &Row) -> ConfigDaoRecord {
        let name: String = row.get(0).expect("Schema error: no name column");
        let value_opt: Option<String> = row.get(1).expect("Schema error: no value column");
        let encrypted_int: i32 = row.get(2).expect("Schema error: no encrypted column");
        match value_opt {
            Some (value) => ConfigDaoRecord::new(&name, Some (&value), encrypted_int != 0),
            None => ConfigDaoRecord::new (&name, None, encrypted_int != 0),
        }
    }

    fn handle_update_execution(result: rusqlite::Result<usize>) -> Result<(), ConfigDaoError> {
        match result {
            Ok(0) => Err(ConfigDaoError::NotPresent),
            Ok(_) => Ok(()),
            // The following line is untested, because we don't know how to trigger it.
            Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
    };
    use crate::test_utils::assert_contains;
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, DEFAULT_CHAIN_ID};

    #[test]
    fn get_all_returns_multiple_results() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "get_all_returns_multiple_results");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let result = subject.get_all().unwrap();

        assert_contains(
            &result,
            &ConfigDaoRecord::new("schema_version", Some(CURRENT_SCHEMA_VERSION), false),
        );
        assert_contains(
            &result,
            &ConfigDaoRecord::new("start_block", Some(&ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK.to_string()), false),
        );
        assert_contains(&result, &ConfigDaoRecord::new ("seed", None, true));
    }

    #[test]
    fn get_returns_not_present_if_row_doesnt_exist() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "get_returns_not_present_if_row_doesnt_exist");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let result = subject.get("booga");

        assert_eq! (result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn transaction_returns_wrapped_transaction() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "transaction_returns_wrapped_transaction");
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let before_value = subject.get("schema_version").unwrap();

        let mut transaction = subject.transaction();

        subject.set(CURRENT_SCHEMA_VERSION, Some ("Booga"));
        let middle_value = subject.get ("schema_version").unwrap();
        transaction.commit();
        let final_value = subject.get ("schema_version").unwrap();
        assert_eq! (&before_value.value_opt.unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq! (&middle_value.value_opt.unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq! (&final_value.value_opt.unwrap(), "Booga");
    }

    #[test]
    fn set_and_get_work() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "set_and_get_work");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let _ = subject.set("seed", Some ("Two wrongs don't make a right, but two Wrights make an airplane")).unwrap();

        let result = subject.get("seed").unwrap();
        assert_eq!(result, ConfigDaoRecord::new ("seed", Some("Two wrongs don't make a right, but two Wrights make an airplane"), true));
    }

    #[test]
    fn setting_nonexistent_value_returns_not_present() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "setting_nonexistent_value_returns_not_present");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let result = subject.set("booga", Some ("bigglesworth"));

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn setting_value_to_none_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "setting_value_to_none_removes_value_but_not_row");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let _ = subject.set("schema_version", None).unwrap();

        let result = subject.get("schema_version").unwrap();
        assert_eq!(result, ConfigDaoRecord::new ("schema_version", None, false));
    }
}
