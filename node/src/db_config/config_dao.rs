// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::config_dao_old::ConfigDaoError::DatabaseError;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::cryptde::PlainData;
use rand::Rng;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Rows, Transaction, NO_PARAMS, Row};

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

pub trait TransactionWrapper: Send + Drop {
    fn commit(&mut self);
}

pub struct TransactionWrapperReal {}

impl TransactionWrapper for TransactionWrapperReal {
    fn commit(&mut self) {
        unimplemented!()
    }
}

impl Drop for TransactionWrapperReal {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl<'a> From<Transaction<'a>> for TransactionWrapperReal {
    fn from(input: Transaction) -> Self {
        unimplemented!()
    }
}

pub trait ConfigDao: Send {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError>;
    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError>;
    fn transaction(&self) -> Box<dyn TransactionWrapper>;
    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let mut stmt = self
            .conn
            .prepare("select name, value, encrypted from config")
            .expect("Schema error: couldn't compose query for config table");
        let mut rows: Rows = stmt
            .query(NO_PARAMS)
            .expect("Schema error: couldn't dump config table");
        let mut results = vec![];
        loop {
            match rows.next() {
                Err(e) => unimplemented!(),
                Ok(Some(row)) => results.push (Self::row_to_config_dao_record(row)),
                Ok(None) => break,
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

    fn transaction(&self) -> Box<dyn TransactionWrapper> {
        unimplemented!()
    }

    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError> {
        let mut stmt = match self
            .conn
            .prepare("update config set value = ? where name = ?")
        {
            Ok(stmt) => stmt,
            Err(e) => unimplemented!(), //return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
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
            Err(e) => unimplemented!(), //Err(ConfigDaoError::DatabaseError(format!("{}", e))), // Don't know how to trigger this
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
    use rusqlite::NO_PARAMS;

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
