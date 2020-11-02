// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use rusqlite::types::ToSql;
use rusqlite::{Rows, NO_PARAMS, Row, Transaction};
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

pub trait ConfigDao {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError>;
    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError>;
    fn start_transaction(&mut self) -> Result<(), ConfigDaoError>;
    fn rollback_transaction(&mut self) -> Result<(), ConfigDaoError>;
    fn commit_transaction(&mut self) -> Result<(), ConfigDaoError>;
    fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
    transaction: Option<Transaction<'static>>
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

    fn start_transaction(&mut self) -> Result<(), ConfigDaoError> {
        unimplemented!()
    }

    fn rollback_transaction(&mut self) -> Result<(), ConfigDaoError> {
        unimplemented!()
    }

    fn commit_transaction(&mut self) -> Result<(), ConfigDaoError> {
        unimplemented!()
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
        ConfigDaoReal {
            conn,
            transaction: None,
        }
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
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        subject.transaction = None;

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
    fn set_and_get_and_committed_transactions_work() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "set_and_get_and_committed_transactions_work");
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let mut confirmer = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, false)
                .unwrap(),
        );
        let initial_value = subject.get("seed").unwrap();
        let modified_value = ConfigDaoRecord::new("seed", Some("Two wrongs don't make a right, but two Wrights make an airplane"), true);
        subject.start_transaction().unwrap();

        subject.set("seed", Some ("Two wrongs don't make a right, but two Wrights make an airplane")).unwrap();
        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get ("seed").unwrap();
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("seed").unwrap();

        assert_contains(&subject_get_all, &modified_value);
        assert_eq!(subject_get, modified_value);
        assert_contains(&confirmer_get_all, &initial_value);
        assert_eq!(confirmer_get, initial_value);

        subject.commit_transaction().unwrap();

        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get ("seed").unwrap();
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("seed").unwrap();
        assert_contains(&subject_get_all, &modified_value);
        assert_eq!(subject_get, modified_value);
        assert_contains(&confirmer_get_all, &modified_value);
        assert_eq!(confirmer_get, modified_value);
    }

    #[test]
    fn set_and_get_and_rolled_back_transactions_work() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "set_and_get_and_rolled_back_transactions_work");
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let mut confirmer = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, false)
                .unwrap(),
        );
        let initial_value = subject.get("seed").unwrap();
        let modified_value = ConfigDaoRecord::new("seed", Some("Two wrongs don't make a right, but two Wrights make an airplane"), true);
        subject.start_transaction().unwrap();

        subject.set("seed", Some ("Two wrongs don't make a right, but two Wrights make an airplane")).unwrap();
        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get ("seed").unwrap();
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("seed").unwrap();

        assert_contains(&subject_get_all, &modified_value);
        assert_eq!(subject_get, modified_value);
        assert_contains(&confirmer_get_all, &initial_value);
        assert_eq!(confirmer_get, initial_value);

        subject.rollback_transaction().unwrap();

        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get ("seed").unwrap();
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("seed").unwrap();
        assert_contains(&subject_get_all, &initial_value);
        assert_eq!(subject_get, initial_value);
        assert_contains(&confirmer_get_all, &initial_value);
        assert_eq!(confirmer_get, initial_value);
    }

    #[test]
    fn killing_config_dao_rolls_back_transaction() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "killing_config_dao_rolls_back_transaction");
        let mut confirmer = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        let initial_value = confirmer.get("seed").unwrap();
        let modified_value = ConfigDaoRecord::new("seed", Some("Two wrongs don't make a right, but two Wrights make an airplane"), true);

        {
            let mut subject = ConfigDaoReal::new(
                DbInitializerReal::new()
                    .initialize(&home_dir, DEFAULT_CHAIN_ID, false)
                    .unwrap(),
            );
            subject.start_transaction().unwrap();

            subject.set("seed", Some("Two wrongs don't make a right, but two Wrights make an airplane")).unwrap();
        }

        let confirmer_get_all = confirmer.get_all().unwrap();
        assert_contains(&confirmer_get_all, &initial_value);
        let confirmer_get = confirmer.get("seed").unwrap();
        assert_eq!(confirmer_get, initial_value);
    }

    #[test]
    fn set_complains_without_transaction() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "set_complains_without_transaction");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );

        let result = subject.set("booga", Some ("bigglesworth"));

        assert_eq!(result, Err(ConfigDaoError::TransactionError));
    }

    #[test]
    fn setting_nonexistent_value_returns_not_present() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "setting_nonexistent_value_returns_not_present");
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        subject.start_transaction().unwrap();

        let result = subject.set("booga", Some ("bigglesworth"));

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn setting_value_to_none_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "setting_value_to_none_removes_value_but_not_row");
        let mut subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        subject.start_transaction().unwrap();

        let _ = subject.set("schema_version", None).unwrap();

        let result = subject.get("schema_version").unwrap();
        assert_eq!(result, ConfigDaoRecord::new ("schema_version", None, false));
    }
}
