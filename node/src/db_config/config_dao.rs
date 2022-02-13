// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::DaoFactoryReal;
use rusqlite::types::ToSql;
use rusqlite::{Row, Rows, Statement, Transaction};

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
    pub fn new(name: &str, value: Option<&str>, encrypted: bool) -> Self {
        Self {
            name: name.to_string(),
            value_opt: value.map(|x| x.to_string()),
            encrypted,
        }
    }

    pub fn new_owned(name: String, value_opt: Option<String>, encrypted: bool) -> Self {
        Self {
            name,
            value_opt,
            encrypted,
        }
    }
}

// Anything that can read from the database implements this trait
pub trait ConfigDaoRead {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError>;
    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError>;
}

// Anything that can write to the database implements this trait
pub trait ConfigDaoWrite {
    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError>;
    fn commit(&mut self) -> Result<(), ConfigDaoError>;
    fn extract(&mut self) -> Result<Transaction, ConfigDaoError>;
}

pub trait ConfigDaoReadWrite: ConfigDaoRead + ConfigDaoWrite {}

// ConfigDao can read from the database but not write to it; however, it can produce a
// ConfigDaoReadWrite, which contains a Transaction and _can_ write to the database.
pub trait ConfigDao: ConfigDaoRead {
    fn start_transaction<'b, 'c: 'b>(
        &'c mut self,
    ) -> Result<Box<dyn ConfigDaoReadWrite + 'b>, ConfigDaoError>;
}

pub struct ConfigDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl ConfigDao for ConfigDaoReal {
    fn start_transaction<'b, 'c: 'b>(
        &'c mut self,
    ) -> Result<Box<dyn ConfigDaoReadWrite + 'b>, ConfigDaoError> {
        let transaction: Transaction<'b> = match self.conn.transaction() {
            Ok(t) => t,
            // This line is untested, because we don't know how to pop this error in a test
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{:?}", e))),
        };
        Ok(Box::new(ConfigDaoWriteableReal::new(transaction)))
    }
}

impl ConfigDaoRead for ConfigDaoReal {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        let stmt = self
            .conn
            .prepare("select name, value, encrypted from config")
            .expect("Schema error: couldn't compose query for config table");
        get_all(stmt)
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        let stmt = self
            .conn
            .prepare("select name, value, encrypted from config where name = ?")
            .expect("Schema error: couldn't compose query for config table");
        get(stmt, name)
    }
}

impl ConfigDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }
}

// This is the real object that contains a Transaction for writing
pub struct ConfigDaoWriteableReal<'a> {
    transaction_opt: Option<Transaction<'a>>,
}

// But the Transaction-bearing writer can also read
impl ConfigDaoRead for ConfigDaoWriteableReal<'_> {
    fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
        if let Some(transaction) = &self.transaction_opt {
            let stmt = transaction
                .prepare("select name, value, encrypted from config")
                .expect("Schema error: couldn't compose query for config table");
            get_all(stmt)
        } else {
            Err(ConfigDaoError::TransactionError)
        }
    }

    fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
        if let Some(transaction) = &self.transaction_opt {
            let stmt = transaction
                .prepare("select name, value, encrypted from config where name = ?")
                .expect("Schema error: couldn't compose query for config table");
            get(stmt, name)
        } else {
            Err(ConfigDaoError::TransactionError)
        }
    }
}

// ...and it can write too
impl<'a> ConfigDaoWrite for ConfigDaoWriteableReal<'a> {
    fn set(&self, name: &str, value: Option<String>) -> Result<(), ConfigDaoError> {
        let transaction = match &self.transaction_opt {
            Some(t) => t,
            None => return Err(ConfigDaoError::TransactionError),
        };
        let mut stmt = match transaction.prepare("update config set value = ? where name = ?") {
            Ok(stmt) => stmt,
            // The following line is untested, because we don't know how to trigger it.
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&value, &name];
        handle_update_execution(stmt.execute(params))
    }

    fn commit(&mut self) -> Result<(), ConfigDaoError> {
        match self.transaction_opt.take() {
            Some(transaction) => match transaction.commit() {
                Ok(_) => Ok(()),
                // The following line is untested, because we don't know how to trigger it.
                Err(e) => Err(ConfigDaoError::DatabaseError(format!("{:?}", e))),
            },
            None => Err(ConfigDaoError::TransactionError),
        }
    }

    fn extract(&mut self) -> Result<Transaction, ConfigDaoError> {
        match self.transaction_opt.take() {
            Some(transaction) => Ok(transaction),
            None => Err(ConfigDaoError::TransactionError),
        }
    }
}

// Because we can't declare a parameter as "writer: Box<dyn ConfigDaoRead + dyn ConfigDaoWrite>"
impl<'a> ConfigDaoReadWrite for ConfigDaoWriteableReal<'a> {}

// This is the real version of ConfigDaoWriteable used in production
impl<'a> ConfigDaoWriteableReal<'a> {
    pub fn new(transaction: Transaction<'a>) -> Self {
        Self {
            transaction_opt: Some(transaction),
        }
    }
}

pub trait ConfigDaoFactory {
    fn make(&self) -> Box<dyn ConfigDao>;
}

impl ConfigDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn ConfigDao> {
        Box::new(ConfigDaoReal::new(self.make_connection()))
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

fn get_all(mut stmt: Statement) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
    let mut rows: Rows = stmt
        .query([])
        .expect("Schema error: couldn't dump config table");
    let mut results = Vec::new();
    loop {
        match rows.next() {
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
            Ok(Some(row)) => {
                let name: String = row.get(0).expect("Schema error: no name column");
                let value_opt: Option<String> = row.get(1).expect("Schema error: no value column");
                let encrypted: i32 = row.get(2).expect("Schema error: no encrypted column");
                match value_opt {
                    Some(s) => results.push(ConfigDaoRecord::new(
                        &name,
                        Some(s.as_str()),
                        encrypted != 0,
                    )),
                    None => results.push(ConfigDaoRecord::new(&name, None, encrypted != 0)),
                }
            }
            Ok(None) => break,
        }
    }
    Ok(results)
}

fn get(mut stmt: Statement, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
    match stmt.query_row(&[name], |row| Ok(row_to_config_dao_record(row))) {
        Ok(record) => Ok(record),
        Err(rusqlite::Error::QueryReturnedNoRows) => Err(ConfigDaoError::NotPresent),
        // The following line is untested, because we don't know how to trigger it.
        Err(e) => Err(ConfigDaoError::DatabaseError(format!("{}", e))),
    }
}

fn row_to_config_dao_record(row: &Row) -> ConfigDaoRecord {
    let name: String = row.get(0).expect("Schema error: no name column");
    let value_opt: Option<String> = row.get(1).expect("Schema error: no value column");
    let encrypted_int: i32 = row.get(2).expect("Schema error: no encrypted column");
    match value_opt {
        Some(value) => ConfigDaoRecord::new(&name, Some(&value), encrypted_int != 0),
        None => ConfigDaoRecord::new(&name, None, encrypted_int != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION,
    };
    use crate::database::db_migrations::MigratorConfig;
    use crate::test_utils::assert_contains;
    use masq_lib::constants::ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn get_all_returns_multiple_results() {
        let home_dir =
            ensure_node_home_directory_exists("config_dao", "get_all_returns_multiple_results");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.get_all().unwrap();

        assert_contains(
            &result,
            &ConfigDaoRecord::new(
                "schema_version",
                Some(&CURRENT_SCHEMA_VERSION.to_string()),
                false,
            ),
        );
        assert_contains(
            &result,
            &ConfigDaoRecord::new(
                "start_block",
                Some(&ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK.to_string()),
                false,
            ),
        );
        assert_contains(
            &result,
            &ConfigDaoRecord::new("consuming_wallet_private_key", None, true),
        );
    }

    #[test]
    fn get_returns_not_present_if_row_doesnt_exist() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "get_returns_not_present_if_row_doesnt_exist",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );

        let result = subject.get("booga");

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn set_and_get_and_committed_transactions_work() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "set_and_get_and_committed_transactions_work",
        );
        let mut dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let confirmer = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::panic_on_migration())
                .unwrap(),
        );
        let initial_value = dao.get("consuming_wallet_private_key").unwrap();
        let modified_value = ConfigDaoRecord::new(
            "consuming_wallet_private_key",
            Some("Two wrongs don't make a right, but two Wrights make an airplane"),
            true,
        );
        let mut subject = dao.start_transaction().unwrap();

        subject
            .set(
                "consuming_wallet_private_key",
                Some("Two wrongs don't make a right, but two Wrights make an airplane".to_string()),
            )
            .unwrap();

        let subject_get_all = subject.get_all().unwrap();
        let subject_get = subject.get("consuming_wallet_private_key").unwrap();
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("consuming_wallet_private_key").unwrap();
        assert_contains(&subject_get_all, &modified_value);
        assert_eq!(subject_get, modified_value);
        assert_contains(&confirmer_get_all, &initial_value);
        assert_eq!(confirmer_get, initial_value);
        subject.commit().unwrap();

        // Can't use a committed ConfigDaoWriteableReal anymore
        assert_eq!(subject.get_all(), Err(ConfigDaoError::TransactionError));
        assert_eq!(
            subject.get("consuming_wallet_private_key"),
            Err(ConfigDaoError::TransactionError)
        );
        assert_eq!(
            subject.set(
                "consuming_wallet_private_key",
                Some("irrelevant".to_string())
            ),
            Err(ConfigDaoError::TransactionError)
        );
        assert_eq!(subject.commit(), Err(ConfigDaoError::TransactionError));
        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("consuming_wallet_private_key").unwrap();
        assert_contains(&confirmer_get_all, &modified_value);
        assert_eq!(confirmer_get, modified_value);
    }

    #[test]
    fn extract_works() {
        let home_dir = ensure_node_home_directory_exists("config_dao", "extract_works");
        let mut dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        {
            let mut first_writer = dao.start_transaction().unwrap();
            let transaction = first_writer.extract().unwrap();
            let mut subject = ConfigDaoWriteableReal::new(transaction);

            subject
                .set(
                    "consuming_wallet_private_key",
                    Some(
                        "Two wrongs don't make a right, but two Wrights make an airplane"
                            .to_string(),
                    ),
                )
                .unwrap();

            subject.commit().unwrap();
            assert_eq!(
                subject.extract().err().unwrap(),
                ConfigDaoError::TransactionError
            );
        }
        let final_value = dao.get("consuming_wallet_private_key").unwrap();
        assert_eq!(
            final_value,
            ConfigDaoRecord::new(
                "consuming_wallet_private_key",
                Some("Two wrongs don't make a right, but two Wrights make an airplane"),
                true
            )
        );
    }

    #[test]
    fn set_and_get_and_rolled_back_transactions_work() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "set_and_get_and_rolled_back_transactions_work",
        );
        let mut dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let confirmer = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, false, MigratorConfig::panic_on_migration())
                .unwrap(),
        );
        let initial_value = dao.get("consuming_wallet_private_key").unwrap();
        let modified_value = ConfigDaoRecord::new(
            "consuming_wallet_private_key",
            Some("Two wrongs don't make a right, but two Wrights make an airplane"),
            true,
        );
        {
            let subject = dao.start_transaction().unwrap();

            subject
                .set(
                    "consuming_wallet_private_key",
                    Some(
                        "Two wrongs don't make a right, but two Wrights make an airplane"
                            .to_string(),
                    ),
                )
                .unwrap();

            let subject_get_all = subject.get_all().unwrap();
            let subject_get = subject.get("consuming_wallet_private_key").unwrap();
            let confirmer_get_all = confirmer.get_all().unwrap();
            let confirmer_get = confirmer.get("consuming_wallet_private_key").unwrap();
            assert_contains(&subject_get_all, &modified_value);
            assert_eq!(subject_get, modified_value);
            assert_contains(&confirmer_get_all, &initial_value);
            assert_eq!(confirmer_get, initial_value);
            // Subject should roll back when dropped
        }

        let confirmer_get_all = confirmer.get_all().unwrap();
        let confirmer_get = confirmer.get("consuming_wallet_private_key").unwrap();
        assert_contains(&confirmer_get_all, &initial_value);
        assert_eq!(confirmer_get, initial_value);
    }

    #[test]
    fn setting_nonexistent_value_returns_not_present() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "setting_nonexistent_value_returns_not_present",
        );
        let mut dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        let subject = dao.start_transaction().unwrap();

        let result = subject.set("booga", Some("bigglesworth".to_string()));

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn setting_value_to_none_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists(
            "config_dao",
            "setting_value_to_none_removes_value_but_not_row",
        );
        let mut dao = ConfigDaoReal::new(
            DbInitializerReal::default()
                .initialize(&home_dir, true, MigratorConfig::test_default())
                .unwrap(),
        );
        {
            let mut subject = dao.start_transaction().unwrap();

            let _ = subject.set("schema_version", None).unwrap();
            subject.commit().unwrap();
        }
        let result = dao.get("schema_version").unwrap();
        assert_eq!(result, ConfigDaoRecord::new("schema_version", None, false));
    }
}
