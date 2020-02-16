// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::config_dao::ConfigDaoError::DatabaseError;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::cryptde::PlainData;
use rand::Rng;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Rows, NO_PARAMS};

#[derive(Debug, PartialEq)]
pub enum ConfigDaoError {
    NotPresent,
    TypeError,
    PasswordError,
    CryptoError(String),
    DatabaseError(String),
}

pub trait ConfigDao: Send {
    fn get_all(
        &self,
        db_password: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, ConfigDaoError>;
    fn check_password(&self, db_password: &str) -> Result<bool, ConfigDaoError>;
    fn change_password(
        &self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), ConfigDaoError>;
    fn get_string(&self, name: &str) -> Result<String, ConfigDaoError>;
    fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError>;
    fn get_bytes_e(&self, name: &str, db_password: &str) -> Result<PlainData, ConfigDaoError>;
    fn set_bytes_e(
        &self,
        name: &str,
        value: &PlainData,
        db_password: &str,
    ) -> Result<(), ConfigDaoError>;
    fn get_u64(&self, name: &str) -> Result<u64, ConfigDaoError>;
    fn clear(&self, name: &str) -> Result<(), ConfigDaoError>;
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
    fn get_all(
        &self,
        _db_password: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, ConfigDaoError> {
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

    fn check_password(&self, db_password: &str) -> Result<bool, ConfigDaoError> {
        let encrypted_string = self.get_string("example_encrypted")?;
        match Bip39::decrypt_bytes(&encrypted_string, db_password) {
            Ok(_) => Ok(true),
            Err(Bip39Error::DecryptionFailure(_)) => Ok(false),
            Err(e) => Err(ConfigDaoError::CryptoError(format!("{:?}", e))),
        }
    }

    fn change_password(
        &self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), ConfigDaoError> {
        if let Some(old_password) = old_password_opt {
            match self.check_password(old_password) {
                Ok(true) => (),
                Ok(false) => return Err(ConfigDaoError::PasswordError),
                Err(ConfigDaoError::NotPresent) => return Err(ConfigDaoError::PasswordError),
                Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{:?}", e))),
            }
        } else if self.check_password("bad password") != Err(ConfigDaoError::NotPresent) {
            return Err(ConfigDaoError::PasswordError);
        }
        let example_data: Vec<u8> = [0..32]
            .iter()
            .map(|_| rand::thread_rng().gen::<u8>())
            .collect();
        let example_encrypted = match Bip39::encrypt_bytes(&example_data, new_password) {
            Ok(bytes) => bytes,
            Err(e) => return Err(ConfigDaoError::CryptoError(format!("{:?}", e))),
        };
        self.set_string("example_encrypted", &example_encrypted)?;
        if old_password_opt == None {
            return Ok(());
        }
        let encrypted_column_names: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("select name from config where encrypted = 1")
                .expect("Couldn't create statement to select names");
            stmt.query_map(NO_PARAMS, |row| {
                let column_name: String = row.get(0).expect("Row has no name");
                Ok(column_name)
            })
            .optional()
            .expect("Config table is corrupt 1")
            .expect("Config table is corrupt 2")
            .flatten()
            .collect()
        };
        for name in encrypted_column_names {
            match self.get_string(&name) {
                Err(ConfigDaoError::NotPresent) => (),
                Err(e) => return Err(e),
                Ok(encrypted_value) => {
                    match Bip39::decrypt_bytes(
                        &encrypted_value,
                        old_password_opt.expect("Old password disappeared"),
                    ) {
                        Err(e) => {
                            return Err(ConfigDaoError::DatabaseError(format!(
                                "Corrupt encrypted value for {}: {:?}",
                                name, e
                            )))
                        }
                        Ok(plain_data) => {
                            let reencrypted =
                                match Bip39::encrypt_bytes(&plain_data.as_slice(), new_password) {
                                    Err(e) => {
                                        return Err(ConfigDaoError::DatabaseError(format!(
                                            "Error reencrypting {}: {:?}",
                                            name, e
                                        )))
                                    }
                                    Ok(s) => s,
                                };
                            self.set_string(&name, &reencrypted)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn get_string(&self, name: &str) -> Result<String, ConfigDaoError> {
        self.try_get(name)
    }

    fn set_string(&self, name: &str, value: &str) -> Result<(), ConfigDaoError> {
        self.try_update(name, value)
    }

    fn get_bytes_e(&self, name: &str, db_password: &str) -> Result<PlainData, ConfigDaoError> {
        let encrypted_string = match self.get_string(name) {
            Ok(s) => s,
            Err(ConfigDaoError::NotPresent) => return Err(ConfigDaoError::NotPresent),
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{:?}", e))),
        };
        match Bip39::decrypt_bytes(&encrypted_string, &db_password) {
            Ok(data) => Ok(data),
            Err(Bip39Error::DecryptionFailure(_)) => Err(ConfigDaoError::PasswordError),
            Err(e) => Err(ConfigDaoError::CryptoError(format!(
                "Can't decrypt value for {}: {:?}",
                name, e
            ))),
        }
    }

    fn set_bytes_e(
        &self,
        name: &str,
        value: &PlainData,
        db_password: &str,
    ) -> Result<(), ConfigDaoError> {
        match self.check_password(db_password) {
            Ok(true) => (),
            Ok(false) => return Err(ConfigDaoError::PasswordError),
            Err(ConfigDaoError::NotPresent) => match self.change_password(None, db_password) {
                Ok(_) => (),
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
        let encrypted_string = match Bip39::encrypt_bytes(&value.as_slice(), db_password) {
            Ok(s) => s,
            Err(e) => {
                return Err(ConfigDaoError::CryptoError(format!(
                    "Could not encrypt value for {}: {:?}",
                    name, e
                )))
            }
        };
        self.set_string(name, &encrypted_string)
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

    fn clear(&self, name: &str) -> Result<(), ConfigDaoError> {
        let mut stmt = match self
            .conn
            .prepare("update config set value = null where name = ?")
        {
            Ok(stmt) => stmt,
            Err(e) => return Err(ConfigDaoError::DatabaseError(format!("{}", e))),
        };
        let params: &[&dyn ToSql] = &[&name];
        handle_update_execution(stmt.execute(params))
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

    #[cfg(test)]
    fn add_string_rows(&self, pairs: Vec<(&str, bool)>) {
        let mut stmt = self
            .conn
            .prepare("insert into config (name, value, encrypted) values (?, null, ?)")
            .unwrap();
        pairs.into_iter().for_each(|(name, encrypted)| {
            let params: &[&dyn ToSql] = &[&name.to_string(), if encrypted { &1 } else { &0 }];
            stmt.execute(params).unwrap();
        });
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
    use crate::test_utils::{assert_contains, DEFAULT_CHAIN_ID};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
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

        let result = subject.get_all(None).unwrap();

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
    fn clear_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists("node", "clear_removes_value_but_not_row");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let _ = subject.clear("schema_version").unwrap();

        let result = subject.get_string("schema_version");
        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn check_password_handles_missing_password() {
        let home_dir =
            ensure_node_home_directory_exists("node", "check_password_handles_missing_password");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.check_password("password");

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn check_password_handles_bad_password() {
        let home_dir =
            ensure_node_home_directory_exists("node", "check_password_handles_bad_password");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject.change_password(None, "password").unwrap();

        let result = subject.check_password("drowssap");

        assert_eq!(result, Ok(false));
    }

    #[test]
    fn check_password_handles_good_password() {
        let home_dir =
            ensure_node_home_directory_exists("node", "check_password_handles_good_password");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject.change_password(None, "password").unwrap();

        let result = subject.check_password("password");

        assert_eq!(result, Ok(true));
    }

    #[test]
    fn setting_the_first_encrypted_field_sets_the_password() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "setting_the_first_encrypted_field_sets_the_password",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject.add_string_rows(vec![("first_encrypted_field", true)]);

        subject
            .set_bytes_e(
                "first_encrypted_field",
                &PlainData::new(b"value"),
                "password",
            )
            .unwrap();

        assert!(subject.check_password("password").unwrap());
    }

    #[test]
    fn change_password_complains_if_given_no_old_password_when_an_old_password_exists() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "change_password_complains_if_given_no_old_password_when_an_old_password_exists",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let old_password = "old password";
        let new_password = "new password";
        subject.change_password(None, old_password).unwrap();

        let result = subject.change_password(None, new_password);

        assert_eq!(result, Err(ConfigDaoError::PasswordError));
    }

    #[test]
    fn change_password_complains_if_given_old_password_when_no_old_password_exists() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "change_password_complains_if_given_old_password_when_no_old_password_exists",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let old_password = "old password";
        let new_password = "new password";

        let result = subject.change_password(Some(old_password), new_password);

        assert_eq!(result, Err(ConfigDaoError::PasswordError));
    }

    #[test]
    fn change_password_complains_if_given_incorrect_old_password() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "change_password_complains_if_given_incorrect_old_password",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let old_password = "old password";
        let new_password = "new password";
        subject.change_password(None, old_password).unwrap();

        let result = subject.change_password(Some(new_password), new_password);

        assert_eq!(result, Err(ConfigDaoError::PasswordError));
    }

    #[test]
    fn change_password_works_when_old_password_exists() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "change_password_works_when_old_password_exists",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let old_password = "old password";
        let new_password = "new password";
        let cleartext_one = "cleartext one";
        let cleartext_two = "cleartext two";
        let ciphertext_one = PlainData::new(&[1, 2, 3, 4]);
        let ciphertext_two = PlainData::new(&[4, 3, 2, 1]);
        subject.add_string_rows(vec![
            ("unencrypted_one", false),
            ("unencrypted_two", false),
            ("encrypted_one", true),
            ("encrypted_two", true),
        ]);
        subject.change_password(None, old_password).unwrap();
        subject
            .set_string("unencrypted_one", cleartext_one)
            .unwrap();
        subject
            .set_string("unencrypted_two", cleartext_two)
            .unwrap();
        subject
            .set_bytes_e("encrypted_one", &ciphertext_one, old_password)
            .unwrap();
        subject
            .set_bytes_e("encrypted_two", &ciphertext_two, old_password)
            .unwrap();

        subject
            .change_password(Some(old_password), new_password)
            .unwrap();

        assert!(!subject.check_password(old_password).unwrap());
        assert!(subject.check_password(new_password).unwrap());
        assert_eq!(
            subject.get_string("unencrypted_one"),
            Ok(cleartext_one.to_string())
        );
        assert_eq!(
            subject.get_string("unencrypted_two"),
            Ok(cleartext_two.to_string())
        );
        assert_eq!(
            subject.get_bytes_e("encrypted_one", new_password),
            Ok(ciphertext_one)
        );
        assert_eq!(
            subject.get_bytes_e("encrypted_two", new_password),
            Ok(ciphertext_two)
        );
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
    fn get_bytes_e_complains_about_nonexistent_row() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "get_bytes_e_complains_about_nonexistent_row",
        );
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_bytes_e("booga", "password");

        assert_eq!(
            result,
            Err(ConfigDaoError::DatabaseError(
                "DatabaseError(\"Bad schema: config row for \\'booga\\' not present\")".to_string()
            )),
        );
    }

    #[test]
    fn get_bytes_e_does_not_find_null_value() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_bytes_e_does_not_find_null_value");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.get_bytes_e("seed", "password");

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn get_bytes_e_balks_at_bad_password() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_bytes_e_balks_at_bad_password");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let data = PlainData::new(&[1, 2, 3, 4]);
        subject.set_bytes_e("seed", &data, "password").unwrap();

        let result = subject.get_bytes_e("seed", "drowssap");

        assert_eq!(result, Err(ConfigDaoError::PasswordError))
    }

    #[test]
    fn get_bytes_e_passes_along_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_bytes_e_passes_along_database_error");
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

        let result = subject.get_bytes_e("booga", "password");

        assert_eq!(
            result,
            Err(ConfigDaoError::DatabaseError(
                "DatabaseError(\"no such table: config\")".to_string()
            )),
        );
    }

    #[test]
    fn get_bytes_e_finds_existing_data() {
        let home_dir = ensure_node_home_directory_exists("node", "get_bytes_e_finds_existing_data");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let data = PlainData::new(&[1, 2, 3, 4]);
        subject.set_bytes_e("seed", &data, "password").unwrap();

        let result = subject.get_bytes_e("seed", "password");

        assert_eq!(result, Ok(data));
    }

    #[test]
    fn set_bytes_e_passes_along_update_database_error() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_bytes_e_passes_along_database_error");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        let data = PlainData::new(&[1, 2, 3, 4]);
        let mut stmt = subject
            .conn
            .prepare("drop table config")
            .expect("Internal error");
        stmt.execute(NO_PARAMS).unwrap();

        let result = subject.set_bytes_e("version", &data, "password");

        assert_eq!(
            result,
            Err(ConfigDaoError::DatabaseError(
                "no such table: config".to_string()
            )),
        );
    }

    #[test]
    fn set_bytes_e_complains_about_nonexistent_entry() {
        let home_dir = ensure_node_home_directory_exists(
            "node",
            "set_bytes_e_complains_about_nonexistent_entry",
        );
        let data = PlainData::new(&[1, 2, 3, 4]);
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );

        let result = subject.set_bytes_e("booga", &data, "password");

        assert_eq!(result, Err(ConfigDaoError::NotPresent));
    }

    #[test]
    fn set_bytes_balks_at_wrong_password() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_bytes_balks_at_wrong_password");
        let data = PlainData::new(&[1, 2, 3, 4]);
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject.change_password(None, "password").unwrap();

        let result = subject.set_bytes_e("booga", &data, "drowssap");

        assert_eq!(result, Err(ConfigDaoError::PasswordError));
    }

    #[test]
    fn set_bytes_e_updates_existing_string() {
        let home_dir =
            ensure_node_home_directory_exists("node", "set_bytes_e_updates_existing_string");
        let original_data = PlainData::new(&[1, 2, 3, 4]);
        let modified_data = PlainData::new(&[4, 3, 2, 1]);
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID)
                .unwrap(),
        );
        subject
            .set_bytes_e("seed", &original_data, "password")
            .unwrap();

        subject
            .set_bytes_e("seed", &modified_data, "password")
            .unwrap();

        let result = subject.get_bytes_e("seed", "password");
        assert_eq!(result, Ok(modified_data));
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
