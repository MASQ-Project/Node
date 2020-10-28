// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::config_dao_old::ConfigDaoError::DatabaseError;
use crate::database::db_initializer::ConnectionWrapper;
use crate::sub_lib::cryptde::PlainData;
use rand::Rng;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Rows, Transaction, NO_PARAMS};

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

impl ConfigDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> ConfigDaoReal {
        ConfigDaoReal { conn }
    }
}

/*
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
            ensure_node_home_directory_exists("node", "get_all_returns_multiple_results");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                Some(ROPSTEN_TESTNET_CONTRACT_CREATION_BLOCK.to_string()),
            ),
        );
        assert_contains(&result, &("seed".to_string(), None));
    }

    #[test]
    fn clear_removes_value_but_not_row() {
        let home_dir = ensure_node_home_directory_exists("node", "clear_removes_value_but_not_row");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
}
*/
