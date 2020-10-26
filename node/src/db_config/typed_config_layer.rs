// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::db_config::config_dao::{ConfigDao, ConfigDaoError, TransactionWrapper, ConfigDaoRecord};
use crate::blockchain::bip39::{Bip39, Bip39Error};
use rand::Rng;
use crate::sub_lib::cryptde::PlainData;
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};

#[derive(Debug, PartialEq)]
pub enum TypedConfigLayerError {
    NotPresent,
    TypeError,
    PasswordError,
    TransactionError,
    CryptoError(String),
    DatabaseError(String),
}

impl From<SecureConfigLayerError> for TypedConfigLayerError {
    fn from(input: SecureConfigLayerError) -> Self {
        match input {
            SecureConfigLayerError::NotPresent => TypedConfigLayerError::NotPresent,
            SecureConfigLayerError::TransactionError => TypedConfigLayerError::TransactionError,
            SecureConfigLayerError::DatabaseError(msg) => TypedConfigLayerError::DatabaseError(msg),
            e => unimplemented! ("Remove from SecureConfigLayerError: {:?}", e),
        }
    }
}

pub trait TypedConfigLayer: Send {
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, TypedConfigLayerError>;
    fn change_password(&self, old_password_opt: Option<&str>, new_password_opt: &str) -> Result<(), TypedConfigLayerError>;
    fn get_all(&self, db_password_opt: Option<&str>) -> Result<Vec<(String, Option<String>)>, TypedConfigLayerError>;
    fn get_string(&self, name: &str, db_password_opt: Option<&str>) -> Result<String, TypedConfigLayerError>;
    fn get_u64(&self, name: &str, db_password_opt: Option<&str>) -> Result<u64, TypedConfigLayerError>;
    fn get_bytes(&self, name: &str, db_password_opt: Option<&str>) -> Result<PlainData, TypedConfigLayerError>;
    fn transaction(&self) -> Box<dyn TransactionWrapper>;
    fn set_string(&self, name: &str, value: &str, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
    fn set_u64(&self, name: &str, value: u64, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
    fn set_bytes(&self, name: &str, value: &PlainData, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
}

struct TypedConfigLayerReal {
    delegate: Box<dyn SecureConfigLayer>,
}

impl TypedConfigLayer for TypedConfigLayerReal {
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, TypedConfigLayerError> {
        unimplemented!()
    }

    fn change_password(&self, old_password_opt: Option<&str>, new_password_opt: &str) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }

    fn get_all(&self, db_password_opt: Option<&str>) -> Result<Vec<(String, Option<String>)>, TypedConfigLayerError> {
        unimplemented!()
    }

    fn get_string(&self, name: &str, db_password_opt: Option<&str>) -> Result<String, TypedConfigLayerError> {
        unimplemented!()
    }

    fn get_u64(&self, name: &str, db_password_opt: Option<&str>) -> Result<u64, TypedConfigLayerError> {
        unimplemented!()
    }

    fn get_bytes(&self, name: &str, db_password_opt: Option<&str>) -> Result<PlainData, TypedConfigLayerError> {
        unimplemented!()
    }

    fn transaction(&self) -> Box<dyn TransactionWrapper> {
        unimplemented!()
    }

    fn set_string(&self, name: &str, value: &str, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }

    fn set_u64(&self, name: &str, value: u64, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }

    fn set_bytes(&self, name: &str, value: &PlainData, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }
}

impl TypedConfigLayerReal {
    pub fn new(dao: Box<dyn SecureConfigLayer>) -> TypedConfigLayerReal {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_config::config_dao::{ConfigDaoError, ConfigDaoRecord};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use crate::blockchain::bip39::Bip39;
    use crate::db_config::secure_config_layer::SecureConfigLayerError::DatabaseError;
    use crate::sub_lib::cryptde::PlainData;

    struct SecureConfigLayerMock {

    }

    impl SecureConfigLayer for SecureConfigLayerMock {
        fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, SecureConfigLayerError> {
            unimplemented!()
        }

        fn change_password(&self, old_password_opt: Option<&str>, new_password_opt: &str) -> Result<(), SecureConfigLayerError> {
            unimplemented!()
        }

        fn get_all(&self, db_password_opt: Option<&str>) -> Result<Vec<(String, String)>, SecureConfigLayerError> {
            unimplemented!()
        }

        fn get(&self, name: &str, db_password_opt: Option<&str>) -> Result<String, SecureConfigLayerError> {
            unimplemented!()
        }

        fn transaction(&self) -> Box<dyn TransactionWrapper> {
            unimplemented!()
        }

        fn set(&self, name: &str, value: Option<&str>, db_password_opt: Option<&str>) -> Result<(), SecureConfigLayerError> {
            unimplemented!()
        }
    }

    impl SecureConfigLayerMock {
        fn new () -> Self {
            Self {

            }
        }

        fn check_password_params (mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            unimplemented!()
        }

        fn check_password_result (self, result: Result<bool, SecureConfigLayerError>) -> Self {
            unimplemented!()
        }

        fn change_password_params (mut self, params: &Arc<Mutex<Vec<(Option<String>, String)>>>) -> Self {
            unimplemented!()
        }

        fn change_password_result (self, result: Result<(), SecureConfigLayerError>) -> Self {
            unimplemented!()
        }

        fn get_all_params (mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            unimplemented!()
        }

        fn get_all_result (self, result: Result<Vec<(String, Option<String>)>, SecureConfigLayerError>) -> Self {
            unimplemented!()
        }

        fn get_params (mut self, params: &Arc<Mutex<Vec<(String, Option<String>)>>>) -> Self {
            unimplemented!()
        }

        fn get_result (self, result: Result<String, SecureConfigLayerError>) -> Self {
            unimplemented!()
        }

        fn transaction_result (self, result: Box<dyn TransactionWrapper>) -> Self {
            unimplemented!()
        }

        fn set_params (mut self, params: &Arc<Mutex<Vec<(String, String, Option<String>)>>>) -> Self {
            unimplemented!()
        }

        fn set_result (self, result: Result<(), SecureConfigLayerError>) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn typed_config_layer_error_from_secure_config_layer_error() {
        assert_eq! (TypedConfigLayerError::from (SecureConfigLayerError::NotPresent), TypedConfigLayerError::NotPresent);
        assert_eq! (TypedConfigLayerError::from (SecureConfigLayerError::PasswordError), TypedConfigLayerError::PasswordError);
        assert_eq! (TypedConfigLayerError::from (SecureConfigLayerError::TransactionError), TypedConfigLayerError::TransactionError);
        assert_eq! (TypedConfigLayerError::from (SecureConfigLayerError::DatabaseError("booga".to_string())), TypedConfigLayerError::DatabaseError("booga".to_string()));
    }

    #[test]
    fn get_string_passes_through_to_get() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_params (&get_params_arc)
            .get_result (Ok("booga".to_string()));
        let subject = TypedConfigLayerReal::new (Box::new (scl));

        let result = subject.get_string("parameter_name", Some ("password"));

        assert_eq! (result, Ok ("booga".to_string()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq! (*get_params, vec![("parameter_name".to_string(), Some ("password".to_string()))])
    }

    /*
    #[test]
    fn get_string_complains_about_nonexistent_row() {
        let home_dir =
            ensure_node_home_directory_exists("node", "get_string_complains_about_nonexistent_row");
        let subject = ConfigDaoReal::new(
            DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
                .unwrap(),
        );
        {
            let mut db = DbInitializerReal::new()
                .initialize(&home_dir, DEFAULT_CHAIN_ID, true)
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
     */
}
