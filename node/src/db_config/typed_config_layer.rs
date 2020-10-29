// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRecord, TransactionWrapper,
};
use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::sub_lib::cryptde::PlainData;
use rand::Rng;

#[derive(Debug, PartialEq)]
pub enum TypedConfigLayerError {
    NotPresent,
    TypeError,
    PasswordError,
    TransactionError,
    DatabaseError(String),
}

impl From<SecureConfigLayerError> for TypedConfigLayerError {
    fn from(input: SecureConfigLayerError) -> Self {
        match input {
            SecureConfigLayerError::NotPresent => TypedConfigLayerError::NotPresent,
            SecureConfigLayerError::PasswordError => TypedConfigLayerError::PasswordError,
            SecureConfigLayerError::TransactionError => TypedConfigLayerError::TransactionError,
            SecureConfigLayerError::DatabaseError(msg) => TypedConfigLayerError::DatabaseError(msg),
        }
    }
}

pub trait TypedConfigLayer: Send {
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, TypedConfigLayerError>;
    fn change_password(&self, old_password_opt: Option<&str>, new_password_opt: &str) -> Result<(), TypedConfigLayerError>;
    fn get_all(&self, db_password_opt: Option<&str>) -> Result<Vec<(String, Option<String>)>, TypedConfigLayerError>;
    fn get_string(&self, name: &str, db_password_opt: Option<&str>) -> Result<Option<String>, TypedConfigLayerError>;
    fn get_u64(&self, name: &str, db_password_opt: Option<&str>) -> Result<Option<u64>, TypedConfigLayerError>;
    fn get_bytes(&self, name: &str, db_password_opt: Option<&str>) -> Result<Option<PlainData>, TypedConfigLayerError>;
    fn transaction(&self) -> Box<dyn TransactionWrapper>;
    fn set_string(&self, name: &str, value: Option<&str>, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
    fn set_u64(&self, name: &str, value: Option<u64>, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
    fn set_bytes(&self, name: &str, value: Option<&PlainData>, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
}

struct TypedConfigLayerReal {
    scl: Box<dyn SecureConfigLayer>,
}

impl TypedConfigLayer for TypedConfigLayerReal {
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, TypedConfigLayerError> {
        Ok(self.scl.check_password(db_password_opt)?)
    }

    fn change_password(
        &self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), TypedConfigLayerError> {
        Ok(self.scl.change_password(old_password_opt, new_password)?)
    }

    fn get_all(
        &self,
        db_password_opt: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, TypedConfigLayerError> {
        Ok(self.scl.get_all(db_password_opt)?)
    }

    fn get_string(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<String>, TypedConfigLayerError> {
        Ok(self.scl.get(name, db_password_opt)?)
    }

    fn get_u64(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<u64>, TypedConfigLayerError> {
        unimplemented!()
    }

    fn get_bytes(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<PlainData>, TypedConfigLayerError> {
        unimplemented!()
    }

    fn transaction(&self) -> Box<dyn TransactionWrapper> {
        self.scl.transaction()
    }

    fn set_string(
        &self,
        name: &str,
        value: Option<&str>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }

    fn set_u64(
        &self,
        name: &str,
        value: Option<u64>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }

    fn set_bytes(
        &self,
        name: &str,
        value: Option<&PlainData>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        unimplemented!()
    }
}

impl TypedConfigLayerReal {
    pub fn new(dao: Box<dyn SecureConfigLayer>) -> Self {
        Self {
            scl: dao,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::db_config::config_dao::{ConfigDaoError, ConfigDaoRecord};
    use crate::sub_lib::cryptde::PlainData;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use crate::db_config::mocks::TransactionWrapperMock;
    use crate::db_config::secure_config_layer::SCLActor;

    struct SecureConfigLayerMock {
        check_password_params: Arc<Mutex<Vec<Option<String>>>>,
        check_password_results: RefCell<Vec<Result<bool, SecureConfigLayerError>>>,
        change_password_params: Arc<Mutex<Vec<(Option<String>, String)>>>,
        change_password_results: RefCell<Vec<Result<(), SecureConfigLayerError>>>,
        get_all_params: Arc<Mutex<Vec<Option<String>>>>,
        get_all_results: RefCell<Vec<Result<Vec<(String, Option<String>)>, SecureConfigLayerError>>>,
        get_params: Arc<Mutex<Vec<(String, Option<String>)>>>,
        get_results: RefCell<Vec<Result<Option<String>, SecureConfigLayerError>>>,
        transaction_results: RefCell<Vec<Box<dyn TransactionWrapper>>>,
        set_informed_params: Arc<Mutex<Vec<(String, Option<String>, Option<String>, Box<dyn SCLActor>)>>>,
        set_informed_results: RefCell<Vec<Result<(), SecureConfigLayerError>>>,
    }

    impl SecureConfigLayer for SecureConfigLayerMock {
        fn check_password(
            &self,
            db_password_opt: Option<&str>,
        ) -> Result<bool, SecureConfigLayerError> {
            self.check_password_params.lock().unwrap().push (db_password_opt.map (|x| x.to_string()));
            self.check_password_results.borrow_mut().remove(0)
        }

        fn change_password(
            &self,
            old_password_opt: Option<&str>,
            new_password: &str,
        ) -> Result<(), SecureConfigLayerError> {
            self.change_password_params.lock().unwrap().push ((old_password_opt.map (|x| x.to_string()), new_password.to_string()));
            self.change_password_results.borrow_mut().remove(0)
        }

        fn get_all(
            &self,
            db_password_opt: Option<&str>,
        ) -> Result<Vec<(String, Option<String>)>, SecureConfigLayerError> {
            self.get_all_params.lock().unwrap().push (db_password_opt.map (|x| x.to_string()));
            self.get_all_results.borrow_mut().remove(0)
        }

        fn get(
            &self,
            name: &str,
            db_password_opt: Option<&str>,
        ) -> Result<Option<String>, SecureConfigLayerError> {
            self.get_params.lock().unwrap().push ((name.to_string(), db_password_opt.map (|x| x.to_string())));
            self.get_results.borrow_mut().remove(0)
        }

        fn transaction(&self) -> Box<dyn TransactionWrapper> {
            self.transaction_results.borrow_mut().remove(0)
        }

        fn set(
            &self,
            name: &str,
            value: Option<&str>,
            db_password_opt: Option<&str>,
        ) -> Result<(), SecureConfigLayerError> {
            unimplemented!()
        }

        fn set_informed(
            &self,
            name: &str,
            value: Option<&str>,
            db_password_opt: Option<&str>,
            act: Box<dyn SCLActor>
        ) -> Result<(), SecureConfigLayerError> {
            self.set_informed_params.lock().unwrap().push ((
                name.to_string(),
                value.map (|x| String::from (x)),
                db_password_opt.map (|x| x.to_string()),
                act
            ));
            self.set_informed_results.borrow_mut().remove(0)
        }
    }

    impl SecureConfigLayerMock {
        fn new() -> Self {
            Self {
                check_password_params: Arc::new(Mutex::new(vec![])),
                check_password_results: RefCell::new(vec![]),
                change_password_params: Arc::new(Mutex::new(vec![])),
                change_password_results: RefCell::new(vec![]),
                get_all_params: Arc::new(Mutex::new(vec![])),
                get_all_results: RefCell::new(vec![]),
                get_params: Arc::new(Mutex::new(vec![])),
                get_results: RefCell::new(vec![]),
                transaction_results: RefCell::new(vec![]),
                set_informed_params: Arc::new(Mutex::new(vec![])),
                set_informed_results: RefCell::new(vec![]),
            }
        }

        fn check_password_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            self.check_password_params = params.clone();
            self
        }

        fn check_password_result(self, result: Result<bool, SecureConfigLayerError>) -> Self {
            self.check_password_results.borrow_mut().push (result);
            self
        }

        fn change_password_params(
            mut self,
            params: &Arc<Mutex<Vec<(Option<String>, String)>>>,
        ) -> Self {
            self.change_password_params = params.clone();
            self
        }

        fn change_password_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            self.change_password_results.borrow_mut().push (result);
            self
        }

        fn get_all_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            self.get_all_params = params.clone();
            self
        }

        fn get_all_result(
            self,
            result: Result<Vec<(String, Option<String>)>, SecureConfigLayerError>,
        ) -> Self {
            self.get_all_results.borrow_mut().push (result);
            self
        }

        fn get_params(mut self, params: &Arc<Mutex<Vec<(String, Option<String>)>>>) -> Self {
            self.get_params = params.clone();
            self
        }

        fn get_result(self, result: Result<Option<String>, SecureConfigLayerError>) -> Self {
            self.get_results.borrow_mut().push (result);
            self
        }

        fn transaction_result(self, result: Box<dyn TransactionWrapper>) -> Self {
            self.transaction_results.borrow_mut().push (result);
            self
        }

        fn set_params(
            mut self,
            params: &Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>,
        ) -> Self {
            unimplemented!()
        }

        fn set_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            unimplemented!()
        }

        fn set_informed_params(
            mut self,
            params: &Arc<Mutex<Vec<(String, Option<String>, Option<String>, Box<dyn SCLActor>)>>>,
        ) -> Self {
            unimplemented!()
        }

        fn set_informed_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn typed_config_layer_error_from_secure_config_layer_error() {
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::NotPresent),
            TypedConfigLayerError::NotPresent
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::PasswordError),
            TypedConfigLayerError::PasswordError
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::TransactionError),
            TypedConfigLayerError::TransactionError
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::DatabaseError("booga".to_string())),
            TypedConfigLayerError::DatabaseError("booga".to_string())
        );
    }

    #[test]
    fn check_password_passes_through() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.check_password(Some("password"));

        assert_eq!(result, Ok(true));
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(
            *check_password_params,
            vec![Some("password".to_string())]
        )
    }

    #[test]
    fn change_password_passes_through() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .change_password_params(&change_password_params_arc)
            .change_password_result(Err(SecureConfigLayerError::TransactionError));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.change_password(None, "password");

        assert_eq!(result, Err(TypedConfigLayerError::TransactionError));
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(
            *change_password_params,
            vec![(None, "password".to_string())]
        )
    }

    #[test]
    fn get_all_passes_through() {
        let get_all_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_all_params(&get_all_params_arc)
            .get_all_result(Err(SecureConfigLayerError::PasswordError));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_all(Some ("password"));

        assert_eq!(result, Err(TypedConfigLayerError::PasswordError));
        let get_all_params = get_all_params_arc.lock().unwrap();
        assert_eq!(
            *get_all_params,
            vec![Some ("password".to_string())]
        )
    }

    #[test]
    fn get_string_passes_through_to_get() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(Some ("booga".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_string("parameter_name", Some("password"));

        assert_eq!(result, Ok(Some("booga".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![("parameter_name".to_string(), Some("password".to_string()))]
        )
    }

    #[test]
    fn transaction_passes_through() {
        let transaction = TransactionWrapperMock::new();
        let committed_arc = transaction.committed_arc();
        let scl = SecureConfigLayerMock::new()
            .transaction_result(Box::new(transaction));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let mut result = subject.transaction();

        {
            let committed = committed_arc.lock().unwrap();
            assert_eq! (*committed, None);
        }
        result.commit();
        {
            let committed = committed_arc.lock().unwrap();
            assert_eq! (*committed, Some(true));
        }
    }

    /*
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
