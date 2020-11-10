// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::db_config::config_dao::{
    ConfigDao, ConfigDaoError, ConfigDaoRecord,
};
use rand::Rng;
use crate::database::connection_wrapper::TransactionWrapper;

pub const EXAMPLE_ENCRYPTED: &str = "example_encrypted";

#[derive(Debug, PartialEq)]
pub enum SecureConfigLayerError {
    NotPresent,
    PasswordError,
    TransactionError,
    DatabaseError(String),
}

impl From<ConfigDaoError> for SecureConfigLayerError {
    fn from(input: ConfigDaoError) -> Self {
        match input {
            ConfigDaoError::NotPresent => SecureConfigLayerError::NotPresent,
            ConfigDaoError::TransactionError => SecureConfigLayerError::TransactionError,
            ConfigDaoError::DatabaseError(msg) => SecureConfigLayerError::DatabaseError(msg),
        }
    }
}

pub trait SCLActor: Send {
    fn act (&self, record: &ConfigDaoRecord, new_value: Option<&str>) -> Result<Option<String>, SecureConfigLayerError>;
}

pub trait SecureConfigLayer {
    fn check_password(&self, db_password_opt: Option<&str>)
        -> Result<bool, SecureConfigLayerError>;
    fn change_password(
        &mut self,
        old_password_opt: Option<&str>,
        new_password_opt: &str,
    ) -> Result<(), SecureConfigLayerError>;
    fn get_all(
        &self,
        db_password_opt: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, SecureConfigLayerError>;
    fn get(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<String>, SecureConfigLayerError>;
    fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a>;
    fn set(
        &self,
        name: &str,
        value_opt: Option<&str>,
        db_password_opt: Option<&str>,
    ) -> Result<(), SecureConfigLayerError>;
    fn set_informed(
        &self,
        name: &str,
        value_opt: Option<&str>,
        db_password_opt: Option<&str>,
        act: Box<dyn SCLActor>,
    ) -> Result<(), SecureConfigLayerError>;
}

struct SecureConfigLayerReal {
    dao: Box<dyn ConfigDao>,
}

impl SecureConfigLayer for SecureConfigLayerReal {
    fn check_password(
        &self,
        db_password_opt: Option<&str>,
    ) -> Result<bool, SecureConfigLayerError> {
        match self.dao.get(EXAMPLE_ENCRYPTED) {
            Ok(example_record) => self.password_matches_example(db_password_opt, example_record),
            Err(e) => Err(SecureConfigLayerError::from(e)),
        }
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), SecureConfigLayerError> {
        if !self.check_password(old_password_opt)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        // let mut transaction = self.dao.transaction();
        self.reencrypt_records(old_password_opt, new_password)?;
        self.install_example_for_password(new_password)?;
        // transaction.commit();
        Ok(())
    }

    fn get_all(
        &self,
        db_password_opt: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, SecureConfigLayerError> {
        if !self.check_password(db_password_opt)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        let init: Result<Vec<(String, Option<String>)>, SecureConfigLayerError> = Ok(vec![]);
        let records = self.dao.get_all()?;
        records
            .into_iter()
            .filter(|record| record.name != EXAMPLE_ENCRYPTED)
            .map(|record| {
                let record_name = record.name.clone();
                match Self::reduce_record(record, db_password_opt) {
                    Ok(decrypted_value_opt) => Ok((record_name, decrypted_value_opt)),
                    Err(e) => Err(e),
                }
            })
            .fold(init, |so_far_result, pair_result| {
                match (so_far_result, pair_result) {
                    (Err(e), _) => Err(e),
                    (Ok(so_far), Ok(pair)) => Ok(append(so_far, pair)),
                    (Ok(_), Err(e)) => Err(e),
                }
            })
    }

    fn get(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        if !self.check_password(db_password_opt)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        Self::reduce_record(self.dao.get(name)?, db_password_opt)
    }

    fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a> {
        unimplemented!()
    }

    fn set(
        &self,
        name: &str,
        value_opt: Option<&str>,
        db_password_opt: Option<&str>,
    ) -> Result<(), SecureConfigLayerError> {
        struct NeutralActor {}
        impl SCLActor for NeutralActor {
            fn act(&self, _: &ConfigDaoRecord, new_value_opt: Option<&str>) -> Result<Option<String>, SecureConfigLayerError> {
                Ok(new_value_opt.map(|x| x.to_string()))
            }
        }
        self.set_informed (name, value_opt, db_password_opt, Box::new (NeutralActor{}))
    }

    fn set_informed(
        &self,
        name: &str,
        value_opt: Option<&str>,
        db_password_opt: Option<&str>,
        act: Box<dyn SCLActor>,
    ) -> Result<(), SecureConfigLayerError> {
        if !self.check_password(db_password_opt)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        let old_record = self.dao.get(name)?;
        let new_value_opt: Option<String> = match (old_record.encrypted, act.act(&old_record, value_opt)?, db_password_opt)
        {
            (_, None, _) => None,
            (false, Some(value), _) => Some(value.to_string()),
            (true, Some(_), None) => return Err(SecureConfigLayerError::PasswordError),
            (true, Some(value), Some(db_password)) => Some(
                Bip39::encrypt_bytes(&value.as_bytes(), db_password).expect("Encryption failed"),
            ),
        };
        let _ = match new_value_opt {
            None => self.dao.set(name, None),
            Some(new_value) => self.dao.set(name, Some(&new_value)),
        };
        Ok(())
    }
}

impl SecureConfigLayerReal {
    pub fn new(dao: Box<dyn ConfigDao>) -> SecureConfigLayerReal {
        Self { dao }
    }

    fn password_matches_example(
        &self,
        db_password_opt: Option<&str>,
        example_record: ConfigDaoRecord,
    ) -> Result<bool, SecureConfigLayerError> {
        if !example_record.encrypted {
            return Err(SecureConfigLayerError::DatabaseError(format!(
                "Password example value '{}' is not encrypted",
                EXAMPLE_ENCRYPTED
            )));
        }
        match (db_password_opt, example_record.value_opt) {
            (None, None) => Ok(true),
            (None, Some(_)) => Ok(false),
            (Some(_), None) => Ok(false),
            (Some(db_password), Some(encrypted_example)) => {
                match Bip39::decrypt_bytes(&encrypted_example, db_password) {
                    Ok(_) => Ok(true),
                    Err(Bip39Error::DecryptionFailure(_)) => Ok(false),
                    Err(e) => Err(SecureConfigLayerError::DatabaseError(format!(
                        "Password example value '{}' is corrupted: {:?}",
                        EXAMPLE_ENCRYPTED, e
                    ))),
                }
            }
        }
    }

    fn reencrypt_records(
        &self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), SecureConfigLayerError> {
        let existing_records = self.dao.get_all()?;
        let init: Result<Vec<ConfigDaoRecord>, SecureConfigLayerError> = Ok(vec![]);
        match existing_records
            .into_iter()
            .filter(|record| record.name != EXAMPLE_ENCRYPTED)
            .fold(init, |so_far, record| match so_far {
                Err(e) => Err(e),
                Ok(records) => match Self::reencrypt_record(record, old_password_opt, new_password)
                {
                    Err(e) => Err(e),
                    Ok(new_record) => Ok(append(records, new_record)),
                },
            }) {
            Err(e) => Err(e),
            Ok(reencrypted_records) => self.update_records(reencrypted_records),
        }
    }

    fn update_records(
        &self,
        reencrypted_records: Vec<ConfigDaoRecord>,
    ) -> Result<(), SecureConfigLayerError> {
        let init: Result<(), SecureConfigLayerError> = Ok(());
        reencrypted_records.into_iter()
            .fold(init, |so_far, record| {
                if so_far.is_ok() {
                    let setter = |value_opt: Option<&str>| self.dao.set(&record.name, value_opt);
                    let result = match &record.value_opt {
                        Some (value) => setter (Some (value)),
                        None => setter (None),
                    };
                    result.map_err (|e| SecureConfigLayerError::DatabaseError(format!("Aborting password change: configuration value '{}' could not be set: {:?}", record.name, e)))
                }
                else {
                    so_far
                }
            })
    }

    fn reencrypt_record(
        old_record: ConfigDaoRecord,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<ConfigDaoRecord, SecureConfigLayerError> {
        match (old_record.encrypted, &old_record.value_opt, old_password_opt) {
            (false, _, _) => Ok(old_record),
            (true, None, _) => Ok(old_record),
            (true, Some (_), None) => Err(SecureConfigLayerError::DatabaseError(format!("Aborting password change: configuration value '{}' is encrypted, but database has no password", old_record.name))),
            (true, Some (value), Some(old_password)) => {
                let decrypted_value = match Bip39::decrypt_bytes(value, old_password) {
                    Ok(plain_data) => plain_data,
                    Err(_) => {
                        return Err(SecureConfigLayerError::DatabaseError(format!("Aborting password change due to database corruption: configuration value '{}' cannot be decrypted", old_record.name)));
                    }
                };
                let reencrypted_value = Bip39::encrypt_bytes(&decrypted_value, new_password).expect ("Encryption failed");
                Ok(ConfigDaoRecord::new (&old_record.name, Some (&reencrypted_value), old_record.encrypted))
            },
        }
    }

    fn install_example_for_password(
        &self,
        new_password: &str,
    ) -> Result<(), SecureConfigLayerError> {
        let example_data: Vec<u8> = [0..32]
            .iter()
            .map(|_| rand::thread_rng().gen::<u8>())
            .collect();
        let example_encrypted =
            Bip39::encrypt_bytes(&example_data, new_password).expect("Encryption failed");
        self.dao
            .set(EXAMPLE_ENCRYPTED, Some(&example_encrypted))
            .map_err(|e| SecureConfigLayerError::from(e))
    }

    fn reduce_record(
        record: ConfigDaoRecord,
        db_password_opt: Option<&str>,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        match (record.encrypted, record.value_opt, db_password_opt) {
            (false, value_opt, _) => Ok(value_opt),
            (true, None, _) => Ok(None),
            (true, Some(_), None) => Err(SecureConfigLayerError::DatabaseError(format!(
                "Database without password contains encrypted value for '{}'",
                record.name
            ))),
            (true, Some(value), Some(db_password)) => {
                match Bip39::decrypt_bytes(&value, db_password) {
                    Ok(plain_data) => match String::from_utf8(plain_data.into()) {
                        Ok(string) => Ok(Some(string)),
                        Err(_) => Err(SecureConfigLayerError::DatabaseError(format!(
                            "Database contains a non-UTF-8 value for '{}'",
                            record.name
                        ))),
                    },
                    Err(_) => Err(SecureConfigLayerError::DatabaseError(format!(
                        "Password for '{}' does not match database password",
                        record.name
                    ))),
                }
            }
        }
    }
}

fn append<T: Clone>(records: Vec<T>, record: T) -> Vec<T> {
    let mut result = records.clone();
    result.push(record);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::db_config::config_dao::{ConfigDaoError, ConfigDaoRecord, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoWrite};
    use crate::db_config::mocks::TransactionWrapperMock;
    use crate::db_config::secure_config_layer::SecureConfigLayerError::DatabaseError;
    use crate::sub_lib::cryptde::PlainData;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    struct ConfigDaoMock {
        get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
        get_params: Arc<Mutex<Vec<String>>>,
        get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
        start_transaction_results: RefCell<Vec<ConfigDaoWriteableMock>>,
    }

    impl ConfigDaoRead for ConfigDaoMock {
        fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
            self.get_all_results.borrow_mut().remove(0)
        }

        fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
            self.get_params.lock().unwrap().push(name.to_string());
            self.get_results.borrow_mut().remove(0)
        }
    }

    impl ConfigDao for ConfigDaoMock {

        fn start_transaction<'a>(&mut self) -> Result<Box<dyn ConfigDaoReadWrite<'a> + 'a>, ConfigDaoError> {
            unimplemented!()
        }
    }

    impl ConfigDaoMock {
        fn new() -> Self {
            Self {
                get_all_results: RefCell::new(vec![]),
                get_params: Arc::new(Mutex::new(vec![])),
                get_results: RefCell::new(vec![]),
                start_transaction_results: RefCell::new(vec![]),
            }
        }

        fn get_all_result(self, result: Result<Vec<ConfigDaoRecord>, ConfigDaoError>) -> Self {
            self.get_all_results.borrow_mut().push(result);
            self
        }

        fn get_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
            self.get_params = params.clone();
            self
        }

        fn get_result(self, result: Result<ConfigDaoRecord, ConfigDaoError>) -> Self {
            self.get_results.borrow_mut().push(result);
            self
        }

        fn start_transaction_result(self, result: ConfigDaoWriteableMock) -> Self {
            self.start_transaction_results.borrow_mut().push(result);
            self
        }
    }

    struct ConfigDaoWriteableMock {
        get_all_results: RefCell<Vec<Result<Vec<ConfigDaoRecord>, ConfigDaoError>>>,
        get_params: Arc<Mutex<Vec<String>>>,
        get_results: RefCell<Vec<Result<ConfigDaoRecord, ConfigDaoError>>>,
        set_params: Arc<Mutex<Vec<(String, Option<String>)>>>,
        set_results: RefCell<Vec<Result<(), ConfigDaoError>>>,
        rollback_results: RefCell<Vec<()>>,
    }

    impl ConfigDaoRead for ConfigDaoWriteableMock {
        fn get_all(&self) -> Result<Vec<ConfigDaoRecord>, ConfigDaoError> {
            self.get_all_results.borrow_mut().remove(0)
        }

        fn get(&self, name: &str) -> Result<ConfigDaoRecord, ConfigDaoError> {
            self.get_params.lock().unwrap().push(name.to_string());
            self.get_results.borrow_mut().remove(0)
        }
    }

    impl ConfigDaoWrite for ConfigDaoWriteableMock {
        fn set(&self, name: &str, value: Option<&str>) -> Result<(), ConfigDaoError> {
            self.set_params
                .lock()
                .unwrap()
                .push((name.to_string(), value.map(|x| x.to_string())));
            self.set_results.borrow_mut().remove(0)
        }

        fn rollback(&mut self) -> Result<(), ConfigDaoError> {
            unimplemented!()
        }
    }

    impl ConfigDaoWriteableMock {
        fn new() -> Self {
            Self {
                get_all_results: RefCell::new(vec![]),
                get_params: Arc::new(Mutex::new(vec![])),
                get_results: RefCell::new(vec![]),
                set_params: Arc::new(Mutex::new(vec![])),
                set_results: RefCell::new(vec![]),
                rollback_results: RefCell::new(vec![]),
            }
        }

        fn get_all_result(self, result: Result<Vec<ConfigDaoRecord>, ConfigDaoError>) -> Self {
            self.get_all_results.borrow_mut().push(result);
            self
        }

        fn get_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
            self.get_params = params.clone();
            self
        }

        fn get_result(self, result: Result<ConfigDaoRecord, ConfigDaoError>) -> Self {
            self.get_results.borrow_mut().push(result);
            self
        }

        fn set_params(mut self, params: &Arc<Mutex<Vec<(String, Option<String>)>>>) -> Self {
            self.set_params = params.clone();
            self
        }

        fn set_result(self, result: Result<(), ConfigDaoError>) -> Self {
            self.set_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn secure_config_layer_error_from_config_dao_error() {
        assert_eq!(
            SecureConfigLayerError::from(ConfigDaoError::NotPresent),
            SecureConfigLayerError::NotPresent
        );
        assert_eq!(
            SecureConfigLayerError::from(ConfigDaoError::TransactionError),
            SecureConfigLayerError::TransactionError
        );
        assert_eq!(
            SecureConfigLayerError::from(ConfigDaoError::DatabaseError("booga".to_string())),
            SecureConfigLayerError::DatabaseError("booga".to_string())
        );
    }

    #[test]
    fn check_password_works_when_no_password_is_supplied_and_no_password_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(None);

        assert_eq!(result, Ok(true));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()])
    }

    #[test]
    fn check_password_works_when_a_password_is_supplied_but_no_password_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("password"));

        assert_eq!(result, Ok(false));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()])
    }

    #[test]
    fn check_password_works_when_no_password_is_supplied_but_a_password_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(None);

        assert_eq!(result, Ok(false));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()])
    }

    #[test]
    fn check_password_works_when_passwords_match() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("password"));

        assert_eq!(result, Ok(true));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn check_password_works_when_passwords_dont_match() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("bad password"));

        assert_eq!(result, Ok(false));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn check_password_fails_when_example_record_is_present_and_unencrypted() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some("booga"),
                false,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("bad password"));

        assert_eq!(
            result,
            Err(DatabaseError(format!(
                "Password example value '{}' is not encrypted",
                EXAMPLE_ENCRYPTED
            )))
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn check_password_fails_when_example_record_is_present_but_corrupt() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let bad_encrypted_example = "Aside from that, Mrs. Lincoln, how was the play?";
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(bad_encrypted_example),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("password"));

        assert_eq! (result, Err(DatabaseError(format!("Password example value '{}' is corrupted: ConversionError(\"Invalid character \\'s\\' at position 1\")", EXAMPLE_ENCRYPTED))));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn check_password_passes_on_unexpected_database_error() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Err(ConfigDaoError::DatabaseError("booga".to_string())));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.check_password(Some("irrelevant"));

        assert_eq!(result, Err(DatabaseError("booga".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn change_password_works_when_no_password_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction = TransactionWrapperMock::new();
        let committed_arc = transaction.committed_arc();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_params(&get_params_arc)
            .start_transaction_result(transaction)
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true),
                ConfigDaoRecord::new("unencrypted_value_key", Some("unencrypted_value"), false),
                ConfigDaoRecord::new("encrypted_value_key", None, true),
                ConfigDaoRecord::new("missing_value_key", None, false),
            ]))
            .get_result(Ok(ConfigDaoRecord::new(
                "unencrypted_value_key",
                Some("unencrypted_value"),
                false,
            )))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .set_result(Ok(()))
            .set_result(Ok(()))
            .set_result(Ok(()));
        let mut subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.change_password(None, "password");

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED]);
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(set_params.len(), 4);
        assert_eq!(
            set_params[0],
            (
                "unencrypted_value_key".to_string(),
                Some("unencrypted_value".to_string())
            )
        );
        assert_eq!(set_params[1], ("encrypted_value_key".to_string(), None));
        assert_eq!(set_params[2], ("missing_value_key".to_string(), None));
        assert_eq!(set_params[3].0, EXAMPLE_ENCRYPTED.to_string());
        let encrypted_example = set_params[3].1.clone();
        match Bip39::decrypt_bytes(&encrypted_example.unwrap(), "password") {
            Ok(_) => (),
            x => panic!("Expected Ok(_), got {:?}", x),
        };
        let committed = committed_arc.lock().unwrap();
        assert_eq!(*committed, Some(true))
    }

    #[test]
    fn change_password_works_when_password_exists_and_old_password_matches() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let transaction = TransactionWrapperMock::new();
        let committed_arc = transaction.committed_arc();
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.".as_bytes();
        let old_encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "old_password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .start_transaction_result(transaction)
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, Some(&encrypted_example), true),
                ConfigDaoRecord::new("unencrypted_value_key", Some("unencrypted_value"), false),
                ConfigDaoRecord::new("encrypted_value_key", Some(&old_encrypted_value), true),
                ConfigDaoRecord::new("missing_encrypted_key", None, true),
                ConfigDaoRecord::new("missing_unencrypted_key", None, false),
            ]))
            .get_result(Ok(ConfigDaoRecord::new(
                "unencrypted_value_key",
                Some("unencrypted_value"),
                false,
            )))
            .set_params(&set_params_arc)
            .set_result(Ok(()))
            .set_result(Ok(()))
            .set_result(Ok(()))
            .set_result(Ok(()))
            .set_result(Ok(()));
        let mut subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.change_password(Some("old_password"), "new_password");

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED]);
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(set_params.len(), 5);
        assert_eq!(
            set_params[0],
            (
                "unencrypted_value_key".to_string(),
                Some("unencrypted_value".to_string())
            )
        );
        assert_eq!(set_params[1].0, "encrypted_value_key".to_string());
        assert_eq!(
            Bip39::decrypt_bytes(&set_params[1].1.as_ref().unwrap(), "new_password").unwrap(),
            PlainData::new(unencrypted_value)
        );
        assert_eq!(set_params[2], ("missing_encrypted_key".to_string(), None));
        assert_eq!(set_params[3], ("missing_unencrypted_key".to_string(), None));
        assert_eq!(set_params[4].0, EXAMPLE_ENCRYPTED.to_string());
        let _ = Bip39::decrypt_bytes(&set_params[4].1.as_ref().unwrap(), "new_password").unwrap();
        let committed = committed_arc.lock().unwrap();
        assert_eq!(*committed, Some(true))
    }

    #[test]
    fn change_password_works_when_password_exists_and_old_password_doesnt_match() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(&encrypted_example),
            true,
        )));
        let mut subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.change_password(Some("bad_password"), "new_password");

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn reencrypt_records_balks_when_a_value_is_incorrectly_encrypted() {
        let unencrypted_value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "bad_password").unwrap();
        let dao = ConfigDaoMock::new().get_all_result(Ok(vec![ConfigDaoRecord::new(
            "badly_encrypted",
            Some(&encrypted_value),
            true,
        )]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.reencrypt_records(Some("old_password"), "new_password");

        assert_eq! (result, Err(SecureConfigLayerError::DatabaseError("Aborting password change due to database corruption: configuration value 'badly_encrypted' cannot be decrypted".to_string())))
    }

    #[test]
    fn reencrypt_records_balks_when_a_value_cant_be_set() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.";
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "old_password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_all_result(Ok(vec![ConfigDaoRecord::new(
                "encrypted_value",
                Some(&encrypted_value),
                true,
            )]))
            .get_result(Ok(ConfigDaoRecord::new(
                "unencrypted_value_key",
                Some("unencrypted_value"),
                false,
            )))
            .set_result(Err(ConfigDaoError::DatabaseError("booga".to_string())))
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.reencrypt_records(Some("old_password"), "new_password");

        assert_eq! (result, Err(SecureConfigLayerError::DatabaseError("Aborting password change: configuration value 'encrypted_value' could not be set: DatabaseError(\"booga\")".to_string())))
    }

    #[test]
    fn reencrypt_record_balks_when_database_has_no_password_but_value_is_encrypted_anyway() {
        let record = ConfigDaoRecord::new("name", Some("value"), true);
        let old_password_opt = None;
        let new_password = "irrelevant";

        let result =
            SecureConfigLayerReal::reencrypt_record(record, old_password_opt, new_password);

        assert_eq! (result, Err(SecureConfigLayerError::DatabaseError("Aborting password change: configuration value 'name' is encrypted, but database has no password".to_string())))
    }

    #[test]
    fn get_all_handles_no_database_password() {
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true),
                ConfigDaoRecord::new("unencrypted_value_key", Some("unencrypted_value"), false),
                ConfigDaoRecord::new("encrypted_value_key", None, true),
                ConfigDaoRecord::new("missing_value_key", None, false),
            ]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(None);

        assert_eq!(
            result,
            Ok(vec![
                (
                    "unencrypted_value_key".to_string(),
                    Some("unencrypted_value".to_string())
                ),
                ("encrypted_value_key".to_string(), None),
                ("missing_value_key".to_string(), None),
            ])
        );
    }

    #[test]
    fn get_all_handles_matching_database_password() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.".to_string();
        let encrypted_value =
            Bip39::encrypt_bytes(&unencrypted_value.clone().into_bytes(), "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, Some(&encrypted_value), true),
                ConfigDaoRecord::new("unencrypted_value_key", Some("unencrypted_value"), false),
                ConfigDaoRecord::new("encrypted_value_key", Some(&encrypted_value), true),
                ConfigDaoRecord::new("missing_value_key", None, false),
                ConfigDaoRecord::new("missing_encrypted_key", None, true),
            ]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(Some("password"));

        assert_eq!(
            result,
            Ok(vec![
                (
                    "unencrypted_value_key".to_string(),
                    Some("unencrypted_value".to_string())
                ),
                ("encrypted_value_key".to_string(), Some(unencrypted_value)),
                ("missing_value_key".to_string(), None),
                ("missing_encrypted_key".to_string(), None),
            ])
        );
    }

    #[test]
    fn get_all_handles_mismatched_database_password() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(&encrypted_example),
            true,
        )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(Some("bad_password"));

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn get_all_complains_about_encrypted_existing_value_in_database_with_no_password() {
        let unencrypted_value = "These are the times that try men's souls.".to_string();
        let encrypted_value =
            Bip39::encrypt_bytes(&unencrypted_value.clone().into_bytes(), "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true),
                ConfigDaoRecord::new("encrypted_value_key", Some(&encrypted_value), true),
            ]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(None);

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Database without password contains encrypted value for 'encrypted_value_key'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn get_all_complains_about_badly_encrypted_value() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.".to_string();
        let encrypted_value =
            Bip39::encrypt_bytes(&unencrypted_value.clone().into_bytes(), "bad_password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, Some(&encrypted_example), true),
                ConfigDaoRecord::new("encrypted_value_key", Some(&encrypted_value), true),
            ]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(Some("password"));

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Password for 'encrypted_value_key' does not match database password".to_string()
            ))
        );
    }

    #[test]
    fn get_all_complains_about_encrypted_non_utf8_string() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        // UTF-8 doesn't tolerate 192 followed by 193
        let unencrypted_value: &[u8] = &[32, 32, 192, 193, 32, 32];
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_all_result(Ok(vec![
                ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, Some(&encrypted_example), true),
                ConfigDaoRecord::new("encrypted_value_key", Some(&encrypted_value), true),
            ]));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get_all(Some("password"));

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Database contains a non-UTF-8 value for 'encrypted_value_key'".to_string()
            ))
        );
    }

    #[test]
    fn get_works_when_database_is_unencrypted_value_is_unencrypted() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some("attribute_value"),
                false,
            )));

        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", None);

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn get_works_when_database_is_unencrypted_value_is_encrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true)));

        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", None);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn get_works_when_database_is_encrypted_value_is_unencrypted() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some("attribute_value"),
                false,
            )));

        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", Some("password"));

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn get_works_when_database_is_encrypted_value_is_encrypted() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let value = "These are the times that try men's souls.";
        let encrypted_value = Bip39::encrypt_bytes(&value, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&encrypted_value),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", Some("password"));

        assert_eq!(
            result,
            Ok(Some(
                "These are the times that try men's souls.".to_string()
            ))
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn get_objects_if_value_is_encrypted_and_present_but_password_is_not_supplied() {
        let value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&value, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&encrypted_value),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", None);

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Database without password contains encrypted value for 'attribute_name'"
                    .to_string()
            ))
        );
    }

    #[test]
    fn get_objects_if_password_is_wrong() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&value, "bad_password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&encrypted_value),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", Some("password"));

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Password for 'attribute_name' does not match database password".to_string()
            ))
        );
    }

    #[test]
    fn get_objects_if_decrypted_string_violates_utf8() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        // UTF-8 doesn't tolerate 192 followed by 193
        let unencrypted_value: &[u8] = &[32, 32, 192, 193, 32, 32];
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&encrypted_value),
                true,
            )));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", Some("password"));

        assert_eq!(
            result,
            Err(SecureConfigLayerError::DatabaseError(
                "Database contains a non-UTF-8 value for 'attribute_name'".to_string()
            ))
        );
    }

    #[test]
    fn get_objects_if_value_is_unrecognized() {
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Err(ConfigDaoError::NotPresent));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("unrecognized_name", None);

        assert_eq!(result, Err(SecureConfigLayerError::NotPresent));
    }

    #[test]
    fn get_objects_if_passwords_dont_match() {
        let dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            None,
            true,
        )));

        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.get("attribute_name", Some("password"));

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn transaction_delegates_to_dao() {
        let transaction = TransactionWrapperMock::new();
        let committed_arc = transaction.committed_arc();
        let dao = ConfigDaoMock::new().start_transaction_result(transaction);
        let mut subject = SecureConfigLayerReal::new(Box::new(dao));

        let mut result = subject.transaction();

        {
            let committed = committed_arc.lock().unwrap();
            assert_eq!(*committed, None);
        }
        result.commit();
        {
            let committed = committed_arc.lock().unwrap();
            assert_eq!(*committed, Some(true));
        }
    }

    #[test]
    fn set_works_when_database_is_unencrypted_and_value_is_unencrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", None, None);

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params, vec![("attribute_name".to_string(), None)])
    }

    #[test]
    fn set_works_when_database_is_unencrypted_and_value_is_unencrypted_and_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", Some("attribute_value"), None);

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "attribute_name".to_string(),
                Some("attribute_value".to_string())
            )]
        )
    }

    #[test]
    fn set_works_when_database_is_unencrypted_and_value_is_encrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true)))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", None, None);

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params, vec![("attribute_name".to_string(), None)])
    }

    #[test]
    fn set_works_when_database_is_encrypted_and_value_is_unencrypted_and_absent() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false)))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", None, Some("password"));

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params, vec![("attribute_name".to_string(), None)])
    }

    #[test]
    fn set_works_when_database_is_encrypted_and_value_is_unencrypted_and_present() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some("attribute_value"),
                false,
            )))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set(
            "attribute_name",
            Some("new_attribute_value"),
            Some("password"),
        );

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![(
                "attribute_name".to_string(),
                Some("new_attribute_value".to_string())
            )]
        )
    }

    #[test]
    fn set_works_when_database_is_encrypted_and_value_is_encrypted_and_absent() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true)))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", None, Some("password"));

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params[0].0, "attribute_name".to_string());
        assert_eq!(set_params[0].1, None);
        assert_eq!(set_params.len(), 1);
    }

    #[test]
    fn set_works_when_database_is_encrypted_and_value_is_encrypted_and_present() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let old_encrypted_value =
            Bip39::encrypt_bytes(&b"old_attribute_value", "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(
                EXAMPLE_ENCRYPTED,
                Some(&encrypted_example),
                true,
            )))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&old_encrypted_value),
                true,
            )))
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set(
            "attribute_name",
            Some("new_attribute_value"),
            Some("password"),
        );

        assert_eq!(result, Ok(()));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(*set_params[0].0, "attribute_name".to_string());
        assert_eq!(
            String::from_utf8(
                Bip39::decrypt_bytes((*set_params)[0].1.as_ref().unwrap(), "password")
                    .unwrap()
                    .into()
            )
            .unwrap(),
            "new_attribute_value".to_string()
        );
        assert_eq!(set_params.len(), 1);
    }

    #[test]
    fn set_works_when_database_is_unencrypted_and_value_is_encrypted_and_present_without_password()
    {
        let old_encrypted_value =
            Bip39::encrypt_bytes(&b"old_attribute_value", "password").unwrap();
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new(
                "attribute_name",
                Some(&old_encrypted_value),
                true,
            )))
            .set_result(Ok(()));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", Some("new_attribute_value"), None);

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn set_works_when_password_doesnt_match() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false)));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", Some("attribute_value"), Some("password"));

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn set_works_when_database_is_unencrypted_and_value_is_encrypted_and_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true)));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", Some("attribute_value"), Some("password"));

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn set_works_when_configuration_item_is_unknown() {
        let dao = ConfigDaoMock::new()
            .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
            .get_result(Err(ConfigDaoError::NotPresent));
        let subject = SecureConfigLayerReal::new(Box::new(dao));

        let result = subject.set("attribute_name", None, None);

        assert_eq!(result, Err(SecureConfigLayerError::NotPresent));
    }
}
