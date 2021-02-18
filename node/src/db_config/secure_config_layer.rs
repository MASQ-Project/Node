// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::db_config::config_dao::{
    ConfigDaoError, ConfigDaoRead, ConfigDaoReadWrite, ConfigDaoRecord,
};
use rand::Rng;

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

pub struct SecureConfigLayer {}

impl Default for SecureConfigLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureConfigLayer {
    pub fn new() -> SecureConfigLayer {
        Self {}
    }

    #[allow(clippy::borrowed_box)]
    pub fn check_password<T: ConfigDaoRead + ?Sized>(
        &self,
        db_password_opt: Option<String>,
        dao: &Box<T>,
    ) -> Result<bool, SecureConfigLayerError> {
        match dao.get(EXAMPLE_ENCRYPTED) {
            Ok(example_record) => self.password_matches_example(db_password_opt, example_record),
            Err(e) => Err(SecureConfigLayerError::from(e)),
        }
    }

    pub fn change_password<'b, T: ConfigDaoReadWrite + ?Sized>(
        &self,
        old_password_opt: Option<String>,
        new_password: &str,
        dao: &'b mut Box<T>,
    ) -> Result<(), SecureConfigLayerError> {
        if !self.check_password(old_password_opt.clone(), dao)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        self.reencrypt_records(old_password_opt, new_password, dao)?;
        self.install_example_for_password(new_password, dao)?;
        Ok(())
    }

    #[allow(clippy::borrowed_box)]
    pub fn encrypt<T: ConfigDaoRead + ?Sized>(
        &self,
        name: &str,
        plain_value_opt: Option<String>,
        password_opt: Option<String>,
        dao: &Box<T>,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        if !self.check_password(password_opt.clone(), dao)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        let record = dao.get(name)?;
        match (record.encrypted, plain_value_opt, password_opt) {
            (false, value_opt, _) => Ok(value_opt),
            (true, Some(plain_value), Some(password)) => {
                match Bip39::encrypt_bytes(&plain_value.as_bytes(), &password) {
                    Err(_) => panic!("Encryption of '{}' failed", plain_value),
                    Ok(crypt_data) => Ok(Some(crypt_data)),
                }
            }
            (true, Some(_), None) => Err(SecureConfigLayerError::PasswordError),
            (true, None, _) => Ok(None),
        }
    }

    #[allow(clippy::borrowed_box)]
    pub fn decrypt<T: ConfigDaoRead + ?Sized>(
        &self,
        record: ConfigDaoRecord,
        password_opt: Option<String>,
        dao: &Box<T>,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        if !self.check_password(password_opt.clone(), dao)? {
            return Err(SecureConfigLayerError::PasswordError);
        }
        match (record.encrypted, record.value_opt, password_opt) {
            (false, value_opt, _) => Ok(value_opt),
            (true, Some(value), Some(password)) => match Bip39::decrypt_bytes(&value, &password) {
                Err(_) => Err(SecureConfigLayerError::PasswordError),
                Ok(plain_data) => match String::from_utf8(plain_data.into()) {
                    Err(_) => panic!(
                        "Database is corrupt: contains a non-UTF-8 value for '{}'",
                        record.name
                    ),
                    Ok(plain_text) => Ok(Some(plain_text)),
                },
            },
            (true, Some(_), None) => Err(SecureConfigLayerError::PasswordError),
            (true, None, _) => Ok(None),
        }
    }

    fn password_matches_example(
        &self,
        db_password_opt: Option<String>,
        example_record: ConfigDaoRecord,
    ) -> Result<bool, SecureConfigLayerError> {
        if !example_record.encrypted {
            panic!("Database is corrupt: Password example value is not encrypted");
        }
        match (db_password_opt, example_record.value_opt) {
            (None, None) => Ok(true),
            (None, Some(_)) => Ok(false),
            (Some(_), None) => Ok(false),
            (Some(db_password), Some(encrypted_example)) => {
                match Bip39::decrypt_bytes(&encrypted_example, &db_password) {
                    Ok(_) => Ok(true),
                    Err(Bip39Error::DecryptionFailure(_)) => Ok(false),
                    Err(e) => panic!(
                        "Database is corrupt: password example value can't be read: {:?}",
                        e
                    ),
                }
            }
        }
    }

    #[allow(clippy::borrowed_box)]
    fn reencrypt_records<T: ConfigDaoReadWrite + ?Sized>(
        &self,
        old_password_opt: Option<String>,
        new_password: &str,
        dao: &Box<T>,
    ) -> Result<(), SecureConfigLayerError> {
        let existing_records = dao.get_all()?;
        let init: Result<Vec<ConfigDaoRecord>, SecureConfigLayerError> = Ok(vec![]);
        match existing_records
            .into_iter()
            .filter(|record| record.name != EXAMPLE_ENCRYPTED)
            .fold(init, |so_far, record| match so_far {
                Err(e) => Err(e),
                Ok(records) => {
                    match Self::reencrypt_record(record, old_password_opt.clone(), new_password) {
                        Err(e) => Err(e),
                        Ok(new_record) => Ok(append(records, new_record)),
                    }
                }
            }) {
            Err(e) => Err(e),
            Ok(reencrypted_records) => self.update_records(reencrypted_records, dao),
        }
    }

    #[allow(clippy::borrowed_box)]
    fn update_records<T: ConfigDaoReadWrite + ?Sized>(
        &self,
        reencrypted_records: Vec<ConfigDaoRecord>,
        dao: &Box<T>,
    ) -> Result<(), SecureConfigLayerError> {
        let init: Result<(), SecureConfigLayerError> = Ok(());
        reencrypted_records.into_iter()
            .fold(init, |so_far, record| {
                if so_far.is_ok() {
                    let setter = |value_opt: Option<&str>| dao.set(&record.name, value_opt.map(|s| s.to_string()));
                    let result = match &record.value_opt {
                        Some(value) => setter(Some(value)),
                        None => setter(None),
                    };
                    result.map_err(|e| SecureConfigLayerError::DatabaseError(format!("Aborting password change: configuration value '{}' could not be set: {:?}", record.name, e)))
                } else {
                    so_far
                }
            })
    }

    fn reencrypt_record(
        old_record: ConfigDaoRecord,
        old_password_opt: Option<String>,
        new_password: &str,
    ) -> Result<ConfigDaoRecord, SecureConfigLayerError> {
        match (old_record.encrypted, &old_record.value_opt, &old_password_opt) {
            (false, _, _) => Ok(old_record),
            (true, None, _) => Ok(old_record),
            (true, Some(_), None) => panic! ("Database is corrupt: configuration value '{}' is encrypted, but database has no password", old_record.name),
            (true, Some(value), Some(old_password)) => {
                let decrypted_value = match Bip39::decrypt_bytes(value, old_password) {
                    Ok(plain_data) => plain_data,
                    Err(_) => panic! ("Database is corrupt: configuration value '{}' cannot be decrypted", old_record.name),
                };
                let reencrypted_value = Bip39::encrypt_bytes(&decrypted_value, new_password).expect("Encryption failed");
                Ok(ConfigDaoRecord::new(&old_record.name, Some(&reencrypted_value), old_record.encrypted))
            },
        }
    }

    #[allow(clippy::borrowed_box)]
    fn install_example_for_password<T: ConfigDaoReadWrite + ?Sized>(
        &self,
        new_password: &str,
        dao: &Box<T>,
    ) -> Result<(), SecureConfigLayerError> {
        let mut example_data = [0u8; 32];
        rand::thread_rng().fill(&mut example_data);
        let example_encrypted =
            Bip39::encrypt_bytes(&example_data, new_password).expect("Encryption failed");
        dao.set(EXAMPLE_ENCRYPTED, Some(example_encrypted))
            .map_err(SecureConfigLayerError::from)
    }
}

fn append<T: Clone>(records: Vec<T>, record: T) -> Vec<T> {
    let mut result = records;
    result.push(record);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip39::Bip39;
    use crate::db_config::config_dao::{ConfigDaoError, ConfigDaoRecord};
    use crate::db_config::mocks::{ConfigDaoMock, ConfigDaoWriteableMock};
    use crate::db_config::secure_config_layer::SecureConfigLayerError::DatabaseError;
    use crate::sub_lib::cryptde::PlainData;
    use std::sync::{Arc, Mutex};

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
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(None, &Box::new(dao));

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
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(Some("password".to_string()), &Box::new(dao));

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
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(None, &Box::new(dao));

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
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(Some("password".to_string()), &Box::new(dao));

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
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(Some("bad password".to_string()), &Box::new(dao));

        assert_eq!(result, Ok(false));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    #[should_panic(expected = "Database is corrupt: Password example value is not encrypted")] // TODO: Modify this test to expect a panic, since database is corrupt
    fn check_password_fails_when_example_record_is_present_and_unencrypted() {
        let dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some("booga"),
            false,
        )));
        let subject = SecureConfigLayer::new();

        let _ = subject.check_password(Some("bad password".to_string()), &Box::new(dao));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: password example value can't be read: ConversionError(\"Invalid character \\'s\\' at position 1\")"
    )]
    fn check_password_fails_when_example_record_is_present_but_corrupt() {
        let bad_encrypted_example = "Aside from that, Mrs. Lincoln, how was the play?";
        let dao = ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(bad_encrypted_example),
            true,
        )));
        let subject = SecureConfigLayer::new();

        let _ = subject.check_password(Some("password".to_string()), &Box::new(dao));
    }

    #[test]
    fn check_password_passes_on_unexpected_database_error() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = ConfigDaoMock::new()
            .get_params(&get_params_arc)
            .get_result(Err(ConfigDaoError::DatabaseError("booga".to_string())));
        let subject = SecureConfigLayer::new();

        let result = subject.check_password(Some("irrelevant".to_string()), &Box::new(dao));

        assert_eq!(result, Err(DatabaseError("booga".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn change_password_works_when_no_password_exists() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let mut writeable = Box::new(
            ConfigDaoWriteableMock::new()
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_params(&get_params_arc)
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
                .set_result(Ok(()))
                .commit_params(&commit_params_arc),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.change_password(None, "password", &mut writeable);

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
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![]);
    }

    #[test]
    fn change_password_works_when_password_exists_and_old_password_matches() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.".as_bytes();
        let old_encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "old_password").unwrap();
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let mut writeable = Box::new(
            ConfigDaoWriteableMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                )))
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
                .set_result(Ok(()))
                .commit_params(&commit_params_arc),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.change_password(
            Some("old_password".to_string()),
            "new_password",
            &mut writeable,
        );

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
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(*commit_params, vec![])
    }

    #[test]
    fn change_password_works_when_password_exists_and_old_password_doesnt_match() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let dao = ConfigDaoWriteableMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(&encrypted_example),
            true,
        )));
        let subject = SecureConfigLayer::new();

        let result = subject.change_password(
            Some("bad_password".to_string()),
            "new_password",
            &mut Box::new(dao),
        );

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: configuration value 'badly_encrypted' cannot be decrypted"
    )]
    fn reencrypt_records_balks_when_a_value_is_incorrectly_encrypted() {
        let unencrypted_value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "bad_password").unwrap();
        let dao = ConfigDaoWriteableMock::new().get_all_result(Ok(vec![ConfigDaoRecord::new(
            "badly_encrypted",
            Some(&encrypted_value),
            true,
        )]));
        let subject = SecureConfigLayer::new();

        let _ = subject.reencrypt_records(
            Some("old_password".to_string()),
            "new_password",
            &Box::new(dao),
        );
    }

    #[test]
    fn reencrypt_records_balks_when_a_value_cant_be_set() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "old_password").unwrap();
        let unencrypted_value = "These are the times that try men's souls.";
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "old_password").unwrap();
        let dao = ConfigDaoWriteableMock::new()
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
        let subject = SecureConfigLayer::new();

        let result = subject.reencrypt_records(
            Some("old_password".to_string()),
            "new_password",
            &Box::new(dao),
        );

        assert_eq! (result, Err(SecureConfigLayerError::DatabaseError("Aborting password change: configuration value 'encrypted_value' could not be set: DatabaseError(\"booga\")".to_string())))
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: configuration value 'name' is encrypted, but database has no password"
    )]
    fn reencrypt_record_balks_when_database_has_no_password_but_value_is_encrypted_anyway() {
        let record = ConfigDaoRecord::new("name", Some("value"), true);
        let old_password_opt = None;
        let new_password = "irrelevant";

        let _ = SecureConfigLayer::reencrypt_record(record, old_password_opt, new_password);
    }

    #[test]
    fn decrypt_works_when_database_is_unencrypted_value_is_unencrypted() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let record = ConfigDaoRecord::new("attribute_name", Some("attribute_value"), false);
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, None, &dao);

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn decrypt_works_when_database_is_unencrypted_value_is_encrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let record = ConfigDaoRecord::new("attribute_name", None, true);
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, None, &dao);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn decrypt_works_when_database_is_encrypted_value_is_unencrypted() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let record = ConfigDaoRecord::new("attribute_name", Some("attribute_value"), false);
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, Some("password".to_string()), &dao);

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn decrypt_works_when_database_is_encrypted_value_is_encrypted() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let value = "These are the times that try men's souls.";
        let encrypted_value = Bip39::encrypt_bytes(&value, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let record = ConfigDaoRecord::new("attribute_name", Some(&encrypted_value), true);
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, Some("password".to_string()), &dao);

        assert_eq!(
            result,
            Ok(Some(
                "These are the times that try men's souls.".to_string()
            ))
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn decrypt_objects_if_value_is_incorrectly_encrypted() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&value, "bad_password").unwrap();
        let record = ConfigDaoRecord::new("attribute_name", Some(&encrypted_value), true);
        let dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(&encrypted_example),
            true,
        ))));
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, Some("password".to_string()), &dao);

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn decrypt_objects_to_decrypting_an_encrypted_value_without_a_password() {
        let value = "These are the times that try men's souls.".as_bytes();
        let encrypted_value = Bip39::encrypt_bytes(&value, "password").unwrap();
        let record = ConfigDaoRecord::new("attribute_name", Some(&encrypted_value), true);
        let dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            None,
            true,
        ))));
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, None, &dao);

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    #[should_panic(
        expected = "Database is corrupt: contains a non-UTF-8 value for 'attribute_name'"
    )]
    fn decrypt_objects_if_decrypted_string_violates_utf8() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        // UTF-8 doesn't tolerate 192 followed by 193
        let unencrypted_value: &[u8] = &[32, 32, 192, 193, 32, 32];
        let encrypted_value = Bip39::encrypt_bytes(&unencrypted_value, "password").unwrap();
        let record = ConfigDaoRecord::new("attribute_name", Some(&encrypted_value), true);
        let dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            Some(&encrypted_example),
            true,
        ))));
        let subject = SecureConfigLayer::new();

        let _ = subject.decrypt(record, Some("password".to_string()), &dao);
    }

    #[test]
    fn decrypt_objects_if_passwords_dont_match() {
        let dao = Box::new(ConfigDaoMock::new().get_result(Ok(ConfigDaoRecord::new(
            EXAMPLE_ENCRYPTED,
            None,
            true,
        ))));
        let record = ConfigDaoRecord::new("attribute_name", Some("attribute_value"), true);
        let subject = SecureConfigLayer::new();

        let result = subject.decrypt(record, Some("password".to_string()), &dao);

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn encrypt_works_when_database_is_unencrypted_and_value_is_unencrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    "attribute_name",
                    Some("irrelevant"),
                    false,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt("attribute_name", None, None, &dao);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_unencrypted_and_value_is_unencrypted_and_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    "attribute_name",
                    Some("irrelevant"),
                    false,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt(
            "attribute_name",
            Some("attribute_value".to_string()),
            None,
            &dao,
        );

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_unencrypted_and_value_is_encrypted_and_absent() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt("attribute_name", None, None, &dao);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn set_works_when_database_is_encrypted_and_value_is_unencrypted_and_absent() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt("attribute_name", None, Some("password".to_string()), &dao);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_encrypted_and_value_is_unencrypted_and_present() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "attribute_name",
                    Some("irrelevant"),
                    false,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt(
            "attribute_name",
            Some("attribute_value".to_string()),
            Some("password".to_string()),
            &dao,
        );

        assert_eq!(result, Ok(Some("attribute_value".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_encrypted_and_value_is_encrypted_and_absent() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt("attribute_name", None, Some("password".to_string()), &dao);

        assert_eq!(result, Ok(None));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_encrypted_and_value_is_encrypted_and_present() {
        let example = "Aside from that, Mrs. Lincoln, how was the play?".as_bytes();
        let encrypted_example = Bip39::encrypt_bytes(&example, "password").unwrap();
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(
                    EXAMPLE_ENCRYPTED,
                    Some(&encrypted_example),
                    true,
                )))
                .get_result(Ok(ConfigDaoRecord::new(
                    "attribute_name",
                    Some("irrelevant"),
                    true,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject
            .encrypt(
                "attribute_name",
                Some("attribute_value".to_string()),
                Some("password".to_string()),
                &dao,
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            String::from_utf8(Bip39::decrypt_bytes(&result, "password").unwrap().into()).unwrap(),
            "attribute_value".to_string()
        );
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![EXAMPLE_ENCRYPTED.to_string(), "attribute_name".to_string()]
        );
    }

    #[test]
    fn encrypt_works_when_database_is_unencrypted_and_value_is_encrypted_and_present_without_password(
    ) {
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new(
                    "attribute_name",
                    Some("irrelevant"),
                    true,
                ))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt(
            "attribute_name",
            Some("attribute_value".to_string()),
            None,
            &dao,
        );

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
    }

    #[test]
    fn encrypt_works_when_password_doesnt_match() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, false))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt(
            "attribute_name",
            Some("attribute_value".to_string()),
            Some("password".to_string()),
            &dao,
        );

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn encrypt_works_when_database_is_unencrypted_and_value_is_encrypted_and_present() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_params(&get_params_arc)
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Ok(ConfigDaoRecord::new("attribute_name", None, true))),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt(
            "attribute_name",
            Some("attribute_value".to_string()),
            Some("password".to_string()),
            &dao,
        );

        assert_eq!(result, Err(SecureConfigLayerError::PasswordError));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![EXAMPLE_ENCRYPTED.to_string()]);
    }

    #[test]
    fn encrypt_works_when_configuration_item_is_unknown() {
        let dao = Box::new(
            ConfigDaoMock::new()
                .get_result(Ok(ConfigDaoRecord::new(EXAMPLE_ENCRYPTED, None, true)))
                .get_result(Err(ConfigDaoError::NotPresent)),
        );
        let subject = SecureConfigLayer::new();

        let result = subject.encrypt("attribute_name", None, None, &dao);

        assert_eq!(result, Err(SecureConfigLayerError::NotPresent));
    }
}
