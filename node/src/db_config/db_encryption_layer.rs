// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::{Bip39, Bip39Error};
use crate::db_config::secure_config_layer::SecureConfigLayerError;

pub struct DbEncryptionLayer {}

impl DbEncryptionLayer {
    pub fn password_matches(
        db_password_opt: &Option<String>,
        example_encrypted_opt: &Option<String>,
    ) -> bool {
        match (db_password_opt, example_encrypted_opt) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(_), None) => false,
            (Some(db_password), Some(encrypted_example)) => {
                match Bip39::decrypt_bytes(encrypted_example, db_password) {
                    Ok(_) => true,
                    Err(Bip39Error::DecryptionFailure(_)) => false,
                    Err(e) => panic!(
                        "Database is corrupt: password example value can't be read: {:?}",
                        e
                    ),
                }
            }
        }
    }

    pub fn decrypt_value(
        crypt_value_opt: &Option<String>,
        db_password_opt: &Option<String>,
        name: &str,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        match (crypt_value_opt, db_password_opt) {
            (Some(value), Some(password)) => match Bip39::decrypt_bytes(value, password) {
                Err(_) => Err(SecureConfigLayerError::PasswordError),
                Ok(plain_data) => match String::from_utf8(plain_data.into()) {
                    Err(_) => panic!(
                        "Database is corrupt: contains a non-UTF-8 value for '{}'",
                        name
                    ),
                    Ok(plain_value) => Ok(Some(plain_value)),
                },
            },
            (Some(_), None) => Err(SecureConfigLayerError::PasswordError),
            (None, _) => Ok(None),
        }
    }

    pub fn encrypt_value(
        plain_value_opt: &Option<String>,
        db_password_opt: &Option<String>,
        name: &str,
    ) -> Result<Option<String>, SecureConfigLayerError> {
        match (plain_value_opt, db_password_opt) {
            (Some(plain_value), Some(password)) => {
                match Bip39::encrypt_bytes(&plain_value.as_bytes(), password) {
                    Err(_) => panic!("Encryption of '{}' for {} failed", plain_value, name),
                    Ok(crypt_data) => Ok(Some(crypt_data)),
                }
            }
            (Some(_), None) => Err(SecureConfigLayerError::PasswordError),
            (None, _) => Ok(None),
        }
    }

    pub fn reencrypt_value(
        crypt_value: &str,
        old_password: &str,
        new_password: &str,
        name: &str,
    ) -> String {
        let decrypted_value = match Bip39::decrypt_bytes(crypt_value, old_password) {
            Ok(plain_data) => plain_data,
            Err(_) => panic!(
                "Database is corrupt: configuration value '{}' cannot be decrypted",
                name
            ),
        };
        Bip39::encrypt_bytes(&decrypted_value, new_password).expect("Encryption failed")
    }

    // These methods were extracted from SecureConfigLayer and are covered by the non_unit_tests there.
}
