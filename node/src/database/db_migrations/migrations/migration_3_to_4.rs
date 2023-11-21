// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::Bip39;
use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;
use crate::db_config::db_encryption_layer::DbEncryptionLayer;
use crate::db_config::typed_config_layer::decode_bytes;
use crate::sub_lib::cryptde::PlainData;
use itertools::Itertools;
use tiny_hderive::bip32::ExtendedPrivKey;

#[allow(non_camel_case_types)]
pub struct Migrate_3_to_4;

impl Migrate_3_to_4 {
    fn maybe_exchange_seed_for_private_key(
        consuming_path_opt: Option<String>,
        example_encrypted_opt: Option<String>,
        seed_encrypted_opt: Option<String>,
        utils: &dyn DBMigDeclarator,
    ) -> Option<String> {
        match (
            consuming_path_opt,
            example_encrypted_opt,
            seed_encrypted_opt,
        ) {
            (Some(consuming_path), Some(example_encrypted), Some(seed_encrypted)) => {
                let password_opt = utils.db_password();
                if !DbEncryptionLayer::password_matches(&password_opt, &Some(example_encrypted)) {
                    panic!("Migrating Database from 3 to 4: bad password");
                }
                let seed_encoded =
                    DbEncryptionLayer::decrypt_value(&Some(seed_encrypted), &password_opt, "seed")
                        .expect("Internal error")
                        .expect("Internal error");
                let seed_data = decode_bytes(Some(seed_encoded))
                    .expect("Internal error")
                    .expect("Internal error");
                let extended_private_key =
                    ExtendedPrivKey::derive(seed_data.as_ref(), consuming_path.as_str())
                        .expect("Internal error");
                let private_key_data = PlainData::new(&extended_private_key.secret());
                Some(
                    Bip39::encrypt_bytes(
                        &private_key_data.as_slice(),
                        password_opt.as_ref().expect("Password somehow disappeared"),
                    )
                    .expect("Internal error: encryption failed"),
                )
            }
            (None, None, None) => None,
            (None, Some(_), None) => None,
            (consuming_path_opt, example_encrypted_opt, seed_encrypted_opt) => panic!(
                "these three options {:?}, {:?}, {:?} leave the database in an inconsistent state",
                consuming_path_opt, example_encrypted_opt, seed_encrypted_opt
            ),
        }
    }
}

impl DatabaseMigration for Migrate_3_to_4 {
    fn migrate<'a>(&self, utils: Box<dyn DBMigDeclarator + 'a>) -> rusqlite::Result<()> {
        let transaction = utils.transaction();
        let mut stmt = transaction
            .prepare("select name, value from config where name in ('example_encrypted', 'seed', 'consuming_wallet_derivation_path') order by name")
            .expect("Internal error");

        let rows = stmt
            .query_map([], |row| {
                let name = row.get::<usize, String>(0).expect("Internal error");
                let value_opt = row.get::<usize, Option<String>>(1).expect("Internal error");
                Ok((name, value_opt))
            })
            .expect("Database is corrupt")
            .map(|r| r.unwrap())
            .collect::<Vec<(String, Option<String>)>>();
        if rows.iter().map(|r| r.0.as_str()).collect_vec()
            != vec![
                "consuming_wallet_derivation_path",
                "example_encrypted",
                "seed",
            ]
        {
            panic!("Database is corrupt");
        }
        let consuming_path_opt = rows[0].1.clone();
        let example_encrypted_opt = rows[1].1.clone();
        let seed_encrypted_opt = rows[2].1.clone();
        let private_key_encoded_opt = Self::maybe_exchange_seed_for_private_key(
            consuming_path_opt,
            example_encrypted_opt,
            seed_encrypted_opt,
            utils.as_ref(),
        );
        let private_key_column = if let Some(private_key) = private_key_encoded_opt {
            format!("'{}'", private_key)
        } else {
            "null".to_string()
        };
        utils.execute_upon_transaction(&[
            &format! ("insert into config (name, value, encrypted) values ('consuming_wallet_private_key', {}, 1)",
                      private_key_column),
            &"delete from config where name in ('seed', 'consuming_wallet_derivation_path', 'consuming_wallet_public_key')",
        ])
    }

    fn old_version(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::bip39::Bip39;
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::db_migrations::migrations::migration_3_to_4::Migrate_3_to_4;
    use crate::database::db_migrations::test_utils::DBMigDeclaratorMock;
    use crate::db_config::db_encryption_layer::DbEncryptionLayer;
    use crate::db_config::typed_config_layer::encode_bytes;
    use crate::sub_lib::cryptde::PlainData;
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::{derivation_path, to_string};
    use rand::Rng;
    use rusqlite::ToSql;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use tiny_hderive::bip32::ExtendedPrivKey;

    #[test]
    fn migration_from_3_to_4_with_wallets() {
        let data_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_3_to_4_with_wallets",
        );
        let db_path = data_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let password_opt = &Some("password".to_string());
        let subject = DbInitializerReal::default();
        let mut external_data = make_external_data();
        external_data.db_password_opt = password_opt.as_ref().cloned();
        let init_config = DbInitializationConfig::create_or_migrate(external_data);
        let original_private_key = {
            let schema3_conn = subject
                .initialize_to_version(&data_path, 3, init_config.clone())
                .unwrap();
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let seed = Seed::new(&mnemonic, "booga");
            let consuming_path = derivation_path(0, 150);
            let original_private_key =
                ExtendedPrivKey::derive(seed.as_bytes(), consuming_path.as_str())
                    .unwrap()
                    .secret();
            let seed_plain = PlainData::new(seed.as_bytes());
            let seed_encoded = encode_bytes(Some(seed_plain)).unwrap().unwrap();
            let seed_encrypted =
                DbEncryptionLayer::encrypt_value(&Some(seed_encoded), password_opt, "seed")
                    .unwrap()
                    .unwrap();
            let mut example_data = [0u8; 32];
            rand::thread_rng().fill(&mut example_data);
            let example_encrypted =
                Bip39::encrypt_bytes(&example_data, password_opt.as_ref().unwrap())
                    .expect("Encryption failed");
            let updates = vec![
                ("consuming_wallet_derivation_path", consuming_path, false),
                ("consuming_wallet_public_key", "booga".to_string(), false),
                ("example_encrypted", example_encrypted, true),
                ("seed", seed_encrypted, true),
            ];
            updates.into_iter().for_each(|(name, value, flag)| {
                let mut stmt = schema3_conn
                    .prepare("update config set value = ?, encrypted = ? where name = ?")
                    .expect(&format!(
                        "Couldn't prepare statement to set {} to {}",
                        name, value
                    ));
                let params: &[&dyn ToSql] =
                    &[&value, &(if flag { 1 } else { 0 }), &name.to_string()];
                let count = stmt.execute(params).unwrap();
                if count != 1 {
                    panic!(
                        "Updating {} to '{}' should have affected 1 row, but affected {}",
                        name, value, count
                    );
                }
            });
            original_private_key.to_vec()
        };

        let migrated_private_key = {
            let mut schema4_conn = subject
                .initialize_to_version(&data_path, 4, init_config)
                .unwrap();
            {
                let mut stmt = schema4_conn.prepare("select count(*) from config where name in ('consuming_wallet_derivation_path', 'consuming_wallet_public_key', 'seed')").unwrap();
                let cruft = stmt
                    .query_row([], |row| Ok(row.get::<usize, u32>(0)))
                    .unwrap()
                    .unwrap();
                assert_eq!(cruft, 0);
            }
            let (private_key_encrypted, encrypted) =
                retrieve_config_row(schema4_conn.as_mut(), "consuming_wallet_private_key");
            assert_eq!(encrypted, true);
            let private_key = Bip39::decrypt_bytes(
                &private_key_encrypted.unwrap(),
                password_opt.as_ref().unwrap(),
            )
            .unwrap();
            private_key.as_slice().to_vec()
        };

        assert_eq!(migrated_private_key, original_private_key);
    }

    #[test]
    fn migration_from_3_to_4_without_secrets() {
        let data_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_3_to_4_without_secrets",
        );
        let db_path = data_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let password_opt = &Some("password".to_string());
        let subject = DbInitializerReal::default();
        let mut external_data = make_external_data();
        external_data.db_password_opt = password_opt.as_ref().cloned();
        let init_config = DbInitializationConfig::create_or_migrate(external_data);
        {
            subject
                .initialize_to_version(&data_path, 3, init_config.clone())
                .unwrap();
        };

        let mut schema4_conn = subject
            .initialize_to_version(&data_path, 4, init_config)
            .unwrap();

        {
            let mut stmt = schema4_conn.prepare("select count(*) from config where name in ('consuming_wallet_derivation_path', 'consuming_wallet_public_key', 'seed')").unwrap();
            let cruft = stmt
                .query_row([], |row| Ok(row.get::<usize, u32>(0)))
                .unwrap()
                .unwrap();
            assert_eq!(cruft, 0);
        }
        let (private_key_encrypted, encrypted) =
            retrieve_config_row(schema4_conn.as_mut(), "consuming_wallet_private_key");
        assert_eq!(private_key_encrypted, None);
        assert_eq!(encrypted, true);
    }

    #[test]
    #[should_panic(expected = "Migrating Database from 3 to 4: bad password")]
    fn migration_from_3_to_4_bad_password() {
        let example_encrypted = Bip39::encrypt_bytes(&b"BBBB", "GoodPassword").unwrap();
        let mig_declarator =
            DBMigDeclaratorMock::default().db_password_result(Some("BadPassword".to_string()));
        let consuming_path_opt = Some("AAAAA".to_string());
        let example_encrypted_opt = Some(example_encrypted);
        let seed_encrypted_opt = Some("CCCCC".to_string());

        Migrate_3_to_4::maybe_exchange_seed_for_private_key(
            consuming_path_opt,
            example_encrypted_opt,
            seed_encrypted_opt,
            &mig_declarator,
        );
    }

    #[test]
    fn database_with_password_but_without_secrets_yet_still_accepted() {
        let mig_declarator = DBMigDeclaratorMock::default();
        let example_encrypted_opt = Some("random garbage".to_string());

        let result = Migrate_3_to_4::maybe_exchange_seed_for_private_key(
            None,
            example_encrypted_opt,
            None,
            &mig_declarator,
        );

        assert_eq!(result, None);
    }

    fn catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
        consuming_path_opt: Option<&str>,
        example_encrypted_opt: Option<&str>,
        seed_encrypted_opt: Option<&str>,
    ) -> String {
        let mig_declarator = &DBMigDeclaratorMock::default();
        let consuming_path_opt = consuming_path_opt.map(to_string);
        let example_encrypted_opt = example_encrypted_opt.map(to_string);
        let seed_encrypted_opt = seed_encrypted_opt.map(to_string);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            Migrate_3_to_4::maybe_exchange_seed_for_private_key(
                consuming_path_opt,
                example_encrypted_opt,
                seed_encrypted_opt,
                mig_declarator,
            )
        }))
        .unwrap_err();
        panic.downcast_ref::<String>().unwrap().to_owned()
    }

    #[test]
    fn migration_panics_if_the_database_is_corrupt() {
        let panic = catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
            Some("consuming_path"),
            Some("example_encrypted"),
            None,
        );
        assert_eq!(panic, "these three options Some(\"consuming_path\"), Some(\"example_encrypted\"), None leave the database in an inconsistent state");

        let panic = catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
            Some("consuming_path"),
            None,
            Some("seed_encrypted"),
        );
        assert_eq!(panic, "these three options Some(\"consuming_path\"), None, Some(\"seed_encrypted\") leave the database in an inconsistent state");

        let panic = catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
            None,
            Some("example_encrypted"),
            Some("seed_encrypted"),
        );
        assert_eq!(panic, "these three options None, Some(\"example_encrypted\"), Some(\"seed_encrypted\") leave the database in an inconsistent state");

        let panic = catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
            None,
            None,
            Some("seed_encrypted"),
        );
        assert_eq!(panic, "these three options None, None, Some(\"seed_encrypted\") leave the database in an inconsistent state");

        let panic = catch_panic_for_maybe_exchange_seed_for_private_key_with_corrupt_database(
            Some("consuming_path"),
            None,
            None,
        );
        assert_eq!(panic, "these three options Some(\"consuming_path\"), None, None leave the database in an inconsistent state");
    }
}
