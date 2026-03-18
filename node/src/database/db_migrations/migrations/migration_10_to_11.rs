// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_10_to_11;

impl DatabaseMigration for Migrate_10_to_11 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        declaration_utils.execute_upon_transaction(&[
            &"INSERT INTO config (name, value, encrypted) VALUES ('last_cryptde', null, 1)",
        ])
    }

    fn old_version(&self) -> usize {
        10
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use std::fs::create_dir_all;

    #[test]
    fn migration_from_10_to_11_is_properly_set() {
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_10_to_11_is_properly_set",
        );
        create_dir_all(&dir_path).unwrap();
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();

        let result = subject.initialize_to_version(
            &dir_path,
            10,
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );

        assert!(result.is_ok());

        let result = subject.initialize_to_version(
            &dir_path,
            11,
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );

        assert!(result.is_ok());
        let connection = result.unwrap();
        let (lc_value, lc_encrypted) = retrieve_config_row(connection.as_ref(), "last_cryptde");
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(lc_value, None);
        assert_eq!(lc_encrypted, true);
        assert_eq!(cs_value, Some("11".to_string()));
        assert_eq!(cs_encrypted, false)
    }
}
