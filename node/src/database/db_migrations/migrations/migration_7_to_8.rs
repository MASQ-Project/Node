// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;
use crate::neighborhood::DEFAULT_MIN_HOPS;

#[allow(non_camel_case_types)]
pub struct Migrate_7_to_8;

impl DatabaseMigration for Migrate_7_to_8 {
    fn migrate<'a>(
        &self,
        mig_declaration_utilities: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let statement = format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('min_hops', '{DEFAULT_MIN_HOPS}', 0)",
        );
        mig_declaration_utilities.execute_upon_transaction(&[&statement])
    }

    fn old_version(&self) -> usize {
        7
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::db_migrations::db_migrator::DatabaseMigration;
    use crate::database::db_migrations::migrations::migration_7_to_8::Migrate_7_to_8;
    use crate::neighborhood::DEFAULT_MIN_HOPS;
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn old_version_says_7() {
        let subject = Migrate_7_to_8 {};

        let result = subject.old_version();

        assert_eq!(result, 7);
    }

    #[test]
    fn migration_from_7_to_8_is_properly_set() {
        let start_at = Migrate_7_to_8 {}.old_version();
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_7_to_8_is_properly_set",
        );
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        {
            subject
                .initialize_to_version(&dir_path, start_at, DbInitializationConfig::test_default())
                .unwrap();
        }

        let result = subject.initialize_to_version(
            &dir_path,
            start_at + 1,
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );

        let connection = result.unwrap();
        let (mhc_value, mhc_encrypted) = retrieve_config_row(connection.as_ref(), "min_hops");
        assert_eq!(mhc_value, Some(DEFAULT_MIN_HOPS.to_string()));
        assert_eq!(mhc_encrypted, false);
        let (schv_value, schv_encrypted) =
            retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(schv_value, Some("8".to_string()));
        assert_eq!(schv_encrypted, false);
    }
}
