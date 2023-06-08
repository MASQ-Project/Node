// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_7_to_8;

impl DatabaseMigration for Migrate_7_to_8 {
    fn migrate<'a>(
        &self,
        mig_declaration_utilities: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let statement =
            "INSERT INTO config (name, value, encrypted) VALUES ('min_hops_count', '3', 0)";
        mig_declaration_utilities.execute_upon_transaction(&[&statement])
    }

    fn old_version(&self) -> usize {
        7
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData, DATABASE_FILE,
    };
    use crate::database::db_migrations::db_migrator::DatabaseMigration;
    use crate::database::db_migrations::migrations::migration_7_to_8::Migrate_7_to_8;
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::utils::NeighborhoodModeLight;

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
                .initialize_to_version(
                    &dir_path,
                    start_at,
                    DbInitializationConfig::create_or_migrate(make_external_data()),
                )
                .unwrap();
        }

        let result = subject.initialize_to_version(
            &dir_path,
            start_at + 1,
            DbInitializationConfig::create_or_migrate(ExternalData::new(
                DEFAULT_CHAIN,
                NeighborhoodModeLight::ConsumeOnly,
                None,
            )),
        );

        let connection = result.unwrap();
        let (bchs_value, bchs_encrypted) =
            retrieve_config_row(connection.as_ref(), "min_hops_count");
        assert_eq!(bchs_value, Some("3".to_string()));
        assert_eq!(bchs_encrypted, false);
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(cs_value, Some("8".to_string()));
        assert_eq!(cs_encrypted, false);
    }
}