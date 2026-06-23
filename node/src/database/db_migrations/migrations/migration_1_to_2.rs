// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_1_to_2;

impl DatabaseMigration for Migrate_1_to_2 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let statement = format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('chain_name', '{}', 0)",
            declaration_utils
                .external_parameters()
                .chain
                .rec()
                .literal_identifier
        );
        declaration_utils.execute_upon_transaction(&[&statement])
    }

    fn old_version(&self) -> usize {
        1
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
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn migration_from_1_to_2_is_properly_set() {
        init_test_logging();
        let start_at = 1;
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_1_to_2_is_properly_set",
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
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );

        let connection = result.unwrap();
        let (chn_value, chn_encrypted) = retrieve_config_row(connection.as_ref(), "chain_name");
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(chn_value, Some("base-sepolia".to_string()));
        assert_eq!(chn_encrypted, false);
        assert_eq!(cs_value, Some("2".to_string()));
        assert_eq!(cs_encrypted, false);
        TestLogHandler::new().exists_log_containing(
            "DbMigrator: Database successfully migrated from version 1 to 2",
        );
    }
}
