// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::db_migrator_utils::MigDeclarationUtilities;

#[allow(non_camel_case_types)]
pub struct Migrate_0_to_1;

impl DatabaseMigration for Migrate_0_to_1 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        declaration_utils.execute_upon_transaction(&[
            &"INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
        ])
    }

    fn old_version(&self) -> usize {
        0
    }
}


#[cfg(test)]
mod tests {
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use crate::database::db_initializer::{DATABASE_FILE, DbInitializationConfig, DbInitializer, DbInitializerReal};
    use crate::test_utils::database_utils::{bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row};
    use std::fs::create_dir_all;

    #[test]
    fn migration_from_0_to_1_is_properly_set() {
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_0_to_1_is_properly_set",
        );
        create_dir_all(&dir_path).unwrap();
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();

        let result = subject.initialize_to_version(
            &dir_path,
            1,
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );
        let connection = result.unwrap();
        let (mp_value, mp_encrypted) = retrieve_config_row(connection.as_ref(), "mapping_protocol");
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(mp_value, None);
        assert_eq!(mp_encrypted, false);
        assert_eq!(cs_value, Some("1".to_string()));
        assert_eq!(cs_encrypted, false)
    }
}