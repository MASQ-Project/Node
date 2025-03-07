// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_2_to_3;

impl DatabaseMigration for Migrate_2_to_3 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let statement_1 =
            "INSERT INTO config (name, value, encrypted) VALUES ('blockchain_service_url', null, 0)";
        let statement_2 = format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('neighborhood_mode', '{}', 0)",
            declaration_utils.external_parameters().neighborhood_mode
        );
        declaration_utils.execute_upon_transaction(&[&statement_1, &statement_2])
    }

    fn old_version(&self) -> usize {
        2
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData, DATABASE_FILE,
    };
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use masq_lib::shared_schema::NeighborhoodMode;

    #[test]
    fn migration_from_2_to_3_is_properly_set() {
        let start_at = 2;
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_2_to_3_is_properly_set",
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
                NeighborhoodMode::ConsumeOnly,
                None,
            )),
        );

        let connection = result.unwrap();
        let (bchs_value, bchs_encrypted) =
            retrieve_config_row(connection.as_ref(), "blockchain_service_url");
        assert_eq!(bchs_value, None);
        assert_eq!(bchs_encrypted, false);
        let (nm_value, nm_encrypted) =
            retrieve_config_row(connection.as_ref(), "neighborhood_mode");
        assert_eq!(nm_value, Some("consume-only".to_string()));
        assert_eq!(nm_encrypted, false);
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(cs_value, Some("3".to_string()));
        assert_eq!(cs_encrypted, false);
    }
}
