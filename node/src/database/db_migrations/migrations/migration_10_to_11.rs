use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_10_to_11;

impl DatabaseMigration for Migrate_10_to_11 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let sql_statement = "create table if not exists sent_payable (
                rowid integer primary key,
                tx_hash text not null,
                receiver_address text not null,
                amount_high_b integer not null,
                amount_low_b integer not null,
                timestamp integer not null,
                gas_price_wei integer not null,
                nonce integer not null,
                status text not null,
                retried integer not null
            )";

        declaration_utils.execute_upon_transaction(&[&sql_statement])
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
        assert_create_table_stm_contains_all_parts, assert_table_exists,
        bring_db_0_back_to_life_and_return_connection, make_external_data,
    };
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use std::fs::create_dir_all;

    #[test]
    fn migration_from_10_to_11_is_applied_correctly() {
        init_test_logging();
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

        let connection = result.unwrap();
        assert_table_exists(connection.as_ref(), "sent_payable");
        let expected_key_words: &[&[&str]] = &[
            &["rowid", "integer", "primary", "key"],
            &["tx_hash", "text", "not", "null"],
            &["receiver_address", "text", "not", "null"],
            &["amount_high_b", "integer", "not", "null"],
            &["amount_low_b", "integer", "not", "null"],
            &["timestamp", "integer", "not", "null"],
            &["gas_price_wei", "integer", "not", "null"],
            &["nonce", "integer", "not", "null"],
            &["status", "text", "not", "null"],
            &["retried", "integer", "not", "null"],
        ];
        assert_create_table_stm_contains_all_parts(
            &*connection,
            "sent_payable",
            expected_key_words,
        );
        TestLogHandler::new().assert_logs_contain_in_order(vec![
            "DbMigrator: Database successfully migrated from version 10 to 11",
        ]);
    }
}
