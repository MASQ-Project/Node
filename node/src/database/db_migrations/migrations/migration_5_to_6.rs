// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;
use crate::sub_lib::accountant;
use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use masq_lib::blockchains::chains::Chain;

#[allow(non_camel_case_types)]
pub struct Migrate_5_to_6;

impl DatabaseMigration for Migrate_5_to_6 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        let statement_1 = Self::make_initialization_statement(
            "payment_thresholds",
            &DEFAULT_PAYMENT_THRESHOLDS.to_string(),
        );
        let statement_2 =
            Self::make_initialization_statement("rate_pack", &DEFAULT_RATE_PACK.to_string());
        let tx = declaration_utils.transaction();
        let chain = tx
            .prepare("SELECT value FROM config WHERE name = 'chain_name'")
            .expect("internal error")
            .query_row([], |row| {
                let res_str = row.get::<_, String>(0);
                res_str.map(|str| Chain::from(str.as_str()))
            })
            .expect("failed to read the chain from db");
        let statement_3 = Self::make_initialization_statement(
            "scan_intervals",
            &accountant::ScanIntervals::compute_default(chain).to_string(),
        );
        declaration_utils.execute_upon_transaction(&[&statement_1, &statement_2, &statement_3])
    }

    fn old_version(&self) -> usize {
        5
    }
}

impl Migrate_5_to_6 {
    fn make_initialization_statement(name: &str, value: &str) -> String {
        format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('{}', '{}', 0)",
            name, value
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::sub_lib::accountant;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;
    use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
    use crate::test_utils::database_utils::{
        bring_db_0_back_to_life_and_return_connection, make_external_data, retrieve_config_row,
    };
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;

    #[test]
    fn migration_from_5_to_6_works() {
        let dir_path =
            ensure_node_home_directory_exists("db_migrations", "migration_from_5_to_6_works");
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        let chain = {
            let conn = subject
                .initialize_to_version(
                    &dir_path,
                    5,
                    DbInitializationConfig::create_or_migrate(make_external_data()),
                )
                .unwrap();
            let chain = conn
                .prepare("SELECT value FROM config WHERE name = 'chain_name'")
                .unwrap()
                .query_row([], |row| row.get::<_, String>(0))
                .unwrap();
            chain
        };

        let result = subject.initialize_to_version(
            &dir_path,
            6,
            DbInitializationConfig::create_or_migrate(make_external_data()),
        );

        let connection = result.unwrap();
        let (payment_thresholds, encrypted) =
            retrieve_config_row(connection.as_ref(), "payment_thresholds");
        assert_eq!(
            payment_thresholds,
            Some(DEFAULT_PAYMENT_THRESHOLDS.to_string())
        );
        assert_eq!(encrypted, false);
        let (rate_pack, encrypted) = retrieve_config_row(connection.as_ref(), "rate_pack");
        assert_eq!(rate_pack, Some(DEFAULT_RATE_PACK.to_string()));
        assert_eq!(encrypted, false);
        let (scan_intervals, encrypted) =
            retrieve_config_row(connection.as_ref(), "scan_intervals");
        assert_eq!(
            scan_intervals,
            Some(
                accountant::ScanIntervals::compute_default(Chain::from(chain.as_str())).to_string()
            )
        );
        assert_eq!(encrypted, false);
    }
}
