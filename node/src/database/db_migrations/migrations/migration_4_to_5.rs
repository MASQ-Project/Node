// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::dao_utils::VigilantRusqliteFlatten;
use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::DBMigDeclarator;

#[allow(non_camel_case_types)]
pub struct Migrate_4_to_5;

impl DatabaseMigration for Migrate_4_to_5 {
    fn migrate<'a>(&self, utils: Box<dyn DBMigDeclarator + 'a>) -> rusqlite::Result<()> {
        let mut select_statement = utils
            .transaction()
            .prepare("select pending_payment_transaction from payable where pending_payment_transaction is not null")?;
        let unresolved_pending_transactions: Vec<String> = select_statement
            .query_map([], |row| {
                Ok(row
                    .get::<usize, String>(0)
                    .expect("select statement was badly prepared"))
            })?
            .vigilant_flatten()
            .collect();
        if !unresolved_pending_transactions.is_empty() {
            warning!(utils.logger(),
                "Migration from 4 to 5: database belonging to the chain '{}'; \
                we discovered possibly abandoned transactions that are said yet to be pending, these are: '{}'; continuing",
                utils.external_parameters().chain.rec().literal_identifier,unresolved_pending_transactions.join("', '") )
        } else {
            debug!(
                utils.logger(),
                "Migration from 4 to 5: no previous pending transactions found; continuing"
            )
        };
        let statement_1 = "alter table payable drop column pending_payment_transaction";
        let statement_2 = "alter table payable add pending_payable_rowid integer null";
        let statement_3 = "create table pending_payable (\
                rowid integer primary key, \
                transaction_hash text not null, \
                amount integer not null, \
                payable_timestamp integer not null, \
                attempt integer not null, \
                process_error text null\
            )";
        let statement_4 =
            "create unique index pending_payable_hash_idx ON pending_payable (transaction_hash)";
        let statement_5 = "drop index idx_receivable_wallet_address";
        let statement_6 = "drop index idx_banned_wallet_address";
        let statement_7 = "drop index idx_payable_wallet_address";
        let statement_8 = "alter table config rename to _config_old";
        let statement_9 = "create table config (\
                name text primary key,\
                value text,\
                encrypted integer not null\
             )";
        let statement_10 = "insert into config (name, value, encrypted) select name, value, encrypted from _config_old";
        let statement_11 = "drop table _config_old";
        utils.execute_upon_transaction(&[
            &statement_1,
            &statement_2,
            &statement_3,
            &statement_4,
            &statement_5,
            &statement_6,
            &statement_7,
            &statement_8,
            &statement_9,
            &statement_10,
            &statement_11,
        ])
    }

    fn old_version(&self) -> usize {
        4
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::dao_utils::{from_time_t, to_time_t};
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, ExternalData, DATABASE_FILE,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::database_utils::{
        assert_create_table_stm_contains_all_parts,
        assert_index_stm_is_coupled_with_right_parameter, assert_no_index_exists_for_table,
        assert_table_does_not_exist, bring_db_0_back_to_life_and_return_connection,
        make_external_data,
    };
    use crate::test_utils::make_wallet;
    use ethereum_types::BigEndianHash;
    use itertools::Itertools;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::shared_schema::NeighborhoodMode;
    use rusqlite::types::Value::Null;
    use rusqlite::ToSql;
    use std::collections::HashMap;
    use std::time::SystemTime;
    use web3::types::{H256, U256};

    #[test]
    fn migration_from_4_to_5_without_pending_transactions() {
        init_test_logging();
        let start_at = 4;
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_4_to_5_without_pending_transactions",
        );
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        let conn = subject
            .initialize_to_version(
                &dir_path,
                start_at,
                DbInitializationConfig::create_or_migrate(make_external_data()),
            )
            .unwrap();
        let wallet_1 = make_wallet("scotland_yard");
        prepare_old_fashioned_account_with_pending_transaction_opt(
            conn.as_ref(),
            None,
            &wallet_1,
            113344,
            from_time_t(250_000_000),
        );
        let config_table_before = fetch_all_from_config_table(conn.as_ref());

        let _ = subject
            .initialize_to_version(
                &dir_path,
                start_at + 1,
                DbInitializationConfig::create_or_migrate(ExternalData::new(
                    TEST_DEFAULT_CHAIN,
                    NeighborhoodMode::ConsumeOnly,
                    Some("password".to_string()),
                )),
            )
            .unwrap();

        let config_table_after = fetch_all_from_config_table(conn.as_ref());
        assert_eq!(config_table_before, config_table_after);
        assert_on_schema_5_was_adopted(conn.as_ref());
        TestLogHandler::new().exists_log_containing("DEBUG: DbMigrator: Migration from 4 to 5: no previous pending transactions found; continuing");
    }

    fn prepare_old_fashioned_account_with_pending_transaction_opt(
        conn: &dyn ConnectionWrapper,
        transaction_hash_opt: Option<H256>,
        wallet: &Wallet,
        amount: i64,
        timestamp: SystemTime,
    ) {
        let hash_str = transaction_hash_opt
            .map(|hash| format!("{:?}", hash))
            .unwrap_or(String::new());
        let mut stm = conn.prepare("insert into payable (wallet_address, balance, last_paid_timestamp, pending_payment_transaction) values (?,?,?,?)").unwrap();
        let params: &[&dyn ToSql] = &[
            &wallet,
            &amount,
            &to_time_t(timestamp),
            if !hash_str.is_empty() {
                &hash_str
            } else {
                &Null
            },
        ];
        let row_count = stm.execute(params).unwrap();
        assert_eq!(row_count, 1);
    }

    #[test]
    fn migration_from_4_to_5_with_pending_transactions() {
        init_test_logging();
        let start_at = 4;
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_4_to_5_with_pending_transactions",
        );
        let db_path = dir_path.join(DATABASE_FILE);
        let conn = bring_db_0_back_to_life_and_return_connection(&db_path);
        let conn = ConnectionWrapperReal::new(conn);
        let wallet_1 = make_wallet("james_bond");
        let transaction_hash_1 = H256::from_uint(&U256::from(45454545));
        let wallet_2 = make_wallet("robinson_crusoe");
        let transaction_hash_2 = H256::from_uint(&U256::from(999888));
        let subject = DbInitializerReal::default();
        {
            let _ = subject
                .initialize_to_version(
                    &dir_path,
                    start_at,
                    DbInitializationConfig::create_or_migrate(make_external_data()),
                )
                .unwrap();
        }
        prepare_old_fashioned_account_with_pending_transaction_opt(
            &conn,
            Some(transaction_hash_1),
            &wallet_1,
            555555,
            SystemTime::now(),
        );
        prepare_old_fashioned_account_with_pending_transaction_opt(
            &conn,
            Some(transaction_hash_2),
            &wallet_2,
            1111111,
            from_time_t(200_000_000),
        );
        let config_table_before = fetch_all_from_config_table(&conn);

        let conn_schema5 = subject
            .initialize_to_version(
                &dir_path,
                start_at + 1,
                DbInitializationConfig::create_or_migrate(ExternalData::new(
                    TEST_DEFAULT_CHAIN,
                    NeighborhoodMode::ConsumeOnly,
                    Some("password".to_string()),
                )),
            )
            .unwrap();

        let config_table_after = fetch_all_from_config_table(&conn);
        assert_eq!(config_table_before, config_table_after);
        assert_on_schema_5_was_adopted(conn_schema5.as_ref());
        TestLogHandler::new().exists_log_containing("WARN: DbMigrator: Migration from 4 to 5: database belonging to the chain 'eth-ropsten'; \
         we discovered possibly abandoned transactions that are said yet to be pending, these are: \
          '0x0000000000000000000000000000000000000000000000000000000002b594d1', \
          '0x00000000000000000000000000000000000000000000000000000000000f41d0'; continuing");
    }

    fn assert_on_schema_5_was_adopted(conn_schema5: &dyn ConnectionWrapper) {
        let expected_key_words: &[&[&str]] = &[
            &["rowid", "integer", "primary", "key"],
            &["transaction_hash", "text", "not", "null"],
            &["amount", "integer", "not", "null"],
            &["payable_timestamp", "integer", "not", "null"],
            &["attempt", "integer", "not", "null"],
            &["process_error", "text", "null"],
        ];
        assert_create_table_stm_contains_all_parts(
            conn_schema5,
            "pending_payable",
            expected_key_words,
        );
        let expected_key_words: &[&[&str]] = &[&["transaction_hash"]];
        assert_index_stm_is_coupled_with_right_parameter(
            conn_schema5,
            "pending_payable_hash_idx",
            expected_key_words,
        );
        let expected_key_words: &[&[&str]] = &[
            &["wallet_address", "text", "primary", "key"],
            &["balance", "integer", "not", "null"],
            &["last_paid_timestamp", "integer", "not", "null"],
            &["pending_payable_rowid", "integer", "null"],
        ];
        assert_create_table_stm_contains_all_parts(conn_schema5, "payable", expected_key_words);
        let expected_key_words: &[&[&str]] = &[
            &["name", "text", "primary", "key"],
            &["value", "text"],
            &["encrypted", "integer", "not", "null"],
        ];
        assert_create_table_stm_contains_all_parts(conn_schema5, "config", expected_key_words);
        assert_no_index_exists_for_table(conn_schema5, "config");
        assert_no_index_exists_for_table(conn_schema5, "payable");
        assert_no_index_exists_for_table(conn_schema5, "receivable");
        assert_no_index_exists_for_table(conn_schema5, "banned");
        assert_table_does_not_exist(conn_schema5, "_config_old")
    }

    fn fetch_all_from_config_table(
        conn: &dyn ConnectionWrapper,
    ) -> Vec<(String, (Option<String>, bool))> {
        let mut stmt = conn
            .prepare("select name, value, encrypted from config")
            .unwrap();
        let mut hash_map_of_values = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    (
                        row.get::<usize, Option<String>>(1).unwrap(),
                        row.get::<usize, i64>(2)
                            .map(|encrypted: i64| encrypted > 0)
                            .unwrap(),
                    ),
                ))
            })
            .unwrap()
            .flatten()
            .collect::<HashMap<String, (Option<String>, bool)>>();
        hash_map_of_values.remove("schema_version").unwrap();
        let mut vec_of_values = hash_map_of_values.into_iter().collect_vec();
        vec_of_values.sort_by_key(|(name, _)| name.clone());
        vec_of_values
    }
}
