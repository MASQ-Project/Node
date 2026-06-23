// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::utils::VigilantRusqliteFlatten;
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::accountant::gwei_to_wei;
use crate::database::db_migrations::db_migrator::DatabaseMigration;
use crate::database::db_migrations::migrator_utils::{
    DBMigDeclarator, StatementObject, StatementWithRusqliteParams,
};
use crate::sub_lib::neighborhood::RatePack;
use itertools::Itertools;
use rusqlite::{Row, ToSql};

#[allow(non_camel_case_types)]
pub struct Migrate_6_to_7;

impl DatabaseMigration for Migrate_6_to_7 {
    fn migrate<'a>(&self, utils: Box<dyn DBMigDeclarator + 'a>) -> rusqlite::Result<()> {
        let mut migration_carrier = Migrate_6_to_7_carrier::new(utils.as_ref());
        migration_carrier.retype_table(
            "payable",
            "balance",
            "wallet_address text primary key,
                              balance_high_b integer not null,
                              balance_low_b integer not null,
                              last_paid_timestamp integer not null,
                              pending_payable_rowid integer null",
        )?;
        migration_carrier.retype_table(
            "receivable",
            "balance",
            "wallet_address text primary key,
                             balance_high_b integer not null,
                             balance_low_b integer not null,
                             last_received_timestamp integer not null",
        )?;
        migration_carrier.retype_table(
            "pending_payable",
            "amount",
            "rowid integer primary key,
                              transaction_hash text not null,
                              amount_high_b integer not null,
                              amount_low_b integer not null,
                              payable_timestamp integer not null,
                              attempt integer not null,
                              process_error text null",
        )?;

        migration_carrier.update_rate_pack();

        migration_carrier.utils.execute_upon_transaction(
            &migration_carrier
                .statements
                .iter()
                .map(|boxed| boxed.as_ref())
                .collect_vec(),
        )
    }

    fn old_version(&self) -> usize {
        6
    }
}

#[allow(non_camel_case_types)]
struct Migrate_6_to_7_carrier<'a> {
    utils: &'a (dyn DBMigDeclarator + 'a),
    statements: Vec<Box<dyn StatementObject>>,
}

impl<'a> Migrate_6_to_7_carrier<'a> {
    fn new(utils: &'a (dyn DBMigDeclarator + 'a)) -> Self {
        Self {
            utils,
            statements: vec![],
        }
    }

    fn retype_table(
        &mut self,
        table: &str,
        old_param_name_of_future_big_int: &str,
        create_new_table_stm: &str,
    ) -> rusqlite::Result<()> {
        self.utils.execute_upon_transaction(&[
            &format!("alter table {table} rename to _{table}_old"),
            &format!(
                "create table compensatory_{table} (old_rowid integer, high_bytes integer null, low_bytes integer null)"
            ),
            &format!("create table {table} ({create_new_table_stm}) strict"),
        ])?;
        let param_names = Self::extract_param_names(create_new_table_stm);
        self.maybe_compose_insert_stm_with_auxiliary_table_to_handle_new_big_int_data(
            table,
            old_param_name_of_future_big_int,
            param_names,
        );
        self.statements
            .push(Box::new(format!("drop table _{table}_old")));
        Ok(())
    }

    fn maybe_compose_insert_stm_with_auxiliary_table_to_handle_new_big_int_data(
        &mut self,
        table: &str,
        big_int_param_old_name: &str,
        param_names: Vec<String>,
    ) {
        let big_int_params_new_names = param_names
            .iter()
            .filter(|segment| segment.contains(big_int_param_old_name))
            .map(|name| name.to_owned())
            .collect::<Vec<String>>();
        let (easy_params, normal_params_prepared_for_inner_join) =
            Self::prepare_unchanged_params(param_names, &big_int_params_new_names);
        let future_big_int_values_including_old_rowids = self
            .utils
            .transaction()
            .prepare(&format!(
                "select rowid, {big_int_param_old_name} from _{table}_old",
            ))
            .expect("rusqlite internal error")
            .query_map([], |row: &Row| {
                let old_rowid = row.get(0).expect("rowid fetching error");
                let balance = row.get(1).expect("old param fetching error");
                Ok((old_rowid, balance))
            })
            .expect("map failed")
            .vigilant_flatten()
            .collect::<Vec<(i64, i64)>>();
        if !future_big_int_values_including_old_rowids.is_empty() {
            self.fill_compensatory_table(future_big_int_values_including_old_rowids, table);
            let new_big_int_params = big_int_params_new_names.join(", ");
            let final_insert_statement = format!(
                "insert into {table} ({easy_params}, {new_big_int_params}) select {normal_params_prepared_for_inner_join}, \
                 R.high_bytes, R.low_bytes from _{table}_old L inner join compensatory_{table} R where L.rowid = R.old_rowid",
            );
            self.statements.push(Box::new(final_insert_statement))
        } else {
            debug!(
                self.utils.logger(),
                "Migration from 6 to 7: no data to migrate in {}", table
            )
        };
    }

    fn prepare_unchanged_params(
        param_names_for_select_stm: Vec<String>,
        big_int_params_names: &[String],
    ) -> (String, String) {
        let easy_params_vec = param_names_for_select_stm
            .into_iter()
            .filter(|name| !big_int_params_names.contains(name))
            .collect_vec();
        let easy_params = easy_params_vec.iter().join(", ");
        let easy_params_preformatted_for_inner_join = easy_params_vec
            .into_iter()
            .map(|word| format!("L.{}", word.trim()))
            .join(", ");
        (easy_params, easy_params_preformatted_for_inner_join)
    }

    fn fill_compensatory_table(&mut self, all_big_int_values_found: Vec<(i64, i64)>, table: &str) {
        let sql_stm = format!(
            "insert into compensatory_{} (old_rowid, high_bytes, low_bytes) values {}",
            table,
            (0..all_big_int_values_found.len())
                .map(|_| "(?, ?, ?)")
                .collect::<String>()
        );
        let params = all_big_int_values_found
            .into_iter()
            .flat_map(|(old_rowid, i64_balance)| {
                let (high, low) = BigIntDivider::deconstruct(gwei_to_wei(i64_balance));
                vec![
                    Box::new(old_rowid) as Box<dyn ToSql>,
                    Box::new(high),
                    Box::new(low),
                ]
            })
            .collect::<Vec<Box<dyn ToSql>>>();
        let statement = StatementWithRusqliteParams { sql_stm, params };
        self.statements.push(Box::new(statement));
    }

    fn extract_param_names(table_creation_lines: &str) -> Vec<String> {
        table_creation_lines
            .split(',')
            .map(|line| {
                let line = line.trim_start();
                line.chars()
                    .take_while(|char| !char.is_whitespace())
                    .collect::<String>()
            })
            .collect()
    }

    fn update_rate_pack(&mut self) {
        let transaction = self.utils.transaction();
        let mut stm = transaction
            .prepare("select value from config where name = 'rate_pack'")
            .expect("stm preparation failed");
        let old_rate_pack = stm
            .query_row([], |row| row.get::<usize, String>(0))
            .expect("row query failed");
        let old_rate_pack_as_native =
            RatePack::try_from(old_rate_pack.as_str()).unwrap_or_else(|_| {
                panic!(
                    "rate pack conversion failed with value: {}; database corrupt!",
                    old_rate_pack
                )
            });
        let new_rate_pack = RatePack {
            routing_byte_rate: gwei_to_wei(old_rate_pack_as_native.routing_byte_rate),
            routing_service_rate: gwei_to_wei(old_rate_pack_as_native.routing_service_rate),
            exit_byte_rate: gwei_to_wei(old_rate_pack_as_native.exit_byte_rate),
            exit_service_rate: gwei_to_wei(old_rate_pack_as_native.exit_service_rate),
        };
        let serialized_rate_pack = new_rate_pack.to_string();
        let params: Vec<Box<dyn ToSql>> = vec![Box::new(serialized_rate_pack)];

        self.statements.push(Box::new(StatementWithRusqliteParams {
            sql_stm: "update config set value = ? where name = 'rate_pack'".to_string(),
            params,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::db_migrations::db_migrator::{DbMigrator, DbMigratorReal};
    use crate::database::rusqlite_wrappers::ConnectionWrapper;
    use crate::db_config::persistent_configuration::{
        PersistentConfiguration, PersistentConfigurationReal,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::database_utils::{
        assert_table_created_as_strict, bring_db_0_back_to_life_and_return_connection,
        make_external_data, retrieve_config_row,
    };
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::Row;
    use std::str::FromStr;

    #[test]
    fn migration_from_6_to_7_works() {
        let dir_path =
            ensure_node_home_directory_exists("db_migrations", "migration_from_6_to_7_works");
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        let pre_db_conn = subject
            .initialize_to_version(
                &dir_path,
                6,
                DbInitializationConfig::create_or_migrate(make_external_data()),
            )
            .unwrap();
        insert_value(&*pre_db_conn,"insert into payable (wallet_address, balance, last_paid_timestamp, pending_payable_rowid) \
         values (\"0xD7d1b2cF58f6500c7CB22fCA42B8512d06813a03\", 56784545484899, 11111, null)");
        insert_value(
            &*pre_db_conn,
            "insert into receivable (wallet_address, balance, last_received_timestamp) \
             values (\"0xD2d1b2eF58f6500c7ae22fCA42B8512d06813a03\",-56784,22222)",
        );
        insert_value(&*pre_db_conn,"insert into pending_payable (rowid, transaction_hash, amount, payable_timestamp,attempt, process_error) \
         values (5, \"0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f222a4bc8cd032f768fc5219838\" ,9123 ,33333 ,1 ,null)");
        let mut persistent_config = PersistentConfigurationReal::from(pre_db_conn);
        let old_rate_pack_in_gwei = "44|50|20|32".to_string();
        persistent_config
            .set_rate_pack(old_rate_pack_in_gwei.clone())
            .unwrap();

        let conn = subject
            .initialize_to_version(
                &dir_path,
                7,
                DbInitializationConfig::create_or_migrate(make_external_data()),
            )
            .unwrap();

        assert_table_created_as_strict(&*conn, "payable");
        assert_table_created_as_strict(&*conn, "receivable");
        let select_sql = "select wallet_address, balance_high_b, balance_low_b, last_paid_timestamp, pending_payable_rowid from payable";
        query_rows_helper(&*conn, select_sql, |row| {
            assert_eq!(
                row.get::<usize, Wallet>(0).unwrap(),
                Wallet::from_str("0xD7d1b2cF58f6500c7CB22fCA42B8512d06813a03").unwrap()
            );
            assert_eq!(row.get::<usize, i64>(1).unwrap(), 6156);
            assert_eq!(row.get::<usize, i64>(2).unwrap(), 5467226021000125952);
            assert_eq!(row.get::<usize, i64>(3).unwrap(), 11111);
            assert_eq!(row.get::<usize, Option<i64>>(4).unwrap(), None);
            Ok(())
        });
        let select_sql = "select wallet_address, balance_high_b, balance_low_b, last_received_timestamp from receivable";
        query_rows_helper(&*conn, select_sql, |row| {
            assert_eq!(
                row.get::<usize, Wallet>(0).unwrap(),
                Wallet::from_str("0xD2d1b2eF58f6500c7ae22fCA42B8512d06813a03").unwrap()
            );
            assert_eq!(row.get::<usize, i64>(1).unwrap(), -1);
            assert_eq!(row.get::<usize, i64>(2).unwrap(), 9223315252854775808);
            assert_eq!(row.get::<usize, i64>(3).unwrap(), 22222);
            Ok(())
        });
        let select_sql = "select rowid, transaction_hash, amount_high_b, amount_low_b, payable_timestamp, attempt, process_error from pending_payable";
        query_rows_helper(&*conn, select_sql, |row| {
            assert_eq!(row.get::<usize, i64>(0).unwrap(), 5);
            assert_eq!(
                row.get::<usize, String>(1).unwrap(),
                "0xb5c8bd9430b6cc87a0e2fe110ece6bf527fa4f222a4bc8cd032f768fc5219838".to_string()
            );
            assert_eq!(row.get::<usize, i64>(2).unwrap(), 0);
            assert_eq!(row.get::<usize, i64>(3).unwrap(), 9123000000000);
            assert_eq!(row.get::<usize, i64>(4).unwrap(), 33333);
            assert_eq!(row.get::<usize, i64>(5).unwrap(), 1);
            assert_eq!(row.get::<usize, Option<String>>(6).unwrap(), None);
            Ok(())
        });
        let (rate_pack, encrypted) = retrieve_config_row(&*conn, "rate_pack");
        assert_eq!(
            rate_pack,
            Some("44000000000|50000000000|20000000000|32000000000".to_string())
        );
        assert_eq!(encrypted, false);
    }

    #[test]
    fn migration_from_6_to_7_without_any_data() {
        init_test_logging();
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_6_to_7_without_any_data",
        );
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        let conn = subject
            .initialize_to_version(
                &dir_path,
                6,
                DbInitializationConfig::create_or_migrate(make_external_data()),
            )
            .unwrap();
        let subject = DbMigratorReal::new(make_external_data());

        subject.migrate_database(6, 7, conn).unwrap();

        let test_log_handler = TestLogHandler::new();
        ["payable", "receivable", "pending_payable"]
            .iter()
            .for_each(|table_name| {
                test_log_handler.exists_log_containing(&format!(
                    "DEBUG: DbMigrator: Migration from 6 to 7: no data to migrate in {table_name}"
                ));
            })
    }

    fn insert_value(conn: &dyn ConnectionWrapper, insert_stm: &str) {
        let mut statement = conn.prepare(insert_stm).unwrap();
        statement.execute([]).unwrap();
    }

    fn query_rows_helper(
        conn: &dyn ConnectionWrapper,
        sql: &str,
        expected_typed_values: fn(&Row) -> rusqlite::Result<()>,
    ) {
        let mut statement = conn.prepare(sql).unwrap();
        statement.query_row([], expected_typed_values).unwrap();
    }
}
