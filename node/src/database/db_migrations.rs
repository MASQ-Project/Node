// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::bip39::Bip39;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use crate::db_config::db_encryption_layer::DbEncryptionLayer;
use crate::db_config::typed_config_layer::decode_bytes;
use crate::sub_lib::cryptde::PlainData;
use itertools::Itertools;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
#[cfg(test)]
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use masq_lib::utils::{ExpectValue, NeighborhoodModeLight, WrapResult};
use rusqlite::{Error, Transaction};
use std::fmt::Debug;
use tiny_hderive::bip32::ExtendedPrivKey;

pub trait DbMigrator {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String>;
}

pub struct DbMigratorReal {
    external: ExternalData,
    logger: Logger,
}

impl DbMigrator for DbMigratorReal {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        mut conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        let migrator_config = DBMigratorInnerConfiguration::new();
        let migration_utils = match DBMigrationUtilitiesReal::new(&mut *conn, migrator_config) {
            Err(e) => return Err(e.to_string()),
            Ok(utils) => utils,
        };
        self.initiate_migrations(
            mismatched_schema,
            target_version,
            Box::new(migration_utils),
            Self::list_of_migrations(),
        )
    }
}

trait DatabaseMigration: Debug {
    fn migrate<'a>(
        &self,
        mig_declaration_utilities: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()>;
    fn old_version(&self) -> usize;
}

trait MigDeclarationUtilities {
    fn db_password(&self) -> Option<String>;
    fn transaction(&self) -> &Transaction;
    fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()>;
    fn external_parameters(&self) -> &ExternalData;
    fn logger(&self) -> &Logger;
}

trait DBMigrationUtilities {
    fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()>;

    fn commit(&mut self) -> Result<(), String>;

    fn make_mig_declaration_utils<'a>(
        &'a self,
        external: &'a ExternalData,
        logger: &'a Logger,
    ) -> Box<dyn MigDeclarationUtilities + 'a>;

    fn too_high_schema_panics(&self, mismatched_schema: usize);
}

struct DBMigrationUtilitiesReal<'a> {
    root_transaction: Option<Transaction<'a>>,
    db_migrator_configuration: DBMigratorInnerConfiguration,
}

impl<'a> DBMigrationUtilitiesReal<'a> {
    fn new<'b: 'a>(
        conn: &'b mut dyn ConnectionWrapper,
        db_migrator_configuration: DBMigratorInnerConfiguration,
    ) -> rusqlite::Result<Self> {
        Self {
            root_transaction: Some(conn.transaction()?),
            db_migrator_configuration,
        }
        .wrap_to_ok()
    }

    fn root_transaction_ref(&self) -> &Transaction<'a> {
        self.root_transaction.as_ref().expectv("root transaction")
    }
}

impl<'a> DBMigrationUtilities for DBMigrationUtilitiesReal<'a> {
    fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()> {
        DbMigratorReal::update_schema_version(
            self.db_migrator_configuration
                .db_configuration_table
                .as_str(),
            self.root_transaction_ref(),
            update_to,
        )
    }

    fn commit(&mut self) -> Result<(), String> {
        self.root_transaction
            .take()
            .expectv("owned root transaction")
            .commit()
            .map_err(|e| e.to_string())
    }

    fn make_mig_declaration_utils<'b>(
        &'b self,
        external: &'b ExternalData,
        logger: &'b Logger,
    ) -> Box<dyn MigDeclarationUtilities + 'b> {
        Box::new(MigDeclarationUtilitiesReal::new(
            self.root_transaction_ref(),
            external,
            logger,
        ))
    }

    fn too_high_schema_panics(&self, mismatched_schema: usize) {
        if mismatched_schema > self.db_migrator_configuration.current_schema_version {
            panic!(
                "Database claims to be more advanced ({}) than the version {} which is the latest \
             version this Node knows about.",
                mismatched_schema, CURRENT_SCHEMA_VERSION
            )
        }
    }
}

struct MigDeclarationUtilitiesReal<'a> {
    root_transaction_ref: &'a Transaction<'a>,
    external: &'a ExternalData,
    logger: &'a Logger,
}

impl<'a> MigDeclarationUtilitiesReal<'a> {
    fn new(
        root_transaction_ref: &'a Transaction<'a>,
        external: &'a ExternalData,
        logger: &'a Logger,
    ) -> Self {
        Self {
            root_transaction_ref,
            external,
            logger,
        }
    }
}

impl MigDeclarationUtilities for MigDeclarationUtilitiesReal<'_> {
    fn db_password(&self) -> Option<String> {
        self.external.db_password_opt.clone()
    }

    fn transaction(&self) -> &Transaction {
        self.root_transaction_ref
    }

    fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()> {
        let transaction = self.root_transaction_ref;
        sql_statements.iter().fold(Ok(()), |so_far, stm| {
            if so_far.is_ok() {
                match transaction.execute(stm, []) {
                    Ok(_) => Ok(()),
                    Err(e) if e == Error::ExecuteReturnedResults => Ok(()),
                    Err(e) => Err(e),
                }
            } else {
                so_far
            }
        })
    }

    fn external_parameters(&self) -> &ExternalData {
        self.external
    }

    fn logger(&self) -> &Logger {
        self.logger
    }
}

struct DBMigratorInnerConfiguration {
    db_configuration_table: String,
    current_schema_version: usize,
}

impl DBMigratorInnerConfiguration {
    fn new() -> Self {
        DBMigratorInnerConfiguration {
            db_configuration_table: "config".to_string(),
            current_schema_version: CURRENT_SCHEMA_VERSION,
        }
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_0_to_1;

impl DatabaseMigration for Migrate_0_to_1 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        declaration_utils.execute_upon_transaction(&[
            "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
        ])
    }

    fn old_version(&self) -> usize {
        0
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_1_to_2;

impl DatabaseMigration for Migrate_1_to_2 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        let statement = format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('chain_name', '{}', 0)",
            declaration_utils
                .external_parameters()
                .chain
                .rec()
                .literal_identifier
        );
        declaration_utils.execute_upon_transaction(&[statement.as_str()])
    }

    fn old_version(&self) -> usize {
        1
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_2_to_3;

impl DatabaseMigration for Migrate_2_to_3 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        let statement_1 =
            "INSERT INTO config (name, value, encrypted) VALUES ('blockchain_service_url', null, 0)";
        let statement_2 = format!(
            "INSERT INTO config (name, value, encrypted) VALUES ('neighborhood_mode', '{}', 0)",
            declaration_utils.external_parameters().neighborhood_mode
        );
        declaration_utils.execute_upon_transaction(&[statement_1, statement_2.as_str()])
    }

    fn old_version(&self) -> usize {
        2
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_3_to_4;

impl DatabaseMigration for Migrate_3_to_4 {
    fn migrate<'a>(&self, utils: Box<dyn MigDeclarationUtilities + 'a>) -> rusqlite::Result<()> {
        let transaction = utils.transaction();
        let mut stmt = transaction
            .prepare("select name, value from config where name in ('example_encrypted', 'seed', 'consuming_wallet_derivation_path') order by name")
            .expect("Internal error");

        let rows = stmt
            .query_map([], |row| {
                let name = row.get::<usize, String>(0).expect("Internal error");
                let value_opt = row.get::<usize, Option<String>>(1).expect("Internal error");
                Ok((name, value_opt))
            })
            .expect("Database is corrupt")
            .map(|r| r.unwrap())
            .collect::<Vec<(String, Option<String>)>>();
        if rows.iter().map(|r| r.0.as_str()).collect_vec()
            != vec![
                "consuming_wallet_derivation_path",
                "example_encrypted",
                "seed",
            ]
        {
            panic!("Database is corrupt");
        }
        let consuming_path_opt = rows[0].1.clone();
        let example_encrypted = rows[1].1.clone();
        let seed_encrypted = rows[2].1.clone();
        let private_key_encoded = match (consuming_path_opt, example_encrypted, seed_encrypted) {
            (Some(consuming_path), Some(example_encrypted), Some(seed_encrypted)) => {
                let password_opt = utils.db_password();
                if !DbEncryptionLayer::password_matches(&password_opt, &Some(example_encrypted)) {
                    panic!("Bad password");
                }
                let seed_encoded =
                    DbEncryptionLayer::decrypt_value(&Some(seed_encrypted), &password_opt, "seed")
                        .expect("Internal error")
                        .expect("Internal error");
                let seed_data = decode_bytes(Some(seed_encoded))
                    .expect("Internal error")
                    .expect("Internal error");
                let extended_private_key =
                    ExtendedPrivKey::derive(seed_data.as_ref(), consuming_path.as_str())
                        .expect("Internal error");
                let private_key_data = PlainData::new(&extended_private_key.secret());
                Some(
                    Bip39::encrypt_bytes(
                        &private_key_data.as_slice(),
                        password_opt.as_ref().expect("Test-drive me!"),
                    )
                    .expect("Internal error: encryption failed"),
                )
            }
            _ => None,
        };
        let private_key_column = if let Some(private_key) = private_key_encoded {
            format!("'{}'", private_key)
        } else {
            "null".to_string()
        };
        utils.execute_upon_transaction(&[
            format! ("insert into config (name, value, encrypted) values ('consuming_wallet_private_key', {}, 1)",
                private_key_column).as_str(),
            "delete from config where name in ('seed', 'consuming_wallet_derivation_path', 'consuming_wallet_public_key')",
        ])
    }

    fn old_version(&self) -> usize {
        3
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_4_to_5;

impl DatabaseMigration for Migrate_4_to_5 {
    fn migrate<'a>(
        &self,
        declaration_utils: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        let mut select_statement = declaration_utils
            .transaction()
            .prepare("select pending_payment_transaction from payable where pending_payment_transaction is not null")?;
        let unresolved_pending_transactions: Vec<String> = select_statement
            .query_map([], |row| {
                Ok(row
                    .get::<usize, String>(0)
                    .expect("select statement was badly prepared"))
            })?
            .flatten()
            .collect();
        if !unresolved_pending_transactions.is_empty() {
            warning!(declaration_utils.logger(),"Migration from 4 to 5: database belonging to the chain '{}'; \
             we discovered possibly abandoned transactions that are said yet to be pending, these are: '{}'; \
              continuing",declaration_utils.external_parameters().chain.rec().literal_identifier,unresolved_pending_transactions.join("', '") )
        } else {
            debug!(
                declaration_utils.logger(),
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
        declaration_utils.execute_upon_transaction(&[
            statement_1,
            statement_2,
            statement_3,
            statement_4,
            statement_5,
            statement_6,
            statement_7,
            statement_8,
            statement_9,
            statement_10,
            statement_11,
        ])
    }

    fn old_version(&self) -> usize {
        4
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

impl DbMigratorReal {
    pub fn new(external: ExternalData) -> Self {
        Self {
            external,
            logger: Logger::new("DbMigrator"),
        }
    }

    fn list_of_migrations<'a>() -> &'a [&'a dyn DatabaseMigration] {
        &[
            &Migrate_0_to_1,
            &Migrate_1_to_2,
            &Migrate_2_to_3,
            &Migrate_3_to_4,
            &Migrate_4_to_5,
        ]
    }

    fn initiate_migrations<'a>(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        mut migration_utilities: Box<dyn DBMigrationUtilities + 'a>,
        list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<(), String> {
        let migrations_to_process = Self::select_migrations_to_process(
            mismatched_schema,
            list_of_migrations,
            target_version,
            &*migration_utilities,
        );
        for record in migrations_to_process {
            let present_db_version = record.old_version();
            if let Err(e) = self.migrate_semi_automated(record, &*migration_utilities, &self.logger)
            {
                return self.dispatch_bad_news(present_db_version, e);
            }
            self.log_success(present_db_version)
        }
        migration_utilities.commit()
    }

    fn migrate_semi_automated<'a>(
        &self,
        record: &dyn DatabaseMigration,
        migration_utilities: &'a (dyn DBMigrationUtilities + 'a),
        logger: &'a Logger,
    ) -> rusqlite::Result<()> {
        info!(
            &self.logger,
            "Migrating from version {} to version {}",
            record.old_version(),
            record.old_version() + 1
        );
        record.migrate(migration_utilities.make_mig_declaration_utils(&self.external, logger))?;
        let migrate_to = record.old_version() + 1;
        migration_utilities.update_schema_version(migrate_to)
    }

    fn update_schema_version(
        name_of_given_table: &str,
        transaction: &Transaction,
        update_to: usize,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            &format!(
                "UPDATE {} SET value = {} WHERE name = 'schema_version'",
                name_of_given_table, update_to
            ),
            [],
        )?;
        Ok(())
    }

    fn select_migrations_to_process<'a>(
        mismatched_schema: usize,
        list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)],
        target_version: usize,
        mig_utils: &dyn DBMigrationUtilities,
    ) -> Vec<&'a (dyn DatabaseMigration + 'a)> {
        mig_utils.too_high_schema_panics(mismatched_schema);
        list_of_migrations
            .iter()
            .skip_while(|entry| entry.old_version() != mismatched_schema)
            .take_while(|entry| entry.old_version() < target_version)
            .map(Self::deref)
            .collect::<Vec<&(dyn DatabaseMigration + 'a)>>()
    }

    fn deref<'a, T: ?Sized>(value: &'a &T) -> &'a T {
        *value
    }

    fn dispatch_bad_news(
        &self,
        current_version: usize,
        error: rusqlite::Error,
    ) -> Result<(), String> {
        let error_message = format!(
            "Migrating database from version {} to {} failed: {:?}",
            current_version,
            current_version + 1,
            error
        );
        error!(self.logger, "{}", &error_message);
        Err(error_message)
    }

    fn log_success(&self, previous_version: usize) {
        info!(
            self.logger,
            "Database successfully migrated from version {} to {}",
            previous_version,
            previous_version + 1
        )
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct MigratorConfig {
    pub should_be_suppressed: Suppression,
    pub external_dataset: Option<ExternalData>,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Suppression {
    No,
    Yes,
    WithErr,
}

impl MigratorConfig {
    pub fn panic_on_migration() -> Self {
        Self {
            should_be_suppressed: Suppression::No,
            external_dataset: None,
        }
    }

    pub fn create_or_migrate(external_params: ExternalData) -> Self {
        //is used also if a fresh db is being created
        Self {
            should_be_suppressed: Suppression::No,
            external_dataset: Some(external_params),
        }
    }

    pub fn migration_suppressed() -> Self {
        Self {
            should_be_suppressed: Suppression::Yes,
            external_dataset: None,
        }
    }

    pub fn migration_suppressed_with_error() -> Self {
        Self {
            should_be_suppressed: Suppression::WithErr,
            external_dataset: None,
        }
    }

    #[cfg(test)]
    pub fn test_default() -> Self {
        Self {
            should_be_suppressed: Suppression::Yes,
            external_dataset: Some(ExternalData {
                chain: TEST_DEFAULT_CHAIN,
                neighborhood_mode: NeighborhoodModeLight::Standard,
                db_password_opt: None,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalData {
    pub chain: Chain,
    pub neighborhood_mode: NeighborhoodModeLight,
    pub db_password_opt: Option<String>,
}

impl ExternalData {
    pub fn new(
        chain: Chain,
        neighborhood_mode: NeighborhoodModeLight,
        db_password_opt: Option<String>,
    ) -> Self {
        Self {
            chain,
            neighborhood_mode,
            db_password_opt,
        }
    }
}

impl From<(MigratorConfig, bool)> for ExternalData {
    fn from(tuple: (MigratorConfig, bool)) -> Self {
        let (migrator_config, db_newly_created) = tuple;
        migrator_config.external_dataset.unwrap_or_else(|| {
            panic!(
                "{}",
                if db_newly_created {
                    "Attempt to create a new database without proper configuration"
                } else {
                    "Attempt to migrate the database at an inappropriate place"
                }
            )
        })
    }
}

#[derive(Debug)]
struct InterimMigrationPlaceholder(usize);

impl DatabaseMigration for InterimMigrationPlaceholder {
    fn migrate<'a>(
        &self,
        _mig_declaration_utilities: Box<dyn MigDeclarationUtilities + 'a>,
    ) -> rusqlite::Result<()> {
        Ok(())
    }

    fn old_version(&self) -> usize {
        self.0 - 1
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::bip39::Bip39;
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION, DATABASE_FILE,
    };
    use crate::database::db_migrations::{
        DBMigrationUtilities, DBMigrationUtilitiesReal, DatabaseMigration, DbMigrator,
        ExternalData, MigDeclarationUtilities, Migrate_0_to_1, MigratorConfig, Suppression,
    };
    use crate::database::db_migrations::{DBMigratorInnerConfiguration, DbMigratorReal};
    use crate::db_config::db_encryption_layer::DbEncryptionLayer;
    use crate::db_config::typed_config_layer::encode_bytes;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::database_utils::retrieve_config_row;
    use crate::test_utils::database_utils::{
        assert_create_table_statement_contains_all_important_parts,
        assert_index_statement_is_coupled_with_right_parameter, assert_no_index_exists_for_table,
        bring_db_0_back_to_life_and_return_connection,
    };
    use crate::test_utils::make_wallet;
    use bip39::{Language, Mnemonic, MnemonicType, Seed};
    use ethereum_types::BigEndianHash;
    use itertools::Itertools;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use masq_lib::utils::{derivation_path, NeighborhoodModeLight};
    use rand::Rng;
    use rusqlite::types::Value::Null;
    use rusqlite::{Connection, Error, OptionalExtension, ToSql, Transaction};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::fs::create_dir_all;
    use std::iter::once;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use tiny_hderive::bip32::ExtendedPrivKey;
    use web3::types::{H256, U256};

    #[derive(Default)]
    struct DBMigrationUtilitiesMock {
        too_high_found_schema_will_panic_params: Arc<Mutex<Vec<usize>>>,
        make_mig_declaration_utils_params: Arc<Mutex<Vec<ExternalData>>>,
        make_mig_declaration_utils_results: RefCell<Vec<Box<dyn MigDeclarationUtilities>>>,
        update_schema_version_params: Arc<Mutex<Vec<usize>>>,
        update_schema_version_results: RefCell<Vec<rusqlite::Result<()>>>,
        commit_results: RefCell<Vec<Result<(), String>>>,
    }

    impl DBMigrationUtilitiesMock {
        pub fn update_schema_version_params(mut self, params: &Arc<Mutex<Vec<usize>>>) -> Self {
            self.update_schema_version_params = params.clone();
            self
        }

        pub fn update_schema_version_result(self, result: rusqlite::Result<()>) -> Self {
            self.update_schema_version_results.borrow_mut().push(result);
            self
        }

        pub fn commit_result(self, result: Result<(), String>) -> Self {
            self.commit_results.borrow_mut().push(result);
            self
        }

        pub fn make_mig_declaration_utils_params(
            mut self,
            params: &Arc<Mutex<Vec<ExternalData>>>,
        ) -> Self {
            self.make_mig_declaration_utils_params = params.clone();
            self
        }

        pub fn make_mig_declaration_utils_result(
            self,
            result: Box<dyn MigDeclarationUtilities>,
        ) -> Self {
            self.make_mig_declaration_utils_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    impl DBMigrationUtilities for DBMigrationUtilitiesMock {
        fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()> {
            self.update_schema_version_params
                .lock()
                .unwrap()
                .push(update_to);
            self.update_schema_version_results.borrow_mut().remove(0)
        }

        fn commit(&mut self) -> Result<(), String> {
            self.commit_results.borrow_mut().remove(0)
        }

        fn make_mig_declaration_utils<'a>(
            &'a self,
            external: &'a ExternalData,
            _logger: &'a Logger,
        ) -> Box<dyn MigDeclarationUtilities + 'a> {
            self.make_mig_declaration_utils_params
                .lock()
                .unwrap()
                .push(external.clone());
            self.make_mig_declaration_utils_results
                .borrow_mut()
                .remove(0)
        }

        fn too_high_schema_panics(&self, mismatched_schema: usize) {
            self.too_high_found_schema_will_panic_params
                .lock()
                .unwrap()
                .push(mismatched_schema);
        }
    }

    #[derive(Default)]
    struct DBMigrateDeclarationUtilitiesMock {
        db_password_results: RefCell<Vec<Option<String>>>,
        execute_upon_transaction_params: Arc<Mutex<Vec<Vec<String>>>>,
        execute_upon_transaction_results: RefCell<Vec<rusqlite::Result<()>>>,
    }

    impl DBMigrateDeclarationUtilitiesMock {
        #[allow(dead_code)]
        pub fn db_password_result(self, result: Option<String>) -> Self {
            self.db_password_results.borrow_mut().push(result);
            self
        }

        pub fn execute_upon_transaction_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.execute_upon_transaction_params = params.clone();
            self
        }

        pub fn execute_upon_transaction_result(self, result: rusqlite::Result<()>) -> Self {
            self.execute_upon_transaction_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    impl MigDeclarationUtilities for DBMigrateDeclarationUtilitiesMock {
        fn db_password(&self) -> Option<String> {
            self.db_password_results.borrow_mut().remove(0)
        }

        fn transaction(&self) -> &Transaction {
            unimplemented!("Not needed so far")
        }

        fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()> {
            self.execute_upon_transaction_params.lock().unwrap().push(
                sql_statements
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
            );
            self.execute_upon_transaction_results.borrow_mut().remove(0)
        }

        fn external_parameters(&self) -> &ExternalData {
            unimplemented!("Not needed so far")
        }

        fn logger(&self) -> &Logger {
            unimplemented!("Not needed so far")
        }
    }

    fn make_external_migration_parameters() -> ExternalData {
        ExternalData {
            chain: TEST_DEFAULT_CHAIN,
            neighborhood_mode: NeighborhoodModeLight::Standard,
            db_password_opt: None,
        }
    }

    #[test]
    fn panic_on_migration_properly_set() {
        assert_eq!(
            MigratorConfig::panic_on_migration(),
            MigratorConfig {
                should_be_suppressed: Suppression::No,
                external_dataset: None
            }
        )
    }

    #[test]
    fn create_or_migrate_properly_set() {
        assert_eq!(
            MigratorConfig::create_or_migrate(make_external_migration_parameters()),
            MigratorConfig {
                should_be_suppressed: Suppression::No,
                external_dataset: Some(make_external_migration_parameters())
            }
        )
    }

    #[test]
    fn migration_suppressed_properly_set() {
        assert_eq!(
            MigratorConfig::migration_suppressed(),
            MigratorConfig {
                should_be_suppressed: Suppression::Yes,
                external_dataset: None
            }
        )
    }

    #[test]
    fn suppressed_with_error_properly_set() {
        assert_eq!(
            MigratorConfig::migration_suppressed_with_error(),
            MigratorConfig {
                should_be_suppressed: Suppression::WithErr,
                external_dataset: None
            }
        )
    }

    #[test]
    fn migrate_database_handles_an_error_from_creating_the_root_transaction() {
        let subject = DbMigratorReal::new(make_external_migration_parameters());
        let mismatched_schema = 0;
        let target_version = 5; //irrelevant
        let connection = ConnectionWrapperMock::default()
            .transaction_result(Err(Error::SqliteSingleThreadedMode)); //hard to find a real-like error for this

        let result =
            subject.migrate_database(mismatched_schema, target_version, Box::new(connection));

        assert_eq!(
            result,
            Err("SQLite was compiled or configured for single-threaded use only".to_string())
        )
    }

    #[test]
    fn initiate_migrations_panics_if_the_schema_is_of_higher_number_than_the_latest_official() {
        let last_version = CURRENT_SCHEMA_VERSION;
        let too_advanced = last_version + 1;
        let connection = Connection::open_in_memory().unwrap();
        let mut conn_wrapper = ConnectionWrapperReal::new(connection);
        let mig_config = DBMigratorInnerConfiguration::new();
        let migration_utilities =
            DBMigrationUtilitiesReal::new(&mut conn_wrapper, mig_config).unwrap();
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let captured_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.initiate_migrations(
                too_advanced,
                CURRENT_SCHEMA_VERSION,
                Box::new(migration_utilities),
                DbMigratorReal::list_of_migrations(),
            )
        }))
        .unwrap_err();

        let panic_message = captured_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            *panic_message,
            format!(
                "Database claims to be more advanced ({}) than the version {} which \
         is the latest version this Node knows about.",
                too_advanced, CURRENT_SCHEMA_VERSION
            )
        )
    }

    #[derive(Default, Debug)]
    struct DBMigrationRecordMock {
        old_version_result: RefCell<usize>,
        migrate_params: Arc<Mutex<Vec<()>>>,
        migrate_result: RefCell<Vec<rusqlite::Result<()>>>,
    }

    impl DBMigrationRecordMock {
        fn old_version_result(self, result: usize) -> Self {
            self.old_version_result.replace(result);
            self
        }

        fn migrate_result(self, result: rusqlite::Result<()>) -> Self {
            self.migrate_result.borrow_mut().push(result);
            self
        }

        fn migrate_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.migrate_params = params.clone();
            self
        }

        fn set_up_necessary_stuff_for_mocked_migration_record(
            self,
            result_o_v: usize,
            result_m: rusqlite::Result<()>,
            params_m: &Arc<Mutex<Vec<()>>>,
        ) -> Self {
            self.old_version_result(result_o_v)
                .migrate_result(result_m)
                .migrate_params(params_m)
        }
    }

    impl DatabaseMigration for DBMigrationRecordMock {
        fn migrate<'a>(
            &self,
            _migration_utilities: Box<dyn MigDeclarationUtilities + 'a>,
        ) -> rusqlite::Result<()> {
            self.migrate_params.lock().unwrap().push(());
            self.migrate_result.borrow_mut().remove(0)
        }

        fn old_version(&self) -> usize {
            *self.old_version_result.borrow()
        }
    }

    #[test]
    #[should_panic(expected = "The list of database migrations is not ordered properly")]
    fn list_validation_check_works_for_badly_ordered_migrations_when_inside() {
        let fake_one = DBMigrationRecordMock::default().old_version_result(6);
        let fake_two = DBMigrationRecordMock::default().old_version_result(2);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    #[test]
    #[should_panic(expected = "The list of database migrations is not ordered properly")]
    fn list_validation_check_works_for_badly_ordered_migrations_when_at_the_end() {
        let fake_one = DBMigrationRecordMock::default().old_version_result(1);
        let fake_two = DBMigrationRecordMock::default().old_version_result(3);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    fn list_validation_check<'a>(list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)]) {
        let begins_at_version = list_of_migrations[0].old_version();
        let iterator = list_of_migrations.iter();
        let ending_sentinel = &DBMigrationRecordMock::default()
            .old_version_result(begins_at_version + iterator.len())
            as &dyn DatabaseMigration;
        let iterator_shifted = list_of_migrations
            .iter()
            .skip(1)
            .chain(once(&ending_sentinel));
        iterator.zip(iterator_shifted).for_each(|(first, second)| {
            assert!(
                two_numbers_are_sequential(first.old_version(), second.old_version()),
                "The list of database migrations is not ordered properly"
            )
        });
    }

    fn two_numbers_are_sequential(first: usize, second: usize) -> bool {
        (first + 1) == second
    }

    #[test]
    fn list_of_migrations_is_correctly_ordered() {
        let _ = list_validation_check(DbMigratorReal::list_of_migrations());
        //success if no panicking
    }

    #[test]
    fn list_of_migrations_ends_on_the_current_version() {
        let last_entry = DbMigratorReal::list_of_migrations().into_iter().last();

        let result = last_entry.unwrap().old_version();

        assert!(two_numbers_are_sequential(result, CURRENT_SCHEMA_VERSION))
    }

    #[test]
    fn migrate_semi_automated_returns_an_error_from_update_schema_version() {
        let update_schema_version_params_arc = Arc::new(Mutex::new(vec![]));
        let mut migration_record = DBMigrationRecordMock::default()
            .old_version_result(4)
            .migrate_result(Ok(()));
        let migration_utilities = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_result(Box::new(
                DBMigrateDeclarationUtilitiesMock::default(),
            ))
            .update_schema_version_result(Err(Error::InvalidQuery))
            .update_schema_version_params(&update_schema_version_params_arc);
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.migrate_semi_automated(
            &mut migration_record,
            &migration_utilities,
            &Logger::new("test logger"),
        );

        assert_eq!(result, Err(Error::InvalidQuery));
        let update_schema_version_params = update_schema_version_params_arc.lock().unwrap();
        assert_eq!(*update_schema_version_params, vec![5]) //doesn't mean the state really changed, this is just an image of the supplied params
    }

    #[test]
    fn initiate_migrations_returns_an_error_from_migrate() {
        init_test_logging();
        let list = &[&DBMigrationRecordMock::default()
            .old_version_result(0)
            .migrate_result(Err(Error::InvalidColumnIndex(5)))
            as &dyn DatabaseMigration];
        let migrate_declaration_utils = DBMigrateDeclarationUtilitiesMock::default();
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_result(Box::new(migrate_declaration_utils));
        let mismatched_schema = 0;
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.initiate_migrations(
            mismatched_schema,
            target_version,
            Box::new(migration_utils),
            list,
        );

        assert_eq!(
            result,
            Err(
                r#"Migrating database from version 0 to 1 failed: InvalidColumnIndex(5)"#
                    .to_string()
            )
        );
        TestLogHandler::new().exists_log_containing(
            r#"ERROR: DbMigrator: Migrating database from version 0 to 1 failed: InvalidColumnIndex(5)"#,
        );
    }

    #[test]
    fn db_password_works() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "db_password_works");
        let db_path = dir_path.join("test_database.db");
        let mut connection_wrapper =
            ConnectionWrapperReal::new(Connection::open(&db_path).unwrap());
        let utils = DBMigrationUtilitiesReal::new(
            &mut connection_wrapper,
            DBMigratorInnerConfiguration {
                db_configuration_table: "irrelevant".to_string(),
                current_schema_version: 0,
            },
        )
        .unwrap();
        let mut external_parameters = make_external_migration_parameters();
        external_parameters.db_password_opt = Some("booga".to_string());
        let logger = Logger::new("test_logger");
        let subject = utils.make_mig_declaration_utils(&external_parameters, &logger);

        let result = subject.db_password();

        assert_eq!(result, Some("booga".to_string()));
    }

    #[test]
    fn transaction_works() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "transaction_works");
        let db_path = dir_path.join("test_database.db");
        let mut connection_wrapper =
            ConnectionWrapperReal::new(Connection::open(&db_path).unwrap());
        let utils = DBMigrationUtilitiesReal::new(
            &mut connection_wrapper,
            DBMigratorInnerConfiguration {
                db_configuration_table: "irrelevant".to_string(),
                current_schema_version: 0,
            },
        )
        .unwrap();
        let external_parameters = make_external_migration_parameters();
        let logger = Logger::new("test_logger");
        let subject = utils.make_mig_declaration_utils(&external_parameters, &logger);

        let result = subject.transaction();

        result
            .execute("CREATE TABLE IF NOT EXISTS test (column TEXT)", [])
            .unwrap();
        // no panic? Test passes!
    }

    #[test]
    fn execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled(
    ) {
        let dir_path = ensure_node_home_directory_exists("db_migrations","execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled");
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            count integer
        )",
                [],
            )
            .unwrap();
        let correct_statement_1 = "INSERT INTO test (name,count) VALUES ('mushrooms',270)";
        let erroneous_statement_1 =
            "INSERT INTO botanic_garden (name, count) VALUES (sunflowers, 100)";
        let erroneous_statement_2 = "INSERT INTO milky_way (star) VALUES (just_discovered)";
        let set_of_sql_statements = &[
            correct_statement_1,
            erroneous_statement_1,
            erroneous_statement_2,
        ];
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration::new();
        let external_parameters = make_external_migration_parameters();
        let subject = DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap();

        let result = subject
            .make_mig_declaration_utils(&external_parameters, &Logger::new("test logger"))
            .execute_upon_transaction(set_of_sql_statements);

        assert_eq!(
            result.unwrap_err().to_string(),
            "no such table: botanic_garden"
        );
        let connection = Connection::open(&db_path).unwrap();
        //when an error occurs, the underlying transaction gets rolled back, and we cannot see any changes to the database
        let assertion: Option<(String, String)> = connection
            .query_row("SELECT count FROM test WHERE name='mushrooms'", [], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .optional()
            .unwrap();
        assert!(assertion.is_none()) //means no result for this query
    }

    #[test]
    fn execute_upon_transaction_handles_also_statements_that_return_something() {
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "execute_upon_transaction_handles_also_statements_that_return_something",
        );
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE botanic_garden (
            name TEXT,
            count integer
        )",
                [],
            )
            .unwrap();
        let statement_1 = "INSERT INTO botanic_garden (name,count) VALUES ('sun_flowers', 100)";
        let statement_2 = "ALTER TABLE botanic_garden RENAME TO just_garden"; //this statement returns an overview of the new table on its execution
        let statement_3 = "COMMIT";
        let set_of_sql_statements = &[statement_1, statement_2, statement_3];
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration::new();
        let external_parameters = make_external_migration_parameters();
        let subject = DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap();

        let result = subject
            .make_mig_declaration_utils(&external_parameters, &Logger::new("test logger"))
            .execute_upon_transaction(set_of_sql_statements);

        assert_eq!(result, Ok(()));
        let connection = Connection::open(&db_path).unwrap();
        let assertion: Option<(String, i64)> = connection
            .query_row("SELECT * FROM just_garden", [], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .optional()
            .unwrap();
        assert!(assertion.is_some()) //means there is a table named 'just_garden' now
    }

    fn make_success_mig_record(
        old_version: usize,
        empty_params_arc: &Arc<Mutex<Vec<()>>>,
    ) -> Box<dyn DatabaseMigration> {
        Box::new(
            DBMigrationRecordMock::default().set_up_necessary_stuff_for_mocked_migration_record(
                old_version,
                Ok(()),
                empty_params_arc,
            ),
        )
    }

    #[test]
    fn initiate_migrations_skips_records_already_included_in_the_current_database_and_migrates_only_the_others(
    ) {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let third_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fourth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fifth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let mig_record_1 = make_success_mig_record(0, &first_record_migration_p_arc);
        let mig_record_2 = make_success_mig_record(1, &second_record_migration_p_arc);
        let mig_record_3 = make_success_mig_record(2, &third_record_migration_p_arc);
        let mig_record_4 = make_success_mig_record(3, &fourth_record_migration_p_arc);
        let mig_record_5 = make_success_mig_record(4, &fifth_record_migration_p_arc);
        let list_of_migrations: &[&dyn DatabaseMigration] = &[
            mig_record_1.as_ref(),
            mig_record_2.as_ref(),
            mig_record_3.as_ref(),
            mig_record_4.as_ref(),
            mig_record_5.as_ref(),
        ];
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            value TEXT
        )",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO test (name, value) VALUES ('schema_version', '2')",
                [],
            )
            .unwrap();
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration {
            db_configuration_table: "test".to_string(),
            current_schema_version: 5,
        };
        let subject = DbMigratorReal::new(make_external_migration_parameters());
        let mismatched_schema = 2;
        let target_version = 5;

        let result = subject.initiate_migrations(
            mismatched_schema,
            target_version,
            Box::new(DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap()),
            list_of_migrations,
        );

        assert_eq!(result, Ok(()));
        let first_record_migration_params = first_record_migration_p_arc.lock().unwrap();
        assert_eq!(*first_record_migration_params, vec![]);
        let second_record_migration_params = second_record_migration_p_arc.lock().unwrap();
        assert_eq!(*second_record_migration_params, vec![]);
        let third_record_migration_params = third_record_migration_p_arc.lock().unwrap();
        assert_eq!(*third_record_migration_params, vec![()]);
        let fourth_record_migration_params = fourth_record_migration_p_arc.lock().unwrap();
        assert_eq!(*fourth_record_migration_params, vec![()]);
        let fifth_record_migration_params = fifth_record_migration_p_arc.lock().unwrap();
        assert_eq!(*fifth_record_migration_params, vec![()]);
        let assertion: (String, String) = connection_wrapper
            .transaction()
            .unwrap()
            .query_row(
                "SELECT name, value FROM test WHERE name='schema_version'",
                [],
                |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())),
            )
            .unwrap();
        assert_eq!(assertion.1, "5")
    }

    #[test]
    fn initiate_migrations_terminates_at_the_specified_version() {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let third_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fourth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fifth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let mig_record_1 = make_success_mig_record(0, &first_record_migration_p_arc);
        let mig_record_2 = make_success_mig_record(1, &second_record_migration_p_arc);
        let mig_record_3 = make_success_mig_record(2, &third_record_migration_p_arc);
        let mig_record_4 = make_success_mig_record(3, &fourth_record_migration_p_arc);
        let mig_record_5 = make_success_mig_record(4, &fifth_record_migration_p_arc);
        let list_of_migrations: &[&dyn DatabaseMigration] = &[
            mig_record_1.as_ref(),
            mig_record_2.as_ref(),
            mig_record_3.as_ref(),
            mig_record_4.as_ref(),
            mig_record_5.as_ref(),
        ];
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            value TEXT
        )",
                [],
            )
            .unwrap();
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration {
            db_configuration_table: "test".to_string(),
            current_schema_version: 5,
        };
        let subject = DbMigratorReal::new(make_external_migration_parameters());
        let mismatched_schema = 0;
        let target_version = 3;

        let result = subject.initiate_migrations(
            mismatched_schema,
            target_version,
            Box::new(DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap()),
            list_of_migrations,
        );

        assert_eq!(result, Ok(()));
        let first_record_migration_params = first_record_migration_p_arc.lock().unwrap();
        assert_eq!(*first_record_migration_params, vec![()]);
        let second_record_migration_params = second_record_migration_p_arc.lock().unwrap();
        assert_eq!(*second_record_migration_params, vec![()]);
        let third_record_migration_params = third_record_migration_p_arc.lock().unwrap();
        assert_eq!(*third_record_migration_params, vec![()]);
        let fourth_record_migration_params = fourth_record_migration_p_arc.lock().unwrap();
        assert_eq!(*fourth_record_migration_params, vec![]);
        let fifth_record_migration_params = fifth_record_migration_p_arc.lock().unwrap();
        assert_eq!(*fifth_record_migration_params, vec![]);
    }

    #[test]
    fn db_migration_happy_path() {
        init_test_logging();
        let execute_upon_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let update_schema_version_params_arc = Arc::new(Mutex::new(vec![]));
        let make_mig_declaration_params_arc = Arc::new(Mutex::new(vec![]));
        let outdated_schema = 0;
        let list = &[&Migrate_0_to_1 as &dyn DatabaseMigration];
        let db_migrate_declaration_utilities = DBMigrateDeclarationUtilitiesMock::default()
            .execute_upon_transaction_params(&execute_upon_transaction_params_arc)
            .execute_upon_transaction_result(Ok(()));
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_params(&make_mig_declaration_params_arc)
            .make_mig_declaration_utils_result(Box::new(db_migrate_declaration_utilities))
            .update_schema_version_params(&update_schema_version_params_arc)
            .update_schema_version_result(Ok(()))
            .commit_result(Ok(()));
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.initiate_migrations(
            outdated_schema,
            target_version,
            Box::new(migration_utils),
            list,
        );

        assert!(result.is_ok());
        let execute_upon_transaction_params = execute_upon_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *execute_upon_transaction_params.get(0).unwrap(),
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
                    .to_string()
            ],
        );
        let update_schema_version_params = update_schema_version_params_arc.lock().unwrap();
        assert_eq!(update_schema_version_params[0], 1);
        TestLogHandler::new().exists_log_containing(
            "INFO: DbMigrator: Database successfully migrated from version 0 to 1",
        );
        let make_mig_declaration_utils_params = make_mig_declaration_params_arc.lock().unwrap();
        assert_eq!(
            *make_mig_declaration_utils_params,
            vec![ExternalData {
                chain: TEST_DEFAULT_CHAIN,
                neighborhood_mode: NeighborhoodModeLight::Standard,
                db_password_opt: None,
            }]
        )
    }

    #[test]
    fn final_commit_of_the_root_transaction_sad_path() {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let list_of_migrations: &[&dyn DatabaseMigration] = &[
            &DBMigrationRecordMock::default().set_up_necessary_stuff_for_mocked_migration_record(
                0,
                Ok(()),
                &first_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_up_necessary_stuff_for_mocked_migration_record(
                1,
                Ok(()),
                &second_record_migration_p_arc,
            ),
        ];
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_result(Box::new(
                DBMigrateDeclarationUtilitiesMock::default(),
            ))
            .make_mig_declaration_utils_result(Box::new(
                DBMigrateDeclarationUtilitiesMock::default(),
            ))
            .update_schema_version_result(Ok(()))
            .update_schema_version_result(Ok(()))
            .commit_result(Err("Committing transaction failed".to_string()));
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result =
            subject.initiate_migrations(0, 2, Box::new(migration_utils), list_of_migrations);

        assert_eq!(result, Err(String::from("Committing transaction failed")));
        let first_record_migration_params = first_record_migration_p_arc.lock().unwrap();
        assert_eq!(*first_record_migration_params, vec![()]);
        let second_record_migration_params = second_record_migration_p_arc.lock().unwrap();
        assert_eq!(*second_record_migration_params, vec![()]);
    }

    #[test]
    fn migration_from_0_to_1_is_properly_set() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "0_to_1");
        create_dir_all(&dir_path).unwrap();
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();

        let result = subject.initialize_to_version(
            &dir_path,
            1,
            false,
            MigratorConfig::create_or_migrate(make_external_migration_parameters()),
        );
        let connection = result.unwrap();
        let (mp_value, mp_encrypted) = retrieve_config_row(connection.as_ref(), "mapping_protocol");
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(mp_value, None);
        assert_eq!(mp_encrypted, false);
        assert_eq!(cs_value, Some("1".to_string()));
        assert_eq!(cs_encrypted, false)
    }

    #[test]
    fn migration_from_1_to_2_is_properly_set() {
        init_test_logging();
        let start_at = 1;
        let dir_path = ensure_node_home_directory_exists("db_migrations", "1_to_2");
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        {
            subject
                .initialize_to_version(
                    &dir_path,
                    start_at,
                    true,
                    MigratorConfig::create_or_migrate(make_external_migration_parameters()),
                )
                .unwrap();
        }

        let result = subject.initialize_to_version(
            &dir_path,
            start_at + 1,
            false,
            MigratorConfig::create_or_migrate(make_external_migration_parameters()),
        );

        let connection = result.unwrap();
        let (chn_value, chn_encrypted) = retrieve_config_row(connection.as_ref(), "chain_name");
        let (cs_value, cs_encrypted) = retrieve_config_row(connection.as_ref(), "schema_version");
        assert_eq!(chn_value, Some("eth-ropsten".to_string()));
        assert_eq!(chn_encrypted, false);
        assert_eq!(cs_value, Some("2".to_string()));
        assert_eq!(cs_encrypted, false);
        TestLogHandler::new().exists_log_containing(
            "DbMigrator: Database successfully migrated from version 1 to 2",
        );
    }

    #[test]
    fn migration_from_2_to_3_is_properly_set() {
        let start_at = 2;
        let dir_path = ensure_node_home_directory_exists("db_migrations", "2_to_3");
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let subject = DbInitializerReal::default();
        {
            subject
                .initialize_to_version(
                    &dir_path,
                    start_at,
                    true,
                    MigratorConfig::create_or_migrate(make_external_migration_parameters()),
                )
                .unwrap();
        }

        let result = subject.initialize_to_version(
            &dir_path,
            start_at + 1,
            false,
            MigratorConfig::create_or_migrate(ExternalData::new(
                DEFAULT_CHAIN,
                NeighborhoodModeLight::ConsumeOnly,
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

    #[test]
    fn migration_from_3_to_4_with_wallets() {
        let data_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_3_to_4_with_wallets",
        );
        let db_path = data_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let password_opt = &Some("password".to_string());
        let subject = DbInitializerReal::default();
        let mut migrator_config =
            MigratorConfig::create_or_migrate(make_external_migration_parameters());
        migrator_config
            .external_dataset
            .as_mut()
            .unwrap()
            .db_password_opt = password_opt.clone();
        let original_private_key = {
            let schema3_conn = subject
                .initialize_to_version(&data_path, 3, true, migrator_config.clone())
                .unwrap();
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let seed = Seed::new(&mnemonic, "booga");
            let consuming_path = derivation_path(0, 150);
            let original_private_key =
                ExtendedPrivKey::derive(seed.as_bytes(), consuming_path.as_str())
                    .unwrap()
                    .secret();
            let seed_plain = PlainData::new(seed.as_bytes());
            let seed_encoded = encode_bytes(Some(seed_plain)).unwrap().unwrap();
            let seed_encrypted =
                DbEncryptionLayer::encrypt_value(&Some(seed_encoded), password_opt, "seed")
                    .unwrap()
                    .unwrap();
            let mut example_data = [0u8; 32];
            rand::thread_rng().fill(&mut example_data);
            let example_encrypted =
                Bip39::encrypt_bytes(&example_data, password_opt.as_ref().unwrap())
                    .expect("Encryption failed");
            let updates = vec![
                ("consuming_wallet_derivation_path", consuming_path, false),
                ("consuming_wallet_public_key", "booga".to_string(), false),
                ("example_encrypted", example_encrypted, true),
                ("seed", seed_encrypted, true),
            ];
            updates.into_iter().for_each(|(name, value, flag)| {
                let mut stmt = schema3_conn
                    .prepare("update config set value = ?, encrypted = ? where name = ?")
                    .expect(&format!(
                        "Couldn't prepare statement to set {} to {}",
                        name, value
                    ));
                let params: &[&dyn ToSql] =
                    &[&value, &(if flag { 1 } else { 0 }), &name.to_string()];
                let count = stmt.execute(params).unwrap();
                if count != 1 {
                    panic!(
                        "Updating {} to '{}' should have affected 1 row, but affected {}",
                        name, value, count
                    );
                }
            });
            original_private_key.to_vec()
        };

        let migrated_private_key = {
            let mut schema4_conn = subject
                .initialize_to_version(&data_path, 4, false, migrator_config)
                .unwrap();
            {
                let mut stmt = schema4_conn.prepare("select count(*) from config where name in ('consuming_wallet_derivation_path', 'consuming_wallet_public_key', 'seed')").unwrap();
                let cruft = stmt
                    .query_row([], |row| Ok(row.get::<usize, u32>(0)))
                    .unwrap()
                    .unwrap();
                assert_eq!(cruft, 0);
            }
            let (private_key_encrypted, encrypted) =
                retrieve_config_row(schema4_conn.as_mut(), "consuming_wallet_private_key");
            assert_eq!(encrypted, true);
            let private_key = Bip39::decrypt_bytes(
                &private_key_encrypted.unwrap(),
                password_opt.as_ref().unwrap(),
            )
            .unwrap();
            private_key.as_slice().to_vec()
        };

        assert_eq!(migrated_private_key, original_private_key);
    }

    #[test]
    fn migration_from_3_to_4_without_password() {
        let data_path = ensure_node_home_directory_exists(
            "db_migrations",
            "migration_from_3_to_4_without_password",
        );
        let db_path = data_path.join(DATABASE_FILE);
        let _ = bring_db_0_back_to_life_and_return_connection(&db_path);
        let password_opt = &Some("password".to_string());
        let subject = DbInitializerReal::default();
        let mut migrator_config =
            MigratorConfig::create_or_migrate(make_external_migration_parameters());
        migrator_config
            .external_dataset
            .as_mut()
            .unwrap()
            .db_password_opt = password_opt.clone();

        let mut schema4_conn = subject
            .initialize_to_version(&data_path, 4, false, migrator_config)
            .unwrap();

        {
            let mut stmt = schema4_conn.prepare("select count(*) from config where name in ('consuming_wallet_derivation_path', 'consuming_wallet_public_key', 'seed')").unwrap();
            let cruft = stmt
                .query_row([], |row| Ok(row.get::<usize, u32>(0)))
                .unwrap()
                .unwrap();
            assert_eq!(cruft, 0);
        }
        let (private_key_encrypted, encrypted) =
            retrieve_config_row(schema4_conn.as_mut(), "consuming_wallet_private_key");
        assert_eq!(private_key_encrypted, None);
        assert_eq!(encrypted, true);
    }

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
                true,
                MigratorConfig::create_or_migrate(make_external_migration_parameters()),
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
                false,
                MigratorConfig::create_or_migrate(ExternalData::new(
                    TEST_DEFAULT_CHAIN,
                    NeighborhoodModeLight::ConsumeOnly,
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
                    true,
                    MigratorConfig::create_or_migrate(make_external_migration_parameters()),
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
                false,
                MigratorConfig::create_or_migrate(ExternalData::new(
                    TEST_DEFAULT_CHAIN,
                    NeighborhoodModeLight::ConsumeOnly,
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
        let expected_key_words = [
            ["rowid", "integer", "primary", "key"].as_slice(),
            ["transaction_hash", "text", "not", "null"].as_slice(),
            ["amount", "integer", "not", "null"].as_slice(),
            ["payable_timestamp", "integer", "not", "null"].as_slice(),
            ["attempt", "integer", "not", "null"].as_slice(),
            ["process_error", "text", "null"].as_slice(),
        ];
        assert_create_table_statement_contains_all_important_parts(
            conn_schema5,
            "pending_payable",
            expected_key_words.as_slice(),
        );
        let expected_key_words = [["transaction_hash"].as_slice()];
        assert_index_statement_is_coupled_with_right_parameter(
            conn_schema5,
            "pending_payable_hash_idx",
            expected_key_words.as_slice(),
        );
        let expected_key_words = [
            ["wallet_address", "text", "primary", "key"].as_slice(),
            ["balance", "integer", "not", "null"].as_slice(),
            ["last_paid_timestamp", "integer", "not", "null"].as_slice(),
            ["pending_payable_rowid", "integer", "null"].as_slice(),
        ];
        assert_create_table_statement_contains_all_important_parts(
            conn_schema5,
            "payable",
            expected_key_words.as_slice(),
        );
        let expected_key_words = [
            ["name", "text", "primary", "key"].as_slice(),
            ["value", "text"].as_slice(),
            ["encrypted", "integer", "not", "null"].as_slice(),
        ];
        assert_create_table_statement_contains_all_important_parts(
            conn_schema5,
            "config",
            expected_key_words.as_slice(),
        );
        assert_no_index_exists_for_table(conn_schema5, "config");
        assert_no_index_exists_for_table(conn_schema5, "payable");
        assert_no_index_exists_for_table(conn_schema5, "receivable");
        assert_no_index_exists_for_table(conn_schema5, "banned");
        let error_stm = conn_schema5
            .prepare("select * from _config_old")
            .unwrap_err();
        let error_msg = match error_stm {
            rusqlite::Error::SqliteFailure(_, Some(msg)) => msg,
            x => panic!("we expected SqliteFailure but we got: {:?}", x),
        };
        assert_eq!(error_msg, "no such table: _config_old".to_string())
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
