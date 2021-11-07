// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use crate::sub_lib::logger::Logger;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::{ExpectValue, WrapResult};
use rusqlite::{Transaction, NO_PARAMS};
use std::fmt::Debug;

pub trait DbMigrator {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String>;
}

pub struct DbMigratorReal {
    external: ExternalMigrationParameters,
    logger: Logger,
}

impl DbMigrator for DbMigratorReal {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        mut conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        let migrator_config = DBMigratorConfiguration::new();
        let migration_utils = match DBMigrationUtilitiesReal::new(&mut *conn, migrator_config) {
            Err(e) => return Err(e.to_string()),
            Ok(utils) => utils,
        };
        self.make_updates(
            mismatched_schema,
            target_version,
            Box::new(migration_utils),
            Self::list_of_updates(),
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
    fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()>;

    fn external_parameters(&self) -> &ExternalMigrationParameters;
}

trait DBMigrationUtilities {
    fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()>;

    fn commit(&mut self) -> Result<(), String>;

    fn make_mig_declaration_utils<'a>(
        &'a self,
        external: &'a ExternalMigrationParameters,
    ) -> Box<dyn MigDeclarationUtilities + 'a>;

    fn too_high_schema_panics(&self, mismatched_schema: usize);
}

struct DBMigrationUtilitiesReal<'a> {
    root_transaction: Option<Transaction<'a>>,
    db_migrator_configuration: DBMigratorConfiguration,
}

impl<'a> DBMigrationUtilitiesReal<'a> {
    fn new<'b: 'a>(
        conn: &'b mut dyn ConnectionWrapper,
        db_migrator_configuration: DBMigratorConfiguration,
    ) -> rusqlite::Result<Self> {
        Self {
            root_transaction: Some(conn.transaction()?),
            db_migrator_configuration,
        }
        .wrap_to_ok()
    }

    fn root_transaction_ref(&self) -> &Transaction<'a> {
        self.root_transaction.as_ref().expect_v("root transaction")
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
            .expect_v("owned root transaction")
            .commit()
            .map_err(|e| e.to_string())
    }

    fn make_mig_declaration_utils<'b>(
        &'b self,
        external: &'b ExternalMigrationParameters,
    ) -> Box<dyn MigDeclarationUtilities + 'b> {
        Box::new(MigDeclarationUtilitiesReal::new(
            self.root_transaction_ref(),
            external,
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
    external: &'a ExternalMigrationParameters,
}

impl<'a> MigDeclarationUtilitiesReal<'a> {
    fn new(
        root_transaction_ref: &'a Transaction<'a>,
        external: &'a ExternalMigrationParameters,
    ) -> Self {
        Self {
            root_transaction_ref,
            external,
        }
    }
}

impl MigDeclarationUtilities for MigDeclarationUtilitiesReal<'_> {
    fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()> {
        let transaction = self.root_transaction_ref;
        sql_statements.iter().fold(Ok(()), |so_far, stm| {
            if so_far.is_ok() {
                transaction.execute(stm, NO_PARAMS).map(|_| ())
            } else {
                so_far
            }
        })
    }

    fn external_parameters(&self) -> &ExternalMigrationParameters {
        self.external
    }
}

struct DBMigratorConfiguration {
    db_configuration_table: String,
    current_schema_version: usize,
}

impl DBMigratorConfiguration {
    fn new() -> Self {
        DBMigratorConfiguration {
            db_configuration_table: "config".to_string(),
            current_schema_version: CURRENT_SCHEMA_VERSION,
        }
    }
}

//define a new update here and add it to this list: 'list_of_updates()'
////////////////////////////////////////////////////////////////////////////////////////////////////

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
            //another statement would follow here
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
            declaration_utils.external_parameters().chain_name
        );
        declaration_utils.execute_upon_transaction(&[
            statement.as_str(), //another statement would follow here
        ])
    }

    fn old_version(&self) -> usize {
        1
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

impl DbMigratorReal {
    pub fn new(external: ExternalMigrationParameters) -> Self {
        Self {
            external,
            logger: Logger::new("DbMigrator"),
        }
    }

    fn list_of_updates<'a>() -> &'a [&'a dyn DatabaseMigration] {
        &[&Migrate_0_to_1, &Migrate_1_to_2]
    }

    fn make_updates<'a>(
        &self,
        mismatched_schema: usize,
        target_version: usize,
        mut migration_utilities: Box<dyn DBMigrationUtilities + 'a>,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<(), String> {
        let updates_to_process = Self::select_updates_to_process(
            mismatched_schema,
            list_of_updates,
            target_version,
            &*migration_utilities,
        );
        for record in updates_to_process {
            let present_db_version = record.old_version();
            if let Err(e) = self.migrate_semi_automated(record, &*migration_utilities) {
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
    ) -> rusqlite::Result<()> {
        record.migrate(migration_utilities.make_mig_declaration_utils(&self.external))?;
        let update_to = record.old_version() + 1;
        migration_utilities.update_schema_version(update_to)
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
            NO_PARAMS,
        )?;
        Ok(())
    }

    fn select_updates_to_process<'a>(
        mismatched_schema: usize,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
        target_version: usize,
        mig_utils: &dyn DBMigrationUtilities,
    ) -> Vec<&'a (dyn DatabaseMigration + 'a)> {
        mig_utils.too_high_schema_panics(mismatched_schema);
        list_of_updates
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
            "Updating database from version {} to {} failed: {:?}",
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
            "Database successfully updated from version {} to {}",
            previous_version,
            previous_version + 1
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExternalMigrationParameters {
    chain_name: String,
}

impl ExternalMigrationParameters {
    pub fn new(chain: Chain) -> Self {
        Self {
            chain_name: chain.rec().literal_identifier.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::{
        DbInitializer, DbInitializerReal, CURRENT_SCHEMA_VERSION, DATABASE_FILE,
    };
    use crate::database::db_migrations::{
        DBMigrationUtilities, DBMigrationUtilitiesReal, DatabaseMigration, DbMigrator,
        ExternalMigrationParameters, MigDeclarationUtilities, Migrate_0_to_1,
    };
    use crate::database::db_migrations::{DBMigratorConfiguration, DbMigratorReal};
    use crate::test_utils::database_utils::{
        assurance_query_for_config_table,
        revive_tables_of_the_version_0_and_return_the_connection_to_the_db,
    };
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::{ensure_node_home_directory_exists, TEST_DEFAULT_CHAIN};
    use rusqlite::{Connection, Error, OptionalExtension, NO_PARAMS};
    use std::cell::RefCell;
    use std::fmt::Debug;
    use std::fs::create_dir_all;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct DBMigrationUtilitiesMock {
        too_high_found_schema_will_panic_params: Arc<Mutex<Vec<usize>>>,
        make_mig_declaration_utils_params: Arc<Mutex<Vec<ExternalMigrationParameters>>>,
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
            params: &Arc<Mutex<Vec<ExternalMigrationParameters>>>,
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
            external: &'a ExternalMigrationParameters,
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
    struct DBUpdateDeclarationUtilitiesMock {
        execute_upon_transaction_params: Arc<Mutex<Vec<Vec<String>>>>,
        execute_upon_transaction_results: RefCell<Vec<rusqlite::Result<()>>>,
    }

    impl DBUpdateDeclarationUtilitiesMock {
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

    impl MigDeclarationUtilities for DBUpdateDeclarationUtilitiesMock {
        fn execute_upon_transaction<'a>(&self, sql_statements: &[&'a str]) -> rusqlite::Result<()> {
            self.execute_upon_transaction_params.lock().unwrap().push(
                sql_statements
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
            );
            self.execute_upon_transaction_results.borrow_mut().remove(0)
        }

        fn external_parameters(&self) -> &ExternalMigrationParameters {
            unimplemented!()
        }
    }

    fn make_external_migration_parameters() -> ExternalMigrationParameters {
        ExternalMigrationParameters {
            chain_name: DEFAULT_CHAIN.rec().literal_identifier.to_string(),
        }
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
    fn make_updates_panics_if_the_given_schema_is_of_higher_number_than_the_latest_official() {
        let last_version = CURRENT_SCHEMA_VERSION;
        let too_advanced = last_version + 1;
        let connection = Connection::open_in_memory().unwrap();
        let mut conn_wrapper = ConnectionWrapperReal::new(connection);
        let mig_config = DBMigratorConfiguration::new();
        let migration_utilities =
            DBMigrationUtilitiesReal::new(&mut conn_wrapper, mig_config).unwrap();
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let captured_panic = catch_unwind(AssertUnwindSafe(|| {
            subject.make_updates(
                too_advanced,
                CURRENT_SCHEMA_VERSION,
                Box::new(migration_utilities),
                DbMigratorReal::list_of_updates(),
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

        fn set_necessary_tooling_for_mock_migration_record(
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
    #[should_panic(expected = "The list of updates for the database is not ordered properly")]
    fn list_validation_check_works() {
        let fake_one = DBMigrationRecordMock::default().old_version_result(6);
        let fake_two = DBMigrationRecordMock::default().old_version_result(3);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    fn list_validation_check<'a>(list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)]) {
        let iterator = list_of_updates.iter();
        let iterator_shifted = list_of_updates.iter().skip(1);
        iterator.zip(iterator_shifted).for_each(|(first, second)| {
            assert!(
                two_numbers_are_sequential(first.old_version(), second.old_version()),
                "The list of updates for the database is not ordered properly"
            )
        });
    }

    fn two_numbers_are_sequential(first: usize, second: usize) -> bool {
        (first + 1) == second
    }

    #[test]
    fn list_of_approved_updates_is_correctly_ordered() {
        let _ = list_validation_check(DbMigratorReal::list_of_updates());
        //success if no panicking
    }

    #[test]
    fn list_of_approved_updates_ends_on_the_current_version() {
        let last_entry = DbMigratorReal::list_of_updates().into_iter().last();

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
            .make_mig_declaration_utils_result(
                Box::new(DBUpdateDeclarationUtilitiesMock::default()),
            )
            .update_schema_version_result(Err(Error::InvalidQuery))
            .update_schema_version_params(&update_schema_version_params_arc);
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.migrate_semi_automated(&mut migration_record, &migration_utilities);

        assert_eq!(result, Err(Error::InvalidQuery));
        let update_schema_version_params = update_schema_version_params_arc.lock().unwrap();
        assert_eq!(*update_schema_version_params, vec![5]) //doesn't mean the state really changed, this is just an image of the supplied params
    }

    #[test]
    fn make_updates_returns_an_error_from_migrate() {
        init_test_logging();
        let list = &[&DBMigrationRecordMock::default()
            .old_version_result(0)
            .migrate_result(Err(Error::InvalidColumnIndex(5)))
            as &dyn DatabaseMigration];
        let update_declaration_utils = DBUpdateDeclarationUtilitiesMock::default();
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_result(Box::new(update_declaration_utils));
        let mismatched_schema = 0;
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.make_updates(
            mismatched_schema,
            target_version,
            Box::new(migration_utils),
            list,
        );

        assert_eq!(
            result,
            Err(
                r#"Updating database from version 0 to 1 failed: InvalidColumnIndex(5)"#
                    .to_string()
            )
        );
        TestLogHandler::new().exists_log_containing(
            r#"ERROR: DbMigrator: Updating database from version 0 to 1 failed: InvalidColumnIndex(5)"#,
        );
    }

    #[test]
    fn execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled(
    ) {
        let dir_path = ensure_node_home_directory_exists("db_migrations","execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled");
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE IF NOT EXISTS test (
            name TEXT,
            count TEXT
        )",
                NO_PARAMS,
            )
            .unwrap();
        let correct_statement_1 = "INSERT INTO test (name,count) VALUES ('mushrooms','270')";
        let erroneous_statement_1 = "INSERT INTO botanic_garden (sun_flowers) VALUES (100)";
        let erroneous_statement_2 = "UPDATE botanic_garden SET (sun_flowers) VALUES (99)";
        let set_of_sql_statements = &[
            correct_statement_1,
            erroneous_statement_1,
            erroneous_statement_2,
        ];
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorConfiguration::new();
        let chain = Chain::EthMainnet; //irrelevant
        let external_parameters = ExternalMigrationParameters::new(chain);
        let subject = DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap();

        let result = subject
            .make_mig_declaration_utils(&external_parameters)
            .execute_upon_transaction(set_of_sql_statements);

        assert_eq!(
            result.unwrap_err().to_string(),
            "no such table: botanic_garden"
        );
        let connection = Connection::open(&db_path).unwrap();
        //when an error occurs, the underlying transaction gets rolled back, and we cannot see any changes to the database
        let assertion: Option<(String, String)> = connection
            .query_row(
                "SELECT count FROM test WHERE name='mushrooms'",
                NO_PARAMS,
                |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())),
            )
            .optional()
            .unwrap();
        assert!(assertion.is_none()) //means no result for this query
    }

    #[test]
    fn make_updates_skips_records_already_included_in_the_current_database_and_updates_only_the_others(
    ) {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let third_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fourth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fifth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let list_of_updates: &[&dyn DatabaseMigration] = &[
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                0,
                Ok(()),
                &first_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                1,
                Ok(()),
                &second_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                2,
                Ok(()),
                &third_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                3,
                Ok(()),
                &fourth_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                4,
                Ok(()),
                &fifth_record_migration_p_arc,
            ),
        ];
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            value TEXT
        )",
                NO_PARAMS,
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO test (name, value) VALUES ('schema_version', '2')",
                NO_PARAMS,
            )
            .unwrap();
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorConfiguration {
            db_configuration_table: "test".to_string(),
            current_schema_version: 5,
        };
        let subject = DbMigratorReal::new(make_external_migration_parameters());
        let mismatched_schema = 2;
        let target_version = 5;

        let result = subject.make_updates(
            mismatched_schema,
            target_version,
            Box::new(DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap()),
            list_of_updates,
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
                NO_PARAMS,
                |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())),
            )
            .unwrap();
        assert_eq!(assertion.1, "5")
    }

    #[test]
    fn make_updates_terminates_at_the_specified_version() {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let third_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fourth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let fifth_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let list_of_updates: &[&dyn DatabaseMigration] = &[
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                0,
                Ok(()),
                &first_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                1,
                Ok(()),
                &second_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                2,
                Ok(()),
                &third_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                3,
                Ok(()),
                &fourth_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                4,
                Ok(()),
                &fifth_record_migration_p_arc,
            ),
        ];
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            value TEXT
        )",
                NO_PARAMS,
            )
            .unwrap();
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorConfiguration {
            db_configuration_table: "test".to_string(),
            current_schema_version: 5,
        };
        let subject = DbMigratorReal::new(make_external_migration_parameters());
        let mismatched_schema = 0;
        let target_version = 3;

        let result = subject.make_updates(
            mismatched_schema,
            target_version,
            Box::new(DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap()),
            list_of_updates,
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
        let db_update_declaration_utilities = DBUpdateDeclarationUtilitiesMock::default()
            .execute_upon_transaction_params(&execute_upon_transaction_params_arc)
            .execute_upon_transaction_result(Ok(()));
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_params(&make_mig_declaration_params_arc)
            .make_mig_declaration_utils_result(Box::new(db_update_declaration_utilities))
            .update_schema_version_params(&update_schema_version_params_arc)
            .update_schema_version_result(Ok(()))
            .commit_result(Ok(()));
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.make_updates(
            outdated_schema,
            target_version,
            Box::new(migration_utils),
            list,
        );

        assert!(result.is_ok());
        let execute_upon_transaction_params = execute_upon_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *execute_upon_transaction_params[0],
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
            ]
        );
        let update_schema_version_params = update_schema_version_params_arc.lock().unwrap();
        assert_eq!(update_schema_version_params[0], 1);
        TestLogHandler::new().exists_log_containing(
            "INFO: DbMigrator: Database successfully updated from version 0 to 1",
        );
        let make_mig_declaration_utils_params = make_mig_declaration_params_arc.lock().unwrap();
        assert_eq!(
            *make_mig_declaration_utils_params,
            vec![ExternalMigrationParameters {
                chain_name: "eth-mainnet".to_string()
            }]
        )
    }

    #[test]
    fn final_commit_of_the_root_transaction_sad_path() {
        let first_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let second_record_migration_p_arc = Arc::new(Mutex::new(vec![]));
        let list_of_updates: &[&dyn DatabaseMigration] = &[
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                0,
                Ok(()),
                &first_record_migration_p_arc,
            ),
            &DBMigrationRecordMock::default().set_necessary_tooling_for_mock_migration_record(
                1,
                Ok(()),
                &second_record_migration_p_arc,
            ),
        ];
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declaration_utils_result(
                Box::new(DBUpdateDeclarationUtilitiesMock::default()),
            )
            .make_mig_declaration_utils_result(
                Box::new(DBUpdateDeclarationUtilitiesMock::default()),
            )
            .update_schema_version_result(Ok(()))
            .update_schema_version_result(Ok(()))
            .commit_result(Err("Committing transaction failed".to_string()));
        let subject = DbMigratorReal::new(make_external_migration_parameters());

        let result = subject.make_updates(0, 2, Box::new(migration_utils), list_of_updates);

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
        let _ = revive_tables_of_the_version_0_and_return_the_connection_to_the_db(&db_path);
        let subject = DbInitializerReal::default();

        let result = subject.initialize_to_version(&dir_path, TEST_DEFAULT_CHAIN, 1, true);

        let connection = result.unwrap();
        let (mp_name, mp_value, mp_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                connection.as_ref(),
                "select name, value, encrypted from config where name = 'mapping_protocol'",
            );
        let (cs_name, cs_value, cs_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                connection.as_ref(),
                "select name, value, encrypted from config where name = 'schema_version'",
            );
        assert_eq!(mp_name, "mapping_protocol".to_string());
        assert_eq!(mp_value, None);
        assert_eq!(mp_encrypted, 0);
        assert_eq!(cs_name, "schema_version".to_string());
        assert_eq!(cs_value, Some("1".to_string()));
        assert_eq!(cs_encrypted, 0)
    }

    #[test]
    fn migration_from_1_to_2_is_properly_set() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "1_to_2");
        let db_path = dir_path.join(DATABASE_FILE);
        let _ = revive_tables_of_the_version_0_and_return_the_connection_to_the_db(&db_path);
        let subject = DbInitializerReal::default();
        {
            subject
                .initialize_to_version(&dir_path, TEST_DEFAULT_CHAIN, 1, true)
                .unwrap();
        }

        let result = subject.initialize_to_version(&dir_path, TEST_DEFAULT_CHAIN, 2, true);

        let connection = result.unwrap();
        let (chn_name, chn_value, chn_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                connection.as_ref(),
                "select name, value, encrypted from config where name = 'chain_name'",
            );
        let (cs_name, cs_value, cs_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                connection.as_ref(),
                "select name, value, encrypted from config where name = 'schema_version'",
            );
        assert_eq!(chn_name, "chain_name".to_string());
        assert_eq!(chn_value, Some("eth-ropsten".to_string()));
        assert_eq!(chn_encrypted, 0);
        assert_eq!(cs_name, "schema_version".to_string());
        assert_eq!(cs_value, Some("2".to_string()));
        assert_eq!(cs_encrypted, 0);
    }
}
