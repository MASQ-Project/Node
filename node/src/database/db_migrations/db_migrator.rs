// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::ExternalData;
use crate::database::db_migrations::migrations::migration_0_to_1::Migrate_0_to_1;
use crate::database::db_migrations::migrations::migration_1_to_2::Migrate_1_to_2;
use crate::database::db_migrations::migrations::migration_2_to_3::Migrate_2_to_3;
use crate::database::db_migrations::migrations::migration_3_to_4::Migrate_3_to_4;
use crate::database::db_migrations::migrations::migration_4_to_5::Migrate_4_to_5;
use crate::database::db_migrations::migrations::migration_5_to_6::Migrate_5_to_6;
use crate::database::db_migrations::migrations::migration_6_to_7::Migrate_6_to_7;
use crate::database::db_migrations::migrations::migration_7_to_8::Migrate_7_to_8;
use crate::database::db_migrations::migrations::migration_8_to_9::Migrate_8_to_9;
use crate::database::db_migrations::migrator_utils::{
    DBMigDeclarator, DBMigrationUtilities, DBMigrationUtilitiesReal, DBMigratorInnerConfiguration,
};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionSafeWrapper};
use masq_lib::logger::Logger;

pub trait DbMigrator {
    fn migrate_database(
        &self,
        obsolete_schema: usize,
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
        obsolete_schema: usize,
        target_version: usize,
        mut conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        let migrator_config = DBMigratorInnerConfiguration::new();
        let migration_utils = match DBMigrationUtilitiesReal::new(&mut *conn, migrator_config) {
            Err(e) => return Err(e.to_string()),
            Ok(utils) => utils,
        };
        self.initiate_migrations(
            obsolete_schema,
            target_version,
            Box::new(migration_utils),
            Self::list_of_migrations(),
        )
    }
}

pub trait DatabaseMigration {
    fn migrate<'a>(
        &self,
        mig_declaration_utilities: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()>;
    fn old_version(&self) -> usize;
}

impl DbMigratorReal {
    pub fn new(external: ExternalData) -> Self {
        Self {
            external,
            logger: Logger::new("DbMigrator"),
        }
    }

    const fn list_of_migrations<'a>() -> &'a [&'a dyn DatabaseMigration] {
        &[
            &Migrate_0_to_1,
            &Migrate_1_to_2,
            &Migrate_2_to_3,
            &Migrate_3_to_4,
            &Migrate_4_to_5,
            &Migrate_5_to_6,
            &Migrate_6_to_7,
            &Migrate_7_to_8,
            &Migrate_8_to_9,
        ]
    }

    fn initiate_migrations<'a>(
        &self,
        obsolete_schema: usize,
        target_version: usize,
        mut migration_utilities: Box<dyn DBMigrationUtilities + 'a>,
        list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<(), String> {
        let migrations_to_process = Self::select_migrations_to_process(
            obsolete_schema,
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
        logger: &Logger,
    ) -> rusqlite::Result<()> {
        info!(
            &self.logger,
            "Migrating from version {} to version {}",
            record.old_version(),
            record.old_version() + 1
        );
        record.migrate(migration_utilities.make_mig_declarator(&self.external, logger))?;
        let migrate_to = record.old_version() + 1;
        migration_utilities.update_schema_version(migrate_to)
    }

    pub fn update_schema_version(
        name_of_given_table: &str,
        transaction: &TransactionSafeWrapper,
        update_to: usize,
    ) -> rusqlite::Result<()> {
        transaction
            .prepare(&format!(
                "UPDATE {} SET value = {} WHERE name = 'schema_version'",
                name_of_given_table, update_to
            ))
            .expect("internal rusqlite error")
            .execute([])?;
        Ok(())
    }

    fn select_migrations_to_process<'a>(
        obsolete_schema: usize,
        list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)],
        target_version: usize,
        mig_utils: &dyn DBMigrationUtilities,
    ) -> Vec<&'a (dyn DatabaseMigration + 'a)> {
        mig_utils.too_high_schema_panics(obsolete_schema);
        list_of_migrations
            .iter()
            .skip_while(|entry| entry.old_version() != obsolete_schema)
            .take_while(|entry| entry.old_version() < target_version)
            .copied()
            .collect::<Vec<&'a (dyn DatabaseMigration + 'a)>>()
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

#[cfg(test)]
mod tests {
    use crate::database::db_initializer::ExternalData;
    use crate::database::db_migrations::db_migrator::{
        DatabaseMigration, DbMigrator, DbMigratorReal,
    };
    use crate::database::db_migrations::migrations::migration_0_to_1::Migrate_0_to_1;
    use crate::database::db_migrations::migrator_utils::{
        DBMigDeclarator, DBMigrationUtilities, DBMigrationUtilitiesReal,
        DBMigratorInnerConfiguration,
    };
    use crate::database::db_migrations::test_utils::DBMigDeclaratorMock;
    use crate::database::rusqlite_wrappers::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::test_utils::ConnectionWrapperMock;
    use crate::test_utils::database_utils::make_external_data;
    use masq_lib::constants::CURRENT_SCHEMA_VERSION;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::NeighborhoodModeLight;
    use rusqlite::{Connection, Error};
    use std::cell::RefCell;
    use std::fmt::Debug;
    use std::iter::once;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct DBMigrationUtilitiesMock {
        too_high_schema_panics_params: Arc<Mutex<Vec<usize>>>,
        make_mig_declarator_params: Arc<Mutex<Vec<ExternalData>>>,
        make_mig_declarator_results: RefCell<Vec<Box<dyn DBMigDeclarator>>>,
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

        pub fn make_mig_declarator_params(
            mut self,
            params: &Arc<Mutex<Vec<ExternalData>>>,
        ) -> Self {
            self.make_mig_declarator_params = params.clone();
            self
        }

        pub fn make_mig_declarator_result(self, result: Box<dyn DBMigDeclarator>) -> Self {
            self.make_mig_declarator_results.borrow_mut().push(result);
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

        fn make_mig_declarator<'a>(
            &'a self,
            external: &'a ExternalData,
            _logger: &'a Logger,
        ) -> Box<dyn DBMigDeclarator + 'a> {
            self.make_mig_declarator_params
                .lock()
                .unwrap()
                .push(external.clone());
            self.make_mig_declarator_results.borrow_mut().remove(0)
        }

        fn too_high_schema_panics(&self, obsolete_schema: usize) {
            self.too_high_schema_panics_params
                .lock()
                .unwrap()
                .push(obsolete_schema);
        }
    }

    #[derive(Default, Debug)]
    struct DatabaseMigrationMock {
        old_version_result: RefCell<usize>,
        migrate_params: Arc<Mutex<Vec<()>>>,
        migrate_results: RefCell<Vec<rusqlite::Result<()>>>,
    }

    impl DatabaseMigrationMock {
        fn old_version_result(self, result: usize) -> Self {
            self.old_version_result.replace(result);
            self
        }

        fn migrate_result(self, result: rusqlite::Result<()>) -> Self {
            self.migrate_results.borrow_mut().push(result);
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

    impl DatabaseMigration for DatabaseMigrationMock {
        fn migrate<'a>(
            &self,
            _migration_utilities: Box<dyn DBMigDeclarator + 'a>,
        ) -> rusqlite::Result<()> {
            self.migrate_params.lock().unwrap().push(());
            self.migrate_results.borrow_mut().remove(0)
        }

        fn old_version(&self) -> usize {
            *self.old_version_result.borrow()
        }
    }

    const _TEST_FROM_COMPILATION_TIME: () =
        if DbMigratorReal::list_of_migrations().len() != CURRENT_SCHEMA_VERSION {
            panic!(
                "It appears you need to increment the current schema version to have DbMigrator \
             work correctly if any new migration added"
            )
        };

    #[test]
    fn migrate_database_handles_an_error_from_creating_the_root_transaction() {
        let subject = DbMigratorReal::new(make_external_data());
        let obsolete_schema = 0;
        let target_version = 5; //irrelevant
        let connection = ConnectionWrapperMock::default()
            .transaction_result(Err(Error::SqliteSingleThreadedMode)); //hard to find a real-like error for this

        let result =
            subject.migrate_database(obsolete_schema, target_version, Box::new(connection));

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
        let subject = DbMigratorReal::new(make_external_data());

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

    #[test]
    #[should_panic(expected = "The list of database migrations is not ordered properly")]
    fn list_validation_check_works_for_badly_ordered_migrations_when_inside() {
        let fake_one = DatabaseMigrationMock::default().old_version_result(6);
        let fake_two = DatabaseMigrationMock::default().old_version_result(2);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    #[test]
    #[should_panic(expected = "The list of database migrations is not ordered properly")]
    fn list_validation_check_works_for_badly_ordered_migrations_when_at_the_end() {
        let fake_one = DatabaseMigrationMock::default().old_version_result(1);
        let fake_two = DatabaseMigrationMock::default().old_version_result(3);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    fn list_validation_check<'a>(list_of_migrations: &'a [&'a (dyn DatabaseMigration + 'a)]) {
        let begins_at_version = list_of_migrations[0].old_version();
        let iterator = list_of_migrations.iter();
        let ending_sentinel = &DatabaseMigrationMock::default()
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
        let mut migration_record = DatabaseMigrationMock::default()
            .old_version_result(4)
            .migrate_result(Ok(()));
        let migration_utilities = DBMigrationUtilitiesMock::default()
            .make_mig_declarator_result(Box::new(DBMigDeclaratorMock::default()))
            .update_schema_version_params(&update_schema_version_params_arc)
            .update_schema_version_result(Err(Error::InvalidQuery));
        let subject = DbMigratorReal::new(make_external_data());

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
        let list = &[&DatabaseMigrationMock::default()
            .old_version_result(0)
            .migrate_result(Err(Error::InvalidColumnIndex(5)))
            as &dyn DatabaseMigration];
        let mig_declarator = DBMigDeclaratorMock::default();
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declarator_result(Box::new(mig_declarator));
        let obsolete_schema = 0;
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_data());

        let result = subject.initiate_migrations(
            obsolete_schema,
            target_version,
            Box::new(migration_utils),
            list,
        );

        assert_eq!(
            result,
            Err("Migrating database from version 0 to 1 failed: InvalidColumnIndex(5)".to_string())
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: DbMigrator: Migrating database from version 0 to 1 failed: InvalidColumnIndex(5)",
        );
    }

    fn make_success_mig_record(
        old_version: usize,
        empty_params_arc: &Arc<Mutex<Vec<()>>>,
    ) -> Box<dyn DatabaseMigration> {
        Box::new(
            DatabaseMigrationMock::default().set_up_necessary_stuff_for_mocked_migration_record(
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
        let subject = DbMigratorReal::new(make_external_data());
        let obsolete_schema = 2;
        let target_version = 5;

        let result = subject.initiate_migrations(
            obsolete_schema,
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
            .prepare("SELECT name, value FROM test WHERE name='schema_version'")
            .unwrap()
            .query_row([], |row| Ok((row.get(0).unwrap(), row.get(1).unwrap())))
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
            .execute("CREATE TABLE test (name TEXT, value TEXT)", [])
            .unwrap();
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration {
            db_configuration_table: "test".to_string(),
            current_schema_version: 5,
        };
        let subject = DbMigratorReal::new(make_external_data());
        let obsolete_schema = 0;
        let target_version = 3;

        let result = subject.initiate_migrations(
            obsolete_schema,
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
        let make_mig_declarator_params_arc = Arc::new(Mutex::new(vec![]));
        let outdated_schema = 0;
        let list = &[&Migrate_0_to_1 as &dyn DatabaseMigration];
        let mig_declarator = DBMigDeclaratorMock::default()
            .execute_upon_transaction_params(&execute_upon_transaction_params_arc)
            .execute_upon_transaction_result(Ok(()));
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declarator_params(&make_mig_declarator_params_arc)
            .make_mig_declarator_result(Box::new(mig_declarator))
            .update_schema_version_params(&update_schema_version_params_arc)
            .update_schema_version_result(Ok(()))
            .commit_result(Ok(()));
        let target_version = 5; //not relevant
        let subject = DbMigratorReal::new(make_external_data());

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
        let make_mig_declarator_params = make_mig_declarator_params_arc.lock().unwrap();
        assert_eq!(
            *make_mig_declarator_params,
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
            &DatabaseMigrationMock::default().set_up_necessary_stuff_for_mocked_migration_record(
                0,
                Ok(()),
                &first_record_migration_p_arc,
            ),
            &DatabaseMigrationMock::default().set_up_necessary_stuff_for_mocked_migration_record(
                1,
                Ok(()),
                &second_record_migration_p_arc,
            ),
        ];
        let migration_utils = DBMigrationUtilitiesMock::default()
            .make_mig_declarator_result(Box::new(DBMigDeclaratorMock::default()))
            .make_mig_declarator_result(Box::new(DBMigDeclaratorMock::default()))
            .update_schema_version_result(Ok(()))
            .update_schema_version_result(Ok(()))
            .commit_result(Err("Committing transaction failed".to_string()));
        let subject = DbMigratorReal::new(make_external_data());

        let result =
            subject.initiate_migrations(0, 2, Box::new(migration_utils), list_of_migrations);

        assert_eq!(result, Err(String::from("Committing transaction failed")));
        let first_record_migration_params = first_record_migration_p_arc.lock().unwrap();
        assert_eq!(*first_record_migration_params, vec![()]);
        let second_record_migration_params = second_record_migration_p_arc.lock().unwrap();
        assert_eq!(*second_record_migration_params, vec![()]);
    }
}
