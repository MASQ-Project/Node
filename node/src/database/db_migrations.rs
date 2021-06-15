// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use crate::sub_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use rusqlite::{Transaction, NO_PARAMS};
use std::fmt::Debug;

const THE_EARLIEST_RECORD_OF_DB_MIGRATION: usize = 0; //TODO maybe remove this

pub trait DbMigrator {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String>;
    fn log_warn(&self, msg: &str);
}

pub struct DbMigratorReal {
    logger: Logger,
}

impl DbMigrator for DbMigratorReal {
    fn migrate_database(
        &self,
        mismatched_schema: usize,
        mut conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        let migration_utils = DBMigrationUtilitiesReal::new(&mut *conn)
            .map_err::<Result<(), String>, _>(|e| return Err(e.to_string()))
            .expect_v("migration utils"); //TODO test drive this, probably not tested
        self.make_updates(
            mismatched_schema,
            Box::new(migration_utils),
            Self::list_of_existing_updates(),
        )
    }
    fn log_warn(&self, msg: &str) {
        warning!(self.logger, "{}", msg)
    }
}

impl Default for DbMigratorReal {
    fn default() -> Self {
        Self::new()
    }
}

trait DatabaseMigration: Debug {
    fn migrate(
        &self,
        migration_utilities: &dyn DBMigrationUtilities,
    ) -> rusqlite::Result<()>;
    fn old_version(&self) -> usize;
}

trait DBMigrationUtilities {
    fn update_schema_version(&self, updated_to: String) -> rusqlite::Result<()>;

    fn execute_upon_transaction(&self, sql_statements: &[&'static str]) -> rusqlite::Result<()>;

    fn commit(&mut self) -> Result<(), String>;
}

struct DBMigrationUtilitiesReal<'a> {
    root_transaction: Option<Transaction<'a>>,
}

impl<'a> DBMigrationUtilitiesReal<'a> {
    fn new<'b: 'a>(conn: &'b mut dyn ConnectionWrapper) -> rusqlite::Result<Self> {
        let new_instance = Self {
            root_transaction: Some(conn.transaction()?),
        };
        Ok(new_instance)
    }

    fn root_transaction_ref(&self) -> &Transaction<'a> {
        self.root_transaction.as_ref().expect_v("root transaction")
    }
}

impl DBMigrationUtilities for DBMigrationUtilitiesReal<'_> {
    fn update_schema_version(&self, updated_to: String) -> rusqlite::Result<()> {
        todo!("test-drive-me");
        DbMigratorReal::update_schema_version(&self.root_transaction_ref(), updated_to)
    }

    fn execute_upon_transaction(&self, sql_statements: &[&'static str]) -> rusqlite::Result<()> {
        todo!("test-drive-me");
        let transaction = &self.root_transaction_ref();
        for stm in sql_statements {
            transaction.execute(stm, NO_PARAMS)?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), String> {
        todo!("test-drive the following");
        self.root_transaction
            .take()
            .expect_v("owned root transaction")
            .commit()
            .map_err(|e| e.to_string())
    }
}

//define a new update here and add it to this list: 'list_of_existing_updates()'
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_0_to_1;

impl DatabaseMigration for Migrate_0_to_1 {
    fn migrate(
        &self,
        mig_utils: &dyn DBMigrationUtilities,
    ) -> rusqlite::Result<()> {
        mig_utils.execute_upon_transaction(&[
            "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
            //another statement would follow here
        ])
    }

    fn old_version(&self) -> usize {
        0
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

impl DbMigratorReal {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("DbMigrator"),
        }
    }

    fn list_of_existing_updates<'a>() -> &'a [&'a dyn DatabaseMigration] {
        &[&Migrate_0_to_1]
    }

    fn make_updates<'a>(
        &self,
        mismatched_schema: usize,
        mut migration_utilities: Box<dyn DBMigrationUtilities + 'a>,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<(), String> {
        let updates_to_process = Self::aggregated_checks(mismatched_schema, list_of_updates)?;
        let mut peekable_list = updates_to_process.iter().peekable();
        for _ in 0..peekable_list.len() {
            let (first_record, next_record) = Self::process_items_behind_dirty_references(
                peekable_list.next(),
                peekable_list.peek(),
            );
            let versions_in_question =
                Self::context_between_two_versions(first_record.old_version(), &next_record);

            if let Err(e) =
                Self::migrate_semi_automated(first_record, next_record, &*migration_utilities)
            {
                return self.take_care_of_bad_news(&versions_in_question, e);
            }
            self.log_success(&versions_in_question)
        }
        migration_utilities.commit()
    }

    fn migrate_semi_automated<'a>(
        record: &dyn DatabaseMigration,
        updated_to: String,
        migration_utilities: &dyn DBMigrationUtilities,
    ) -> rusqlite::Result<()> {
        record.migrate(migration_utilities)?;
        migration_utilities.update_schema_version(updated_to)
    }

    fn update_schema_version(
        transaction: &Transaction,
        updated_to: String,
    ) -> rusqlite::Result<()> {
        transaction.execute(
            "UPDATE config SET value = ? WHERE name = 'schema_version'",
            &[updated_to],
        )?;
        Ok(())
    }

    fn aggregated_checks<'a>(
        mismatched_schema: usize,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<Vec<&'a (dyn DatabaseMigration + 'a)>, String> {
        Self::schema_initial_validation_check(mismatched_schema);
        let updates_to_process = list_of_updates
            .iter()
            .skip_while(|entry| entry.old_version().ne(&mismatched_schema))
            .map(Self::deref)
            .collect::<Vec<&(dyn DatabaseMigration + 'a)>>();
        let _ = Self::check_out_quantity_of_those_remaining(
            mismatched_schema,
            updates_to_process.len(),
        )?;
        Ok(updates_to_process)
    }

    fn deref<'a>(value: &'a &dyn DatabaseMigration) -> &'a dyn DatabaseMigration {
        *value
    }

    fn process_items_behind_dirty_references<'a>(
        first: Option<&'a &dyn DatabaseMigration>,
        second: Option<&&&dyn DatabaseMigration>,
    ) -> (&'a dyn DatabaseMigration, String) {
        let first = *first.expect_v("migration record");
        let identity_of_the_second = Self::identify_the_next_one(second);
        (first, identity_of_the_second)
    }

    fn identify_the_next_one(subject: Option<&&&dyn DatabaseMigration>) -> String {
        if let Some(next_higher) = subject {
            next_higher.old_version().to_string()
        } else {
            CURRENT_SCHEMA_VERSION.to_string()
        }
    }

    fn check_out_quantity_of_those_remaining(
        mismatched_schema: usize,
        count: usize,
    ) -> Result<(), String> {
        match count {
            0 => Err(format!("Database claims to be more advanced ({}) than the version {} which is the latest released.", mismatched_schema, CURRENT_SCHEMA_VERSION)),
            _ => Ok(())
        }
    }

    fn take_care_of_bad_news(&self, versions: &str, error: rusqlite::Error) -> Result<(), String> {
        let error_message = format!("Updating database {} failed: {:?}", versions, error);
        warning!(self.logger, "{}", &error_message);
        Err(error_message)
    }

    fn context_between_two_versions(first: usize, second: &str) -> String {
        format!("from version {} to {}", first, second)
    }

    fn log_success(&self, versions: &str) {
        info!(self.logger, "Database successfully updated {}", versions)
    }

    fn compare_two_numbers(first: usize, second: usize) -> bool {
        first.le(&second)
    }

    fn schema_initial_validation_check(mismatched_schema: usize) {
        //TODO is really this effort necessary any longer?
        if mismatched_schema.eq(&CURRENT_SCHEMA_VERSION) {
            panic!("Ordered to update the database but already up to date")
        };
        //check for a higher version than the last official takes place further
    }
}

#[cfg(test)]
mod tests {
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::database::db_migrations::{DBMigrationUtilities, DatabaseMigration, Migrate_0_to_1};
    use crate::database::db_migrations::{DbMigratorReal};
    use crate::database::test_utils::assurance_query_for_config_table;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use lazy_static::lazy_static;
    use masq_lib::test_utils::utils::BASE_TEST_DIR;
    use rusqlite::{Connection, Transaction, NO_PARAMS};
    use std::cell::RefCell;
    use std::fs::create_dir_all;
    use std::ops::Not;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;

    #[derive(Default)]
    struct DBMigrationUtilitiesMock {
        update_schema_version_params: Arc<Mutex<Vec<String>>>,
        update_schema_version_results: RefCell<Vec<rusqlite::Result<()>>>,
        execute_upon_transaction_params: Arc<Mutex<Vec<Vec<String>>>>,
        execute_upon_transaction_result: RefCell<Vec<rusqlite::Result<()>>>,
        commit_params: Arc<Mutex<Vec<()>>>,
        commit_results: RefCell<Vec<Result<(), String>>>,
    }

    impl DBMigrationUtilitiesMock {
        pub fn update_schema_version_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
            self.update_schema_version_params = params.clone();
            self
        }

        pub fn update_schema_version_result(self, result: rusqlite::Result<()>) -> Self {
            self.update_schema_version_results.borrow_mut().push(result);
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
            self.execute_upon_transaction_result
                .borrow_mut()
                .push(result);
            self
        }

        pub fn commit_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.commit_params = params.clone();
            self
        }

        pub fn commit_result(self, result: Result<(), String>) -> Self {
            self.commit_results.borrow_mut().push(result);
            self
        }
    }

    impl DBMigrationUtilities for DBMigrationUtilitiesMock {
        fn update_schema_version(&self, updated_to: String) -> rusqlite::Result<()> {
            self.update_schema_version_params
                .lock()
                .unwrap()
                .push(updated_to);
            self.update_schema_version_results.borrow_mut().remove(0)
        }

        fn execute_upon_transaction(
            &self,
            sql_statements: &[&'static str],
        ) -> rusqlite::Result<()> {
            self.execute_upon_transaction_params.lock().unwrap().push(
                sql_statements
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
            );
            self.execute_upon_transaction_result.borrow_mut().remove(0)
        }

        fn commit(&mut self) -> Result<(), String> {
            self.commit_params.lock().unwrap().push(());
            self.commit_results.borrow_mut().remove(0)
        }
    }

    lazy_static! {
        static ref TEST_DIRECTORY_FOR_DB_MIGRATION: PathBuf =
            PathBuf::from(format!("{}/db_migration", BASE_TEST_DIR));
    }

    #[test]
    #[should_panic(expected = "Ordered to update the database but already up to date")]
    fn schema_initial_validation_check_panics_if_the_given_schema_is_equal_to_the_latest_one() {
        let _ = DbMigratorReal::schema_initial_validation_check(CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn make_updates_panics_if_the_given_schema_is_of_higher_number_than_the_latest_official() {
        let last_version = CURRENT_SCHEMA_VERSION;
        let too_advanced = last_version + 1;
        let migration_utilities = DBMigrationUtilitiesMock::default();
        let connection = ConnectionWrapperMock::default();

        let subject = DbMigratorReal::default();

        let result = subject.make_updates(
            too_advanced,
            Box::new(migration_utilities),
            DbMigratorReal::list_of_existing_updates(),
        );

        assert_eq!(result,Err(format!("Database claims to be more advanced ({}) than the version {} which is the latest released.",too_advanced,CURRENT_SCHEMA_VERSION)))
    }

    #[derive(Default, Debug)]
    struct MigrationRecordMock {
        old_version_result: RefCell<usize>,
        migrate_params: Arc<Mutex<Vec<()>>>, //TODO is there a better thing to assert on than just to pretend
        migrate_result: RefCell<Vec<rusqlite::Result<()>>>,
    }

    impl MigrationRecordMock {
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
    }

    impl DatabaseMigration for MigrationRecordMock {
        fn migrate(
            &self,
            migration_utilities: &dyn DBMigrationUtilities,
        ) -> rusqlite::Result<()> {
            //TODO add params mechanism
            // self.migrate_params.lock().unwrap().push(()); //TODO rethink, seems bad
            self.migrate_result.borrow_mut().remove(0)
        }

        fn old_version(&self) -> usize {
            self.old_version_result.clone().take()
        }
    }

    #[test]
    #[should_panic(expected = "The list of updates for the database is not ordered properly")]
    fn list_validation_check_works() {
        let fake_one = MigrationRecordMock::default().old_version_result(6);
        let fake_two = MigrationRecordMock::default().old_version_result(3);
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_to_1, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    fn list_validation_check<'a>(list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)]) {
        let iterator = list_of_updates.iter();
        let iterator_shifted = list_of_updates.iter().skip(1);
        iterator.zip(iterator_shifted).for_each(|(first, second)| {
            if DbMigratorReal::compare_two_numbers(first.old_version(), second.old_version()).not()
            {
                panic!("The list of updates for the database is not ordered properly")
            }
        });
    }

    #[test]
    fn list_of_existing_updates_is_correctly_ordered() {
        let _ = list_validation_check(DbMigratorReal::list_of_existing_updates());
        //success if no panicking
    }

    #[test]
    fn initiate_list_of_existing_updates_does_not_end_with_version_higher_than_the_current_version()
    {
        let last_entry = DbMigratorReal::list_of_existing_updates()
            .into_iter()
            .last();

        let result = last_entry.unwrap().old_version();

        assert!(DbMigratorReal::compare_two_numbers(
            result,
            CURRENT_SCHEMA_VERSION
        ))
    }

    #[test]
    fn db_migration_happy_path() {
        init_test_logging();
        let execute_upon_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let update_schema_version_params_arc = Arc::new(Mutex::new(vec![]));
        let commit_params_arc = Arc::new(Mutex::new(vec![]));
        let outdated_schema = 0;
        let list = &[&Migrate_0_to_1 as &dyn DatabaseMigration];
        let migration_utils = DBMigrationUtilitiesMock::default()
            .execute_upon_transaction_params(&execute_upon_transaction_params_arc)
            .execute_upon_transaction_result(Ok(()))
            .update_schema_version_params(&update_schema_version_params_arc)
            .update_schema_version_result(Ok(()))
            .commit_params(&commit_params_arc)
            .commit_result(Ok(()));
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, Box::new(migration_utils), list);

        assert!(result.is_ok());
        let execute_upon_transaction_params = execute_upon_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *execute_upon_transaction_params[0],
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
            ]
        );
        let update_schema_version_params = update_schema_version_params_arc.lock().unwrap();
        assert_eq!(update_schema_version_params[0], "1");
        let commit_params = commit_params_arc.lock().unwrap();
        assert_eq!(commit_params[0], ());
        TestLogHandler::new().exists_log_containing(
            "INFO: DbMigrator: Database successfully updated from version 0 to 1",
        );
    }

    //TODO test multiple items...maybe even with a failure on some later record

    #[test]
    fn transacting_migration_sad_path() {
        // init_test_logging();
        // let execution_upon_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        // //let connection = Connection::open_in_memory().unwrap();
        // // connection
        // //     .execute(
        // //         "CREATE TABLE test (
        // //     name TEXT,
        // //     value TEXT
        // // )",
        // //         NO_PARAMS,
        // //     )
        // //     .unwrap();
        // let mut connection_wrapper = ConnectionWrapperMock::default();
        // // .execute_upon_transaction_result(Err(rusqlite::Error::InvalidQuery))
        // // .execute_upon_transaction_params(params_arc_clone);
        // let outdated_schema = 0;
        // let list = &[&MigrationRecordMock::default()
        //     .old_version_result(0)
        //     .execute_upon_transaction_params(&execution_upon_transaction_params_arc)
        //     .execute_upon_transaction_result(Err(rusqlite::Error::InvalidQuery))
        //     as &(dyn DatabaseMigration + 'static)];
        // //.inject_update_statement(update_statement)
        // //.inject_sql_statement(statement) as &(dyn DatabaseMigration + 'static)];
        // //let connection_wrapper
        // let transaction = connection_wrapper.transaction().unwrap();
        // let migration_utils = DBMigrationUtilitiesMock::default(); //TODO missing configuration
        // let subject = DbMigratorReal::default();
        //
        // let result = subject.make_updates(outdated_schema, Box::new(connection_wrapper),Box::new(migration_utils),list);
        //
        // assert_eq!(
        //     result,
        //     Err("Updating database from version 0.0.10 to 0.11 failed: InvalidQuery".to_string())
        // );
        // assert_eq!(
        //     *execution_upon_transaction_params_arc
        //         .lock()
        //         .unwrap()
        //         .pop()
        //         .unwrap(),
        //     vec![
        //         "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
        //     ]
        // );
        // TestLogHandler::new().exists_log_containing(
        //     "WARN: DbMigrator: Updating database from version 0.0.10 to 0.11 failed: InvalidQuery",
        // );
    }

    #[test]
    fn migration_from_0_0_10_to_0_11_is_properly_set() {
        // let dir_path = TEST_DIRECTORY_FOR_DB_MIGRATION.join("0_0_10_to_0_11");
        // create_dir_all(&dir_path).unwrap();
        // let db_path = dir_path.join("test_database.db");
        // let connection = Connection::open(&db_path).unwrap();
        // connection
        //     .execute(
        //         "create table if not exists config (
        //         name text not null,
        //         value text,
        //         encrypted integer not null
        //     )",
        //         NO_PARAMS,
        //     )
        //     .unwrap();
        // connection.execute("INSERT INTO config (name, value, encrypted) VALUES ('schema_version', '0.0.10', 0)",NO_PARAMS).unwrap();
        // let connection_wrapper = ConnectionWrapperReal::new(connection);
        // let outdated_schema = 0;
        // let list = &[&Migrate_0_to_1 as &(dyn DatabaseMigration + 'static)];
        // let migration_utils = DBMigrationUtilitiesMock::default();
        // let subject = DbMigratorReal::default();
        //
        // let result = subject.make_updates(outdated_schema, Box::new(migration_utils),list);
        //
        // assert!(result.is_ok());
        // let connection = Connection::open(&db_path).unwrap();
        // let (mp_name, mp_value, mp_encrypted): (String, Option<String>, u16) =
        //     assurance_query_for_config_table(
        //         &connection,
        //         "select name, value, encrypted from config where name = 'mapping_protocol'",
        //     );
        // let (cs_name, cs_value, cs_encrypted): (String, Option<String>, u16) =
        //     assurance_query_for_config_table(
        //         &connection,
        //         "select name, value, encrypted from config where name = 'schema_version'",
        //     );
        // assert_eq!(mp_name, "mapping_protocol".to_string());
        // assert_eq!(mp_value, None);
        // assert_eq!(mp_encrypted, 0);
        // assert_eq!(cs_name, "schema_version".to_string());
        // assert_eq!(cs_value, Some("1".to_string()));
        // assert_eq!(cs_encrypted, 0)
    }
}
