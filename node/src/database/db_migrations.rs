// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use crate::sub_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use regex::Regex;
use rusqlite::{Transaction, NO_PARAMS};
use std::fmt::Debug;

const VERSION_BEFORE_THE_PASS_TO_THE_NEW_FORMAT: &str = "0.0.10";
const THE_EARLIEST_RECORD_OF_DB_MIGRATION_IN_THE_TWO_DIGIT_FORMAT: &str = "0.11";

pub trait DbMigrator {
    fn migrate_database(
        &self,
        mismatched_schema: &str,
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
        mismatched_schema: &str,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        self.make_updates(mismatched_schema, Self::list_of_existing_updates(), conn)
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
    fn migrate<'a: 'b, 'b>(
        &self,
        conn: &'a mut (dyn ConnectionWrapper + 'a),
    ) -> rusqlite::Result<Transaction<'b>>;
    fn old_version(&self) -> &str;

    fn update_schema_version(
        //this 'self' use is vain but required by testing and trait object safeness
        &self,
        transaction: &Transaction,
        updated_to: String,
    ) -> rusqlite::Result<()> {
        DbMigratorReal::update_schema_version(transaction, updated_to)
    }
    fn execute_upon_transaction<'a: 'b, 'b>(
        //this 'self' use is vain but required by testing and trait object safeness
        &self,
        conn: &'a mut (dyn ConnectionWrapper + 'a),
        sql_statements: &[&'static str],
    ) -> rusqlite::Result<Transaction<'b>> {
        let transaction = conn.transaction()?;
        for stm in sql_statements {
            transaction.execute(stm, NO_PARAMS)?;
        }
        Ok(transaction)
    }
}

//define your update here and add it to this list: 'list_of_existing_updates()'
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_0_0_10_to_0_11;

impl DatabaseMigration for Migrate_0_0_10_to_0_11 {
    fn migrate<'a: 'b, 'b>(
        &self,
        conn: &'a mut (dyn ConnectionWrapper + 'a),
    ) -> rusqlite::Result<Transaction<'b>> {
        self.execute_upon_transaction(
            conn,
            &[
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
                //another statement would follow here
            ],
        )
    }

    fn old_version(&self) -> &str {
        "0.0.10"
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
        &[&Migrate_0_0_10_to_0_11]
    }

    fn make_updates<'a>(
        &self,
        mismatched_schema: &str,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
        mut conn: Box<dyn ConnectionWrapper + 'a>,
    ) -> Result<(), String> {
        let updates_to_process = Self::aggregated_checks(mismatched_schema, list_of_updates)?;
        let mut peekable_list = updates_to_process.iter().peekable();
        for _ in 0..peekable_list.len() {
            let (first_record, next_record) = Self::process_items_from_beneath_dirty_references(
                peekable_list.next(),
                peekable_list.peek(),
            );
            let versions_in_question =
                Self::context_between_two_versions(first_record.old_version(), &next_record);

            if let Err(e) = Self::migrate_semi_automated(first_record, next_record, &mut *conn) {
                return self.see_about_bad_news(&versions_in_question, e);
            }
            self.log_success(&versions_in_question)
        }
        Ok(())
    }

    fn migrate_semi_automated<'a>(
        record: &dyn DatabaseMigration,
        updated_to: String,
        conn: &mut (dyn ConnectionWrapper + 'a),
    ) -> rusqlite::Result<()> {
        let transaction = record.migrate(conn)?;
        record.update_schema_version(&transaction, updated_to)?;
        transaction.commit()
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
        mismatched_schema: &str,
        list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)],
    ) -> Result<Vec<&'a (dyn DatabaseMigration + 'a)>, String> {
        Self::schema_initial_validation_check(mismatched_schema);
        let updates_to_process = list_of_updates
            .iter()
            .skip_while(|entry| entry.old_version().ne(mismatched_schema))
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

    fn process_items_from_beneath_dirty_references<'a>(
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
        mismatched_schema: &str,
        count: usize,
    ) -> Result<(), String> {
        match count {
            0 => Err(format!("Database claims to be more advanced ({}) than the version {} which is the latest released.", mismatched_schema, CURRENT_SCHEMA_VERSION)),
            _ => Ok(())
        }
    }

    fn see_about_bad_news(&self, versions: &str, error: rusqlite::Error) -> Result<(), String> {
        let error_message = format!("Updating database {} failed: {:?}", versions, error);
        warning!(self.logger, "{}", &error_message);
        Err(error_message)
    }

    fn context_between_two_versions(first: &str, second: &str) -> String {
        format!("from version {} to {}", first, second)
    }

    fn log_success(&self, versions: &str) {
        info!(self.logger, "Database successfully updated {}", versions)
    }

    fn compare_set_of_numbers(first_set: &str, second_set: &str) -> bool {
        Self::str_version_numeric_transcription(first_set)
            .iter()
            .zip(Self::str_version_numeric_transcription(second_set).iter())
            .map(|(first_set_digits, second_set_digits)| first_set_digits <= second_set_digits)
            .all(|element| element)
    }

    fn str_version_numeric_transcription(version: &str) -> Vec<u32> {
        version
            .split('.')
            .map(|section| section.parse::<u32>().expect_v("pre-checked form"))
            .collect::<Vec<u32>>()
    }

    fn schema_initial_validation_check(mismatched_schema: &str) {
        if mismatched_schema.eq(VERSION_BEFORE_THE_PASS_TO_THE_NEW_FORMAT) {
            return;
        };
        if Self::wrong_syntax_detected_by_regex(mismatched_schema) {
            panic!(
                "Database is corrupted: schema version syntax {{{}}}",
                mismatched_schema
            )
        };
        if Self::compare_set_of_numbers(
            mismatched_schema,
            THE_EARLIEST_RECORD_OF_DB_MIGRATION_IN_THE_TWO_DIGIT_FORMAT,
        ) && mismatched_schema.ne(THE_EARLIEST_RECORD_OF_DB_MIGRATION_IN_THE_TWO_DIGIT_FORMAT)
        {
            panic!("Database version is too low and incompatible with any official version: database corrupted")
        };
        if mismatched_schema.eq(CURRENT_SCHEMA_VERSION) {
            panic!("Ordered to update the database but already up to date")
        };
        //check for a higher version than the last official takes place further
    }

    fn wrong_syntax_detected_by_regex(mismatched_schema: &str) -> bool {
        match Regex::new(r"\d+\.\d+")
            .expect("regex failed")
            .find(mismatched_schema)
        {
            None => true,
            Some(unchecked_match) => {
                let range = unchecked_match.range();
                if range.start == 0 && range.end == mismatched_schema.len() {
                    false
                } else {
                    true
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::database::db_migrations::{DatabaseMigration, Migrate_0_0_10_to_0_11};
    use crate::database::db_migrations::{
        DbMigratorReal, VERSION_BEFORE_THE_PASS_TO_THE_NEW_FORMAT,
    };
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

    lazy_static! {
        static ref TEST_DIRECTORY_FOR_DB_MIGRATION: PathBuf =
            PathBuf::from(format!("{}/db_migration", BASE_TEST_DIR));
    }

    #[test]
    #[should_panic(expected = "Database is corrupted: schema version syntax {0.a.b}")]
    fn schema_initial_validation_check_panics_if_the_given_schema_has_wrong_syntax() {
        let _ = DbMigratorReal::schema_initial_validation_check("0.a.b");
    }

    #[test]
    #[should_panic(expected = "Database is corrupted: schema version syntax {0.2.5.8}")]
    fn schema_initial_validation_check_panics_if_the_given_schema_has_wrong_syntax_but_which_includes_a_sector_of_the_right_form(
    ) {
        let _ = DbMigratorReal::schema_initial_validation_check("0.2.5.8");
    }

    #[test]
    fn schema_initial_validation_check_with_three_digits_passes_for_0_0_10() {
        let _ = DbMigratorReal::schema_initial_validation_check(
            VERSION_BEFORE_THE_PASS_TO_THE_NEW_FORMAT,
        );
    }

    #[test]
    #[should_panic(expected = "Ordered to update the database but already up to date")]
    fn schema_initial_validation_check_panics_if_the_given_schema_is_equal_to_the_latest_one() {
        let _ = DbMigratorReal::schema_initial_validation_check(CURRENT_SCHEMA_VERSION);
    }

    #[test]
    #[should_panic(
        expected = "Database version is too low and incompatible with any official version: database corrupted"
    )]
    fn schema_initial_validation_check_panics_if_the_given_schema_is_lower_than_any_in_the_list() {
        let _ = DbMigratorReal::schema_initial_validation_check("0.8");
    }

    #[test]
    fn make_updates_panics_if_the_given_schema_is_of_higher_number_than_the_latest_official() {
        let ending_digit: char = CURRENT_SCHEMA_VERSION.chars().last().unwrap();
        let higher_number = ending_digit.to_digit(10).unwrap() + 1;
        let too_advanced = format!(
            "{}{}",
            CURRENT_SCHEMA_VERSION
                .strip_suffix(ending_digit)
                .unwrap()
                .to_string(),
            higher_number
        );
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(
            too_advanced.as_str(),
            DbMigratorReal::list_of_existing_updates(),
            Box::new(ConnectionWrapperMock::default()),
        );

        assert_eq!(result,Err(format!("Database claims to be more advanced ({}) than the version {} which is the latest released.",too_advanced,CURRENT_SCHEMA_VERSION)))
    }

    #[test]
    fn version_numeric_transcription_works() {
        let result = DbMigratorReal::str_version_numeric_transcription("3.21.6");

        assert_eq!(*result, [3, 21, 6])
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_happy_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.33", "1.33"); //unrealistic--should be 0.33 -> 1.00

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_switching_from_d_d_d_to_d_d_works() {
        let result = DbMigratorReal::compare_set_of_numbers("0.0.10", "0.11");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_happy_path() {
        let result = DbMigratorReal::compare_set_of_numbers("3.33", "3.34");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_bad_path() {
        let result = DbMigratorReal::compare_set_of_numbers("1.33", "0.34");

        assert_eq!(result, false)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_bad_path() {
        let result = DbMigratorReal::compare_set_of_numbers("30.33", "30.31");

        assert_eq!(result, false)
    }

    #[derive(Default, Debug)]
    struct MigrationRecordMock<'a> {
        old_version_result: RefCell<&'static str>,
        main_migration_statements: RefCell<&'static [&'static str]>,
        update_statement: RefCell<&'static str>,
        execute_upon_transaction_params: Arc<Mutex<Vec<Vec<String>>>>,
        execute_upon_transaction_result: RefCell<Vec<rusqlite::Result<Transaction<'a>>>>,
    }

    impl MigrationRecordMock<'_> {
        fn old_version_result(self, result: &'static str) -> Self {
            self.old_version_result.replace(result);
            self
        }
        fn inject_sql_statement(self, statement: &'static [&'static str]) -> Self {
            self.main_migration_statements.replace(statement);
            self
        }

        fn inject_update_statement(self, statement: &'static str) -> Self {
            self.update_statement.replace(statement);
            self
        }

        fn execute_upon_transaction_result(
            self,
            result: rusqlite::Result<Transaction<'static>>,
        ) -> Self {
            self.execute_upon_transaction_result
                .borrow_mut()
                .push(result);
            self
        }

        fn execute_upon_transaction_params(
            mut self,
            params: &Arc<Mutex<Vec<Vec<String>>>>,
        ) -> Self {
            self.execute_upon_transaction_params = params.clone();
            self
        }
    }

    impl DatabaseMigration for MigrationRecordMock<'_> {
        fn migrate<'a: 'b, 'b>(
            &self,
            conn: &'a mut (dyn ConnectionWrapper + 'a),
        ) -> rusqlite::Result<Transaction<'b>> {
            self.execute_upon_transaction(conn, self.main_migration_statements.take())
        }

        fn old_version(&self) -> &str {
            self.old_version_result.clone().take()
        }

        fn update_schema_version(
            &self,
            transaction: &Transaction,
            _updated_to: String,
        ) -> rusqlite::Result<()> {
            todo!("resolve what to do with this active mock");
            transaction.execute(self.update_statement.take(), NO_PARAMS)?;
            Ok(())
        }

        fn execute_upon_transaction<'a: 'b, 'b>(
            &self,
            conn: &'a mut (dyn ConnectionWrapper + 'a),
            _sql_statements: &[&'static str],
        ) -> rusqlite::Result<Transaction<'b>> {
            todo!("resolve what to do with this active mock");
            let transaction = conn.transaction()?;
            for stm in self.main_migration_statements.take() {
                transaction.execute(stm, NO_PARAMS)?;
            }
            Ok(transaction)
        }
    }

    #[test]
    #[should_panic(expected = "The list of updates for the database is not ordered properly")]
    fn list_validation_check_works() {
        let fake_one = MigrationRecordMock::default().old_version_result("0.50");
        let fake_two = MigrationRecordMock::default().old_version_result("0.13");
        let list: &[&dyn DatabaseMigration] = &[&Migrate_0_0_10_to_0_11, &fake_one, &fake_two];

        let _ = list_validation_check(list);
    }

    fn list_validation_check<'a>(list_of_updates: &'a [&'a (dyn DatabaseMigration + 'a)]) {
        let iterator = list_of_updates.iter();
        let iterator_shifted = list_of_updates.iter().skip(1);
        iterator.zip(iterator_shifted).for_each(|(first, second)| {
            if DbMigratorReal::compare_set_of_numbers(first.old_version(), second.old_version())
                .not()
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

        assert!(DbMigratorReal::compare_set_of_numbers(
            result,
            CURRENT_SCHEMA_VERSION
        ))
    }

    #[test]
    fn transacting_migration_happy_path() {
        init_test_logging();
        //params are tested in the next test where I don't use ConnectionWrapperReal
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
        let connection_wrapper = ConnectionWrapperReal::new(connection);
        let outdated_schema = "0.0.10";
        let statement = &["INSERT INTO test (name, value) VALUES (\"booga\", \"gibberish\")"];
        let update_statement = "UPDATE test SET value = '0.11' WHERE name = 'schema_version'";
        let list = &[&MigrationRecordMock::default()
            .old_version_result("0.0.10")
            .inject_update_statement(update_statement)
            .inject_sql_statement(statement)
            as &(dyn DatabaseMigration + 'static)];
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, list, Box::new(connection_wrapper));

        eprintln!("{:?}", result);
        assert!(result.is_ok());
        TestLogHandler::new().exists_log_containing(
            "INFO: DbMigrator: Database successfully updated from version 0.0.10 to 0.11",
        );
    }

    #[test]
    fn transacting_migration_sad_path() {
        init_test_logging();
        let execution_upon_transaction_params_arc = Arc::new(Mutex::new(vec![]));
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
        let connection_wrapper = ConnectionWrapperMock::default();
        // .execute_upon_transaction_result(Err(rusqlite::Error::InvalidQuery))
        // .execute_upon_transaction_params(params_arc_clone);
        let outdated_schema = "0.0.10";
        let list = &[&MigrationRecordMock::default()
            .old_version_result("0.0.10")
            .execute_upon_transaction_params(&execution_upon_transaction_params_arc)
            .execute_upon_transaction_result(Err(rusqlite::Error::InvalidQuery))
            as &(dyn DatabaseMigration + 'static)];
        //.inject_update_statement(update_statement)
        //.inject_sql_statement(statement) as &(dyn DatabaseMigration + 'static)];
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, list, Box::new(connection_wrapper));

        assert_eq!(
            result,
            Err("Updating database from version 0.0.10 to 0.11 failed: InvalidQuery".to_string())
        );
        assert_eq!(
            *execution_upon_transaction_params_arc
                .lock()
                .unwrap()
                .pop()
                .unwrap(),
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
            ]
        );
        TestLogHandler::new().exists_log_containing(
            "WARN: DbMigrator: Updating database from version 0.0.10 to 0.11 failed: InvalidQuery",
        );
    }

    #[test]
    fn migration_from_0_0_10_to_0_11_is_properly_set() {
        let dir_path = TEST_DIRECTORY_FOR_DB_MIGRATION.join("0_0_10_to_0_11");
        create_dir_all(&dir_path).unwrap();
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "create table if not exists config (
                name text not null,
                value text,
                encrypted integer not null
            )",
                NO_PARAMS,
            )
            .unwrap();
        connection.execute("INSERT INTO config (name, value, encrypted) VALUES ('schema_version', '0.0.10', 0)",NO_PARAMS).unwrap();
        let connection_wrapper = ConnectionWrapperReal::new(connection);
        let outdated_schema = "0.0.10";
        let list = &[&Migrate_0_0_10_to_0_11 as &(dyn DatabaseMigration + 'static)];
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, list, Box::new(connection_wrapper));

        assert!(result.is_ok());
        let connection = Connection::open(&db_path).unwrap();
        let (mp_name, mp_value, mp_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                &connection,
                "select name, value, encrypted from config where name = 'mapping_protocol'",
            );
        let (cs_name, cs_value, cs_encrypted): (String, Option<String>, u16) =
            assurance_query_for_config_table(
                &connection,
                "select name, value, encrypted from config where name = 'schema_version'",
            );
        assert_eq!(mp_name, "mapping_protocol".to_string());
        assert_eq!(mp_value, None);
        assert_eq!(mp_encrypted, 0);
        assert_eq!(cs_name, "schema_version".to_string());
        assert_eq!(cs_value, Some("0.11".to_string()));
        assert_eq!(cs_encrypted, 0)
    }
}
