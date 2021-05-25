// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use regex::Regex;
use std::fmt::Debug;
use std::ops::Not;
use std::slice::Iter;

const THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS: &str = "0.0.10";

trait MigrateDatabase: Debug + 'static {
    fn migrate(&self, conn: &Box<dyn ConnectionWrapper>) -> rusqlite::Result<usize>;
    fn version_compatibility(&self) -> &str;
}

//define your update here
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_0_0_10_to_0_0_11;

impl MigrateDatabase for Migrate_0_0_10_to_0_0_11 {
    fn migrate(&self, conn: &Box<dyn ConnectionWrapper>) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
        )
    }

    fn version_compatibility(&self) -> &str {
        "0.0.10"
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn migrate_database(outdated_schema: &str, conn: Box<dyn ConnectionWrapper>) {
    make_updates(outdated_schema, list_of_existing_updates(), conn)
}

fn make_updates<'a>(
    outdated_schema: &str,
    list_of_updates: &'a [&'a dyn MigrateDatabase],
    conn: Box<dyn ConnectionWrapper>,
) {
    schema_initial_validation_check(outdated_schema);
    let list_iterator = list_validation_check(list_of_updates);
    let updates_to_process =
        list_iterator.skip_while(|entry| entry.version_compatibility() != outdated_schema);
    if updates_to_process.clone().count() == 0 {
        panic!("Your database schema claims to be newer than the official newest one")
    }
    eprintln!("{:?}", updates_to_process);
    updates_to_process.for_each(|record| {
        if let Err(e) = record.migrate(&conn) {
            panic!(
                "Updating database from version {} failed due to: {:?}",
                record.version_compatibility(),
                e
            )
        }
    })
}

//to avoid creating an unnecessary global variable
fn list_of_existing_updates<'a>() -> &'a [&'a dyn MigrateDatabase] {
    &[&Migrate_0_0_10_to_0_0_11]
}

fn list_validation_check<'a>(
    list_of_updates: &'a [&'a (dyn MigrateDatabase + 'static)],
) -> Iter<'a, &'a dyn MigrateDatabase> {
    let iterator = list_of_updates.iter();
    let iterator_shifted = list_of_updates.iter().skip(1);
    iterator
        .clone()
        .zip(iterator_shifted)
        .for_each(|(first, second)| {
            if compare_set_of_numbers(
                first.version_compatibility(),
                second.version_compatibility(),
            )
            .not()
            {
                panic!("The list of updates for the database is not sorted properly")
            }
        });
    iterator
}

fn compare_set_of_numbers(first_set: &str, second_set: &str) -> bool {
    str_version_numeric_transcription(first_set)
        .iter()
        .zip(str_version_numeric_transcription(second_set).iter())
        .map(|(first_set_digits, second_set_digits)| first_set_digits <= second_set_digits)
        .all(|element| element == true)
}

fn str_version_numeric_transcription(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|section| section.parse::<u32>().unwrap())
        .collect::<Vec<u32>>()
}

fn schema_initial_validation_check(outdated_schema: &str) {
    if Regex::new(r"\d+\.\d+\.\d+")
        .expect("regex failed")
        .is_match(outdated_schema)
        .not()
    {
        panic!("Database is corrupted: current schema")
    };
    if compare_set_of_numbers(outdated_schema, THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS)
        && outdated_schema != THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS
    {
        panic!("Database version is too low and incompatible with any official version: database corrupted")
    };
    if outdated_schema == CURRENT_SCHEMA_VERSION {
        panic!("Ordered to update the database but already up to date")
    };
    //check for a too high version is placed further
}

#[cfg(test)]
mod tests {
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::database::db_migration::MigrateDatabase;
    use crate::database::db_migration::{
        compare_set_of_numbers, list_of_existing_updates, make_updates,
        schema_initial_validation_check, str_version_numeric_transcription,
        Migrate_0_0_10_to_0_0_11,
    };
    use crossbeam_channel::bounded;
    use rusqlite::{Connection, NO_PARAMS};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::{panic, thread};

    #[test]
    #[should_panic(expected = "Database is corrupted: current schema")]
    fn validation_check_panics_if_the_given_schema_has_wrong_syntax() {
        let _ = schema_initial_validation_check("0.xx.5");
    }

    #[test]
    #[should_panic(expected = "Ordered to update the database but already up to date")]
    fn validation_check_panics_if_the_given_schema_is_equal_to_the_latest_one() {
        let _ = schema_initial_validation_check(CURRENT_SCHEMA_VERSION);
    }

    #[test]
    #[should_panic(
        expected = "Database version is too low and incompatible with any official version: database corrupted"
    )]
    fn validation_check_panics_if_the_given_schema_is_lower_than_any_in_the_list() {
        let _ = schema_initial_validation_check("0.0.0");
    }

    #[test]
    #[should_panic(
        expected = "Your database schema claims to be newer than the official newest one"
    )]
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

        let _ = make_updates(
            too_advanced.as_str(),
            list_of_existing_updates(),
            Box::new(ConnectionWrapperMock::default()),
        );
    }

    #[test]
    fn version_numeric_transcription_works() {
        let result = str_version_numeric_transcription("3.21.6");

        assert_eq!(*result, [3, 21, 6])
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_happy_path() {
        let result = compare_set_of_numbers("0.30.33", "1.30.33");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_middle_grade_happy_path() {
        let result = compare_set_of_numbers("0.2.33", "0.3.33");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_happy_path() {
        let result = compare_set_of_numbers("0.30.33", "0.30.34");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_bad_path() {
        let result = compare_set_of_numbers("1.30.33", "0.30.34");

        assert_eq!(result, false)
    }

    #[test]
    fn compare_set_of_numbers_middle_grade_bad_path() {
        let result = compare_set_of_numbers("0.8.33", "0.3.37");

        assert_eq!(result, false)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_bad_path() {
        let result = compare_set_of_numbers("0.30.33", "0.30.31");

        assert_eq!(result, false)
    }

    #[derive(Default, Debug)]
    struct FakeMigrationRecord {
        version_result: RefCell<&'static str>,
        sql_statement: RefCell<&'static str>,
    }

    impl FakeMigrationRecord {
        fn version_result(self, result: &'static str) -> Self {
            self.version_result.replace(result);
            self
        }
        fn sql_statement(self, result: &'static str) -> Self {
            self.sql_statement.replace(result);
            self
        }
    }

    impl MigrateDatabase for FakeMigrationRecord {
        fn migrate(&self, conn: &Box<dyn ConnectionWrapper>) -> rusqlite::Result<usize> {
            conn.execute(&self.sql_statement.take())
        }

        fn version_compatibility(&self) -> &str {
            self.version_result.clone().take()
        }
    }

    #[test]
    #[should_panic(expected = "The list of updates for the database is not sorted properly")]
    fn make_updates_panics_if_the_list_of_updates_is_not_sorted_in_ascending_order() {
        let list: &[&dyn MigrateDatabase] = &[
            &Migrate_0_0_10_to_0_0_11,
            &FakeMigrationRecord::default().version_result("0.0.50"),
            &FakeMigrationRecord::default().version_result("0.0.13"),
        ];

        let _ = make_updates("0.0.10", list, Box::new(ConnectionWrapperMock::default()));
    }

    #[test]
    fn initiate_list_of_existing_updates_does_not_end_with_version_higher_than_the_current_version()
    {
        let last_entry = list_of_existing_updates().into_iter().last();

        let result = last_entry.unwrap().version_compatibility();

        assert!(compare_set_of_numbers(result, CURRENT_SCHEMA_VERSION))
    }

    #[test]
    fn transacting_migration_happy_path() {
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
        let statement = "INSERT INTO test (name, value) VALUES (\"booga\", \"gibberish\")";
        let list = &[&FakeMigrationRecord::default()
            .version_result("0.0.10")
            .sql_statement(statement) as &(dyn MigrateDatabase + 'static)];

        let _ = make_updates(outdated_schema, list, Box::new(connection_wrapper));
    }

    #[test]
    #[should_panic(expected = "Updating database from version 0.0.10 failed due to: InvalidQuery")]
    fn transacting_migration_sad_path() {
        let execution_params_arc = Arc::new(Mutex::new(vec![]));
        let params_arc_clone = execution_params_arc.clone();
        let (tx, rx) = bounded(1);
        let handle = thread::spawn(move || {
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
            let connection_wrapper = ConnectionWrapperMock::default()
                .execute_result(Err(rusqlite::Error::InvalidQuery))
                .execute_params(params_arc_clone);
            let outdated_schema = "0.0.10";
            let list = &[&Migrate_0_0_10_to_0_0_11 as &(dyn MigrateDatabase + 'static)];

            let _ = make_updates(outdated_schema, list, Box::new(connection_wrapper));
            tx.send(()).unwrap()
        });
        //waits until tx dies due to a panic in its thread
        rx.recv().unwrap_err();

        //now we should have the vec for params filled with data
        assert_eq!(
            *execution_params_arc
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
                    .to_string()
            ]
        );
        //this is a hack as big as a mountain but let's be benevolent once
        //interpretation: message which belongs to the panic from the background thread is inserted into another panic
        //in the foreground thread to prevent a failure of this test because of the panic in '<unnamed>' thread
        handle
            .join()
            .unwrap_or_else(|e| panic!("{}", e.downcast_ref::<String>().unwrap()));
    }
}
