// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
use crate::sub_lib::logger::Logger;
use regex::Regex;
use std::fmt::Debug;
use std::ops::Not;
use std::slice::Iter;

const THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS: &str = "0.0.10";

trait MigrateDatabase: Debug + 'static {
    fn migrate<'a>(&self, conn: &mut Box<dyn ConnectionWrapper + 'a>) -> rusqlite::Result<()>;
    fn version_compatibility(&self) -> &str;
}

//define your update here
//use either 'execute' for a single operation or 'transaction' for multiple ones
////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Migrate_0_0_10_to_0_0_11;

impl MigrateDatabase for Migrate_0_0_10_to_0_0_11 {
    fn migrate<'a>(&self, conn: &mut Box<dyn ConnectionWrapper + 'a>) -> rusqlite::Result<()> {
        let transaction = conn.execute_upon_transaction(&[
            "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)",
            "UPDATE config SET value = '0.0.11' WHERE name = 'current_schema'",
        ])?;
        transaction.commit()
    }

    fn version_compatibility(&self) -> &str {
        "0.0.10"
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait DbMigrator {
    fn migrate_database(
        &self,
        outdated_schema: &str,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String>;
}

pub struct DbMigratorReal {
    logger: Logger,
}

impl DbMigrator for DbMigratorReal {
    fn migrate_database(
        &self,
        outdated_schema: &str,
        conn: Box<dyn ConnectionWrapper>,
    ) -> Result<(), String> {
        self.make_updates(outdated_schema, Self::list_of_existing_updates(), conn)
    }
}

impl Default for DbMigratorReal {
    fn default() -> Self {
        Self::new()
    }
}

impl DbMigratorReal {
    pub fn new() -> Self {
        Self {
            logger: Logger::new("DbMigrator"),
        }
    }

    fn make_updates<'a>(
        &self,
        outdated_schema: &str,
        list_of_updates: &'a [&'a dyn MigrateDatabase],
        mut conn: Box<dyn ConnectionWrapper + 'a>,
    ) -> Result<(), String> {
        Self::schema_initial_validation_check(outdated_schema);
        let list_iterator = Self::list_validation_check(list_of_updates);
        let updates_to_process =
            list_iterator.skip_while(|entry| entry.version_compatibility() != outdated_schema);
        if updates_to_process.clone().count() == 0 {
            panic!("Your database schema claims to be newer than the official newest one")
        }
        for u in updates_to_process {
            if let Err(e) = u.migrate(&mut conn) {
                return Err(format!(
                    "Updating database from version {} failed due to: {:?}",
                    u.version_compatibility(),
                    e
                ));
            }
        }
        Ok(())
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
                if Self::compare_set_of_numbers(
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
        Self::str_version_numeric_transcription(first_set)
            .iter()
            .zip(Self::str_version_numeric_transcription(second_set).iter())
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
        if Self::compare_set_of_numbers(
            outdated_schema,
            THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS,
        ) && outdated_schema != THE_EARLIEST_ENTRY_IN_THE_LIST_OF_DB_MIGRATIONS
        {
            panic!("Database version is too low and incompatible with any official version: database corrupted")
        };
        if outdated_schema == CURRENT_SCHEMA_VERSION {
            panic!("Ordered to update the database but already up to date")
        };
        //check for a too high version is placed further
    }
}

#[cfg(test)]
mod tests {
    use crate::database::connection_wrapper::{ConnectionWrapper, ConnectionWrapperReal};
    use crate::database::db_initializer::test_utils::ConnectionWrapperMock;
    use crate::database::db_initializer::CURRENT_SCHEMA_VERSION;
    use crate::database::db_migration::DbMigratorReal;
    use crate::database::db_migration::{MigrateDatabase, Migrate_0_0_10_to_0_0_11};
    use lazy_static::lazy_static;
    use masq_lib::test_utils::utils::BASE_TEST_DIR;
    use rusqlite::{Connection, NO_PARAMS};
    use std::cell::RefCell;
    use std::fs::create_dir_all;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    lazy_static! {
        static ref TEST_DIRECTORY_FOR_DB_MIGRATION: PathBuf =
            PathBuf::from(format!("{}/db_migration", BASE_TEST_DIR));
    }

    #[test]
    #[should_panic(expected = "Database is corrupted: current schema")]
    fn validation_check_panics_if_the_given_schema_has_wrong_syntax() {
        let _ = DbMigratorReal::schema_initial_validation_check("0.xx.5");
    }

    #[test]
    #[should_panic(expected = "Ordered to update the database but already up to date")]
    fn validation_check_panics_if_the_given_schema_is_equal_to_the_latest_one() {
        let _ = DbMigratorReal::schema_initial_validation_check(CURRENT_SCHEMA_VERSION);
    }

    #[test]
    #[should_panic(
        expected = "Database version is too low and incompatible with any official version: database corrupted"
    )]
    fn validation_check_panics_if_the_given_schema_is_lower_than_any_in_the_list() {
        let _ = DbMigratorReal::schema_initial_validation_check("0.0.0");
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
        let subject = DbMigratorReal::default();

        let _ = subject.make_updates(
            too_advanced.as_str(),
            DbMigratorReal::list_of_existing_updates(),
            Box::new(ConnectionWrapperMock::default()),
        );
    }

    #[test]
    fn version_numeric_transcription_works() {
        let result = DbMigratorReal::str_version_numeric_transcription("3.21.6");

        assert_eq!(*result, [3, 21, 6])
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_happy_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.30.33", "1.30.33");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_middle_grade_happy_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.2.33", "0.3.33");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_happy_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.30.33", "0.30.34");

        assert_eq!(result, true)
    }

    #[test]
    fn compare_set_of_numbers_highest_grade_bad_path() {
        let result = DbMigratorReal::compare_set_of_numbers("1.30.33", "0.30.34");

        assert_eq!(result, false)
    }

    #[test]
    fn compare_set_of_numbers_middle_grade_bad_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.8.33", "0.3.37");

        assert_eq!(result, false)
    }

    #[test]
    fn compare_set_of_numbers_lowest_grade_bad_path() {
        let result = DbMigratorReal::compare_set_of_numbers("0.30.33", "0.30.31");

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
        fn migrate<'a>(&self, conn: &mut Box<dyn ConnectionWrapper + 'a>) -> rusqlite::Result<()> {
            conn.execute(&self.sql_statement.take()).map(|_| ())
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
        let subject = DbMigratorReal::default();

        let _ = subject.make_updates("0.0.10", list, Box::new(ConnectionWrapperMock::default()));
    }

    #[test]
    fn initiate_list_of_existing_updates_does_not_end_with_version_higher_than_the_current_version()
    {
        let last_entry = DbMigratorReal::list_of_existing_updates()
            .into_iter()
            .last();

        let result = last_entry.unwrap().version_compatibility();

        assert!(DbMigratorReal::compare_set_of_numbers(
            result,
            CURRENT_SCHEMA_VERSION
        ))
    }

    #[test]
    fn transacting_migration_happy_path() {
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
        let statement = "INSERT INTO test (name, value) VALUES (\"booga\", \"gibberish\")";
        let list = &[&FakeMigrationRecord::default()
            .version_result("0.0.10")
            .sql_statement(statement) as &(dyn MigrateDatabase + 'static)];
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, list, Box::new(connection_wrapper));

        assert!(result.is_ok());
    }

    #[test]
    fn transacting_migration_sad_path() {
        let execution_params_arc = Arc::new(Mutex::new(vec![]));
        let params_arc_clone = execution_params_arc.clone();
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
            .execute_upon_transaction_result(Err(rusqlite::Error::InvalidQuery))
            .execute_upon_transaction_params(params_arc_clone);
        let outdated_schema = "0.0.10";
        let list = &[&Migrate_0_0_10_to_0_0_11 as &(dyn MigrateDatabase + 'static)];
        let subject = DbMigratorReal::default();

        let result = subject.make_updates(outdated_schema, list, Box::new(connection_wrapper));

        assert_eq!(
            result,
            Err("Updating database from version 0.0.10 failed due to: InvalidQuery".to_string())
        );
        assert_eq!(
            *execution_params_arc.lock().unwrap().pop().unwrap(),
            vec![
                "INSERT INTO config (name, value, encrypted) VALUES ('mapping_protocol', null, 0)"
                    .to_string(),
                "UPDATE config SET value = '0.0.11' WHERE name = 'current_schema'".to_string()
            ]
        );
    }

    #[test]
    fn migration_from_0_0_10_to_0_0_11_is_properly_set() {
        let dir_path = TEST_DIRECTORY_FOR_DB_MIGRATION.join("0_0_10_to_0_0_11");
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
        connection.execute("INSERT INTO config (name, value, encrypted) VALUES ('current_schema', '0.0.10', 0)",NO_PARAMS).unwrap();
        let connection_wrapper = ConnectionWrapperReal::new(connection);
        let outdated_schema = "0.0.10";
        let list = &[&Migrate_0_0_10_to_0_0_11 as &(dyn MigrateDatabase + 'static)];
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
                "select name, value, encrypted from config where name = 'current_schema'",
            );
        assert_eq!(mp_name, "mapping_protocol".to_string());
        assert_eq!(mp_value, None);
        assert_eq!(mp_encrypted, 0);
        assert_eq!(cs_name, "current_schema".to_string());
        assert_eq!(cs_value, Some("0.0.11".to_string()));
        assert_eq!(cs_encrypted, 0)
    }

    fn assurance_query_for_config_table(
        conn: &Connection,
        stm: &str,
    ) -> (String, Option<String>, u16) {
        conn.query_row(stm, NO_PARAMS, |r| {
            Ok((r.get(0).unwrap(), r.get(1).unwrap(), r.get(2).unwrap()))
        })
        .unwrap()
    }
}
