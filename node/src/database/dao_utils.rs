// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::unsigned_to_signed;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use crate::database::db_migrations::MigratorConfig;
use masq_lib::utils::{plus, ExpectValue};
use std::cell::RefCell;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => unsigned_to_signed(d.as_secs()).expect("MASQNode has expired"),
    }
}

pub fn now_time_t() -> i64 {
    to_time_t(SystemTime::now())
}

pub fn from_time_t(time_t: i64) -> SystemTime {
    let interval = Duration::from_secs(time_t as u64);
    SystemTime::UNIX_EPOCH + interval
}

pub struct DaoFactoryReal {
    pub data_directory: PathBuf,
    pub create_if_necessary: bool,
    pub migrator_config: RefCell<Option<MigratorConfig>>,
}

impl DaoFactoryReal {
    pub fn new(
        data_directory: &Path,
        create_if_necessary: bool,
        migrator_config: MigratorConfig,
    ) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            create_if_necessary,
            migrator_config: RefCell::new(Some(migrator_config)),
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal::default(),
            &self.data_directory,
            self.create_if_necessary,
            self.migrator_config.take().expectv("MigratorConfig"),
        )
    }
}

pub fn changed_rows_or_query_error<T: Debug>(
    results: Result<impl Iterator<Item = Result<T, rusqlite::Error>>, rusqlite::Error>,
    rows_changed_counter: fn(Vec<T>) -> usize,
) -> Result<usize, rusqlite::Error> {
    let (oks, mut errs): (Vec<_>, Vec<_>) =
        results
            .expect("query failed on binding")
            .fold((vec![], vec![]), |acc, current| {
                if let Ok(val) = current {
                    (plus(acc.0, val), acc.1)
                } else {
                    (acc.0, plus(acc.1, current.expect_err("we saw it was err")))
                }
            });
    if errs.is_empty() {
        if !oks.is_empty() {
            Ok(rows_changed_counter(oks))
        } else {
            Ok(0)
        }
    } else if errs.len() == 1 {
        Err(errs.remove(0))
    } else {
        panic!(
            "broken code: we expect to get maximally a single error but got: {:?}",
            errs
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::fut::ok;
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            false,
            MigratorConfig::test_default(),
        );

        let _ = subject.make_connection();
    }

    #[test]
    fn changed_rows_or_query_error_returns_the_number() {
        let random_collection_of_changed_data = vec![Ok(5_i64), Ok(111), Ok(4321)];
        let iterator = random_collection_of_changed_data.into_iter();

        let result = changed_rows_or_query_error(iterator, |ok_vec| ok_vec.len());

        assert_eq!(result, Ok(3))
    }

    #[test]
    fn changed_rows_or_query_error_suspects_0_if_nothing_changed() {
        let random_collection_of_changed_data: Vec<Result<i64, _>> = vec![];
        let iterator = random_collection_of_changed_data.into_iter();

        let result = changed_rows_or_query_error(iterator, |ok_vec| ok_vec.len());

        assert_eq!(result, Ok(0))
    }

    #[test]
    fn changed_rows_or_query_error_returns_the_error() {
        //it's important to note that the real situation can only be a single error, not more errors
        let random_collection_of_changed_data: Vec<Result<i64, _>> =
            vec![Err(rusqlite::Error::QueryReturnedNoRows)];
        let iterator = random_collection_of_changed_data.into_iter();

        let result = changed_rows_or_query_error(iterator, |ok_vec| ok_vec.len());

        assert_eq!(result, Err(rusqlite::Error::QueryReturnedNoRows))
    }

    #[test]
    #[should_panic(
        expected = "broken code: we expect to get maximally a single error but got: [Err(QueryReturnedNoRows), Err(InvalidQuery)]"
    )]
    fn more_than_one_error_is_considered_a_malformation() {
        //it's important to note that the real situation can only be a single error, not more errors
        let random_collection_of_changed_data: Vec<Result<i64, _>> = vec![
            Err(rusqlite::Error::QueryReturnedNoRows),
            Err(rusqlite::Error::InvalidQuery),
        ];
        let iterator = random_collection_of_changed_data.into_iter();

        let _ = changed_rows_or_query_error(iterator, |ok_vec| ok_vec.len());
    }
}
