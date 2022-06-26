// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::accountant::{checked_conversion, sign_conversion};
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use crate::database::db_migrations::MigratorConfig;
use masq_lib::utils::ExpectValue;
use rusqlite::{params_from_iter, Row, ToSql};
use std::cell::RefCell;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => sign_conversion::<u64, i64>(d.as_secs()).expect("MASQNode has expired"),
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

pub enum CustomQuery<N> {
    TopRecords(usize),
    RangeQuery {
        min_age: usize,
        max_age: usize,
        min_amount: N,
        max_amount: N,
    },
}

impl<N: Copy + Display> CustomQuery<N> {
    pub fn query<R, S, F1, F2>(
        self,
        conn: &dyn ConnectionWrapper,
        main_stm_assembler: F1,
        variant_range: &str,
        variant_top: &str,
        value_fetcher: F2,
    ) -> Option<Vec<R>>
    where
        F1: Fn(&str, &str) -> String,
        F2: Fn(&Row) -> rusqlite::Result<R>,
        S: TryFrom<N> + ToSql,
    {
        let (finalized_stm, params) = match self {
            Self::TopRecords(count) => (
                main_stm_assembler("", variant_top),
                vec![Box::new(count as i64) as Box<dyn ToSql>],
            ),
            Self::RangeQuery {
                min_age,
                max_age,
                min_amount,
                max_amount,
            } => {
                let now = to_time_t(SystemTime::now());
                let params: Vec<Box<dyn ToSql>> = vec![
                    Box::new(now - min_age as i64),
                    Box::new(now - max_age as i64),
                    Box::new(checked_conversion::<N, S>(min_amount)),
                    Box::new(checked_conversion::<N, S>(max_amount)),
                ];
                (main_stm_assembler(variant_range, ""), params)
            }
        };
        match conn
            .prepare(&finalized_stm)
            .expect("select statement is wrong")
            .query_map(
                params_from_iter(params.iter().map(|param| param.as_ref())),
                value_fetcher,
            ) {
            Ok(accounts) => Some(accounts.flatten().collect::<Vec<R>>()), //TODO flatten???
            Err(e) => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
