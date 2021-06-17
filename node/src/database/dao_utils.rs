// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::jackass_unsigned_to_signed;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::db_initializer::{connection_or_panic, DbInitializerReal};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

pub fn to_time_t(system_time: SystemTime) -> i64 {
    match system_time.duration_since(SystemTime::UNIX_EPOCH) {
        Err(e) => unimplemented!("{}", e),
        Ok(d) => jackass_unsigned_to_signed(d.as_secs()).expect("MASQNode has expired"),
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
    pub chain_id: u8,
    pub create_if_necessary: bool,
}

impl DaoFactoryReal {
    pub fn new(data_directory: &Path, chain_id: u8, create_if_necessary: bool) -> Self {
        Self {
            data_directory: data_directory.to_path_buf(),
            chain_id,
            create_if_necessary,
        }
    }

    pub fn make_connection(&self) -> Box<dyn ConnectionWrapper> {
        connection_or_panic(
            &DbInitializerReal {},
            &self.data_directory,
            self.chain_id,
            self.create_if_necessary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::test_utils::utils::DEFAULT_CHAIN_ID;
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Failed to connect to database at \"nonexistent")]
    fn connection_panics_if_connection_cannot_be_made() {
        let subject = DaoFactoryReal::new(
            &PathBuf::from_str("nonexistent").unwrap(),
            DEFAULT_CHAIN_ID,
            false,
        );

        let _ = subject.make_connection();
    }
}
