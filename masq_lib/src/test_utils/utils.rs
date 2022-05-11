// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use chrono::{DateTime, Local};
use log::Record;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs, io, thread};

pub const TEST_DEFAULT_CHAIN: Chain = Chain::EthRopsten;
pub const TEST_DEFAULT_MULTINODE_CHAIN: Chain = Chain::Dev;
pub const BASE_TEST_DIR: &str = "generated/test";

pub fn node_home_directory(module: &str, name: &str) -> PathBuf {
    let home_dir_string = format!("{}/{}/{}/home", BASE_TEST_DIR, module, name);
    PathBuf::from(home_dir_string.as_str())
}

pub fn ensure_node_home_directory_does_not_exist(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    home_dir
}

pub fn ensure_node_home_directory_exists(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    let _ = fs::create_dir_all(&home_dir);
    home_dir
}

pub fn is_running_under_github_actions() -> bool {
    if let Ok(value) = std::env::var("GITHUB_ACTIONS") {
        &value == "true"
    } else {
        false
    }
}

pub fn real_format_function(
    write: &mut dyn io::Write,
    timestamp: &DateTime<Local>,
    record: &Record,
) -> Result<(), io::Error> {
    let timestamp = timestamp.naive_local().format("%Y-%m-%dT%H:%M:%S%.3f");
    let thread_id_str = format!("{:?}", thread::current().id());
    let thread_id = &thread_id_str[9..(thread_id_str.len() - 1)];
    let level = record.level();
    let name = record.module_path().unwrap_or("<unnamed>");
    write.write_fmt(format_args!(
        "{} Thd{}: {}: {}: ",
        timestamp, thread_id, level, name
    ))?;
    write.write_fmt(*record.args())
}

pub fn to_millis(dur: &Duration) -> u64 {
    (dur.as_secs() * 1000) + (u64::from(dur.subsec_nanos()) / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(TEST_DEFAULT_CHAIN, Chain::EthRopsten);
        assert_eq!(TEST_DEFAULT_MULTINODE_CHAIN, Chain::Dev);
        assert_eq!(BASE_TEST_DIR, "generated/test");
    }
}
