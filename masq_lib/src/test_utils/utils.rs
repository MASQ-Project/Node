// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

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

pub fn to_millis(dur: &Duration) -> u64 {
    (dur.as_secs() * 1000) + (u64::from(dur.subsec_nanos()) / 1_000_000)
}

#[cfg(not(feature = "no_test_share"))]
pub struct MutexIncrementInset(pub usize);

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
