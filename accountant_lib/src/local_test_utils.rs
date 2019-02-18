// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::fs;
use std::path::PathBuf;

pub const BASE_TEST_DIR: &str = "generated/test";

pub fn ensure_node_home_directory_exists(name: &str) -> PathBuf {
    let home_dir_string = format!("{}/{}/home", BASE_TEST_DIR, name);
    let home_dir = PathBuf::from(home_dir_string.as_str());
    fs::remove_dir_all(&home_dir).is_ok();
    fs::create_dir_all(&home_dir).is_ok();
    home_dir
}
