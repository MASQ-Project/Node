// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_big_integer::big_int_db_processor::KnownKeyVariants::TestKey;
use crate::accountant::db_big_integer::big_int_db_processor::{DisplayableToSql, KnownKeyVariants};
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use rusqlite::Connection;

pub fn create_new_empty_db(module: &str, test_name: &str) -> Connection {
    let home_dir = ensure_node_home_directory_exists(module, test_name);
    let db_path = home_dir.join("test_table.db");
    Connection::open(db_path.as_path()).unwrap()
}

pub fn test_database_key<'a>(val: &'a dyn DisplayableToSql) -> KnownKeyVariants<'a> {
    TestKey {
        var_name: "name",
        sub_name: ":name",
        val,
    }
}
