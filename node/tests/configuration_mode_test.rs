// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use masq_lib::test_utils::environment_guard::EnvironmentGuard;
use node_lib::database::db_initializer::CURRENT_SCHEMA_VERSION;
use node_lib::test_utils::assert_string_contains;
use utils::MASQNode;

#[test]
fn dump_configuration_integration() {
    let _eg = EnvironmentGuard::new();
    let console_log = MASQNode::run_dump_config("dump_configuration_integration");

    assert_string_contains(
        &console_log,
        &format!("\"schemaVersion\": \"{}\"", CURRENT_SCHEMA_VERSION),
    );
}
