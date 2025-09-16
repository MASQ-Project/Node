// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use masq_lib::constants::{CURRENT_SCHEMA_VERSION, DEFAULT_CHAIN};
use masq_lib::messages::{UiShutdownRequest, NODE_UI_PROTOCOL};
use masq_lib::test_utils::environment_guard::EnvironmentGuard;
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::utils::find_free_port;
use node_lib::test_utils::assert_string_contains;

#[test]
fn dump_configuration_with_an_existing_database_integration() {
    let _eg = EnvironmentGuard::new();
    let test_name = "dump_configuration_with_an_existing_database_integration";
    {
        //running Node in order to create a new database which cannot be made by --dump-config itself
        let port = find_free_port();
        let mut node = utils::MASQNode::start_standard(
            test_name,
            Some(
                CommandConfig::new()
                    .pair("--blockchain-service-url", "https://booga.com")
                    .pair("--ui-port", &port.to_string())
                    .pair("--chain", "polygon-amoy"),
            ),
            true,
            true,
            false,
            true,
        );
        node.wait_for_log("UIGateway bound", Some(5000));
        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
        let shutdown_request = UiShutdownRequest {};
        client.send(shutdown_request);
        node.wait_for_exit();
    }

    let mut node = utils::MASQNode::run_dump_config(
        test_name,
        Some(CommandConfig::new().pair("--chain", "polygon-amoy")),
        false,
        true,
        true,
        false,
    );

    match node.wait_for_exit() {
        None => panic!("the process terminated unexpectedly"),
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_string_contains(
                stdout.as_ref(),
                &format!("\"schemaVersion\": \"{}\"", CURRENT_SCHEMA_VERSION),
            );
        }
    };
}

#[test]
fn dump_configuration_and_no_preexisting_database_integration() {
    let _eg = EnvironmentGuard::new();

    let mut node = utils::MASQNode::run_dump_config(
        "dump_configuration_and_no_preexisting_database_integration",
        Some(CommandConfig::new().pair("--chain", DEFAULT_CHAIN.rec().literal_identifier)),
        true,
        true,
        true,
        false,
    );

    match node.wait_for_exit() {
        None => panic!("the process terminated unexpectedly"),
        Some(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_string_contains(stderr.as_ref(), "Could not find database at:");
            assert_string_contains(stderr.as_ref(),
                                   "It is created when the Node operates the first time. Running --dump-config before that has no effect"
            )
        }
    };
}
