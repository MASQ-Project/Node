// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use masq_lib::messages::{UiShutdownRequest, NODE_UI_PROTOCOL};
use masq_lib::test_utils::environment_guard::EnvironmentGuard;
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::utils::find_free_port;
use node_lib::test_utils::assert_string_contains;

#[test]
fn dump_configuration_integration() {
    let _eg = EnvironmentGuard::new();
    let test_name = "dump_configuration_integration";
    {
        //running Node in order to create a new database which cannot be made by --dump-config itself
        let port = find_free_port();
        let mut node = utils::MASQNode::start_standard(
            test_name,
            Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
            true,
            true,
            true,
        );
        node.wait_for_log("UIGateway bound", Some(5000));
        let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
        let shutdown_request = UiShutdownRequest {};
        client.send(shutdown_request);
        node.wait_for_exit();
    }

    let console_log = MASQNode::run_dump_config(test_name,Some(CommandConfig::new().pair("--chain","ropsten")),false,true,false);

    // assert_string_contains(
    //     &console_log,
    //     &format!("\"schemaVersion\": \"{}\"", CURRENT_SCHEMA_VERSION),
    // );
}
