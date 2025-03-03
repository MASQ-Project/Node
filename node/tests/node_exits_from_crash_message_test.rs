// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use masq_lib::messages::{ToMessageBody, UiCrashRequest, NODE_UI_PROTOCOL};
use masq_lib::utils::{find_free_port};
use masq_lib::test_utils::ui_connection::UiConnection;

//we test only those actors who are subscribers of UiGateway who are:
//accountant,
//neighborhood,
//blockchain_bridge,
//dispatcher,
//configurator,
//don't add more tests unless you know what you're doing

#[tokio::test]
async fn node_exits_from_blockchain_bridge_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_blockchain_bridge_panic_integration",
        node_lib::blockchain::blockchain_bridge::CRASH_KEY,
    ).await;
}

#[tokio::test]
async fn node_exits_from_dispatcher_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_dispatcher_panic_integration",
        node_lib::dispatcher::CRASH_KEY,
    ).await;
}

#[tokio::test]
async fn node_exits_from_accountant_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_accountant_panic_integration",
        node_lib::accountant::CRASH_KEY,
    ).await;
}

#[tokio::test]
async fn node_exits_from_neighborhood_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_neighborhood_panic_integration",
        node_lib::neighborhood::CRASH_KEY,
    ).await;
}

#[tokio::test]
async fn node_exits_from_configurator_panic_integration() {
    start_node_and_request_crash(
        "node_exits_configurator_panic_integration",
        node_lib::node_configurator::configurator::CRASH_KEY,
    ).await;
}

#[tokio::test]
async fn node_exits_from_uigateway_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_uigateway_panic_integration",
        node_lib::ui_gateway::CRASH_KEY,
    ).await;
}

async fn start_node_and_request_crash(dir_name: &str, crash_key: &str) {
    let port = find_free_port();
    let panic_config = CommandConfig::new()
        .pair("--crash-point", "message")
        .pair("--neighborhood-mode", "zero-hop")
        .pair("--ui-port", format!("{}", port).as_str());
    let mut node =
        utils::MASQNode::start_standard(dir_name, Some(panic_config), true, true, false, true);
    let crash_request = UiCrashRequest {
        actor: crash_key.to_string(),
        panic_message: "Test panic".to_string(),
    };
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL).await.unwrap();

    client.send(crash_request).await;

    let success = node.wait_for_exit().unwrap().status.success();
    assert!(!success, "Did not fail as expected");
}
