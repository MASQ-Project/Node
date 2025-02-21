// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use masq_lib::messages::{ToMessageBody, UiCrashRequest};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::{find_free_port, localhost};
use node_lib::daemon::launch_verifier::ClientWrapperReal;
use tungstenite::Message;
use websocket::{ClientBuilder, OwnedMessage};

//we test only those actors who are subscribers of UiGateway who are:
//accountant,
//neighborhood,
//blockchain_bridge,
//dispatcher,
//configurator,
//don't add more tests unless you know what you're doing

#[test]
fn node_exits_from_blockchain_bridge_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_blockchain_bridge_panic_integration",
        node_lib::blockchain::blockchain_bridge::CRASH_KEY,
    );
}

#[test]
fn node_exits_from_dispatcher_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_dispatcher_panic_integration",
        node_lib::dispatcher::CRASH_KEY,
    );
}

#[test]
fn node_exits_from_accountant_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_accountant_panic_integration",
        node_lib::accountant::CRASH_KEY,
    );
}

#[test]
fn node_exits_from_neighborhood_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_neighborhood_panic_integration",
        node_lib::neighborhood::CRASH_KEY,
    );
}

#[test]
fn node_exits_from_configurator_panic_integration() {
    start_node_and_request_crash(
        "node_exits_configurator_panic_integration",
        node_lib::node_configurator::configurator::CRASH_KEY,
    );
}

#[test]
fn node_exits_from_uigateway_panic_integration() {
    start_node_and_request_crash(
        "node_exits_from_uigateway_panic_integration",
        node_lib::ui_gateway::CRASH_KEY,
    );
}

fn start_node_and_request_crash(dir_name: &str, crash_key: &str) {
    let port = find_free_port();
    let panic_config = CommandConfig::new()
        .pair("--crash-point", "message")
        .pair("--neighborhood-mode", "zero-hop")
        .pair("--ui-port", format!("{}", port).as_str());
    let mut node =
        utils::MASQNode::start_standard(dir_name, Some(panic_config), true, true, false, true);
    let msg = UiTrafficConverter::new_marshal(
        UiCrashRequest {
            actor: crash_key.to_string(),
            panic_message: "Test panic".to_string(),
        }
        .tmb(0),
    );
    let mut client = ClientWrapperReal::new(format!("ws://{}:{}", localhost(), port).as_str());
    let mut client = ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str())
        .expect("Couldn't create ClientBuilder")
        .add_protocol("MASQNode-UIv2")
        .connect_insecure()
        .unwrap();
    client.send_message(&Message::Text(msg)).unwrap();

    let success = node.wait_for_exit().unwrap().status.success();
    assert!(!success, "Did not fail as expected");
}
