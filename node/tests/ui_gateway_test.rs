// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use masq_lib::messages::SerializableLogLevel::Warn;
use masq_lib::messages::{
    UiChangePasswordRequest, UiDescriptorRequest, UiDescriptorResponse, UiFinancialsRequest,
    UiFinancialsResponse, UiLogBroadcast, UiShutdownRequest, UiWalletAddressesRequest,
    NODE_UI_PROTOCOL,
};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::utils::find_free_port;
use utils::CommandConfig;

#[test]
fn dispatcher_message_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "dispatcher_message_integration",
        Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let descriptor_req = UiDescriptorRequest {};
    let mut descriptor_client = UiConnection::new(port, NODE_UI_PROTOCOL);
    let shutdown_req = UiShutdownRequest {};
    let mut shutdown_client = UiConnection::new(port, NODE_UI_PROTOCOL);

    descriptor_client.send(descriptor_req);
    let _: UiDescriptorResponse = descriptor_client.skip_until_received().unwrap();
    shutdown_client.send(shutdown_req);

    node.wait_for_exit();
}

#[test]
fn request_financial_information_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "request_financial_information_integration",
        Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let financials_request = UiFinancialsRequest {
        payable_minimum_amount: 0,
        payable_maximum_age: 1_000_000_000_000,
        receivable_minimum_amount: 0,
        receivable_maximum_age: 1_000_000_000_000,
    };
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);

    client.send(financials_request);
    let financials_response: UiFinancialsResponse = client.skip_until_received().unwrap();

    assert_eq!(financials_response.payables.len(), 0);
    assert_eq!(financials_response.receivables.len(), 0);
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}

#[test]
fn log_broadcasts_are_correctly_received_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "log_broadcasts_are_correctly_received",
        Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
    client.send(UiWalletAddressesRequest {
        db_password: "blah".to_string(),
    });
    client.send(UiChangePasswordRequest {
        old_password_opt: Some("blah".to_string()),
        new_password: "blah".to_string(),
    });

    let broadcasts: Vec<UiLogBroadcast> = (0..2)
        .map(|_| client.skip_until_received().unwrap())
        .collect();

    assert_eq!(broadcasts,
               vec![
                   UiLogBroadcast { msg: "Failed to obtain wallet addresses: 281474976710669, Wallet pair not yet configured".to_string(), log_level: Warn },
                   UiLogBroadcast { msg: "Failed to change password: PasswordError".to_string(), log_level: Warn }
               ]
    );
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}

#[test]
fn dead_clients_are_dumped_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "dead_clients_are_dumped",
        Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
        true,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let client_1 = UiConnection::new(port, NODE_UI_PROTOCOL);
    let client_1_addr = client_1.local_addr();
    let mut client_2 = UiConnection::new(port, NODE_UI_PROTOCOL);

    drop(client_1);

    let broadcasts: Vec<UiLogBroadcast> = (0..2)
        .map(|_| client_2.skip_until_received().unwrap())
        .collect();
    let expected_message_snippet = format!("UI at {} violated protocol", client_1_addr);
    assert!(
        broadcasts[0].msg.contains(&expected_message_snippet),
        "{} not present in: {:?}",
        expected_message_snippet,
        broadcasts[0].msg
    );
    let expected_message_snippet = "Client 0: BrokenPipe, dropping its reference".to_string();
    assert!(
        broadcasts[1].msg.contains(&expected_message_snippet),
        "{} not present in: {:?}",
        expected_message_snippet,
        broadcasts[1].msg
    );
    client_2.send(UiShutdownRequest {});
    node.wait_for_exit();
}
