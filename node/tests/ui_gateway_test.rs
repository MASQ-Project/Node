// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use masq_lib::messages::{
    UiDescriptorRequest, UiDescriptorResponse, UiFinancialsRequest, UiFinancialsResponse,
    UiShutdownRequest, NODE_UI_PROTOCOL,
};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::utils::find_free_port;
use utils::CommandConfig;

#[test]
fn dispatcher_message_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(Some(
        CommandConfig::new().pair("--ui-port", &port.to_string()),
    ));
    node.wait_for_log("UIGateway bound", Some(5000));
    let descriptor_req = UiDescriptorRequest {};
    let mut descriptor_client = UiConnection::new(port, NODE_UI_PROTOCOL);
    let shutdown_req = UiShutdownRequest {};
    let mut shutdown_client = UiConnection::new(port, NODE_UI_PROTOCOL);

    descriptor_client.send(descriptor_req);
    let _: UiDescriptorResponse = descriptor_client.receive().unwrap();
    shutdown_client.send(shutdown_req);

    node.wait_for_exit();
}

#[test]
fn request_financial_information_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(Some(
        CommandConfig::new().pair("--ui-port", &port.to_string()),
    ));
    node.wait_for_log("UIGateway bound", Some(5000));
    let financials_request = UiFinancialsRequest {
        payable_minimum_amount: 0,
        payable_maximum_age: 1_000_000_000_000,
        receivable_minimum_amount: 0,
        receivable_maximum_age: 1_000_000_000_000,
    };
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);

    client.send(financials_request);
    let financials_response: UiFinancialsResponse = client.receive().unwrap();

    assert_eq!(financials_response.payables.len(), 0);
    assert_eq!(financials_response.receivables.len(), 0);
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}
