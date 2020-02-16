// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use futures::future::*;
use masq_lib::messages::{UiFinancialsRequest, UiFinancialsResponse, NODE_UI_PROTOCOL};
use masq_lib::ui_gateway::MessagePath::TwoWay;
use masq_lib::ui_gateway::{
    MessageBody, MessageTarget, NodeFromUiMessage, NodeToUiMessage, DEFAULT_UI_PORT,
};
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::localhost;
use node_lib::sub_lib::ui_gateway::UiMessage;
use node_lib::test_utils::assert_matches;
use node_lib::ui_gateway::ui_traffic_converter::{
    UiTrafficConverterOld, UiTrafficConverterOldReal,
};
use std::time::Duration;
use tokio::prelude::*;
use tokio::runtime::Runtime;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

#[test]
fn ui_gateway_message_integration() {
    fdlimit::raise_fd_limit();
    let mut node = utils::MASQNode::start_standard(None);
    node.wait_for_log("UIGateway bound", Some(5000));
    let converter = UiTrafficConverterOldReal::new();
    let msg = converter
        .marshal(UiMessage::GetNodeDescriptor)
        .expect("Couldn't marshal GetNodeDescriptor message");

    let descriptor_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .expect("Couldn't create first ClientBuilder")
            .add_protocol("MASQNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(msg)))
            .and_then(|s| s.into_future().map_err(|e| e.0))
            .map(|(m, _)| match m {
                Some(OwnedMessage::Text(s)) => assert!(!s.is_empty()),
                _ => panic!("Expected a text response"),
            })
            .timeout(Duration::from_millis(1000))
            .map_err(|e| panic!("failed to get response by timeout {:?}", e));

    let shutdown_msg = converter
        .marshal(UiMessage::ShutdownMessage)
        .expect("Couldn't marshal ShutdownMessage");

    let shutdown_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .expect("Couldn't create second ClientBuilder")
            .add_protocol("MASQNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(shutdown_msg)));

    let mut rt = Runtime::new().expect("Couldn't create Runtime");
    rt.block_on(descriptor_client)
        .expect("Couldn't block on descriptor_client");
    rt.block_on(shutdown_client)
        .expect("Couldn't block on shutdown_client");
    rt.shutdown_on_idle()
        .wait()
        .expect("Couldn't wait on shutdown_on_idle");

    node.wait_for_exit();
}

#[test]
fn ui_gateway_dot_graph_message_integration() {
    fdlimit::raise_fd_limit();
    let mut node = utils::MASQNode::start_standard(None);
    node.wait_for_log("UIGateway bound", Some(5000));

    let converter = UiTrafficConverterOldReal::new();
    let msg = converter
        .marshal(UiMessage::NeighborhoodDotGraphRequest)
        .unwrap();

    let descriptor_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("MASQNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(msg)))
            .and_then(|s| s.into_future().map_err(|e| e.0))
            .map(|(m, _)| match m {
                Some(OwnedMessage::Text(s)) => {
                    assert!(!s.is_empty());
                    assert_matches(s.as_str(), r"digraph db \{ .+ \}");
                }
                _ => panic!("Expected a text response"),
            })
            .timeout(Duration::from_millis(2000))
            .map_err(|e| panic!("failed to get response by timeout {:?}", e));

    let shutdown_msg = converter
        .marshal(UiMessage::ShutdownMessage)
        .expect("Couldn't marshal ShutdownMessage");

    let shutdown_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .expect("Couldn't create second ClientBuilder")
            .add_protocol("MASQNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(shutdown_msg)));

    let mut rt = Runtime::new().expect("Couldn't create Runtime");
    rt.block_on(descriptor_client)
        .expect("Couldn't block on descriptor_client");
    rt.block_on(shutdown_client)
        .expect("Couldn't block on shutdown_client");
    rt.shutdown_on_idle()
        .wait()
        .expect("Couldn't wait on shutdown_on_idle");

    node.wait_for_exit();
}

#[test]
fn request_financial_information_integration() {
    fdlimit::raise_fd_limit();
    let mut node = utils::MASQNode::start_standard(None);
    node.wait_for_log("UIGateway bound", Some(5000));

    let payload = UiFinancialsRequest {
        payable_minimum_amount: 0,
        payable_maximum_age: 1_000_000_000_000,
        receivable_minimum_amount: 0,
        receivable_maximum_age: 1_000_000_000_000,
    };
    let request_msg = UiTrafficConverter::new_marshal_from_ui(NodeFromUiMessage {
        client_id: 1234,
        body: MessageBody {
            opcode: "financials".to_string(),
            path: TwoWay(2222),
            payload: Ok(serde_json::to_string(&payload).unwrap()),
        },
    });

    let descriptor_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol(NODE_UI_PROTOCOL)
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(request_msg)))
            .and_then(|s| s.into_future().map_err(|e| e.0))
            .map(|(m, _)| match m {
                Some(OwnedMessage::Text(response_json)) => {
                    let response_msg: NodeToUiMessage = UiTrafficConverter::new_unmarshal_to_ui(
                        &response_json,
                        MessageTarget::ClientId(1234),
                    )
                    .unwrap();
                    assert_eq!(response_msg.target, MessageTarget::ClientId(1234));
                    assert_eq!(response_msg.body.opcode, "financials".to_string());
                    assert_eq!(response_msg.body.path, TwoWay(2222));
                    let payload = serde_json::from_str::<UiFinancialsResponse>(
                        &response_msg.body.payload.as_ref().unwrap(),
                    )
                    .unwrap();
                    assert_eq!(payload.payables.len(), 0);
                    assert_eq!(payload.receivables.len(), 0);
                }
                other => panic!("Expected text, received {:?}", other),
            })
            .timeout(Duration::from_millis(2000))
            .map_err(|e| panic!("failed to get response by timeout {:?}", e));

    let shutdown_msg = UiTrafficConverterOldReal::new()
        .marshal(UiMessage::ShutdownMessage)
        .expect("Couldn't marshal ShutdownMessage");

    let shutdown_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .expect("Couldn't create second ClientBuilder")
            .add_protocol("MASQNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(shutdown_msg)));

    let mut rt = Runtime::new().expect("Couldn't create Runtime");
    rt.block_on(descriptor_client)
        .expect("Couldn't block on descriptor_client");
    rt.block_on(shutdown_client)
        .expect("Couldn't block on shutdown_client");
    rt.shutdown_on_idle()
        .wait()
        .expect("Couldn't wait on shutdown_on_idle");

    node.wait_for_exit();
}
