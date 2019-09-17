// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use futures::future::*;
use node_lib::sub_lib::ui_gateway::{UiMessage, DEFAULT_UI_PORT};
use node_lib::sub_lib::utils::localhost;
use node_lib::test_utils::assert_matches;
use node_lib::ui_gateway::ui_traffic_converter::{UiTrafficConverter, UiTrafficConverterReal};
use std::time::Duration;
use tokio::prelude::*;
use tokio::runtime::Runtime;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

#[test]
fn ui_gateway_message_integration() {
    fdlimit::raise_fd_limit();
    let mut node = utils::SubstratumNode::start_standard(None);
    node.wait_for_log("UIGateway bound", Some(5000));
    let converter = UiTrafficConverterReal::new();
    let msg = converter
        .marshal(UiMessage::GetNodeDescriptor)
        .expect("Couldn't marshal GetNodeDescriptor message");

    let descriptor_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .expect("Couldn't create first ClientBuilder")
            .add_protocol("SubstratumNode-UI")
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
            .add_protocol("SubstratumNode-UI")
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
    let mut node = utils::SubstratumNode::start_standard(None);
    node.wait_for_log("UIGateway bound", Some(5000));

    let converter = UiTrafficConverterReal::new();
    let msg = converter
        .marshal(UiMessage::NeighborhoodDotGraphRequest)
        .unwrap();

    let digraph_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("SubstratumNode-UI")
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

    let shutdown_msg = converter.marshal(UiMessage::ShutdownMessage).unwrap();

    let shutdown_client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("SubstratumNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| s.send(OwnedMessage::Text(shutdown_msg)));

    let mut rt = Runtime::new().unwrap();
    rt.block_on(digraph_client).unwrap();
    rt.block_on(shutdown_client).unwrap();
    rt.shutdown_on_idle().wait().unwrap();

    node.wait_for_exit();
}
