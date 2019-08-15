// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod utils;

use futures::future::*;
use node_lib::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use std::time::Duration;
use tokio::prelude::*;
use tokio::runtime::Runtime;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

#[test]
fn ui_gateway_message_integration() {
    fdlimit::raise_fd_limit();
    let mut node = utils::SubstratumNode::start_standard(None);

    let descriptor_client =
        ClientBuilder::new(format!("ws://127.0.0.1:{}", DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("SubstratumNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| {
                s.send(OwnedMessage::Text(String::from(
                    "{ \
                     \"GetNodeDescriptor\": null \
                     }",
                )))
            })
            .and_then(|s| s.into_future().map_err(|e| e.0))
            .map(|(m, _)| match m {
                Some(OwnedMessage::Text(s)) => assert!(!s.is_empty()),
                _ => panic!("Expected a text response"),
            })
            .timeout(Duration::from_millis(1000))
            .map_err(|e| panic!("failed to get response by timeout {:}", e));

    let shutdown_client =
        ClientBuilder::new(format!("ws://127.0.0.1:{}", DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("SubstratumNode-UI")
            .async_connect_insecure()
            .and_then(|(s, _)| {
                s.send(OwnedMessage::Text(String::from(
                    "{ \
                     \"ShutdownMessage\": null \
                     }",
                )))
            });

    let mut rt = Runtime::new().unwrap();
    rt.block_on(descriptor_client).unwrap();
    rt.block_on(shutdown_client).unwrap();
    rt.shutdown_on_idle().wait().unwrap();

    node.wait_for_exit();
}
