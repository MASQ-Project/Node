// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod utils;

use sub_lib::ui_gateway::DEFAULT_UI_PORT;
use websocket::ClientBuilder;
use websocket::OwnedMessage;

#[test]
fn ui_gateway_shutdown_integration() {
    let mut node = utils::SubstratumNode::start(None);

    let mut ui_client = ClientBuilder::new(format!("ws://127.0.0.1:{}", DEFAULT_UI_PORT).as_str())
        .unwrap()
        .add_protocol("SubstratumNode-UI")
        .connect_insecure()
        .unwrap();

    ui_client
        .send_message(&OwnedMessage::Text(String::from(
            "{ \
             \"message_type\": \"shutdown\" \
             }",
        )))
        .unwrap();

    node.wait_for_exit(1000);
}
