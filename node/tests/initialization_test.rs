// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use node_lib::database::db_initializer::DATABASE_FILE;
use utils::CommandConfig;
use utils::MASQNode;
use std::thread::Thread;
use std::time::Duration;
use websocket::{ClientBuilder, OwnedMessage};
use node_lib::sub_lib::utils::localhost;
use node_lib::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use serde_json::Value;

#[test]
fn clap_help_does_not_initialize_database_integration() {
    match std::fs::remove_file(DATABASE_FILE) {
        Ok(_) => (),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(ref e) => panic!("{:?}", e),
    }

    let mut node = MASQNode::start_standard(Some(
        CommandConfig::new().opt("--help"), // We don't specify --data-directory because the --help logic doesn't evaluate it
    ));

    node.wait_for_exit().unwrap();
    let failure = std::fs::File::open(DATABASE_FILE);
    assert_eq!(failure.err().unwrap().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn initialization_sequence_integration() {
    let mut node = MASQNode::start_standard(Some(
        CommandConfig::new().opt("--initialization")
    ));
    let mut client =
        ClientBuilder::new(format!("ws://{}:{}", localhost(), DEFAULT_UI_PORT).as_str())
            .unwrap()
            .add_protocol("MASQNode-UIv2")
            .connect_insecure().unwrap();
    client.send_message(&OwnedMessage::Text(r#"
        {
            "opcode": "setup",
            "contextId": 1234,
            "payload": {
                parameters: [
                    {"name": "dns-servers", "value": "1.1.1.1"},
                    {"name": "neighborhood-mode", "value": "zero-hop"}
                ]
            }
        }
    "#.to_string())).unwrap();
    let json = match client.recv_message() {
        Ok(OwnedMessage::Text(json)) => json,
        x => panic! ("Expected text; received {:?}", x),
    };
    let msg_map = match serde_json::from_str(&json) {
        Ok(Value::Object(map)) => map,
        x => panic!("Expected object; received {:?}", x),
    };
    let payload_map = match msg_map.get("payload") {
        Value::Object(map) => map,
        x => panic!("Expected object; received {:?}", x),
    };
    payload_map.
}