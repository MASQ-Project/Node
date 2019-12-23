// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use node_lib::database::db_initializer::DATABASE_FILE;
use node_lib::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use node_lib::ui_gateway::messages::{UiSetup, UiShutdownOrder, UiStartOrder, UiStartResponse};
use std::ops::Add;
use std::time::{Duration, SystemTime};
use sysinfo::{System, SystemExt};
use utils::CommandConfig;
use utils::MASQNode;
use utils::UiConnection;

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
    let mut node = MASQNode::start_daemon(None);
    let mut initialization_client = UiConnection::new(DEFAULT_UI_PORT, "MASQNode-UIv2");
    let _: UiSetup = initialization_client
        .transact(UiSetup::new(vec![
            ("dns-servers", "1.1.1.1"),
            ("neighborhood-mode", "zero-hop"),
        ]))
        .unwrap();

    let response: UiStartResponse = initialization_client.transact(UiStartOrder {}).unwrap();

    let mut service_client = UiConnection::new(response.redirect_ui_port, "MASQNode-UIv2");
    service_client.send(UiShutdownOrder {});
    wait_for_process_end(response.new_process_id);
    initialization_client.send(UiShutdownOrder {});
    node.wait_for_exit().unwrap();
}

fn wait_for_process_end(process_id: i32) {
    let mut system = System::new();
    let deadline = SystemTime::now().add(Duration::from_millis(2000));
    loop {
        if SystemTime::now().gt(&deadline) {
            panic!(
                "Process {} not dead after receiving shutdownOrder",
                process_id
            )
        }
        system.refresh_all();
        #[cfg (target_os = "windows")]
        let process_id = process_id as usize;
        if system.get_process(process_id).is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500))
    }
}
