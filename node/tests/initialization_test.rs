// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use node_lib::daemon::launch_verifier::{VerifierTools, VerifierToolsReal};
use node_lib::database::db_initializer::DATABASE_FILE;
use node_lib::test_utils::find_free_port;
use node_lib::ui_gateway::messages::ToMessageBody;
use node_lib::ui_gateway::messages::{
    UiFinancialsRequest, UiRedirect, UiSetup, UiShutdownOrder, UiStartOrder, UiStartResponse,
    NODE_NOT_RUNNING_ERROR,
};
use std::ops::Add;
use std::time::{Duration, SystemTime};
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
    let daemon_port = find_free_port();
    let mut daemon = MASQNode::start_daemon(Some(
        CommandConfig::new().pair("--ui-port", format!("{}", daemon_port).as_str()),
    ));
    let mut initialization_client = UiConnection::new(daemon_port, "MASQNode-UIv2");
    let data_directory = std::env::current_dir()
        .unwrap()
        .join("generated")
        .join("test")
        .join("initialization_sequence_integration")
        .to_string_lossy()
        .to_string();
    let _: UiSetup = initialization_client
        .transact(UiSetup::new(vec![
            ("dns-servers", "1.1.1.1"),
            ("neighborhood-mode", "zero-hop"),
            ("log-level", "trace"),
            ("data-directory", &data_directory),
        ]))
        .unwrap();
    let financials_request = UiFinancialsRequest {
        payable_minimum_amount: 0,
        payable_maximum_age: 0,
        receivable_minimum_amount: 0,
        receivable_maximum_age: 0,
    };
    let context_id = 1234;

    let not_running_financials_response = initialization_client
        .transact_with_context_id::<UiFinancialsRequest, UiRedirect>(
            financials_request.clone(),
            context_id,
        )
        .unwrap_err();
    let start_response: UiStartResponse = initialization_client.transact(UiStartOrder {}).unwrap();
    let running_financials_response: UiRedirect = initialization_client
        .transact_with_context_id(financials_request.clone(), context_id)
        .unwrap();

    assert_eq!(not_running_financials_response.0, NODE_NOT_RUNNING_ERROR);
    assert_eq!(
        not_running_financials_response.1,
        "Cannot handle financials request: Node is not running".to_string()
    );
    assert_eq!(running_financials_response.opcode, "financials".to_string());
    assert_eq!(
        running_financials_response.port,
        start_response.redirect_ui_port
    );
    let json = financials_request.tmb(context_id).payload.unwrap();
    let expected_payload: UiFinancialsRequest = serde_json::from_str(&json).unwrap();
    let actual_payload: UiFinancialsRequest =
        serde_json::from_str(&running_financials_response.payload).unwrap();
    assert_eq!(actual_payload, expected_payload);
    let mut service_client = UiConnection::new(start_response.redirect_ui_port, "MASQNode-UIv2");
    service_client.send(UiShutdownOrder {});
    wait_for_process_end(start_response.new_process_id);
    let _ = daemon.kill();
    match daemon.wait_for_exit() {
        None => eprintln! ("wait_for_exit produced no output: weird"),
        Some(output) => eprintln! ("wait_for_exit produced exit status {:?} and stdout:\n------\n{}\n------\nstderr:\n------\n{}\n------\n", output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)),
    }
}

fn wait_for_process_end(process_id: u32) {
    let tools = VerifierToolsReal::new();
    let deadline = SystemTime::now().add(Duration::from_millis(2000));
    loop {
        if SystemTime::now().gt(&deadline) {
            panic!(
                "Process {} not dead after receiving shutdownOrder",
                process_id
            )
        }
        if !tools.process_is_running(process_id) {
            break;
        }
        tools.delay(500);
    }
}
