// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::MASQNode;
use masq_lib::messages::SerializableLogLevel::Warn;
use masq_lib::messages::{
    UiChangePasswordRequest, UiFinancialsRequest, UiFinancialsResponse, UiLogBroadcast, UiRedirect,
    UiSetupRequest, UiSetupResponse, UiShutdownRequest, UiStartOrder, UiStartResponse,
    UiWalletAddressesRequest, NODE_UI_PROTOCOL,
};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::find_free_port;
use node_lib::accountant::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::database::db_initializer::{DbInitializer, DbInitializerReal};
use node_lib::database::db_migrations::MigratorConfig;
use node_lib::test_utils::make_wallet;
use utils::CommandConfig;

#[test]
fn ui_requests_something_and_gets_corresponding_response() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let home_dir = ensure_node_home_directory_exists(
        "ui_gateway_test",
        "ui_requests_something_and_gets_corresponding_response",
    );
    let make_conn = || {
        DbInitializerReal::default()
            .initialize(&home_dir, true, MigratorConfig::panic_on_migration())
            .unwrap()
    };
    PayableDaoReal::new(make_conn())
        .more_money_payable(&make_wallet("abc"), 45678)
        .unwrap();
    ReceivableDaoReal::new(make_conn())
        .more_money_receivable(&make_wallet("xyz"), 65432)
        .unwrap();
    let mut node = utils::MASQNode::start_standard(
        "ui_requests_something_and_gets_corresponding_response",
        Some(
            CommandConfig::new()
                .pair("--ui-port", &port.to_string())
                .pair(
                    "--data-directory",
                    home_dir.into_os_string().to_str().unwrap(),
                ),
        ),
        false,
        true,
        false,
        true,
    );
    node.wait_for_log("UIGateway bound", Some(5000));
    let financials_request = UiFinancialsRequest {};
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);

    client.send(financials_request);
    let response: UiFinancialsResponse = client.skip_until_received().unwrap();

    assert_eq!(
        response,
        UiFinancialsResponse {
            total_unpaid_and_pending_payable: 45678,
            total_paid_payable: 0,
            total_unpaid_receivable: 65432,
            total_paid_receivable: 0
        }
    );
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
fn daemon_does_not_allow_node_to_keep_his_client_alive_integration() {
    //Daemon's probe that tests the Node's "life functions" has a side effect of a new reference of
    //a client registered by the Node in that process, so Daemon sends a Websocket close message to
    //break all bounds
    fdlimit::raise_fd_limit();
    let data_directory = ensure_node_home_directory_exists(
        "ui_gateway_test",
        "daemon_does_not_allow_node_to_keep_his_client_alive_integration",
    );
    let daemon_port = find_free_port();
    let mut daemon = utils::MASQNode::start_daemon(
        "daemon_does_not_allow_node_to_keep_his_client_alive_integration",
        Some(CommandConfig::new().pair("--ui-port", daemon_port.to_string().as_str())),
        true,
        true,
        false,
        true,
    );
    let mut daemon_client = UiConnection::new(daemon_port, NODE_UI_PROTOCOL);
    let _: UiSetupResponse = daemon_client
        .transact(UiSetupRequest::new(vec![
            ("ip", Some("100.80.1.1")),
            ("chain", Some("eth-mainnet")),
            ("neighborhood-mode", Some("standard")),
            ("log-level", Some("trace")),
            ("data-directory", Some(&data_directory.to_str().unwrap())),
        ]))
        .unwrap();

    let _: UiStartResponse = daemon_client.transact(UiStartOrder {}).unwrap();

    let connect_and_disconnect_assertion =
        |required_number_of_captures: usize, pattern_in_log: fn(port_spec: &str) -> String| {
            let port_number_regex_str = r"UI connected at 127\.0\.0\.1:([\d]*)";
            //TODO fix this when GH-580 is being played
            //let log_file_directory = data_directory.join("eth-mainnet");
            let log_file_directory = data_directory.clone();
            let mut read_buffer = String::new();
            let ui_connected_so_far = MASQNode::capture_log_at_directory(
                port_number_regex_str,
                &log_file_directory.as_path(),
                &mut read_buffer,
                vec![1],
                required_number_of_captures,
                Some(5000),
            );
            let port_spec_ui = ui_connected_so_far[required_number_of_captures - 1][0].as_str();
            read_buffer.clear();
            MASQNode::wait_for_match_at_directory(
                pattern_in_log(port_spec_ui).as_str(),
                log_file_directory.as_path(),
                &mut read_buffer,
                Some(1500),
            );
            port_spec_ui.parse::<u16>().unwrap()
        };
    let assertion_pattern_1 = |port_spec_ui: &str| {
        format!(
            r"UI at 127\.0\.0\.1:{} \(client ID 0\) disconnected from port ",
            port_spec_ui
        )
    };
    let first_port = connect_and_disconnect_assertion(1, assertion_pattern_1);
    let shutdown_request = UiShutdownRequest {};
    //daemon was disconnected from Node automatically without na order from outside the box
    let ui_redirect: UiRedirect = daemon_client.transact(shutdown_request.clone()).unwrap();
    let mut node_client = UiConnection::new(ui_redirect.port, NODE_UI_PROTOCOL);
    node_client.send(shutdown_request);
    let assertion_pattern_2 =
        |_port_spec_ui: &str| "Received shutdown order from client 1".to_string();
    let second_port = connect_and_disconnect_assertion(2, assertion_pattern_2);
    let _ = daemon.kill();
    daemon.wait_for_exit();
    assert_ne!(first_port, second_port)
}

#[test]
fn cleanup_after_deceased_clients_works_integration() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let mut node = utils::MASQNode::start_standard(
        "cleanup_after_deceased_clients_works_integration",
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

    //Windows behaves differently, it admits that the connection is broken not until the second attempt
    //to write into the presumed stream, so we have to bring more attempts
    #[cfg(target_os = "windows")]
    client_2.send(UiChangePasswordRequest {
        old_password_opt: Some("boooga".to_string()),
        new_password: "wow".to_string(),
    });
    let expected_message_snippet_first = format!("UI at {} violated protocol", client_1_addr);
    node.wait_for_log(&expected_message_snippet_first, Some(2000));
    #[cfg(not(target_os = "windows"))]
    let expected_message_snippet_second =
        "Client 0: BrokenPipe, dropping its reference".to_string();
    #[cfg(target_os = "windows")]
    let expected_message_snippet_second =
        "Client 0: ConnectionReset, dropping its reference".to_string();
    node.wait_for_log(&expected_message_snippet_second, Some(1000));
    client_2.send(UiShutdownRequest {});
    node.wait_for_exit();
}
