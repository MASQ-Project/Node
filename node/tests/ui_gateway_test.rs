// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use masq_lib::messages::{
    UiFinancialsRequest, UiFinancialsResponse, UiShutdownRequest, NODE_UI_PROTOCOL,
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

    let response: UiFinancialsResponse = client.receive().unwrap();
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
