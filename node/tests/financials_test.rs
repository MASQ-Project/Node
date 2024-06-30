// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::{make_conn, CommandConfig};
use masq_lib::messages::{
    TopRecordsConfig, TopRecordsOrdering, UiFinancialsRequest, UiFinancialsResponse,
    UiShutdownRequest, NODE_UI_PROTOCOL,
};
use masq_lib::test_utils::ui_connection::UiConnection;
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::find_free_port;
use node_lib::accountant::db_access_objects::payable_dao::{PayableDao, PayableDaoReal};
use node_lib::accountant::db_access_objects::receivable_dao::{ReceivableDao, ReceivableDaoReal};
use node_lib::accountant::db_access_objects::utils::{from_time_t, to_time_t};
use node_lib::accountant::gwei_to_wei;
use node_lib::test_utils::make_wallet;
use std::time::SystemTime;
use utils::MASQNode;

#[test]
fn financials_command_retrieves_payable_and_receivable_records() {
    fdlimit::raise_fd_limit();
    let port = find_free_port();
    let home_dir = ensure_node_home_directory_exists(
        "financials_test",
        "financials_command_retrieves_payable_and_receivable_records",
    );
    let now = SystemTime::now();
    let timestamp_payable = from_time_t(to_time_t(now) - 678);
    let timestamp_receivable_1 = from_time_t(to_time_t(now) - 10000);
    let timestamp_receivable_2 = from_time_t(to_time_t(now) - 1111);
    let wallet_payable = make_wallet("efef");
    let wallet_receivable_1 = make_wallet("abcde");
    let wallet_receivable_2 = make_wallet("ccccc");
    let amount_payable = gwei_to_wei(45678357_u64);
    let amount_receivable_1 = gwei_to_wei(9000_u64);
    let amount_receivable_2 = gwei_to_wei(345678_u64);
    PayableDaoReal::new(make_conn(&home_dir))
        .more_money_payable(timestamp_payable, &wallet_payable, amount_payable)
        .unwrap();
    let receivable_dao = ReceivableDaoReal::new(make_conn(&home_dir));
    receivable_dao
        .more_money_receivable(
            timestamp_receivable_1,
            &wallet_receivable_1,
            amount_receivable_1,
        )
        .unwrap();
    receivable_dao
        .more_money_receivable(
            timestamp_receivable_2,
            &wallet_receivable_2,
            amount_receivable_2,
        )
        .unwrap();
    let mut node = MASQNode::start_standard(
        "financials_command_retrieves_payable_and_receivable_records",
        Some(CommandConfig::new().pair("--ui-port", &port.to_string())),
        false,
        true,
        false,
        true,
    );
    let financials_request = UiFinancialsRequest {
        stats_required: false,
        top_records_opt: Some(TopRecordsConfig {
            count: 10,
            ordered_by: TopRecordsOrdering::Balance,
        }),
        custom_queries_opt: None,
    };
    let mut client = UiConnection::new(port, NODE_UI_PROTOCOL);
    let before = SystemTime::now();

    client.send(financials_request);
    let response: UiFinancialsResponse = client.skip_until_received().unwrap();

    let after = SystemTime::now();
    assert_eq!(response.stats_opt, None);
    let query_results = response.query_results_opt.unwrap();
    let payable = query_results.payable_opt.unwrap();
    let receivable = query_results.receivable_opt.unwrap();
    assert_eq!(payable[0].wallet, wallet_payable.to_string());
    assert_eq!(payable[0].balance_gwei, 45678357_u64);
    assert_eq!(payable[0].pending_payable_hash_opt, None);
    assert_eq!(receivable[0].wallet, wallet_receivable_1.to_string());
    assert_eq!(receivable[0].balance_gwei, 9000_i64);
    assert_eq!(receivable[1].wallet, wallet_receivable_2.to_string());
    assert_eq!(receivable[1].balance_gwei, 345678_i64);
    let act_period = after.duration_since(before).unwrap().as_secs();
    let age_payable = payable[0].age_s;
    assert!(age_payable >= 678 && age_payable <= (age_payable + act_period));
    let age_receivable_1 = receivable[0].age_s;
    assert!(age_receivable_1 >= 10000 && age_receivable_1 <= (age_receivable_1 + act_period));
    let age_receivable_2 = receivable[1].age_s;
    assert!(age_receivable_2 >= 1111 && age_receivable_2 <= (age_receivable_2 + act_period));
    client.send(UiShutdownRequest {});
    node.wait_for_exit();
}
