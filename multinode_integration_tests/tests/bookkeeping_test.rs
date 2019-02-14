// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate accountant_lib;
extern crate base64;
extern crate hopper_lib;
extern crate multinode_integration_tests_lib;
extern crate neighborhood_lib;
extern crate node_lib;
extern crate proxy_client_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use accountant_lib::dao_utils;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use multinode_integration_tests_lib::substratum_real_node::SubstratumRealNode;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use sub_lib::proxy_client::TEMPORARY_PER_BYTE_RATE;
use sub_lib::proxy_client::TEMPORARY_PER_EXIT_RATE;

#[test]
fn provided_services_are_recorded_in_accounts_receivable() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let bootstrap = cluster.start_mock_bootstrap_node(vec![5550]);

    let _nodes = (0..3)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(bootstrap.node_reference())
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();
    thread::sleep(Duration::from_millis(2000));

    let originating_node = cluster
        .get_real_node_by_key(&bootstrap.originating_node_key())
        .unwrap();
    let mut client = originating_node.make_client(80);
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
    let before = dao_utils::to_time_t(&SystemTime::now());

    client.send_chunk(Vec::from(request));
    let response = client.wait_for_chunk();

    let after = dao_utils::to_time_t(&SystemTime::now());
    let exit_node = cluster
        .get_real_node_by_key(&bootstrap.exit_node_key())
        .unwrap();
    let receivable_dao = exit_node.daos().receivable;
    let account_status = receivable_dao
        .account_status(originating_node.consuming_wallet().as_ref().unwrap())
        .unwrap();

    let expected_example_request_charge = calculate_exit_charge(request.len());
    let expected_example_response_charge = calculate_exit_charge(response.len());
    assert_eq!(
        account_status.balance as u64,
        expected_example_request_charge + expected_example_response_charge
    );
    let timestamp = dao_utils::to_time_t(&account_status.last_received_timestamp);
    assert!(timestamp >= before);
    assert!(timestamp <= after);
}

fn calculate_exit_charge(bytes: usize) -> u64 {
    TEMPORARY_PER_EXIT_RATE + (TEMPORARY_PER_BYTE_RATE * bytes as u64)
}
