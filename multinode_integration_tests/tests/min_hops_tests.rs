// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::messages::{ToMessageBody, UiSetConfigurationRequest};
use masq_lib::utils::{find_free_port, index_of};
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder,
};
use node_lib::sub_lib::neighborhood::Hops;
use std::thread;
use std::time::Duration;

#[test]
fn data_can_be_routed_using_different_min_hops() {
    // This test fails sometimes due to a timeout: "Couldn't read chunk: Kind(TimedOut)"
    // You may fix it by increasing the timeout for the client.
    assert_http_end_to_end_routing(Hops::OneHop);
    assert_http_end_to_end_routing(Hops::TwoHops);
    assert_http_end_to_end_routing(Hops::SixHops);
}

fn assert_http_end_to_end_routing(min_hops: Hops) {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let config = NodeStartupConfigBuilder::standard()
        .min_hops(min_hops)
        .chain(cluster.chain)
        .consuming_wallet_info(make_consuming_wallet_info("first_node"))
        .build();
    let first_node = cluster.start_real_node(config);

    // For 1-hop route, 3 nodes are necessary if we use last node as the originating node
    let nodes_count = (min_hops as usize) + 2;
    let nodes = (0..nodes_count)
        .map(|i| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .consuming_wallet_info(make_consuming_wallet_info(&format!("node_{i}")))
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let last_node = nodes.last().unwrap();
    let mut client = last_node.make_client(8080, 5000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn min_hops_can_be_changed_during_runtime() {
    let initial_min_hops = Hops::OneHop;
    let new_min_hops = Hops::TwoHops;
    let mut cluster = MASQNodeCluster::start().unwrap();
    let ui_port = find_free_port();
    let first_node_config = NodeStartupConfigBuilder::standard()
        .min_hops(initial_min_hops)
        .chain(cluster.chain)
        .consuming_wallet_info(make_consuming_wallet_info("first_node"))
        .ui_port(ui_port)
        .build();
    let first_node = cluster.start_real_node(first_node_config);
    let ui_client = first_node.make_ui(ui_port);

    for _ in 0..initial_min_hops as u8 {
        cluster.start_real_node(
            NodeStartupConfigBuilder::standard()
                .neighbor(first_node.node_reference())
                .chain(cluster.chain)
                .build(),
        );
    }
    thread::sleep(Duration::from_millis(1000));

    let mut client = first_node.make_client(8080, 5000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();

    // Client shutdown is necessary to re-initialize stream keys for old requests
    client.shutdown();

    assert_eq!(
        index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );

    ui_client.send_request(
        UiSetConfigurationRequest {
            name: "min-hops".to_string(),
            value: new_min_hops.to_string(),
        }
        .tmb(1),
    );
    let response = ui_client.wait_for_response(1, Duration::from_secs(2));
    assert!(response.payload.is_ok());

    let mut client = first_node.make_client(8080, 5000);
    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let response = client.wait_for_chunk();
    assert_eq!(
        index_of(
            &response,
            &b"<h3>Subtitle: Can't find a route to www.example.com</h3>"[..]
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}
