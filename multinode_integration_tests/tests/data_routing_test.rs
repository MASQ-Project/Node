// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::sub_lib::http_server_impersonator;
use node_lib::sub_lib::utils::index_of;
use std::thread;
use std::time::Duration;

#[test]
fn end_to_end_gossip_and_routing_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );

    let node_3 = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(originating_node.node_reference())
            .build(),
    );
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(node_3.node_reference())
            .build(),
    );

    // Let gossip storm die down
    thread::sleep(Duration::from_millis(1000));

    let mut client = originating_node.make_client(80);
    client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));
    let response = client.wait_for_chunk();

    assert_eq!(
        index_of(
            &response,
            &b"This domain is established to be used for illustrative examples in documents."[..]
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn cannot_find_route_for_http_request_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );
    thread::sleep(Duration::from_millis(1000));

    let mut client = originating_node.make_client(80);

    client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));
    let response = client.wait_for_chunk();

    let expected_response = http_server_impersonator::make_error_response(
        503,
        "Routing Problem",
        "Can't find a route to www.example.com",
        "Substratum can't find a route through the Network yet to a Node that knows \
         where to find www.example.com. Maybe later enough will be known about the Network to \
         find that Node, but we can't guarantee it. We're sorry.",
    );

    assert!(
        &response.starts_with(&expected_response),
        "Actual response:\n{:?}",
        response
    );
}

#[test]
fn cannot_find_route_for_tls_request_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );
    thread::sleep(Duration::from_millis(1000));

    let mut client = originating_node.make_client(443);
    client.set_timeout(Duration::from_secs(3));

    client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));
    let response = client.wait_for_chunk();

    let expected_response: Vec<u8> = vec![];

    assert_eq!(response, expected_response);
}

#[test]
fn multiple_stream_zero_hop_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let zero_hop_node = cluster.start_real_node(NodeStartupConfigBuilder::zero_hop().build());
    let mut one_client = zero_hop_node.make_client(80);
    let mut another_client = zero_hop_node.make_client(80);

    one_client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));
    another_client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.fallingfalling.com\r\n\r\n"[..],
    ));

    let one_response = one_client.wait_for_chunk();
    let another_response = another_client.wait_for_chunk();

    assert_eq!(
        index_of(
            &one_response,
            &b"This domain is established to be used for illustrative examples in documents."[..]
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(one_response).unwrap()
    );
    assert_eq!(
        index_of(
            &another_response,
            &b"FALLING FALLING .COM BY RAFAEL ROZENDAAL"[..]
        )
        .is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(another_response).unwrap()
    );
}
