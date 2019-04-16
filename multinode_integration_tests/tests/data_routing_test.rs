// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::proxy_server::protocol_pack::ServerImpersonator;
use node_lib::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
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
fn http_routing_failure_produces_internal_error_response() {
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

    let expected_response =
        ServerImpersonatorHttp {}.route_query_failure_response("www.example.com");

    assert!(
        &response.starts_with(&expected_response),
        "Actual response:\n{:?}",
        response
    );
}

#[test]
fn tls_routing_failure_produces_internal_error_response() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap.node_reference())
            .build(),
    );
    let mut client = originating_node.make_client(443);
    let client_hello = vec![
        0x16, // content_type: Handshake
        0x03, 0x03, // TLS 1.2
        0x00, 0x3F, // length
        0x01, // handshake_type: ClientHello
        0x00, 0x00, 0x3B, // length
        0x00, 0x00, // version: don't care
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // random: don't care
        0x00, // session_id_length
        0x00, 0x00, // cipher_suites_length
        0x00, // compression_methods_length
        0x00, 0x13, // extensions_length
        0x00, 0x00, // extension_type: server_name
        0x00, 0x0F, // extension_length
        0x00, 0x0D, // server_name_list_length
        0x00, // server_name_type
        0x00, 0x0A, // server_name_length
        's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
        'o' as u8, 'm' as u8, // server_name
    ];

    client.send_chunk(client_hello);
    let response = client.wait_for_chunk();

    assert_eq!(
        vec![
            0x15, // alert
            0x03, 0x03, // TLS 1.2
            0x00, 0x02, // packet length
            0x02, // fatal alert
            0x50, // internal_error alert
        ],
        response
    )
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
