// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate base64;
extern crate hopper_lib;
extern crate multinode_integration_tests_lib;
extern crate neighborhood_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use multinode_integration_tests_lib::substratum_node::NodeReference;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::gossip::GossipNodeRecord;
use neighborhood_lib::neighborhood_database::NodeRecord;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use neighborhood_lib::neighborhood_database::NodeSignatures;
use node_lib::json_masquerader::JsonMasquerader;
use std::net::IpAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use sub_lib::accountant;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_server_impersonator;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::utils::index_of;
use sub_lib::utils::plus;
use sub_lib::wallet::Wallet;
use test_utils::test_utils::make_meaningless_stream_key;

#[test]
fn http_request_to_cores_package_and_cores_package_to_http_response_test() {
    let masquerader = JsonMasquerader::new();
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_bootstrap = cluster.start_mock_node(vec![5550]);
    let mock_standard = cluster.start_mock_node(vec![5551]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .earning_wallet(Wallet::new("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
            .neighbor(mock_bootstrap.node_reference())
            .build(),
    );

    let (_, _, package) = mock_bootstrap
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();
    let incoming_cores_package = package
        .to_expired(
            IpAddr::from_str("1.2.3.4").unwrap(),
            mock_bootstrap.cryptde(),
        )
        .unwrap();
    let incoming_gossip = incoming_cores_package.payload::<Gossip>().unwrap();
    let inner = NodeRecordInner {
        public_key: subject.public_key(),
        node_addr_opt: Some(subject.node_addr()),
        is_bootstrap_node: false,
        earning_wallet: Wallet::new("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
        consuming_wallet: Some(accountant::TEMPORARY_CONSUMING_WALLET.clone()),
        neighbors: vec![mock_bootstrap.public_key()],
        version: 0,
    };
    let cryptde = CryptDENull::from(&subject.public_key());
    let complete_signature = inner.generate_signature(&cryptde);

    let mut obscured_inner = inner.clone();
    obscured_inner.node_addr_opt = None;
    let obscured_signature = obscured_inner.generate_signature(&cryptde);
    assert_eq!(
        incoming_gossip.node_records,
        vec!(GossipNodeRecord {
            inner,
            signatures: NodeSignatures::new(complete_signature, obscured_signature),
        })
    );

    let ne1_noderef = NodeReference::new(
        Key::new(&b"ne1"[..]),
        IpAddr::from_str("100.100.100.001").unwrap(),
        vec![5561],
    );
    let ne2_noderef = NodeReference::new(
        Key::new(&b"ne2"[..]),
        IpAddr::from_str("100.100.100.002").unwrap(),
        vec![5562],
    );
    let outgoing_gossip = make_gossip(vec![
        (&subject.node_reference(), false),
        (&mock_standard.node_reference(), true),
        (&ne1_noderef, false),
        (&ne2_noderef, false),
    ]);
    let route = Route::new(
        vec![RouteSegment::new(
            vec![&mock_bootstrap.public_key(), &subject.public_key()],
            Component::Neighborhood,
        )],
        mock_bootstrap.cryptde(),
        Some(Wallet::new("0xEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")),
    )
    .unwrap();
    let outgoing_package =
        IncipientCoresPackage::new(route, outgoing_gossip, &subject.public_key());
    mock_bootstrap
        .transmit_package(
            5551,
            outgoing_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    mock_standard
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();

    // It'd be nice if there were a better way to ensure that the Gossip had been consumed.
    thread::sleep(Duration::from_millis(1000));

    let mut client = subject.make_client(80);
    client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));

    let (_, _, package) = mock_standard
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();
    let request_payload_ser = CryptDENull::from(&ne1_noderef.public_key)
        .decode(&package.payload)
        .unwrap();
    let request_payload =
        serde_cbor::de::from_slice::<ClientRequestPayload>(&request_payload_ser.data[..]).unwrap();

    assert_eq!(request_payload.sequenced_packet.last_data, false);
    assert_eq!(request_payload.sequenced_packet.sequence_number, 0);
    assert_eq!(
        request_payload.sequenced_packet.data,
        Vec::from(&b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..])
    );
    assert_eq!(
        request_payload.target_hostname,
        Some(String::from("www.example.com"))
    );
    assert_eq!(request_payload.target_port, 80);
    assert_eq!(request_payload.protocol, ProxyProtocol::HTTP);
    assert_eq!(request_payload.originator_public_key, subject.public_key());

    let route = Route::new(
        vec![RouteSegment::new(
            vec![&mock_standard.public_key(), &subject.public_key()],
            Component::ProxyServer,
        )],
        mock_standard.cryptde(),
        Some(Wallet::new("consuming")),
    )
    .unwrap();
    let response_payload = ClientResponsePayload {
        stream_key: request_payload.stream_key,
        sequenced_packet: SequencedPacket {data: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nOoh! Do you work out?".to_vec (), sequence_number: 0, last_data: false},
    };
    let outgoing_package =
        IncipientCoresPackage::new(route, response_payload, &subject.public_key());
    mock_standard
        .transmit_package(
            5551,
            outgoing_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    let response = client.wait_for_chunk();
    assert_eq!(
        index_of(&response, &b"Ooh! Do you work out?"[..]).is_some(),
        true
    );
}

#[test]
fn cores_package_to_http_request_and_http_response_to_cores_package_test() {
    let masquerader = JsonMasquerader::new();
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_bootstrap = cluster.start_mock_node(vec![5550]);
    let mock_standard = cluster.start_mock_node(vec![5551]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(mock_bootstrap.node_reference())
            .build(),
    );

    mock_bootstrap
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();

    let ne1_noderef = NodeReference::new(
        Key::new(&b"ne1"[..]),
        IpAddr::from_str("100.100.100.001").unwrap(),
        vec![5561],
    );
    let ne2_noderef = NodeReference::new(
        Key::new(&b"ne2"[..]),
        IpAddr::from_str("100.100.100.002").unwrap(),
        vec![5562],
    );
    let ne3_noderef = NodeReference::new(
        Key::new(&b"ne3"[..]),
        IpAddr::from_str("100.100.100.003").unwrap(),
        vec![5563],
    );
    let outgoing_gossip = make_gossip(vec![
        (&ne1_noderef, false),
        (&ne2_noderef, false),
        (&ne3_noderef, false),
        (&mock_standard.node_reference(), true),
    ]);
    let route = Route::new(
        vec![RouteSegment::new(
            vec![&mock_bootstrap.public_key(), &subject.public_key()],
            Component::Neighborhood,
        )],
        mock_bootstrap.cryptde(),
        Some(Wallet::new("consuming")),
    )
    .unwrap();
    let outgoing_package =
        IncipientCoresPackage::new(route, outgoing_gossip, &subject.public_key());
    mock_bootstrap
        .transmit_package(
            5551,
            outgoing_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    mock_standard
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();

    let client_request_payload = ClientRequestPayload {
        stream_key: make_meaningless_stream_key(),
        sequenced_packet: SequencedPacket {
            data: b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".to_vec(),
            sequence_number: 0,
            last_data: true,
        },
        target_hostname: Some(String::from("www.example.com")),
        target_port: 80,
        protocol: ProxyProtocol::HTTP,
        originator_public_key: ne1_noderef.public_key.clone(),
    };
    let route = Route::new(
        vec![
            RouteSegment::new(
                vec![&mock_standard.public_key(), &subject.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![
                    &subject.public_key(),
                    &mock_standard.public_key(),
                    &ne3_noderef.public_key,
                    &ne2_noderef.public_key,
                    &ne1_noderef.public_key,
                ],
                Component::ProxyServer,
            ),
        ],
        mock_standard.cryptde(),
        Some(Wallet::new("consuming")),
    )
    .unwrap();
    let outgoing_package =
        IncipientCoresPackage::new(route, client_request_payload, &subject.public_key());
    mock_standard
        .transmit_package(
            5551,
            outgoing_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    let (_, _, package) = mock_standard
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();
    let response_payload_ser = CryptDENull::from(&ne1_noderef.public_key)
        .decode(&package.payload)
        .unwrap();
    let response_payload =
        serde_cbor::de::from_slice::<ClientResponsePayload>(&response_payload_ser.data[..])
            .unwrap();
    assert_eq!(response_payload.stream_key, make_meaningless_stream_key());
    assert_eq!(response_payload.sequenced_packet.last_data, false);
    assert_eq!(response_payload.sequenced_packet.sequence_number, 0);
    assert_eq!(
        index_of(
            &response_payload.sequenced_packet.data,
            &b"This domain is established to be used for illustrative examples in documents."[..]
        )
        .is_some(),
        true
    );
}

#[test]
fn end_to_end_gossip_and_routing_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );

    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );
    cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );

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

fn make_gossip(pairs: Vec<(&NodeReference, bool)>) -> Gossip {
    let node_ref_count = pairs.len() as usize;
    let mut gossip_node_records = pairs.into_iter().fold(vec![], |so_far, pair| {
        let (node_ref_ref, reveal) = pair;
        let inner = NodeRecordInner {
            public_key: node_ref_ref.public_key.clone(),
            node_addr_opt: if reveal {
                Some(node_ref_ref.node_addr.clone())
            } else {
                None
            },
            is_bootstrap_node: false,
            earning_wallet: Wallet::new("earning"),
            consuming_wallet: Some(Wallet::new("consuming")),
            neighbors: vec![],
            version: 0,
        };
        let (complete_signature, obscured_signature) = {
            let mut nr = NodeRecord::new(
                &node_ref_ref.public_key,
                Some(&node_ref_ref.node_addr),
                inner.earning_wallet.clone(),
                inner.consuming_wallet.clone(),
                false,
                None,
                0,
            );
            nr.sign(&CryptDENull::from(&node_ref_ref.public_key));
            (
                nr.signatures().unwrap().complete().clone(),
                nr.signatures().unwrap().obscured().clone(),
            )
        };
        plus(
            so_far,
            GossipNodeRecord {
                inner,
                signatures: NodeSignatures::new(complete_signature, obscured_signature),
            },
        )
    });
    for i in 0..(node_ref_count - 1) {
        let neighbor_key = gossip_node_records[i + 1].inner.public_key.clone();
        gossip_node_records[i].inner.neighbors.push(neighbor_key);
    }
    for i in 1..node_ref_count {
        let neighbor_key = gossip_node_records[i - 1].inner.public_key.clone();
        gossip_node_records[i].inner.neighbors.push(neighbor_key);
    }
    Gossip {
        node_records: gossip_node_records,
    }
}
