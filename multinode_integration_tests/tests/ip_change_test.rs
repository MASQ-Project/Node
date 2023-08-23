// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::masq_mock_node::MASQMockNodeGutsBuilder;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_client::MASQNodeClient;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::mock_router::MockRouter;
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::neighborhood::gossip::Gossip_0v1;
use node_lib::sub_lib::cryptde::decodex;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use multinode_integration_tests_lib::masq_real_node::STANDARD_CLIENT_TIMEOUT_MILLIS;

#[test]
#[ignore]
fn receiving_ipchange_gossip_modifies_connections_appropriately() {
    // Set up network with one real Node, one mock Node with full neighborship, one disconnected mock Node
    let mut cluster = MASQNodeCluster::start().unwrap();
    let root_node = make_node_record(1234, true);
    let mut db = db_from_node(&root_node);
    let old_ip_neighbor_key = db.add_node(make_node_record(2345, true)).unwrap();
    let fictional_relay_key = db.add_node(make_node_record(3456, true)).unwrap();
    let fictional_exit_key = db.add_node(make_node_record(4567, true)).unwrap();
    let new_ip_neighbor_key = db.add_node(make_node_record(5678, true)).unwrap();
    db.add_arbitrary_full_neighbor(root_node.public_key(), &old_ip_neighbor_key);
    db.add_arbitrary_full_neighbor(&old_ip_neighbor_key, &fictional_relay_key);
    db.add_arbitrary_full_neighbor(&fictional_relay_key, &fictional_exit_key);
    let (_, real_node, mut node_map) =
        construct_neighborhood(&mut cluster, db, vec![&new_ip_neighbor_key]);
    let old_mock_node = node_map.remove(&old_ip_neighbor_key).unwrap();
    let mut new_mock_node = node_map.remove(&new_ip_neighbor_key).unwrap();
    let builder = MASQMockNodeGutsBuilder::from(&old_mock_node)
        .node_addr(new_mock_node.node_addr())
        .name(new_mock_node.name());
    let _container_preserver = new_mock_node.guts_from_builder(builder);
    // Have the connected mock Node disconnect its TCP stream to simulate IP address change
    old_mock_node.kill();
    // Have the disconnected mock Node connect and send an IpChange, impersonating old_mock_node
    new_mock_node
        .transmit_ipchange_or_debut(&real_node)
        .unwrap();
    // Connect a client and send a request.
    let mut client = MASQNodeClient::new(
        SocketAddr::new(real_node.ip_address(), 80),
        STANDARD_CLIENT_TIMEOUT_MILLIS
    );
    client.send_chunk("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes());
    // Verify that the request shows up at the formerly disconnected mock Node.
    let (_, _, _) = new_mock_node
        .wait_for_package(&JsonMasquerader::new(), Duration::from_secs(2))
        .unwrap();
}

#[test]
#[ignore]
fn receiving_announce_from_router_produces_ipchange_gossip() {
    // Set up network with one real Node, one mock Node with full neighborship, and a mock router.
    let mut cluster = MASQNodeCluster::start().unwrap();
    let root_node = make_node_record(1234, true);
    let mut db = db_from_node(&root_node);
    let neighbor_key = db.add_node(make_node_record(2345, true)).unwrap();
    db.add_arbitrary_full_neighbor(root_node.public_key(), &neighbor_key);
    let (_, real_node, mut node_map) = construct_neighborhood(&mut cluster, db, vec![]);
    let new_ip_address = {
        let current_ip_address = match real_node.ip_address() {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            x => panic!("Expected IPv4 addr; found {:?}", x),
        };
        let octets = &current_ip_address.octets();
        IpAddr::V4(Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            octets[3] + 1,
        ))
    };
    let mock_router = cluster.start_mock_pcp_router();
    let mock_node = node_map.remove(&neighbor_key).unwrap();
    // Wait for the new Node to get situated
    thread::sleep(Duration::from_secs(1));
    // Have the mock router announce a change in public IP.
    mock_router.announce_ip_change(real_node.ip_address(), new_ip_address);
    // Verify that IpChange Gossip shows up at the mock Node.
    let (_, _, live_cores_package) = mock_node
        .wait_for_package(&JsonMasquerader::new(), Duration::from_secs(2))
        .unwrap();
    let mut gossip = decodex::<Gossip_0v1>(
        mock_node.main_cryptde_null().unwrap(),
        &live_cores_package.payload,
    )
    .unwrap();
    // Now verify the Gossip
    let node_record = gossip.node_records.remove(0);
    let expected_node_addr = NodeAddr::new(&new_ip_address, &real_node.port_list());
    assert_eq!(node_record.node_addr_opt, Some(expected_node_addr));
    assert_eq!(gossip.node_records.is_empty(), true);
}
