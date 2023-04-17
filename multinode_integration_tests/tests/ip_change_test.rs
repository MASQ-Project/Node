// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::SocketAddr;
use std::time::Duration;
use multinode_integration_tests_lib::masq_node::PortSelector;
use multinode_integration_tests_lib::masq_node_client::MASQNodeClient;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use multinode_integration_tests_lib::masq_node::MASQNode;

#[test]
fn receiving_ipchange_gossip_modifies_connections_appropriately() {
    // Set up network with one real Node, one mock Node with full neighborship, one disconnected mock Node
    let mut cluster = MASQNodeCluster::start().unwrap();
    let root_node = make_node_record(1234, true);
    let mut db = db_from_node (&root_node);
    let old_ip_neighbor_key = db.add_node(make_node_record(2345, true)).unwrap();
    let fictional_relay_key = db.add_node(make_node_record(3456, true)).unwrap();
    let fictional_exit_key = db.add_node(make_node_record(4567, true)).unwrap();
    let new_ip_neighbor_key = db.add_node(make_node_record (5678, true)).unwrap();
    db.add_arbitrary_full_neighbor (root_node.public_key(), &old_ip_neighbor_key);
    db.add_arbitrary_full_neighbor (&old_ip_neighbor_key, &fictional_relay_key);
    db.add_arbitrary_full_neighbor (&fictional_relay_key, &fictional_exit_key);
    let (_, real_node, mut node_map) =
        construct_neighborhood (&mut cluster, db, vec![
            &new_ip_neighbor_key
        ]);
    let old_mock_node = node_map.remove(&old_ip_neighbor_key).unwrap();
    let mut new_mock_node = node_map.remove (&new_ip_neighbor_key).unwrap();
    let _container_preserver = new_mock_node.copy_guts_from(&old_mock_node);
    // (maybe) have the connected mock Node disconnect its TCP stream.
    old_mock_node.kill();
    // Have the disconnected mock Node connect and send an IpChange
    new_mock_node.transmit_ipchange_or_debut(&real_node).unwrap();
    // Verify that the real Node disconnects any remaining streams to the originally-connected mock Node.
    // (not this time: we disconnected them already)
    // Connect a client and send a request. Verify that the request shows up at the formerly disconnected mock Node.
    let mut client = MASQNodeClient::new(SocketAddr::new (real_node.ip_address(), 80));
    client.send_chunk("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes());
    let (_, _, _) = new_mock_node
        .wait_for_package(&JsonMasquerader::new(), Duration::from_secs(2))
        .unwrap();
}

#[test]
fn receiving_announce_from_router_produces_ipchange_gossip() {
    // Set up network with one real Node, one mock Node with full neighborship, and a mock router.
    // Have the mock router announce a change in public IP.
    // Verify that the mock Node receives IpChange Gossip.
    // Connect a client and send a request. Verify that the request shows up at the mock Node.
    todo! ("Finish me")
}
