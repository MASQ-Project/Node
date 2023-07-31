// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::test_utils::utils::TEST_DEFAULT_MULTINODE_CHAIN;
use masq_lib::utils::{find_free_port, index_of};
use multinode_integration_tests_lib::masq_node::{MASQNode, PortSelector};
use multinode_integration_tests_lib::masq_node_client::MASQNodeClient;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{make_consuming_wallet_info, MASQRealNode, NodeStartupConfigBuilder, STANDARD_CLIENT_TIMEOUT_MILLIS};
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::neighborhood::AccessibleGossipRecord;
use node_lib::sub_lib::cryptde::{CryptDE, PublicKey};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::hopper::{ExpiredCoresPackage, IncipientCoresPackage, MessageType};
use node_lib::sub_lib::neighborhood::{Hops, RatePack};
use node_lib::sub_lib::proxy_client::DnsResolveFailure_0v1;
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::versioned_data::VersionedData;
use node_lib::test_utils::assert_string_contains;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use multinode_integration_tests_lib::masq_mock_node::MASQMockNode;
use node_lib::sub_lib::proxy_server::ClientRequestPayload_0v1;

#[test]
#[ignore] // Should be removed by SC-811/GH-158
fn neighborhood_notified_of_newly_missing_node() {
    // Set up three-Node network, and add a mock witness Node.
    let mut cluster = MASQNodeCluster::start().unwrap();
    let chain = cluster.chain;
    let neighbor = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .fake_public_key(&PublicKey::new(&[1, 2, 3, 4]))
            .chain(chain)
            .build(),
    );
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[2, 3, 4, 5]))
            .chain(chain)
            .build(),
    );
    let _staying_up_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[3, 4, 5, 6]))
            .chain(chain)
            .build(),
    );
    let disappearing_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor.node_reference())
            .fake_public_key(&PublicKey::new(&[4, 5, 6, 7]))
            .chain(chain)
            .build(),
    );
    let witness_node = cluster
        .start_mock_node_with_public_key(vec![find_free_port()], &PublicKey::new(&[5, 6, 7, 8]));
    witness_node.transmit_debut(&originating_node).unwrap();
    let (introductions, _) = witness_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();
    assert!(
        introductions.node_records.len() > 1,
        "Should have been introductions, but wasn't: {}",
        introductions.to_dot_graph(
            (
                originating_node.main_public_key(),
                &Some(originating_node.node_addr()),
            ),
            (
                witness_node.main_public_key(),
                &Some(witness_node.node_addr()),
            ),
        )
    );

    // Kill one of the Nodes--not the originating Node and not the witness Node.
    cluster.stop_node(disappearing_node.name());

    //Establish a client on the originating Node and send some ill-fated traffic.
    let mut client = originating_node.make_client(8080, STANDARD_CLIENT_TIMEOUT_MILLIS);
    client.send_chunk("GET http://example.com HTTP/1.1\r\n\r\n".as_bytes());

    // Now direct the witness Node to wait for Gossip about the disappeared Node.
    let (disappearance_gossip, _) = witness_node
        .wait_for_gossip(Duration::from_secs(130))
        .unwrap();

    let dot_graph = disappearance_gossip.to_dot_graph(
        (
            originating_node.main_public_key(),
            &Some(originating_node.node_addr()),
        ),
        (
            witness_node.main_public_key(),
            &Some(witness_node.node_addr()),
        ),
    );
    assert_eq!(
        3,
        disappearance_gossip.node_records.len(),
        "Should have had three records: {}",
        dot_graph
    );
    let disappearance_agrs: Vec<AccessibleGossipRecord> = disappearance_gossip.try_into().unwrap();
    let originating_node_agr = disappearance_agrs
        .into_iter()
        .find(|agr| &agr.inner.public_key == originating_node.main_public_key())
        .unwrap();
    assert!(
        !originating_node_agr
            .inner
            .neighbors
            .contains(&disappearing_node.main_public_key(),),
        "Originating Node {} should not be connected to the disappeared Node {}, but is: {}",
        originating_node.main_public_key(),
        disappearing_node.main_public_key(),
        dot_graph
    );
}

#[test]
fn dns_resolution_failure_with_real_nodes_route_error() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let low_rate_pack_1 = RatePack {
        routing_byte_rate: 6,
        routing_service_rate: 8,
        exit_byte_rate: 10,
        exit_service_rate: 13
    };

    /* Mock_node_good_exit <-- Originating_node --> Mock_node_bad_exit */

    let (originating_node, bad_exit_node, good_exit_node, bad_exit_node_public_key, good_exit_node_public_key) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let mut bad_exit_node_record = make_node_record(4567, true);
        let good_exit_node_record = make_node_record(5678, true);
        bad_exit_node_record.inner.rate_pack = low_rate_pack_1;
        let bad_exit_node_public_key = db.add_node(bad_exit_node_record).unwrap();
        let good_exit_node_public_key = db.add_node(good_exit_node_record).unwrap();
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &bad_exit_node_public_key);
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &good_exit_node_public_key);
        let (_, originating_node, mut node_map) = construct_neighborhood(&mut cluster, db, vec![], Hops::OneHop);
        let bad_exit_node = node_map.remove(&bad_exit_node_public_key).unwrap();
        let good_exit_node = node_map.remove(&good_exit_node_public_key).unwrap();
        (
            originating_node,
            bad_exit_node,
            good_exit_node,
            bad_exit_node_public_key,
            good_exit_node_public_key
        )
    };
    let masquerader = JsonMasquerader::new();

    let good_exit_cryptde = CryptDENull::from(&good_exit_node_public_key, TEST_DEFAULT_MULTINODE_CHAIN);
    let key_length = good_exit_node_public_key.len();
    let mut client = originating_node.make_client(8080, 10000);

    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
    let (_, _, live_cores_package) = good_exit_node
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let (_, intended_exit_public_key) =
        CryptDENull::extract_key_pair(key_length, &live_cores_package.payload);
    assert_eq!(intended_exit_public_key, good_exit_node_public_key);

    let expired_cores_package: ExpiredCoresPackage<MessageType> = live_cores_package
        .to_expired(
            originating_node.socket_addr(PortSelector::First),
            &good_exit_cryptde,
            &good_exit_cryptde,
        )
        .unwrap();

    //Loop while waiting from a ClientRequest message type
    match expired_cores_package.payload {
        MessageType::ClientRequest(_) => {}
        MessageType::ClientResponse(_) => {}
        MessageType::Gossip(_) => {}
        MessageType::GossipFailure(_) => {}
        MessageType::DnsResolveFailed(_) => {}
    }
    eprintln!("expired_cores_package: {:?}", expired_cores_package);

    // xpiredCoresPackage { immediate_neighbor: 1.2.3.4:5678, paying_wallet: None, remaining_route: Route { hops: [
    //     CryptData { data: [133, 134, 135, 136, 163, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 64, 101, 112, 97, 121, 101, 114, 246, 105, 99, 111, 109, 112, 111, 110, 101, 110, 116, 0] },
    //     CryptData { data: [52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52] }] },
    //     payload: Gossip(VersionedData { version: DataVersion { major: 0, minor: 1 },
    //         bytes: [161, 108, 110, 111, 100, 101, 95, 114, 101, 99, 111, 114, 100, 115, 130, 163, 107, 115, 105, 103, 110, 101, 100, 95, 100, 97, 116, 97, 88, 228, 167, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 68, 4, 5, 6, 7, 110, 101, 97, 114, 110, 105, 110, 103, 95, 119, 97, 108, 108, 101, 116, 161, 103, 97, 100, 100, 114, 101, 115, 115, 148, 24, 189, 24, 112, 24, 32, 24, 232, 24, 152, 24, 167, 24, 80, 24, 122, 24, 179, 24, 136, 24, 144, 24, 30, 24, 226, 24, 179, 24, 168, 24, 183, 24, 29, 24, 210, 24, 46, 24, 123, 105, 114, 97, 116, 101, 95, 112, 97, 99, 107, 164, 113, 114, 111, 117, 116, 105, 110, 103, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 6, 116, 114, 111, 117, 116, 105, 110, 103, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 8, 110, 101, 120, 105, 116, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 10, 113, 101, 120, 105, 116, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 13, 105, 110, 101, 105, 103, 104, 98, 111, 114, 115, 129, 68, 1, 2, 3, 4, 115, 97, 99, 99, 101, 112, 116, 115, 95, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 115, 245, 107, 114, 111, 117, 116, 101, 115, 95, 100, 97, 116, 97, 245, 103, 118, 101, 114, 115, 105, 111, 110, 2, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 24, 4, 5, 6, 7, 74, 154, 0, 245, 8, 222, 36, 225, 113, 2, 158, 52, 162, 32, 90, 159, 253, 44, 85, 16, 109, 110, 111, 100, 101, 95, 97, 100, 100, 114, 95, 111, 112, 116, 246, 163, 107, 115, 105, 103, 110, 101, 100, 95, 100, 97, 116, 97, 88, 241, 167, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 68, 1, 2, 3, 4, 110, 101, 97, 114, 110, 105, 110, 103, 95, 119, 97, 108, 108, 101, 116, 161, 103, 97, 100, 100, 114, 101, 115, 115, 148, 24, 39, 24, 217, 24, 162, 24, 172, 24, 131, 24, 180, 24, 147, 24, 248, 24, 140, 24, 233, 24, 180, 24, 83, 24, 46, 24, 220, 24, 247, 24, 78, 24, 149, 24, 185, 24, 120, 24, 141, 105, 114, 97, 116, 101, 95, 112, 97, 99, 107, 164, 113, 114, 111, 117, 116, 105, 110, 103, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 211, 116, 114, 111, 117, 116, 105, 110, 103, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 5, 154, 110, 101, 120, 105, 116, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 213, 113, 101, 120, 105, 116, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 6, 98, 105, 110, 101, 105, 103, 104, 98, 111, 114, 115, 130, 68, 4, 5, 6, 7, 68, 5, 6, 7, 8, 115, 97, 99, 99, 101, 112, 116, 115, 95, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 115, 245, 107, 114, 111, 117, 116, 101, 115, 95, 100, 97, 116, 97, 245, 103, 118, 101, 114, 115, 105, 111, 110, 2, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 24, 1, 2, 3, 4, 236, 8, 200, 207, 211, 245, 186, 249, 72, 214, 217, 155, 207, 244, 90, 32, 52, 146, 218, 108, 109, 110, 111, 100, 101, 95, 97, 100, 100, 114, 95, 111, 112, 116, 162, 103, 105, 112, 95, 97, 100, 100, 114, 161, 98, 86, 52, 132, 24, 172, 18, 1, 1, 101, 112, 111, 114, 116, 115, 129, 25, 30, 227],
    //         phantom: PhantomData }), payload_len: 1296 }


    // ExpiredCoresPackage {
    //     immediate_neighbor: 172.18.1.1:5517,
    //     paying_wallet: None, remaining_route: Route {
    //     hops: [CryptData { data: [133, 134, 135, 136, 163, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 64, 101, 112, 97, 121, 101, 114, 246, 105, 99, 111, 109, 112, 111, 110, 101, 110, 116, 0] }, CryptData { data: [52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52] }] },
    //     payload: Gossip(VersionedData { version: DataVersion { major: 0, minor: 1 },
    //         bytes: [161, 108, 110, 111, 100, 101, 95, 114, 101, 99, 111, 114, 100, 115, 130, 163, 107, 115, 105, 103, 110, 101, 100, 95, 100, 97, 116, 97, 88, 241, 167, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 68, 1, 2, 3, 4, 110, 101, 97, 114, 110, 105, 110, 103, 95, 119, 97, 108, 108, 101, 116, 161, 103, 97, 100, 100, 114, 101, 115, 115, 148, 24, 39, 24, 217, 24, 162, 24, 172, 24, 131, 24, 180, 24, 147, 24, 248, 24, 140, 24, 233, 24, 180, 24, 83, 24, 46, 24, 220, 24, 247, 24, 78, 24, 149, 24, 185, 24, 120, 24, 141, 105, 114, 97, 116, 101, 95, 112, 97, 99, 107, 164, 113, 114, 111, 117, 116, 105, 110, 103, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 211, 116, 114, 111, 117, 116, 105, 110, 103, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 5, 154, 110, 101, 120, 105, 116, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 213, 113, 101, 120, 105, 116, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 6, 98, 105, 110, 101, 105, 103, 104, 98, 111, 114, 115, 130, 68, 4, 5, 6, 7, 68, 5, 6, 7, 8, 115, 97, 99, 99, 101, 112, 116, 115, 95, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 115, 245, 107, 114, 111, 117, 116, 101, 115, 95, 100, 97, 116, 97, 245, 103, 118, 101, 114, 115, 105, 111, 110, 2, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 24, 1, 2, 3, 4, 236, 8, 200, 207, 211, 245, 186, 249, 72, 214, 217, 155, 207, 244, 90, 32, 52, 146, 218, 108, 109, 110, 111, 100, 101, 95, 97, 100, 100, 114, 95, 111, 112, 116, 162, 103, 105, 112, 95, 97, 100, 100, 114, 161, 98, 86, 52, 132, 24, 172, 18, 1, 1, 101, 112, 111, 114, 116, 115, 129, 25, 21, 141, 163, 107, 115, 105, 103, 110, 101, 100, 95, 100, 97, 116, 97, 88, 228, 167, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 68, 4, 5, 6, 7, 110, 101, 97, 114, 110, 105, 110, 103, 95, 119, 97, 108, 108, 101, 116, 161, 103, 97, 100, 100, 114, 101, 115, 115, 148, 24, 189, 24, 112, 24, 32, 24, 232, 24, 152, 24, 167, 24, 80, 24, 122, 24, 179, 24, 136, 24, 144, 24, 30, 24, 226, 24, 179, 24, 168, 24, 183, 24, 29, 24, 210, 24, 46, 24, 123, 105, 114, 97, 116, 101, 95, 112, 97, 99, 107, 164, 113, 114, 111, 117, 116, 105, 110, 103, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 6, 116, 114, 111, 117, 116, 105, 110, 103, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 8, 110, 101, 120, 105, 116, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 10, 113, 101, 120, 105, 116, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 13, 105, 110, 101, 105, 103, 104, 98, 111, 114, 115, 129, 68, 1, 2, 3, 4, 115, 97, 99, 99, 101, 112, 116, 115, 95, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 115, 245, 107, 114, 111, 117, 116, 101, 115, 95, 100, 97, 116, 97, 245, 103, 118, 101, 114, 115, 105, 111, 110, 2, 105, 115, 105, 103, 110, 97, 116, 117, 114, 101, 88, 24, 4, 5, 6, 7, 74, 154, 0, 245, 8, 222, 36, 225, 113, 2, 158, 52, 162, 32, 90, 159, 253, 44, 85, 16, 109, 110, 111, 100, 101, 95, 97, 100, 100, 114, 95, 111, 112, 116, 246],
    //         phantom: PhantomData }), payload_len: 1295 }


    // ExpiredCoresPackage<MessageType>
    // ExpiredCoresPackage<ClientRequestPayload_0v1>

    // let response = client.wait_for_chunk();
    // assert_eq!(
    //     index_of(&response, &b"<h1>Example Domain</h1>"[..]).is_some(),
    //     true,
    //     "Actual response:\n{}",
    //     String::from_utf8(response).unwrap()
    // );
}

#[test]
fn dns_resolution_failure_with_real_nodes() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .consuming_wallet_info(make_consuming_wallet_info("first_node"))
            .chain(cluster.chain)
            .build(),
    );
    let nodes = (0..5)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();
    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));
    let mut client = first_node.make_client(8080, 10000);

    client.send_chunk(b"GET / HTTP/1.1\r\nHost: www.nonexistent.com\r\n\r\n");

    let response = client.wait_for_chunk();
    assert_eq!(
        index_of(&response, &b"<h2>Title: DNS Resolution Problem</h2>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response.clone()).unwrap()
    );
    assert_eq!(
        index_of(&response, &b"<h3>Subtitle: Exit Nodes couldn't resolve \"www.nonexistent.com\"</h3>"[..]).is_some(),
        true,
        "Actual response:\n{}",
        String::from_utf8(response).unwrap()
    );
}

#[test]
fn dns_resolution_failure_automatic_retries_works() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Make network:
    // originating_node --> relay1 --> relay2 --> cheap_exit

    let (originating_node, relay1_mock, cheap_exit_key) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let relay1_key = db.add_node(make_node_record(2345, true)).unwrap();
        let relay2_key = db.add_node(make_node_record(3456, false)).unwrap();
        let cheap_exit_node = make_node_record(4567, false);
        let cheap_exit_key = db.add_node(cheap_exit_node).unwrap();
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &relay1_key);
        db.add_arbitrary_full_neighbor(&relay1_key, &relay2_key);
        db.add_arbitrary_full_neighbor(&relay2_key, &cheap_exit_key);
        let (_, originating_node, mut node_map) = construct_neighborhood(&mut cluster, db, vec![], Hops::ThreeHops);
        let relay1_mock = node_map.remove(&relay1_key).unwrap();
        (
            originating_node,
            relay1_mock,
            cheap_exit_key,
        )
    };
    let mut client: MASQNodeClient =
        originating_node.make_client(8080, 5000);
    let masquerader = JsonMasquerader::new();
    let originating_node_alias_cryptde = CryptDENull::from(
        &originating_node.alias_public_key(),
        TEST_DEFAULT_MULTINODE_CHAIN,
    );
    let relay1_cryptde =
        CryptDENull::from(&relay1_mock.main_public_key(), TEST_DEFAULT_MULTINODE_CHAIN);
    let cheap_exit_cryptde = CryptDENull::from(&cheap_exit_key, TEST_DEFAULT_MULTINODE_CHAIN);
    let key_length = cheap_exit_key.len();

    // This request should be routed through cheap_exit because it's cheaper
    client.send_chunk("GET / HTTP/1.1\r\nHost: nonexistent.com\r\n\r\n".as_bytes());
    let (_, _, live_cores_package) = relay1_mock
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let (_, intended_exit_public_key) =
        CryptDENull::extract_key_pair(key_length, &live_cores_package.payload);
    assert_eq!(intended_exit_public_key, cheap_exit_key);
    let expired_cores_package: ExpiredCoresPackage<MessageType> = live_cores_package
        .to_expired(
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            &relay1_cryptde,
            &cheap_exit_cryptde,
        )
        .unwrap();

    // Respond with a DNS failure to put nonexistent.com on the unreachable-host list
    let dns_fail_pkg_1 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_2 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_3 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_4 =
        make_dns_fail_package(expired_cores_package, &originating_node_alias_cryptde);

    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_1,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_2,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_3,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_4,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let dns_error_response: Vec<u8> = client.wait_for_chunk();
    let dns_error_response_str = String::from_utf8(dns_error_response).unwrap();
    assert_string_contains(&dns_error_response_str, "<h1>Error 503</h1>");
    assert_string_contains(
        &dns_error_response_str,
        "<h2>Title: DNS Resolution Problem</h2>",
    );
    assert_string_contains(
        &dns_error_response_str,
        "<h3>Subtitle: Exit Nodes couldn't resolve \"nonexistent.com\"</h3>",
    );
    assert_string_contains(
        &dns_error_response_str,
        &format!(
            "<p>DNS Failure, We have tried multiple Exit Nodes and all have failed to resolve this address nonexistent.com</p>"
        ),
    );
}

#[test]
fn dns_resolution_failure_no_longer_blacklists_exit_node_for_all_hosts() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Make network:
    // originating_node --> relay1 --> relay2 --> cheap_exit
    //                                   |
    //                                   +--> normal_exit
    let (originating_node, relay1_mock, cheap_exit_key, normal_exit_key, _third_exit_key, _forth_exit_key) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let relay1_key = db.add_node(make_node_record(2345, true)).unwrap();
        let relay2_key = db.add_node(make_node_record(3456, false)).unwrap();
        let mut cheap_exit_node = make_node_record(4567, false);
        let normal_exit_node = make_node_record(5678, false);
        let third_exit_node = make_node_record(6789, false);
        let forth_exit_node = make_node_record(7890, false);
        cheap_exit_node.inner.rate_pack = cheaper_rate_pack(normal_exit_node.rate_pack(), 1);
        let cheap_exit_key = db.add_node(cheap_exit_node).unwrap();
        let normal_exit_key = db.add_node(normal_exit_node).unwrap();
        let third_exit_key = db.add_node(third_exit_node).unwrap();
        let forth_exit_key = db.add_node(forth_exit_node).unwrap();
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &relay1_key);
        db.add_arbitrary_full_neighbor(&relay1_key, &relay2_key);
        db.add_arbitrary_full_neighbor(&relay2_key, &cheap_exit_key);
        db.add_arbitrary_full_neighbor(&relay2_key, &normal_exit_key);
        db.add_arbitrary_full_neighbor(&relay2_key, &third_exit_key);
        db.add_arbitrary_full_neighbor(&relay2_key, &forth_exit_key);

        let (_, originating_node, mut node_map) = construct_neighborhood(&mut cluster, db, vec![], Hops::ThreeHops);
        let relay1_mock = node_map.remove(&relay1_key).unwrap();
        (
            originating_node,
            relay1_mock,
            cheap_exit_key,
            normal_exit_key,
            third_exit_key,
            forth_exit_key,
        )
    };
    let mut client: MASQNodeClient =
        originating_node.make_client(8080, 5000);
    let masquerader = JsonMasquerader::new();
    let originating_node_alias_cryptde = CryptDENull::from(
        &originating_node.alias_public_key(),
        TEST_DEFAULT_MULTINODE_CHAIN,
    );
    let relay1_cryptde =
        CryptDENull::from(&relay1_mock.main_public_key(), TEST_DEFAULT_MULTINODE_CHAIN);
    let cheap_exit_cryptde = CryptDENull::from(&cheap_exit_key, TEST_DEFAULT_MULTINODE_CHAIN);
    let key_length = normal_exit_key.len();

    // This request should be routed through cheap_exit because it's cheaper
    client.send_chunk("GET / HTTP/1.1\r\nHost: nonexistent.com\r\n\r\n".as_bytes());
    let (_, _, live_cores_package) = relay1_mock
        .wait_for_package(&masquerader, Duration::from_secs(2))
        .unwrap();
    let (_, intended_exit_public_key) =
        CryptDENull::extract_key_pair(key_length, &live_cores_package.payload);
    assert_eq!(intended_exit_public_key, cheap_exit_key);
    let expired_cores_package: ExpiredCoresPackage<MessageType> = live_cores_package
        .to_expired(
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            &relay1_cryptde,
            &cheap_exit_cryptde,
        )
        .unwrap();

    // Respond with a DNS failure to put nonexistent.com on the unreachable-host list
    let dns_fail_pkg_1 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_2 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_3 =
        make_dns_fail_package(expired_cores_package.clone(), &originating_node_alias_cryptde);
    let dns_fail_pkg_4 =
        make_dns_fail_package(expired_cores_package, &originating_node_alias_cryptde);

    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_1,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_2,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_3,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    relay1_mock
        .transmit_package(
            relay1_mock.port_list()[0],
            dns_fail_pkg_4,
            &masquerader,
            originating_node.main_public_key(),
            originating_node.socket_addr(PortSelector::First),
        )
        .unwrap();
    let dns_error_response: Vec<u8> = client.wait_for_chunk();
    let dns_error_response_str = String::from_utf8(dns_error_response).unwrap();
    assert_string_contains(&dns_error_response_str, "<h1>Error 503</h1>");
    assert_string_contains(
        &dns_error_response_str,
        "<h2>Title: DNS Resolution Problem</h2>",
    );
    assert_string_contains(
        &dns_error_response_str,
        "<h3>Subtitle: Exit Nodes couldn't resolve \"nonexistent.com\"</h3>",
    );
    assert_string_contains(
        &dns_error_response_str,
        &format!(
            "<p>DNS Failure, We have tried multiple Exit Nodes and all have failed to resolve this address nonexistent.com</p>"
        ),
    );

    // This request should be routed through normal_exit because it's unreachable through cheap_exit
    client.send_chunk("GET / HTTP/1.1\r\nHost: nonexistent.com\r\n\r\n".as_bytes());
    let (_, _, live_cores_package) = relay1_mock
        .wait_for_package(&masquerader, Duration::from_secs(5))
        .unwrap();
    let (_, intended_exit_public_key) =
        CryptDENull::extract_key_pair(key_length, &live_cores_package.payload);
    assert_eq!(intended_exit_public_key, normal_exit_key);

    // TODO GH-674: Once the new exit node is picked, the Node will continue using that exit node
    // for all its route unless the current exit node faces an extreme penalty. Maybe it's not the
    // most economical solution. For example, in the assertion below, we may prefer to use
    // cheaper_exit_node instead.
    // TODO: Maybe we're using the same stream key (it represents the TCP connection b/w Client and the Originating Node)
    // that resulted in DNS Failure?
    // If the stream key remains the same, any request going through that stream key
    // will pick the last route.
    client.send_chunk("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes());
    let (_, _, live_cores_package) = relay1_mock
        .wait_for_package(&masquerader, Duration::from_secs(5))
        .unwrap();
    let (_, intended_exit_public_key) =
        CryptDENull::extract_key_pair(key_length, &live_cores_package.payload);
    assert_eq!(intended_exit_public_key, normal_exit_key);
}

fn cheaper_rate_pack(base_rate_pack: &RatePack, decrement: u64) -> RatePack {
    let mut result = *base_rate_pack;
    result.exit_byte_rate -= decrement;
    result.exit_service_rate -= decrement;
    result
}

fn make_dns_fail_package(
    expired_cores_package: ExpiredCoresPackage<MessageType>,
    destination_alias_cryptde: &dyn CryptDE,
) -> IncipientCoresPackage {
    let route = Route {
        hops: vec![
            expired_cores_package.remaining_route.hops[4].clone(),
            expired_cores_package.remaining_route.hops[5].clone(),
            expired_cores_package.remaining_route.hops[6].clone(),
        ],
    };
    let client_request_vdata = match expired_cores_package.payload {
        MessageType::ClientRequest(vdata) => vdata,
        x => panic!("Expected ClientRequest, got {:?}", x),
    };
    let stream_key = client_request_vdata
        .extract(&node_lib::sub_lib::migrations::client_request_payload::MIGRATIONS)
        .unwrap()
        .stream_key;
    let dns_fail_vdata = VersionedData::new(
        &node_lib::sub_lib::migrations::dns_resolve_failure::MIGRATIONS,
        &DnsResolveFailure_0v1 { stream_key },
    );
    IncipientCoresPackage::new(
        destination_alias_cryptde,
        route,
        MessageType::DnsResolveFailed(dns_fail_vdata),
        destination_alias_cryptde.public_key(),
    )
    .unwrap()
}
