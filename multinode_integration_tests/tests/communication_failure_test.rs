// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::utils::find_free_port;
use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::NodeStartupConfigBuilder;
use node_lib::neighborhood::AccessibleGossipRecord;
use node_lib::sub_lib::cryptde::PublicKey;
use std::convert::TryInto;
use std::time::Duration;
use multinode_integration_tests_lib::neighborhood_constructor::construct_neighborhood;
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::sub_lib::neighborhood::{DEFAULT_RATE_PACK, RatePack};
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};

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
    let mut client = originating_node.make_client(8080);
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

fn cheap_rate_pack (decrement: u64) -> RatePack {
    let mut result = DEFAULT_RATE_PACK;
    result.exit_byte_rate -= decrement;
    result.exit_service_rate -= decrement;
    result
}

#[test]
fn dns_resolution_failure_no_longer_blacklists_exit_node_for_all_hosts() {
    let (db, relay1) = {
        let originating_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&originating_node);
        let relay1 = db.add_node(make_node_record(2345, true)).unwrap();
        let relay2 = db.add_node(make_node_record(3456, false)).unwrap();
        let mut cheap_exit_node = make_node_record(4567, false);
        cheap_exit_node.inner.rate_pack = cheap_rate_pack(1);
        let cheap_exit = db.add_node(cheap_exit_node).unwrap();
        let normal_exit = db.add_node(make_node_record(5678, false)).unwrap();
        db.add_arbitrary_full_neighbor(originating_node.public_key(), &relay1);
        db.add_arbitrary_full_neighbor(&relay1, &relay2);
        db.add_arbitrary_full_neighbor(&relay2, &cheap_exit);
        db.add_arbitrary_full_neighbor(&relay2, &normal_exit);
        (db, relay1)
    };
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (_, originating_node, mut node_map)
        = construct_neighborhood(&mut cluster, db, vec![]);
    let relay1_mock = node_map.get(&relay1).unwrap();
    relay1_mock.
}