// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{MASQRealNode, NodeStartupConfigBuilder};
use multinode_integration_tests_lib::multinode_gossip::{
    parse_gossip, GossipType, MultinodeGossip, StandardBuilder,
};
use multinode_integration_tests_lib::neighborhood_constructor::{
    construct_neighborhood, do_not_modify_config,
};
use node_lib::neighborhood::gossip_acceptor::MAX_DEGREE;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use std::thread;
use std::time::Duration;

#[test]
fn graph_connects_but_does_not_over_connect() {
    let neighborhood_size = 5;
    let mut cluster = MASQNodeCluster::start().unwrap();

    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .fake_public_key(&PublicKey::new(&[4, 3, 2, 0]))
            .chain(cluster.chain)
            .build(),
    );
    let real_nodes = (1..neighborhood_size)
        .map(|index| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .fake_public_key(&PublicKey::new(&[4, 3, 2, index as u8]))
                    .chain(cluster.chain)
                    .build(),
            )
        })
        .collect::<Vec<MASQRealNode>>();
    let last_node = real_nodes.last().unwrap();
    let mock_node =
        cluster.start_mock_node_with_public_key(vec![10000], &PublicKey::new(&[1, 2, 3, 4]));
    let dont_count_these = vec![mock_node.main_public_key()];
    // Wait for Gossip to abate
    thread::sleep(Duration::from_millis(2000));

    mock_node.transmit_debut(last_node).unwrap();
    let (gossip, sender) = mock_node.wait_for_gossip(Duration::from_secs(2)).unwrap();
    match parse_gossip(&gossip, sender) {
        GossipType::IntroductionGossip(_) => (),
        _ => panic!("Received unexpected Gossip when expecting Introduction"),
    }
    let standard_gossip = StandardBuilder::new()
        .add_masq_node(&mock_node, 100)
        .half_neighbors(mock_node.main_public_key(), last_node.main_public_key())
        .build();
    mock_node
        .transmit_multinode_gossip(last_node, &standard_gossip)
        .unwrap();
    let (gossip, sender) = mock_node.wait_for_gossip(Duration::from_secs(2)).unwrap();
    let standard_gossip = match parse_gossip(&gossip, sender) {
        GossipType::StandardGossip(standard_gossip) => standard_gossip,
        _ => panic!("Received unexpected Gossip when expecting Standard Gossip"),
    };

    // Neighborhood includes all real nodes plus mock node, but gossip to mock node won't include record for mock node.
    assert_eq!(standard_gossip.len(), neighborhood_size);
    let problems = standard_gossip
        .key_set()
        .into_iter()
        .filter(|key| !dont_count_these.contains(&key))
        .map(|key| standard_gossip.agr(&key).unwrap())
        .filter(|agr| agr.inner.neighbors.len() < 2 || agr.inner.neighbors.len() > 5)
        .map(|agr| (agr.inner.public_key.clone(), agr.inner.neighbors.len()))
        .collect::<Vec<(PublicKey, usize)>>();
    assert!(
        problems.is_empty(),
        "These Nodes had the wrong number of neighbors: {:?}",
        problems
    );
}

#[test]
fn lots_of_stalled_nodes_dont_prevent_acceptance_of_new_node() {
    let root_node = make_node_record(1234, true);
    let mut db = db_from_node(&root_node);
    for idx in 0..MAX_DEGREE as u16 {
        let stalled_node_key = &db.add_node(make_node_record(4000 + idx, true)).unwrap();
        db.add_arbitrary_half_neighbor(root_node.public_key(), stalled_node_key);
    }
    let full_neighbor_key = &db.add_node(make_node_record(2345, true)).unwrap();
    db.add_arbitrary_full_neighbor(root_node.public_key(), full_neighbor_key);
    let mut cluster = MASQNodeCluster::start().unwrap();
    let (_, root_node, _) =
        construct_neighborhood(&mut cluster, db, vec![], do_not_modify_config());
    let new_node =
        cluster.start_mock_node_with_public_key(vec![5050], &PublicKey::new(&[3, 4, 5, 6]));

    new_node.transmit_debut(&root_node).unwrap();

    let (gossip, sender) = new_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();
    match parse_gossip(&gossip, sender) {
        GossipType::IntroductionGossip(introduction) => {
            assert_eq!(introduction.introducer_key(), root_node.main_public_key());
            assert_eq!(introduction.introducee_key(), full_neighbor_key);
        }
        _ => panic!("Received unexpected Gossip when expecting Introduction"),
    }
}
