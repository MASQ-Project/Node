// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::multinode_gossip::{
    parse_gossip, GossipType, MultinodeGossip, StandardBuilder,
};
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    NodeStartupConfigBuilder, SubstratumRealNode,
};
use node_lib::sub_lib::cryptde::PublicKey;
use std::thread;
use std::time::Duration;

#[test]
fn graph_connects_but_does_not_over_connect() {
    let neighborhood_size = 5;
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let first_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .fake_public_key(&PublicKey::new(&[4, 3, 2, 0]))
            .build(),
    );
    let real_nodes = (1..neighborhood_size)
        .map(|index| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .fake_public_key(&PublicKey::new(&[4, 3, 2, index as u8]))
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();
    let last_node = real_nodes.last().unwrap();
    let mock_node =
        cluster.start_mock_node_with_public_key(vec![10000], &PublicKey::new(&[1, 2, 3, 4]));
    let dont_count_these = vec![mock_node.public_key()];
    // Wait for Gossip to abate
    thread::sleep(Duration::from_millis(2000));

    mock_node.transmit_debut(last_node).unwrap();
    let (gossip, sender) = mock_node.wait_for_gossip(Duration::from_secs(2)).unwrap();
    match parse_gossip(&gossip, sender) {
        GossipType::IntroductionGossip(_) => (),
        _ => panic!("Received unexpected Gossip when expecting Introduction"),
    }
    let standard_gossip = StandardBuilder::new()
        .add_substratum_node(&mock_node, 100)
        .half_neighbors(mock_node.public_key(), last_node.public_key())
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
