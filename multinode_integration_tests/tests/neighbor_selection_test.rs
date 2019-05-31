// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::multinode_gossip::{
    parse_gossip, GossipType, MultinodeGossip, SingleNode,
};
use multinode_integration_tests_lib::substratum_mock_node::SubstratumMockNode;
use multinode_integration_tests_lib::substratum_node::{NodeReference, SubstratumNode};
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde_null::CryptDENull;
use std::time::Duration;

#[test]
#[ignore]
fn debut_target_does_not_introduce_known_neighbors() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let common_neighbor = cluster.start_mock_node(vec![10000]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(common_neighbor.node_reference())
            .build(),
    );
    let (gossip, ip_addr) = common_neighbor
        .wait_for_gossip(Duration::from_secs(2))
        .unwrap();
    match parse_gossip(&gossip, ip_addr) {
        GossipType::DebutGossip(_) => (),
        _ => panic!(
            "Unexpected Gossip: {}",
            gossip.to_dot_graph(
                ip_addr,
                (
                    common_neighbor.public_key(),
                    &Some(common_neighbor.node_addr())
                )
            )
        ),
    }
    common_neighbor.transmit_debut(&subject).unwrap();
    let debuter = cluster.start_mock_node(vec![10000]);
    let mut debut = SingleNode::new(&debuter);
    debut
        .agr_mut(debuter.public_key())
        .unwrap()
        .inner
        .neighbors
        .insert(common_neighbor.public_key().clone());
    debut
        .agr_mut(debuter.public_key())
        .unwrap()
        .regenerate_signed_gossip(&CryptDENull::from(debuter.public_key()));

    debuter.transmit_multinode_gossip(&subject, &debut).unwrap();

    match debuter.wait_for_gossip(Duration::from_secs(2)) {
        Some(_) => panic!("Subject sent response Gossip when it should have been silent"),
        None => (), // No Gossip for two seconds: test passes
    }
}

#[test]
#[ignore]
fn debut_target_does_not_pass_to_known_neighbors() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let common_neighbors = (0..5)
        .into_iter()
        .map(|_| cluster.start_mock_node(vec![10000]))
        .collect::<Vec<SubstratumMockNode>>();
    let common_node_references = common_neighbors
        .iter()
        .map(|n| n.node_reference())
        .collect::<Vec<NodeReference>>();
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbors(common_node_references.clone())
            .build(),
    );
    common_neighbors.iter().for_each(|n| {
        n.wait_for_gossip(Duration::from_secs(2)).unwrap();
        n.transmit_debut(&subject).unwrap();
    });
    let debuter = cluster.start_mock_node(vec![10000]);
    let mut debut = SingleNode::new(&debuter);
    debut
        .agr_mut(debuter.public_key())
        .unwrap()
        .inner
        .neighbors
        .extend(
            common_node_references
                .into_iter()
                .map(|node_ref| node_ref.public_key)
                .collect::<Vec<PublicKey>>(),
        );
    debut
        .agr_mut(debuter.public_key())
        .unwrap()
        .regenerate_signed_gossip(&CryptDENull::from(debuter.public_key()));

    debuter.transmit_multinode_gossip(&subject, &debut).unwrap();

    match debuter.wait_for_gossip(Duration::from_secs(2)) {
        Some(_) => panic!("Subject sent response Gossip when it should have been silent"),
        None => (), // No Gossip for two seconds: test passes
    }
}
