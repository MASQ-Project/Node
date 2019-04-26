// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use core::convert::TryInto;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::neighborhood::neighborhood::AccessibleGossipRecord;
use node_lib::test_utils::test_utils::find_free_port;
use std::time::Duration;

#[test]
#[ignore] // Should be removed by SC-811
fn neighborhood_notified_of_newly_missing_node() {
    // Set up three-Node network, and add a mock witness Node.
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let originating_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap.node_reference())
            .build(),
    );
    let _staying_up_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap.node_reference())
            .build(),
    );
    let disappearing_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap.node_reference())
            .build(),
    );
    let witness_node = cluster.start_mock_node(vec![find_free_port()]);
    witness_node.send_debut(&originating_node);
    let (introductions, _) = witness_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();
    assert!(
        introductions.node_records.len() > 1,
        "Should have been introductions, but wasn't: {}",
        introductions.to_dot_graph(
            (
                originating_node.public_key(),
                &Some(originating_node.node_addr())
            ),
            (witness_node.public_key(), &Some(witness_node.node_addr()))
        )
    );

    // Kill one of the Nodes--not the originating Node and not the witness Node.
    cluster.stop_node(disappearing_node.name());

    //Establish a client on the originating Node and send some ill-fated traffic.
    let mut client = originating_node.make_client(80);
    client.send_chunk(Vec::from(
        "GET http://example.com HTTP/1.1\r\n\r\n".as_bytes(),
    ));

    // Now direct the witness Node to wait for Gossip about the disappeared Node.
    let (disappearance_gossip, _) = witness_node
        .wait_for_gossip(Duration::from_secs(130))
        .unwrap();

    let dot_graph = disappearance_gossip.to_dot_graph(
        (
            originating_node.public_key(),
            &Some(originating_node.node_addr()),
        ),
        (witness_node.public_key(), &Some(witness_node.node_addr())),
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
        .find(|agr| &agr.inner.public_key == originating_node.public_key())
        .unwrap();
    assert!(
        !originating_node_agr
            .inner
            .neighbors
            .contains(&disappearing_node.public_key()),
        "Originating Node {} should not be connected to the disappeared Node {}, but is: {}",
        originating_node.public_key(),
        disappearing_node.public_key(),
        dot_graph
    );
}
