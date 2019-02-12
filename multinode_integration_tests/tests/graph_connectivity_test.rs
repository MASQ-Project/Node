// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[test]
fn graph_connects_but_does_not_over_connect() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());
    let mock_node = cluster.start_mock_node(vec![34685]);

    for _ in 0..5 {
        cluster.start_real_node(
            NodeStartupConfigBuilder::standard()
                .neighbor(bootstrap_node.node_reference())
                .build(),
        );
    }

    thread::sleep(Duration::from_millis(1000));

    mock_node.bootstrap_from(&bootstrap_node);

    let response_gossip = mock_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();

    assert_eq!(response_gossip.node_records.len(), 7);

    // count the number of connections each node has and store how many nodes have that number of connections
    let mut counts: HashMap<usize, u32> = HashMap::new();
    for node_record in response_gossip.node_records {
        let i = node_record.inner.neighbors.len();
        *counts.entry(i).or_insert(0) += 1;
    }

    assert_eq!(counts.len(), 4);
    assert_eq!(counts[&0], 1); // the mock node will not have any connections because it didn't create any
    assert_eq!(counts[&4], 2); // 2 nodes will have 4 connections
    assert_eq!(counts[&5], 3); // 3 nodes will have 5 connections
    assert_eq!(counts[&6], 1); // the bootstrap node will have 6 connections
}
