// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node::SubstratumNodeUtils;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use std::time::Duration;

#[test]
fn blockchain_bridge_logs_when_started() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let private_key = "0011223300112233001122330011223300112233001122330011223300112233";
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .consuming_private_key(private_key)
            .build(),
    );

    SubstratumNodeUtils::wrote_log_containing(
        subject.name(),
        format! ("DEBUG: BlockchainBridge: Received BindMessage; consuming private key that hashes to {}", sha1_hash(private_key.as_bytes())).as_str(),
        Duration::from_millis(1000),
    )
}

fn sha1_hash(data: &[u8]) -> String {
    let mut hash = sha1::Sha1::new();
    hash.update(data);
    hash.digest().to_string()
}
