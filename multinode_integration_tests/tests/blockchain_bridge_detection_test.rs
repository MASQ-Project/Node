// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node::SubstratumNodeUtils;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use std::time::Duration;

#[test]
fn blockchain_bridge_logs_when_started() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let subject = cluster.start_real_node(NodeStartupConfigBuilder::zero_hop().build());

    SubstratumNodeUtils::wrote_log_containing(
        subject.name(),
        r"DEBUG: BlockchainBridge: Received BindMessage",
        Duration::from_millis(1000),
    )
}
