// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node::SubstratumNodeUtils;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    ConsumingWalletInfo, NodeStartupConfigBuilder,
};
use regex::escape;
use std::time::Duration;

#[test]
fn blockchain_bridge_logs_when_started() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let private_key = "0011223300112233001122330011223300112233001122330011223300112233";
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(private_key.to_string()))
            .build(),
    );

    let escaped_pattern = escape(&format!(
        "DEBUG: BlockchainBridge: Received BindMessage; consuming wallet address {}",
        subject.consuming_wallet().unwrap()
    ));
    SubstratumNodeUtils::wrote_log_containing(
        subject.name(),
        &escaped_pattern,
        Duration::from_millis(1000),
    )
}
