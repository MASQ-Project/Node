// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node::MASQNodeUtils;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::masq_real_node::{
    ConsumingWalletInfo, NodeStartupConfigBuilder,
};
use regex::escape;
use std::time::Duration;

#[test]
fn debtors_are_credited_once_but_not_twice() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    // Create and initialize mock blockchain client: prepare a receivable at block 2000
    // Start a real Node pointing at the mock blockchain client with a start block of 1000
    // Get the config DAO
    // Get the receivable DAO
    // Create a receivable record to match the client receivable
    // Wait for a scan log
    // Kill the real Node
    // Use the receivable DAO to verify that the receivable's balance has been adjusted
    // Use the config DAO to verify that the start block has been advanced to 2001
    todo!("Complete me");
}

#[test]
fn blockchain_bridge_logs_when_started() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let private_key = "0011223300112233001122330011223300112233001122330011223300112233";
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::zero_hop()
            .consuming_wallet_info(ConsumingWalletInfo::PrivateKey(private_key.to_string()))
            .chain(cluster.chain)
            .build(),
    );

    let escaped_pattern = escape(&format!(
        "DEBUG: BlockchainBridge: Received BindMessage; consuming wallet address {}",
        subject.consuming_wallet().unwrap()
    ));
    MASQNodeUtils::wrote_log_containing(
        subject.name(),
        &escaped_pattern,
        Duration::from_millis(1000),
    )
}
