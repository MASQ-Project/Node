// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::gossip_builder::GossipBuilder;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node::SubstratumNodeUtils;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::sub_lib::wallet::Wallet;
use std::time::Duration;

#[test]
fn accountant_notified_of_accruing_debt_for_requested_exit_service() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_bootstrap = cluster.start_mock_node(vec![5550]);
    let mock_standard = cluster.start_mock_node(vec![5551]);
    let mock_other = cluster.start_mock_node(vec![5552]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .earning_wallet(Wallet::new("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
            .neighbor(mock_bootstrap.node_reference())
            .build(),
    );

    // This gossip is from the real node (subject) bootstrapping
    mock_bootstrap
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();

    let cores_package = GossipBuilder::new(Some(subject.earning_wallet()))
        .add_node(&mock_bootstrap, true, true)
        .add_node(&subject, false, true)
        .add_node(&mock_standard, false, true)
        .add_node(&mock_other, false, true)
        .add_connection(&mock_bootstrap.public_key(), &subject.public_key())
        .add_connection(&mock_bootstrap.public_key(), &mock_standard.public_key())
        .add_connection(&mock_standard.public_key(), &subject.public_key())
        .add_connection(&subject.public_key(), &mock_standard.public_key())
        .add_connection(&mock_standard.public_key(), &mock_other.public_key())
        .add_connection(&mock_other.public_key(), &mock_standard.public_key())
        .build_cores_package(&mock_bootstrap.public_key(), &subject.public_key());

    let masquerader = JsonMasquerader::new();
    mock_bootstrap
        .transmit_package(
            5551,
            cores_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    mock_other
        .wait_for_package(&masquerader, Duration::from_millis(1000))
        .unwrap();

    let mut client = subject.make_client(80);
    client.send_chunk(Vec::from(
        &b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"[..],
    ));

    SubstratumNodeUtils::wrote_log_containing(
        subject.name(),
        r"Accruing debt to wallet mock_node_\d_earning for consuming exit service 41 bytes",
        Duration::from_millis(1000),
    )
}
