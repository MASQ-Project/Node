// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate base64;
extern crate hopper_lib;
extern crate multinode_integration_tests_lib;
extern crate neighborhood_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::gossip::GossipNodeRecord;
use neighborhood_lib::neighborhood_database::NodeRecord;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use neighborhood_lib::neighborhood_database::NodeSignatures;
use std::thread;
use std::time::Duration;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::wallet::Wallet;
use test_utils::test_utils::assert_contains;
use sub_lib::accountant;

#[test]
fn when_bootstrapping_from_a_node_then_the_node_sends_gossip_upon_startup() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let server = SubstratumCoresServer::new();
    let bootstrap_node_ref = server.node_reference();

    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node_ref.clone())
            .build(),
    );

    let package = server.wait_for_package(Duration::from_millis(1000));
    let cores_package = package.to_expired(server.cryptde());
    let gossip: Gossip = cores_package.payload().unwrap();
    let node_ref = subject.node_reference();
    let inner = NodeRecordInner {
        public_key: node_ref.public_key.clone(),
        node_addr_opt: Some(node_ref.node_addr.clone()),
        is_bootstrap_node: false,
        earning_wallet: accountant::DEFAULT_EARNING_WALLET.clone(),
        consuming_wallet: Some (accountant::TEMPORARY_CONSUMING_WALLET.clone()),
        neighbors: vec![bootstrap_node_ref.public_key.clone()],
        version: 0,
    };
    let (complete_signature, obscured_signature) = {
        let mut nr = NodeRecord::new(
            &node_ref.public_key,
            Some(&node_ref.node_addr),
            inner.earning_wallet.clone(),
            inner.consuming_wallet.clone(),
            false,
            None,
            0,
        );
        nr.sign(&CryptDENull::from(&node_ref.public_key));
        (
            nr.signatures().unwrap().complete().clone(),
            nr.signatures().unwrap().obscured().clone(),
        )
    };
    assert_contains(
        &gossip.node_records,
        &GossipNodeRecord {
            inner,
            signatures: NodeSignatures::new(complete_signature, obscured_signature),
        },
    );
}

#[test]
fn when_bootstrapping_from_a_standard_node_then_the_gossip_reveals_that_it_is_standard() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_node = cluster.start_mock_node(vec![34685]);
    let bootstrap_node = cluster.start_real_node(NodeStartupConfigBuilder::bootstrap().build());

    let neighbor_node = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(bootstrap_node.node_reference())
            .build(),
    );

    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(neighbor_node.node_reference())
            .build(),
    );

    thread::sleep(Duration::from_millis(1000)); // let the gossip settle down

    mock_node.bootstrap_from(&subject);

    let response_gossip = mock_node
        .wait_for_gossip(Duration::from_millis(1000))
        .expect("did not receive gossip");

    let neighbor_record = response_gossip
        .node_records
        .iter()
        .find(|record| record.public_key() == neighbor_node.public_key())
        .expect("should contain neighbor");

    assert!(!neighbor_record.inner.is_bootstrap_node);
}
