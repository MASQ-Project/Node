// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate multinode_integration_tests_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate hopper_lib;
extern crate neighborhood_lib;
extern crate base64;
extern crate test_utils;

use multinode_integration_tests_lib::substratum_cores_server::SubstratumCoresServer;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use std::time::Duration;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::gossip::GossipNodeRecord;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use neighborhood_lib::neighborhood_database::NodeRecord;
use sub_lib::cryptde_null::CryptDENull;
use neighborhood_lib::neighborhood_database::NodeSignatures;
use test_utils::test_utils::assert_contains;

#[test]
fn when_bootstrapping_from_a_node_then_the_node_sends_gossip_upon_startup () {
    let mut cluster = SubstratumNodeCluster::start ().unwrap ();
    let server = SubstratumCoresServer::new ();
    let bootstrap_node_ref = server.node_reference ();

    let subject = cluster.start_real_node(NodeStartupConfigBuilder::standard ()
        .bootstrap_from (bootstrap_node_ref.clone ())
        .build ()
    );

    let package = server.wait_for_package(Duration::from_millis (1000));
    let cores_package = package.to_expired (server.cryptde());
    let gossip: Gossip = cores_package.payload ().unwrap ();
    let node_ref = subject.node_reference();
    let inner = NodeRecordInner {
        public_key: node_ref.public_key.clone (),
        node_addr_opt: Some (node_ref.node_addr.clone ()),
        is_bootstrap_node: false,
        neighbors: vec! (bootstrap_node_ref.public_key.clone ()),
    };
    let (complete_signature, obscured_signature) = {
        let mut nr = NodeRecord::new(&node_ref.public_key, Some(&node_ref.node_addr), false, None);
        nr.sign(&CryptDENull::from(&node_ref.public_key));
        (nr.signatures().unwrap().complete().clone(), nr.signatures().unwrap().obscured().clone())
    };
    assert_contains (&gossip.node_records, &GossipNodeRecord {
        inner,
        signatures: NodeSignatures::new(complete_signature, obscured_signature),
    });
}
