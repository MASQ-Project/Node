// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate base64;
extern crate hopper_lib;
extern crate multinode_integration_tests_lib;
extern crate neighborhood_lib;
extern crate node_lib;
extern crate regex;
extern crate serde_cbor;
extern crate sub_lib;
extern crate test_utils;

use multinode_integration_tests_lib::gossip_builder::GossipBuilder;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use node_lib::json_masquerader::JsonMasquerader;
use std::time::Duration;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;

#[test]
fn neighborhood_notified_of_missing_node_when_connection_refused() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_bootstrap = cluster.start_mock_node(vec![5550]);
    let refusing_node = cluster.start_mock_node(vec![5551]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .bootstrap_from(mock_bootstrap.node_reference())
            .build(),
    );
    let _bootstrap_gossip_package = mock_bootstrap
        .wait_for_package(&JsonMasquerader::new(), Duration::from_millis(1000))
        .unwrap();
    let refusing_node_key = refusing_node.public_key();

    let cores_package = GossipBuilder::new()
        .add_node(&mock_bootstrap, true, true)
        .add_node(&subject, true, true)
        .add_fictional_node(NodeRecordInner {
            public_key: refusing_node_key.clone(),
            node_addr_opt: Some(NodeAddr::new(&refusing_node.ip_address(), &vec![1234])),
            is_bootstrap_node: false,
            neighbors: vec![],
        })
        .add_connection(&mock_bootstrap.public_key(), &subject.public_key())
        .add_connection(&subject.public_key(), &refusing_node_key)
        .build_cores_package(&mock_bootstrap.public_key(), &subject.public_key());

    let masquerader = JsonMasquerader::new();
    mock_bootstrap
        .transmit_package(
            5550,
            cores_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    let cores_package = IncipientCoresPackage::new(
        Route::new(
            vec![RouteSegment::new(
                vec![
                    &mock_bootstrap.public_key(),
                    &subject.public_key(),
                    &refusing_node_key,
                ],
                Component::ProxyClient,
            )],
            mock_bootstrap.cryptde(),
        )
        .unwrap(),
        String::from("Meaningless payload"),
        &refusing_node_key,
    );
    mock_bootstrap
        .transmit_package(
            5550,
            cores_package,
            &masquerader,
            &subject.public_key(),
            subject.socket_addr(PortSelector::First),
        )
        .unwrap();

    let _rebroadcast_bootstrap_gossip_package =
        mock_bootstrap.wait_for_package(&JsonMasquerader::new(), Duration::from_millis(1000));

    let (_, _, new_neighborhood_gossip_package) = mock_bootstrap
        .wait_for_package(&JsonMasquerader::new(), Duration::from_millis(1000))
        .unwrap();
    let cores_package = new_neighborhood_gossip_package.to_expired(mock_bootstrap.cryptde());
    let gossip: Gossip = cores_package.payload().unwrap();
    let subject_record = gossip
        .node_records
        .iter()
        .find(|&x| x.inner.public_key == subject.public_key())
        .expect("should have the subject node record");

    assert!(!subject_record
        .inner
        .neighbors
        .contains(&refusing_node.public_key()));
}
