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

use multinode_integration_tests_lib::gossip_builder::GossipBuilder;
use multinode_integration_tests_lib::substratum_node::PortSelector;
use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::NodeStartupConfigBuilder;
use node_lib::json_masquerader::JsonMasquerader;
use std::time::Duration;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;

#[test]
fn neighborhood_notified_of_missing_node_when_connection_refused() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let mock_bootstrap = cluster.start_mock_node(vec![5550]);
    let subject = cluster.start_real_node(
        NodeStartupConfigBuilder::standard()
            .neighbor(mock_bootstrap.node_reference())
            .build(),
    );

    // This gossip is from the real node (subject) bootstrapping
    mock_bootstrap
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();

    let masquerader = JsonMasquerader::new();

    let disappearing_node_name: String;
    let disappearing_node_key = {
        let disappearing_node = cluster.start_real_node(
            NodeStartupConfigBuilder::standard()
                .neighbor(mock_bootstrap.node_reference())
                .build(),
        );
        disappearing_node_name = String::from(disappearing_node.name());
        let key = disappearing_node.public_key();

        // This gossip is from the disappearing node bootstrapping
        mock_bootstrap
            .wait_for_gossip(Duration::from_millis(1000))
            .unwrap();

        let cores_package = GossipBuilder::new()
            .add_node(&mock_bootstrap, true, true)
            .add_node(&subject, false, true)
            .add_node(&disappearing_node, false, true)
            .add_connection(&mock_bootstrap.public_key(), &subject.public_key())
            .add_connection(&mock_bootstrap.public_key(), &key)
            .build_cores_package(&mock_bootstrap.public_key(), &subject.public_key());

        mock_bootstrap
            .transmit_package(
                5550,
                cores_package,
                &masquerader,
                &subject.public_key(),
                subject.socket_addr(PortSelector::First),
            )
            .unwrap();

        // The first of these gossip messages comes in response to the gossip sent to the subject node from the bootstrap (mock) node
        // The second comes from the disappearing node as it introduces itself after learning the IP of the bootstrap node from the subject node
        // The third comes from the subject node after its database is updated due to receiving gossip from the disappearing node
        for _ in 0..3 {
            mock_bootstrap
                .wait_for_gossip(Duration::from_millis(1000))
                .unwrap();
        }

        key
    };

    cluster.stop_node(&disappearing_node_name);

    let cores_package = IncipientCoresPackage::new(
        Route::new(
            vec![RouteSegment::new(
                vec![
                    &mock_bootstrap.public_key(),
                    &subject.public_key(),
                    &disappearing_node_key,
                ],
                Component::ProxyClient,
            )],
            mock_bootstrap.cryptde(),
        )
        .unwrap(),
        String::from("Meaningless payload"),
        &disappearing_node_key,
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

    let gossip = mock_bootstrap
        .wait_for_gossip(Duration::from_millis(180000))
        .unwrap();
    let subject_record = gossip
        .node_records
        .iter()
        .find(|&x| x.inner.public_key == subject.public_key())
        .expect("should have the subject node record");

    assert!(!subject_record
        .inner
        .neighbors
        .contains(&disappearing_node_key));
}
