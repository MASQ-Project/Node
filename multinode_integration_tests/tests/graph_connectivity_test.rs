// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use core::convert::TryInto;
use multinode_integration_tests_lib::substratum_node::{SubstratumNode, SubstratumNodeUtils};
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    NodeStartupConfigBuilder, SubstratumRealNode,
};
use node_lib::neighborhood::gossip::{Gossip, GossipNodeRecord};
use node_lib::neighborhood::neighborhood::AccessibleGossipRecord;
use node_lib::neighborhood::node_record::NodeRecordInner;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::sub_lib::wallet::Wallet;
use node_lib::test_utils::test_utils::{find_free_port, vec_to_btset};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

#[test]
fn graph_connects_but_does_not_over_connect() {
    let neighborhood_size = 5;
    let mut cluster = SubstratumNodeCluster::start().unwrap();

    let first_node = cluster.start_real_node(NodeStartupConfigBuilder::standard().build());
    let real_nodes = (1..neighborhood_size)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();
    let mock_node = cluster.start_mock_node(vec![find_free_port()]);
    let dont_count_these = vec![mock_node.public_key()];
    // Wait for Gossip to abate
    thread::sleep(Duration::from_millis(2000));

    // Start the bootstrap process; follow passes until Introductions arrive
    mock_node.send_debut(&first_node);
    let mut retries_left = neighborhood_size;
    let mut introductions_opt: Option<Vec<AccessibleGossipRecord>> = None;
    while retries_left > 0 {
        let (intros, _) = match mock_node.wait_for_gossip(Duration::from_millis(1000)) {
            Some(pair) => pair,
            None => {
                println!("{}", SubstratumNodeUtils::retrieve_logs("test_node_2"));
                panic!("Received no Gossip after a second")
            }
        };
        let agrs: Vec<AccessibleGossipRecord> = intros.clone().try_into().unwrap();
        if intros.node_records.len() > 1 {
            introductions_opt = Some(agrs);
            break;
        }
        let pass_target = real_nodes
            .iter()
            .find(|n| n.public_key() == &agrs[0].inner.public_key)
            .unwrap();
        mock_node.send_debut(pass_target);
        retries_left -= 1;
    }
    let introductions = introductions_opt.unwrap();

    // Compose and send a standard Gossip message that will stimulate a general Gossip broadcast
    let another_agr = introductions
        .iter()
        .find(|agr| &agr.inner.public_key != mock_node.public_key())
        .unwrap();
    let mock_inner = NodeRecordInner {
        public_key: mock_node.public_key().clone(),
        earning_wallet: Wallet::new("0000"),
        rate_pack: DEFAULT_RATE_PACK.clone(),
        is_bootstrap_node: false,
        neighbors: vec_to_btset(vec![first_node.public_key().clone()]),
        version: 100, // to make the sample Node update its database and send out standard Gossip
    };
    let standard_gossip = Gossip {
        node_records: vec![
            GossipNodeRecord::from((
                mock_inner.clone(),
                Some(mock_node.node_addr()),
                mock_node.cryptde(),
            )),
            GossipNodeRecord::from(another_agr.clone()),
        ],
    };
    let socket_addrs: Vec<SocketAddr> = first_node.node_addr().into();
    mock_node
        .transmit_gossip(
            mock_node.port_list()[0],
            standard_gossip,
            &first_node.public_key(),
            socket_addrs[0],
        )
        .unwrap();

    // Snag the broadcast and assert on it: everything that isn't test harness or bootstrap Node
    // should have degree at least 2 and no more than 5.
    let (current_state, _) = mock_node
        .wait_for_gossip(Duration::from_millis(1000))
        .unwrap();
    let dot_graph = current_state.to_dot_graph(
        another_agr,
        (&mock_inner.public_key, &Some(mock_node.node_addr())),
    );
    // True number of Nodes in source database should be neighborhood_size + 2,
    // but gossip target (mock_node) will not be included in Gossip so should be neighborhood size + 1 (bootstrap).
    assert_eq!(
        neighborhood_size,
        current_state.node_records.len(),
        "Current-state Gossip should have {} GossipNodeRecords, but has {}: {}",
        neighborhood_size,
        current_state.node_records.len(),
        dot_graph
    );
    let current_state_agrs: Vec<AccessibleGossipRecord> = current_state.try_into().unwrap();
    let key_degrees = current_state_agrs
        .iter()
        .filter(|agr| !dont_count_these.contains(&&agr.inner.public_key))
        .map(|agr| {
            (
                agr.inner.public_key.clone(),
                degree(
                    &current_state_agrs,
                    &agr.inner.public_key,
                    &dont_count_these,
                ),
            )
        })
        .filter(|pair| (pair.1 < 2 || pair.1 > 5))
        .collect::<Vec<(PublicKey, usize)>>();
    assert!(
        key_degrees.is_empty(),
        "These Nodes had the wrong number of neighbors: {:?}\n{}",
        key_degrees,
        dot_graph
    );
}

fn degree(
    agrs: &Vec<AccessibleGossipRecord>,
    key: &PublicKey,
    dont_count_these: &Vec<&PublicKey>,
) -> usize {
    record_of(agrs, key)
        .unwrap()
        .inner
        .neighbors
        .iter()
        .filter(|k| !dont_count_these.contains(k))
        .count()
}

fn record_of<'a>(
    agrs: &'a Vec<AccessibleGossipRecord>,
    key: &PublicKey,
) -> Option<&'a AccessibleGossipRecord> {
    agrs.iter().find(|n| &n.inner.public_key == key)
}
