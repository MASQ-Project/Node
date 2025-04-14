// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use multinode_integration_tests_lib::masq_node::MASQNode;
use multinode_integration_tests_lib::masq_node_cluster::MASQNodeCluster;
use multinode_integration_tests_lib::multinode_gossip::GossipType;
use multinode_integration_tests_lib::multinode_gossip::{
    parse_gossip, MultinodeGossip, SingleNode, Standard,
};
use multinode_integration_tests_lib::neighborhood_constructor::{
    construct_neighborhood, do_not_modify_config,
};
use node_lib::neighborhood::gossip::AccessibleGossipRecord;
use node_lib::neighborhood::gossip::GossipBuilder;
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::NodeRecord;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::neighborhood::GossipFailure_0v1;
use node_lib::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
use node_lib::test_utils::vec_to_set;
use std::convert::TryInto;
use std::time::Duration;

#[test]
fn debut_target_does_not_introduce_known_neighbors() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let one_common_neighbor = make_node_record(1234, true);
    let another_common_neighbor = make_node_record(2435, true);
    let dest_db = {
        let subject_node_record = make_node_record(3456, true);
        let mut dest_db = db_from_node(&make_node_record(3456, true));
        dest_db.add_node(one_common_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            subject_node_record.public_key(),
            one_common_neighbor.public_key(),
        );
        dest_db.add_node(another_common_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            subject_node_record.public_key(),
            another_common_neighbor.public_key(),
        );
        dest_db
    };
    let debuter_mock_node =
        cluster.start_mock_node_with_public_key(vec![10000], &PublicKey::new(&[4, 5, 6, 7]));
    let debuter_node_record = NodeRecord::from(&debuter_mock_node);
    let mut src_db = db_from_node(&debuter_node_record);
    src_db.add_node(one_common_neighbor.clone()).unwrap();
    src_db.add_arbitrary_full_neighbor(
        debuter_node_record.public_key(),
        one_common_neighbor.public_key(),
    );
    src_db.add_node(another_common_neighbor.clone()).unwrap();
    src_db.add_arbitrary_full_neighbor(
        debuter_node_record.public_key(),
        another_common_neighbor.public_key(),
    );
    let (_, subject_real_node, _) =
        construct_neighborhood(&mut cluster, dest_db, vec![], do_not_modify_config());
    let debut_gossip = SingleNode::from(
        GossipBuilder::new(&src_db)
            .node(debuter_mock_node.main_public_key(), true)
            .build(),
    );

    debuter_mock_node
        .transmit_multinode_gossip(&subject_real_node, &debut_gossip)
        .unwrap();
    let (result, _) = debuter_mock_node
        .wait_for_gossip(Duration::from_secs(2))
        .unwrap();

    let agrs: Vec<AccessibleGossipRecord> = result.try_into().unwrap();

    let standard_gossip = Standard::from(&agrs);
    assert_eq!(
        standard_gossip.key_set(),
        vec_to_set(vec![
            subject_real_node.main_public_key().clone(),
            one_common_neighbor.public_key().clone(),
            another_common_neighbor.public_key().clone(),
        ])
    );
}

#[test]
fn debut_target_does_not_pass_to_known_neighbors() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let common_neighbors = (0..5)
        .into_iter()
        .map(|index| make_node_record(1111 + index, true))
        .collect::<Vec<NodeRecord>>();
    let dest_db = {
        let subject_node_record = make_node_record(3456, true);
        let mut dest_db = db_from_node(&make_node_record(3456, true));
        common_neighbors.iter().for_each(|node| {
            dest_db.add_node(node.clone()).unwrap();
            dest_db
                .add_arbitrary_full_neighbor(subject_node_record.public_key(), node.public_key());
        });
        dest_db
    };
    let debuter_mock_node =
        cluster.start_mock_node_with_public_key(vec![10000], &PublicKey::new(&[1, 2, 3, 4]));
    let debuter_node_record = NodeRecord::from(&debuter_mock_node);
    let mut src_db = db_from_node(&debuter_node_record);
    common_neighbors.iter().for_each(|node| {
        src_db.add_node(node.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(debuter_node_record.public_key(), node.public_key());
    });
    let (_, subject_real_node, _) =
        construct_neighborhood(&mut cluster, dest_db, vec![], do_not_modify_config());
    let debut_gossip = SingleNode::from(
        GossipBuilder::new(&src_db)
            .node(debuter_mock_node.main_public_key(), true)
            .build(),
    );

    debuter_mock_node
        .transmit_multinode_gossip(&subject_real_node, &debut_gossip)
        .unwrap();
    let result = debuter_mock_node.wait_for_gossip_failure(Duration::from_secs(2));

    assert_eq!(result.unwrap().0, GossipFailure_0v1::NoSuitableNeighbors);
}

#[test]
fn node_remembers_its_neighbors_across_a_bounce() {
    let mut cluster = MASQNodeCluster::start().unwrap();
    let dest_db = {
        let originating_node = make_node_record(1234, true);
        let mut dest_db: NeighborhoodDatabase = db_from_node(&originating_node);
        let relay1 = &dest_db.add_node(make_node_record(2345, true)).unwrap();
        let relay2 = &dest_db.add_node(make_node_record(3456, false)).unwrap();
        let exit_node = &dest_db.add_node(make_node_record(4567, false)).unwrap();
        dest_db.add_arbitrary_full_neighbor(originating_node.public_key(), relay1);
        dest_db.add_arbitrary_full_neighbor(relay1, relay2);
        dest_db.add_arbitrary_full_neighbor(relay2, exit_node);
        dest_db
    };
    let (_, originating_node, _) =
        construct_neighborhood(&mut cluster, dest_db, vec![], do_not_modify_config());
    let relay1 = cluster.get_mock_node_by_name("mock_node_2").unwrap();

    originating_node.kill_node();

    let mut config = originating_node.get_startup_config();
    config.neighbors = vec![];
    originating_node.restart_node(config);
    let (gossip, ip_addr) = relay1.wait_for_gossip(Duration::from_millis(5000)).unwrap();
    match parse_gossip(&gossip, ip_addr) {
        GossipType::DebutGossip(_) => (),
        gt => panic!("Expected GossipType::Debut, but found {:?}", gt),
    }
}
