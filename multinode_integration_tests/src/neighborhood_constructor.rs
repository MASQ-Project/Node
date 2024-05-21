// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::masq_mock_node::MASQMockNode;
use crate::masq_node::MASQNode;
use crate::masq_node_cluster::MASQNodeCluster;
use crate::masq_real_node::{make_consuming_wallet_info, NodeStartupConfigBuilder};
use crate::masq_real_node::{MASQRealNode, NodeStartupConfig};
use crate::multinode_gossip::{Standard, StandardBuilder};
use node_lib::neighborhood::gossip::Gossip_0v1;
use node_lib::neighborhood::gossip_producer::{GossipProducer, GossipProducerReal};
use node_lib::neighborhood::neighborhood_database::NeighborhoodDatabase;
use node_lib::neighborhood::node_record::{NodeRecord, NodeRecordMetadata};
use node_lib::neighborhood::AccessibleGossipRecord;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::utils::time_t_timestamp;
use node_lib::test_utils::neighborhood_test_utils::db_from_node;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::time::Duration;

/// Construct a neighborhood for testing that corresponds to a provided NeighborhoodDatabase, with a MASQRealNode
/// corresponding to the root of the database, MASQMockNodes corresponding to all the root's immediate neighbors,
/// and MASQMockNodes or fictional Nodes corresponding to all other Nodes in the provided database.
///
/// The result of this function is a single MASQRealNode and a series of MASQMockNodes, where the real Node
/// will contain a database corresponding in structure precisely to the one provided (as long as the one provided
/// doesn't contain fundamental problems, such as Nodes with degree six or greater, or half-neighbor relationships).
/// The mock and real Nodes provided will have the same public keys as the NodeRecords in the provided database, but
/// different NodeAddrs.
///
/// Of course, all the MASQNodes produced by this function will use CryptDENull, so any other MASQNodes
/// that are intended to communicate with them must use CryptDENull as well.
///
/// # Arguments
///
/// * `cluster` - A mutable reference to the MASQNodeCluster that should be used to create MASQRealNodes and MASQMockNodes.
/// * `model_db` - The database describing the structure that should be imposed on the
///                     MASQRealNode's internal database. This database is consumed by this call.
/// * `additional_keys_to_mock` - If this collection is empty, MASQMockNodes will only be created to correspond to
///                                 immediate neighbors of `model_db.root()`. If you want MASQMockNodes corresponding
///                                 to other Nodes in `model_db` to be created, put their public keys here.
///
/// # Returns
///
/// * `NeighborhoodDatabase` - A NeighborhoodDatabase with the same structure as `model_db`, but with public keys
///                             and NodeAddrs and neighbors and versions changed where appropriate to approximate as
///                             closely as possible the database that the MASQRealNode will have internally when
///                             `construct_neighborhood()` returns.
/// * `MASQRealNode` - The real Node corresponding to the NodeRecord at `model_db.root()`. It will have the same
///                             public key as the original `model_db.root()`, but a different NodeAddr.
/// * `HashMap<PublicKey, MASQMockNode>` The mock Nodes corresponding to other NodeRecords in `model_db`. They
///                                             will have the same public keys as the `model_db` NodeRecords they
///                                             represent, but different NodeAddrs.
pub fn construct_neighborhood<F>(
    cluster: &mut MASQNodeCluster,
    model_db: NeighborhoodDatabase,
    additional_keys_to_mock: Vec<&PublicKey>,
    modify_config: F,
) -> (
    NeighborhoodDatabase,
    MASQRealNode,
    HashMap<PublicKey, MASQMockNode>,
)
where
    F: FnOnce(NodeStartupConfigBuilder) -> NodeStartupConfig,
{
    let config_builder = NodeStartupConfigBuilder::standard()
        .fake_public_key(model_db.root().public_key())
        .consuming_wallet_info(make_consuming_wallet_info(
            model_db.root().public_key().to_string().as_str(),
        ))
        .rate_pack(model_db.root().inner.rate_pack)
        .chain(cluster.chain);
    let config = modify_config(config_builder);
    let real_node = cluster.start_real_node(config);
    let (mock_node_map, adjacent_mock_node_keys) =
        make_mock_node_map(cluster, &model_db, &real_node, additional_keys_to_mock);
    let modified_nodes = make_modified_node_records(model_db, &mock_node_map);
    let modified_db = make_modified_db(&real_node, &modified_nodes);
    let gossip_source_mock_node = mock_node_map
        .get(adjacent_mock_node_keys.first().unwrap())
        .unwrap();
    make_and_send_final_setup_gossip(gossip_source_mock_node, &modified_nodes, &real_node);
    absorb_final_setup_responses(&adjacent_mock_node_keys, &mock_node_map);
    (modified_db, real_node, mock_node_map)
}

pub fn do_not_modify_config() -> impl FnOnce(NodeStartupConfigBuilder) -> NodeStartupConfig {
    |builder: NodeStartupConfigBuilder| builder.build()
}

fn make_mock_node_map(
    cluster: &mut MASQNodeCluster,
    model_db: &NeighborhoodDatabase,
    real_node: &MASQRealNode,
    additional_keys_to_mock: Vec<&PublicKey>,
) -> (HashMap<PublicKey, MASQMockNode>, Vec<PublicKey>) {
    let adjacent_mock_nodes = form_mock_node_skeleton(cluster, model_db, real_node);
    let adjacent_mock_node_keys = adjacent_mock_nodes
        .iter()
        .map(|node| node.main_public_key().clone())
        .collect::<Vec<PublicKey>>();
    let mut mock_node_map = adjacent_mock_nodes
        .into_iter()
        .map(|node| (node.main_public_key().clone(), node))
        .collect::<HashMap<PublicKey, MASQMockNode>>();
    additional_keys_to_mock.iter().for_each(|key| {
        let mock_node = cluster.start_mock_node_with_public_key(vec![10000], key);
        let mock_node_key = mock_node.main_public_key().clone();
        mock_node_map.insert(mock_node_key, mock_node);
    });
    (mock_node_map, adjacent_mock_node_keys)
}

fn make_modified_node_records(
    model_db: NeighborhoodDatabase,
    mock_node_map: &HashMap<PublicKey, MASQMockNode>,
) -> Vec<NodeRecord> {
    model_db
        .keys()
        .iter()
        .map(|key| {
            let model_node = model_db.node_by_key(key).unwrap();
            let mut modified_node = model_node.clone();
            modify_node(&mut modified_node, model_node, mock_node_map);
            modified_node
        })
        .collect()
}

fn make_modified_db(
    real_node: &MASQRealNode,
    modified_nodes: &[NodeRecord],
) -> NeighborhoodDatabase {
    let mut modified_db = local_db_from_node(&NodeRecord::from(real_node));
    modified_db.root_mut().set_version(2);
    modified_nodes
        .iter()
        .filter(|node| node.public_key() != real_node.main_public_key())
        .for_each(|node| {
            let mut cloned_node = node.clone();
            cloned_node.set_version(2);
            cloned_node.resign();
            modified_db.add_node(cloned_node).unwrap();
        });
    modified_db
}

fn make_and_send_final_setup_gossip(
    gossip_source_mock_node: &MASQMockNode,
    modified_nodes: &[NodeRecord],
    real_node: &MASQRealNode,
) {
    let gossip_source_key = gossip_source_mock_node.main_public_key().clone();
    let gossip_source_node = modified_nodes
        .iter()
        .find(|node| node.public_key() == &gossip_source_key)
        .unwrap();
    let mut gossip_db = local_db_from_node(gossip_source_node);
    modified_nodes
        .iter()
        .filter(|node| node.public_key() != &gossip_source_key)
        .for_each(|node| {
            let mut cloned_node = node.clone();
            cloned_node.set_version(2);
            cloned_node.resign();
            gossip_db.add_node(cloned_node).unwrap();
        });
    let gossip: Gossip_0v1 = GossipProducerReal::new()
        .produce(&mut gossip_db, real_node.main_public_key())
        .unwrap();
    gossip_source_mock_node
        .transmit_multinode_gossip(real_node, &Standard::from(&gossip.try_into().unwrap()))
        .unwrap();
}

fn absorb_final_setup_responses(
    adjacent_mock_node_keys: &[PublicKey],
    mock_node_map: &HashMap<PublicKey, MASQMockNode>,
) {
    adjacent_mock_node_keys.iter().for_each(|mock_node_key| {
        let mock_node = mock_node_map.get(mock_node_key).unwrap();
        mock_node.wait_for_gossip(Duration::from_secs(2)).unwrap();
    });
}

fn form_mock_node_skeleton(
    cluster: &mut MASQNodeCluster,
    model_db: &NeighborhoodDatabase,
    real_node: &MASQRealNode,
) -> Vec<MASQMockNode> {
    model_db
        .root()
        .full_neighbor_keys(model_db)
        .into_iter()
        .map(|model_node_key| {
            let mut configurable_node =
                cluster.start_mutable_mock_node_with_public_key(vec![10000], model_node_key);
            configurable_node.absorb_configuration(model_db.node_by_key(model_node_key).unwrap());
            let node = cluster.finalize_and_add(configurable_node);
            node.transmit_debut(real_node).unwrap();
            node.wait_for_gossip(Duration::from_secs(2)).unwrap();
            let standard_gossip = StandardBuilder::new()
                .add_masq_node(&node, 1)
                .half_neighbors(node.main_public_key(), real_node.main_public_key())
                .chain_id(cluster.chain)
                .build();
            node.transmit_multinode_gossip(real_node, &standard_gossip)
                .unwrap();
            node.wait_for_gossip(Duration::from_secs(2)).unwrap();
            node
        })
        .collect::<Vec<MASQMockNode>>()
}

fn modify_node(
    gossip_node: &mut NodeRecord,
    model_node: &NodeRecord,
    mock_node_map: &HashMap<PublicKey, MASQMockNode>,
) {
    let node_addr_opt = match mock_node_map.get(gossip_node.public_key()) {
        Some(mock_node) => Some(mock_node.node_addr()),
        None => model_node.node_addr_opt(),
    };
    gossip_node.metadata.node_addr_opt = node_addr_opt;
    gossip_node.inner.version = 2;
    gossip_node.inner.neighbors = model_node
        .half_neighbor_keys()
        .into_iter()
        .cloned()
        .collect::<BTreeSet<PublicKey>>();
    gossip_node.resign();
}

fn local_db_from_node(node: &NodeRecord) -> NeighborhoodDatabase {
    let mut db = db_from_node(node);
    db.root_mut().inner = node.inner.clone();
    db.root_mut().resign();
    db
}

impl From<&MASQMockNode> for NodeRecord {
    fn from(mock_node: &MASQMockNode) -> Self {
        from_masq_node_to_node_record(mock_node)
    }
}

impl From<&MASQRealNode> for NodeRecord {
    fn from(real_node: &MASQRealNode) -> Self {
        from_masq_node_to_node_record(real_node)
    }
}

fn from_masq_node_to_node_record(masq_node: &dyn MASQNode) -> NodeRecord {
    let agr = AccessibleGossipRecord::from(masq_node);
    NodeRecord {
        inner: agr.inner.clone(),
        metadata: NodeRecordMetadata {
            last_update: time_t_timestamp(),
            node_addr_opt: agr.node_addr_opt.clone(),
            unreachable_hosts: Default::default(),
            node_distrust_score: 0,
            node_location_opt: None
        },
        signed_gossip: agr.signed_gossip.clone(),
        signature: agr.signature,
    }
}
