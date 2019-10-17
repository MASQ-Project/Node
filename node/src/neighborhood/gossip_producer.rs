// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use super::gossip::Gossip;
use super::gossip::GossipBuilder;
use super::neighborhood_database::NeighborhoodDatabase;
use crate::sub_lib::cryptde::PublicKey;
use std::collections::BTreeSet;

pub trait GossipProducer: Send {
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip;
    fn produce_debut(&self, database: &NeighborhoodDatabase) -> Gossip;
}

pub struct GossipProducerReal {}

impl GossipProducer for GossipProducerReal {
    /*
        `produce`
            the purpose of `produce` is to convert the raw neighborhood from the DB into a Gossip message for a target Node
            the Gossip that `produce` returns includes the entire neighborhood, but masks the NodeAddrs of Nodes whose
            NodeAddrs the target Node does not know (except that the NodeAddr of this Node is never masked).
        params:
            `database`: the DB that contains the whole neighborhood
            `target`: the Node to produce the gossip for
                allows `produce` to determine which NodeAddrs to mask/reveal, based on which other Nodes `target` has as half neighbors
        returns:
            a Gossip message representing the current neighborhood for a target Node
    */
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip {
        let target_node_ref = database
            .node_by_key(target)
            .unwrap_or_else(|| panic!("Target node {:?} not in NeighborhoodDatabase", target));
        let mut referenced_keys: BTreeSet<PublicKey> = database
            .keys()
            .into_iter()
            .flat_map(|k| database.node_by_key(k))
            .flat_map(|n| n.inner.neighbors.clone())
            .collect();
        // Local Node is always Gossipped
        referenced_keys.insert (database.root().public_key().clone());
        let builder = database
            .keys()
            .into_iter()
            .filter(|k| *k != target)
            .filter(|k| referenced_keys.contains(k))
            .flat_map(|k| database.node_by_key(k))
            .fold(GossipBuilder::new(database), |so_far, node_record_ref| {
                let reveal_node_addr = node_record_ref.accepts_connections()
                    && (
                    node_record_ref.public_key() == database.root().public_key()
                        || target_node_ref.has_half_neighbor(node_record_ref.public_key())
                    // TODO SC-894/GH-132: Do we really want to reveal this?
                );
                so_far.node(node_record_ref.public_key(), reveal_node_addr)
            });
        builder.build()
    }

    fn produce_debut(&self, database: &NeighborhoodDatabase) -> Gossip {
        GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build()
    }
}

impl GossipProducerReal {
    pub fn new() -> GossipProducerReal {
        GossipProducerReal {}
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipNodeRecord;
    use super::*;
    use crate::neighborhood::neighborhood_test_utils::db_from_node;
    use crate::neighborhood::neighborhood_test_utils::make_node_record;
    use crate::neighborhood::node_record::{NodeRecord, NodeRecordInner};
    use crate::neighborhood::AccessibleGossipRecord;
    use crate::sub_lib::cryptde::CryptDE;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::{assert_contains, DEFAULT_CHAIN_ID};
    use itertools::Itertools;
    use std::collections::btree_set::BTreeSet;
    use std::convert::TryFrom;

    #[test]
    #[should_panic(expected = "Target node AgMEBQ not in NeighborhoodDatabase")]
    fn produce_fails_for_target_not_in_database() {
        let this_node = make_node_record(1234, true);
        let target_node = make_node_record(2345, true);
        let database = db_from_node(&this_node);

        let subject = GossipProducerReal::new();

        subject.produce(&database, target_node.public_key());
    }

    #[test]
    fn produce_reveals_and_conceals_node_addrs_appropriately() {
        let root_node = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let target_node_key = &db.add_node(make_node_record(1235, true)).unwrap();
        let common_neighbor_key = &db.add_node(make_node_record(1236, true)).unwrap();
        let root_full_neighbor_key = &db.add_node(make_node_record(1237, true)).unwrap();
        let target_full_neighbor_key = &db.add_node(make_node_record(1238, false)).unwrap();
        let knows_target_key = &db.add_node(make_node_record(1239, false)).unwrap();
        let target_knows_key = &db.add_node(make_node_record(1240, false)).unwrap();
        let knows_root_key = &db.add_node(make_node_record(1241, false)).unwrap();
        let root_knows_key_ac = &db.add_node(make_node_record(1242, true)).unwrap();
        let root_knows_key_nac = &db.add_node(make_node_record(1243, true)).unwrap();
        let referencer = &db.add_node(make_node_record(1300, false)).unwrap();
        db.node_by_key_mut(root_knows_key_nac)
            .unwrap()
            .inner
            .accepts_connections = false;
        db.add_arbitrary_full_neighbor(root_node.public_key(), target_node_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), common_neighbor_key);
        db.add_arbitrary_full_neighbor(target_node_key, common_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), root_full_neighbor_key);
        db.add_arbitrary_full_neighbor(target_node_key, target_full_neighbor_key);
        db.add_arbitrary_half_neighbor(knows_target_key, target_node_key);
        db.add_arbitrary_half_neighbor(knows_root_key, root_node.public_key());
        db.add_arbitrary_half_neighbor(target_node_key, target_knows_key);
        db.add_arbitrary_half_neighbor(root_node.public_key(), root_knows_key_ac);
        db.add_arbitrary_half_neighbor(root_node.public_key(), root_knows_key_nac);
        db.add_arbitrary_half_neighbor(target_node_key, root_knows_key_nac);
        db.add_arbitrary_half_neighbor(referencer, knows_target_key);
        db.add_arbitrary_half_neighbor(referencer, knows_root_key);
        let subject = GossipProducerReal::new();
        let db = db.clone();

        let gossip = subject.produce(&db, target_node_key);

        type Digest = (PublicKey, Vec<u8>, bool, BTreeSet<PublicKey>);
        let gnr_digest = |gnr: GossipNodeRecord| {
            let has_ip = gnr.node_addr_opt.is_some();
            let nri = NodeRecordInner::try_from(gnr).unwrap();
            (
                nri.public_key.clone(),
                nri.public_key.into(),
                has_ip,
                nri.neighbors.clone(),
            )
        };
        let node_digest = |key: &PublicKey, has_ip: bool| {
            (
                key.clone(),
                key.clone().into(),
                has_ip,
                db.node_by_key(key)
                    .unwrap()
                    .half_neighbor_keys()
                    .into_iter()
                    .map(|kr| kr.clone())
                    .collect::<BTreeSet<PublicKey>>(),
            )
        };
        let mut expected_gossip_digests = vec![
            node_digest(root_node.public_key(), true),
            node_digest(common_neighbor_key, true),
            node_digest(root_full_neighbor_key, false),
            node_digest(target_full_neighbor_key, false),
            node_digest(knows_target_key, false),
            node_digest(target_knows_key, false),
            node_digest(knows_root_key, false),
            node_digest(root_knows_key_ac, false),
            node_digest(root_knows_key_nac, false),
        ];
        expected_gossip_digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut actual_gossip_digests = gossip
            .node_records
            .into_iter()
            .map(|gnr| gnr_digest(gnr))
            .collect::<Vec<Digest>>();
        actual_gossip_digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(actual_gossip_digests, expected_gossip_digests);
    }

    #[test]
    fn produce_does_not_reveal_root_node_addr_if_root_does_not_accept_connections() {
        let root_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        db.node_by_key_mut(root_node.public_key())
            .unwrap()
            .inner
            .accepts_connections = false;
        let target_node_key = &db.add_node(make_node_record(1235, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), target_node_key);
        let subject = GossipProducerReal::new();
        let db = db.clone();

        let gossip = subject.produce(&db, target_node_key);

        let gossip_root = gossip
            .node_records
            .into_iter()
            .map(|gnr| AccessibleGossipRecord::try_from(gnr).unwrap())
            .find(|agr| &agr.inner.public_key == root_node.public_key())
            .unwrap();
        assert_eq!(gossip_root.node_addr_opt, None);
    }

    #[test]
    fn produce_does_not_gossip_about_isolated_nodes() {
        let root_node: NodeRecord = make_node_record(1234, true); // AQIDBA
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let once_referenced = db.add_node(make_node_record(2345, true)).unwrap(); // AgMEBQ
        let never_referenced = db.add_node(make_node_record(3456, true)).unwrap(); // AwQFBg
        let gossip_target = db.add_node(make_node_record(4567, true)).unwrap(); // BAUGBw
        db.add_arbitrary_half_neighbor(&once_referenced, root_node.public_key());
        db.add_arbitrary_half_neighbor(&never_referenced, root_node.public_key());
        db.add_arbitrary_half_neighbor(&never_referenced, &once_referenced);
        db.add_arbitrary_full_neighbor(&gossip_target, root_node.public_key());
        let subject = GossipProducerReal::new();

        let gossip = subject.produce(&db, &gossip_target);

        let gossipped_keys = gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .map(|agr| agr.inner.public_key)
            .collect_vec();
        assert_contains(&gossipped_keys, root_node.public_key());
        assert_contains(&gossipped_keys, &once_referenced);
        assert_eq!(gossipped_keys.len(), 2);
    }

    #[test]
    fn produce_includes_root_node_in_first_debut_response() {
        let root_node: NodeRecord = make_node_record(1234, true); // AQIDBA
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let gossip_target = db.add_node(make_node_record(2345, true)).unwrap(); // AgMEBQ
        db.add_arbitrary_half_neighbor(root_node.public_key(), &gossip_target);
        let subject = GossipProducerReal::new();

        let gossip = subject.produce(&db, &gossip_target);

        let gossipped_keys = gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .map(|agr| agr.inner.public_key)
            .collect_vec();
        assert_contains(&gossipped_keys, root_node.public_key());
        assert_eq!(gossipped_keys.len(), 1);
    }

    #[test]
    fn produce_debut_creates_a_gossip_to_a_target_about_ourselves_when_accepting_connections() {
        let our_node_record: NodeRecord = make_node_record(7771, true);
        let db = db_from_node(&our_node_record);
        let subject = GossipProducerReal::new();

        let result_gossip: Gossip = subject.produce_debut(&db);

        assert_eq!(result_gossip.node_records.len(), 1);
        let result_gossip_record = result_gossip.node_records.first().unwrap();
        assert_eq!(
            result_gossip_record.node_addr_opt,
            Some(our_node_record.metadata.node_addr_opt.clone().unwrap())
        );
        let result_node_record_inner = NodeRecordInner::try_from(result_gossip_record).unwrap();
        assert_eq!(result_node_record_inner, our_node_record.inner);
        let our_cryptde = CryptDENull::from(our_node_record.public_key(), DEFAULT_CHAIN_ID);
        assert_eq!(
            our_cryptde.verify_signature(
                &our_node_record.signed_gossip,
                &our_node_record.signature,
                our_cryptde.public_key()
            ),
            true,
        );
    }

    #[test]
    fn produce_debut_creates_a_gossip_to_a_target_about_ourselves_when_not_accepting_connections() {
        let mut our_node_record: NodeRecord = make_node_record(7771, true);
        our_node_record.inner.accepts_connections = false;
        let db = db_from_node(&our_node_record);
        let subject = GossipProducerReal::new();

        let result_gossip: Gossip = subject.produce_debut(&db);

        assert_eq!(result_gossip.node_records.len(), 1);
        let result_gossip_record = result_gossip.node_records.first().unwrap();
        assert_eq!(result_gossip_record.node_addr_opt, None);
        let result_node_record_inner = NodeRecordInner::try_from(result_gossip_record).unwrap();
        assert_eq!(result_node_record_inner, our_node_record.inner);
        let our_cryptde = CryptDENull::from(our_node_record.public_key(), DEFAULT_CHAIN_ID);
        assert_eq!(
            our_cryptde.verify_signature(
                &our_node_record.signed_gossip,
                &our_node_record.signature,
                our_cryptde.public_key()
            ),
            true,
        );
    }
}
