// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use super::gossip::GossipBuilder;
use super::gossip::Gossip_0v1;
use super::neighborhood_database::NeighborhoodDatabase;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::utils::time_t_timestamp;
use masq_lib::logger::Logger;
use std::cell::Cell;

pub const DEAD_NODE_CHECK_INTERVAL_SECS: u32 = 60;

pub trait GossipProducer: Send {
    fn produce(
        &self,
        database: &mut NeighborhoodDatabase,
        target: &PublicKey,
    ) -> Option<Gossip_0v1>;
    fn produce_debut(&self, database: &NeighborhoodDatabase) -> Gossip_0v1;
}

pub struct GossipProducerReal {
    logger: Logger,
    last_dead_node_check: Cell<u32>,
}

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
    fn produce(
        &self,
        database: &mut NeighborhoodDatabase,
        target: &PublicKey,
    ) -> Option<Gossip_0v1> {
        if time_t_timestamp() - self.last_dead_node_check.get() >= DEAD_NODE_CHECK_INTERVAL_SECS {
            debug!(self.logger, "Checking for dead Nodes");
            database.cull_dead_nodes();
            self.last_dead_node_check.set(time_t_timestamp());
        }
        let target_node_ref = match database.node_by_key(target) {
            Some(node) => node,
            None => {
                debug!(
                    self.logger,
                    "Target {} is removed or nonexistent; producing no Gossip for it", target
                );
                return None;
            }
        };
        let referenced_keys = database.referenced_node_keys();
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
        Some(builder.build())
    }

    fn produce_debut(&self, database: &NeighborhoodDatabase) -> Gossip_0v1 {
        GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build()
    }
}

impl Default for GossipProducerReal {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipProducerReal {
    pub fn new() -> GossipProducerReal {
        GossipProducerReal {
            logger: Logger::new("GossipProducer"),
            last_dead_node_check: Cell::new(time_t_timestamp()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipNodeRecord;
    use super::*;
    use crate::neighborhood::neighborhood_database::ISOLATED_NODE_GRACE_PERIOD_SECS;
    use crate::neighborhood::node_record::{NodeRecord, NodeRecordInner_0v1};
    use crate::neighborhood::AccessibleGossipRecord;
    use crate::sub_lib::cryptde::CryptDE;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::utils::time_t_timestamp;
    use crate::test_utils::assert_contains;
    use crate::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
    use itertools::Itertools;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::collections::btree_set::BTreeSet;
    use std::convert::TryFrom;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DEAD_NODE_CHECK_INTERVAL_SECS, 60);
    }

    #[test]
    fn constructor_populates_last_dead_node_check() {
        let begin_at = time_t_timestamp();
        let subject = GossipProducerReal::new();
        let end_at = time_t_timestamp();

        assert!(
            (subject.last_dead_node_check.get() >= begin_at)
                && (subject.last_dead_node_check.get() <= end_at)
        );
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

        let gossip = subject.produce(&mut db, target_node_key).unwrap();

        type Digest = (PublicKey, Vec<u8>, bool, BTreeSet<PublicKey>);
        let gnr_digest = |gnr: GossipNodeRecord| {
            let has_ip = gnr.node_addr_opt.is_some();
            let nri = NodeRecordInner_0v1::try_from(gnr).unwrap();
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

        let gossip = subject.produce(&mut db, target_node_key).unwrap();

        let gossip_root = gossip
            .node_records
            .into_iter()
            .map(|gnr| AccessibleGossipRecord::try_from(gnr).unwrap())
            .find(|agr| &agr.inner.public_key == root_node.public_key())
            .unwrap();
        assert_eq!(gossip_root.node_addr_opt, None);
    }

    #[test]
    fn produce_does_not_make_gossip_about_nonexistent_or_removed_nodes() {
        let root_node: NodeRecord = make_node_record(1234, true);
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let nonexistent_node = make_node_record(2345, false);
        let subject = GossipProducerReal::new();

        let result = subject.produce(&mut db, nonexistent_node.public_key());

        assert_eq!(result, None);
    }

    #[test]
    fn produce_does_not_gossip_about_isolated_nodes_but_does_not_immediately_remove_them() {
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

        let gossip = subject.produce(&mut db, &gossip_target).unwrap();

        let gossipped_keys = gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .map(|agr| agr.inner.public_key)
            .collect_vec();
        assert_contains(&gossipped_keys, root_node.public_key());
        assert_contains(&gossipped_keys, &once_referenced);
        assert_eq!(gossipped_keys.len(), 2);
        assert!(db.node_by_key(&never_referenced).is_some());
    }

    #[test]
    fn produce_removes_nodes_that_are_isolated_and_stale() {
        let root_node: NodeRecord = make_node_record(1234, true); // AQIDBA
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let once_referenced = db.add_node(make_node_record(2345, true)).unwrap(); // AgMEBQ
        db.node_by_key_mut(&once_referenced)
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);
        let never_referenced = db.add_node(make_node_record(3456, true)).unwrap(); // AwQFBg
        db.node_by_key_mut(&never_referenced)
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);
        let gossip_target = db.add_node(make_node_record(4567, true)).unwrap(); // BAUGBw
        db.add_arbitrary_half_neighbor(&once_referenced, root_node.public_key());
        db.add_arbitrary_half_neighbor(&never_referenced, root_node.public_key());
        db.add_arbitrary_half_neighbor(&never_referenced, &once_referenced);
        db.add_arbitrary_full_neighbor(&gossip_target, root_node.public_key());
        let subject = GossipProducerReal::new();
        subject
            .last_dead_node_check
            .set(time_t_timestamp() - DEAD_NODE_CHECK_INTERVAL_SECS - 2);

        let begin_at = time_t_timestamp();
        let gossip = subject.produce(&mut db, &gossip_target).unwrap();
        let end_at = time_t_timestamp();

        assert!(subject.last_dead_node_check.get() >= begin_at);
        assert!(subject.last_dead_node_check.get() <= end_at);
        let gossipped_keys = gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .map(|agr| agr.inner.public_key)
            .collect_vec();
        assert_contains(&gossipped_keys, root_node.public_key());
        assert_eq!(gossipped_keys.len(), 1);
        assert!(db.node_by_key(&once_referenced).is_some());
        assert!(db.node_by_key(&never_referenced).is_none());
    }

    #[test]
    fn produce_includes_root_node_in_first_debut_response() {
        let root_node: NodeRecord = make_node_record(1234, true); // AQIDBA
        let mut db: NeighborhoodDatabase = db_from_node(&root_node);
        let gossip_target = db.add_node(make_node_record(2345, true)).unwrap(); // AgMEBQ
        db.add_arbitrary_half_neighbor(root_node.public_key(), &gossip_target);
        let subject = GossipProducerReal::new();

        let gossip = subject.produce(&mut db, &gossip_target).unwrap();

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
        let mut our_node_record: NodeRecord = make_node_record(7771, true);
        our_node_record.inner.country_code = "US".to_string();
        let db = db_from_node(&our_node_record);
        let subject = GossipProducerReal::new();

        let result_gossip: Gossip_0v1 = subject.produce_debut(&db);

        assert_eq!(result_gossip.node_records.len(), 1);
        let result_gossip_record = result_gossip.node_records.first().unwrap();
        assert_eq!(
            result_gossip_record.node_addr_opt,
            Some(our_node_record.metadata.node_addr_opt.clone().unwrap())
        );
        let result_node_record_inner = NodeRecordInner_0v1::try_from(result_gossip_record).unwrap();
        assert_eq!(result_node_record_inner, our_node_record.inner);
        let our_cryptde = CryptDENull::from(our_node_record.public_key(), TEST_DEFAULT_CHAIN);
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

        let result_gossip: Gossip_0v1 = subject.produce_debut(&db);

        assert_eq!(result_gossip.node_records.len(), 1);
        let result_gossip_record = result_gossip.node_records.first().unwrap();
        assert_eq!(result_gossip_record.node_addr_opt, None);
        let result_node_record_inner = NodeRecordInner_0v1::try_from(result_gossip_record).unwrap();
        assert_eq!(result_node_record_inner, our_node_record.inner);
        let our_cryptde = CryptDENull::from(our_node_record.public_key(), TEST_DEFAULT_CHAIN);
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
