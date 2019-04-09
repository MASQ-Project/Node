// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use super::gossip::Gossip;
use super::gossip::GossipBuilder;
use super::neighborhood_database::NeighborhoodDatabase;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::logger::Logger;

pub trait GossipProducer: Send {
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip;
}

pub struct GossipProducerReal {
    logger: Logger,
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
    fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip {
        let target_node_ref = database
            .node_by_key(target)
            .expect(format!("Target node {:?} not in NeighborhoodDatabase", target).as_str());
        let builder = database
            .keys()
            .into_iter()
            .filter(|k| *k != target)
            .flat_map(|k| database.node_by_key(k))
            .fold(GossipBuilder::new(database), |so_far, node_record_ref| {
                let reveal_node_addr = node_record_ref.public_key() == database.root().public_key()
                    || target_node_ref.has_half_neighbor(node_record_ref.public_key());
                so_far.node(node_record_ref.public_key(), reveal_node_addr)
            });
        let gossip = builder.build();
        self.logger.trace(format!(
            "Created Gossip: {}",
            gossip.to_dot_graph(database.root(), target_node_ref)
        ));
        gossip
    }
}

impl GossipProducerReal {
    pub fn new() -> GossipProducerReal {
        GossipProducerReal {
            logger: Logger::new("GossipProducerReal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipNodeRecord;
    use super::super::neighborhood_test_utils::*;
    use super::*;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use std::collections::HashSet;

    #[test]
    #[should_panic(expected = "Target node AgMEBQ not in NeighborhoodDatabase")]
    fn produce_fails_for_target_not_in_database() {
        let this_node = make_node_record(1234, true, false);
        let target_node = make_node_record(2345, true, false);
        let database = db_from_node(&this_node);

        let subject = GossipProducerReal::new();

        subject.produce(&database, target_node.public_key());
    }

    #[test]
    fn produce_reveals_and_conceals_node_addrs_appropriately() {
        let root_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&root_node);
        let target_node_key = &db.add_node(&make_node_record(1235, true, false)).unwrap();
        let common_neighbor_key = &db.add_node(&make_node_record(1236, true, false)).unwrap();
        let root_full_neighbor_key = &db.add_node(&make_node_record(1237, true, false)).unwrap();
        let target_full_neighbor_key = &db.add_node(&make_node_record(1238, false, false)).unwrap();
        let knows_target_key = &db.add_node(&make_node_record(1239, false, false)).unwrap();
        let target_knows_key = &db.add_node(&make_node_record(1240, false, false)).unwrap();
        let knows_root_key = &db.add_node(&make_node_record(1241, false, false)).unwrap();
        let root_knows_key = &db.add_node(&make_node_record(1242, true, false)).unwrap();
        let root_bootstrap_key = &db.add_node(&make_node_record(1243, true, true)).unwrap();
        let target_bootstrap_key = &db.add_node(&make_node_record(1244, false, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), target_node_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), common_neighbor_key);
        db.add_arbitrary_full_neighbor(target_node_key, common_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), root_full_neighbor_key);
        db.add_arbitrary_full_neighbor(target_node_key, target_full_neighbor_key);
        db.add_arbitrary_half_neighbor(knows_target_key, target_node_key);
        db.add_arbitrary_half_neighbor(knows_root_key, root_node.public_key());
        db.add_arbitrary_half_neighbor(target_node_key, target_knows_key);
        db.add_arbitrary_half_neighbor(root_node.public_key(), root_knows_key);
        db.add_arbitrary_full_neighbor(target_node_key, target_bootstrap_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), root_bootstrap_key);
        let subject = GossipProducerReal::new();
        let db = db.clone();

        let gossip = subject.produce(&db, target_node_key);

        type Digest = (PublicKey, Vec<u8>, bool, HashSet<PublicKey>);
        let gnr_digest = |gnr: GossipNodeRecord| {
            (
                gnr.public_key(),
                gnr.public_key().into(),
                gnr.inner.node_addr_opt.is_some(),
                gnr.inner.neighbors,
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
                    .collect::<HashSet<PublicKey>>(),
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
            node_digest(root_knows_key, false),
            node_digest(root_bootstrap_key, false),
            node_digest(target_bootstrap_key, false),
        ];
        expected_gossip_digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut actual_gossip_digests = gossip
            .node_records
            .into_iter()
            .map(|gnr| gnr_digest(gnr))
            .collect::<Vec<Digest>>();
        actual_gossip_digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(expected_gossip_digests, actual_gossip_digests);
    }

    #[test]
    fn produce_logs_about_the_resulting_gossip() {
        init_test_logging();

        let this_node = make_node_record(1234, true, false);

        let mut database = db_from_node(&this_node);
        let first_neighbor = &database
            .add_node(&make_node_record(2345, true, false))
            .unwrap();
        let target = &database
            .add_node(&make_node_record(4567, true, false))
            .unwrap();
        database.add_arbitrary_full_neighbor(this_node.public_key(), first_neighbor);
        database.add_arbitrary_full_neighbor(this_node.public_key(), target);
        database.add_arbitrary_full_neighbor(first_neighbor, target);
        let subject = GossipProducerReal::new();

        let _result = subject.produce(&database, target);

        TestLogHandler::new().exists_log_containing("Created Gossip: digraph db { ");
        TestLogHandler::new().exists_log_containing(
            "\"AQIDBA\" [label=\"v0\\nAQIDBA\\n1.2.3.4:1234\"] [style=filled];",
        );
        TestLogHandler::new().exists_log_containing("\"BAUGBw\" [label=\"BAUGBw\"] [shape=none];");
        TestLogHandler::new()
            .exists_log_containing("\"AgMEBQ\" [label=\"v0\\nAgMEBQ\\n2.3.4.5:2345\"];");
        TestLogHandler::new().exists_log_containing("\"AgMEBQ\" -> \"BAUGBw\";");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" -> \"AgMEBQ\";");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" -> \"BAUGBw\";");
    }
}
