// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use gossip::Gossip;
use neighborhood_database::NeighborhoodDatabase;
use sub_lib::logger::Logger;
use gossip_acceptor::GossipAcceptor;
use sub_lib::cryptde::Key;
use neighborhood_database::NodeRecord;
use gossip::GossipNodeRecord;

// The purpose of this temporary code is to accept only single-node Gossips from 0.4.0-level Nodes
// at startup and form those nodes into a topological linked list, with the first reporting Node
// at one end and the most-recent reporting Node at the other. This is a convenient topology for
// testing because it offers A) determinism, B) Nodes that know each other's IP address, and
// C) Nodes that do not know each other's IP address.
//
// Once we're past 0.5.0 and the Network is allowed to self-heal, this code will be pulled out
// and the Neighborhoods of bootstrap Nodes will act identically to the Neighborhoods of other
// Nodes.

pub struct TemporaryBootstrapGossipAcceptor {
    pub logger: Logger
}

impl GossipAcceptor for TemporaryBootstrapGossipAcceptor {
    fn handle(&self, database: &mut NeighborhoodDatabase, gossip: Gossip) -> bool {
        let foreign_node_record = match Self::find_single_foreign_node_record(database, &gossip) {
            None => {
                self.logger.error (format! ("I'm just a TemporaryBootstrapGossipAcceptor; I don't know what to do with {}-node Gossip messages!", gossip.node_records.len ()));
                return false
            },
            Some (foreign_node_record) => foreign_node_record
        };

        if foreign_node_record.public_key ().data.is_empty() {
            self.logger.error(format!("Rejected Gossip from Node with blank public key"));
            return false
        }

        if database.keys().len() == 1 {
            self.initial_case(database, foreign_node_record);
        } else {
            self.normal_case(database, foreign_node_record);
        }
        self.logger.debug (format! ("After processing Gossip: {:?}", database));
        true
    }
}

impl TemporaryBootstrapGossipAcceptor {
    pub fn new() -> TemporaryBootstrapGossipAcceptor {
        TemporaryBootstrapGossipAcceptor {logger: Logger::new ("TemporaryBootstrapGossipAcceptor")}
    }

    fn initial_case(&self, database: &mut NeighborhoodDatabase, foreign_node_record: NodeRecord) {
        let root_key_ref = &database.root().public_key().clone();
        database.add_node(&foreign_node_record).expect (&format! ("initial case collision: {:?}", foreign_node_record.public_key ()));
        database.add_neighbor(foreign_node_record.public_key(), root_key_ref).expect ("add_node failed");
        database.add_neighbor(root_key_ref, foreign_node_record.public_key()).expect ("add_node failed");
    }

    fn normal_case(&self, database: &mut NeighborhoodDatabase, foreign_node_record: NodeRecord) {
        let first_neighbor_key_ref = &TemporaryBootstrapGossipAcceptor::find_first_neighbor(database).clone();
        let last_neighbor_key_ref = &TemporaryBootstrapGossipAcceptor::find_last_neighbor(database, first_neighbor_key_ref).clone();
        let root_key_ref = &database.root().public_key().clone();
        database.add_node(&foreign_node_record).expect(&format! ("normal_case collision: {:?}", foreign_node_record.public_key ()));
        database.add_neighbor(foreign_node_record.public_key(), root_key_ref).expect ("root node disappeared");
        database.add_neighbor(foreign_node_record.public_key(), last_neighbor_key_ref).expect ("add_node failed");
        database.add_neighbor(last_neighbor_key_ref, foreign_node_record.public_key()).expect ("last neighbor disappeared");
    }

    fn find_first_neighbor(database: &NeighborhoodDatabase) -> &Key {
        *database.keys().iter().find(|key_ref_ref_ref| {
            let key_ref = **key_ref_ref_ref;
            let root = database.root();
            root.has_neighbor(key_ref) && database.node_by_key(key_ref).expect("node magically disappeared").has_neighbor(root.public_key())
        }).expect(&format! ("could not find first neighbor: {:?}", database))
    }

    fn find_last_neighbor<'a>(database: &'a NeighborhoodDatabase, first_neighbor: &'a Key) -> &'a Key {
        let mut prev = database.root().public_key();
        let mut curr = first_neighbor;

        for _ in 0..database.keys ().len () {
            let next_opt = database.node_by_key(curr).as_ref().expect("node magically disappeared").neighbors()
                .iter().find(|neighbor_key_ref_ref| (*neighbor_key_ref_ref != prev) && (*neighbor_key_ref_ref != database.root ().public_key ()));

            match next_opt {
                Some(next) => {
                    prev = curr;
                    curr = next;
                },
                None => return curr
            }
        }
        panic! ("Could not find last neighbor: database is not linear like it's supposed to be: {:?}", database);
    }

    fn find_single_foreign_node_record (database: &NeighborhoodDatabase, gossip: &Gossip) -> Option<NodeRecord> {
        let root_key = database.root ().public_key ().clone ();
        let foreign_gossip_node_records = gossip.node_records.iter ()
            .filter (|gnr_ref_ref| gnr_ref_ref.inner.public_key != root_key)
            .map (|gnr_ref| {gnr_ref.clone ()})
            .collect::<Vec<GossipNodeRecord>> ();
        if foreign_gossip_node_records.len () != 1 {return None}
        Some (foreign_gossip_node_records[0].to_node_record ())
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use neighborhood_test_utils::make_node_record;
    use gossip::GossipBuilder;
    use neighborhood_test_utils::*;
    use neighborhood_database::NodeRecord;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::test_utils::cryptde;
    use sub_lib::cryptde::CryptData;

    #[test]
    fn adding_three_good_single_node_gossips_and_one_bad_one_produces_expected_database_pattern () {
        init_test_logging ();
        let this_node = make_node_record(1234, true, true);
        let first_node = make_node_record(2345, true, false);
        let second_node = make_node_record(3456, true, false);
        let third_node = make_node_record(4567, true, false);
        let bad_node = NodeRecord::new (&Key::new (&[]), None, false, Some(CryptData::new(b"hello")), Some(CryptData::new(b"world")));
        let mut database = NeighborhoodDatabase::new(this_node.public_key(), &this_node.node_addr_opt ().unwrap (), this_node.is_bootstrap_node(), cryptde ());

        let first_gossip = GossipBuilder::new().node(&first_node, true).build();
        let second_gossip = GossipBuilder::new().node(&second_node, true).build();
        let third_gossip = GossipBuilder::new().node(&third_node, true).build();
        let bad_gossip = GossipBuilder::new ().node (&bad_node, true).build();

        let subject = TemporaryBootstrapGossipAcceptor::new();

        subject.handle(&mut database, first_gossip);
        subject.handle(&mut database, second_gossip);
        subject.handle(&mut database, third_gossip);
        subject.handle(&mut database, bad_gossip);

        assert_eq!(neighbor_keys_of(&database, &this_node), vec_to_set(vec! (first_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &first_node), vec_to_set(vec! (this_node.public_key(), second_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &second_node), vec_to_set(vec! (this_node.public_key(), first_node.public_key(), third_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &third_node), vec_to_set(vec! (this_node.public_key(), second_node.public_key())));
        TestLogHandler::new ().exists_log_containing ("ERROR: TemporaryBootstrapGossipAcceptor: Rejected Gossip from Node with blank public key");
    }
}
