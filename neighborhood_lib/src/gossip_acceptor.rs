// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use gossip::Gossip;
use neighborhood_database::NeighborhoodDatabase;
use sub_lib::logger::Logger;
use neighborhood_database::NeighborhoodDatabaseError;
use gossip::GossipNodeRecord;
use sub_lib::cryptde::Key;
use std::collections::HashSet;
use neighborhood_database::NodeRecord;

pub trait GossipAcceptor {
    // Philosophy of handling Gossip messages that are malformed: Don't spend effort on rejecting
    // malformed Gossip for security reasons. Do whatever's easiest. An attacker might send
    // malformed Gossip accidentally at the beginning, but he will soon learn to generate valid
    // Gossip, whereupon effort spent detecting malformed Gossip will be wasted.
    fn handle (&self, database: &mut NeighborhoodDatabase, gossip: Gossip) -> bool;
}

pub struct GossipAcceptorReal {
    pub logger: Logger
}

impl GossipAcceptor for GossipAcceptorReal {

    /*
        `handle`
            the purpose of `handle` is to update a node's known neighborhood based on incoming Gossip. It doesn't do
            anything special with the Gossip, just records any new information, but it does not change already known information
            e.g. it will add an IP addr to a known neighbor without one, but it will not change a known IP addr of a known neighbor
            it will also add to its own neighbor list any nodes in the Gossip that include NodeAddr information
        params:
            `database`: the DB that contains this node's known neighborhood
            `gossip`: the Gossip message with which to update the DB
    */
    fn handle(&self, database: &mut NeighborhoodDatabase, gossip: Gossip) -> bool {
        let mut changed = self.handle_node_records (database, &gossip);
        changed = self.add_ip_neighbors (database, &gossip) || changed;
        self.logger.debug (format! ("Database after accepting Gossip: {:?}", database));
        changed
    }
}

impl GossipAcceptorReal {
    pub fn new() -> GossipAcceptorReal {
        GossipAcceptorReal {logger: Logger::new ("GossipAcceptorReal")}
    }

    fn handle_node_records (&self, database: &mut NeighborhoodDatabase, gossip_ref: &Gossip) -> bool {
        let mut changed = false;
        gossip_ref.node_records.iter ()
            .filter (|gnr_ref_ref| {
                self.is_not_invalid(&gnr_ref_ref)
            })
            .for_each(|gnr_ref| {
                changed = if database.keys().contains(&gnr_ref.inner.public_key) {
                    let node_record = database.node_by_key_mut(&gnr_ref.inner.public_key).expect("Key magically disappeared");
                    self.update_node_addrs (gnr_ref, node_record) ||
                        self.update_neighbors (gnr_ref, node_record) ||
                        self.update_signatures (gnr_ref, node_record) || changed
                } else {
                    database.add_node(&gnr_ref.to_node_record()).expect("Key magically appeared");
                    true
                }
            });
        changed
    }

    fn add_ip_neighbors (&self, database: &mut NeighborhoodDatabase, gossip_ref: &Gossip) -> bool {
        let mut changed = false;
        let root_key_ref = database.root ().public_key ().clone ();
        gossip_ref.node_records.iter ().for_each (|gnr_ref| {
            if gnr_ref.inner.node_addr_opt.is_some () && (&gnr_ref.inner.public_key != &root_key_ref) {
                changed = database.add_neighbor (&root_key_ref, &gnr_ref.inner.public_key).expect ("Node magically disappeared") || changed;
                // TODO remove this line (it will make gnr_ref's node record signature invalid the next time we gossip)
                changed = database.add_neighbor (&gnr_ref.inner.public_key, &root_key_ref).expect ("Node magically disappeared") || changed;
            }
        });
        changed
    }

    fn is_not_invalid(&self, gnr: &GossipNodeRecord) -> bool {
        let empty_key = Key::new (&[]);
        if gnr.inner.public_key.data.is_empty() {
            self.logger.error(format!("Rejecting GossipNodeRecord with blank public key"));
            false
        } else if gnr.inner.neighbors.contains(&empty_key) {
            self.logger.error(format!("Rejecting neighbor reference with blank public key"));
            false
        } else if gnr.inner.neighbors.contains(&gnr.inner.public_key) {
            self.logger.error(format! ("Gossip attempted to make node {} neighbor to itself: ignoring", &gnr.inner.public_key));
            false
        } else {
            true
        }
    }

    fn update_node_addrs (&self, gnr_ref: &GossipNodeRecord, node_record: &mut NodeRecord) -> bool {
        if let Some(new_node_addr_ref) = gnr_ref.inner.node_addr_opt.as_ref() {
            match node_record.set_node_addr(new_node_addr_ref) {
                Ok(_) => true,
                Err(NeighborhoodDatabaseError::NodeAddrAlreadySet(old_addr)) => {
                    self.logger.error(format!("Gossip attempted to change IP address of node {} from {} to {}: ignoring",
                                              &gnr_ref.inner.public_key, old_addr.ip_addr(), new_node_addr_ref.ip_addr()));
                    false
                },
                Err(_) => panic!("Compiler candy")
            }
        }
        else {
            false
        }
    }

    fn update_neighbors (&self, gnr_ref: &GossipNodeRecord, node_record: &mut NodeRecord) -> bool {
        let unchanged = {
            let existing_neighbors: HashSet<&Key> = gnr_ref.inner.neighbors.iter().collect();
            let incoming_neighbors: HashSet<&Key> = node_record.neighbors().iter().collect();
            existing_neighbors == incoming_neighbors
        };
        if unchanged {
            false
        }
        else {
            let neighbors = node_record.neighbors_mut();
            neighbors.clear();
            neighbors.extend(gnr_ref.inner.neighbors.clone());
            true
        }
    }

    fn update_signatures(&self, gnr_ref: &GossipNodeRecord, node_record: &mut NodeRecord) -> bool {
        node_record.set_signatures(gnr_ref.signatures.clone())
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use neighborhood_test_utils::make_node_record;
    use std::net::Ipv4Addr;
    use std::net::IpAddr;
    use test_utils::logging::TestLogHandler;
    use test_utils::logging::init_test_logging;
    use neighborhood_database::NodeRecord;
    use sub_lib::node_addr::NodeAddr;
    use gossip::GossipNodeRecord;
    use sub_lib::cryptde::Key;
    use gossip::GossipBuilder;
    use neighborhood_test_utils::*;
    use test_utils::test_utils::cryptde;
    use sub_lib::cryptde::CryptData;
    use neighborhood_database::NodeSignatures;

    #[test]
    fn gossip_is_copied_into_single_node_database() {
        init_test_logging();
        let mut existing_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(existing_node.public_key(),
                                                     existing_node.node_addr_opt().as_ref().unwrap(), existing_node.is_bootstrap_node(), cryptde ());
        let incoming_far_left = make_node_record(2345, false, false);
        let mut incoming_near_left = make_node_record(3456, true, false);
        let mut incoming_near_right = make_node_record(4657, true, false);
        let mut incoming_far_right = make_node_record(5678, false, false);
        let mut bad_record_with_blank_key = NodeRecord::new (&Key::new (&[]), None, false, Some(NodeSignatures::new(CryptData::new(b"hello"), CryptData::new(b"world"))));
        incoming_near_left.neighbors_mut ().push (incoming_far_left.public_key ().clone ());
        incoming_near_left.neighbors_mut ().push (existing_node.public_key ().clone ());
        existing_node.neighbors_mut ().push (incoming_near_left.public_key ().clone ());
        existing_node.neighbors_mut ().push (incoming_near_right.public_key ().clone ());
        incoming_near_right.neighbors_mut ().push (existing_node.public_key ().clone ());
        incoming_near_right.neighbors_mut ().push (incoming_far_right.public_key ().clone ());
        incoming_far_right.neighbors_mut ().push (bad_record_with_blank_key.public_key ().clone ());
        bad_record_with_blank_key.neighbors_mut ().push (incoming_far_right.public_key ().clone ());
        let gossip = GossipBuilder::new()
            .node(&incoming_far_left, false)
            .node(&incoming_near_left, true)
            .node(&existing_node, true)
            .node(&incoming_near_right, true)
            .node(&incoming_far_right, false)
            .node(&bad_record_with_blank_key, false)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(database.keys(), vec_to_set (vec!(
            incoming_far_left.public_key(),
            incoming_near_left.public_key(),
            existing_node.public_key(),
            incoming_near_right.public_key()
        )));
        let empty_neighbors: Vec<&Key> = vec! ();
        assert_eq!(neighbor_keys_of(&database, &incoming_far_left),
                   empty_neighbors);
        assert_eq!(neighbor_keys_of(&database, &incoming_near_left),
                   vec!(incoming_far_left.public_key(), existing_node.public_key()));
        assert_eq!(neighbor_keys_of(&database, &existing_node),
                   vec!(incoming_near_left.public_key(), incoming_near_right.public_key()));
        assert_eq!(neighbor_keys_of(&database, &incoming_near_right),
                   vec!(existing_node.public_key(), incoming_far_right.public_key()));
        let tlh = TestLogHandler::new ();
        tlh.assert_logs_contain_in_order (vec! (
            "ERROR: GossipAcceptorReal: Rejecting neighbor reference with blank public key",
            "ERROR: GossipAcceptorReal: Rejecting GossipNodeRecord with blank public key",
        ));
    }

    #[test]
    fn gossip_generates_neighbors_from_provided_ip_addresses_with_standard_gossip_acceptor() {
        let existing_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(existing_node.public_key(),
                                                     existing_node.node_addr_opt().as_ref().unwrap(), existing_node.is_bootstrap_node(), cryptde ());
        let neighbor_one = make_node_record(4657, true, false);
        let neighbor_two = make_node_record(5678, true, false);
        let not_a_neighbor_one = make_node_record(2345, false, false);
        let not_a_neighbor_two = make_node_record(3456, false, false);
        let gossip = GossipBuilder::new()
            .node(&neighbor_one, true)
            .node(&neighbor_two, true)
            .node(&not_a_neighbor_one, false)
            .node(&not_a_neighbor_two, false)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(neighbor_keys_of(&database, &existing_node),
                   vec!(neighbor_one.public_key(), neighbor_two.public_key()));
        assert_eq!(neighbor_keys_of(&database, &neighbor_one), vec!(existing_node.public_key()));
        assert_eq!(neighbor_keys_of(&database, &neighbor_two), vec!(existing_node.public_key()));
        assert_eq!(neighbor_keys_of(&database, &not_a_neighbor_one).is_empty (), true);
        assert_eq!(neighbor_keys_of(&database, &not_a_neighbor_two).is_empty (), true);
        assert_eq!(database.keys().len(), 5);
    }

    #[test]
    fn gossip_that_would_change_existing_node_ip_is_rejected() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let existing_node = make_node_record(2345, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();
        let new_node = NodeRecord::new_for_tests(existing_node.public_key(), Some(&NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(3, 4, 5, 6)), &vec!(12345))), false);
        let gossip = GossipBuilder::new()
            .node(&new_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        let existing_node_ref = database.node_by_key(existing_node.public_key()).unwrap();
        let existing_node_addr = existing_node_ref.node_addr_opt().unwrap();
        assert_eq!(existing_node_addr.ip_addr(), existing_node.node_addr_opt().unwrap().ip_addr());
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("ERROR: GossipAcceptorReal: Gossip attempted to change IP address of node AgMEBQ from 2.3.4.5 to 3.4.5.6: ignoring"));
    }

    #[test]
    fn gossip_that_would_add_new_ip_for_existing_node_is_accepted() {
        let this_node = make_node_record(1234, true, false);
        let existing_node = make_node_record(2345, false, false);
        let incoming_node = make_node_record(2345, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();

        let gossip = GossipBuilder::new()
            .node(&incoming_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        let incoming_node_ref = database.node_by_key(incoming_node.public_key()).unwrap();
        let incoming_node_addr = incoming_node_ref.node_addr_opt().unwrap();
        assert_eq!(incoming_node_addr.ip_addr(), incoming_node.node_addr_opt().unwrap().ip_addr());
        assert_eq!(database.has_neighbor (this_node.public_key (), incoming_node.public_key ()), true);
    }

    #[test]
    fn handle_neighbor_pairs_complains_about_gossip_records_that_neighbor_themselves() {
        init_test_logging();
        let mut this_node = make_node_record(1234, true, false);
        // existing_neighbor (2345) has a neighbor of its own: 5678.
        let mut existing_neighbor = make_node_record (2345, true, false);
        existing_neighbor.neighbors_mut().push (Key::new (&[5, 6, 7, 8]));
        this_node.neighbors_mut ().push (existing_neighbor.public_key ().clone ());
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node (&existing_neighbor).unwrap ();

        // Now node 2345 claims a completely different neighbors list including itself: 2345 and 6789.
        let mut invalid_record = make_node_record(2345, true, false);
        let invalid_record_public_key = invalid_record.public_key ().clone ();
        invalid_record.neighbors_mut ().push (invalid_record_public_key);
        invalid_record.neighbors_mut ().push (Key::new (&[6, 7, 8, 9]));

        let gossip = Gossip {
            node_records: vec!(
                GossipNodeRecord::from(&invalid_record, true),
            )
        };
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        // existing_neighbor in the database is untouched by the invalid Gossip.
        assert_eq!(database.node_by_key(existing_neighbor.public_key()).unwrap().neighbors(),
                   &vec!(Key::new (&[5, 6, 7, 8]), this_node.public_key ().clone ()));
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("ERROR: GossipAcceptorReal: Gossip attempted to make node AgMEBQ neighbor to itself: ignoring"));
    }

    #[test]
    fn handle_returns_true_when_an_existing_node_record_updates_signatures() {
        let this_node = make_node_record(1234, true, false);
        let neighbor = NodeRecord::new(&Key::new(&[2, 3, 4, 5]), Some(&NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(2, 3, 4, 5)), &vec![1337])), false, None);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(), &this_node.node_addr_opt().unwrap(), this_node.is_bootstrap_node(), cryptde());

        database.add_node(&neighbor).unwrap();
        database.add_neighbor(this_node.public_key(), neighbor.public_key()).unwrap ();

        let mut signed_neighbor = neighbor.clone();
        signed_neighbor.sign(cryptde());

        let gossip = GossipBuilder::new()
            .node(&signed_neighbor, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        let neighbor_in_db = database.node_by_key(neighbor.public_key()).unwrap();
        assert!(result, "Gossip did not result in a change to the DB as expected");
        assert_eq!(neighbor_in_db.signatures(), signed_neighbor.signatures());
    }

    #[test]
    fn handle_returns_true_when_a_new_node_record_is_added_without_a_node_addr_or_new_edges() {
        let this_node = make_node_record(1234, true, false);
        let incoming_node = make_node_record(2345, false, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        let gossip = GossipBuilder::new()
            .node(&incoming_node, false)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        let incoming_node_ref = database.node_by_key(incoming_node.public_key()).unwrap();
        let incoming_node_addr = incoming_node_ref.node_addr_opt();
        assert!(incoming_node_addr.is_none());
        assert!(result, "Gossip did not result in a change to the DB as expected")
    }

    #[test]
    fn handle_returns_true_when_a_new_edge_is_created_between_already_known_nodes() {
        let mut this_node = make_node_record(1234, true, false);
        let existing_node = make_node_record(2345, false, false);
        this_node.neighbors_mut().push (existing_node.public_key().clone ());
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();

        let gossip = GossipBuilder::new()
            .node(&this_node, true)
            .node(&existing_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert_eq!(database.has_neighbor (this_node.public_key (), existing_node.public_key ()), true);
        assert!(result, "Gossip did not result in a change to the DB as expected")
    }

    #[test]
    fn handle_returns_true_when_an_existing_node_record_is_updated_to_include_node_addr() {
        let this_node = make_node_record(1234, true, false);

        let existing_node_with_ip = make_node_record(2345, true, false);
        let existing_node_without_ip = NodeRecord::new(&existing_node_with_ip.public_key().clone(), None,
                                                       existing_node_with_ip.is_bootstrap_node(), existing_node_with_ip.signatures().clone());

        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());

        database.add_node(&existing_node_without_ip).unwrap();
        database.add_neighbor(this_node.public_key(), existing_node_with_ip.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&existing_node_with_ip, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert_eq!(database.has_neighbor (this_node.public_key (), existing_node_with_ip.public_key ()), true);
        assert!(result, "Gossip did not result in a change to the DB as expected")
    }

    #[test]
    fn handle_returns_true_when_a_new_node_record_includes_a_node_addr() {
        let this_node = make_node_record(1234, true, false);

        let incoming_node = make_node_record(2345, true, false);

        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());

        let gossip = GossipBuilder::new()
            .node(&incoming_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert_eq!(database.has_neighbor (this_node.public_key (), incoming_node.public_key ()), true);
        assert!(result, "Gossip did not result in a change to the DB as expected")
    }

    #[test]
    fn handle_returns_false_when_gossip_results_in_no_changes_for_existing_node_with_no_node_addr() {
        let this_node = make_node_record(1234, true, false);
        let existing_node = make_node_record(2345, false, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();

        let gossip = GossipBuilder::new()
            .node(&existing_node, false)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert!(!result, "Gossip unexpectedly resulted in a change to the DB");
    }

    #[test]
    fn handle_returns_false_when_gossip_results_in_no_changes_for_existing_node_with_node_addr() {
        let this_node = make_node_record(1234, true, false);
        let mut existing_node = make_node_record(2345, true, false);
        existing_node.neighbors_mut ().push (this_node.public_key ().clone ());
        let mut database = NeighborhoodDatabase::new(
            this_node.public_key(),
            this_node.node_addr_opt().as_ref().unwrap(),
            this_node.is_bootstrap_node(),
            cryptde ()
        );
        database.add_node(&existing_node).unwrap();
        database.add_neighbor(this_node.public_key(), existing_node.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&existing_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert_eq!(database.has_neighbor (this_node.public_key (), existing_node.public_key ()), true);
        assert!(!result, "Gossip unexpectedly resulted in a change to the DB");
    }

    #[test]
    fn handle_does_not_complain_when_gossip_contains_an_existing_signature() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let neighbor = make_node_record(9876, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(), &this_node.node_addr_opt().unwrap(), this_node.is_bootstrap_node(), cryptde());

        database.add_node(&neighbor).unwrap();
        database.add_neighbor(this_node.public_key(), neighbor.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&neighbor, true)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        TestLogHandler::new().exists_no_log_containing(&format!("ERROR: GossipAcceptorReal: Gossip tried to modify signatures of node CQgHBg from {:?} to {:?}", neighbor.signatures().clone().unwrap(), neighbor.signatures().clone().unwrap()));
    }
}
