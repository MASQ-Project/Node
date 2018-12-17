// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use gossip::Gossip;
use neighborhood_database::NeighborhoodDatabase;
use sub_lib::logger::Logger;
use neighborhood_database::NeighborhoodDatabaseError;

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
        changed = self.handle_neighbor_pairs (database, &gossip) || changed;
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
                if gnr_ref_ref.inner.public_key.data.is_empty() {
                    self.logger.error (format! ("Rejecting GossipNodeRecord with blank public key"));
                    false
                }
                else {
                    true
                }
            })
            .for_each(|gnr_ref| {
                if database.keys().contains(&gnr_ref.inner.public_key) {
                    let node_record = database.node_by_key_mut(&gnr_ref.inner.public_key).expect("Key magically disappeared").clone();

                    if let Some(new_node_addr_ref) = gnr_ref.inner.node_addr_opt.as_ref() {
                        match database.node_by_key_mut(node_record.public_key()).expect("Key magically disappeared").set_node_addr(new_node_addr_ref) {
                            Ok(_) => changed = true,
                            Err(NeighborhoodDatabaseError::NodeAddrAlreadySet(old_addr)) => {
                                self.logger.error(format!("Gossip attempted to change IP address of node {} from {} to {}: ignoring",
                                                          &gnr_ref.inner.public_key, old_addr.ip_addr(), new_node_addr_ref.ip_addr()));
                            },
                            Err(_) => panic!("Compiler candy")
                        }
                    }

                    match database.node_by_key_mut(node_record.public_key()).expect("Key magically disappeared").set_signatures(gnr_ref.signatures.clone()) {
                        Ok(true) => changed = true,
                        Ok(false) => (),
                        Err(NeighborhoodDatabaseError::NodeSignaturesAlreadySet(signatures)) => {
                            self.logger.error(format!("Gossip tried to modify signatures of node {} from {:?} to {:?}", node_record.public_key(), signatures, gnr_ref.signatures));
                        },
                        Err(_) => panic!("Compiler candy")
                    }
                } else {
                    database.add_node(&gnr_ref.to_node_record()).expect("Key magically appeared");
                    changed = true;
                }
            });
        changed
    }

    fn handle_neighbor_pairs (&self, database: &mut NeighborhoodDatabase, gossip_ref: &Gossip) -> bool {
        let mut changed = false;
        let key_ref_from_index = |index| {
            let usize_index = index as usize;
            if usize_index < gossip_ref.node_records.len () {
                Some(&gossip_ref.node_records[usize_index].inner.public_key)
            } else {
                None
            }
        };
        gossip_ref.neighbor_pairs.iter ().for_each (|neighbor_relationship| {
            match (key_ref_from_index (neighbor_relationship.from), key_ref_from_index (neighbor_relationship.to)) {
                (Some (from_key_ref), Some (to_key_ref)) if from_key_ref == to_key_ref => self.logger.error (format! ("Gossip attempted to make node {} neighbor to itself: ignoring", from_key_ref)),
                (Some (from_key_ref), _) if from_key_ref.data.is_empty () => self.logger.error (format! ("Rejecting neighbor reference with blank public key")),
                (_, Some (to_key_ref)) if to_key_ref.data.is_empty () => self.logger.error (format! ("Rejecting neighbor reference with blank public key")),
                (Some (from_key_ref), Some (to_key_ref)) => {
                    changed = database.add_neighbor (from_key_ref, to_key_ref).expect("Should have added nodes with these keys already") || changed;
                },
                (_, _) => self.logger.error (format! ("Gossip described neighbor relationship from node #{} to node #{}, but only contained {} nodes: ignoring", neighbor_relationship.from, neighbor_relationship.to, gossip_ref.node_records.len ()))
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
}

#[cfg (test)]
mod tests {
    use super::*;
    use neighborhood_test_utils::make_node_record;
    use std::collections::HashSet;
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
    use gossip::NeighborRelationship;
    use test_utils::test_utils::cryptde;
    use sub_lib::cryptde::CryptData;
    use neighborhood_database::NodeSignatures;

    #[test]
    fn gossip_is_copied_into_single_node_database() {
        init_test_logging();
        let existing_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(existing_node.public_key(),
                                                     existing_node.node_addr_opt().as_ref().unwrap(), existing_node.is_bootstrap_node(), cryptde ());
        let incoming_far_left = make_node_record(2345, false, false);
        let incoming_near_left = make_node_record(3456, true, false);
        let incoming_near_right = make_node_record(4657, true, false);
        let incoming_far_right = make_node_record(5678, false, false);
        let bad_record_with_blank_key = NodeRecord::new (&Key::new (&[]), None, false, Some(NodeSignatures::new(CryptData::new(b"hello"), CryptData::new(b"world"))));
        let gossip = GossipBuilder::new()
            .node(&incoming_far_left, false)
            .node(&incoming_near_left, true)
            .node(&existing_node, true)
            .node(&incoming_near_right, true)
            .node(&incoming_far_right, false)
            .node(&bad_record_with_blank_key, false)
            .neighbor_pair(incoming_near_left.public_key(), incoming_far_left.public_key())
            .neighbor_pair(incoming_near_left.public_key(), existing_node.public_key())
            .neighbor_pair(existing_node.public_key(), incoming_near_left.public_key())
            .neighbor_pair(existing_node.public_key(), incoming_near_right.public_key())
            .neighbor_pair(incoming_near_right.public_key(), existing_node.public_key())
            .neighbor_pair(incoming_near_right.public_key(), incoming_far_right.public_key())
            .neighbor_pair(incoming_far_right.public_key(), bad_record_with_blank_key.public_key())
            .neighbor_pair(bad_record_with_blank_key.public_key(), incoming_far_right.public_key())
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(database.keys(), vec_to_set(vec!(incoming_far_left.public_key(), incoming_near_left.public_key(),
                                                    existing_node.public_key(), incoming_near_right.public_key(), incoming_far_right.public_key())));
        assert_eq!(neighbor_keys_of(&database, &incoming_far_left), HashSet::new());
        assert_eq!(neighbor_keys_of(&database, &incoming_near_left),
                   vec_to_set(vec!(incoming_far_left.public_key(), existing_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &existing_node),
                   vec_to_set(vec!(incoming_near_left.public_key(), incoming_near_right.public_key())));
        assert_eq!(neighbor_keys_of(&database, &incoming_near_right),
                   vec_to_set(vec!(existing_node.public_key(), incoming_far_right.public_key())));
        assert_eq!(neighbor_keys_of(&database, &incoming_far_right), HashSet::new());
        let tlh = TestLogHandler::new ();
        tlh.assert_logs_contain_in_order (vec! (
            "ERROR: GossipAcceptorReal: Rejecting GossipNodeRecord with blank public key",
            "ERROR: GossipAcceptorReal: Rejecting neighbor reference with blank public key"
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
                   vec_to_set(vec!(neighbor_one.public_key(), neighbor_two.public_key())));
        assert_eq!(neighbor_keys_of(&database, &neighbor_one), vec_to_set(vec!(existing_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &neighbor_two), vec_to_set(vec!(existing_node.public_key())));
        assert_eq!(neighbor_keys_of(&database, &not_a_neighbor_one), HashSet::new());
        assert_eq!(neighbor_keys_of(&database, &not_a_neighbor_two), HashSet::new());
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
    fn handle_neighbor_pairs_complains_about_indices_that_resolve_to_matching_public_keys() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        let left_twin = make_node_record(2345, true, false);
        let right_twin = make_node_record(2345, true, false);
        let gossip = Gossip {
            node_records: vec!(
                GossipNodeRecord::from(&left_twin, true),
                GossipNodeRecord::from(&right_twin, true),
            ),
            neighbor_pairs: vec!(NeighborRelationship {
                from: 0,
                to: 1
            }),
        };
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(database.node_by_key(left_twin.public_key()).unwrap().neighbors(), &vec!(this_node.public_key().clone()));
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("ERROR: GossipAcceptorReal: Gossip attempted to make node AgMEBQ neighbor to itself: ignoring"));
    }

    #[test]
    fn handle_neighbor_pairs_complains_when_from_neighbor_index_is_bad() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        let incoming_node = make_node_record(2345, true, false);
        let gossip = Gossip {
            node_records: vec!(
                GossipNodeRecord::from(&incoming_node, true),
            ),
            neighbor_pairs: vec!(NeighborRelationship {
                from: 42,
                to: 0
            }),
        };
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(database.node_by_key(incoming_node.public_key()).unwrap().neighbors(), &vec!(this_node.public_key().clone()));
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("ERROR: GossipAcceptorReal: Gossip described neighbor relationship from node #42 to node #0, but only contained 1 nodes: ignoring"));
    }

    #[test]
    fn handle_neighbor_pairs_complains_when_to_neighbor_index_is_bad() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        let incoming_node = make_node_record(2345, true, false);
        let gossip = Gossip {
            node_records: vec!(
                GossipNodeRecord::from(&incoming_node, true),
            ),
            neighbor_pairs: vec!(NeighborRelationship {
                from: 0,
                to: 42
            }),
        };
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        assert_eq!(database.node_by_key(incoming_node.public_key()).unwrap().neighbors(), &vec!(this_node.public_key().clone()));
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("ERROR: GossipAcceptorReal: Gossip described neighbor relationship from node #0 to node #42, but only contained 1 nodes: ignoring"));
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
        let this_node = make_node_record(1234, true, false);
        let existing_node = make_node_record(2345, false, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();

        let gossip = GossipBuilder::new()
            .node(&this_node, true)
            .node(&existing_node, true)
            .neighbor_pair(this_node.public_key(), existing_node.public_key())
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
        let existing_node = make_node_record(2345, true, false);
        let mut database = NeighborhoodDatabase::new(this_node.public_key(),
                                                     this_node.node_addr_opt().as_ref().unwrap(), this_node.is_bootstrap_node(), cryptde ());
        database.add_node(&existing_node).unwrap();
        database.add_neighbor(this_node.public_key(), existing_node.public_key()).unwrap ();
        database.add_neighbor(existing_node.public_key(), this_node.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&existing_node, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        assert_eq!(database.has_neighbor (this_node.public_key (), existing_node.public_key ()), true);
        assert!(!result, "Gossip unexpectedly resulted in a change to the DB");
    }

    #[test]
    fn handle_returns_false_when_an_existing_neighbor_with_existing_signatures_is_gossipped_about() {
        let this_node = make_node_record(1234, true, false);
        let neighbor = make_node_record(2345, true, false);
        let malefactor = NodeRecord::new(neighbor.public_key(), neighbor.node_addr_opt().as_ref(), neighbor.is_bootstrap_node(), Some(NodeSignatures::new(CryptData::new(&[6, 7, 5, 4]), CryptData::new(&[3, 6, 9, 12]))));
        let mut database = NeighborhoodDatabase::new(this_node.public_key(), &this_node.node_addr_opt().unwrap(), this_node.is_bootstrap_node(), cryptde());

        database.add_node(&neighbor).unwrap();
        database.add_neighbor(this_node.public_key(), neighbor.public_key()).unwrap ();
        database.add_neighbor(neighbor.public_key(), this_node.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&malefactor, true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut database, gossip);

        let neighbor_in_db = database.node_by_key(neighbor.public_key()).unwrap();
        assert_eq!(neighbor_in_db.signatures(), neighbor.signatures());
        assert!(!result, "Gossip unexpectedly resulted in a change to the DB");
    }

    #[test]
    fn handle_complains_when_an_existing_neighbor_with_existing_signatures_is_gossipped_about() {
        init_test_logging();
        let this_node = make_node_record(1234, true, false);
        let neighbor = make_node_record(2345, true, false);
        let malefactor = NodeRecord::new(neighbor.public_key(), neighbor.node_addr_opt().as_ref(), neighbor.is_bootstrap_node(), Some(NodeSignatures::new(CryptData::new(&[6, 7, 5, 4]), CryptData::new(&[3, 6, 9, 12]))));
        let mut database = NeighborhoodDatabase::new(this_node.public_key(), &this_node.node_addr_opt().unwrap(), this_node.is_bootstrap_node(), cryptde());

        database.add_node(&neighbor).unwrap();
        database.add_neighbor(this_node.public_key(), neighbor.public_key()).unwrap ();

        let gossip = GossipBuilder::new()
            .node(&malefactor, true)
            .build();
        let subject = GossipAcceptorReal::new();

        subject.handle(&mut database, gossip);

        TestLogHandler::new().await_log_containing(&format!("ERROR: GossipAcceptorReal: Gossip tried to modify signatures of node AgMEBQ from {:?} to {:?}", neighbor.signatures().unwrap(), malefactor.signatures().unwrap()), 500);
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
