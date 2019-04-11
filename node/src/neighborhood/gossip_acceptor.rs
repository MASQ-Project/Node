use crate::neighborhood::gossip::GossipNodeRecord;
use crate::neighborhood::gossip::{Gossip, GossipBuilder};
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::node_record::NodeRecord;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::node_addr::NodeAddr;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Clone, PartialEq, Debug)]
pub enum GossipAcceptanceResult {
    Ignored, // Don't change anything; this Gossip was not worth accepting.
    Relay(Gossip, PublicKey, NodeAddr), // Don't change anything, but send this relay Gossip back to the debuter at the provided key and NodeAddr.
    Accepted(Vec<(Gossip, PublicKey, NodeAddr)>), // If debuts are provided, send only the debuts. If no debuts, Gossip the current database around.
}

pub trait GossipAcceptor: Send {
    fn handle(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult;
}

pub struct GossipAcceptorReal {
    logger: Logger,
}

impl GossipAcceptor for GossipAcceptorReal {
    fn handle(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult {
        match Self::determine_type(gossip, gossip_source) {
            GossipType::Debut => self.handle_debut(database, gossip),
            GossipType::Pass => self.handle_pass(database, gossip),
            GossipType::Standard => self.handle_standard_gossip(database, gossip, gossip_source),
            GossipType::Reject => GossipAcceptanceResult::Ignored,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
enum GossipType {
    Debut,
    Pass,
    Standard,
    Reject,
}

impl GossipAcceptorReal {
    pub fn new() -> GossipAcceptorReal {
        GossipAcceptorReal {
            logger: Logger::new("GossipAcceptor"),
        }
    }

    fn determine_type(gossip: &Gossip, gossip_source: IpAddr) -> GossipType {
        if Self::is_standard(gossip) {
            GossipType::Standard
        } else if Self::is_debut(gossip, gossip_source) {
            GossipType::Debut
        } else if Self::is_pass(gossip, gossip_source) {
            GossipType::Pass
        } else {
            GossipType::Reject
        }
    }

    // A Debut must contain a single GossipNodeRecord; it must provide its IP address; it must specify at least one port; and it must be sourced by the debuting Node.
    fn is_debut(gossip: &Gossip, gossip_source: IpAddr) -> bool {
        if gossip.node_records.len() != 1 {
            return false;
        }
        match &gossip.node_records[0].inner.node_addr_opt {
            None => false,
            Some(node_addr) => {
                !node_addr.ports().is_empty() && node_addr.ip_addr() == gossip_source
            }
        }
    }

    // A Pass must contain a single GossipNodeRecord representing the pass target; it must provide its IP address; it must specify at least one port; and it must _not_ be sourced by the pass target.
    fn is_pass(gossip: &Gossip, gossip_source: IpAddr) -> bool {
        if gossip.node_records.len() != 1 {
            return false;
        }
        match &gossip.node_records[0].inner.node_addr_opt {
            None => false,
            Some(node_addr) => {
                !node_addr.ports().is_empty() && node_addr.ip_addr() != gossip_source
            }
        }
    }

    // Standard Gossip must contain more than one GossipNodeRecord. Beyond that, the requirements are somewhat murky.
    fn is_standard(gossip: &Gossip) -> bool {
        gossip.node_records.len() > 1
    }

    //////

    fn handle_debut(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
    ) -> GossipAcceptanceResult {
        if database.root().is_bootstrap_node() {
            self.handle_debut_bootstrap(database, gossip)
        } else {
            self.handle_debut_standard(database, gossip)
        }
    }

    fn handle_pass(
        &self,
        database: &mut NeighborhoodDatabase,
        pass: &Gossip,
    ) -> GossipAcceptanceResult {
        let gossip = GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build();
        let pass_target_key = pass.node_records[0].public_key(); // empty Gossip shouldn't get here
        let pass_target_node_addr = pass.node_records[0]
            .inner
            .node_addr_opt
            .clone()
            .expect("Pass lost its NodeAddr");
        GossipAcceptanceResult::Relay(gossip, pass_target_key, pass_target_node_addr)
    }

    fn handle_standard_gossip(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult {
        // identify and add new Nodes that are not introductions
        let mut db_changed =
            self.identify_and_add_non_introductory_new_nodes(database, gossip, gossip_source);
        // identify and update Nodes that have obsolete versions
        db_changed = self.identify_and_update_obsolete_nodes(database, gossip) || db_changed;
        // update root node if necessary
        db_changed = self.handle_root_node(database, gossip_source) || db_changed;
        // identify, compose, and return Debuts for Nodes that have been introduced
        let debuts = self.make_debuts(database, gossip, gossip_source);
        // If there are no new introductory or non-introductory Nodes, and no Nodes need updating, return ::Ignored and don't change the database.
        // Otherwise, return ::Accepted with the Debuts.
        if db_changed || !debuts.is_empty() {
            GossipAcceptanceResult::Accepted(debuts)
        } else {
            GossipAcceptanceResult::Ignored
        }
    }

    //////

    fn handle_debut_standard(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
    ) -> GossipAcceptanceResult {
        let source_node = &gossip.node_records[0]; // empty Gossip shouldn't get here
        let source_key = source_node.public_key();
        let source_node_addr = source_node
            .inner
            .node_addr_opt
            .clone()
            .expect("Debut node lost its NodeAddr");
        match self.find_more_appropriate_neighbor(database) {
            Some(key) => GossipAcceptanceResult::Relay(
                Self::make_pass_gossip(database, key),
                source_key,
                source_node_addr,
            ),
            None => match self.try_accept_debut(database, source_node) {
                Ok(result) => result,
                Err(_) => {
                    let lcn = Self::find_least_connected_neighbor(database).expect(
                        "If there aren't any neighbors, try_accept_debut() should have succeeded",
                    );
                    GossipAcceptanceResult::Relay(
                        Self::make_pass_gossip(database, lcn),
                        source_key,
                        source_node_addr,
                    )
                }
            },
        }
    }

    fn handle_debut_bootstrap(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
    ) -> GossipAcceptanceResult {
        let least_connected_neighbor_key_opt = {
            let neighbor_vec = Self::root_neighbors_ordered_by_degree(database);
            if neighbor_vec.is_empty() {
                None
            } else {
                Some(neighbor_vec[0].clone())
            }
        };
        let source_node = &gossip.node_records[0]; // empty Gossip shouldn't get here
        self.try_accept_debut(database, source_node).is_ok(); // can't really get an error here
        match least_connected_neighbor_key_opt {
            None => GossipAcceptanceResult::Accepted(vec![]),
            Some(least_connected_neighbor_key) => {
                let pass_gossip = GossipBuilder::new(database)
                    .node(&least_connected_neighbor_key, true)
                    .build();
                GossipAcceptanceResult::Accepted(vec![(
                    pass_gossip,
                    source_node.public_key(),
                    source_node
                        .inner
                        .node_addr_opt
                        .clone()
                        .expect("NodeAddr magically disappeared"),
                )])
            }
        }
    }

    fn find_more_appropriate_neighbor<'a>(
        &self,
        database: &'a NeighborhoodDatabase,
    ) -> Option<&'a PublicKey> {
        let neighbor_vec = Self::root_neighbors_ordered_by_degree(database);
        let neighbors_3_or_greater_vec: Vec<&PublicKey> = neighbor_vec
            .into_iter()
            .skip_while(|k| database.gossip_target_degree(*k) <= 2)
            .collect();
        match neighbors_3_or_greater_vec.first().map(|kr| *kr) {
            // No neighbors of degree 3 or greater
            None => None,
            // Neighbor of degree 3 or greater, but not less connected than I am
            Some(ref key)
                if database.gossip_target_degree(key)
                    >= database.gossip_target_degree(database.root().public_key()) =>
            {
                None
            }
            // Neighbor of degree 3 or greater less connected than I am
            Some(key) => Some(key),
        }
    }

    fn try_accept_debut(
        &self,
        database: &mut NeighborhoodDatabase,
        source_node: &GossipNodeRecord,
    ) -> Result<GossipAcceptanceResult, ()> {
        if (database.gossip_target_degree(database.root().public_key()) >= 5)
            && database.root().is_not_bootstrap_node()
        {
            return Err(());
        }
        let debuting_node = source_node.to_node_record();
        let node_key = match database.add_node(&debuting_node) {
            Ok(key) => key,
            Err(NeighborhoodDatabaseError::NodeKeyCollision(_)) => {
                self.logger.warning(format!(
                    "Ignored re-debut from Node {}, which is already in the database",
                    debuting_node.public_key()
                ));
                return Ok(GossipAcceptanceResult::Ignored);
            }
            Err(e) => panic!(
                "Unexpected error accepting debut node {}: {:?}",
                debuting_node.public_key(),
                e
            ),
        };
        match database.add_half_neighbor(&node_key) {
            Err(NeighborhoodDatabaseError::NodeKeyNotFound(k)) => {
                panic!("Node {} magically disappeared", k)
            }
            Err(e) => panic!(
                "Unexpected error accepting debut from {}/{:?}: {:?}",
                debuting_node.public_key(),
                debuting_node.node_addr_opt(),
                e
            ),
            Ok(true) => {
                database.root_mut().increment_version();
                Ok(GossipAcceptanceResult::Accepted(
                    self.make_acceptance_gossip_opt(database, &debuting_node),
                ))
            }
            Ok(false) => panic!("Brand-new neighbor already existed"),
        }
    }

    fn identify_and_add_non_introductory_new_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
        gossip_source: IpAddr,
    ) -> bool {
        let all_keys = database
            .keys()
            .into_iter()
            .map(|x| x.clone())
            .collect::<HashSet<PublicKey>>();
        gossip
            .node_records
            .iter()
            .filter(|gnr| !all_keys.contains(&gnr.public_key()))
            .filter(|gnr| match &gnr.inner.node_addr_opt {
                None => true,
                Some(node_addr) => node_addr.ip_addr() == gossip_source,
            })
            .map(|gnr| gnr.to_node_record())
            .for_each(|nr| {
                database
                    .add_node(&nr)
                    .expect("List of new Nodes contained existing Nodes");
            });
        database.keys().len() != all_keys.len()
    }

    fn identify_and_update_obsolete_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        gossip: &Gossip,
    ) -> bool {
        let change_flags: Vec<bool> = gossip
            .node_records
            .iter()
            .flat_map(|gnr| match database.node_by_key(&gnr.public_key()) {
                Some(existing_node) if existing_node.version() < gnr.inner.version => {
                    Some(self.update_database_record(database, gnr))
                }
                _ => None,
            })
            .collect();
        change_flags.into_iter().any(|f| f)
    }

    fn handle_root_node(&self, database: &mut NeighborhoodDatabase, gossip_source: IpAddr) -> bool {
        let gossip_node = match database.node_by_ip(&gossip_source) {
            None => return false,
            Some(node) => node,
        };
        let gossip_node_key = gossip_node.public_key().clone();
        match database.add_half_neighbor(&gossip_node_key) {
            Err(_) => false,
            Ok(false) => false,
            Ok(true) => {
                database.root_mut().increment_version();
                true
            }
        }
    }

    fn make_debuts(
        &self,
        database: &NeighborhoodDatabase,
        gossip: &Gossip,
        gossip_source: IpAddr,
    ) -> Vec<(Gossip, PublicKey, NodeAddr)> {
        let all_keys = database
            .keys()
            .into_iter()
            .map(|x| x.clone())
            .collect::<HashSet<PublicKey>>();
        let debut_gossip = GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build();
        gossip
            .node_records
            .iter()
            .filter(|gnr| !all_keys.contains(&gnr.public_key()))
            .filter(|gnr| match &gnr.inner.node_addr_opt {
                Some(node_addr) => {
                    !node_addr.ports().is_empty() && (node_addr.ip_addr() != gossip_source)
                }
                None => false,
            })
            .map(|gnr| {
                (
                    debut_gossip.clone(),
                    gnr.public_key(),
                    gnr.inner
                        .node_addr_opt
                        .as_ref()
                        .expect("Disappeared!")
                        .clone(),
                )
            })
            .collect::<Vec<(Gossip, PublicKey, NodeAddr)>>()
    }

    //////

    fn make_acceptance_gossip_opt(
        &self,
        database: &NeighborhoodDatabase,
        debuting_node: &NodeRecord,
    ) -> Vec<(Gossip, PublicKey, NodeAddr)> {
        let mut neighbor_keys = database.root().half_neighbor_keys();
        neighbor_keys.remove(debuting_node.public_key());
        let least_connected_neighbor_key =
            Self::find_least_connected_neighbor_excluding(database, debuting_node.public_key());
        least_connected_neighbor_key
            .map(|least_connected_neighbor_key| {
                let node_addr = debuting_node
                    .node_addr_opt()
                    .expect("NodeAddr disappeared!");
                (
                    GossipBuilder::new(database)
                        .node(database.root().public_key(), true)
                        .node(least_connected_neighbor_key, true)
                        .build(),
                    debuting_node.public_key().clone(),
                    node_addr,
                )
            })
            .into_iter()
            .collect()
    }

    fn find_least_connected_neighbor(database: &NeighborhoodDatabase) -> Option<&PublicKey> {
        Self::root_neighbors_ordered_by_degree(database)
            .first()
            .map(|lcn| *lcn)
    }

    fn find_least_connected_neighbor_excluding<'a>(
        database: &'a NeighborhoodDatabase,
        excluded: &'a PublicKey,
    ) -> Option<&'a PublicKey> {
        let mut keys = database.root().half_neighbor_keys();
        keys.remove(excluded);
        Self::keys_ordered_by_degree(database, keys)
            .first()
            .map(|lcn| *lcn)
    }

    fn root_neighbors_ordered_by_degree(database: &NeighborhoodDatabase) -> Vec<&PublicKey> {
        Self::keys_ordered_by_degree(database, database.root().half_neighbor_keys())
    }

    fn keys_ordered_by_degree<'a>(
        database: &NeighborhoodDatabase,
        keys: HashSet<&'a PublicKey>,
    ) -> Vec<&'a PublicKey> {
        let mut non_bootstrap_neighbor_keys_vec = keys
            .into_iter()
            .filter(|k| match database.node_by_key(*k) {
                None => true,
                Some(n) => n.is_not_bootstrap_node(),
            })
            .collect::<Vec<&PublicKey>>();
        non_bootstrap_neighbor_keys_vec.sort_unstable_by(|a, b| {
            database
                .gossip_target_degree(*a)
                .cmp(&database.gossip_target_degree(*b))
        });
        non_bootstrap_neighbor_keys_vec
    }

    fn make_pass_gossip(database: &NeighborhoodDatabase, pass_target: &PublicKey) -> Gossip {
        GossipBuilder::new(database).node(pass_target, true).build()
    }

    fn update_database_record(
        &self,
        database: &mut NeighborhoodDatabase,
        gnr: &GossipNodeRecord,
    ) -> bool {
        let node_record = database
            .node_by_key_mut(&gnr.public_key())
            .expect("Node magically disappeared");
        match (node_record.node_addr_opt(), gnr.inner.node_addr_opt.clone()) {
            (None, Some(new_node_addr)) => {
                node_record
                    .set_node_addr(&new_node_addr)
                    .expect("Unexpected complaint about changing NodeAddr");
            }
            _ => (), // Maybe we eventually want to detect errors here and abort the change, returning false.
        }
        node_record.inner.neighbors = gnr.inner.neighbors.clone();
        // TODO: During SC-778, take out this line: is_bootstrap_node flags shouldn't _really_ ever change. But until then, we will tell and believe lies about the Node we boot from, until it tells us differently.
        node_record.inner.is_bootstrap_node = gnr.inner.is_bootstrap_node;
        node_record.set_version(gnr.inner.version);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::neighborhood_test_utils::{db_from_node, make_node_record};
    use crate::neighborhood::node_record::NodeRecord;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::test_utils::{assert_contains, vec_to_set};
    use std::str::FromStr;

    #[test]
    fn proper_debut_is_identified() {
        let (gossip, _, gossip_source) = make_debut(2345);

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Debut, result);
    }

    #[test]
    fn debut_without_node_addr_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_debut(2345);
        gossip.node_records[0].inner.node_addr_opt = None;

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Reject, result);
    }

    #[test]
    fn debut_without_node_addr_ports_is_rejected() {
        let (mut gossip, _, gossip_source) = make_debut(2345);
        gossip.node_records[0].inner.node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &vec![],
        ));

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Reject, result);
    }

    #[test]
    fn proper_pass_is_identified() {
        let (gossip, _, gossip_source) = make_pass(2345);

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Pass, result);
    }

    #[test]
    fn pass_without_node_addr_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_pass(2345);
        gossip.node_records[0].inner.node_addr_opt = None;

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Reject, result);
    }

    #[test]
    fn pass_without_node_addr_ports_is_rejected() {
        let (mut gossip, _, gossip_source) = make_pass(2345);
        gossip.node_records[0].inner.node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &vec![],
        ));

        let result = GossipAcceptorReal::determine_type(&gossip, gossip_source);

        assert_eq!(GossipType::Reject, result);
    }

    #[test]
    fn proper_standard_gossip_is_identified() {
        let root_node = make_node_record(1234, true, false);
        let mut src_db = db_from_node(&root_node);
        let node_a_key = &src_db
            .add_node(&make_node_record(2345, true, false))
            .unwrap();
        let node_b_key = &src_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        let gossip = GossipBuilder::new(&src_db)
            .node(root_node.public_key(), true)
            .node(node_a_key, true)
            .node(node_b_key, false)
            .build();

        let result = GossipAcceptorReal::determine_type(
            &gossip,
            root_node.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(GossipType::Standard, result);
    }

    #[test]
    fn empty_gossip_is_rejected() {
        let just_a_node = make_node_record(1234, true, false);
        let gossip = Gossip {
            node_records: vec![],
        };

        let result = GossipAcceptorReal::determine_type(
            &gossip,
            just_a_node.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(GossipType::Reject, result);
    }

    #[test]
    fn rejectable_gossip_is_ignored() {
        let just_a_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&just_a_node);
        let gossip = Gossip {
            node_records: vec![],
        };
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(
            &mut db,
            &gossip,
            just_a_node.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
    }

    #[test]
    fn first_debut_is_handled() {
        let mut root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        assert_eq!(GossipAcceptanceResult::Accepted(vec![]), result);
        root_node.add_half_neighbor_key(debut_node.public_key().clone());
        root_node.increment_version();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn second_debut_is_handled() {
        let mut root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_key);
        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        let expected_acceptance_gossip = GossipBuilder::new(&dest_db)
            .node(root_node.public_key(), true)
            .node(existing_node_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Accepted(vec![(
                expected_acceptance_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap()
            )]),
            result
        );
        root_node.add_half_neighbor_key(debut_node.public_key().clone());
        root_node.add_half_neighbor_key(existing_node_key.clone());
        root_node.increment_version();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn fourth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        let existing_node_2_key = &dest_db
            .add_node(&make_node_record(4567, true, false))
            .unwrap();
        let existing_node_3_key = &dest_db
            .add_node(&make_node_record(5678, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_2_key, existing_node_3_key);

        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        let expected_acceptance_gossip_1 = GossipBuilder::new(&dest_db)
            .node(root_node.public_key(), true)
            .node(existing_node_1_key, true)
            .build();
        let expected_acceptance_gossip_2 = GossipBuilder::new(&dest_db)
            .node(root_node.public_key(), true)
            .node(existing_node_3_key, true)
            .build();
        let debut_key = debut_node.public_key().clone();
        let debut_node_addr = debut_node.node_addr_opt().as_ref().unwrap().clone();
        assert_contains(
            &vec![
                GossipAcceptanceResult::Accepted(vec![(
                    expected_acceptance_gossip_1,
                    debut_key.clone(),
                    debut_node_addr.clone(),
                )]),
                GossipAcceptanceResult::Accepted(vec![(
                    expected_acceptance_gossip_2,
                    debut_key.clone(),
                    debut_node_addr.clone(),
                )]),
            ],
            &result,
        );
        root_node.add_half_neighbor_key(debut_node.public_key().clone());
        root_node.add_half_neighbor_key(existing_node_1_key.clone());
        root_node.add_half_neighbor_key(existing_node_2_key.clone());
        root_node.add_half_neighbor_key(existing_node_3_key.clone());
        root_node.increment_version();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn fifth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        let existing_node_2_key = &dest_db
            .add_node(&make_node_record(4567, true, false))
            .unwrap();
        let existing_node_3_key = &dest_db
            .add_node(&make_node_record(5678, true, false))
            .unwrap();
        let existing_node_4_key = &dest_db
            .add_node(&make_node_record(6789, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_4_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_2_key, existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_3_key, existing_node_4_key);

        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        let expected_acceptance_gossip_2 = GossipBuilder::new(&dest_db)
            .node(existing_node_2_key, true)
            .build();
        let expected_acceptance_gossip_3 = GossipBuilder::new(&dest_db)
            .node(existing_node_3_key, true)
            .build();
        assert_contains(
            &vec![
                GossipAcceptanceResult::Relay(
                    expected_acceptance_gossip_2,
                    debut_node.public_key().clone(),
                    debut_node.node_addr_opt().unwrap(),
                ),
                GossipAcceptanceResult::Relay(
                    expected_acceptance_gossip_3,
                    debut_node.public_key().clone(),
                    debut_node.node_addr_opt().unwrap(),
                ),
            ],
            &result,
        );
        root_node.add_half_neighbor_key(existing_node_1_key.clone());
        root_node.add_half_neighbor_key(existing_node_2_key.clone());
        root_node.add_half_neighbor_key(existing_node_3_key.clone());
        root_node.add_half_neighbor_key(existing_node_4_key.clone());
        assert_eq!(&root_node, dest_db.root());
    }

    #[test]
    fn debut_when_degree_is_five_is_passed_to_least_connected_neighbor() {
        let mut root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        let existing_node_2_key = &dest_db
            .add_node(&make_node_record(4567, true, false))
            .unwrap();
        let existing_node_3_key = &dest_db
            .add_node(&make_node_record(5678, true, false))
            .unwrap();
        let existing_node_4_key = &dest_db
            .add_node(&make_node_record(6789, true, false))
            .unwrap();
        let existing_node_5_key = &dest_db
            .add_node(&make_node_record(7890, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_4_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_5_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_3_key, existing_node_4_key);

        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        let expected_acceptance_gossip = GossipBuilder::new(&dest_db)
            .node(existing_node_5_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Relay(
                expected_acceptance_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap()
            ),
            result
        );
        root_node.add_half_neighbor_key(existing_node_1_key.clone());
        root_node.add_half_neighbor_key(existing_node_2_key.clone());
        root_node.add_half_neighbor_key(existing_node_3_key.clone());
        root_node.add_half_neighbor_key(existing_node_4_key.clone());
        root_node.add_half_neighbor_key(existing_node_5_key.clone());
        assert_eq!(&root_node, dest_db.root());
    }

    #[test]
    fn bootstrap_node_handles_initial_debut_properly() {
        let mut root_node = make_node_record(1234, true, true);
        let mut dest_db = db_from_node(&root_node);
        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        assert_eq!(GossipAcceptanceResult::Accepted(vec![]), result);
        root_node.add_half_neighbor_key(debut_node.public_key().clone());
        root_node.increment_version();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn bootstrap_node_handles_later_debut_properly() {
        let root_node = make_node_record(1234, true, true);
        let mut dest_db = db_from_node(&root_node);
        let relay_target_key = &dest_db
            .add_node(&make_node_record(2345, true, false))
            .unwrap();
        let one_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        let two_key = &dest_db
            .add_node(&make_node_record(4567, true, false))
            .unwrap();
        let three_key = &dest_db
            .add_node(&make_node_record(5678, true, false))
            .unwrap();
        let four_key = &dest_db
            .add_node(&make_node_record(6789, true, false))
            .unwrap();
        let five_key = &dest_db
            .add_node(&make_node_record(7890, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), relay_target_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), one_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), two_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), three_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), four_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), five_key);
        dest_db.add_arbitrary_full_neighbor(one_key, two_key);
        dest_db.add_arbitrary_full_neighbor(two_key, three_key);
        dest_db.add_arbitrary_full_neighbor(three_key, four_key);
        dest_db.add_arbitrary_full_neighbor(four_key, five_key);
        let (gossip, debut_node, gossip_source) = make_debut(8901);
        let subject = GossipAcceptorReal::new();
        let mut root_node = dest_db.root().clone();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        let relay_gossip = GossipAcceptorReal::make_pass_gossip(&dest_db, relay_target_key);
        assert_eq!(
            GossipAcceptanceResult::Accepted(vec![(
                relay_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap()
            )]),
            result
        );
        root_node.add_half_neighbor_key(debut_node.public_key().clone());
        root_node.increment_version();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn redebut_is_ignored() {
        init_test_logging();
        let root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_key = &dest_db
            .add_node(&make_node_record(3456, true, false))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_key);
        let (gossip, debut_node, gossip_source) = make_debut(3456);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut dest_db, &gossip, gossip_source);

        assert_eq!(GossipAcceptanceResult::Ignored, result);
        TestLogHandler::new ().exists_log_containing (format! ("WARN: GossipAcceptor: Ignored re-debut from Node {}, which is already in the database", debut_node.public_key()).as_str());
    }

    #[test]
    fn pass_is_properly_handled() {
        let root_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&root_node);
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(&mut db, &gossip, gossip_source);

        let expected_relay_gossip = GossipBuilder::new(&db)
            .node(root_node.public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Relay(
                expected_relay_gossip,
                pass_target.public_key().clone(),
                pass_target.node_addr_opt().unwrap()
            ),
            result
        );
        assert_eq!(1, db.keys().len());
    }

    #[test]
    fn standard_gossip_containing_introductions_is_properly_handled() {
        let root_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&root_node);
        let node_a = make_node_record(2345, true, false);
        let mut src_db = db_from_node(&node_a);
        let node_b = make_node_record(3456, true, false);
        let node_c = make_node_record(4567, false, false);
        let node_d = make_node_record(5678, false, false);
        let node_e = make_node_record(6789, true, false);
        let node_f = make_node_record(7890, true, false);
        dest_db.add_node(&node_a).unwrap();
        dest_db.add_node(&node_b).unwrap();
        dest_db.add_node(&node_d).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), node_a.public_key());
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), node_b.public_key());
        dest_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        dest_db.add_arbitrary_full_neighbor(node_b.public_key(), node_d.public_key());
        // TODO: During SC-778, take out this modification. Until then, the fact that root_node is booting from node_a means it thinks node_a is a bootstrap Node.
        dest_db
            .node_by_key_mut(node_a.public_key())
            .unwrap()
            .inner
            .is_bootstrap_node = true;
        src_db.add_node(&node_b).unwrap();
        src_db.add_node(&node_c).unwrap();
        src_db.add_node(&node_e).unwrap();
        src_db.add_node(&node_f).unwrap();
        src_db.add_node(&root_node).unwrap();
        src_db
            .node_by_key_mut(node_a.public_key())
            .unwrap()
            .increment_version();
        src_db
            .node_by_key_mut(node_b.public_key())
            .unwrap()
            .increment_version();
        src_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        src_db.add_arbitrary_full_neighbor(node_a.public_key(), node_e.public_key());
        src_db.add_arbitrary_full_neighbor(node_a.public_key(), node_f.public_key());
        src_db.add_arbitrary_full_neighbor(node_a.public_key(), root_node.public_key());
        src_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        src_db.add_arbitrary_full_neighbor(node_b.public_key(), root_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(node_a.public_key(), true)
            .node(node_b.public_key(), false)
            .node(node_c.public_key(), false)
            .node(node_e.public_key(), true)
            .node(node_f.public_key(), true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(
            &mut dest_db,
            &gossip,
            node_a.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(
            GossipAcceptanceResult::Accepted(vec![
                (
                    GossipBuilder::new(&dest_db)
                        .node(dest_db.root().public_key(), true)
                        .build(),
                    node_e.public_key().clone(),
                    node_e.node_addr_opt().unwrap().clone(),
                ),
                (
                    GossipBuilder::new(&dest_db)
                        .node(dest_db.root().public_key(), true)
                        .build(),
                    node_f.public_key().clone(),
                    node_f.node_addr_opt().unwrap().clone(),
                )
            ]),
            result
        );
        let mut expected_dest_db = src_db.clone();
        expected_dest_db.remove_arbitrary_half_neighbor(node_e.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_f.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_b.public_key(), node_d.public_key());
        expected_dest_db.add_node(&node_d).unwrap();
        expected_dest_db.add_arbitrary_half_neighbor(node_d.public_key(), node_b.public_key());
        assert_eq!(
            expected_dest_db
                .node_by_key(root_node.public_key())
                .unwrap(),
            dest_db.node_by_key(root_node.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db.node_by_key(node_a.public_key()).unwrap(),
            dest_db.node_by_key(node_a.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db.node_by_key(node_b.public_key()).unwrap(),
            dest_db.node_by_key(node_b.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db.node_by_key(node_c.public_key()).unwrap(),
            dest_db.node_by_key(node_c.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db.node_by_key(node_d.public_key()).unwrap(),
            dest_db.node_by_key(node_d.public_key()).unwrap()
        );
        assert_eq!(None, dest_db.node_by_key(node_e.public_key()));
        assert_eq!(None, dest_db.node_by_key(node_f.public_key()));
    }

    #[test]
    fn standard_gossip_does_not_stimulate_introduction_response_for_gossip_source() {
        let dest_node = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&dest_node);
        let src_node = make_node_record(2345, true, false);
        let mut src_db = db_from_node(&src_node);
        let third_node = make_node_record(3456, true, false);
        dest_db.add_node(&third_node).unwrap();
        src_db.add_node(&dest_node).unwrap();
        src_db.add_node(&third_node).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), third_node.public_key());
        src_db.add_arbitrary_full_neighbor(dest_node.public_key(), third_node.public_key());
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), third_node.public_key());
        src_db
            .node_by_key_mut(src_node.public_key())
            .unwrap()
            .increment_version();
        src_db
            .node_by_key_mut(third_node.public_key())
            .unwrap()
            .increment_version();
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(third_node.public_key(), true)
            .build();
        let subject = GossipAcceptorReal::new();

        let result = subject.handle(
            &mut dest_db,
            &gossip,
            src_node.node_addr_opt().unwrap().ip_addr(),
        );

        let mut expected_dest_db = src_db.clone();
        expected_dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), src_node.public_key());
        expected_dest_db
            .node_by_key_mut(dest_node.public_key())
            .unwrap()
            .increment_version();
        assert_eq!(GossipAcceptanceResult::Accepted(vec![]), result);
        assert_eq!(
            expected_dest_db
                .node_by_key(third_node.public_key())
                .unwrap(),
            dest_db.node_by_key(third_node.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db.node_by_key(src_node.public_key()).unwrap(),
            dest_db.node_by_key(src_node.public_key()).unwrap()
        );
        assert_eq!(
            expected_dest_db
                .node_by_key(dest_node.public_key())
                .unwrap(),
            dest_db.node_by_key(dest_node.public_key()).unwrap()
        );
    }

    #[test]
    fn standard_gossip_with_current_and_obsolete_versions_doesnt_change_anything() {
        let dest_root = make_node_record(1234, true, false);
        let mut dest_db = db_from_node(&dest_root);
        let src_root = make_node_record(2345, true, false);
        let mut src_db = db_from_node(&src_root);
        let mut current_node = make_node_record(3456, true, false);
        let mut obsolete_node = make_node_record(4567, false, false);
        current_node.set_version(100);
        obsolete_node.set_version(100);
        dest_db.add_node(&src_root).unwrap();
        dest_db.add_node(&current_node).unwrap();
        dest_db.add_node(&obsolete_node).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), current_node.public_key());
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), obsolete_node.public_key());
        dest_db.add_arbitrary_full_neighbor(src_root.public_key(), current_node.public_key());
        dest_db.add_arbitrary_full_neighbor(src_root.public_key(), obsolete_node.public_key());
        obsolete_node.set_version(99);
        src_db.add_node(&dest_root).unwrap();
        src_db.add_node(&current_node).unwrap();
        src_db.add_node(&obsolete_node).unwrap();
        src_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        src_db.add_arbitrary_full_neighbor(dest_root.public_key(), current_node.public_key());
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), obsolete_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .node(current_node.public_key(), false)
            .node(obsolete_node.public_key(), false)
            .build();
        let subject = GossipAcceptorReal::new();
        let original_dest_db = dest_db.clone();

        let result = subject.handle(
            &mut dest_db,
            &gossip,
            src_root.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
        assert_eq!(
            original_dest_db
                .node_by_key(dest_root.public_key())
                .unwrap(),
            dest_db.node_by_key(dest_root.public_key()).unwrap()
        );
        assert_eq!(
            original_dest_db.node_by_key(src_root.public_key()).unwrap(),
            dest_db.node_by_key(src_root.public_key()).unwrap()
        );
        assert_eq!(
            original_dest_db
                .node_by_key(current_node.public_key())
                .unwrap(),
            dest_db.node_by_key(current_node.public_key()).unwrap()
        );
        assert_eq!(
            original_dest_db
                .node_by_key(obsolete_node.public_key())
                .unwrap(),
            dest_db.node_by_key(obsolete_node.public_key()).unwrap()
        );
    }

    #[test]
    fn make_debuts_chooses_properly() {
        let root_node = make_node_record(1234, true, false);
        let no_node_addr = make_node_record(2345, false, false);
        let valid_target = make_node_record(4567, true, false);
        let existing_neighbor = make_node_record(5678, true, false);
        let gossip_source = make_node_record(6789, true, false);
        let mut src_db = db_from_node(&root_node);
        src_db.add_node(&no_node_addr).unwrap();
        src_db.add_node(&valid_target).unwrap();
        src_db.add_node(&gossip_source).unwrap();
        let incoming_gossip = GossipBuilder::new(&src_db)
            .node(root_node.public_key(), true)
            .node(no_node_addr.public_key(), true)
            .node(valid_target.public_key(), true)
            .node(gossip_source.public_key(), true)
            .build();
        let mut dest_db = db_from_node(&root_node);
        dest_db.add_node(&existing_neighbor).unwrap();
        dest_db.add_arbitrary_half_neighbor(root_node.public_key(), existing_neighbor.public_key());
        let subject = GossipAcceptorReal::new();

        let result = subject.make_debuts(
            &dest_db,
            &incoming_gossip,
            gossip_source.node_addr_opt().unwrap().ip_addr(),
        );

        let (gossip, public_key, node_addr) = &result[0];
        assert_eq!(1, result.len());
        assert_eq!(valid_target.public_key(), public_key);
        assert_eq!(valid_target.node_addr_opt().unwrap(), *node_addr);
        let gnr = gossip.node_records[0].clone();
        assert_eq!(1, gossip.node_records.len());
        assert_eq!(root_node.public_key(), &gnr.public_key());
        assert_eq!(root_node.node_addr_opt(), gnr.inner.node_addr_opt);
        assert_eq!(
            vec_to_set(vec![existing_neighbor.public_key().clone()]),
            gnr.inner.neighbors.clone()
        );
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_twos_and_finds_three() {
        let root_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key =
            &db.add_node(&make_node_record(2345, true, false)).unwrap();
        let other_neighbor_1_key = &db.add_node(&make_node_record(3456, true, false)).unwrap();
        let other_neighbor_2_key = &db.add_node(&make_node_record(4567, true, false)).unwrap();
        let other_neighbor_3_key = &db.add_node(&make_node_record(5678, true, false)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        let subject = GossipAcceptorReal::new();

        let result = subject.find_more_appropriate_neighbor(&db);

        assert_eq!(Some(less_connected_neighbor_key), result);
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_if_all_neighbors_are_connected_as_well_as_me() {
        let root_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key =
            &db.add_node(&make_node_record(2345, true, false)).unwrap();
        let other_neighbor_1_key = &db.add_node(&make_node_record(3456, true, false)).unwrap();
        let other_neighbor_2_key = &db.add_node(&make_node_record(4567, true, false)).unwrap();
        let other_neighbor_3_key = &db.add_node(&make_node_record(5678, true, false)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_3_key);
        let subject = GossipAcceptorReal::new();

        let result = subject.find_more_appropriate_neighbor(&db);

        assert_eq!(None, result);
    }

    #[test]
    fn root_neighbors_ordered_by_degree_ignores_bootstrap_nodes() {
        let root_node = make_node_record(1234, true, false);
        let mut db = db_from_node(&root_node);
        let near_bootstrap_key = &db.add_node(&make_node_record(2345, true, true)).unwrap();
        let far_bootstrap_key = &db.add_node(&make_node_record(3456, true, true)).unwrap();
        let distant_node_key = &db.add_node(&make_node_record(4567, true, false)).unwrap();
        let high_degree_key = &db.add_node(&make_node_record(5678, true, false)).unwrap();
        let low_degree_key = &db.add_node(&make_node_record(6789, true, false)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), near_bootstrap_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), high_degree_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), low_degree_key);
        db.add_arbitrary_full_neighbor(high_degree_key, distant_node_key);
        db.add_arbitrary_full_neighbor(low_degree_key, near_bootstrap_key);
        db.add_arbitrary_full_neighbor(low_degree_key, far_bootstrap_key);

        let result = GossipAcceptorReal::root_neighbors_ordered_by_degree(&db);

        assert_eq!(vec![low_degree_key, high_degree_key], result)
    }

    fn make_debut(n: u16) -> (Gossip, NodeRecord, IpAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n);
        let gossip_source = debut_node.node_addr_opt().unwrap().ip_addr();
        (gossip, debut_node, gossip_source)
    }

    fn make_pass(n: u16) -> (Gossip, NodeRecord, IpAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n);
        (
            gossip,
            debut_node,
            IpAddr::from_str("200.200.200.200").unwrap(),
        )
    }

    fn make_single_node_gossip(n: u16) -> (Gossip, NodeRecord) {
        let debut_node = make_node_record(n, true, false);
        let src_db = db_from_node(&debut_node);
        let gossip = GossipBuilder::new(&src_db)
            .node(debut_node.public_key(), true)
            .build();
        (gossip, debut_node)
    }
}
