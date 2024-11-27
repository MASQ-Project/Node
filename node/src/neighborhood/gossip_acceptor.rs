// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::{GossipBuilder, GossipNodeRecord, Gossip_0v1};
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::node_record::NodeRecord;
use crate::neighborhood::{AccessibleGossipRecord, UserExitPreferences};
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::neighborhood::{
    ConnectionProgressEvent, ConnectionProgressMessage, GossipFailure_0v1, NeighborhoodMetadata,
};
use crate::sub_lib::node_addr::NodeAddr;
use masq_lib::logger::Logger;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

/// Note: if you decide to change this, make sure you test thoroughly. Values less than 5 may lead
/// to inability to grow the network beyond a very small size; values greater than 5 may lead to
/// Gossip storms.
pub const MAX_DEGREE: usize = 5;
// In case we meet a pass target after this duration, we would treat
// pass target as if we met it for the first time.
const PASS_GOSSIP_EXPIRED_TIME: Duration = Duration::from_secs(60);

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GossipAcceptanceResult {
    // The incoming Gossip produced database changes. Generate standard Gossip and broadcast.
    Accepted,
    // Don't generate Gossip from the database: instead, send this Gossip to the provided key and NodeAddr.
    Reply(Gossip_0v1, PublicKey, NodeAddr),
    // The incoming Gossip was proper, and we tried to accept it, but couldn't.
    Failed(GossipFailure_0v1, PublicKey, NodeAddr),
    // The incoming Gossip contained nothing we didn't know. Don't send out any Gossip because of it.
    Ignored,
    // Gossip was ignored because it was evil: ban the sender of the Gossip as a malefactor.
    Ban(String),
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Qualification {
    Matched,
    Unmatched,
    Malformed(String),
}

trait NamedType {
    fn type_name(&self) -> &'static str;
}

trait GossipHandler: NamedType + Send /* Send because lazily-written tests require it */ {
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification;
    fn handle(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult;
}

struct DebutHandler {
    logger: Logger,
}

impl NamedType for DebutHandler {
    fn type_name(&self) -> &'static str {
        "DebutHandler"
    }
}

impl GossipHandler for DebutHandler {
    // A Debut must contain a single AGR; it must provide its IP address if it accepts connections;
    // it must specify at least one port; it must be sourced by the debuting Node;
    // and it must not already be in our database.
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification {
        if agrs.len() != 1 {
            return Qualification::Unmatched;
        }
        if database.node_by_key(&agrs[0].inner.public_key).is_some() {
            return Qualification::Unmatched;
        }
        match &agrs[0].node_addr_opt {
            None => {
                if agrs[0].inner.accepts_connections {
                    Qualification::Malformed(format!(
                        "Debut from {} for {} contained no NodeAddr",
                        gossip_source, agrs[0].inner.public_key
                    ))
                } else {
                    Qualification::Matched
                }
            }
            Some(node_addr) => {
                if agrs[0].inner.accepts_connections {
                    if node_addr.ports().is_empty() {
                        Qualification::Malformed(format!(
                            "Debut from {} for {} contained NodeAddr with no ports",
                            gossip_source, agrs[0].inner.public_key
                        ))
                    } else if node_addr.ip_addr() == gossip_source.ip() {
                        Qualification::Matched
                    } else {
                        Qualification::Unmatched
                    }
                } else {
                    Qualification::Malformed(format!(
                        "Debut from {} for {} does not accept connections, yet contained NodeAddr",
                        gossip_source, agrs[0].inner.public_key
                    ))
                }
            }
        }
    }

    fn handle(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        mut agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        let source_agr = {
            let mut agr = agrs.remove(0); // empty Gossip shouldn't get here
            if agr.node_addr_opt.is_none() {
                agr.node_addr_opt = Some(NodeAddr::from(&gossip_source));
            }
            agr
        };
        let source_key = source_agr.inner.public_key.clone();
        let source_node_addr = source_agr
            .node_addr_opt
            .as_ref()
            .expect("Source Node NodeAddr disappeared")
            .clone();
        if let Some(preferred_key) = self.find_more_appropriate_neighbor(database, &source_agr) {
            let preferred_ip = database
                .node_by_key(preferred_key)
                .expect("Preferred Node disappeared")
                .node_addr_opt()
                .expect("Preferred Node's NodeAddr disappeared")
                .ip_addr();
            debug!(self.logger,
                "DebutHandler is commissioning Pass of {} at {} to more appropriate neighbor {} at {}",
                source_key,
                gossip_source,
                preferred_key,
                preferred_ip,
            );
            return GossipAcceptanceResult::Reply(
                Self::make_pass_gossip(database, preferred_key),
                source_key,
                source_node_addr,
            );
        }
        if let Ok(result) = self.try_accept_debut(
            cryptde,
            database,
            &source_agr,
            gossip_source,
            neighborhood_metadata.user_exit_preferences_opt,
        ) {
            return result;
        }
        debug!(self.logger, "Seeking neighbor for Pass");
        let lcn_key = match Self::find_least_connected_half_neighbor_excluding(
            database,
            &source_agr,
        ) {
            None => {
                debug!(self.logger,
                    "Neighbor count at maximum, but no non-common neighbors. DebutHandler is reluctantly ignoring debut from {} at {}",
                    source_key, source_node_addr
                );
                return GossipAcceptanceResult::Failed(
                    GossipFailure_0v1::NoSuitableNeighbors,
                    (&source_agr.inner.public_key).clone(),
                    (&source_agr
                        .node_addr_opt
                        .expect("Debuter's NodeAddr disappeared"))
                        .clone(),
                );
            }
            Some(key) => key,
        };
        let lcn_ip_str = match database
            .node_by_key(lcn_key)
            .expect("LCN Disappeared")
            .node_addr_opt()
        {
            Some(node_addr) => node_addr.ip_addr().to_string(),
            None => "?.?.?.?".to_string(),
        };
        debug!(
            self.logger,
            "DebutHandler is commissioning Pass of {} at {} to {} at {}",
            source_key,
            source_node_addr.ip_addr(),
            lcn_key,
            lcn_ip_str
        );
        GossipAcceptanceResult::Reply(
            Self::make_pass_gossip(database, lcn_key),
            source_key,
            source_node_addr,
        )
    }
}

impl DebutHandler {
    fn new(logger: Logger) -> DebutHandler {
        DebutHandler { logger }
    }

    fn find_more_appropriate_neighbor<'b>(
        &self,
        database: &'b NeighborhoodDatabase,
        excluded: &'b AccessibleGossipRecord,
    ) -> Option<&'b PublicKey> {
        let neighbor_vec =
            Self::root_full_neighbors_ordered_by_degree_excluding(database, excluded);
        let qualified_neighbors: Vec<&PublicKey> = neighbor_vec
            .into_iter()
            .filter(|k| {
                database
                    .node_by_key(*k)
                    .expect("Node disappeared")
                    .accepts_connections()
            })
            .skip_while(|k| database.gossip_target_degree(*k) <= 2)
            .collect();
        match qualified_neighbors.first().cloned() {
            // No neighbors of degree 3 or greater
            None => {
                debug!(
                    self.logger,
                    "No degree-3-or-greater neighbors; can't find more-appropriate neighbor.",
                );
                None
            }
            // Neighbor of degree 3 or greater, but not less connected than I am
            Some(key)
                if database.gossip_target_degree(key)
                    >= database.gossip_target_degree(database.root().public_key()) =>
            {
                debug!(self.logger, "No neighbors of degree 3 or greater are less-connected than this Node: can't find more-appropriate neighbor");
                None
            }
            // Neighbor of degree 3 or greater less connected than I am
            Some(key) => {
                debug!(self.logger, "Found more-appropriate neighbor");
                Some(key)
            }
        }
    }

    fn try_accept_debut(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        debuting_agr: &AccessibleGossipRecord,
        gossip_source: SocketAddr,
        user_exit_preferences_opt: Option<UserExitPreferences>,
    ) -> Result<GossipAcceptanceResult, ()> {
        if database.gossip_target_degree(database.root().public_key()) >= MAX_DEGREE {
            debug!(self.logger, "Neighbor count already at maximum");
            return Err(());
        }
        let debut_node_addr_opt = debuting_agr.node_addr_opt.clone();
        let mut debuting_node = NodeRecord::from(debuting_agr);
        match user_exit_preferences_opt {
            Some(user_exit_preferences) => {
                //TODO 788 check if country code is present in Neighborhood DB and if yes, perform assign country code to exit_countries without duplication
                user_exit_preferences.assign_nodes_country_undesirability(&mut debuting_node);
            }
            None => (),
        }

        // TODO 468 make debuting_node mut and add country_undesirability to its metadata
        let debut_node_key = database
            .add_node(debuting_node)
            .expect("Debuting Node suddenly appeared in database");
        match database.add_half_neighbor(&debut_node_key) {
            Err(NeighborhoodDatabaseError::NodeKeyNotFound(k)) => {
                panic!("Node {} magically disappeared", k)
            }
            Err(e) => panic!(
                "Unexpected error accepting debut from {}/{:?}: {:?}",
                debut_node_key, debut_node_addr_opt, e
            ),
            Ok(true) => {
                let root_mut = database.root_mut();
                root_mut.increment_version();
                root_mut.regenerate_signed_gossip(cryptde);
                trace!(self.logger, "Current database: {}", database.to_dot_graph());
                if Self::should_not_make_another_introduction(debuting_agr) {
                    let ip_addr_str = match &debuting_agr.node_addr_opt {
                        Some(node_addr) => node_addr.ip_addr().to_string(),
                        None => "?.?.?.?".to_string(),
                    };
                    debug!(self.logger, "Node {} at {} is responding to first introduction: sending standard Gossip instead of further introduction",
                                              debuting_agr.inner.public_key,
                                              ip_addr_str);
                    Ok(GossipAcceptanceResult::Accepted)
                } else {
                    match self.make_introduction(database, debuting_agr, gossip_source) {
                        Some((introduction, target_key, target_node_addr)) => {
                            Ok(GossipAcceptanceResult::Reply(
                                introduction,
                                target_key,
                                target_node_addr,
                            ))
                        }
                        None => {
                            debug!(
                                self.logger,
                                "DebutHandler has no one to introduce, but is debuting back to {} at {}",
                                &debut_node_key,
                                gossip_source,
                            );
                            trace!(
                                self.logger,
                                "DebutHandler database state: {}",
                                &database.to_dot_graph(),
                            );
                            let debut_gossip = Self::create_debut_gossip_response(
                                cryptde,
                                database,
                                debut_node_key,
                            );
                            Ok(GossipAcceptanceResult::Reply(
                                debut_gossip,
                                debuting_agr.inner.public_key.clone(),
                                debuting_agr
                                    .node_addr_opt
                                    .as_ref()
                                    .expect("Debut gossip always has an IP")
                                    .clone(),
                            ))
                        }
                    }
                }
            }
            Ok(false) => panic!("Brand-new neighbor already existed"),
        }
    }

    fn create_debut_gossip_response(
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        debut_node_key: PublicKey,
    ) -> Gossip_0v1 {
        let mut root_node = database.root().clone();
        root_node.clear_half_neighbors();
        root_node
            .add_half_neighbor_key(debut_node_key.clone())
            .unwrap_or_else(|e| {
                panic!(
                    "Couldn't add debuting {} as a half neighbor: {:?}",
                    debut_node_key, e
                )
            });
        let root_node_addr_opt = root_node.node_addr_opt();
        let gnr = GossipNodeRecord::from((root_node.inner, root_node_addr_opt, cryptde));
        Gossip_0v1 {
            node_records: vec![gnr],
        }
    }

    fn make_introduction(
        &self,
        database: &NeighborhoodDatabase,
        debuting_agr: &AccessibleGossipRecord,
        gossip_source: SocketAddr,
    ) -> Option<(Gossip_0v1, PublicKey, NodeAddr)> {
        if let Some(lcn_key) =
            Self::find_least_connected_full_neighbor_excluding(database, debuting_agr)
        {
            let lcn_node_addr_str = match database
                .node_by_key(lcn_key)
                .expect("LCN disappeared")
                .node_addr_opt()
            {
                Some(node_addr) => node_addr.to_string(),
                None => "?.?.?.?:?".to_string(),
            };
            let debut_node_addr = match &debuting_agr.node_addr_opt {
                Some(node_addr) => node_addr.clone(),
                None => NodeAddr::from(&gossip_source),
            };
            debug!(
                self.logger,
                "DebutHandler commissioning Introduction of {} at {} to {} at {}",
                lcn_key,
                lcn_node_addr_str,
                &debuting_agr.inner.public_key,
                debut_node_addr
            );
            Some((
                GossipBuilder::new(database)
                    .node(database.root().public_key(), true)
                    .node(lcn_key, true)
                    .build(),
                debuting_agr.inner.public_key.clone(),
                debut_node_addr,
            ))
        } else {
            None
        }
    }

    fn find_least_connected_half_neighbor_excluding<'b>(
        database: &'b NeighborhoodDatabase,
        excluded: &'b AccessibleGossipRecord,
    ) -> Option<&'b PublicKey> {
        Self::find_least_connected_neighbor_excluding(
            database.root().half_neighbor_keys(),
            database,
            excluded,
        )
    }

    fn find_least_connected_full_neighbor_excluding<'b>(
        database: &'b NeighborhoodDatabase,
        excluded: &'b AccessibleGossipRecord,
    ) -> Option<&'b PublicKey> {
        Self::find_least_connected_neighbor_excluding(
            database
                .root()
                .full_neighbor_keys(database)
                .into_iter()
                .filter(|k| {
                    database
                        .node_by_key(*k)
                        .expect("Node disappeared")
                        .accepts_connections()
                })
                .collect(),
            database,
            excluded,
        )
    }

    fn find_least_connected_neighbor_excluding<'b>(
        keys: HashSet<&'b PublicKey>,
        database: &'b NeighborhoodDatabase,
        excluded: &'b AccessibleGossipRecord,
    ) -> Option<&'b PublicKey> {
        let excluded_keys = Self::node_and_neighbor_keys(excluded);
        Self::keys_ordered_by_degree_excluding(database, keys, excluded_keys)
            .first()
            .cloned()
    }

    fn keys_ordered_by_degree_excluding<'b>(
        database: &'b NeighborhoodDatabase,
        keys: HashSet<&'b PublicKey>,
        excluding: HashSet<&'b PublicKey>,
    ) -> Vec<&'b PublicKey> {
        let mut neighbor_keys_vec: Vec<&PublicKey> = keys.difference(&excluding).cloned().collect();
        neighbor_keys_vec.sort_unstable_by(|a, b| {
            database
                .gossip_target_degree(*a)
                .cmp(&database.gossip_target_degree(*b))
        });
        neighbor_keys_vec
    }

    fn root_full_neighbors_ordered_by_degree_excluding<'b>(
        database: &'b NeighborhoodDatabase,
        excluded: &'b AccessibleGossipRecord,
    ) -> Vec<&'b PublicKey> {
        let excluded_keys = Self::node_and_neighbor_keys(excluded);
        Self::keys_ordered_by_degree_excluding(
            database,
            database.root().full_neighbor_keys(database),
            excluded_keys,
        )
    }

    fn node_and_neighbor_keys(agr: &AccessibleGossipRecord) -> HashSet<&PublicKey> {
        let mut keys = HashSet::new();
        keys.insert(&agr.inner.public_key);
        for key_ref in &agr.inner.neighbors {
            keys.insert(key_ref);
        }
        keys
    }

    fn should_not_make_another_introduction(debuting_agr: &AccessibleGossipRecord) -> bool {
        !debuting_agr.inner.neighbors.is_empty()
    }

    fn make_pass_gossip(database: &NeighborhoodDatabase, pass_target: &PublicKey) -> Gossip_0v1 {
        GossipBuilder::new(database).node(pass_target, true).build()
    }
}

#[derive(PartialEq, Debug)]
struct PassHandler {
    // previous_pass_targets is used to stop the cycle of infinite pass gossips
    // in case it receives an ip address that is already a part of this hash set.
    // previous_pass_targets: HashSet<IpAddr>,
    previous_pass_targets: RefCell<HashMap<IpAddr, SystemTime>>,
}

impl NamedType for PassHandler {
    fn type_name(&self) -> &'static str {
        "PassHandler"
    }
}

impl GossipHandler for PassHandler {
    // A Pass must contain a single AGR representing the pass target; it must provide its IP address;
    // it must specify at least one port; and it must _not_ be sourced by the pass target.
    fn qualifies(
        &self,
        _database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification {
        if agrs.len() != 1 {
            return Qualification::Unmatched;
        }
        match &agrs[0].node_addr_opt {
            None => Qualification::Malformed(format!(
                "Pass from {} to {} did not contain NodeAddr",
                gossip_source, agrs[0].inner.public_key
            )),
            Some(node_addr) => {
                if node_addr.ports().is_empty() {
                    Qualification::Malformed(format!(
                        "Pass from {} to {} at {} contained NodeAddr with no ports",
                        gossip_source,
                        agrs[0].inner.public_key,
                        node_addr.ip_addr()
                    ))
                } else if node_addr.ip_addr() == gossip_source.ip() {
                    Qualification::Unmatched
                } else {
                    Qualification::Matched
                }
            }
        }
    }

    fn handle(
        &self,
        _cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        _gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        let pass_agr = &agrs[0]; // empty Gossip shouldn't get here
        let pass_target_node_addr: NodeAddr = pass_agr
            .node_addr_opt
            .clone()
            .expect("Pass lost its NodeAddr");
        let pass_target_ip_addr = pass_target_node_addr.ip_addr();
        let send_cpm = |event: ConnectionProgressEvent| {
            let connection_progress_message = ConnectionProgressMessage {
                peer_addr: _gossip_source.ip(),
                event,
            };
            neighborhood_metadata
                .cpm_recipient
                .try_send(connection_progress_message)
                .expect("System is dead.");
        };
        let gossip_acceptance_reply = || {
            let gossip = GossipBuilder::new(database)
                .node(database.root().public_key(), true)
                .build();
            GossipAcceptanceResult::Reply(
                gossip,
                pass_agr.inner.public_key.clone(),
                pass_target_node_addr,
            )
        };

        let mut hash_map = self.previous_pass_targets.borrow_mut();
        let gossip_acceptance_result = match hash_map.get_mut(&pass_target_ip_addr) {
            None => match neighborhood_metadata
                .connection_progress_peers
                .contains(&pass_target_ip_addr)
            {
                true => {
                    send_cpm(ConnectionProgressEvent::PassLoopFound);
                    GossipAcceptanceResult::Ignored
                }
                false => {
                    hash_map.insert(pass_target_ip_addr, SystemTime::now());
                    send_cpm(ConnectionProgressEvent::PassGossipReceived(
                        pass_target_ip_addr,
                    ));
                    gossip_acceptance_reply()
                }
            },
            Some(timestamp) => {
                let duration_since = SystemTime::now()
                    .duration_since(*timestamp)
                    .expect("Failed to calculate duration for pass target timestamp.");
                *timestamp = SystemTime::now();
                if duration_since <= PASS_GOSSIP_EXPIRED_TIME {
                    send_cpm(ConnectionProgressEvent::PassLoopFound);
                    GossipAcceptanceResult::Ignored
                } else {
                    send_cpm(ConnectionProgressEvent::PassGossipReceived(
                        pass_target_ip_addr,
                    ));
                    gossip_acceptance_reply()
                }
            }
        };
        gossip_acceptance_result
    }
}

impl PassHandler {
    fn new() -> PassHandler {
        PassHandler {
            previous_pass_targets: RefCell::new(Default::default()),
        }
    }
}

struct IntroductionHandler {
    logger: Logger,
}

impl NamedType for IntroductionHandler {
    fn type_name(&self) -> &'static str {
        "IntroductionHandler"
    }
}

impl GossipHandler for IntroductionHandler {
    // An Introduction must contain two AGRs, one representing the introducer and one representing
    // the introducee. Both records must provide their IP addresses. One of the IP addresses must
    // match the gossip_source. The other record's IP address must not match the gossip_source. The
    // record whose IP address does not match the gossip source must not already be in the database.
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification {
        if let Some(qual) = Self::verify_size(agrs) {
            return qual;
        }
        let (introducer, introducee) =
            match Self::order_is_introducee_introducer(agrs, gossip_source) {
                Err(qual) => return qual,
                Ok(true) => (&agrs[0], &agrs[1]),
                Ok(false) => (&agrs[1], &agrs[0]),
            };
        if let Some(qual) = Self::verify_introducer(introducer, database.root()) {
            return qual;
        };
        if let Some(qual) = Self::verify_introducee(database, introducer, introducee, gossip_source)
        {
            return qual;
        };
        Qualification::Matched
    }

    fn handle(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        if database.root().full_neighbor_keys(database).len() >= MAX_DEGREE {
            GossipAcceptanceResult::Ignored
        } else {
            let (introducer, introducee) = Self::identify_players(agrs, gossip_source)
                .expect("Introduction not properly qualified");
            let introducer_key = introducer.inner.public_key.clone();
            let introducer_ip_addr = introducer
                .node_addr_opt
                .as_ref()
                .expect("IP Address not found for the Node Addr.")
                .ip_addr();
            let introducee_ip_addr = introducee
                .node_addr_opt
                .as_ref()
                .expect("IP Address not found for the Node Addr.")
                .ip_addr();
            // TODO 468 pass the NeighborhoodMetadata into update_database
            match self.update_database(
                database,
                cryptde,
                introducer,
                neighborhood_metadata.user_exit_preferences_opt,
            ) {
                Ok(_) => (),
                Err(e) => {
                    return GossipAcceptanceResult::Ban(format!(
                        "Introducer {} tried changing immutable characteristic: {}",
                        introducer_key, e
                    ));
                }
            }
            let connection_progess_message = ConnectionProgressMessage {
                peer_addr: introducer_ip_addr,
                event: ConnectionProgressEvent::IntroductionGossipReceived(introducee_ip_addr),
            };
            neighborhood_metadata
                .cpm_recipient
                .try_send(connection_progess_message)
                .expect("Neighborhood is dead");
            let (debut, target_key, target_node_addr) =
                GossipAcceptorReal::make_debut_triple(database, &introducee)
                    .expect("Introduction not properly qualified");
            GossipAcceptanceResult::Reply(debut, target_key, target_node_addr)
        }
    }
}

impl IntroductionHandler {
    fn new(logger: Logger) -> IntroductionHandler {
        IntroductionHandler { logger }
    }

    fn verify_size(agrs: &[AccessibleGossipRecord]) -> Option<Qualification> {
        if agrs.len() != 2 {
            return Some(Qualification::Unmatched);
        }
        None
    }

    fn order_is_introducee_introducer(
        agrs_ref: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Result<bool, Qualification> {
        let first_agr = &agrs_ref[0];
        let first_ip = match first_agr.node_addr_opt.as_ref() {
            None => return Err(Qualification::Unmatched),
            Some(node_addr) => node_addr.ip_addr(),
        };
        let second_agr = &agrs_ref[1];
        let second_ip = match second_agr.node_addr_opt.as_ref() {
            None => return Err(Qualification::Unmatched),
            Some(node_addr) => node_addr.ip_addr(),
        };
        if first_ip == gossip_source.ip() {
            Ok(true)
        } else if second_ip == gossip_source.ip() {
            Ok(false)
        } else {
            Err(Qualification::Malformed(format!(
                "In Introduction, neither {} from {} nor {} from {} claims the source IP {}",
                first_agr.inner.public_key,
                first_ip,
                second_agr.inner.public_key,
                second_ip,
                gossip_source.ip()
            )))
        }
    }

    #[allow(clippy::branches_sharing_code)]
    fn identify_players(
        mut agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
    ) -> Result<(AccessibleGossipRecord, AccessibleGossipRecord), Qualification> {
        let pair = if Self::order_is_introducee_introducer(&agrs, gossip_source)? {
            let introducer = agrs.remove(0);
            let introducee = agrs.remove(0);
            (introducer, introducee)
        } else {
            let introducee = agrs.remove(0);
            let introducer = agrs.remove(0);
            (introducer, introducee)
        };
        Ok(pair)
    }

    fn verify_introducer(
        agr: &AccessibleGossipRecord,
        root_node: &NodeRecord,
    ) -> Option<Qualification> {
        if &agr.inner.public_key == root_node.public_key() {
            return Some(Qualification::Malformed(format!(
                "Introducer {} claims local Node's public key",
                agr.inner.public_key
            )));
        }
        let introducer_node_addr = agr.node_addr_opt.as_ref().expect("NodeAddr disappeared");
        if introducer_node_addr.ports().is_empty() {
            return Some(Qualification::Malformed(format!(
                "Introducer {} from {} has no ports",
                &agr.inner.public_key,
                introducer_node_addr.ip_addr()
            )));
        }
        if let Some(root_node_addr) = root_node.node_addr_opt() {
            if introducer_node_addr.ip_addr() == root_node_addr.ip_addr() {
                return Some(Qualification::Malformed(format!(
                    "Introducer {} claims to be at local Node's IP address",
                    agr.inner.public_key
                )));
            }
        }
        None
    }

    fn verify_introducee(
        database: &NeighborhoodDatabase,
        introducer: &AccessibleGossipRecord,
        introducee: &AccessibleGossipRecord,
        gossip_source: SocketAddr,
    ) -> Option<Qualification> {
        if database.node_by_key(&introducee.inner.public_key).is_some() {
            return Some(Qualification::Unmatched);
        }
        let introducee_node_addr = match introducee.node_addr_opt.as_ref() {
            None => return Some(Qualification::Unmatched),
            Some(node_addr) => node_addr,
        };
        if introducee_node_addr.ports().is_empty() {
            return Some(Qualification::Malformed(format!(
                "Introducer {} from {} introduced {} from {} with no ports",
                &introducer.inner.public_key,
                match &introducer.node_addr_opt {
                    Some(node_addr) => node_addr.ip_addr().to_string(),
                    None => "?.?.?.?".to_string(),
                },
                &introducee.inner.public_key,
                introducee_node_addr.ip_addr()
            )));
        }
        if introducee
            .node_addr_opt
            .as_ref()
            .expect("Introducee NodeAddr disappeared")
            .ip_addr()
            == gossip_source.ip()
        {
            return Some(Qualification::Malformed(format!(
                "Introducer {} and introducee {} both claim {}",
                introducer.inner.public_key,
                introducee.inner.public_key,
                gossip_source.ip()
            )));
        }
        None
    }

    fn update_database(
        &self,
        database: &mut NeighborhoodDatabase,
        cryptde: &dyn CryptDE,
        introducer: AccessibleGossipRecord,
        user_exit_preferences_opt: Option<UserExitPreferences>,
    ) -> Result<bool, String> {
        let introducer_key = introducer.inner.public_key.clone();
        match database.node_by_key_mut(&introducer_key) {
            Some(existing_introducer_ref) => {
                if existing_introducer_ref.version() < introducer.inner.version {
                    debug!(
                        self.logger,
                        "Updating obsolete introducer {} from version {} to version {}",
                        introducer_key,
                        existing_introducer_ref.version(),
                        introducer.inner.version
                    );
                    existing_introducer_ref.update(introducer)?;
                } else {
                    debug!(
                        self.logger,
                        "Preserving existing introducer {} at version {}",
                        introducer_key,
                        existing_introducer_ref.version()
                    );
                    return Ok(false);
                }
            }
            None => {
                let mut new_introducer = NodeRecord::from(introducer);
                //TODO 468 add country undesirability
                match user_exit_preferences_opt {
                    //TODO 788 check if country code is present in Neighborhood DB and if yes, perform assign country code to exit_countries without duplication
                    Some(user_exit_preferences) => user_exit_preferences
                        .assign_nodes_country_undesirability(&mut new_introducer),
                    None => (),
                }
                //TODO probably make one function to use on all places
                debug!(
                    self.logger,
                    "Adding introducer {} to database", introducer_key
                );
                database
                    .add_node(new_introducer)
                    .expect("add_node should always work here");
            }
        }
        if database
            .add_half_neighbor(&introducer_key)
            .expect("introducer not in database")
        {
            database.root_mut().increment_version();
            database.root_mut().regenerate_signed_gossip(cryptde);
        }
        trace!(self.logger, "Current database: {}", database.to_dot_graph());
        Ok(true)
    }
}

struct StandardGossipHandler {
    logger: Logger,
}

impl NamedType for StandardGossipHandler {
    fn type_name(&self) -> &'static str {
        "StandardGossipHandler"
    }
}

impl GossipHandler for StandardGossipHandler {
    // Standard Gossip must not be a Debut, Pass, or Introduction. There must be no record in the
    // Gossip describing the local Node (although there may be records that reference the local Node as a neighbor).
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification {
        // must-not-be-debut-pass-or-introduction is assured by StandardGossipHandler's placement in the gossip_handlers list
        let agrs_next_door = agrs
            .iter()
            .filter(|agr| agr.node_addr_opt.is_some())
            .collect::<Vec<&AccessibleGossipRecord>>();
        let root_node = database.root();
        if root_node.accepts_connections() {
            if let Some(impostor) = agrs_next_door.iter().find(|agr| {
                Self::ip_of(agr)
                    == root_node
                        .node_addr_opt()
                        .expect("Root Node that accepts connections must have NodeAddr")
                        .ip_addr()
            }) {
                return Qualification::Malformed(
                    format!("Standard Gossip from {} contains a record claiming that {} has this Node's IP address",
                            gossip_source,
                            impostor.inner.public_key));
            }
        }
        if agrs
            .iter()
            .any(|agr| &agr.inner.public_key == root_node.public_key())
        {
            return Qualification::Malformed(format!(
                "Standard Gossip from {} contains a record with this Node's public key",
                gossip_source
            ));
        }
        let init_addr_set: HashSet<IpAddr> = HashSet::new();
        let init_dup_set: HashSet<IpAddr> = HashSet::new();
        let dup_set = agrs_next_door
            .into_iter()
            .fold((init_addr_set, init_dup_set), |so_far, agr| {
                let (addr_set, dup_set) = so_far;
                let ip_addr = Self::ip_of(agr);
                if addr_set.contains(&ip_addr) {
                    (addr_set, Self::add_ip_addr(dup_set, ip_addr))
                } else {
                    (Self::add_ip_addr(addr_set, ip_addr), dup_set)
                }
            })
            .1;

        if dup_set.is_empty() {
            Qualification::Matched
        } else {
            let dup_vec = dup_set.into_iter().take(1).collect::<Vec<IpAddr>>();
            let first_dup_ip = dup_vec.first().expect("Duplicate IP address disappeared");
            Qualification::Malformed(format!(
                "Standard Gossip from {} contains multiple records claiming to be from {}",
                gossip_source, first_dup_ip
            ))
        }
    }

    fn handle(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        let initial_neighborship_status =
            StandardGossipHandler::check_full_neighbor(database, gossip_source.ip());

        let patch = self.compute_patch(&agrs, database.root(), neighborhood_metadata.db_patch_size);
        let filtered_agrs = self.filter_agrs_by_patch(agrs, patch);

        // TODO 468 get structs from neighborhood metadata
        let mut db_changed = self.identify_and_add_non_introductory_new_nodes(
            database,
            &filtered_agrs,
            gossip_source,
            neighborhood_metadata.user_exit_preferences_opt.as_ref(),
        );
        db_changed = self.identify_and_update_obsolete_nodes(database, filtered_agrs) || db_changed;
        db_changed =
            self.add_src_node_as_half_neighbor(cryptde, database, gossip_source) || db_changed;
        let final_neighborship_status =
            StandardGossipHandler::check_full_neighbor(database, gossip_source.ip());
        // If no Nodes need updating, return ::Ignored and don't change the database.
        // Otherwise, return ::Accepted.
        if db_changed {
            trace!(self.logger, "Current database: {}", database.to_dot_graph());
            if (initial_neighborship_status, final_neighborship_status) == (false, true) {
                // Received Reply for Acceptance of Debut Gossip (false, true)
                let cpm = ConnectionProgressMessage {
                    peer_addr: gossip_source.ip(),
                    event: ConnectionProgressEvent::StandardGossipReceived,
                };
                neighborhood_metadata
                    .cpm_recipient
                    .try_send(cpm)
                    .unwrap_or_else(|e| panic!("Neighborhood is dead: {}", e));
            }
            GossipAcceptanceResult::Accepted
        } else {
            debug!(
                self.logger,
                "Gossip contained nothing new: StandardGossipHandler is ignoring it"
            );
            GossipAcceptanceResult::Ignored
        }
    }
}

impl StandardGossipHandler {
    fn new(logger: Logger) -> StandardGossipHandler {
        StandardGossipHandler { logger }
    }

    fn compute_patch(
        &self,
        agrs: &[AccessibleGossipRecord],
        root_node: &NodeRecord,
        db_patch_size: u8,
    ) -> HashSet<PublicKey> {
        let agrs_by_key = agrs
            .iter()
            .map(|agr| (&agr.inner.public_key, agr))
            .collect::<HashMap<&PublicKey, &AccessibleGossipRecord>>();

        let mut patch: HashSet<PublicKey> = HashSet::new();
        self.compute_patch_recursive(
            &mut patch,
            root_node.public_key(),
            &agrs_by_key,
            db_patch_size,
            root_node,
        );

        patch
    }

    fn compute_patch_recursive(
        &self,
        patch: &mut HashSet<PublicKey>,
        current_node_key: &PublicKey,
        agrs: &HashMap<&PublicKey, &AccessibleGossipRecord>,
        hops_remaining: u8,
        root_node: &NodeRecord,
    ) {
        patch.insert(current_node_key.clone());
        if hops_remaining == 0 {
            return;
        }
        let neighbors = if current_node_key == root_node.public_key() {
            &root_node.inner.neighbors
        } else {
            match agrs.get(current_node_key) {
                Some(agr) => &agr.inner.neighbors,
                None => {
                    patch.remove(current_node_key);
                    trace!(
                        self.logger,
                        "While computing patch no AGR record found for public key {:?}",
                        current_node_key
                    );
                    return;
                }
            }
        };

        for neighbor in neighbors {
            if !patch.contains(neighbor) {
                self.compute_patch_recursive(patch, neighbor, agrs, hops_remaining - 1, root_node)
            }
        }
    }

    fn filter_agrs_by_patch(
        &self,
        agrs: Vec<AccessibleGossipRecord>,
        patch: HashSet<PublicKey>,
    ) -> Vec<AccessibleGossipRecord> {
        agrs.into_iter()
            .filter(|agr| patch.contains(&agr.inner.public_key))
            .collect::<Vec<AccessibleGossipRecord>>()
    }

    fn identify_and_add_non_introductory_new_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
        user_exit_preferences_opt: Option<&UserExitPreferences>,
    ) -> bool {
        let all_keys = database
            .keys()
            .into_iter()
            .cloned()
            .collect::<HashSet<PublicKey>>();
        agrs.iter()
            .filter(|agr| !all_keys.contains(&agr.inner.public_key))
            // TODO: A node that tells us the IP Address of the node that isn't in our database should be malefactor banned
            .filter(|agr| match &agr.node_addr_opt {
                None => true,
                Some(node_addr) => {
                    let socket_addrs: Vec<SocketAddr> = node_addr.clone().into();
                    socket_addrs.contains(&gossip_source)
                }
            })
            .for_each(|agr| {
                let mut node_record = NodeRecord::from(agr);
                // TODO modify for country undesirability in node_record (make it mut)
                match user_exit_preferences_opt {
                    Some(user_exit_preferences) => {
                        //TODO 788 check if country code is present in Neighborhood DB and if yes, perform assign country code to exit_countries without duplication
                        user_exit_preferences.assign_nodes_country_undesirability(&mut node_record)
                    }
                    None => (),
                }
                trace!(
                    self.logger,
                    "Discovered new Node {:?}: {:?}",
                    node_record.public_key(),
                    node_record.full_neighbor_keys(database)
                );
                database
                    .add_node(node_record)
                    .expect("List of new Nodes contained existing Nodes");
            });
        database.keys().len() != all_keys.len()
    }

    fn identify_and_update_obsolete_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
    ) -> bool {
        agrs.into_iter().fold(false, |b, agr| {
            match database.node_by_key(&agr.inner.public_key) {
                Some(existing_node) if agr.inner.version > existing_node.version() => {
                    trace!(
                        self.logger,
                        "Updating Node {:?} from v{} to v{}",
                        existing_node.public_key(),
                        existing_node.version(),
                        agr.inner.version
                    );
                    self.update_database_record(database, agr) || b
                }
                _ => b,
            }
        })
    }

    fn add_src_node_as_half_neighbor(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        gossip_source: SocketAddr,
    ) -> bool {
        let gossip_node = match database.node_by_ip(&gossip_source.ip()) {
            None => return false,
            Some(node) => node,
        };
        let gossip_node_key = gossip_node.public_key().clone();
        if database.root().full_neighbor_keys(database).len() >= MAX_DEGREE {
            false
        } else {
            match database.add_half_neighbor(&gossip_node_key) {
                Err(_) => false,
                Ok(false) => false,
                Ok(true) => {
                    let root_mut = database.root_mut();
                    root_mut.increment_version();
                    root_mut.regenerate_signed_gossip(cryptde);
                    true
                }
            }
        }
    }

    fn update_database_record(
        &self,
        database: &mut NeighborhoodDatabase,
        agr: AccessibleGossipRecord,
    ) -> bool {
        let existing_node_record = database
            .node_by_key_mut(&agr.inner.public_key)
            .expect("Node magically disappeared");
        let new_version = agr.inner.version;
        match existing_node_record.update(agr) {
            Ok(_) => true,
            Err(e) => {
                error!(
                    self.logger,
                    "Failed to update {} from v{} to v{}: {}",
                    existing_node_record.public_key(),
                    existing_node_record.version(),
                    new_version,
                    e
                );
                false
            }
        }
    }

    fn add_ip_addr(set: HashSet<IpAddr>, ip_addr: IpAddr) -> HashSet<IpAddr> {
        let mut result = set;
        result.insert(ip_addr);
        result
    }

    fn ip_of(agr: &AccessibleGossipRecord) -> IpAddr {
        agr.node_addr_opt
            .as_ref()
            .expect("Should have NodeAddr")
            .ip_addr()
    }

    fn check_full_neighbor(db: &NeighborhoodDatabase, gossip_source_ip: IpAddr) -> bool {
        if let Some(node) = db.node_by_ip(&gossip_source_ip) {
            return db.has_full_neighbor(db.root().public_key(), &node.inner.public_key);
        }
        false
    }
}

struct RejectHandler {}

impl NamedType for RejectHandler {
    fn type_name(&self) -> &'static str {
        "RejectHandler"
    }
}

impl GossipHandler for RejectHandler {
    fn qualifies(
        &self,
        _database: &NeighborhoodDatabase,
        agrs: &[AccessibleGossipRecord],
        gossip_source: SocketAddr,
    ) -> Qualification {
        Qualification::Malformed(format!(
            "Gossip with {} records from {} is unclassifiable by any qualifier",
            agrs.len(),
            gossip_source
        ))
    }

    fn handle(
        &self,
        _cryptde: &dyn CryptDE,
        _database: &mut NeighborhoodDatabase,
        _agrs: Vec<AccessibleGossipRecord>,
        _gossip_source: SocketAddr,
        _neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        panic!("Should never be called")
    }
}

impl RejectHandler {
    fn new() -> RejectHandler {
        RejectHandler {}
    }
}

pub trait GossipAcceptor: Send /* Send because lazily-written tests require it */ {
    fn handle(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult;
}

pub struct GossipAcceptorReal<'a> {
    cryptde: &'a dyn CryptDE,
    gossip_handlers: Vec<Box<dyn GossipHandler>>,
    logger: Logger,
}

impl<'a> GossipAcceptor for GossipAcceptorReal<'a> {
    fn handle(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
        neighborhood_metadata: NeighborhoodMetadata,
    ) -> GossipAcceptanceResult {
        let (qualification, handler_ref) = self
            .gossip_handlers
            .iter()
            .map(|h| (h.qualifies(database, &agrs, gossip_source), h.as_ref()))
            .find(|pair| !matches!(pair, (Qualification::Unmatched, _)))
            .expect("gossip_handlers should intercept everything");
        match qualification {
            Qualification::Matched => {
                debug!(
                    self.logger,
                    "Gossip delegated to {}",
                    handler_ref.type_name()
                );
                handler_ref.handle(
                    self.cryptde,
                    database,
                    agrs,
                    gossip_source,
                    neighborhood_metadata,
                )
            }
            Qualification::Unmatched => {
                panic!("Nothing in gossip_handlers returned Matched or Malformed")
            }
            Qualification::Malformed(reason) => GossipAcceptanceResult::Ban(reason),
        }
    }
}

impl<'a> GossipAcceptorReal<'a> {
    pub fn new(cryptde: &'a dyn CryptDE) -> GossipAcceptorReal {
        let logger = Logger::new("GossipAcceptor");
        GossipAcceptorReal {
            gossip_handlers: vec![
                Box::new(DebutHandler::new(logger.clone())),
                Box::new(PassHandler::new()),
                Box::new(IntroductionHandler::new(logger.clone())),
                Box::new(StandardGossipHandler::new(logger.clone())),
                Box::new(RejectHandler::new()),
            ],
            cryptde,
            logger,
        }
    }

    fn make_debut_triple(
        database: &NeighborhoodDatabase,
        debut_target: &AccessibleGossipRecord,
    ) -> Result<(Gossip_0v1, PublicKey, NodeAddr), String> {
        let debut_target_node_addr = match &debut_target.node_addr_opt {
            None => {
                return Err(format!(
                    "Can't generate debut to {}: no IP address supplied",
                    debut_target.inner.public_key
                ));
            }
            Some(node_addr) => {
                if node_addr.ports().is_empty() {
                    return Err(format!(
                        "Can't generate debut to {} at {}: no ports were specified",
                        debut_target.inner.public_key,
                        node_addr.ip_addr()
                    ));
                };
                node_addr
            }
        };
        let debut_gossip = GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build();
        Ok((
            debut_gossip,
            debut_target.inner.public_key.clone(),
            debut_target_node_addr.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::gossip_producer::GossipProducer;
    use crate::neighborhood::gossip_producer::GossipProducerReal;
    use crate::neighborhood::node_record::NodeRecord;
    use crate::neighborhood::{
        ExitPreference, UserExitPreferences, COUNTRY_UNDESIRABILITY_FACTOR,
        UNREACHABLE_COUNTRY_PENALTY,
    };
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::{
        ConnectionProgressEvent, ConnectionProgressMessage, ExitLocation,
    };
    use crate::sub_lib::utils::time_t_timestamp;
    use crate::test_utils::neighborhood_test_utils::{
        db_from_node, gossip_about_nodes_from_database, linearly_connect_nodes,
        make_meaningless_db, make_node_record, make_node_record_f, make_node_records,
        public_keys_from_node_records, DB_PATCH_SIZE_FOR_TEST,
    };
    use crate::test_utils::unshared_test_utils::make_cpm_recipient;
    use crate::test_utils::{assert_contains, main_cryptde, vec_to_set};
    use actix::System;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::convert::TryInto;
    use std::net::Ipv4Addr;
    use std::ops::{Add, Sub};
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(MAX_DEGREE, 5);
        assert_eq!(PASS_GOSSIP_EXPIRED_TIME, Duration::from_secs(60));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        Standard,
        OriginateOnly,
        // GossipAcceptor doesn't care about ConsumeOnly; that's routing, not Gossip
        // ZeroHop is decentralized and should never appear in GossipAcceptor tests
    }

    fn make_default_neighborhood_metadata() -> NeighborhoodMetadata {
        NeighborhoodMetadata {
            connection_progress_peers: vec![],
            cpm_recipient: make_cpm_recipient().0,
            db_patch_size: DB_PATCH_SIZE_FOR_TEST,
            user_exit_preferences_opt: None,
        }
    }

    #[test]
    fn proper_debut_of_accepting_node_with_populated_database_is_identified_and_handled() {
        let (gossip, new_node, gossip_source_opt) = make_debut(2345, Mode::Standard);
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let neighbor_key = &db.add_node(make_node_record(3456, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), neighbor_key);
        let cryptde = CryptDENull::from(db.root().public_key(), TEST_DEFAULT_CHAIN);
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let qualifies_result =
            subject.qualifies(&db, &agrs_vec.as_slice(), gossip_source_opt.clone());
        let handle_result = subject.handle(
            &cryptde,
            &mut db,
            agrs_vec,
            gossip_source_opt,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let introduction = GossipBuilder::new(&db)
            .node(db.root().public_key(), true)
            .node(neighbor_key, true)
            .build();
        assert_eq!(
            handle_result,
            GossipAcceptanceResult::Reply(
                introduction,
                new_node.public_key().clone(),
                new_node.node_addr_opt().unwrap(),
            ),
        );
    }

    #[test]
    fn proper_debut_of_non_accepting_node_with_populated_database_is_identified_and_handled() {
        let (gossip, new_node, gossip_source) = make_debut(2345, Mode::OriginateOnly);
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let neighbor_key = &db.add_node(make_node_record(3456, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), neighbor_key);
        let cryptde = CryptDENull::from(db.root().public_key(), TEST_DEFAULT_CHAIN);
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let qualifies_result = subject.qualifies(&db, agrs_vec.as_slice(), gossip_source.clone());
        let handle_result = subject.handle(
            &cryptde,
            &mut db,
            agrs_vec,
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let introduction = GossipBuilder::new(&db)
            .node(db.root().public_key(), true)
            .node(neighbor_key, true)
            .build();
        assert_eq!(
            handle_result,
            GossipAcceptanceResult::Reply(
                introduction,
                new_node.public_key().clone(),
                NodeAddr::from(&gossip_source),
            ),
        );
    }

    #[test]
    fn proper_debut_of_node_cant_produce_introduction_because_of_common_neighbor() {
        let src_root = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_root);
        let cryptde = CryptDENull::from(src_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let dest_root = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_root);
        let one_common_neighbor = make_node_record(3456, true);
        let another_common_neighbor = make_node_record(4567, true);
        src_db.add_node(one_common_neighbor.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), one_common_neighbor.public_key());
        src_db.add_node(another_common_neighbor.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(
            src_root.public_key(),
            another_common_neighbor.public_key(),
        );
        dest_db.add_node(one_common_neighbor.clone()).unwrap();
        dest_db
            .add_arbitrary_full_neighbor(dest_root.public_key(), one_common_neighbor.public_key());
        dest_db.add_node(another_common_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(
            dest_root.public_key(),
            another_common_neighbor.public_key(),
        );
        let gossip = GossipBuilder::new(&src_db)
            .node(src_db.root().public_key(), true)
            .build();
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs_vec,
            src_root.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        assert_eq!(result, GossipAcceptanceResult::Accepted);
    }

    #[test]
    fn proper_debut_of_node_cant_be_passed_because_of_common_neighbors() {
        let src_root = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_root);
        let cryptde = CryptDENull::from(src_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let dest_root = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_root);
        (0..MAX_DEGREE as u16).into_iter().for_each(|index| {
            let common_neighbor = make_node_record(3456 + index, true);
            src_db.add_node(common_neighbor.clone()).unwrap();
            src_db.add_arbitrary_full_neighbor(src_root.public_key(), common_neighbor.public_key());
            dest_db.add_node(common_neighbor.clone()).unwrap();
            dest_db
                .add_arbitrary_full_neighbor(dest_root.public_key(), common_neighbor.public_key());
        });
        let gossip = GossipBuilder::new(&src_db)
            .node(src_db.root().public_key(), true)
            .build();
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs_vec,
            src_root.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        assert_eq!(
            result,
            GossipAcceptanceResult::Failed(
                GossipFailure_0v1::NoSuitableNeighbors,
                src_root.public_key().clone(),
                src_root.node_addr_opt().unwrap(),
            )
        );
    }

    #[test]
    fn debut_with_node_addr_not_accepting_connections_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_debut(2345, Mode::OriginateOnly);
        let subject = DebutHandler::new(Logger::new("test"));
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &[1234],
        ));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(
                format! ("Debut from 200.200.200.200:2000 for AgMEBQ does not accept connections, yet contained NodeAddr")
            ),
        );
    }

    #[test]
    fn debut_without_node_addr_accepting_connections_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_debut(2345, Mode::Standard);
        gossip.node_records[0].node_addr_opt = None;
        let subject = DebutHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(
                "Debut from 2.3.4.5:2345 for AgMEBQ contained no NodeAddr".to_string()
            ),
        );
    }

    #[test]
    fn debut_without_node_addr_ports_accepting_connections_is_rejected() {
        let (mut gossip, _, gossip_source) = make_debut(2345, Mode::Standard);
        gossip.node_records[0].node_addr_opt =
            Some(NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[]));
        let subject = DebutHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(
                "Debut from 2.3.4.5:2345 for AgMEBQ contained NodeAddr with no ports".to_string()
            ),
        );
    }

    #[test]
    fn apparent_debut_with_node_already_in_database_is_unmatched() {
        let (gossip, new_node, gossip_source) = make_debut(2345, Mode::Standard);
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let neighbor_key = &db.add_node(make_node_record(3456, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), neighbor_key);
        db.add_node(new_node.clone()).unwrap();
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.qualifies(&db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(result, Qualification::Unmatched);
    }

    #[test]
    fn debut_of_already_connected_node_produces_accepted_result_instead_of_introduction_to_prevent_overconnection(
    ) {
        let src_root = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_root);
        let dest_root = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_root);
        let dest_cryptde = CryptDENull::from(dest_root.public_key(), TEST_DEFAULT_CHAIN);
        let common_neighbor = make_node_record(3456, true);
        let dest_neighbor = make_node_record(4567, true);
        src_db.add_node(common_neighbor.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), common_neighbor.public_key());
        dest_db.add_node(common_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), common_neighbor.public_key());
        dest_db.add_node(dest_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), dest_neighbor.public_key());
        let agrs_vec: Vec<AccessibleGossipRecord> = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .build()
            .try_into()
            .unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &dest_cryptde,
            &mut dest_db,
            agrs_vec,
            dest_root.node_addr_opt().clone().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        assert_eq!(result, GossipAcceptanceResult::Accepted);
    }

    #[test]
    fn two_parallel_debuts_in_progress_handled_by_try_accept_debut_without_introduction() {
        let mut root_node = make_node_record(1234, true);
        let half_debuted_node = make_node_record(2345, true);
        let new_debutant = make_node_record(4567, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        dest_db.add_node(half_debuted_node.clone()).unwrap();
        dest_db.add_arbitrary_half_neighbor(root_node.public_key(), half_debuted_node.public_key());
        let logger = Logger::new("Debut test");
        let subject = DebutHandler::new(logger);
        let neighborhood_metadata = make_default_neighborhood_metadata();

        let counter_debut = subject
            .try_accept_debut(
                &root_node_cryptde,
                &mut dest_db,
                &AccessibleGossipRecord::from(&new_debutant),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 5, 6, 7)), 4567),
                neighborhood_metadata.user_exit_preferences_opt,
            )
            .unwrap();

        let (debut_reply, dest_public_key, dest_node_addr) = match counter_debut {
            GossipAcceptanceResult::Reply(
                ref debut_reply,
                ref dest_public_key,
                ref dest_node_addr,
            ) => (debut_reply, dest_public_key, dest_node_addr),
            x => panic!("Expected Reply, got {:?}", x),
        };

        assert_eq!(dest_public_key, new_debutant.public_key());
        assert_eq!(dest_node_addr, &new_debutant.node_addr_opt().unwrap());
        root_node
            .add_half_neighbor_key(new_debutant.public_key().clone())
            .unwrap();
        assert_eq!(
            counter_debut,
            GossipAcceptanceResult::Reply(
                debut_reply.clone(),
                dest_public_key.clone(),
                dest_node_addr.clone()
            )
        )
    }

    #[test]
    fn proper_pass_is_identified_and_processed() {
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = PassHandler::new();
        let mut dest_db = make_meaningless_db();
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let qualifies_result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs_vec,
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let debut = GossipBuilder::new(&dest_db)
            .node(dest_db.root().public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                debut,
                pass_target.public_key().clone(),
                pass_target.node_addr_opt().unwrap().clone(),
            ),
            handle_result
        );
    }

    #[test]
    fn pass_without_node_addr_is_rejected() {
        let (mut gossip, _, gossip_source) = make_pass(2345);
        gossip.node_records[0].node_addr_opt = None;
        let subject = PassHandler::new();
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            Qualification::Malformed(
                "Pass from 200.200.200.200:2000 to AgMEBQ did not contain NodeAddr".to_string()
            ),
            result
        );
    }

    #[test]
    fn pass_without_node_addr_ports_is_rejected() {
        let (mut gossip, _, gossip_source) = make_pass(2345);
        gossip.node_records[0].node_addr_opt =
            Some(NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[]));
        let subject = PassHandler::new();
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            Qualification::Malformed(
                "Pass from 200.200.200.200:2000 to AgMEBQ at 1.2.3.4 contained NodeAddr with no ports"
                    .to_string()
            ),
            result
        );
    }

    #[test]
    fn gossip_containing_other_than_two_records_is_not_an_introduction() {
        let (gossip, _, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), agrs_vec.as_slice(), gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_introducee_is_in_the_database_is_unmatched() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let not_introducee = make_node_record(3456, true);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        dest_db.add_node(not_introducee.clone()).unwrap();
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_nobody_admits_to_being_source_is_unmatched() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[0].node_addr_opt = None;
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_introducer_does_not_provide_at_least_one_port_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[0].node_addr_opt =
            Some(NodeAddr::new(&IpAddr::from_str("2.3.4.5").unwrap(), &[]));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            Qualification::Malformed("Introducer AgMEBQ from 2.3.4.5 has no ports".to_string()),
            result
        );
    }

    #[test]
    fn gossip_where_introducee_does_not_provide_node_addr_is_not_introduction() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[1].node_addr_opt = None;
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_introducee_does_not_provide_at_least_one_port_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[1].node_addr_opt =
            Some(NodeAddr::new(&IpAddr::from_str("3.4.5.6").unwrap(), &[]));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            Qualification::Malformed(
                "Introducer AgMEBQ from 2.3.4.5 introduced AwQFBg from 3.4.5.6 with no ports"
                    .to_string()
            ),
            result
        );
    }

    #[test]
    fn gossip_where_no_record_has_the_gossip_source_ip_is_not_introduction() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("4.5.6.7").unwrap(),
            &[4567],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(Qualification::Malformed("In Introduction, neither AgMEBQ from 4.5.6.7 nor AwQFBg from 3.4.5.6 claims the source IP 2.3.4.5".to_string()), result);
    }

    #[test]
    fn introduction_where_both_records_have_gossip_source_ip_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[1].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &[2345],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);

        assert_eq!(
            Qualification::Malformed(
                "Introducer AgMEBQ and introducee AwQFBg both claim 2.3.4.5".to_string()
            ),
            result
        );
    }

    #[test]
    fn introduction_where_introducer_has_local_public_key_is_malformed() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let mut agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        agrs[0].inner.public_key = dest_root.public_key().clone();
        let introducer_key = &agrs[0].inner.public_key;

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(
            Qualification::Malformed(format!(
                "Introducer {} claims local Node's public key",
                introducer_key
            )),
            result
        );
    }

    #[test]
    fn introduction_where_introducer_has_local_ip_address_is_malformed() {
        let (gossip, _) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let mut agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        agrs[0].node_addr_opt = dest_root.node_addr_opt();
        let introducer_key = &agrs[0].inner.public_key;

        let result = subject.qualifies(&dest_db, &agrs, dest_root.node_addr_opt().unwrap().into());

        assert_eq!(
            Qualification::Malformed(format!(
                "Introducer {} claims to be at local Node's IP address",
                introducer_key
            )),
            result
        );
    }

    #[test]
    fn introduction_that_tries_to_change_immutable_characteristics_of_introducer_is_suspicious() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let introducer_key = &agrs[0].inner.public_key;
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
        dest_db
            .node_by_key_mut(introducer_key)
            .unwrap()
            .set_version(0);
        dest_db
            .node_by_key_mut(introducer_key)
            .unwrap()
            .force_node_addr(&NodeAddr::from(
                &SocketAddr::from_str("4.5.6.7:4567").unwrap(),
            ));
        dest_db.resign_node(introducer_key);
        let introducer_before_gossip = dest_db.node_by_key(introducer_key).unwrap().clone();
        let before = time_t_timestamp();

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs.clone(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
        assert_eq!(qualifies_result, Qualification::Matched);
        assert_eq!(
            handle_result,
            GossipAcceptanceResult::Ban(format!("Introducer {} tried changing immutable characteristic: Updating a NodeRecord must not change its node_addr_opt: 4.5.6.7:4567 -> 2.3.4.5:2345", introducer_key)),
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(introducer_key).unwrap(),
            &introducer_before_gossip,
            before,
            after,
        );
    }

    #[test]
    fn introduction_with_no_problems_qualifies_when_no_local_ip_address_is_known() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record_f(7878, false, false, true);
        let dest_db = db_from_node(&dest_root);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(Qualification::Matched, result);
    }

    #[test]
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_not_in_database() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.user_exit_preferences_opt = Some(UserExitPreferences {
            exit_countries: vec!["FR".to_string()],
            exit_location_preference: ExitPreference::ExitCountryNoFallback,
            exit_locations_opt: Some(vec![ExitLocation {
                country_codes: vec!["FR".to_string()],
                priority: 2,
            }]),
            db_countries: vec!["FR".to_string()],
        });

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs.clone(),
            gossip_source,
            neighborhood_metadata,
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let debut = GossipBuilder::new(&dest_db)
            .node(dest_db.root().public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                debut,
                agrs[1].inner.public_key.clone(),
                agrs[1].node_addr_opt.clone().unwrap(),
            ),
            handle_result
        );

        let result_introducer: &NodeRecord =
            dest_db.node_by_key_mut(&agrs[0].inner.public_key).unwrap();
        let mut expected_introducer = NodeRecord::from(&agrs[0]);
        expected_introducer.metadata.last_update = result_introducer.metadata.last_update;
        expected_introducer.metadata.country_undesirability = COUNTRY_UNDESIRABILITY_FACTOR;
        expected_introducer.resign();
        assert_eq!(result_introducer, &expected_introducer);
        assert_eq!(
            dest_db
                .root()
                .has_half_neighbor(expected_introducer.public_key()),
            true
        );
        assert_eq!(dest_db.root().version(), 1);
        assert_eq!(dest_db.node_by_key(&agrs[1].inner.public_key), None);
    }

    #[test]
    fn introduction_with_no_problems_is_ignored_when_target_is_already_max_degree() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        for i in 0..MAX_DEGREE as u16 {
            let key = dest_db.add_node(make_node_record(i, true)).unwrap();
            dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), &key);
        }
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs.clone(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(handle_result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_in_database_and_obsolete(
    ) {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
        dest_db
            .node_by_key_mut(&agrs[0].inner.public_key)
            .unwrap()
            .set_version(0);
        dest_db.resign_node(&agrs[0].inner.public_key);

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs.clone(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let debut = GossipBuilder::new(&dest_db)
            .node(dest_db.root().public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                debut,
                agrs[1].inner.public_key.clone(),
                agrs[1].node_addr_opt.clone().unwrap(),
            ),
            handle_result
        );
        let result_introducer: &NodeRecord =
            dest_db.node_by_key_mut(&agrs[0].inner.public_key).unwrap();
        let mut expected_introducer = NodeRecord::from(&agrs[0]);
        expected_introducer.metadata.last_update = result_introducer.metadata.last_update;
        expected_introducer.resign();
        assert_eq!(result_introducer, &expected_introducer);
        assert_eq!(
            true,
            dest_db
                .root()
                .has_half_neighbor(expected_introducer.public_key())
        );
        assert_eq!(1, dest_db.root().version());
        assert_eq!(None, dest_db.node_by_key(&agrs[1].inner.public_key));
    }

    #[test]
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_in_database_and_up_to_date(
    ) {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        // These don't count because they're half-only neighbors. Will they be ignored?
        for idx in 0..MAX_DEGREE {
            let half_neighbor_key = &dest_db
                .add_node(make_node_record(4000 + idx as u16, true))
                .unwrap();
            dest_db.add_arbitrary_half_neighbor(dest_root.public_key(), half_neighbor_key);
        }
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
        dest_db.add_arbitrary_half_neighbor(dest_root.public_key(), &agrs[0].inner.public_key);

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs.clone(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(Qualification::Matched, qualifies_result);
        let debut = GossipBuilder::new(&dest_db)
            .node(dest_db.root().public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                debut,
                agrs[1].inner.public_key.clone(),
                agrs[1].node_addr_opt.clone().unwrap(),
            ),
            handle_result
        );

        let result_introducer: &NodeRecord =
            dest_db.node_by_key_mut(&agrs[0].inner.public_key).unwrap();
        let mut expected_introducer = NodeRecord::from(&agrs[0]);
        expected_introducer.metadata.last_update = result_introducer.metadata.last_update;
        expected_introducer.resign();
        assert_eq!(result_introducer, &expected_introducer);
        assert_eq!(
            true,
            dest_db
                .root()
                .has_half_neighbor(expected_introducer.public_key())
        );
        assert_eq!(0, dest_db.root().version());
        assert_eq!(None, dest_db.node_by_key(&agrs[1].inner.public_key));
    }

    #[test]
    fn check_full_neighbor_proves_that_gossip_source_is_a_full_neighbor() {
        let root_node = make_node_record(1111, true); // This is us
        let mut root_db = db_from_node(&root_node);
        let full_neighbor = make_node_record(9012, true); // Full Neighbor
        root_db.add_node(full_neighbor.clone()).unwrap();
        root_db.add_arbitrary_full_neighbor(root_node.public_key(), full_neighbor.public_key());
        let full_neighbor_ip = full_neighbor.node_addr_opt().unwrap().ip_addr();

        let result = StandardGossipHandler::check_full_neighbor(&root_db, full_neighbor_ip);

        assert_eq!(result, true);
    }

    #[test]
    fn check_full_neighbor_proves_that_node_that_is_not_in_our_db_is_not_a_full_neighbor() {
        let root_node = make_node_record(1111, true); // This is us
        let root_db = db_from_node(&root_node);
        let ip_not_in_our_db = IpAddr::from_str("1.2.3.4").unwrap();

        let result = StandardGossipHandler::check_full_neighbor(&root_db, ip_not_in_our_db);

        assert_eq!(result, false);
    }

    #[test]
    fn check_full_neighbor_proves_that_node_that_is_our_half_neighbor_is_not_a_full_neighbor() {
        let root_node = make_node_record(1111, true); // This is us
        let mut root_db = db_from_node(&root_node);
        let half_neighbor = make_node_record(3456, true); // In DB, but half neighbor
        root_db.add_node(half_neighbor.clone()).unwrap();
        root_db.add_arbitrary_half_neighbor(half_neighbor.public_key(), root_node.public_key());
        let ip_addr_of_half_neighbor = half_neighbor.node_addr_opt().unwrap().ip_addr();

        let result = StandardGossipHandler::check_full_neighbor(&root_db, ip_addr_of_half_neighbor);

        assert_eq!(result, false);
    }

    #[test]
    fn standard_gossip_that_doesnt_contain_record_with_gossip_source_ip_is_matched() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let node_a = make_node_record(3456, true);
        let node_b = make_node_record(4567, true);
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(node_a.clone()).unwrap();
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), dest_node.public_key());
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), src_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), false)
            .node(node_a.public_key(), false)
            .node(node_b.public_key(), false)
            .build();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let gossip_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&mut dest_db, gossip_vec.as_slice(), gossip_source);

        assert_eq!(result, Qualification::Matched,);
    }

    #[test]
    fn standard_gossip_that_contains_record_describing_local_node_by_public_key_is_malformed() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let node_a = make_node_record(3456, true);
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), dest_node.public_key());
        src_db.add_node(node_a.clone()).unwrap();
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), src_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(node_a.public_key(), false)
            .node(dest_node.public_key(), false)
            .build();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let gossip_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&mut dest_db, gossip_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4:1234 contains a record with this Node's public key"
            )),
        );
    }

    #[test]
    fn standard_gossip_that_contains_record_describing_local_node_by_ip_address_is_malformed() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let node_a = make_node_record(3456, true);
        let mut node_b = make_node_record(4567, true);
        node_b.metadata.node_addr_opt = dest_node.node_addr_opt();
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(node_a.clone()).unwrap();
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), dest_node.public_key());
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), src_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(node_a.public_key(), false)
            .node(node_b.public_key(), true)
            .build();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let gossip_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&mut dest_db, gossip_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4:1234 contains a record claiming that {} has this Node's IP address",
                node_b.public_key()
            )),
        );
    }

    #[test]
    fn standard_gossip_that_contains_multiple_records_with_same_ip_is_malformed() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let node_a = make_node_record(3456, true);
        let node_b = make_node_record(4567, true);
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(node_a.clone()).unwrap();
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), dest_node.public_key());
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), src_node.public_key());
        let mut gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(node_a.public_key(), true)
            .node(node_b.public_key(), true)
            .build();
        gossip.node_records[2].node_addr_opt = Some(NodeAddr::new(
            &node_a.node_addr_opt().unwrap().ip_addr(),
            &[4567],
        ));
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let gossip_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.qualifies(&mut dest_db, gossip_vec.as_slice(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4:1234 contains multiple records claiming to be from 3.4.5.6"
            )),
        );
    }

    #[test]
    fn proper_standard_gossip_is_matched_and_handled() {
        /*
          Destination Node ==>
            S---D

          Source Node ==>
           A---S---D
               |
               B

          The source node(S) will gossip about Node A and B
          to the destination node(D).
        */
        let src_root = make_node_record(1234, true);
        let dest_root = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_root);
        let node_a = make_node_record(3456, true);
        let node_b = make_node_record(4567, true);
        let mut dest_db = db_from_node(&dest_root);
        dest_db.add_node(src_root.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        src_db.add_node(dest_db.root().clone()).unwrap();
        src_db.add_node(node_a.clone()).unwrap();
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), dest_root.public_key());
        src_db.add_arbitrary_half_neighbor(src_root.public_key(), &node_a.public_key());
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), &node_b.public_key());
        src_db
            .node_by_key_mut(src_root.public_key())
            .unwrap()
            .increment_version();
        src_db.resign_node(src_root.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .node(node_a.public_key(), false)
            .node(node_b.public_key(), false)
            .build();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let cryptde = CryptDENull::from(dest_db.root().public_key(), TEST_DEFAULT_CHAIN);
        let agrs_vec: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let gossip_source: SocketAddr = src_root.node_addr_opt().unwrap().into();
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.user_exit_preferences_opt = Some(UserExitPreferences {
            exit_countries: vec!["FR".to_string()],
            exit_location_preference: ExitPreference::ExitCountryWithFallback,
            exit_locations_opt: Some(vec![ExitLocation {
                country_codes: vec!["FR".to_string()],
                priority: 1,
            }]),
            db_countries: vec!["FR".to_string()],
        });
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let system = System::new("test");

        let qualifies_result = subject.qualifies(&dest_db, agrs_vec.as_slice(), gossip_source);
        let handle_result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs_vec,
            gossip_source,
            neighborhood_metadata,
        );

        assert_eq!(
            dest_db
                .node_by_key(node_a.public_key())
                .unwrap()
                .metadata
                .country_undesirability,
            0u32
        );
        assert_eq!(
            dest_db
                .node_by_key(node_b.public_key())
                .unwrap()
                .metadata
                .country_undesirability,
            UNREACHABLE_COUNTRY_PENALTY
        );
        assert_eq!(Qualification::Matched, qualifies_result);
        assert_eq!(GossipAcceptanceResult::Accepted, handle_result);
        assert_eq!(
            &src_db.root().inner,
            &dest_db.node_by_key(src_root.public_key()).unwrap().inner
        );
        assert!(dest_db.has_full_neighbor(dest_db.root().public_key(), src_db.root().public_key()));
        assert_eq!(
            &src_db.node_by_key(node_a.public_key()).unwrap().inner,
            &dest_db.node_by_key(node_a.public_key()).unwrap().inner
        );
        assert_eq!(
            &src_db.node_by_key(node_b.public_key()).unwrap().inner,
            &dest_db.node_by_key(node_b.public_key()).unwrap().inner
        );
        System::current().stop();
        assert_eq!(system.run(), 0);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn standard_gossip_handler_can_compute_patch() {
        /*
            Over here, root node is A and patch contains [A, B, C, D].
                                  A---B---C---D---E
            What does this test proves:
            The distance of A and E is more than 3 hops, hence E is being excluded.
        */

        let subject = StandardGossipHandler::new(Logger::new("test"));
        let node_a = make_node_record(1111, true);
        let node_b = make_node_record(2222, true);
        let node_c = make_node_record(3333, false);
        let node_d = make_node_record(4444, false);
        let node_e = make_node_record(5555, false);
        let mut node_a_db = db_from_node(&node_a);
        node_a_db.add_node(node_b.clone()).unwrap();
        node_a_db.add_node(node_c.clone()).unwrap();
        node_a_db.add_node(node_d.clone()).unwrap();
        node_a_db.add_node(node_e.clone()).unwrap();
        node_a_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_c.public_key(), node_d.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_d.public_key(), node_e.public_key());
        let gossip = GossipBuilder::new(&node_a_db)
            .node(node_b.public_key(), false)
            .node(node_c.public_key(), false)
            .node(node_d.public_key(), false)
            .node(node_e.public_key(), false)
            .build();
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.compute_patch(&agrs, node_a_db.root(), DB_PATCH_SIZE_FOR_TEST);

        let expected_hashset = vec![
            node_a.public_key().clone(),
            node_b.public_key().clone(),
            node_c.public_key().clone(),
            node_d.public_key().clone(),
        ]
        .into_iter()
        .collect::<HashSet<PublicKey>>();
        assert_eq!(result, expected_hashset);
    }

    #[test]
    fn standard_gossip_handler_computes_neighbors_from_database_and_neighbors_of_neighbors_from_agrs(
    ) {
        /*
            Over here, root node is A and patch contains [A, B, Y, C, D].
                                  A---B---C---D
                                      |
                                      Y
            What does this test proves:
            1) To find neighbors, we'll look into the root node's database. (For Example, A---B).
            2) To find neighbors of neighbors, we'll look into the AGRs. (For Example, B---Y, B---C, and C---D).
        */

        let subject = StandardGossipHandler::new(Logger::new("test"));
        let node_a = make_node_record(1111, true);
        let node_b = make_node_record(2222, true);
        let node_c = make_node_record(3333, false);
        let node_d = make_node_record(4444, false);
        let node_y = make_node_record(5555, false);
        let mut node_a_db = db_from_node(&node_a);
        node_a_db.add_node(node_b.clone()).unwrap();
        node_a_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        let mut node_b_db = db_from_node(&node_b);
        node_b_db.add_node(node_a.clone()).unwrap();
        node_b_db.add_node(node_y.clone()).unwrap();
        node_b_db.add_node(node_c.clone()).unwrap();
        node_b_db.add_node(node_d.clone()).unwrap();
        node_b_db.add_arbitrary_full_neighbor(node_b.public_key(), node_a.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_b.public_key(), node_y.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_c.public_key(), node_d.public_key());
        let gossip = GossipBuilder::new(&node_b_db)
            .node(node_b.public_key(), true)
            .node(node_c.public_key(), false)
            .node(node_d.public_key(), false)
            .node(node_y.public_key(), false)
            .build();
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let patch = subject.compute_patch(&agrs, node_a_db.root(), DB_PATCH_SIZE_FOR_TEST);

        let expected_hashset = vec![
            node_a.public_key().clone(),
            node_b.public_key().clone(),
            node_c.public_key().clone(),
            node_d.public_key().clone(),
            node_y.public_key().clone(),
        ]
        .into_iter()
        .collect::<HashSet<PublicKey>>();
        assert_eq!(patch, expected_hashset);
    }

    #[test]
    fn standard_gossip_handler_can_handle_node_for_which_agr_is_not_found_while_computing_patch() {
        /*
            Over here, root node is A and patch contains [A, B, C, D].
                                  A---B---C---D
                                  |
                                  X
            In this test, we won't provide AGR for Node X and thereby compute_patch() will not add
            Node X inside the patch. Also, logger will log it as it happens.
        */

        init_test_logging();
        let test_name = "standard_gossip_handler_can_handle_node_for_which_agr_is_not_found_while_computing_patch";
        let subject = StandardGossipHandler::new(Logger::new(test_name));
        let node_a = make_node_record(1111, true);
        let node_b = make_node_record(2222, true);
        let node_c = make_node_record(3333, false);
        let node_d = make_node_record(4444, false);
        let node_x = make_node_record(6666, false);
        let mut node_a_db = db_from_node(&node_a);
        node_a_db.add_node(node_b.clone()).unwrap();
        node_a_db.add_node(node_c.clone()).unwrap();
        node_a_db.add_node(node_d.clone()).unwrap();
        node_a_db.add_node(node_x.clone()).unwrap();
        node_a_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_a.public_key(), node_x.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_c.public_key(), node_d.public_key());
        let gossip = GossipBuilder::new(&node_a_db)
            .node(node_b.public_key(), false)
            .node(node_c.public_key(), false)
            .node(node_d.public_key(), false)
            .build();
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let patch = subject.compute_patch(&agrs, node_a_db.root(), DB_PATCH_SIZE_FOR_TEST);

        let expected_hashset = vec![
            node_a.public_key().clone(),
            node_b.public_key().clone(),
            node_c.public_key().clone(),
            node_d.public_key().clone(),
        ]
        .into_iter()
        .collect::<HashSet<PublicKey>>();
        assert_eq!(patch, expected_hashset);
        TestLogHandler::new().exists_log_matching(&format!(
            "TRACE: {}: While computing patch no AGR record found for public key {:?}",
            test_name,
            node_x.public_key()
        ));
    }

    #[test]
    fn standard_gossip_handler_will_ignore_gossips_from_outside_the_patch() {
        /*
            Over here, root node is A and patch contains [A, B, C, D].
                                  A---B---C---D---E---F
                                  |___________||______|

            The node B sends a gossip to A.
                                  A <---- B
            Node B tells Node A about the full neighborship of E and F.
            Since, the relation between E and F is outside the patch, standard gossip handler
            will not perform any database changes and will mark the gossip as ignored.

        */

        let cryptde = main_cryptde();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let node_a = make_node_record(1111, true);
        let node_b = make_node_record(2222, true);
        let node_c = make_node_record(3333, false);
        let node_d = make_node_record(4444, false);
        let node_e = make_node_record(5555, false);
        let node_f = make_node_record(6666, false);
        let mut node_a_db = db_from_node(&node_a);
        node_a_db.add_node(node_b.clone()).unwrap();
        node_a_db.add_node(node_c.clone()).unwrap();
        node_a_db.add_node(node_d.clone()).unwrap();
        node_a_db.add_node(node_e.clone()).unwrap();
        node_a_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_c.public_key(), node_d.public_key());
        node_a_db.add_arbitrary_full_neighbor(node_d.public_key(), node_e.public_key());
        let gossip_source: SocketAddr = node_b.node_addr_opt().unwrap().into();
        let mut node_b_db = db_from_node(&node_b);
        node_b_db.add_node(node_a.clone()).unwrap();
        node_b_db.add_node(node_c.clone()).unwrap();
        node_b_db.add_node(node_d.clone()).unwrap();
        node_b_db.add_node(node_e.clone()).unwrap();
        node_b_db.add_node(node_f.clone()).unwrap();
        node_b_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_b.public_key(), node_c.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_c.public_key(), node_d.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_d.public_key(), node_e.public_key());
        node_b_db.add_arbitrary_full_neighbor(node_e.public_key(), node_f.public_key());
        let gossip = GossipBuilder::new(&node_b_db)
            .node(node_b.public_key(), true)
            .node(node_c.public_key(), false)
            .node(node_d.public_key(), false)
            .node(node_e.public_key(), false)
            .node(node_f.public_key(), false)
            .build();
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.handle(
            cryptde,
            &mut node_a_db,
            agrs,
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(result, GossipAcceptanceResult::Ignored);
    }

    fn assert_compute_patch(db_patch_size: u8) {
        let subject = StandardGossipHandler::new(Logger::new("assert_compute_patch"));
        // one node to finish hops and another node that's outside the patch
        let nodes_count = db_patch_size as usize + 2;
        let nodes = make_node_records(nodes_count as u16);
        let db = linearly_connect_nodes(&nodes);
        // gossip is intended for the first node (also root), thereby it's excluded
        let gossip = gossip_about_nodes_from_database(&db, &nodes[1..]);
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let result = subject.compute_patch(&agrs, db.root(), db_patch_size);

        // last node is excluded because it is outside the patch
        let expected_nodes = &nodes[0..nodes_count - 1];
        let expected_patch = public_keys_from_node_records(&expected_nodes);
        assert_eq!(result, expected_patch);
    }

    #[test]
    fn patch_can_be_calculated_for_realistic_sizes() {
        assert_compute_patch(3);
        assert_compute_patch(4);
        assert_compute_patch(5);
        assert_compute_patch(6);
    }

    #[test]
    fn no_cpm_is_sent_in_case_full_neighborship_doesn_t_exist_and_cannot_be_created() {
        // Received gossip from a node we couldn't make a neighbor {Degree too high or malefactor banned node} (false, false)
        // This is Standard Gossip, even though it looks like a Debut,
        // because it's specifically handled by a StandardGossipHandler
        // instead of the GossipAcceptor (which would identify it as a Debut),
        // so the test is unrealistic. Also that the Gossip is ignored because
        // Node B isn't in Node A's patch, which matters to a StandardGossipHandler.
        let cryptde = main_cryptde();
        let root_node = make_node_record(1111, true);
        let mut root_db = db_from_node(&root_node);
        let src_node = make_node_record(2222, true);
        let src_node_socket_addr = SocketAddr::try_from(src_node.node_addr_opt().unwrap()).unwrap();
        let src_db = db_from_node(&src_node);
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let agrs = gossip.try_into().unwrap();
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let system = System::new("test");

        let result = subject.handle(
            cryptde,
            &mut root_db,
            agrs,
            src_node_socket_addr,
            make_default_neighborhood_metadata(),
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
        assert_eq!(result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn cpm_is_sent_in_case_full_neighborship_doesn_t_exist_and_is_created() {
        // Received Reply for Acceptance of Debut Gossip - (false, true)
        let cryptde = main_cryptde();
        let root_node = make_node_record(1111, true);
        let mut root_db = db_from_node(&root_node);
        let src_node = make_node_record(2222, true);
        let src_node_socket_addr = SocketAddr::try_from(src_node.node_addr_opt().unwrap()).unwrap();
        let mut src_db = db_from_node(&src_node);
        root_db.add_node(src_node.clone()).unwrap();
        root_db.add_half_neighbor(src_node.public_key()).unwrap();
        src_db.root_mut().increment_version();
        src_db.add_node(root_node.clone()).unwrap();
        src_db.add_half_neighbor(root_node.public_key()).unwrap();
        src_db.root_mut().resign();
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let agrs = gossip.try_into().unwrap();
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let system = System::new("test");

        let result = subject.handle(
            cryptde,
            &mut root_db,
            agrs,
            src_node_socket_addr,
            neighborhood_metadata,
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        assert_eq!(result, GossipAcceptanceResult::Accepted);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let received_message = recording.get_record::<ConnectionProgressMessage>(0);
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: src_node.node_addr_opt().unwrap().ip_addr(),
                event: ConnectionProgressEvent::StandardGossipReceived
            }
        );
    }

    #[test]
    fn cpm_is_not_sent_in_case_full_neighborship_exists_and_is_destroyed() {
        // Somebody banned us. (true, false)
        let cryptde = main_cryptde();
        let root_node = make_node_record(1111, true);
        let mut root_db = db_from_node(&root_node);
        let src_node = make_node_record(2222, true);
        let src_node_socket_addr = SocketAddr::try_from(src_node.node_addr_opt().unwrap()).unwrap();
        let mut src_db = db_from_node(&src_node);
        root_db.add_node(src_node.clone()).unwrap();
        root_db.add_arbitrary_full_neighbor(root_node.public_key(), src_node.public_key());
        src_db.root_mut().increment_version();
        src_db.add_node(root_node.clone()).unwrap();
        src_db.root_mut().resign();
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let agrs = gossip.try_into().unwrap();
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let system = System::new("test");

        let result = subject.handle(
            cryptde,
            &mut root_db,
            agrs,
            src_node_socket_addr,
            neighborhood_metadata,
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        assert_eq!(result, GossipAcceptanceResult::Accepted);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn cpm_is_not_sent_in_case_full_neighborship_exists_and_continues() {
        // Standard Gossips received after Neighborship is established (true, true)
        let cryptde = main_cryptde();
        let root_node = make_node_record(1111, true);
        let mut root_db = db_from_node(&root_node);
        let src_node = make_node_record(2222, true);
        let src_node_socket_addr = SocketAddr::try_from(src_node.node_addr_opt().unwrap()).unwrap();
        let mut src_db = db_from_node(&src_node);
        root_db.add_node(src_node.clone()).unwrap();
        root_db.add_arbitrary_full_neighbor(root_node.public_key(), src_node.public_key());
        src_db.root_mut().increment_version();
        src_db.add_node(root_node.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), root_node.public_key());
        src_db.root_mut().resign();
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(root_node.public_key(), true)
            .build();
        let agrs = gossip.try_into().unwrap();
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let system = System::new("test");

        let result = subject.handle(
            cryptde,
            &mut root_db,
            agrs,
            src_node_socket_addr,
            neighborhood_metadata,
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        assert_eq!(result, GossipAcceptanceResult::Accepted);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn standard_gossip_handler_doesnt_add_gossipping_node_if_already_max_degree() {
        let src_root = make_node_record(1234, true);
        let dest_root = make_node_record(2345, true);
        let five_neighbors: Vec<NodeRecord> = (0..MAX_DEGREE as u16)
            .into_iter()
            .map(|index| make_node_record(5110 + index, true))
            .collect();
        let add_neighbors = |db: &mut NeighborhoodDatabase, count: usize| {
            five_neighbors.iter().take(count).for_each(|node| {
                db.add_node(node.clone()).unwrap();
                let root_key = db.root().public_key().clone();
                db.add_arbitrary_full_neighbor(&root_key, node.public_key());
            });
        };
        let mut src_db = db_from_node(&src_root);
        add_neighbors(&mut src_db, 2);
        src_db.add_node(dest_root.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(five_neighbors[0].public_key(), dest_root.public_key());
        let mut dest_db = db_from_node(&dest_root);
        let dest_cryptde = CryptDENull::from(dest_root.public_key(), TEST_DEFAULT_CHAIN);
        add_neighbors(&mut dest_db, MAX_DEGREE);
        dest_db.add_node(src_root.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(five_neighbors[0].public_key(), src_root.public_key());
        let gossip = GossipProducerReal::new()
            .produce(&mut src_db, dest_root.public_key())
            .unwrap();
        let subject = make_subject(&dest_cryptde);

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_root.node_addr_opt().clone().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        assert_eq!(result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn last_gossip_handler_rejects_everything() {
        let subject = make_subject(main_cryptde());
        let reject_handler = subject.gossip_handlers.last().unwrap();
        let db = make_meaningless_db();
        let (debut, _, debut_gossip_source) = make_debut(1234, Mode::Standard);
        let (pass, _, pass_gossip_source) = make_pass(2345);
        let (introduction, introduction_gossip_source) = make_introduction(3456, 4567);
        let (standard_gossip, _, standard_gossip_source) = make_debut(9898, Mode::Standard);
        let debut_vec: Vec<AccessibleGossipRecord> = debut.try_into().unwrap();
        let pass_vec: Vec<AccessibleGossipRecord> = pass.try_into().unwrap();
        let introduction_vec: Vec<AccessibleGossipRecord> = introduction.try_into().unwrap();
        let standard_gossip_vec: Vec<AccessibleGossipRecord> = standard_gossip.try_into().unwrap();

        let debut_result = reject_handler.qualifies(&db, debut_vec.as_slice(), debut_gossip_source);
        let pass_result = reject_handler.qualifies(&db, pass_vec.as_slice(), pass_gossip_source);
        let introduction_result =
            reject_handler.qualifies(&db, introduction_vec.as_slice(), introduction_gossip_source);
        let standard_gossip_result =
            reject_handler.qualifies(&db, standard_gossip_vec.as_slice(), standard_gossip_source);

        assert_eq!(
            debut_result,
            Qualification::Malformed(
                "Gossip with 1 records from 1.2.3.4:1234 is unclassifiable by any qualifier"
                    .to_string()
            )
        );
        assert_eq!(
            pass_result,
            Qualification::Malformed(
                "Gossip with 1 records from 200.200.200.200:2000 is unclassifiable by any qualifier"
                    .to_string()
            )
        );
        assert_eq!(
            introduction_result,
            Qualification::Malformed(
                "Gossip with 2 records from 3.4.5.6:3456 is unclassifiable by any qualifier"
                    .to_string()
            )
        );
        assert_eq!(
            standard_gossip_result,
            Qualification::Malformed(
                "Gossip with 1 records from 9.8.9.8:9898 is unclassifiable by any qualifier"
                    .to_string()
            )
        );
    }

    #[test]
    fn non_useful_gossip_is_ignored() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let node_a = make_node_record(3456, true);
        let node_b = make_node_record(4567, true);
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(node_a.clone()).unwrap();
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_node.public_key(), dest_node.public_key());
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_node(node_a.clone()).unwrap();
        dest_db.add_node(node_b.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), src_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(node_a.public_key(), false)
            .node(node_b.public_key(), false)
            .build();
        let subject = make_subject(main_cryptde());

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_node.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
    }

    #[test]
    fn first_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        let (gossip, mut debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = make_subject(&root_node_cryptde);
        let before = time_t_timestamp();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.user_exit_preferences_opt = Some(UserExitPreferences {
            exit_countries: vec!["CZ".to_string()],
            exit_location_preference: ExitPreference::ExitCountryWithFallback,
            exit_locations_opt: Some(vec![ExitLocation {
                country_codes: vec!["CZ".to_string()],
                priority: 1,
            }]),
            db_countries: vec!["CZ".to_string()],
        });

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            gossip_source,
            neighborhood_metadata,
        );

        let after = time_t_timestamp();

        let expected = "Reply(Gossip_0v1 { node_records: [
GossipNodeRecord {
	inner: NodeRecordInner_0v1 {
		public_key: 0x01020304,
		node_addr_opt: Some(1.2.3.4:[1234]),
		earning_wallet: Wallet { kind: Address(0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0) },
		rate_pack: RatePack { routing_byte_rate: 1235, routing_service_rate: 1434, exit_byte_rate: 1237, exit_service_rate: 1634 },
		neighbors: [0x02030405],
		version: 1,
	},
	node_addr_opt: Some(1.2.3.4:[1234]),
	signed_data:
Length: 254 (0xfe) bytes
0000:   a8 6a 70 75  62 6c 69 63  5f 6b 65 79  44 01 02 03   .jpublic_keyD...
0010:   04 6e 65 61  72 6e 69 6e  67 5f 77 61  6c 6c 65 74   .nearning_wallet
0020:   a1 67 61 64  64 72 65 73  73 94 18 54  18 69 00 18   .gaddress..T.i..
0030:   db 18 8d 18  6e 09 18 37  18 49 18 71  18 33 18 d1   ....n..7.I.q.3..
0040:   18 ae 18 6f  18 df 18 5f  18 4b 18 75  18 bc 18 d0   ...o..._.K.u....
0050:   69 72 61 74  65 5f 70 61  63 6b a4 71  72 6f 75 74   irate_pack.qrout
0060:   69 6e 67 5f  62 79 74 65  5f 72 61 74  65 19 04 d3   ing_byte_rate...
0070:   74 72 6f 75  74 69 6e 67  5f 73 65 72  76 69 63 65   trouting_service
0080:   5f 72 61 74  65 19 05 9a  6e 65 78 69  74 5f 62 79   _rate...nexit_by
0090:   74 65 5f 72  61 74 65 19  04 d5 71 65  78 69 74 5f   te_rate...qexit_
00a0:   73 65 72 76  69 63 65 5f  72 61 74 65  19 06 62 69   service_rate..bi
00b0:   6e 65 69 67  68 62 6f 72  73 81 44 02  03 04 05 73   neighbors.D....s
00c0:   61 63 63 65  70 74 73 5f  63 6f 6e 6e  65 63 74 69   accepts_connecti
00d0:   6f 6e 73 f5  6b 72 6f 75  74 65 73 5f  64 61 74 61   ons.kroutes_data
00e0:   f5 67 76 65  72 73 69 6f  6e 01 70 63  6f 75 6e 74   .gversion.pcount
00f0:   72 79 5f 63  6f 64 65 5f  6f 70 74 62  41 55         ry_code_optbAU
	signature:
Length: 24 (0x18) bytes
0000:   01 02 03 04  f7 26 1e a5  d4 4a 71 d9  f8 42 08 35   .....&...Jq..B.5
0010:   e4 99 27 4a  85 7f 01 11                             ..'J....
}] }, 0x02030405, 2.3.4.5:[2345])".to_string();
        assert_eq!(format!("{:?}", result), expected);
        root_node
            .add_half_neighbor_key(debut_node.public_key().clone())
            .unwrap();
        root_node.increment_version();
        root_node.metadata.last_update = dest_db.root().metadata.last_update;
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        let reference_node = dest_db.node_by_key_mut(debut_node.public_key()).unwrap();
        debut_node.metadata.last_update = reference_node.metadata.last_update;
        debut_node.resign();
        assert_eq!(
            reference_node.metadata.country_undesirability,
            UNREACHABLE_COUNTRY_PENALTY
        );
        reference_node.metadata.country_undesirability = 0u32;
        assert_node_records_eq(reference_node, &debut_node, before, after);
    }

    #[test]
    fn second_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db.node_by_key_mut(existing_node_key).unwrap().resign();
        let (gossip, mut debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = make_subject(&root_node_cryptde);
        let before = time_t_timestamp();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
        let expected_acceptance_gossip = GossipBuilder::new(&dest_db)
            .node(root_node.public_key(), true)
            .node(existing_node_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                expected_acceptance_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap(),
            ),
            result
        );
        root_node
            .add_half_neighbor_key(debut_node.public_key().clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_key.clone())
            .unwrap();
        root_node.increment_version();
        root_node.metadata.last_update = dest_db.root().metadata.last_update;
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        let reference_node = dest_db.node_by_key_mut(debut_node.public_key()).unwrap();
        debut_node.metadata.last_update = reference_node.metadata.last_update;
        debut_node.resign();
        assert_node_records_eq(reference_node, &debut_node, before, after)
    }

    #[test]
    fn fourth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        let existing_node_2_key = &dest_db.add_node(make_node_record(4567, true)).unwrap();
        let existing_node_3_key = &dest_db.add_node(make_node_record(5678, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_2_key, existing_node_3_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_1_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_2_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_3_key)
            .unwrap()
            .resign();

        let (gossip, mut debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = make_subject(&root_node_cryptde);
        let before = time_t_timestamp();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
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
            &[
                GossipAcceptanceResult::Reply(
                    expected_acceptance_gossip_1,
                    debut_key.clone(),
                    debut_node_addr.clone(),
                ),
                GossipAcceptanceResult::Reply(
                    expected_acceptance_gossip_2,
                    debut_key.clone(),
                    debut_node_addr.clone(),
                ),
            ],
            &result,
        );
        root_node
            .add_half_neighbor_key(debut_node.public_key().clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_1_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_2_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_3_key.clone())
            .unwrap();
        root_node.increment_version();
        root_node.metadata.last_update = dest_db.root().metadata.last_update;
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        let reference_node = dest_db.node_by_key_mut(debut_node.public_key()).unwrap();
        debut_node.metadata.last_update = reference_node.metadata.last_update;
        debut_node.resign();
        assert_node_records_eq(reference_node, &debut_node, before, after)
    }

    #[test]
    fn fifth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        let existing_node_2_key = &dest_db.add_node(make_node_record(4567, true)).unwrap();
        let existing_node_3_key = &dest_db.add_node(make_node_record(5678, true)).unwrap();
        let existing_node_4_key = &dest_db.add_node(make_node_record(6789, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_4_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_2_key, existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_3_key, existing_node_4_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_1_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_2_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_3_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_4_key)
            .unwrap()
            .resign();

        let (gossip, debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = make_subject(&root_node_cryptde);

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let expected_acceptance_gossip_2 = GossipBuilder::new(&dest_db)
            .node(existing_node_2_key, true)
            .build();
        let expected_acceptance_gossip_3 = GossipBuilder::new(&dest_db)
            .node(existing_node_3_key, true)
            .build();
        assert_contains(
            &[
                GossipAcceptanceResult::Reply(
                    expected_acceptance_gossip_2,
                    debut_node.public_key().clone(),
                    debut_node.node_addr_opt().unwrap(),
                ),
                GossipAcceptanceResult::Reply(
                    expected_acceptance_gossip_3,
                    debut_node.public_key().clone(),
                    debut_node.node_addr_opt().unwrap(),
                ),
            ],
            &result,
        );
        root_node
            .add_half_neighbor_key(existing_node_1_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_2_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_3_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_4_key.clone())
            .unwrap();
        root_node.metadata.last_update = dest_db.root().metadata.last_update;
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
    }

    #[test]
    fn debut_when_degree_is_five_is_passed_to_least_connected_neighbor() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_1_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        let existing_node_2_key = &dest_db.add_node(make_node_record(4567, true)).unwrap();
        let existing_node_3_key = &dest_db.add_node(make_node_record(5678, true)).unwrap();
        let existing_node_4_key = &dest_db.add_node(make_node_record(6789, true)).unwrap();
        let existing_node_5_key = &dest_db.add_node(make_node_record(7890, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_1_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_3_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_4_key);
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_5_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_1_key, existing_node_2_key);
        dest_db.add_arbitrary_full_neighbor(existing_node_3_key, existing_node_4_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_1_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_2_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_3_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_4_key)
            .unwrap()
            .resign();
        dest_db
            .node_by_key_mut(existing_node_5_key)
            .unwrap()
            .resign();

        let (gossip, debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = make_subject(&root_node_cryptde);

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let expected_acceptance_gossip = GossipBuilder::new(&dest_db)
            .node(existing_node_5_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                expected_acceptance_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap(),
            ),
            result
        );
        root_node
            .add_half_neighbor_key(existing_node_1_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_2_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_3_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_4_key.clone())
            .unwrap();
        root_node
            .add_half_neighbor_key(existing_node_5_key.clone())
            .unwrap();
        root_node.resign();
        root_node.metadata.last_update = dest_db.root().metadata.last_update;
        assert_eq!(&root_node, dest_db.root());
    }

    #[test]
    fn redebut_is_passed_to_standard_gossip_handler_and_ignored_if_it_is_not_a_new_version() {
        let src_node = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_half_neighbor(src_node.public_key()).unwrap();
        // no version bump of src_node here: resulting Gossip is old news
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_half_neighbor(dest_node.public_key()).unwrap();

        let debut = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let subject = make_subject(main_cryptde());

        let result = subject.handle(
            &mut dest_db,
            debut.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
        assert_eq!(
            false,
            dest_db
                .node_by_key(src_node.public_key())
                .unwrap()
                .has_half_neighbor(dest_node.public_key())
        );
    }

    #[test]
    fn redebut_is_passed_to_standard_gossip_handler_and_incorporated_if_it_is_a_new_version() {
        let mut src_node = make_node_record(1234, true);
        src_node.set_last_updated(0);
        let mut src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        dest_db.add_node(src_node.clone()).unwrap();
        dest_db.add_half_neighbor(src_node.public_key()).unwrap();
        src_db.root_mut().increment_version();
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_half_neighbor(dest_node.public_key()).unwrap();
        src_db.resign_node(src_node.public_key());

        let debut = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let debut_agrs = debut.try_into().unwrap();
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();
        let subject = make_subject(main_cryptde());

        let begin_at = time_t_timestamp();
        let result = subject.handle(
            &mut dest_db,
            debut_agrs,
            gossip_source,
            make_default_neighborhood_metadata(),
        );
        let end_at = time_t_timestamp();

        assert_eq!(GossipAcceptanceResult::Accepted, result);
        let node = dest_db.node_by_key(src_node.public_key()).unwrap();
        assert_eq!(node.has_half_neighbor(dest_node.public_key()), true);
        assert_eq!(
            (node.last_updated() == begin_at) || (node.last_updated() == end_at),
            true
        );
    }

    #[test]
    fn introduction_is_impossible_if_only_candidate_is_half_neighbor() {
        let src_node = make_node_record(1234, true);
        let src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_node);
        let half_neighbor_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), half_neighbor_key);

        let debut = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let debut_agrs = debut.try_into().unwrap();
        let gossip_source = src_node.node_addr_opt().unwrap().into();
        let subject = make_subject(main_cryptde());

        let result = subject.handle(
            &mut dest_db,
            debut_agrs,
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let mut root_node = dest_db.root().clone();
        root_node.clear_half_neighbors();
        root_node
            .add_half_neighbor_key(src_node.public_key().clone())
            .expect("expected half neighbor");
        let gnr = GossipNodeRecord::from((
            root_node.inner.clone(),
            root_node.node_addr_opt(),
            main_cryptde(),
        ));
        let debut_gossip = Gossip_0v1 {
            node_records: vec![gnr],
        };
        let expected = make_expected_non_introduction_debut_response(&src_node, debut_gossip);
        assert_eq!(result, expected);
        assert_eq!(
            dest_db
                .node_by_key(dest_node.public_key())
                .unwrap()
                .has_half_neighbor(src_node.public_key()),
            true,
        );
    }

    #[test]
    fn introduction_is_impossible_if_only_candidate_does_not_accept_connections() {
        let src_node = make_node_record(1234, true);
        let src_db = db_from_node(&src_node);
        let dest_node = make_node_record(2345, true);
        let mut dest_db: NeighborhoodDatabase = db_from_node(&dest_node);
        let unaccepting_key = &dest_db
            .add_node(make_node_record_f(3456, true, false, true))
            .unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), unaccepting_key);

        let debut = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .build();
        let debut_agrs = debut.try_into().unwrap();
        let gossip_source = src_node.node_addr_opt().unwrap().into();
        let subject = make_subject(main_cryptde());

        let result = subject.handle(
            &mut dest_db,
            debut_agrs,
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let mut root_node = dest_db.root().clone();
        root_node.clear_half_neighbors();
        root_node
            .add_half_neighbor_key(src_node.public_key().clone())
            .expect("expected half neighbor");
        let gnr = GossipNodeRecord::from((
            root_node.inner.clone(),
            root_node.node_addr_opt(),
            main_cryptde(),
        ));
        let debut_gossip = Gossip_0v1 {
            node_records: vec![gnr],
        };
        let expected = make_expected_non_introduction_debut_response(&src_node, debut_gossip);
        assert_eq!(result, expected);
        assert_eq!(
            dest_db
                .node_by_key(dest_node.public_key())
                .unwrap()
                .has_half_neighbor(src_node.public_key()),
            true,
        );
    }

    fn make_expected_non_introduction_debut_response(
        src_node: &NodeRecord,
        debut_gossip: Gossip_0v1,
    ) -> GossipAcceptanceResult {
        GossipAcceptanceResult::Reply(
            debut_gossip,
            src_node.public_key().clone(),
            src_node.node_addr_opt().as_ref().unwrap().clone(),
        )
    }

    #[test]
    fn introduction_gossip_handler_sends_cpm_for_neighborship_established() {
        let cryptde = main_cryptde();
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let (gossip, gossip_source) = make_introduction(0, 1);
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        let (_introducer, introducee) =
            IntroductionHandler::identify_players(agrs.clone(), gossip_source).unwrap();
        let new_ip = introducee.node_addr_opt.unwrap().ip_addr();
        let system =
            System::new("introduction_gossip_handler_sends_cpm_for_neighborship_established");

        subject.handle(cryptde, &mut db, agrs, gossip_source, neighborhood_metadata);

        System::current().stop();
        assert_eq!(system.run(), 0);
        let recording = recording_arc.lock().unwrap();
        let received_message: &ConnectionProgressMessage = recording.get_record(0);
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: gossip_source.ip(),
                event: ConnectionProgressEvent::IntroductionGossipReceived(new_ip)
            }
        )
    }

    #[test]
    fn pass_handler_is_constructed_properly() {
        let pass_handler = PassHandler::new();

        assert_eq!(
            pass_handler,
            PassHandler {
                previous_pass_targets: RefCell::new(HashMap::new()),
            }
        );
    }

    #[test]
    fn pass_is_properly_handled() {
        // This test makes sure GossipAcceptor works correctly
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = make_subject(main_cryptde());

        let result = subject.handle(
            &mut db,
            gossip.try_into().unwrap(),
            gossip_source,
            make_default_neighborhood_metadata(),
        );

        let expected_relay_gossip = GossipBuilder::new(&db)
            .node(root_node.public_key(), true)
            .build();
        assert_eq!(
            result,
            GossipAcceptanceResult::Reply(
                expected_relay_gossip,
                pass_target.public_key().clone(),
                pass_target.node_addr_opt().unwrap(),
            )
        );
        assert_eq!(db.keys().len(), 1);
    }

    #[test]
    fn handles_a_new_pass_target() {
        let cryptde = main_cryptde();
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let subject = PassHandler::new();
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let system = System::new("handles_a_new_pass_target");
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let initial_timestamp = SystemTime::now();

        let result = subject.handle(
            cryptde,
            &mut db,
            gossip.try_into().unwrap(),
            gossip_source,
            neighborhood_metadata,
        );

        let final_timestamp = SystemTime::now();
        match result {
            GossipAcceptanceResult::Reply(_, _, _) => (),
            other => panic!(
                "Expected GossipAcceptanceResult::Reply but received {:?}",
                other
            ),
        }
        System::current().stop();
        assert_eq!(system.run(), 0);
        let recording = recording_arc.lock().unwrap();
        let received_message: &ConnectionProgressMessage = recording.get_record(0);
        let pass_target_ip_addr = pass_target.node_addr_opt().unwrap().ip_addr();
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: gossip_source.ip(),
                event: ConnectionProgressEvent::PassGossipReceived(pass_target_ip_addr)
            }
        );
        let previous_pass_targets = subject.previous_pass_targets.borrow();
        let timestamp = previous_pass_targets.get(&pass_target_ip_addr).unwrap();
        assert_eq!(previous_pass_targets.len(), 1);
        assert!(initial_timestamp <= *timestamp && *timestamp <= final_timestamp);
    }

    #[test]
    fn handles_pass_target_that_is_not_yet_expired() {
        let cryptde = main_cryptde();
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let subject = PassHandler::new();
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let pass_target_ip_addr = pass_target.node_addr_opt().unwrap().ip_addr();
        subject.previous_pass_targets.borrow_mut().insert(
            pass_target_ip_addr,
            SystemTime::now()
                .sub(PASS_GOSSIP_EXPIRED_TIME)
                .add(Duration::from_secs(1)),
        );
        let system = System::new("handles_pass_target_that_is_not_yet_expired");
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let initial_timestamp = SystemTime::now();

        let result = subject.handle(
            cryptde,
            &mut db,
            gossip.try_into().unwrap(),
            gossip_source,
            neighborhood_metadata,
        );

        let final_timestamp = SystemTime::now();
        System::current().stop();
        assert_eq!(system.run(), 0);
        assert_eq!(result, GossipAcceptanceResult::Ignored);
        let recording = recording_arc.lock().unwrap();
        let received_message: &ConnectionProgressMessage = recording.get_record(0);
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: gossip_source.ip(),
                event: ConnectionProgressEvent::PassLoopFound
            }
        );
        let previous_pass_targets = subject.previous_pass_targets.borrow();
        let timestamp = previous_pass_targets.get(&pass_target_ip_addr).unwrap();
        assert_eq!(previous_pass_targets.len(), 1);
        assert!(initial_timestamp <= *timestamp && *timestamp <= final_timestamp);
    }

    #[test]
    fn handles_pass_target_that_is_a_part_of_a_different_connection_progress() {
        let cryptde = main_cryptde();
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let subject = PassHandler::new();
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let pass_target_ip_addr = pass_target.node_addr_opt().unwrap().ip_addr();
        let system =
            System::new("handles_pass_target_that_is_a_part_of_a_different_connection_progress");
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        neighborhood_metadata.connection_progress_peers = vec![pass_target_ip_addr];

        let result = subject.handle(
            cryptde,
            &mut db,
            gossip.try_into().unwrap(),
            gossip_source,
            neighborhood_metadata,
        );

        System::current().stop();
        assert_eq!(system.run(), 0);
        assert_eq!(result, GossipAcceptanceResult::Ignored);
        let recording = recording_arc.lock().unwrap();
        let received_message: &ConnectionProgressMessage = recording.get_record(0);
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: gossip_source.ip(),
                event: ConnectionProgressEvent::PassLoopFound
            }
        );
    }

    #[test]
    fn handles_pass_target_that_has_expired() {
        let cryptde = main_cryptde();
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let subject = PassHandler::new();
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let (cpm_recipient, recording_arc) = make_cpm_recipient();
        let mut neighborhood_metadata = make_default_neighborhood_metadata();
        neighborhood_metadata.cpm_recipient = cpm_recipient;
        let pass_target_ip_addr = pass_target.node_addr_opt().unwrap().ip_addr();
        let expired_time = PASS_GOSSIP_EXPIRED_TIME.add(Duration::from_secs(1));
        subject
            .previous_pass_targets
            .borrow_mut()
            .insert(pass_target_ip_addr, SystemTime::now().sub(expired_time));
        let system = System::new("handles_pass_target_that_has_expired");
        let initial_timestamp = SystemTime::now();

        let result = subject.handle(
            cryptde,
            &mut db,
            gossip.try_into().unwrap(),
            gossip_source,
            neighborhood_metadata,
        );

        let final_timestamp = SystemTime::now();
        match result {
            GossipAcceptanceResult::Reply(_, _, _) => (),
            other => panic!(
                "Expected GossipAcceptanceResult::Reply but received {:?}",
                other
            ),
        }
        System::current().stop();
        assert_eq!(system.run(), 0);
        let recording = recording_arc.lock().unwrap();
        let received_message: &ConnectionProgressMessage = recording.get_record(0);
        assert_eq!(
            received_message,
            &ConnectionProgressMessage {
                peer_addr: gossip_source.ip(),
                event: ConnectionProgressEvent::PassGossipReceived(pass_target_ip_addr)
            }
        );
        let previous_pass_targets = subject.previous_pass_targets.borrow();
        let timestamp = previous_pass_targets.get(&pass_target_ip_addr).unwrap();
        assert!(initial_timestamp <= *timestamp && *timestamp <= final_timestamp);
    }

    #[test]
    fn standard_gossip_containing_unfamiliar_node_addrs_leads_to_them_being_ignored() {
        /*

        <---- Databases before the gossip ---->

        Destination Database (Root) ==>

          Root
         /  |
        B---A
        |
        D

        Source Database (A) ==>

          Root
         /  |
        B---A---E
        |   |
        C   F

        <------------------------------------->
         */

        let root_node = make_node_record(1234, true);
        let mut dest_db = db_from_node(&root_node);
        let node_a = make_node_record(2345, true);
        let mut src_db = db_from_node(&node_a);
        let node_b = make_node_record(3456, true);
        let node_c = make_node_record(4567, false);
        let node_d = make_node_record(5678, false);
        let node_e = make_node_record(6789, true);
        let node_f = make_node_record(7890, true);

        dest_db.add_node(node_a.clone()).unwrap();
        dest_db.add_node(node_b.clone()).unwrap();
        dest_db.add_node(node_d.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), node_a.public_key());
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), node_b.public_key());
        dest_db.add_arbitrary_full_neighbor(node_a.public_key(), node_b.public_key());
        dest_db.add_arbitrary_full_neighbor(node_b.public_key(), node_d.public_key());
        src_db.add_node(node_b.clone()).unwrap();
        src_db.add_node(node_c.clone()).unwrap();
        src_db.add_node(node_e.clone()).unwrap();
        src_db.add_node(node_f.clone()).unwrap();
        src_db.add_node(root_node.clone()).unwrap();
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
        resign_nodes(
            &mut src_db,
            vec![&root_node, &node_a, &node_b, &node_c, &node_e, &node_f],
        );
        let gossip = GossipBuilder::new(&src_db)
            .node(node_a.public_key(), true)
            .node(node_b.public_key(), false)
            .node(node_c.public_key(), false)
            .node(node_e.public_key(), true)
            .node(node_f.public_key(), true)
            .build();
        let subject = make_subject(main_cryptde());
        let before = time_t_timestamp();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            node_a.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
        assert_eq!(GossipAcceptanceResult::Accepted, result);
        let mut expected_dest_db = src_db.clone();
        expected_dest_db.remove_arbitrary_half_neighbor(node_e.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_f.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_b.public_key(), node_d.public_key());
        expected_dest_db.add_node(node_d.clone()).unwrap();
        expected_dest_db.add_arbitrary_half_neighbor(node_d.public_key(), node_b.public_key());
        resign_nodes(
            &mut expected_dest_db,
            vec![&node_a, &node_b, &node_d, &node_e, &node_f],
        );
        fix_last_update_nodes(&mut expected_dest_db, &dest_db);
        expected_dest_db
            .node_by_key_mut(node_c.public_key())
            .unwrap()
            .metadata
            .node_location_opt = None;
        assert_node_records_eq(
            dest_db.node_by_key_mut(root_node.public_key()).unwrap(),
            expected_dest_db
                .node_by_key(root_node.public_key())
                .unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(node_a.public_key()).unwrap(),
            expected_dest_db.node_by_key(node_a.public_key()).unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(node_b.public_key()).unwrap(),
            expected_dest_db.node_by_key(node_b.public_key()).unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(node_c.public_key()).unwrap(),
            expected_dest_db.node_by_key(node_c.public_key()).unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(node_d.public_key()).unwrap(),
            expected_dest_db.node_by_key(node_d.public_key()).unwrap(),
            before,
            after,
        );
        assert_eq!(dest_db.node_by_key(node_e.public_key()), None);
        assert_eq!(dest_db.node_by_key(node_f.public_key()), None);
    }

    fn fix_last_update_nodes(
        expected_db: &mut NeighborhoodDatabase,
        dest_db: &NeighborhoodDatabase,
    ) {
        let keys = expected_db
            .keys()
            .iter()
            .map(|key| (*key).clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .for_each(|pubkey| match dest_db.node_by_key(&pubkey) {
                Some(node_record) => {
                    expected_db
                        .node_by_key_mut(&pubkey)
                        .unwrap()
                        .metadata
                        .last_update = node_record.metadata.last_update;
                    expected_db.node_by_key_mut(&pubkey).unwrap().resign();
                }
                None => {}
            });
    }

    #[test]
    fn initial_standard_gossip_does_not_produce_neighborship_if_destination_degree_is_already_full()
    {
        /*
        Destination Database ==>
            N2  N3
             \  /
        N1---Dest---Third
             /  \
            N4  N5

        Source Database ==>
        Src---Third---Dest

        Disc

        Expected Destination Database ==>
            N2  N3
             \  /   Third
        N1---Dest---|
             /  \   Src
            N4  N5
         */
        let dest_node = make_node_record(1234, true);
        let dest_node_cryptde = CryptDENull::from(&dest_node.public_key(), TEST_DEFAULT_CHAIN);
        let mut dest_db = db_from_node(&dest_node);
        let src_node = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_node);
        let third_node = make_node_record(3456, true);
        let disconnected_node = make_node_record(4567, true); // Why does this have an Ip Address?
                                                              // These are only half neighbors. Will they be ignored in degree calculation?
        for idx in 0..MAX_DEGREE {
            let failed_node_key = &dest_db
                .add_node(make_node_record(4000 + idx as u16, true))
                .unwrap();
            dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), failed_node_key);
        }
        dest_db.add_node(third_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_node.public_key(), third_node.public_key());
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(third_node.clone()).unwrap();
        src_db.add_node(disconnected_node.clone()).unwrap();
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
        resign_nodes(&mut src_db, vec![&src_node, &dest_node, &third_node]);
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(third_node.public_key(), true)
            .node(disconnected_node.public_key(), false)
            .build();
        let subject = make_subject(&dest_node_cryptde);
        let before = time_t_timestamp();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_node.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
        let mut expected_dest_db = src_db.clone();
        expected_dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), src_node.public_key());
        expected_dest_db
            .remove_neighbor(disconnected_node.public_key())
            .unwrap();
        for idx in 0..MAX_DEGREE {
            let failed_node_key = &expected_dest_db
                .add_node(make_node_record(4000 + idx as u16, true))
                .unwrap();
            expected_dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), failed_node_key);
        }
        let dest_node_mut = expected_dest_db
            .node_by_key_mut(dest_node.public_key())
            .unwrap();
        dest_node_mut.increment_version();
        dest_node_mut.resign();
        assert_eq!(result, GossipAcceptanceResult::Accepted);
        fix_last_update_nodes(&mut expected_dest_db, &dest_db);
        assert_node_records_eq(
            dest_db.node_by_key_mut(third_node.public_key()).unwrap(),
            expected_dest_db
                .node_by_key(third_node.public_key())
                .unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(src_node.public_key()).unwrap(),
            expected_dest_db.node_by_key(src_node.public_key()).unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(dest_node.public_key()).unwrap(),
            expected_dest_db
                .node_by_key(dest_node.public_key())
                .unwrap(),
            before,
            after,
        );
        // If you're here because you're working on GH-650, and this assert is failing,
        // everything's fine: GH-650 is supposed to make it fail. Modify the assert so
        // that it ensures that the disconnected Node is preserved.
        assert_eq!(dest_db.node_by_key(disconnected_node.public_key()), None);
    }

    #[test]
    fn standard_gossip_with_current_and_obsolete_versions_doesnt_change_anything() {
        let dest_root = make_node_record(1234, true);
        let mut dest_db = db_from_node(&dest_root);
        let src_root = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_root);
        let mut current_node = make_node_record(3456, true);
        let mut obsolete_node = make_node_record(4567, false);
        current_node.set_version(100);
        obsolete_node.set_version(100);
        dest_db.add_node(src_root.clone()).unwrap();
        dest_db.add_node(current_node.clone()).unwrap();
        dest_db.add_node(obsolete_node.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), current_node.public_key());
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), obsolete_node.public_key());
        dest_db.add_arbitrary_full_neighbor(src_root.public_key(), current_node.public_key());
        dest_db.add_arbitrary_full_neighbor(src_root.public_key(), obsolete_node.public_key());
        obsolete_node.set_version(99);
        src_db.add_node(dest_root.clone()).unwrap();
        src_db.add_node(current_node.clone()).unwrap();
        src_db.add_node(obsolete_node.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        src_db.add_arbitrary_full_neighbor(dest_root.public_key(), current_node.public_key());
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), obsolete_node.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .node(current_node.public_key(), false)
            .node(obsolete_node.public_key(), false)
            .build();
        let subject = make_subject(main_cryptde());
        let original_dest_db = dest_db.clone();
        let before = time_t_timestamp();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_root.node_addr_opt().unwrap().into(),
            make_default_neighborhood_metadata(),
        );

        let after = time_t_timestamp();
        assert_eq!(result, GossipAcceptanceResult::Ignored);
        assert_node_records_eq(
            dest_db.node_by_key_mut(dest_root.public_key()).unwrap(),
            original_dest_db
                .node_by_key(dest_root.public_key())
                .unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(src_root.public_key()).unwrap(),
            original_dest_db.node_by_key(src_root.public_key()).unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(current_node.public_key()).unwrap(),
            original_dest_db
                .node_by_key(current_node.public_key())
                .unwrap(),
            before,
            after,
        );
        assert_node_records_eq(
            dest_db.node_by_key_mut(obsolete_node.public_key()).unwrap(),
            original_dest_db
                .node_by_key(obsolete_node.public_key())
                .unwrap(),
            before,
            after,
        );
    }

    #[test]
    fn make_debut_triple_doesnt_like_record_with_no_node_addr() {
        let root_node = make_node_record(1234, true);
        let db = db_from_node(&root_node);
        let neighbor = make_node_record(2345, false);
        let agr = AccessibleGossipRecord::from(&neighbor);

        let result = GossipAcceptorReal::make_debut_triple(&db, &agr);

        assert_eq!(
            Err(format!(
                "Can't generate debut to {}: no IP address supplied",
                neighbor.public_key()
            )),
            result
        );
    }

    #[test]
    fn make_debut_triple_doesnt_like_record_with_no_ports() {
        let root_node = make_node_record(1234, true);
        let db = db_from_node(&root_node);
        let mut neighbor = make_node_record(2345, true);
        neighbor.metadata.node_addr_opt =
            Some(NodeAddr::new(&IpAddr::from_str("2.3.4.5").unwrap(), &[]));
        let agr = AccessibleGossipRecord::from(&neighbor);

        let result = GossipAcceptorReal::make_debut_triple(&db, &agr);

        assert_eq!(
            Err(format!(
                "Can't generate debut to {} at {}: no ports were specified",
                neighbor.public_key(),
                neighbor.node_addr_opt().unwrap().ip_addr()
            )),
            result
        );
    }

    #[test]
    fn make_debut_triple_works_when_its_happy() {
        let root_node = make_node_record(1234, true);
        let db = db_from_node(&root_node);
        let neighbor = make_node_record(2345, true);
        let agr = AccessibleGossipRecord::from(&neighbor);

        let result = GossipAcceptorReal::make_debut_triple(&db, &agr);

        assert_eq!(
            Ok((
                GossipBuilder::new(&db)
                    .node(root_node.public_key(), true)
                    .build(),
                neighbor.public_key().clone(),
                neighbor.node_addr_opt().unwrap()
            )),
            result
        );
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_twos_and_finds_three() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let other_neighbor_1_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let other_neighbor_2_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let other_neighbor_3_key = &db.add_node(make_node_record(5678, true)).unwrap();
        let excluded_key = &db.add_node(make_node_record(6789, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        let subject = DebutHandler::new(Logger::new("test"));
        let excluded = AccessibleGossipRecord::from((&db, excluded_key, true));

        let result = subject.find_more_appropriate_neighbor(&db, &excluded);

        assert_eq!(result, Some(less_connected_neighbor_key));
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_if_all_neighbors_are_connected_as_well_as_me() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let other_neighbor_1_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let other_neighbor_2_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let other_neighbor_3_key = &db.add_node(make_node_record(5678, true)).unwrap();
        let excluded_key = &db.add_node(make_node_record(6789, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_3_key);
        let subject = DebutHandler::new(Logger::new("test"));
        let excluded = AccessibleGossipRecord::from((&db, excluded_key, true));

        let result = subject.find_more_appropriate_neighbor(&db, &excluded);

        assert_eq!(result, None);
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_if_candidate_is_not_accepting_connections() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key = &db
            .add_node(make_node_record_f(2345, true, false, true))
            .unwrap();
        let other_neighbor_1_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let other_neighbor_2_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let other_neighbor_3_key = &db.add_node(make_node_record(5678, true)).unwrap();
        let other_neighbor_4_key = &db.add_node(make_node_record(6789, true)).unwrap();
        let excluded_key = &db.add_node(make_node_record(7890, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_4_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        let subject = DebutHandler::new(Logger::new("test"));
        let excluded = AccessibleGossipRecord::from((&db, excluded_key, true));

        let result = subject.find_more_appropriate_neighbor(&db, &excluded);

        assert_eq!(result, None);
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_if_candidate_is_excluded() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let less_connected_neighbor_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let other_neighbor_1_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let other_neighbor_2_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let other_neighbor_3_key = &db.add_node(make_node_record(5678, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        let subject = DebutHandler::new(Logger::new("test"));
        let less_connected_neighbor_agr =
            AccessibleGossipRecord::from((&db, less_connected_neighbor_key, true));

        let result = subject.find_more_appropriate_neighbor(&db, &less_connected_neighbor_agr);

        assert_eq!(result, None);
    }

    #[test]
    fn root_neighbors_ordered_by_degree() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let near_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let far_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let distant_node_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let high_degree_key = &db.add_node(make_node_record(5678, true)).unwrap();
        let low_degree_key = &db.add_node(make_node_record(6789, true)).unwrap();
        let excluded_key = &db.add_node(make_node_record(7890, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), high_degree_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), low_degree_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), excluded_key);
        db.add_arbitrary_full_neighbor(high_degree_key, distant_node_key);
        db.add_arbitrary_full_neighbor(high_degree_key, near_key);
        db.add_arbitrary_full_neighbor(low_degree_key, far_key);
        let excluded_agr = AccessibleGossipRecord::from((&db, excluded_key, true));

        let result =
            DebutHandler::root_full_neighbors_ordered_by_degree_excluding(&db, &excluded_agr);

        assert_eq!(result, vec![low_degree_key, high_degree_key])
    }

    #[test]
    fn find_least_connected_half_neighbor_excluding_includes_half_neighbors() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let excluded_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let well_connected_full_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let less_connected_half_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let neighbor_1_key = &db.add_node(make_node_record(5678, false)).unwrap();
        let neighbor_2_key = &db.add_node(make_node_record(6789, false)).unwrap();
        let neighbor_3_key = &db.add_node(make_node_record(7890, false)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), excluded_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), well_connected_full_key);
        db.add_arbitrary_half_neighbor(root_node.public_key(), less_connected_half_key);
        db.add_arbitrary_full_neighbor(less_connected_half_key, neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_half_key, neighbor_2_key);
        db.add_arbitrary_full_neighbor(well_connected_full_key, neighbor_1_key);
        db.add_arbitrary_full_neighbor(well_connected_full_key, neighbor_2_key);
        db.add_arbitrary_full_neighbor(well_connected_full_key, neighbor_3_key);
        let excluded_agr = AccessibleGossipRecord::from(db.node_by_key(excluded_key).unwrap());

        let result =
            DebutHandler::find_least_connected_half_neighbor_excluding(&db, &excluded_agr).unwrap();

        assert_eq!(result, less_connected_half_key)
    }

    #[test]
    fn root_full_neighbors_ordered_by_degree_excluding_ignores_half_neighbors() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let excluded_key = &db.add_node(make_node_record(2345, true)).unwrap();
        let three_neighbors_key = &db.add_node(make_node_record(3456, true)).unwrap();
        let two_neighbors_key = &db.add_node(make_node_record(4567, true)).unwrap();
        let one_neighbor_key = &db.add_node(make_node_record(4568, true)).unwrap();
        let neighbor_1_key = &db.add_node(make_node_record(5678, false)).unwrap();
        let neighbor_2_key = &db.add_node(make_node_record(6789, false)).unwrap();
        let neighbor_3_key = &db.add_node(make_node_record(7890, false)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), excluded_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), three_neighbors_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), two_neighbors_key);
        db.add_arbitrary_half_neighbor(root_node.public_key(), one_neighbor_key);
        db.add_arbitrary_full_neighbor(one_neighbor_key, neighbor_1_key);
        db.add_arbitrary_full_neighbor(two_neighbors_key, neighbor_1_key);
        db.add_arbitrary_full_neighbor(two_neighbors_key, neighbor_2_key);
        db.add_arbitrary_full_neighbor(three_neighbors_key, neighbor_1_key);
        db.add_arbitrary_full_neighbor(three_neighbors_key, neighbor_2_key);
        db.add_arbitrary_full_neighbor(three_neighbors_key, neighbor_3_key);
        let excluded_agr = AccessibleGossipRecord::from(db.node_by_key(excluded_key).unwrap());

        let result =
            DebutHandler::root_full_neighbors_ordered_by_degree_excluding(&db, &excluded_agr);

        assert_eq!(
            vec_to_set(result),
            vec_to_set(vec![two_neighbors_key, three_neighbors_key])
        );
    }

    fn resign_nodes(db: &mut NeighborhoodDatabase, nodes: Vec<&NodeRecord>) {
        nodes
            .into_iter()
            .for_each(|n| db.node_by_key_mut(n.public_key()).unwrap().resign());
    }

    fn make_debut(n: u16, mode: Mode) -> (Gossip_0v1, NodeRecord, SocketAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n, mode);
        let gossip_source: SocketAddr = match debut_node.node_addr_opt() {
            Some(node_addr) => node_addr.into(),
            None => SocketAddr::from_str("200.200.200.200:2000").unwrap(),
        };
        (gossip, debut_node, gossip_source)
    }

    fn make_pass(n: u16) -> (Gossip_0v1, NodeRecord, SocketAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n, Mode::Standard);
        (
            gossip,
            debut_node,
            SocketAddr::from_str("200.200.200.200:2000").unwrap(),
        )
    }

    fn make_single_node_gossip(n: u16, mode: Mode) -> (Gossip_0v1, NodeRecord) {
        let mut debut_node = make_node_record(n, true);
        adjust_for_mode(&mut debut_node, mode);
        let src_db = db_from_node(&debut_node);
        let gossip = GossipBuilder::new(&src_db)
            .node(debut_node.public_key(), true)
            .build();
        (gossip, debut_node)
    }

    fn make_introduction(introducer_n: u16, introducee_n: u16) -> (Gossip_0v1, SocketAddr) {
        let mut introducer_node: NodeRecord = make_node_record(introducer_n, true);
        adjust_for_mode(&mut introducer_node, Mode::Standard);
        introducer_node.set_version(10);
        let mut introducee_node: NodeRecord = make_node_record(introducee_n, true);
        adjust_for_mode(&mut introducee_node, Mode::Standard);
        introducee_node.set_version(10);
        let introducer_key = introducer_node.public_key().clone();
        let introducee_key = introducee_node.public_key().clone();
        let gossip_source: SocketAddr = introducer_node.node_addr_opt().unwrap().into();

        let mut src_db = db_from_node(&introducer_node);
        src_db.add_node(introducee_node.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(&introducer_key, &introducee_key);
        src_db
            .node_by_key_mut(&introducer_key)
            .unwrap()
            .increment_version();
        src_db
            .node_by_key_mut(&introducee_key)
            .unwrap()
            .increment_version();
        src_db.resign_node(&introducer_key);
        src_db.resign_node(&introducee_key);
        let gossip = GossipBuilder::new(&src_db)
            .node(&introducer_key, true)
            .node(&introducee_key, true)
            .build();

        (gossip, gossip_source)
    }

    fn adjust_for_mode(node: &mut NodeRecord, mode: Mode) {
        match mode {
            Mode::Standard => {
                assert!(node.node_addr_opt().is_some());
                node.inner.accepts_connections = true;
                node.inner.routes_data = true;
            }
            Mode::OriginateOnly => {
                node.metadata.node_addr_opt = None;
                node.inner.accepts_connections = false;
                node.inner.routes_data = true;
            }
        }
    }

    fn make_subject(crypt_de: &dyn CryptDE) -> GossipAcceptorReal {
        GossipAcceptorReal::new(crypt_de)
    }

    fn assert_node_records_eq(
        actual: &mut NodeRecord,
        expected: &NodeRecord,
        before: u32,
        after: u32,
    ) {
        assert!(
            actual.metadata.last_update >= before,
            "Timestamp should have been at least {}, but was {}",
            before,
            actual.metadata.last_update
        );
        assert!(
            actual.metadata.last_update <= after,
            "Timestamp should not have been after {}, but was {}",
            after,
            actual.metadata.last_update
        );
        assert_eq!(actual, expected);
    }
}
