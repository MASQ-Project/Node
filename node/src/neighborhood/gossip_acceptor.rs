// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::{Gossip, GossipBuilder};
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::node_record::NodeRecord;
use crate::neighborhood::AccessibleGossipRecord;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::node_addr::NodeAddr;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

/// Note: if you decide to change this, make sure you test thoroughly. Values less than 5 may lead
/// to inability to grow the network beyond a very small size; values greater than 5 may lead to
/// Gossip storms.
pub const MAX_DEGREE: usize = 5;

#[derive(Clone, PartialEq, Debug)]
pub enum GossipAcceptanceResult {
    // The incoming Gossip produced database changes. Generate standard Gossip and broadcast.
    Accepted,
    // Don't generate Gossip from the database: instead, send this Gossip to the provided key and NodeAddr.
    Reply(Gossip, PublicKey, NodeAddr),
    // The incoming Gossip contained nothing we didn't know. Don't send out any Gossip because of it.
    Ignored,
    // Gossip was ignored because it was evil: ban the sender of the Gossip as a malefactor.
    Ban(String),
}

#[derive(Clone, PartialEq, Debug)]
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
        agrs: &Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
    ) -> Qualification;
    fn handle(
        &self,
        cryptde: &dyn CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
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
        agrs: &Vec<AccessibleGossipRecord>,
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
                source_node_addr.clone(),
            );
        }
        if let Ok(result) = self.try_accept_debut(cryptde, database, &source_agr, gossip_source) {
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
                return GossipAcceptanceResult::Ignored;
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
                    "No degree-3-or-greater neighbors; can't find more-appropriate neighbor"
                );
                None
            }
            // Neighbor of degree 3 or greater, but not less connected than I am
            Some(ref key)
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
    ) -> Result<GossipAcceptanceResult, ()> {
        if database.gossip_target_degree(database.root().public_key()) >= MAX_DEGREE {
            debug!(self.logger, "Neighbor count already at maximum");
            return Err(());
        }
        let debut_node_addr_opt = debuting_agr.node_addr_opt.clone();
        let debuting_node = NodeRecord::from(debuting_agr);
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
                if Self::should_not_make_introduction(&debuting_agr) {
                    let ip_addr_str = match &debuting_agr.node_addr_opt {
                        Some(node_addr) => node_addr.ip_addr().to_string(),
                        None => "?.?.?.?".to_string(),
                    };
                    debug!(self.logger, "Node {} at {} is responding to first introduction: sending update Gossip instead of further introduction",
                                              debuting_agr.inner.public_key,
                                              ip_addr_str);
                    Ok(GossipAcceptanceResult::Accepted)
                } else {
                    match self.make_introduction(database, &debuting_agr, gossip_source) {
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
                                "DebutHandler can't make an introduction, but is accepting {} at {} and broadcasting change",
                                &debut_node_key,
                                gossip_source,
                            );
                            Ok(GossipAcceptanceResult::Accepted)
                        }
                    }
                }
            }
            Ok(false) => panic!("Brand-new neighbor already existed"),
        }
    }

    fn make_introduction(
        &self,
        database: &NeighborhoodDatabase,
        debuting_agr: &AccessibleGossipRecord,
        gossip_source: SocketAddr,
    ) -> Option<(Gossip, PublicKey, NodeAddr)> {
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

    fn should_not_make_introduction(debuting_agr: &AccessibleGossipRecord) -> bool {
        !debuting_agr.inner.neighbors.is_empty()
    }

    fn make_pass_gossip(database: &NeighborhoodDatabase, pass_target: &PublicKey) -> Gossip {
        GossipBuilder::new(database).node(pass_target, true).build()
    }
}

struct PassHandler {}

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
        agrs: &Vec<AccessibleGossipRecord>,
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
    ) -> GossipAcceptanceResult {
        let gossip = GossipBuilder::new(database)
            .node(database.root().public_key(), true)
            .build();
        let pass_agr = &agrs[0]; // empty Gossip shouldn't get here
        let pass_target_node_addr = pass_agr
            .node_addr_opt
            .clone()
            .expect("Pass lost its NodeAddr");
        GossipAcceptanceResult::Reply(
            gossip,
            pass_agr.inner.public_key.clone(),
            pass_target_node_addr,
        )
    }
}

impl PassHandler {
    fn new() -> PassHandler {
        PassHandler {}
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
        agrs: &Vec<AccessibleGossipRecord>,
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
    ) -> GossipAcceptanceResult {
        if database.root().full_neighbor_keys(database).len() >= MAX_DEGREE {
            GossipAcceptanceResult::Ignored
        } else {
            let (introducer, introducee) = Self::identify_players(agrs, gossip_source)
                .expect("Introduction not properly qualified");
            let introducer_key = introducer.inner.public_key.clone();
            match self.update_database(database, cryptde, introducer) {
                Ok(_) => (),
                Err(e) => {
                    return GossipAcceptanceResult::Ban(format!(
                        "Introducer {} tried changing immutable characteristic: {}",
                        introducer_key, e
                    ));
                }
            }
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

    fn verify_size(agrs: &Vec<AccessibleGossipRecord>) -> Option<Qualification> {
        if agrs.len() != 2 {
            return Some(Qualification::Unmatched);
        }
        None
    }

    fn order_is_introducee_introducer(
        agrs_ref: &Vec<AccessibleGossipRecord>,
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
    ) -> Result<bool, String> {
        let introducer_key = &introducer.inner.public_key.clone();
        match database.node_by_key_mut(introducer_key) {
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
                let new_introducer = NodeRecord::from(introducer);
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
            .add_half_neighbor(introducer_key)
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
        agrs: &Vec<AccessibleGossipRecord>,
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
    ) -> GossipAcceptanceResult {
        let mut db_changed =
            self.identify_and_add_non_introductory_new_nodes(database, &agrs, gossip_source);
        db_changed = self.identify_and_update_obsolete_nodes(database, &agrs) || db_changed;
        db_changed = self.handle_root_node(cryptde, database, gossip_source) || db_changed;
        // If no Nodes need updating, return ::Ignored and don't change the database.
        // Otherwise, return ::Accepted.
        if db_changed {
            trace!(self.logger, "Current database: {}", database.to_dot_graph());
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

    fn identify_and_add_non_introductory_new_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: &Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
    ) -> bool {
        let all_keys = database
            .keys()
            .into_iter()
            .cloned()
            .collect::<HashSet<PublicKey>>();
        agrs.iter()
            .filter(|agr| !all_keys.contains(&agr.inner.public_key))
            .filter(|agr| match &agr.node_addr_opt {
                None => true,
                Some(node_addr) => {
                    let socket_addrs: Vec<SocketAddr> = node_addr.clone().into();
                    socket_addrs.contains(&gossip_source)
                }
            })
            .for_each(|agr| {
                database
                    .add_node(NodeRecord::from(agr))
                    .expect("List of new Nodes contained existing Nodes");
            });
        database.keys().len() != all_keys.len()
    }

    fn identify_and_update_obsolete_nodes(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: &Vec<AccessibleGossipRecord>,
    ) -> bool {
        let change_flags: Vec<bool> = agrs
            .iter()
            .flat_map(|agr| match database.node_by_key(&agr.inner.public_key) {
                Some(existing_node) if existing_node.version() < agr.inner.version => {
                    Some(self.update_database_record(database, agr))
                }
                _ => None,
            })
            .collect();
        change_flags.into_iter().any(|f| f)
    }

    fn handle_root_node(
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
        agr: &AccessibleGossipRecord,
    ) -> bool {
        let existing_node_record = database
            .node_by_key_mut(&agr.inner.public_key)
            .expect("Node magically disappeared");
        if let (None, Some(new_node_addr)) = (
            existing_node_record.node_addr_opt(),
            agr.node_addr_opt.clone(),
        ) {
            existing_node_record
                .set_node_addr(&new_node_addr)
                .expect("Unexpected complaint about changing NodeAddr");
        } // Maybe we eventually want to detect errors here and abort the change, returning false.

        existing_node_record.inner = agr.inner.clone();
        existing_node_record.signed_gossip = agr.signed_gossip.clone();
        existing_node_record.signature = agr.signature.clone();
        true
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
        agrs: &Vec<AccessibleGossipRecord>,
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
    ) -> GossipAcceptanceResult {
        let (qualification, handler_ref) = self
            .gossip_handlers
            .iter()
            .map(|h| (h.qualifies(database, &agrs, gossip_source), h.as_ref()))
            .find(|pair| match pair {
                (Qualification::Unmatched, _) => false,
                _ => true,
            })
            .expect("gossip_handlers should intercept everything");
        match qualification {
            Qualification::Matched => {
                debug!(
                    self.logger,
                    "Gossip delegated to {}",
                    handler_ref.type_name()
                );
                handler_ref.handle(self.cryptde, database, agrs, gossip_source)
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
    ) -> Result<(Gossip, PublicKey, NodeAddr), String> {
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
    use crate::neighborhood::neighborhood_test_utils::{
        db_from_node, make_meaningless_db, make_node_record, make_node_record_f,
    };
    use crate::neighborhood::node_record::NodeRecord;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::{assert_contains, cryptde, vec_to_set, DEFAULT_CHAIN_ID};
    use std::convert::TryInto;
    use std::str::FromStr;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        Standard,
        OriginateOnly,
        // GossipAcceptor doesn't care about ConsumeOnly; that's routing, not Gossip
        // ZeroHop is decentralized and should never appear in GossipAcceptor tests
    }

    #[test]
    fn proper_debut_of_accepting_node_with_populated_database_is_identified_and_handled() {
        let (gossip, new_node, gossip_source_opt) = make_debut(2345, Mode::Standard);
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let neighbor_key = &db.add_node(make_node_record(3456, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), neighbor_key);
        let cryptde = CryptDENull::from(db.root().public_key(), DEFAULT_CHAIN_ID);
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let qualifies_result = subject.qualifies(&db, &agrs, gossip_source_opt.clone());
        let handle_result = subject.handle(&cryptde, &mut db, agrs, gossip_source_opt);

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
        let cryptde = CryptDENull::from(db.root().public_key(), DEFAULT_CHAIN_ID);
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let qualifies_result = subject.qualifies(&db, &agrs, gossip_source.clone());
        let handle_result = subject.handle(&cryptde, &mut db, agrs, gossip_source);

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
        let cryptde = CryptDENull::from(src_db.root().public_key(), DEFAULT_CHAIN_ID);
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
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs,
            src_root.node_addr_opt().unwrap().into(),
        );

        assert_eq!(result, GossipAcceptanceResult::Accepted);
    }

    #[test]
    fn proper_debut_of_node_cant_be_passed_because_of_common_neighbors() {
        let src_root = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_root);
        let cryptde = CryptDENull::from(src_db.root().public_key(), DEFAULT_CHAIN_ID);
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
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &cryptde,
            &mut dest_db,
            agrs,
            src_root.node_addr_opt().unwrap().into(),
        );

        assert_eq!(result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn debut_with_node_addr_not_accepting_connections_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_debut(2345, Mode::OriginateOnly);
        let subject = DebutHandler::new(Logger::new("test"));
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &vec![1234],
        ));

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

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

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

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
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &vec![],
        ));
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

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
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.qualifies(&db, &agrs, gossip_source);

        assert_eq!(result, Qualification::Unmatched);
    }

    #[test]
    fn debut_of_already_connected_node_produces_accepted_result_instead_of_introduction_to_prevent_overconnection(
    ) {
        let src_root = make_node_record(1234, true);
        let mut src_db = db_from_node(&src_root);
        let dest_root = make_node_record(2345, true);
        let mut dest_db = db_from_node(&dest_root);
        let dest_cryptde = CryptDENull::from(dest_root.public_key(), DEFAULT_CHAIN_ID);
        let common_neighbor = make_node_record(3456, true);
        let dest_neighbor = make_node_record(4567, true);
        src_db.add_node(common_neighbor.clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), common_neighbor.public_key());
        dest_db.add_node(common_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), common_neighbor.public_key());
        dest_db.add_node(dest_neighbor.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), dest_neighbor.public_key());
        let agrs = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .build()
            .try_into()
            .unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.handle(
            &dest_cryptde,
            &mut dest_db,
            agrs,
            dest_root.node_addr_opt().clone().unwrap().into(),
        );

        assert_eq!(result, GossipAcceptanceResult::Accepted);
    }

    #[test]
    fn proper_pass_is_identified_and_processed() {
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = PassHandler::new();
        let mut dest_db = make_meaningless_db();
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let agrs = gossip.try_into().unwrap();

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs, gossip_source);

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

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

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
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("1.2.3.4").unwrap(),
            &vec![],
        ));
        let subject = PassHandler::new();

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

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
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), &agrs, gossip_source);

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
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_nobody_admits_to_being_source_is_unmatched() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[0].node_addr_opt = None;
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_introducer_does_not_provide_at_least_one_port_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[0].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &vec![],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

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
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(Qualification::Unmatched, result);
    }

    #[test]
    fn introduction_where_introducee_does_not_provide_at_least_one_port_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[1].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("3.4.5.6").unwrap(),
            &vec![],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

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
            &vec![4567],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

        assert_eq!(Qualification::Malformed("In Introduction, neither AgMEBQ from 4.5.6.7 nor AwQFBg from 3.4.5.6 claims the source IP 2.3.4.5".to_string()), result);
    }

    #[test]
    fn introduction_where_both_records_have_gossip_source_ip_is_malformed() {
        let (mut gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let dest_db = db_from_node(&dest_root);
        gossip.node_records[1].node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &vec![2345],
        ));
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&dest_db, &agrs, gossip_source);

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
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
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
            .unset_node_addr();
        dest_db.resign_node(introducer_key);
        let introducer_before_gossip = dest_db.node_by_key(introducer_key).unwrap().clone();

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs.clone(), gossip_source);

        assert_eq!(Qualification::Matched, qualifies_result);
        assert_eq!(
            GossipAcceptanceResult::Ban(format!("Introducer {} tried changing immutable characteristic: Updating a NodeRecord must not change its node_addr_opt", introducer_key)),
            handle_result
        );
        assert_eq!(
            &introducer_before_gossip,
            dest_db.node_by_key(introducer_key).unwrap()
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
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs.clone(), gossip_source);

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
        let expected_introducer = NodeRecord::from(&agrs[0]);
        assert_eq!(
            Some(&expected_introducer),
            dest_db.node_by_key(&agrs[0].inner.public_key)
        );
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
    fn introduction_with_no_problems_is_ignored_when_target_is_already_max_degree() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        for i in 0..MAX_DEGREE as u16 {
            let key = dest_db.add_node(make_node_record(i, true)).unwrap();
            dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), &key);
        }
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();

        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs.clone(), gossip_source);

        assert_eq!(handle_result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_in_database_and_obsolete(
    ) {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
        dest_db
            .node_by_key_mut(&agrs[0].inner.public_key)
            .unwrap()
            .set_version(0);
        dest_db.resign_node(&agrs[0].inner.public_key);

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs.clone(), gossip_source);

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
        let expected_introducer = NodeRecord::from(&agrs[0]);
        assert_eq!(
            Some(&expected_introducer),
            dest_db.node_by_key(&agrs[0].inner.public_key)
        );
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
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
        dest_db.add_arbitrary_half_neighbor(dest_root.public_key(), &agrs[0].inner.public_key);

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs.clone(), gossip_source);

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
        let expected_introducer = NodeRecord::from(&agrs[0]);
        assert_eq!(
            Some(&expected_introducer),
            dest_db.node_by_key(&agrs[0].inner.public_key)
        );
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

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

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

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

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

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

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
            &vec![4567],
        ));
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let gossip_source: SocketAddr = src_node.node_addr_opt().unwrap().into();

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

        assert_eq!(
            result,
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4:1234 contains multiple records claiming to be from 3.4.5.6"
            )),
        );
    }

    #[test]
    fn proper_standard_gossip_is_matched_and_handled() {
        let src_root = make_node_record(1234, true);
        let dest_root = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_root);
        let node_a_key = &src_db.add_node(make_node_record(3456, true)).unwrap();
        let node_b_key = &src_db.add_node(make_node_record(4567, true)).unwrap();
        let mut dest_db = db_from_node(&dest_root);
        dest_db.add_node(src_root.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(dest_root.public_key(), src_root.public_key());
        src_db.add_node(dest_db.root().clone()).unwrap();
        src_db.add_arbitrary_full_neighbor(src_root.public_key(), dest_root.public_key());
        let gossip = GossipBuilder::new(&src_db)
            .node(src_root.public_key(), true)
            .node(node_a_key, false)
            .node(node_b_key, false)
            .build();
        let subject = StandardGossipHandler::new(Logger::new("test"));
        let cryptde = CryptDENull::from(dest_db.root().public_key(), DEFAULT_CHAIN_ID);
        let agrs = gossip.try_into().unwrap();
        let gossip_source: SocketAddr = src_root.node_addr_opt().unwrap().into();

        let qualifies_result = subject.qualifies(&dest_db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut dest_db, agrs, gossip_source);

        assert_eq!(Qualification::Matched, qualifies_result);
        assert_eq!(GossipAcceptanceResult::Accepted, handle_result);
        assert_eq!(
            &src_db.root().inner,
            &dest_db.node_by_key(src_root.public_key()).unwrap().inner
        );
        assert!(dest_db.has_full_neighbor(dest_db.root().public_key(), src_db.root().public_key()));
        assert_eq!(
            &src_db.node_by_key(node_a_key).unwrap().inner,
            &dest_db.node_by_key(node_a_key).unwrap().inner
        );
        assert_eq!(
            &src_db.node_by_key(node_b_key).unwrap().inner,
            &dest_db.node_by_key(node_b_key).unwrap().inner
        );
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
        let dest_cryptde = CryptDENull::from(dest_root.public_key(), DEFAULT_CHAIN_ID);
        add_neighbors(&mut dest_db, MAX_DEGREE);
        dest_db.add_node(src_root.clone()).unwrap();
        dest_db.add_arbitrary_full_neighbor(five_neighbors[0].public_key(), src_root.public_key());
        let gossip = GossipProducerReal::new().produce(&src_db, dest_root.public_key());
        let subject = GossipAcceptorReal::new(&dest_cryptde);

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_root.node_addr_opt().clone().unwrap().into(),
        );

        assert_eq!(result, GossipAcceptanceResult::Ignored);
    }

    #[test]
    fn last_gossip_handler_rejects_everything() {
        let subject = GossipAcceptorReal::new(cryptde());
        let reject_handler = subject.gossip_handlers.last().unwrap();
        let db = make_meaningless_db();
        let (debut, _, debut_gossip_source) = make_debut(1234, Mode::Standard);
        let (pass, _, pass_gossip_source) = make_pass(2345);
        let (introduction, introduction_gossip_source) = make_introduction(3456, 4567);
        let (standard_gossip, _, standard_gossip_source) = make_debut(9898, Mode::Standard);

        let debut_result =
            reject_handler.qualifies(&db, &debut.try_into().unwrap(), debut_gossip_source);
        let pass_result =
            reject_handler.qualifies(&db, &pass.try_into().unwrap(), pass_gossip_source);
        let introduction_result = reject_handler.qualifies(
            &db,
            &introduction.try_into().unwrap(),
            introduction_gossip_source,
        );
        let standard_gossip_result = reject_handler.qualifies(
            &db,
            &standard_gossip.try_into().unwrap(),
            standard_gossip_source,
        );

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
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_node.node_addr_opt().unwrap().into(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
    }

    #[test]
    fn first_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), DEFAULT_CHAIN_ID);
        let mut dest_db = db_from_node(&root_node);
        let (gossip, debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

        assert_eq!(GossipAcceptanceResult::Accepted, result);
        root_node
            .add_half_neighbor_key(debut_node.public_key().clone())
            .unwrap();
        root_node.increment_version();
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn second_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), DEFAULT_CHAIN_ID);
        let mut dest_db = db_from_node(&root_node);
        let existing_node_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db.node_by_key_mut(existing_node_key).unwrap().resign();
        let (gossip, debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

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
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn fourth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), DEFAULT_CHAIN_ID);
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

        let (gossip, debut_node, gossip_source) = make_debut(2345, Mode::Standard);
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

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
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
        assert_eq!(
            &debut_node,
            dest_db.node_by_key(debut_node.public_key()).unwrap()
        );
    }

    #[test]
    fn fifth_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), DEFAULT_CHAIN_ID);
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
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

        let expected_acceptance_gossip_2 = GossipBuilder::new(&dest_db)
            .node(existing_node_2_key, true)
            .build();
        let expected_acceptance_gossip_3 = GossipBuilder::new(&dest_db)
            .node(existing_node_3_key, true)
            .build();
        assert_contains(
            &vec![
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
        root_node.resign();
        assert_eq!(&root_node, dest_db.root());
    }

    #[test]
    fn debut_when_degree_is_five_is_passed_to_least_connected_neighbor() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key(), DEFAULT_CHAIN_ID);
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
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

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
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(&mut dest_db, debut.try_into().unwrap(), gossip_source);

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
        let src_node = make_node_record(1234, true);
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
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(&mut dest_db, debut_agrs, gossip_source);

        assert_eq!(GossipAcceptanceResult::Accepted, result);
        assert_eq!(
            true,
            dest_db
                .node_by_key(src_node.public_key())
                .unwrap()
                .has_half_neighbor(dest_node.public_key())
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
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(&mut dest_db, debut_agrs, gossip_source);

        assert_eq!(result, GossipAcceptanceResult::Accepted);
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
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(&mut dest_db, debut_agrs, gossip_source);

        assert_eq!(result, GossipAcceptanceResult::Accepted);
        assert_eq!(
            dest_db
                .node_by_key(dest_node.public_key())
                .unwrap()
                .has_half_neighbor(src_node.public_key()),
            true,
        );
    }

    #[test]
    fn pass_is_properly_handled() {
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(&mut db, gossip.try_into().unwrap(), gossip_source);

        let expected_relay_gossip = GossipBuilder::new(&db)
            .node(root_node.public_key(), true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                expected_relay_gossip,
                pass_target.public_key().clone(),
                pass_target.node_addr_opt().unwrap(),
            ),
            result
        );
        assert_eq!(1, db.keys().len());
    }

    #[test]
    fn standard_gossip_containing_unfamiliar_node_addrs_leads_to_them_being_ignored() {
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
        src_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(node_a.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(node_b.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(node_c.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(node_e.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(node_f.public_key())
            .unwrap()
            .resign();
        let gossip = GossipBuilder::new(&src_db)
            .node(node_a.public_key(), true)
            .node(node_b.public_key(), false)
            .node(node_c.public_key(), false)
            .node(node_e.public_key(), true)
            .node(node_f.public_key(), true)
            .build();
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            node_a.node_addr_opt().unwrap().into(),
        );

        assert_eq!(GossipAcceptanceResult::Accepted, result);
        let mut expected_dest_db = src_db.clone();
        expected_dest_db.remove_arbitrary_half_neighbor(node_e.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_f.public_key(), node_a.public_key());
        expected_dest_db.remove_arbitrary_half_neighbor(node_b.public_key(), node_d.public_key());
        expected_dest_db.add_node(node_d.clone()).unwrap();
        expected_dest_db.add_arbitrary_half_neighbor(node_d.public_key(), node_b.public_key());
        expected_dest_db
            .node_by_key_mut(node_a.public_key())
            .unwrap()
            .resign();
        expected_dest_db
            .node_by_key_mut(node_b.public_key())
            .unwrap()
            .resign();
        expected_dest_db
            .node_by_key_mut(node_d.public_key())
            .unwrap()
            .resign();
        expected_dest_db
            .node_by_key_mut(node_e.public_key())
            .unwrap()
            .resign();
        expected_dest_db
            .node_by_key_mut(node_f.public_key())
            .unwrap()
            .resign();
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
        let dest_node = make_node_record(1234, true);
        let dest_node_cryptde = CryptDENull::from(&dest_node.public_key(), DEFAULT_CHAIN_ID);
        let mut dest_db = db_from_node(&dest_node);
        let src_node = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_node);
        let third_node = make_node_record(3456, true);
        let disconnected_node = make_node_record(4567, true);
        // These are only half neighbors. Will they be ignored in degree calculation?
        for idx in 0..MAX_DEGREE {
            let failed_node_key = &dest_db
                .add_node(make_node_record(4000 + idx as u16, true))
                .unwrap();
            dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), failed_node_key);
        }
        dest_db.add_node(third_node.clone()).unwrap();
        src_db.add_node(dest_node.clone()).unwrap();
        src_db.add_node(third_node.clone()).unwrap();
        src_db.add_node(disconnected_node.clone()).unwrap();
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
        src_db
            .node_by_key_mut(src_node.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(dest_node.public_key())
            .unwrap()
            .resign();
        src_db
            .node_by_key_mut(third_node.public_key())
            .unwrap()
            .resign();
        let gossip = GossipBuilder::new(&src_db)
            .node(src_node.public_key(), true)
            .node(third_node.public_key(), true)
            .node(disconnected_node.public_key(), false)
            .build();
        let subject = GossipAcceptorReal::new(&dest_node_cryptde);

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_node.node_addr_opt().unwrap().into(),
        );

        let mut expected_dest_db = src_db.clone();
        expected_dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), src_node.public_key());
        expected_dest_db
            .node_by_key_mut(disconnected_node.public_key())
            .unwrap()
            .metadata
            .node_addr_opt = None;
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
        assert_eq!(GossipAcceptanceResult::Accepted, result);
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
        assert_eq!(
            expected_dest_db
                .node_by_key(disconnected_node.public_key())
                .unwrap(),
            dest_db.node_by_key(disconnected_node.public_key()).unwrap()
        )
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
        let subject = GossipAcceptorReal::new(cryptde());
        let original_dest_db = dest_db.clone();

        let result = subject.handle(
            &mut dest_db,
            gossip.try_into().unwrap(),
            src_root.node_addr_opt().unwrap().into(),
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
        neighbor.metadata.node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &vec![],
        ));
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

    fn make_debut(n: u16, mode: Mode) -> (Gossip, NodeRecord, SocketAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n, mode);
        let gossip_source: SocketAddr = match debut_node.node_addr_opt() {
            Some(node_addr) => node_addr.into(),
            None => SocketAddr::from_str("200.200.200.200:2000").unwrap(),
        };
        (gossip, debut_node, gossip_source)
    }

    fn make_pass(n: u16) -> (Gossip, NodeRecord, SocketAddr) {
        let (gossip, debut_node) = make_single_node_gossip(n, Mode::Standard);
        (
            gossip,
            debut_node,
            SocketAddr::from_str("200.200.200.200:2000").unwrap(),
        )
    }

    fn make_single_node_gossip(n: u16, mode: Mode) -> (Gossip, NodeRecord) {
        let mut debut_node = make_node_record(n, true);
        adjust_for_mode(&mut debut_node, mode);
        let src_db = db_from_node(&debut_node);
        let gossip = GossipBuilder::new(&src_db)
            .node(debut_node.public_key(), true)
            .build();
        (gossip, debut_node)
    }

    fn make_introduction(introducer_n: u16, introducee_n: u16) -> (Gossip, SocketAddr) {
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
}
