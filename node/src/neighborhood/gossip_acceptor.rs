use crate::neighborhood::gossip::{Gossip, GossipBuilder};
use crate::neighborhood::neighborhood::AccessibleGossipRecord;
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::node_record::NodeRecord;
use crate::sub_lib::cryptde::{CryptDE, PublicKey};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::node_addr::NodeAddr;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Clone, PartialEq, Debug)]
pub enum GossipAcceptanceResult {
    Accepted, // There are database changes. Generate standard Gossip and broadcast.
    Reply(Gossip, PublicKey, NodeAddr), // Don't generate Gossip from the database: instead, send this Gossip to the provided key and NodeAddr.
    Ignored,                            // Don't send out any Gossip because of this.
    Ban(String), // Gossip was ignored because it was evil: ban the sender of the Gossip as a malefactor.
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
        gossip_source: IpAddr,
    ) -> Qualification;
    fn handle(
        &self,
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
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
    // A Debut must contain a single AGR; it must provide its IP address; it must specify at least one port;
    // and it must be sourced by the debuting Node.
    fn qualifies(
        &self,
        _database: &NeighborhoodDatabase,
        agrs: &Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> Qualification {
        if agrs.len() != 1 {
            return Qualification::Unmatched;
        }
        match &agrs[0].node_addr_opt {
            None => Qualification::Malformed(format!(
                "Debut from {} for {} contained no NodeAddr",
                gossip_source, agrs[0].inner.public_key
            )),
            Some(node_addr) => {
                if node_addr.ports().is_empty() {
                    Qualification::Malformed(format!(
                        "Debut from {} for {} contained NodeAddr with no ports",
                        gossip_source, agrs[0].inner.public_key
                    ))
                } else if node_addr.ip_addr() == gossip_source {
                    Qualification::Matched
                } else {
                    Qualification::Unmatched
                }
            }
        }
    }

    fn handle(
        &self,
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        mut args: Vec<AccessibleGossipRecord>,
        _gossip_source: IpAddr,
    ) -> GossipAcceptanceResult {
        let source_agr = args.remove(0); // empty Gossip shouldn't get here
        let source_key = source_agr.inner.public_key.clone();
        let source_node_addr = source_agr
            .node_addr_opt
            .clone()
            .expect("Debut node lost its NodeAddr");
        match self.find_more_appropriate_neighbor(database) {
            Some(preferred_key) => {
                let preferred_ip = database
                    .node_by_key(preferred_key)
                    .expect("Disappeared")
                    .node_addr_opt()
                    .expect("Disappeared")
                    .ip_addr();
                self.logger.debug(format!(
                    "DebutHandler is commissioning Pass of {} at {} to more appropriate neighbor {} at {}",
                    source_key,
                    source_node_addr.ip_addr(),
                    preferred_key,
                    preferred_ip,
                ));
                GossipAcceptanceResult::Reply(
                    Self::make_pass_gossip(database, preferred_key),
                    source_key,
                    source_node_addr,
                )
            }
            None => match self.try_accept_debut(cryptde, database, source_agr) {
                Ok(result) => result,
                Err(_) => {
                    let lcn_key = Self::find_least_connected_neighbor(database).expect(
                        "If there aren't any neighbors, try_accept_debut() should have succeeded",
                    );
                    let lcn_ip = database
                        .node_by_key(lcn_key)
                        .expect("Disappeared")
                        .node_addr_opt()
                        .expect("Disappeared")
                        .ip_addr();
                    self.logger.debug(format!(
                        "Neighbor count at maximum. DebutHandler is commissioning Pass of {} at {} to {} at {}",
                        source_key, source_node_addr.ip_addr(), lcn_key, lcn_ip
                    ));
                    GossipAcceptanceResult::Reply(
                        Self::make_pass_gossip(database, lcn_key),
                        source_key,
                        source_node_addr,
                    )
                }
            },
        }
    }
}

impl DebutHandler {
    fn new(logger: Logger) -> DebutHandler {
        DebutHandler { logger }
    }

    fn find_more_appropriate_neighbor<'b>(
        &self,
        database: &'b NeighborhoodDatabase,
    ) -> Option<&'b PublicKey> {
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
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        debuting_agr: AccessibleGossipRecord,
    ) -> Result<GossipAcceptanceResult, ()> {
        if database.gossip_target_degree(database.root().public_key()) >= 5 {
            return Err(());
        }
        let public_key = debuting_agr.inner.public_key.clone();
        let debut_node_addr = debuting_agr
            .node_addr_opt
            .clone()
            .expect("Debut Gossip should have been checked for NodeAddr");
        let debuting_node = NodeRecord::from(&debuting_agr);
        let debut_node_key = match database.add_node(debuting_node) {
            Ok(key) => key,
            Err(NeighborhoodDatabaseError::NodeKeyCollision(_)) => {
                self.logger.info(format!(
                    "Passing re-debut from Node {} on to StandardGossipHandler",
                    public_key
                ));
                let standard_gossip_handler = StandardGossipHandler::new(self.logger.clone());
                return Ok(standard_gossip_handler.handle(
                    cryptde,
                    database,
                    vec![debuting_agr],
                    debut_node_addr.ip_addr(),
                ));
            }
            Err(e) => panic!(
                "Unexpected error accepting debut node {}: {:?}",
                public_key, e
            ),
        };
        match database.add_half_neighbor(&debut_node_key) {
            Err(NeighborhoodDatabaseError::NodeKeyNotFound(k)) => {
                panic!("Node {} magically disappeared", k)
            }
            Err(e) => panic!(
                "Unexpected error accepting debut from {}/{:?}: {:?}",
                debut_node_key,
                Some(debut_node_addr),
                e
            ),
            Ok(true) => {
                let root_mut = database.root_mut();
                root_mut.increment_version();
                root_mut.regenerate_signed_gossip(cryptde);
                self.logger
                    .debug(format!("Current database: {}", database.to_dot_graph()));
                match self.make_introduction(database, &debut_node_key) {
                    Some((introduction, target_ip, target_node_addr)) => Ok(
                        GossipAcceptanceResult::Reply(introduction, target_ip, target_node_addr),
                    ),
                    None => Ok(GossipAcceptanceResult::Accepted),
                }
            }
            Ok(false) => panic!("Brand-new neighbor already existed"),
        }
    }

    fn make_introduction(
        &self,
        database: &NeighborhoodDatabase,
        debut_node_key: &PublicKey,
    ) -> Option<(Gossip, PublicKey, NodeAddr)> {
        let debut_node = database.node_by_key(debut_node_key).expect("Disappeared");
        let mut neighbor_keys = database.root().half_neighbor_keys();
        neighbor_keys.remove(debut_node.public_key());
        // TODO: Remove all debut_node's half-neighbors from neighbor_keys.
        let least_connected_neighbor_key_opt =
            Self::find_least_connected_neighbor_excluding(database, debut_node.public_key());
        match least_connected_neighbor_key_opt {
            Some(lcn_key) => {
                let lcn_node_addr = database
                    .node_by_key(lcn_key)
                    .expect("Disappeared")
                    .node_addr_opt()
                    .expect("Disappeared");
                let debut_node_addr = debut_node.node_addr_opt().expect("Disappeared");
                self.logger.debug(format!(
                    "DebutHandler commissioning Introduction of {} at {} to {} at {}",
                    lcn_key,
                    lcn_node_addr,
                    debut_node.public_key(),
                    debut_node_addr
                ));
                Some((
                    GossipBuilder::new(database)
                        .node(database.root().public_key(), true)
                        .node(lcn_key, true)
                        .build(),
                    debut_node.public_key().clone(),
                    debut_node_addr,
                ))
            }
            None => None,
        }
    }

    fn find_least_connected_neighbor(database: &NeighborhoodDatabase) -> Option<&PublicKey> {
        Self::root_neighbors_ordered_by_degree(database)
            .first()
            .map(|lcn| *lcn)
    }

    fn find_least_connected_neighbor_excluding<'b>(
        database: &'b NeighborhoodDatabase,
        excluded: &'b PublicKey,
    ) -> Option<&'b PublicKey> {
        let mut keys = database.root().half_neighbor_keys();
        keys.remove(excluded);
        Self::keys_ordered_by_degree(database, keys)
            .first()
            .map(|lcn| *lcn)
    }

    fn keys_ordered_by_degree<'b>(
        database: &NeighborhoodDatabase,
        keys: HashSet<&'b PublicKey>,
    ) -> Vec<&'b PublicKey> {
        let mut neighbor_keys_vec = keys.into_iter().collect::<Vec<&PublicKey>>();
        neighbor_keys_vec.sort_unstable_by(|a, b| {
            database
                .gossip_target_degree(*a)
                .cmp(&database.gossip_target_degree(*b))
        });
        neighbor_keys_vec
    }

    fn root_neighbors_ordered_by_degree(database: &NeighborhoodDatabase) -> Vec<&PublicKey> {
        Self::keys_ordered_by_degree(database, database.root().half_neighbor_keys())
    }

    fn make_pass_gossip(database: &NeighborhoodDatabase, pass_target: &PublicKey) -> Gossip {
        GossipBuilder::new(database).node(pass_target, true).build()
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
    // match the gossip_source. The other record's IP address must not match the gossip_source.
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
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
        if let Some(qual) = Self::verify_introducee(introducer, introducee, gossip_source) {
            return qual;
        };
        Qualification::Matched
    }

    fn handle(
        &self,
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult {
        let (introducer, introducee) = Self::identify_players(agrs, gossip_source)
            .expect("Introduction not properly qualified");
        let introducer_key = introducer.inner.public_key.clone();
        match self.update_database(database, cryptde, introducer) {
            Ok(_) => (),
            Err(e) => {
                return GossipAcceptanceResult::Ban(format!(
                    "Introducer {} tried changing immutable characteristic: {}",
                    introducer_key, e
                ))
            }
        }
        let (debut, target_key, target_node_addr) =
            GossipAcceptorReal::make_debut_triple(database, &introducee)
                .expect("Introduction not properly qualified");
        GossipAcceptanceResult::Reply(debut, target_key, target_node_addr)
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
        gossip_source: IpAddr,
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
        if first_ip == gossip_source {
            Ok(true)
        } else if second_ip == gossip_source {
            Ok(false)
        } else {
            Err(Qualification::Malformed(format!(
                "In Introduction, neither {} from {} nor {} from {} claims the source IP {}",
                first_agr.inner.public_key,
                first_ip,
                second_agr.inner.public_key,
                second_ip,
                gossip_source
            )))
        }
    }

    fn identify_players(
        mut agrs: Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> Result<(AccessibleGossipRecord, AccessibleGossipRecord), Qualification> {
        let pair = match Self::order_is_introducee_introducer(&agrs, gossip_source)? {
            true => {
                let introducer = agrs.remove(0);
                let introducee = agrs.remove(0);
                (introducer, introducee)
            }
            false => {
                let introducee = agrs.remove(0);
                let introducer = agrs.remove(0);
                (introducer, introducee)
            }
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
        if introducer_node_addr.ip_addr()
            == root_node
                .node_addr_opt()
                .expect("Root node must have NodeAddr")
                .ip_addr()
        {
            return Some(Qualification::Malformed(format!(
                "Introducer {} claims to be at local Node's IP address",
                agr.inner.public_key
            )));
        }
        None
    }

    fn verify_introducee(
        introducer: &AccessibleGossipRecord,
        introducee: &AccessibleGossipRecord,
        gossip_source: IpAddr,
    ) -> Option<Qualification> {
        let introducee_node_addr = match introducee.node_addr_opt.as_ref() {
            None => return Some(Qualification::Unmatched),
            Some(node_addr) => node_addr,
        };
        if introducee_node_addr.ports().is_empty() {
            return Some(Qualification::Malformed(format!(
                "Introducer {} from {} introduced {} from {} with no ports",
                &introducer.inner.public_key,
                introducer
                    .node_addr_opt
                    .as_ref()
                    .expect("Disappeared")
                    .ip_addr(),
                &introducee.inner.public_key,
                introducee_node_addr.ip_addr()
            )));
        }
        if introducee
            .node_addr_opt
            .as_ref()
            .expect("Disappeared")
            .ip_addr()
            == gossip_source
        {
            return Some(Qualification::Malformed(format!(
                "Introducer {} and introducee {} both claim {}",
                introducer.inner.public_key, introducee.inner.public_key, gossip_source
            )));
        }
        None
    }

    fn update_database(
        &self,
        database: &mut NeighborhoodDatabase,
        cryptde: &CryptDE,
        introducer: AccessibleGossipRecord,
    ) -> Result<(), String> {
        let introducer_key = &introducer.inner.public_key.clone();
        match database.node_by_key_mut(introducer_key) {
            Some(existing_introducer_ref) => {
                if existing_introducer_ref.version() < introducer.inner.version {
                    self.logger.debug(format!(
                        "Updating obsolete introducer {} from version {} to version {}",
                        introducer_key,
                        existing_introducer_ref.version(),
                        introducer.inner.version
                    ));
                    existing_introducer_ref.update(introducer)?;
                } else {
                    self.logger.debug(format!(
                        "Preserving existing introducer {} at version {}",
                        introducer_key,
                        existing_introducer_ref.version()
                    ));
                }
            }
            None => {
                let new_introducer = NodeRecord::from(introducer);
                self.logger
                    .debug(format!("Adding introducer {} to database", introducer_key));
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
        self.logger
            .debug(format!("Current database: {}", database.to_dot_graph()));
        Ok(())
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
        gossip_source: IpAddr,
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
                } else if node_addr.ip_addr() == gossip_source {
                    Qualification::Unmatched
                } else {
                    Qualification::Matched
                }
            }
        }
    }

    fn handle(
        &self,
        _cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        _gossip_source: IpAddr,
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

struct StandardGossipHandler {
    logger: Logger,
}

impl NamedType for StandardGossipHandler {
    fn type_name(&self) -> &'static str {
        "StandardGossipHandler"
    }
}

impl GossipHandler for StandardGossipHandler {
    // Standard Gossip must contain more than one GossipNodeRecord, and it must not be an Introduction. At least one
    // record in the Gossip must contain the IP address from which the Gossip arrived. There must be no record in the
    // Gossip describing the local Node (although there may be records that reference the local Node as a neighbor).
    fn qualifies(
        &self,
        database: &NeighborhoodDatabase,
        agrs: &Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> Qualification {
        // must-not-be-introduction is assured by StandardGossipHandler's placement in the gossip_handlers list
        if agrs.len() < 2 {
            return Qualification::Unmatched;
        }
        let agrs_next_door = agrs
            .iter()
            .filter(|agr| agr.node_addr_opt.is_some())
            .collect::<Vec<&AccessibleGossipRecord>>();
        if !agrs_next_door
            .iter()
            .any(|agr| Self::ip_of(agr) == gossip_source)
        {
            return Qualification::Malformed(format!(
                "Standard Gossip from {} contains no record claiming to be from {}",
                gossip_source, gossip_source
            ));
        }
        let root_node = database.root();
        match agrs_next_door.iter()
            .find (|agr| Self::ip_of(agr) == root_node.node_addr_opt().expect("Root Node must have NodeAddr").ip_addr())
        {
            Some(impostor) => return Qualification::Malformed(format!("Standard Gossip from {} contains a record claiming that {} has this Node's IP address", gossip_source, impostor.inner.public_key)),
            None => (),
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
            let first_dup_ip = dup_vec.first().expect("Disappeared");
            Qualification::Malformed(format!(
                "Standard Gossip from {} contains multiple records claiming to be from {}",
                gossip_source, first_dup_ip
            ))
        }
    }

    fn handle(
        &self,
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult {
        let mut db_changed =
            self.identify_and_add_non_introductory_new_nodes(database, &agrs, gossip_source);
        db_changed = self.identify_and_update_obsolete_nodes(database, &agrs) || db_changed;
        db_changed = self.handle_root_node(cryptde, database, gossip_source) || db_changed;
        // If no Nodes need updating, return ::Ignored and don't change the database.
        // Otherwise, return ::Accepted.
        if db_changed {
            self.logger
                .debug(format!("Current database: {}", database.to_dot_graph()));
            GossipAcceptanceResult::Accepted
        } else {
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
        gossip_source: IpAddr,
    ) -> bool {
        let all_keys = database
            .keys()
            .into_iter()
            .map(|x| x.clone())
            .collect::<HashSet<PublicKey>>();
        agrs.iter()
            .filter(|agr| !all_keys.contains(&agr.inner.public_key))
            .filter(|agr| match &agr.node_addr_opt {
                None => true,
                Some(node_addr) => node_addr.ip_addr() == gossip_source,
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
        cryptde: &CryptDE,
        database: &mut NeighborhoodDatabase,
        gossip_source: IpAddr,
    ) -> bool {
        let gossip_node = match database.node_by_ip(&gossip_source) {
            None => return false,
            Some(node) => node,
        };
        let gossip_node_key = gossip_node.public_key().clone();
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

    fn update_database_record(
        &self,
        database: &mut NeighborhoodDatabase,
        agr: &AccessibleGossipRecord,
    ) -> bool {
        let existing_node_record = database
            .node_by_key_mut(&agr.inner.public_key)
            .expect("Node magically disappeared");
        match (
            existing_node_record.node_addr_opt(),
            agr.node_addr_opt.clone(),
        ) {
            (None, Some(new_node_addr)) => {
                existing_node_record
                    .set_node_addr(&new_node_addr)
                    .expect("Unexpected complaint about changing NodeAddr");
            }
            _ => (), // Maybe we eventually want to detect errors here and abort the change, returning false.
        }
        existing_node_record.inner = agr.inner.clone();
        existing_node_record.signed_gossip = agr.signed_gossip.clone();
        existing_node_record.signature = agr.signature.clone();
        true
    }

    fn add_ip_addr(set: HashSet<IpAddr>, ip_addr: IpAddr) -> HashSet<IpAddr> {
        let mut result = HashSet::from(set);
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
        gossip_source: IpAddr,
    ) -> Qualification {
        Qualification::Malformed(format!(
            "Gossip with {} records from {} is unclassifiable by any qualifier",
            agrs.len(),
            gossip_source
        ))
    }

    fn handle(
        &self,
        _cryptde: &CryptDE,
        _database: &mut NeighborhoodDatabase,
        _agrs: Vec<AccessibleGossipRecord>,
        _gossip_source: IpAddr,
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
        gossip_source: IpAddr,
    ) -> GossipAcceptanceResult;
}

pub struct GossipAcceptorReal<'a> {
    cryptde: &'a CryptDE,
    gossip_handlers: Vec<Box<GossipHandler>>,
    logger: Logger,
}

impl<'a> GossipAcceptor for GossipAcceptorReal<'a> {
    fn handle(
        &self,
        database: &mut NeighborhoodDatabase,
        agrs: Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
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
                self.logger
                    .debug(format!("Gossip delegated to {}", handler_ref.type_name()));
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
    pub fn new(cryptde: &'a CryptDE) -> GossipAcceptorReal {
        let logger = Logger::new("GossipAcceptor");
        GossipAcceptorReal {
            gossip_handlers: vec![
                Box::new(IntroductionHandler::new(logger.clone())),
                Box::new(StandardGossipHandler::new(logger.clone())),
                Box::new(DebutHandler::new(logger.clone())),
                Box::new(PassHandler::new()),
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
                ))
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
    use crate::neighborhood::neighborhood_test_utils::{
        db_from_node, make_meaningless_db, make_node_record,
    };
    use crate::neighborhood::node_record::NodeRecord;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::test_utils::{assert_contains, cryptde};
    use std::convert::TryInto;
    use std::str::FromStr;

    #[test]
    fn proper_debut_with_populated_database_is_identified_and_handled() {
        let (gossip, new_node, gossip_source) = make_debut(2345);
        let root_node = make_node_record(1234, true);
        let mut db = db_from_node(&root_node);
        let neighbor_key = &db.add_node(make_node_record(3456, true)).unwrap();
        db.add_arbitrary_full_neighbor(root_node.public_key(), neighbor_key);
        let cryptde = CryptDENull::from(db.root().public_key());
        let agrs = gossip.try_into().unwrap();
        let subject = DebutHandler::new(Logger::new("test"));

        let qualifies_result = subject.qualifies(&db, &agrs, gossip_source);
        let handle_result = subject.handle(&cryptde, &mut db, agrs, gossip_source);

        assert_eq!(Qualification::Matched, qualifies_result);
        let introduction = GossipBuilder::new(&db)
            .node(db.root().public_key(), true)
            .node(neighbor_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                introduction,
                new_node.public_key().clone(),
                new_node.node_addr_opt().unwrap()
            ),
            handle_result
        );
    }

    #[test]
    fn debut_without_node_addr_is_rejected() {
        let (mut gossip, _j, gossip_source) = make_debut(2345);
        gossip.node_records[0].node_addr_opt = None;
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.qualifies(
            &make_meaningless_db(),
            &gossip.try_into().unwrap(),
            gossip_source,
        );

        assert_eq!(
            Qualification::Malformed(
                "Debut from 2.3.4.5 for AgMEBQ contained no NodeAddr".to_string()
            ),
            result
        );
    }

    #[test]
    fn debut_without_node_addr_ports_is_rejected() {
        let (mut gossip, _, gossip_source) = make_debut(2345);
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
            Qualification::Malformed(
                "Debut from 2.3.4.5 for AgMEBQ contained NodeAddr with no ports".to_string()
            ),
            result
        );
    }

    #[test]
    fn proper_pass_is_identified_and_processed() {
        let (gossip, pass_target, gossip_source) = make_pass(2345);
        let subject = PassHandler::new();
        let mut dest_db = make_meaningless_db();
        let cryptde = CryptDENull::from(dest_db.root().public_key());
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
                pass_target.node_addr_opt().unwrap().clone()
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
                "Pass from 200.200.200.200 to AgMEBQ did not contain NodeAddr".to_string()
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
                "Pass from 200.200.200.200 to AgMEBQ at 1.2.3.4 contained NodeAddr with no ports"
                    .to_string()
            ),
            result
        );
    }

    #[test]
    fn gossip_containing_other_than_two_records_is_not_an_introduction() {
        let (gossip, _, gossip_source) = make_debut(2345);
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs = gossip.try_into().unwrap();

        let result = subject.qualifies(&make_meaningless_db(), &agrs, gossip_source);

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

        let result = subject.qualifies(
            &dest_db,
            &agrs,
            dest_root.node_addr_opt().unwrap().ip_addr(),
        );

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
        let cryptde = CryptDENull::from(dest_db.root().public_key());
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
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_not_in_database() {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key());
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
                agrs[1].node_addr_opt.clone().unwrap()
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
    fn introduction_with_no_problems_is_processed_correctly_when_introducer_is_in_database_and_obsolete(
    ) {
        let (gossip, gossip_source) = make_introduction(2345, 3456);
        let dest_root = make_node_record(7878, true);
        let mut dest_db = db_from_node(&dest_root);
        let cryptde = CryptDENull::from(dest_db.root().public_key());
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
                agrs[1].node_addr_opt.clone().unwrap()
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
        let cryptde = CryptDENull::from(dest_db.root().public_key());
        let subject = IntroductionHandler::new(Logger::new("test"));
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        dest_db.add_node(NodeRecord::from(&agrs[0])).unwrap();
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
                agrs[1].node_addr_opt.clone().unwrap()
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
    fn standard_gossip_that_doesnt_contain_record_with_gossip_source_ip_is_malformed() {
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

        assert_eq!(
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4 contains no record claiming to be from 1.2.3.4"
            )),
            result
        );
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

        assert_eq!(
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4 contains a record with this Node's public key"
            )),
            result
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

        assert_eq!(
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4 contains a record claiming that {} has this Node's IP address",
                node_b.public_key()
            )),
            result
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();

        let result = subject.qualifies(&mut dest_db, &gossip.try_into().unwrap(), gossip_source);

        assert_eq!(
            Qualification::Malformed(format!(
                "Standard Gossip from 1.2.3.4 contains multiple records claiming to be from 3.4.5.6"
            )),
            result
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
        let cryptde = CryptDENull::from(dest_db.root().public_key());
        let agrs = gossip.try_into().unwrap();
        let gossip_source = src_root.node_addr_opt().unwrap().ip_addr();

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
    fn malformed_gossip_stimulates_ban_request() {
        let just_a_node = make_node_record(1234, true);
        let agrs = vec![];
        let subject = GossipAcceptorReal::new(cryptde());

        let result = subject.handle(
            &mut make_meaningless_db(),
            agrs,
            just_a_node.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(
            GossipAcceptanceResult::Ban(
                "Gossip with 0 records from 1.2.3.4 is unclassifiable by any qualifier".to_string()
            ),
            result
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
            src_node.node_addr_opt().unwrap().ip_addr(),
        );

        assert_eq!(GossipAcceptanceResult::Ignored, result);
    }

    #[test]
    fn first_debut_is_handled() {
        let mut root_node = make_node_record(1234, true);
        let root_node_cryptde = CryptDENull::from(&root_node.public_key());
        let mut dest_db = db_from_node(&root_node);
        let (gossip, debut_node, gossip_source) = make_debut(2345);
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
        let root_node_cryptde = CryptDENull::from(&root_node.public_key());
        let mut dest_db = db_from_node(&root_node);
        let existing_node_key = &dest_db.add_node(make_node_record(3456, true)).unwrap();
        dest_db.add_arbitrary_full_neighbor(root_node.public_key(), existing_node_key);
        dest_db
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .resign();
        dest_db.node_by_key_mut(existing_node_key).unwrap().resign();
        let (gossip, debut_node, gossip_source) = make_debut(2345);
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
                debut_node.node_addr_opt().unwrap()
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
        let root_node_cryptde = CryptDENull::from(&root_node.public_key());
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

        let (gossip, debut_node, gossip_source) = make_debut(2345);
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
        let root_node_cryptde = CryptDENull::from(&root_node.public_key());
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

        let (gossip, debut_node, gossip_source) = make_debut(2345);
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
        let root_node_cryptde = CryptDENull::from(&root_node.public_key());
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

        let (gossip, debut_node, gossip_source) = make_debut(2345);
        let subject = GossipAcceptorReal::new(&root_node_cryptde);

        let result = subject.handle(&mut dest_db, gossip.try_into().unwrap(), gossip_source);

        let expected_acceptance_gossip = GossipBuilder::new(&dest_db)
            .node(existing_node_5_key, true)
            .build();
        assert_eq!(
            GossipAcceptanceResult::Reply(
                expected_acceptance_gossip,
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap()
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
        init_test_logging();
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();
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
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: GossipAcceptor: Passing re-debut from Node {} on to StandardGossipHandler",
                src_node.public_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn redebut_is_passed_to_standard_gossip_handler_and_incorporated_if_it_is_a_new_version() {
        init_test_logging();
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
        let gossip_source = src_node.node_addr_opt().unwrap().ip_addr();
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
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: GossipAcceptor: Passing re-debut from Node {} on to StandardGossipHandler",
                src_node.public_key()
            )
            .as_str(),
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
                pass_target.node_addr_opt().unwrap()
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
            node_a.node_addr_opt().unwrap().ip_addr(),
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
        let dest_node_cryptde = CryptDENull::from(&dest_node.public_key());
        let mut dest_db = db_from_node(&dest_node);
        let src_node = make_node_record(2345, true);
        let mut src_db = db_from_node(&src_node);
        let third_node = make_node_record(3456, true);
        let disconnected_node = make_node_record(4567, true);
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
            src_node.node_addr_opt().unwrap().ip_addr(),
        );

        let mut expected_dest_db = src_db.clone();
        expected_dest_db.add_arbitrary_half_neighbor(dest_node.public_key(), src_node.public_key());
        expected_dest_db
            .node_by_key_mut(disconnected_node.public_key())
            .unwrap()
            .metadata
            .node_addr_opt = None;
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
        db.add_arbitrary_full_neighbor(root_node.public_key(), less_connected_neighbor_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_2_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), other_neighbor_3_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_1_key);
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_2_key);
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.find_more_appropriate_neighbor(&db);

        assert_eq!(Some(less_connected_neighbor_key), result);
    }

    #[test]
    fn find_more_appropriate_neighbor_rejects_if_all_neighbors_are_connected_as_well_as_me() {
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
        db.add_arbitrary_full_neighbor(less_connected_neighbor_key, other_neighbor_3_key);
        let subject = DebutHandler::new(Logger::new("test"));

        let result = subject.find_more_appropriate_neighbor(&db);

        assert_eq!(None, result);
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
        db.add_arbitrary_full_neighbor(root_node.public_key(), high_degree_key);
        db.add_arbitrary_full_neighbor(root_node.public_key(), low_degree_key);
        db.add_arbitrary_full_neighbor(high_degree_key, distant_node_key);
        db.add_arbitrary_full_neighbor(high_degree_key, near_key);
        db.add_arbitrary_full_neighbor(low_degree_key, far_key);

        let result = DebutHandler::root_neighbors_ordered_by_degree(&db);

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
        let debut_node = make_node_record(n, true);
        let src_db = db_from_node(&debut_node);
        let gossip = GossipBuilder::new(&src_db)
            .node(debut_node.public_key(), true)
            .build();
        (gossip, debut_node)
    }

    fn make_introduction(introducer_n: u16, introducee_n: u16) -> (Gossip, IpAddr) {
        let mut introducer_node = make_node_record(introducer_n, true);
        introducer_node.set_version(10);
        let mut introducee_node = make_node_record(introducee_n, true);
        introducee_node.set_version(10);
        let introducer_key = introducer_node.public_key().clone();
        let introducee_key = introducee_node.public_key().clone();

        let gossip_source = introducer_node.node_addr_opt().unwrap().ip_addr();

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
}
