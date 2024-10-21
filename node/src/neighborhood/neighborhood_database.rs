// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::neighborhood_database::NeighborhoodDatabaseError::NodeKeyNotFound;
use crate::neighborhood::dot_graph::{
    render_dot_graph, DotRenderable, EdgeRenderable, NodeRenderable, NodeRenderableInner,
};
use crate::neighborhood::node_location::get_node_location;
use crate::neighborhood::node_record::{NodeRecord, NodeRecordError, NodeRecordInputs};
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::neighborhood::NeighborhoodMode;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::utils::time_t_timestamp;
use crate::sub_lib::wallet::Wallet;
use itertools::Itertools;
use masq_lib::logger::Logger;
use masq_lib::utils::ExpectValue;
use std::collections::HashSet;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::IpAddr;

pub const ISOLATED_NODE_GRACE_PERIOD_SECS: u32 = 30;

#[derive(Clone)]
pub struct NeighborhoodDatabase {
    this_node: PublicKey,
    by_public_key: HashMap<PublicKey, NodeRecord>,
    by_ip_addr: HashMap<IpAddr, PublicKey>,
    logger: Logger,
}

impl Debug for NeighborhoodDatabase {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(self.to_dot_graph().as_str())
    }
}

impl NeighborhoodDatabase {
    pub fn new(
        public_key: &PublicKey,
        neighborhood_mode: NeighborhoodMode,
        earning_wallet: Wallet,
        cryptde: &dyn CryptDE,
    ) -> NeighborhoodDatabase {
        let mut result = NeighborhoodDatabase {
            this_node: public_key.clone(),
            by_public_key: HashMap::new(),
            by_ip_addr: HashMap::new(),
            logger: Logger::new("NeighborhoodDatabase"),
        };
        let location_opt = match neighborhood_mode.node_addr_opt() {
            Some(node_addr) => get_node_location(Some(node_addr.ip_addr())),
            None => None,
        };
        let node_record_data = NodeRecordInputs {
            earning_wallet,
            rate_pack: *neighborhood_mode.rate_pack(),
            accepts_connections: neighborhood_mode.accepts_connections(),
            routes_data: neighborhood_mode.routes_data(),
            version: 0,
            location_opt,
        };
        let mut node_record = NodeRecord::new(public_key, cryptde, node_record_data);
        if let Some(node_addr) = neighborhood_mode.node_addr_opt() {
            node_record
                .set_node_addr(&node_addr)
                .expect("NodeAddr suddenly appeared out of nowhere");
        }
        node_record.regenerate_signed_gossip(cryptde);
        result.add_arbitrary_node(node_record);
        result
    }

    pub fn root(&self) -> &NodeRecord {
        self.node_by_key(&self.this_node).expect("Internal error")
    }

    pub fn root_mut(&mut self) -> &mut NodeRecord {
        let root_key = &self.this_node.clone();
        self.node_by_key_mut(root_key).expect("Internal error")
    }

    pub fn keys(&self) -> HashSet<&PublicKey> {
        self.by_public_key.keys().collect()
    }

    pub fn node_by_key(&self, public_key: &PublicKey) -> Option<&NodeRecord> {
        self.by_public_key.get(public_key)
    }

    pub fn node_by_key_mut(&mut self, public_key: &PublicKey) -> Option<&mut NodeRecord> {
        self.by_public_key.get_mut(public_key)
    }

    pub fn nodes_mut(&mut self) -> Vec<&mut NodeRecord> {
        self.by_public_key
            .iter_mut()
            .map(|(_key, node_record)| node_record)
            .collect()
    }

    pub fn node_by_ip(&self, ip_addr: &IpAddr) -> Option<&NodeRecord> {
        match self.by_ip_addr.get(ip_addr) {
            Some(key) => self.node_by_key(key),
            None => None,
        }
    }

    pub fn has_half_neighbor(&self, from: &PublicKey, to: &PublicKey) -> bool {
        match self.node_by_key(from) {
            Some(f) => f.has_half_neighbor(to),
            None => false,
        }
    }

    pub fn has_full_neighbor(&self, from: &PublicKey, to: &PublicKey) -> bool {
        self.has_half_neighbor(from, to) && self.has_half_neighbor(to, from)
    }

    pub fn gossip_target_degree(&self, target: &PublicKey) -> usize {
        let target_node = match self.node_by_key(target) {
            None => return 0,
            Some(n) => n,
        };
        let full_accepting_degree = target_node
            .full_neighbors(self)
            .into_iter()
            .filter(|k| k.accepts_connections())
            .collect_vec()
            .len();
        let keys = self.keys();
        // If a Node in our database references a Node not in our database, we can't tell
        // whether that's a half or full neighborship. We assume here for purposes of
        // degree calculation that it's full.
        let nonexistent_degree = target_node
            .half_neighbor_keys()
            .into_iter()
            .filter(|k| !keys.contains(k))
            .count();
        full_accepting_degree + nonexistent_degree
    }

    pub fn add_node(
        &mut self,
        node_record: NodeRecord,
    ) -> Result<PublicKey, NeighborhoodDatabaseError> {
        let public_key = node_record.public_key().clone();
        let node_addr_opt = node_record.node_addr_opt();
        Self::check_for_ports(&node_addr_opt)?;
        self.check_for_collision(&public_key)?;
        self.add_arbitrary_node(node_record);
        Ok(public_key)
    }

    // This method cannot be used to add neighbors to any node but the local node. This is deliberate. If you
    // need it to do something else, reevaluate why you need it, because you're probably wrong.
    pub fn add_half_neighbor(
        &mut self,
        new_neighbor: &PublicKey,
    ) -> Result<bool, NeighborhoodDatabaseError> {
        if !self.keys().contains(new_neighbor) {
            return Err(NodeKeyNotFound(new_neighbor.clone()));
        };
        let node_key = &self.this_node.clone();
        if self.has_half_neighbor(node_key, new_neighbor) {
            return Ok(false);
        }
        match self.node_by_key_mut(node_key) {
            Some(node) => match node.add_half_neighbor_key(new_neighbor.clone()) {
                Err(NodeRecordError::SelfNeighborAttempt(key)) => {
                    Err(NeighborhoodDatabaseError::SelfNeighborAttempt(key))
                }
                Ok(_) => {
                    node.metadata.last_update = time_t_timestamp();
                    Ok(true)
                }
            },
            None => Err(NodeKeyNotFound(node_key.clone())),
        }
    }

    pub fn remove_neighbor(&mut self, node_key: &PublicKey) -> Result<bool, String> {
        let ip_addr: Option<IpAddr>;
        {
            let to_remove = match self.node_by_key_mut(node_key) {
                Some(node_record) => {
                    ip_addr = node_record.node_addr_opt().map(|addr| addr.ip_addr());
                    node_record
                }
                None => {
                    return Err(format!(
                        "could not remove nonexistent neighbor by public key: {:?}",
                        node_key
                    ));
                }
            };
            to_remove.unset_node_addr();
        }
        match ip_addr {
            Some(ip) => self.by_ip_addr.remove(&ip),
            None => None,
        };

        if self.root_mut().remove_half_neighbor_key(node_key) {
            self.root_mut().increment_version();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn remove_node(&mut self, node_key: &PublicKey) {
        let ip_addr_opt = match self.node_by_key(node_key) {
            None => None,
            Some(node) => node.node_addr_opt().map(|na| na.ip_addr()),
        };
        let _ = self.by_public_key.remove(node_key).is_some();
        if let Some(ip_addr) = ip_addr_opt {
            let _ = self.by_ip_addr.remove(&ip_addr).is_some();
        }
    }

    pub fn cull_dead_nodes(&mut self) {
        let referenced_node_keys = self.referenced_node_keys();
        let deadline = time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS;
        let to_cull: BTreeSet<PublicKey> = self
            .keys()
            .into_iter()
            .filter(|k| !referenced_node_keys.contains(*k))
            .cloned()
            .filter(|k| {
                self.node_by_key(k)
                    .expect("Node disappeared")
                    .last_updated()
                    <= deadline
            })
            .collect();
        if !to_cull.is_empty() {
            info!(self.logger, "Culling from the neighborhood {} Node{} that {} been isolated for {} seconds or more: {:?}",
                  to_cull.len(),
                  if to_cull.len() == 1 { "" } else { "s" },
                  if to_cull.len() == 1 { "has" } else { "have" },
                  ISOLATED_NODE_GRACE_PERIOD_SECS,
                  to_cull
            );
            to_cull.iter().for_each(|k| self.remove_node(k));
        }
    }

    pub fn to_dot_graph(&self) -> String {
        let renderables = self.to_dot_renderables();
        render_dot_graph(renderables)
    }

    pub fn referenced_node_keys(&self) -> BTreeSet<PublicKey> {
        let mut keys: BTreeSet<PublicKey> = self
            .keys()
            .into_iter()
            .flat_map(|k| self.node_by_key(k))
            .flat_map(|n| n.inner.neighbors.clone())
            .collect();
        // Local Node is always referenced
        keys.insert(self.root().public_key().clone());
        keys
    }

    pub fn new_public_ip(&mut self, public_ip: IpAddr) {
        let record = self.root_mut();
        let public_key = record.public_key().clone();
        let node_addr_opt = record.metadata.node_addr_opt.clone();
        let old_node_addr = node_addr_opt.expectv("Root node");
        let new_node_addr = NodeAddr::new(&public_ip, &old_node_addr.ports());
        record.metadata.node_addr_opt = Some(new_node_addr);
        self.by_ip_addr.remove(&old_node_addr.ip_addr());
        self.by_ip_addr.insert(public_ip, public_key);
    }

    fn to_dot_renderables(&self) -> Vec<Box<dyn DotRenderable>> {
        let mut mentioned: HashSet<PublicKey> = HashSet::new();
        let mut present: HashSet<PublicKey> = HashSet::new();
        let mut node_renderables: Vec<NodeRenderable> = vec![];
        let mut edge_renderables: Vec<EdgeRenderable> = vec![];
        self.keys()
            .into_iter()
            .map(|k| self.node_by_key(k).expect("Node magically disappeared"))
            .for_each(|nr| {
                present.insert(nr.public_key().clone());
                let public_key = nr.public_key();
                nr.half_neighbor_keys().into_iter().for_each(|k| {
                    mentioned.insert(k.clone());
                    edge_renderables.push(EdgeRenderable {
                        from: public_key.clone(),
                        to: k.clone(),
                    })
                });
                node_renderables.push(NodeRenderable {
                    inner: Some(NodeRenderableInner {
                        version: nr.version(),
                        accepts_connections: nr.accepts_connections(),
                        routes_data: nr.routes_data(),
                    }),
                    public_key: public_key.clone(),
                    node_addr: nr.node_addr_opt(),
                    known_source: public_key == self.root().public_key(),
                    known_target: false,
                    is_present: true,
                });
            });
        mentioned.difference(&present).for_each(|k| {
            node_renderables.push(NodeRenderable {
                inner: None,
                public_key: k.clone(),
                node_addr: None,
                known_source: false,
                known_target: false,
                is_present: false,
            })
        });
        let mut result: Vec<Box<dyn DotRenderable>> = vec![];
        for renderable in node_renderables {
            result.push(Box::new(renderable))
        }
        for renderable in edge_renderables {
            result.push(Box::new(renderable))
        }
        result
    }

    fn add_arbitrary_node(&mut self, node_record: NodeRecord) {
        let public_key = node_record.public_key().clone();
        let node_addr_opt = node_record.node_addr_opt();
        self.by_public_key.insert(public_key.clone(), node_record);
        if let Some(node_addr) = node_addr_opt {
            self.by_ip_addr.insert(node_addr.ip_addr(), public_key);
        }
    }

    fn check_for_ports(node_addr_opt: &Option<NodeAddr>) -> Result<(), NeighborhoodDatabaseError> {
        match node_addr_opt {
            None => Ok(()),
            Some(node_addr) => {
                if node_addr.ports().is_empty() {
                    Err(NeighborhoodDatabaseError::EmptyPortList)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn check_for_collision(&self, public_key: &PublicKey) -> Result<(), NeighborhoodDatabaseError> {
        if self.keys().contains(public_key) {
            Err(NeighborhoodDatabaseError::NodeKeyCollision(
                public_key.clone(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NeighborhoodDatabaseError {
    NodeKeyNotFound(PublicKey),
    NodeKeyCollision(PublicKey),
    SelfNeighborAttempt(PublicKey),
    NodeAddrAlreadySet(NodeAddr),
    EmptyPortList,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::node_location::NodeLocation;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::utils::time_t_timestamp;
    use crate::test_utils::assert_string_contains;
    use crate::test_utils::neighborhood_test_utils::{
        db_from_node, make_node_record, make_segmented_ip, make_segments,
    };
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::iter::FromIterator;
    use std::str::FromStr;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(ISOLATED_NODE_GRACE_PERIOD_SECS, 30);
    }

    #[test]
    fn a_brand_new_database_has_the_expected_contents() {
        let mut this_node = make_node_record(1234, true);

        let subject = db_from_node(&this_node);

        let last_update = subject.root().metadata.last_update;
        this_node.metadata.last_update = last_update;

        assert_eq!(subject.this_node, this_node.public_key().clone());
        assert_eq!(
            subject.by_public_key,
            [(this_node.public_key().clone(), this_node.clone())]
                .iter()
                .cloned()
                .collect()
        );
        assert_eq!(
            subject.by_ip_addr,
            [(
                this_node.node_addr_opt().as_ref().unwrap().ip_addr(),
                this_node.public_key().clone()
            )]
            .iter()
            .cloned()
            .collect()
        );
        let root = subject.root();
        assert_eq!(*root, this_node);
    }

    #[test]
    fn can_get_mutable_root() {
        let mut this_node = make_node_record(1234, true);

        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            this_node.earning_wallet(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );

        let last_update = subject.root().metadata.last_update;
        this_node.metadata.last_update = last_update;

        assert_eq!(subject.this_node, this_node.public_key().clone());
        assert_eq!(
            subject.by_public_key,
            [(this_node.public_key().clone(), this_node.clone())]
                .iter()
                .cloned()
                .collect()
        );
        assert_eq!(
            subject.by_ip_addr,
            [(
                this_node.node_addr_opt().as_ref().unwrap().ip_addr(),
                this_node.public_key().clone()
            )]
            .iter()
            .cloned()
            .collect()
        );
        let root = subject.root_mut();
        assert_eq!(*root, this_node);
    }

    #[test]
    fn cant_add_a_node_twice() {
        let this_node = make_node_record(1234, true);
        let first_copy = make_node_record(2345, true);
        let second_copy = make_node_record(2345, true);
        let mut subject = db_from_node(&this_node);
        let first_result = subject.add_node(first_copy.clone());

        let second_result = subject.add_node(second_copy.clone());

        assert_eq!(&first_result.unwrap(), first_copy.public_key());
        assert_eq!(
            second_result.err().unwrap(),
            NeighborhoodDatabaseError::NodeKeyCollision(second_copy.public_key().clone())
        )
    }

    #[test]
    fn cant_add_a_node_without_any_ports() {
        let this_node = make_node_record(1234, true);
        let mut subject = db_from_node(&this_node);
        let mut node_with_no_ports = make_node_record(2345, true);
        node_with_no_ports.unset_node_addr();
        let changed = node_with_no_ports
            .set_node_addr(&NodeAddr::new(&IpAddr::from_str("2.3.4.5").unwrap(), &[]))
            .unwrap();
        node_with_no_ports.resign();

        let result = subject.add_node(node_with_no_ports);

        assert_eq!(true, changed);
        assert_eq!(Err(NeighborhoodDatabaseError::EmptyPortList), result)
    }

    #[test]
    fn node_by_key_works() {
        let mut this_node = make_node_record(1234, true);

        let one_node = make_node_record(4567, true);
        let another_node = make_node_record(5678, true);
        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            Wallet::from_str("0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0").unwrap(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );

        subject.add_node(one_node.clone()).unwrap();

        let this_pubkey = this_node.public_key();
        let updated_record = subject
            .by_public_key
            .iter()
            .filter(|(pubkey, _node_record)| *pubkey == this_pubkey)
            .exactly_one()
            .unwrap();
        this_node.metadata.last_update = updated_record.1.metadata.last_update;

        assert_eq!(
            subject.node_by_key(this_node.public_key()).unwrap().clone(),
            this_node
        );
        assert_eq!(
            subject.node_by_key(one_node.public_key()).unwrap().clone(),
            one_node
        );
        assert_eq!(subject.node_by_key(another_node.public_key()), None);
    }

    #[test]
    fn node_by_ip_works() {
        let mut this_node = make_node_record(1234, true);
        this_node.inner.country_code_opt = Some("AU".to_string());
        this_node.metadata.node_location_opt = Some(NodeLocation {
            country_code: "AU".to_string(),
            free_world_bit: true,
        });
        this_node.resign();
        let one_node = make_node_record(4567, true);
        let another_node = make_node_record(5678, true);
        let mut subject = db_from_node(&this_node);

        subject.add_node(one_node.clone()).unwrap();

        let this_pubkey = this_node.public_key();
        let updated_record = subject
            .by_public_key
            .iter()
            .filter(|(pubkey, _node_record)| *pubkey == this_pubkey)
            .exactly_one()
            .unwrap();
        this_node.metadata.last_update = updated_record.1.metadata.last_update;

        assert_eq!(
            subject
                .node_by_ip(&this_node.node_addr_opt().unwrap().ip_addr())
                .unwrap()
                .clone(),
            this_node
        );
        assert_eq!(
            subject
                .node_by_ip(&one_node.node_addr_opt().unwrap().ip_addr())
                .unwrap()
                .clone(),
            one_node
        );
        assert_eq!(
            subject.node_by_ip(&another_node.node_addr_opt().unwrap().ip_addr()),
            None
        );
    }

    #[test]
    fn nodes_mut_works() {
        let root_node = make_node_record(1234, true);
        let node_a = make_node_record(2345, false);
        let node_b = make_node_record(3456, true);
        let mut subject = NeighborhoodDatabase::new(
            root_node.public_key(),
            (&root_node).into(),
            Wallet::from_str("0x0000000000000000000000000000000000004444").unwrap(),
            &CryptDENull::from(root_node.public_key(), TEST_DEFAULT_CHAIN),
        );
        subject.add_node(node_a.clone()).unwrap();
        subject.add_node(node_b.clone()).unwrap();
        let mut num: u16 = 7890;
        let mut keys_nums: Vec<(PublicKey, u16)> = vec![];

        let mutable_nodes = subject.nodes_mut();
        for node in mutable_nodes {
            node.metadata.node_addr_opt = Some(NodeAddr::new(
                &make_segmented_ip(make_segments(num)),
                &[num],
            ));
            keys_nums.push((node.inner.public_key.clone(), num));
            num += 1;
        }

        for (pub_key, num) in keys_nums {
            assert_eq!(
                &subject
                    .node_by_key(&pub_key)
                    .unwrap()
                    .clone()
                    .metadata
                    .node_addr_opt,
                &Some(NodeAddr::new(
                    &make_segmented_ip(make_segments(num)),
                    &[num]
                ))
            );
        }
    }

    #[test]
    fn add_half_neighbor_works() {
        let this_node = make_node_record(1234, true);
        let one_node = make_node_record(2345, false);
        let another_node = make_node_record(3456, true);
        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            Wallet::from_str("0x0000000000000000000000000000000000001234").unwrap(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );
        subject.add_node(one_node.clone()).unwrap();
        subject.add_node(another_node.clone()).unwrap();
        subject.add_arbitrary_half_neighbor(one_node.public_key(), another_node.public_key());
        subject.add_arbitrary_half_neighbor(another_node.public_key(), one_node.public_key());

        subject
            .add_half_neighbor(another_node.public_key())
            .unwrap();
        subject.add_half_neighbor(one_node.public_key()).unwrap();

        assert_eq!(0, subject.root().version());
        assert_eq!(
            subject
                .node_by_key(this_node.public_key())
                .unwrap()
                .has_half_neighbor(one_node.public_key()),
            true
        );
        assert_eq!(
            subject
                .node_by_key(this_node.public_key())
                .unwrap()
                .has_half_neighbor(another_node.public_key()),
            true
        );
        assert_eq!(
            subject
                .node_by_key(another_node.public_key())
                .unwrap()
                .has_full_neighbor(&subject, &one_node.public_key()),
            true
        );
        assert_eq!(
            subject
                .node_by_key(one_node.public_key())
                .unwrap()
                .has_full_neighbor(&subject, &another_node.public_key()),
            true
        );
        assert_eq!(
            subject
                .node_by_key(this_node.public_key())
                .unwrap()
                .has_half_neighbor(this_node.public_key()),
            false
        );
        assert_eq!(
            subject
                .node_by_key(one_node.public_key())
                .unwrap()
                .has_half_neighbor(this_node.public_key()),
            false
        );
        assert_eq!(
            subject
                .node_by_key(one_node.public_key())
                .unwrap()
                .has_half_neighbor(one_node.public_key()),
            false
        );
        assert_eq!(
            subject
                .node_by_key(another_node.public_key())
                .unwrap()
                .has_half_neighbor(this_node.public_key()),
            false
        );
        assert_eq!(
            subject
                .node_by_key(another_node.public_key())
                .unwrap()
                .has_half_neighbor(another_node.public_key()),
            false
        );
        assert_eq!(
            subject.keys(),
            HashSet::from_iter(
                vec!(
                    this_node.public_key(),
                    one_node.public_key(),
                    another_node.public_key()
                )
                .into_iter()
            )
        );
    }

    #[test]
    fn add_half_neighbor_complains_if_to_node_doesnt_exist() {
        let this_node = make_node_record(1234, true);
        let nonexistent_node = make_node_record(2345, true);
        let mut subject = db_from_node(&this_node);

        let result = subject.add_half_neighbor(nonexistent_node.public_key());

        assert_eq!(
            result,
            Err(NeighborhoodDatabaseError::NodeKeyNotFound(
                nonexistent_node.public_key().clone()
            ))
        )
    }

    #[test]
    fn add_half_neighbor_complains_when_node_tries_to_neighbor_itself() {
        let this_node = make_node_record(1234, true);
        let mut subject = db_from_node(&this_node);

        let result = subject.add_half_neighbor(this_node.public_key());

        assert_eq!(
            result,
            Err(NeighborhoodDatabaseError::SelfNeighborAttempt(
                this_node.public_key().clone()
            ))
        )
    }

    #[test]
    fn add_half_neighbor_returns_true_when_new_edge_is_created() {
        let this_node = make_node_record(1234, true);
        let other_node = make_node_record(2345, true);
        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            Wallet::from_str("0x0000000000000000000000000000000000001234").unwrap(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );
        subject.add_node(other_node.clone()).unwrap();
        subject.root_mut().metadata.last_update = time_t_timestamp() - 2;
        let before = time_t_timestamp();

        let result = subject.add_half_neighbor(other_node.public_key());

        let after = time_t_timestamp();
        assert_eq!(Ok(true), result, "add_arbitrary_neighbor done goofed");
        assert!(before <= subject.root().metadata.last_update);
        assert!(subject.root().metadata.last_update <= after);
    }

    #[test]
    fn add_half_neighbor_returns_false_when_edge_already_exists() {
        let this_node = make_node_record(1234, true);
        let other_node = make_node_record(2345, true);
        let mut subject = db_from_node(&this_node);
        subject.add_node(other_node.clone()).unwrap();
        subject.add_half_neighbor(other_node.public_key()).unwrap();

        let result = subject.add_half_neighbor(other_node.public_key());

        assert_eq!(Ok(false), result, "add_arbitrary_neighbor done goofed");
    }

    #[test]
    fn gossip_target_degree() {
        let root = make_node_record(1000, true);
        let mut db = db_from_node(&root);
        // connection-accepting full-neighbor
        let a = &db.add_node(make_node_record(1001, true)).unwrap();
        let b = &db.add_node(make_node_record(1002, true)).unwrap();
        let c = &db.add_node(make_node_record(1003, true)).unwrap();
        db.add_arbitrary_full_neighbor(a, b);
        db.add_arbitrary_full_neighbor(a, c);
        // connection-rejecting full-neighbor
        let g = {
            let mut g_node: NodeRecord = make_node_record(2001, true);
            g_node.inner.accepts_connections = false;
            &db.add_node(g_node).unwrap()
        };
        db.add_arbitrary_full_neighbor(a, g);
        // half-neighbor
        let m = &db.add_node(make_node_record(1004, true)).unwrap();
        let n = &db.add_node(make_node_record(1005, true)).unwrap();
        let o = &db.add_node(make_node_record(1006, true)).unwrap();
        db.add_arbitrary_half_neighbor(m, n);
        db.add_arbitrary_half_neighbor(m, o);
        // nonexistent neighbor
        let mut s_rec = make_node_record(1010, true);
        s_rec
            .add_half_neighbor_key(PublicKey::new(&[8, 8, 8, 8]))
            .unwrap();
        s_rec
            .add_half_neighbor_key(PublicKey::new(&[9, 9, 9, 9]))
            .unwrap();
        let s = &db.add_node(s_rec).unwrap();
        assert_eq!(2, db.gossip_target_degree(a));
        assert_eq!(0, db.gossip_target_degree(m));
        assert_eq!(2, db.gossip_target_degree(s));
    }

    #[test]
    fn database_can_be_pretty_printed_to_dot_format() {
        let this_node = make_node_record(1234, true); // AQIDBA
        let node_one = make_node_record(2345, true); // AgMEBQ
        let node_two = make_node_record(3456, true); // AwQFBg
        let node_three = make_node_record(4567, true); // BAUGBw

        let mut subject = db_from_node(&this_node);

        subject.add_node(node_one.clone()).unwrap();
        subject.add_node(node_two.clone()).unwrap();
        subject.add_node(node_three.clone()).unwrap();

        subject.add_arbitrary_half_neighbor(&this_node.public_key(), &node_one.public_key());
        subject.add_arbitrary_half_neighbor(&node_one.public_key(), &this_node.public_key());

        subject.add_arbitrary_half_neighbor(&node_one.public_key(), &node_two.public_key());
        subject.add_arbitrary_half_neighbor(&node_two.public_key(), &node_one.public_key());
        subject.add_arbitrary_half_neighbor(&node_two.public_key(), &this_node.public_key());

        subject.add_arbitrary_half_neighbor(&node_two.public_key(), &node_three.public_key());
        subject.add_arbitrary_half_neighbor(&node_three.public_key(), &node_two.public_key());
        subject.add_arbitrary_half_neighbor(&node_three.public_key(), &this_node.public_key());
        subject.root_mut().increment_version();

        let result = subject.to_dot_graph();

        assert_eq!(result.matches("->").count(), 8);
        assert_string_contains(
            &result,
            "\"AQIDBA\" [label=\"AR v1\\nAQIDBA\\n1.2.3.4:1234\"] [style=filled];",
        );
        assert_string_contains(
            &result,
            "\"AgMEBQ\" [label=\"AR v0\\nAgMEBQ\\n2.3.4.5:2345\"];",
        );
        assert_string_contains(
            &result,
            "\"AwQFBg\" [label=\"AR v0\\nAwQFBg\\n3.4.5.6:3456\"];",
        );
        assert_string_contains(
            &result,
            "\"BAUGBw\" [label=\"AR v0\\nBAUGBw\\n4.5.6.7:4567\"];",
        );
        assert_string_contains(&result, "\"AQIDBA\" -> \"AgMEBQ\";");
        assert_string_contains(&result, "\"AgMEBQ\" -> \"AQIDBA\";");
        assert_string_contains(&result, "\"AgMEBQ\" -> \"AwQFBg\";");
        assert_string_contains(&result, "\"AwQFBg\" -> \"AgMEBQ\";");
        assert_string_contains(&result, "\"AwQFBg\" -> \"AQIDBA\";");
        assert_string_contains(&result, "\"BAUGBw\" -> \"AwQFBg\";");
        assert_string_contains(&result, "\"AwQFBg\" -> \"BAUGBw\";");
        assert_string_contains(&result, "\"BAUGBw\" -> \"AQIDBA\";");
    }

    #[test]
    fn new_public_ip_replaces_ip_address_and_nothing_else() {
        let this_node = make_node_record(1234, true);
        let mut old_node = this_node.clone();
        old_node.inner.country_code_opt = Some("AU".to_string());
        old_node.metadata.node_location_opt = Some(NodeLocation {
            country_code: "AU".to_string(),
            free_world_bit: true,
        });
        old_node.resign();

        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            this_node.earning_wallet(),
            &CryptDENull::from(this_node.public_key(), DEFAULT_CHAIN),
        );
        let new_public_ip = IpAddr::from_str("4.3.2.1").unwrap();

        subject.new_public_ip(new_public_ip);

        let this_pubkey = this_node.public_key();
        let updated_record = subject
            .by_public_key
            .iter()
            .filter(|(pubkey, _node_record)| *pubkey == this_pubkey)
            .exactly_one()
            .unwrap();
        old_node.metadata.last_update = updated_record.1.metadata.last_update;

        let mut new_node = subject.root().clone();
        assert_eq!(subject.node_by_ip(&new_public_ip), Some(&new_node));
        assert_eq!(
            subject.node_by_ip(&old_node.metadata.node_addr_opt.clone().unwrap().ip_addr()),
            None
        );
        assert_eq!(new_node.node_addr_opt().unwrap().ip_addr(), new_public_ip);
        new_node.metadata.node_addr_opt = old_node.metadata.node_addr_opt.clone(); // undo the only change
        assert_eq!(new_node, old_node); // now they should be identical
    }

    #[test]
    fn remove_neighbor_returns_error_when_given_nonexistent_node_key() {
        let this_node = make_node_record(123, true);
        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            Wallet::from_str("0x0000000000000000000000000000000000000123").unwrap(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );
        let nonexistent_key = &PublicKey::new(b"nonexistent");

        let result = subject.remove_neighbor(nonexistent_key);

        let err_message = format!(
            "could not remove nonexistent neighbor by public key: {:?}",
            nonexistent_key
        );
        assert_eq!(0, subject.root().version());
        assert_eq!(err_message, result.expect_err("not an error"));
    }

    #[test]
    fn remove_neighbor_returns_true_when_neighbor_was_removed() {
        let this_node = make_node_record(123, true);
        let mut subject = db_from_node(&this_node);
        let other_node = make_node_record(2345, true);
        subject.add_node(other_node.clone()).unwrap();
        subject.add_arbitrary_half_neighbor(&this_node.public_key(), &other_node.public_key());

        let result = subject.remove_neighbor(other_node.public_key());

        assert_eq!(
            None,
            subject
                .node_by_key(other_node.public_key())
                .unwrap()
                .node_addr_opt()
        );
        assert_eq!(
            None,
            subject.node_by_ip(&other_node.node_addr_opt().unwrap().ip_addr())
        );
        assert_eq!(1, subject.root().version());
        assert!(result.ok().expect("should be ok"));
    }

    #[test]
    fn remove_neighbor_returns_false_when_neighbor_was_not_removed() {
        let this_node = make_node_record(123, true);
        let mut subject = NeighborhoodDatabase::new(
            this_node.public_key(),
            (&this_node).into(),
            Wallet::from_str("0x0000000000000000000000000000000000000123").unwrap(),
            &CryptDENull::from(this_node.public_key(), TEST_DEFAULT_CHAIN),
        );
        let neighborless_node = make_node_record(2345, true);
        subject.add_node(neighborless_node.clone()).unwrap();

        let result = subject.remove_neighbor(neighborless_node.public_key());

        assert_eq!(
            None,
            subject
                .node_by_key(neighborless_node.public_key())
                .unwrap()
                .node_addr_opt()
        );
        assert_eq!(
            None,
            subject.node_by_ip(&neighborless_node.node_addr_opt().unwrap().ip_addr())
        );
        assert_eq!(0, subject.root().version());
        assert!(!result.ok().expect("should be ok"));
    }

    #[test]
    fn cull_dead_nodes_distinguishes_between_nodes_that_stink_and_nodes_that_dont() {
        let root_node = make_node_record(1234, true);
        let mut subject: NeighborhoodDatabase = db_from_node(&root_node);
        let live_node_key = &subject.add_node(make_node_record(2345, true)).unwrap();
        let non_stinky_node_key = &subject.add_node(make_node_record(3456, true)).unwrap();
        let stinky_node_key = &subject.add_node(make_node_record(4567, true)).unwrap();
        subject
            .node_by_key_mut(stinky_node_key)
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);
        subject.add_arbitrary_half_neighbor(root_node.public_key(), live_node_key);
        subject.add_arbitrary_half_neighbor(non_stinky_node_key, root_node.public_key());
        subject.add_arbitrary_half_neighbor(stinky_node_key, root_node.public_key());

        subject.cull_dead_nodes();

        assert!(subject.node_by_key(root_node.public_key()).is_some());
        assert!(subject.node_by_key(non_stinky_node_key).is_some());
        assert!(subject.node_by_key(stinky_node_key).is_none());
    }

    #[test]
    fn cull_dead_nodes_never_culls_the_root() {
        let root_node = make_node_record(1234, true);
        let mut subject: NeighborhoodDatabase = db_from_node(&root_node);
        subject
            .node_by_key_mut(root_node.public_key())
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);

        subject.cull_dead_nodes();

        assert!(subject.node_by_key(root_node.public_key()).is_some());
    }

    #[test]
    fn cull_dead_nodes_does_not_recurse() {
        let root_node = make_node_record(1234, true);
        let mut subject: NeighborhoodDatabase = db_from_node(&root_node);
        let dead = &subject.add_node(make_node_record(2345, true)).unwrap();
        subject
            .node_by_key_mut(dead)
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);
        let referenced_by_dead = &subject.add_node(make_node_record(3456, true)).unwrap();
        subject
            .node_by_key_mut(referenced_by_dead)
            .unwrap()
            .set_last_updated(time_t_timestamp() - ISOLATED_NODE_GRACE_PERIOD_SECS - 2);
        subject.add_arbitrary_half_neighbor(referenced_by_dead, root_node.public_key());
        subject.add_arbitrary_half_neighbor(dead, referenced_by_dead);

        subject.cull_dead_nodes();

        assert!(subject.node_by_key(root_node.public_key()).is_some());
        assert!(subject.node_by_key(referenced_by_dead).is_some());
        assert!(subject.node_by_key(dead).is_none());
    }
}
