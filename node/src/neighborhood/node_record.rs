// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::GossipNodeRecord;
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::node_location::{get_node_location, NodeLocation};
use crate::neighborhood::{
    regenerate_signed_gossip, AccessibleGossipRecord, WRONG_COUNTRY_PENALTY,
};
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData, PublicKey};
use crate::sub_lib::neighborhood::{NodeDescriptor, RatePack};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::utils::time_t_timestamp;
use crate::sub_lib::wallet::Wallet;
use masq_lib::blockchains::chains::Chain;
use serde_derive::{Deserialize, Serialize};
use std::collections::btree_set::BTreeSet;
use std::collections::HashSet;
use std::convert::TryFrom;

//TODO create special serializer for NodeRecordInner_0v1 to simplify public_key, earning_wallet, rate_pack and neighbors
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct NodeRecordInner_0v1 {
    pub public_key: PublicKey,
    pub earning_wallet: Wallet,
    pub rate_pack: RatePack,
    pub neighbors: BTreeSet<PublicKey>,
    pub accepts_connections: bool,
    pub routes_data: bool,
    pub version: u32,
    pub country_code: String,
}

impl TryFrom<GossipNodeRecord> for NodeRecordInner_0v1 {
    type Error = String;

    fn try_from(gnr: GossipNodeRecord) -> Result<Self, Self::Error> {
        match serde_cbor::from_slice(gnr.signed_data.as_slice()) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(format!("{:?}", e)),
        }
    }
}

impl TryFrom<&GossipNodeRecord> for NodeRecordInner_0v1 {
    type Error = String;

    fn try_from(gnr_addr_ref: &GossipNodeRecord) -> Result<Self, Self::Error> {
        NodeRecordInner_0v1::try_from(gnr_addr_ref.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRecordError {
    SelfNeighborAttempt(PublicKey),
}

#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub inner: NodeRecordInner_0v1,
    pub metadata: NodeRecordMetadata,
    pub signed_gossip: PlainData,
    pub signature: CryptData,
}

#[derive(Clone)]
pub struct NodeRecordInputs {
    pub earning_wallet: Wallet,
    pub rate_pack: RatePack,
    pub accepts_connections: bool,
    pub routes_data: bool,
    pub version: u32,
    pub location: Option<NodeLocation>,
}

impl NodeRecord {
    pub fn new(
        public_key: &PublicKey,
        cryptde: &dyn CryptDE, // Must be the new NodeRecord's CryptDE: used for signing
        node_record_inputs: NodeRecordInputs,
    ) -> NodeRecord {
        let mut country = String::default();
        match node_record_inputs.location.as_ref() {
            Some(node_location) => {
                country = node_location.country_code.clone();
            }
            None => {}
        };
        let mut node_record = NodeRecord {
            metadata: NodeRecordMetadata::new(node_record_inputs.location),
            inner: NodeRecordInner_0v1 {
                public_key: public_key.clone(),
                earning_wallet: node_record_inputs.earning_wallet,
                rate_pack: node_record_inputs.rate_pack,
                accepts_connections: node_record_inputs.accepts_connections,
                routes_data: node_record_inputs.routes_data,
                neighbors: BTreeSet::new(),
                version: node_record_inputs.version,
                country_code: country,
            },
            signed_gossip: PlainData::new(&[]),
            signature: CryptData::new(&[]),
        };
        node_record.regenerate_signed_gossip(cryptde);
        node_record
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.inner.public_key
    }

    pub fn node_addr_opt(&self) -> Option<NodeAddr> {
        self.metadata.node_addr_opt.clone()
    }

    pub fn node_descriptor(&self, chain: Chain, cryptde: &dyn CryptDE) -> NodeDescriptor {
        NodeDescriptor::from((self, chain, cryptde))
    }

    pub fn country_code_exeption(&self, country_code: &String) -> u64 {
        match self.inner.country_code == *country_code {
            true => 0,
            false => WRONG_COUNTRY_PENALTY as u64,
        }
    }

    pub fn set_node_addr(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Result<bool, NeighborhoodDatabaseError> {
        match self.metadata.node_addr_opt {
            Some(ref inner_node_addr) if node_addr == inner_node_addr => Ok(false),
            Some(ref inner_node_addr) => Err(NeighborhoodDatabaseError::NodeAddrAlreadySet(
                inner_node_addr.clone(),
            )),
            None => {
                self.metadata.node_addr_opt = Some(node_addr.clone());
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    pub fn force_node_addr(&mut self, node_addr: &NodeAddr) {
        self.metadata.node_addr_opt = Some(node_addr.clone());
    }

    pub fn unset_node_addr(&mut self) {
        self.metadata.node_addr_opt = None
    }

    pub fn half_neighbor_keys(&self) -> HashSet<&PublicKey> {
        self.inner.neighbors.iter().collect()
    }

    pub fn has_half_neighbor(&self, key: &PublicKey) -> bool {
        self.inner.neighbors.contains(key)
    }

    pub fn add_half_neighbor_key(&mut self, key: PublicKey) -> Result<(), NodeRecordError> {
        if &key == self.public_key() {
            return Err(NodeRecordError::SelfNeighborAttempt(
                self.public_key().clone(),
            ));
        }
        self.inner.neighbors.insert(key);
        Ok(())
    }

    pub fn remove_half_neighbor_key(&mut self, key: &PublicKey) -> bool {
        self.inner.neighbors.remove(key)
    }

    pub fn clear_half_neighbors(&mut self) {
        self.inner.neighbors.clear();
    }

    // Keep in mind that this is a O(n^2) method
    pub fn full_neighbors<'a>(&self, db: &'a NeighborhoodDatabase) -> Vec<&'a NodeRecord> {
        let keys = self.full_neighbor_keys(db);
        keys.into_iter()
            .map(|k| {
                db.node_by_key(k)
                    .unwrap_or_else(|| panic!("Node with key {} magically disappeared", k))
            })
            .collect()
    }

    // Keep in mind that this is a O(n^2) method
    pub fn full_neighbor_keys(&self, db: &NeighborhoodDatabase) -> HashSet<&PublicKey> {
        self.half_neighbor_keys()
            .into_iter()
            .filter(|k| {
                if let Some(node_record_ref) = db.node_by_key(k) {
                    node_record_ref.has_half_neighbor(self.public_key())
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn has_full_neighbor(&self, db: &NeighborhoodDatabase, key: &PublicKey) -> bool {
        if !self.half_neighbor_keys().contains(key) {
            return false;
        }
        match db.node_by_key(key) {
            Some(neighbor) => neighbor.half_neighbor_keys().contains(self.public_key()),
            None => false,
        }
    }

    pub fn regenerate_signed_gossip(&mut self, cryptde: &dyn CryptDE) {
        let (signed_gossip, signature) = regenerate_signed_gossip(&self.inner, cryptde);
        self.signed_gossip = signed_gossip;
        self.signature = signature;
    }

    pub fn signed_gossip(&self) -> &PlainData {
        &self.signed_gossip
    }

    pub fn signature(&self) -> &CryptData {
        &self.signature
    }

    pub fn accepts_connections(&self) -> bool {
        self.inner.accepts_connections
    }

    pub fn routes_data(&self) -> bool {
        self.inner.routes_data
    }

    pub fn version(&self) -> u32 {
        self.inner.version
    }

    pub fn increment_version(&mut self) {
        self.inner.version += 1;
    }

    pub fn last_updated(&self) -> u32 {
        self.metadata.last_update
    }

    #[cfg(test)]
    pub fn set_last_updated(&mut self, time_t: u32) {
        self.metadata.last_update = time_t;
    }

    pub fn set_version(&mut self, value: u32) {
        self.inner.version = value;
    }

    pub fn earning_wallet(&self) -> Wallet {
        self.inner.earning_wallet.clone()
    }

    pub fn set_earning_wallet(&mut self, earning_wallet: Wallet) -> bool {
        if self.inner.earning_wallet == earning_wallet {
            false
        } else {
            self.inner.earning_wallet = earning_wallet;
            true
        }
    }

    pub fn rate_pack(&self) -> &RatePack {
        &self.inner.rate_pack
    }

    pub fn update(&mut self, agr: AccessibleGossipRecord) -> Result<(), String> {
        if &agr.inner.public_key != self.public_key() {
            return Err(format!(
                "Updating a NodeRecord must not change its public key: {} -> {}",
                self.public_key(),
                agr.inner.public_key
            ));
        }
        if &agr.inner.rate_pack != self.rate_pack() {
            return Err(format!(
                "Updating a NodeRecord must not change its rate pack: {} -> {}",
                self.rate_pack(),
                agr.inner.rate_pack
            ));
        }
        match (&self.metadata.node_addr_opt, &agr.node_addr_opt) {
            (None, None) => (),
            (None, Some(na)) => self.metadata.node_addr_opt = Some(na.clone()),
            (Some(_), None) => (),
            (Some(existing), Some(incoming)) if existing != incoming => {
                return Err(format!(
                    "Updating a NodeRecord must not change its node_addr_opt: {} -> {}",
                    existing, incoming
                ))
            }
            _ => (),
        }
        self.metadata.last_update = time_t_timestamp();
        self.signed_gossip = agr.signed_gossip;
        self.signature = agr.signature;
        self.inner = agr.inner;
        Ok(())
    }
}

impl From<AccessibleGossipRecord> for NodeRecord {
    fn from(agr: AccessibleGossipRecord) -> Self {
        let ip_add_opt = agr.node_addr_opt.as_ref().map(|node_rec| node_rec.ip_addr);
        let mut node_record = NodeRecord {
            inner: agr.inner,
            metadata: NodeRecordMetadata::new(get_node_location(ip_add_opt)),
            signed_gossip: agr.signed_gossip,
            signature: agr.signature,
        };
        node_record.metadata.node_addr_opt = agr.node_addr_opt;
        node_record
    }
}

impl From<&AccessibleGossipRecord> for NodeRecord {
    fn from(agr_ref: &AccessibleGossipRecord) -> Self {
        let agr = agr_ref.clone();
        NodeRecord::from(agr)
    }
}

impl TryFrom<&GossipNodeRecord> for NodeRecord {
    type Error = String;

    fn try_from(gnr: &GossipNodeRecord) -> Result<Self, Self::Error> {
        let inner = NodeRecordInner_0v1::try_from(gnr)?;
        let ip_addr_opt = gnr.node_addr_opt.as_ref().map(|node_rec| node_rec.ip_addr);
        let mut node_record = NodeRecord {
            inner,
            metadata: NodeRecordMetadata::new(get_node_location(ip_addr_opt)),
            signed_gossip: gnr.signed_data.clone(),
            signature: gnr.signature.clone(),
        };
        node_record.metadata.node_addr_opt = gnr.node_addr_opt.clone();
        Ok(node_record)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct NodeRecordMetadata {
    pub last_update: u32,
    pub node_addr_opt: Option<NodeAddr>,
    pub unreachable_hosts: HashSet<String>,
    pub node_location_opt: Option<NodeLocation>,
    pub node_distrust_score: u32,
    pub country_undesirablity: Option<u32>
    //TODO introduce various scores for latency, reliability and so
}

impl NodeRecordMetadata {
    pub fn new(node_location_opt: Option<NodeLocation>) -> NodeRecordMetadata {
        NodeRecordMetadata {
            last_update: time_t_timestamp(),
            node_addr_opt: None,
            unreachable_hosts: Default::default(),
            node_location_opt,
            node_distrust_score: Default::default(),
            country_undesirablity: None, //TODO use this field to compute coutnry_code undesirability to use in routing engine
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::ZERO_RATE_PACK;
    use crate::test_utils::make_wallet;
    use crate::test_utils::neighborhood_test_utils::{db_from_node, make_node_record};
    use crate::test_utils::{assert_contains, main_cryptde, rate_pack};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn can_create_a_node_record_from_a_reference() {
        let mut expected_node_record = make_node_record(1234, true);
        expected_node_record.set_version(6);
        expected_node_record.resign();
        let mut db = db_from_node(&make_node_record(2345, true));
        db.add_node(expected_node_record.clone()).unwrap();
        let builder = GossipBuilder::new(&db).node(expected_node_record.public_key(), true);
        let before = time_t_timestamp();

        let actual_node_record =
            NodeRecord::try_from(builder.build().node_records.first().unwrap()).unwrap();

        let after = time_t_timestamp();
        assert!(
            before <= actual_node_record.metadata.last_update
                && actual_node_record.metadata.last_update <= after
        );
        expected_node_record.metadata.last_update = actual_node_record.metadata.last_update;
        expected_node_record.metadata.node_location_opt =
            actual_node_record.metadata.node_location_opt.clone();
        expected_node_record.resign();
        assert_eq!(actual_node_record, expected_node_record);
    }

    #[test]
    fn set_node_addr_works_once_but_not_twice() {
        let mut subject = make_node_record(1234, false);
        assert_eq!(subject.node_addr_opt(), None);
        let first_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &[4321]);
        let result = subject.set_node_addr(&first_node_addr);
        assert_eq!(result, Ok(true));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr.clone()));
        let second_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &[5432]);
        let result = subject.set_node_addr(&second_node_addr);
        assert_eq!(
            result,
            Err(NeighborhoodDatabaseError::NodeAddrAlreadySet(
                first_node_addr.clone()
            ))
        );
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr));
    }

    #[test]
    fn set_node_addr_works_twice_if_the_new_address_is_the_same_as_the_old() {
        let mut subject = make_node_record(1234, false);
        assert_eq!(subject.node_addr_opt(), None);
        let first_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &[4321]);
        let result = subject.set_node_addr(&first_node_addr);
        assert_eq!(result, Ok(true));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr.clone()));
        let second_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &[4321]);
        let result = subject.set_node_addr(&second_node_addr);
        assert_eq!(result, Ok(false));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr));
    }

    #[test]
    fn node_descriptor_works_when_node_addr_is_present() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let mut subject = make_node_record(1234, true);
        subject.metadata.node_addr_opt = Some(NodeAddr::new(
            &subject.metadata.node_addr_opt.unwrap().ip_addr(),
            &[1234, 2345],
        ));

        let result = subject.node_descriptor(TEST_DEFAULT_CHAIN, cryptde);

        assert_eq!(
            result,
            NodeDescriptor::try_from((
                main_cryptde(),
                "masq://eth-ropsten:AQIDBA@1.2.3.4:1234/2345"
            ))
            .unwrap()
        );
    }

    #[test]
    fn node_descriptor_works_when_node_addr_is_not_present() {
        let cryptde: &dyn CryptDE = main_cryptde();
        let subject: NodeRecord = make_node_record(1234, false);

        let result = subject.node_descriptor(TEST_DEFAULT_CHAIN, cryptde);

        assert_eq!(
            result,
            NodeDescriptor::try_from((main_cryptde(), "masq://eth-ropsten:AQIDBA@:")).unwrap()
        );
    }

    #[test]
    fn unset_node_addr() {
        let mut subject = make_node_record(1234, true);

        subject.unset_node_addr();

        assert_eq!(None, subject.node_addr_opt());
    }

    #[test]
    fn half_neighbor_manipulation() {
        let mut subject = make_node_record(1234, false);

        assert_eq!(subject.half_neighbor_keys().is_empty(), true);

        let neighbor_one = PublicKey::new(&b"one"[..]);
        let neighbor_two = PublicKey::new(&b"two"[..]);
        let neighbor_three = PublicKey::new(&b"three"[..]);
        let neighbor_four = PublicKey::new(&b"four"[..]);

        subject.add_half_neighbor_key(neighbor_one.clone()).unwrap();
        subject.add_half_neighbor_key(neighbor_two.clone()).unwrap();
        subject
            .add_half_neighbor_key(neighbor_three.clone())
            .unwrap();
        subject.add_half_neighbor_key(neighbor_one.clone()).unwrap();

        assert_eq!(
            subject.half_neighbor_keys(),
            vec![&neighbor_one, &neighbor_two, &neighbor_three]
                .into_iter()
                .collect::<HashSet<&PublicKey>>()
        );
        assert_eq!(subject.has_half_neighbor(&neighbor_two), true);
        assert_eq!(subject.has_half_neighbor(&neighbor_four), false);

        subject.remove_half_neighbor_key(&neighbor_two);

        assert_eq!(
            subject.half_neighbor_keys(),
            vec![&neighbor_one, &neighbor_three]
                .into_iter()
                .collect::<HashSet<&PublicKey>>()
        );

        subject.clear_half_neighbors();

        assert_eq!(subject.half_neighbor_keys(), HashSet::new());
    }

    #[test]
    fn node_cannot_be_its_own_neighbor() {
        let mut subject = make_node_record(1234, false);

        let result = subject.add_half_neighbor_key(subject.public_key().clone());

        assert_eq!(
            Err(NodeRecordError::SelfNeighborAttempt(
                subject.public_key().clone()
            )),
            result
        );
    }

    #[test]
    fn full_neighbor_exploration() {
        let this_node = make_node_record(1000, true);
        let mut database = db_from_node(&this_node);
        let half_neighbor_one = make_node_record(1001, true);
        let half_neighbor_two = make_node_record(1002, true);
        let mut half_neighbor_reverse = make_node_record(1003, true);
        let mut full_neighbor_one = make_node_record(1005, true);
        let mut full_neighbor_two = make_node_record(1006, true);
        let disconnected = make_node_record(1008, false);
        let nonexistent = make_node_record(1009, false);

        {
            let this_node = database.root_mut();
            this_node
                .add_half_neighbor_key(half_neighbor_one.public_key().clone())
                .unwrap();
            this_node
                .add_half_neighbor_key(half_neighbor_two.public_key().clone())
                .unwrap();
            this_node
                .add_half_neighbor_key(full_neighbor_one.public_key().clone())
                .unwrap();
            this_node
                .add_half_neighbor_key(full_neighbor_two.public_key().clone())
                .unwrap();
        }
        let this_node = database.root();
        vec![
            &mut half_neighbor_reverse,
            &mut full_neighbor_one,
            &mut full_neighbor_two,
        ]
        .into_iter()
        .for_each(|n| {
            n.add_half_neighbor_key(this_node.public_key().clone())
                .unwrap()
        });

        vec![
            &half_neighbor_one,
            &half_neighbor_two,
            &half_neighbor_reverse,
            &full_neighbor_one,
            &full_neighbor_two,
            &disconnected,
        ]
        .into_iter()
        .for_each(|n| {
            database.add_node(n.clone()).unwrap();
        });

        let this_node = database.root();
        let full_neighbors = this_node.full_neighbors(&database);
        assert_contains(&full_neighbors, &&full_neighbor_one);
        assert_contains(&full_neighbors, &&full_neighbor_two);
        assert_eq!(full_neighbors.len(), 2);
        assert_eq!(
            this_node.full_neighbor_keys(&database),
            vec![
                full_neighbor_one.public_key(),
                full_neighbor_two.public_key()
            ]
            .into_iter()
            .collect::<HashSet<&PublicKey>>()
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, full_neighbor_one.public_key()),
            true
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, half_neighbor_one.public_key()),
            false
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, half_neighbor_reverse.public_key()),
            false
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, disconnected.public_key()),
            false
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, nonexistent.public_key()),
            false
        );
    }

    #[test]
    fn node_record_partial_eq() {
        let earning_wallet = make_wallet("wallet");
        let node_record_data = NodeRecordInputs {
            earning_wallet: earning_wallet.clone(),
            rate_pack: rate_pack(100),
            accepts_connections: true,
            routes_data: true,
            version: 0,
            location: None,
        };
        let node_record_data_duplicate = node_record_data.clone();
        let node_record_data_with_neighbor = node_record_data.clone();
        let node_record_data_mod_key = node_record_data.clone();
        let mut node_record_data_mod_earning_wallet = node_record_data.clone();
        let mut node_record_data_mod_rate_pack = node_record_data.clone();
        let mut node_record_data_mod_accepts_connections = node_record_data.clone();
        let mut node_record_data_mod_routes_data = node_record_data.clone();
        let mut node_record_data_mod_version = node_record_data.clone();
        let node_record_data_mod_signed_gossip = node_record_data.clone();
        let node_record_data_mod_signature = node_record_data.clone();
        let node_record_data_mod_node_addr = node_record_data.clone();
        let exemplar = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data,
        );
        let duplicate = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_duplicate,
        );
        let mut with_neighbor = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_with_neighbor,
        );
        let mod_key = NodeRecord::new(
            &PublicKey::new(&b"kope"[..]),
            main_cryptde(),
            node_record_data_mod_key,
        );
        with_neighbor
            .add_half_neighbor_key(mod_key.public_key().clone())
            .unwrap();
        let mut mod_node_addr = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_node_addr,
        );
        mod_node_addr
            .set_node_addr(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.5").unwrap(),
                &[1234],
            ))
            .unwrap();
        node_record_data_mod_earning_wallet.earning_wallet = make_wallet("booga");
        let mod_earning_wallet = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_earning_wallet,
        );
        node_record_data_mod_rate_pack.rate_pack = rate_pack(200);
        let mod_rate_pack = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_rate_pack,
        );
        node_record_data_mod_accepts_connections.accepts_connections = false;
        let mod_accepts_connections = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_accepts_connections,
        );
        node_record_data_mod_routes_data.routes_data = false;
        let mod_routes_data = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_routes_data,
        );
        let mut mod_signed_gossip = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_signed_gossip,
        );
        mod_signed_gossip.signed_gossip = mod_rate_pack.signed_gossip.clone();
        let mut mod_signature = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_signature,
        );
        mod_signature.signature = CryptData::new(&[]);
        node_record_data_mod_version.version = 1;
        let mod_version = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            main_cryptde(),
            node_record_data_mod_version,
        );

        assert_eq!(exemplar, exemplar);
        assert_eq!(exemplar, duplicate);
        assert_ne!(exemplar, with_neighbor);
        assert_ne!(exemplar, mod_key);
        assert_ne!(exemplar, mod_node_addr);
        assert_ne!(exemplar, mod_earning_wallet);
        assert_ne!(exemplar, mod_rate_pack);
        assert_ne!(exemplar, mod_accepts_connections);
        assert_ne!(exemplar, mod_routes_data);
        assert_ne!(exemplar, mod_signed_gossip);
        assert_ne!(exemplar, mod_signature);
        assert_ne!(exemplar, mod_version);
    }

    #[test]
    fn increment_version_increments_node_record_version_by_1() {
        let mut this_node = make_node_record(123, true);

        assert_eq!(this_node.version(), 0);

        this_node.increment_version();
        assert_eq!(this_node.version(), 1);

        this_node.increment_version();
        assert_eq!(this_node.version(), 2);

        this_node.increment_version();
        assert_eq!(this_node.version(), 3);
    }

    #[test]
    fn set_version_sets_the_version() {
        let mut this_node = make_node_record(123, true);
        assert_eq!(this_node.version(), 0);

        this_node.set_version(10000);

        assert_eq!(this_node.version(), 10000);
    }

    #[test]
    fn last_updated_is_set_upon_construction() {
        let begin_at = time_t_timestamp();
        let subject = make_node_record(1234, true);
        let end_at = time_t_timestamp();

        assert!((subject.last_updated() == begin_at) || (subject.last_updated() == end_at));
    }

    #[test]
    fn last_updated_is_controlled_by_set_last_updated() {
        let mut subject = make_node_record(1234, true);

        subject.set_last_updated(12345678);

        assert_eq!(subject.last_updated(), 12345678);
    }

    #[test]
    fn set_earning_wallet_returns_true_when_the_earning_wallet_changes() {
        let mut this_node = make_node_record(1234, true);
        assert_eq!(
            this_node.earning_wallet(),
            Wallet::from_str("0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0").unwrap()
        );

        assert!(this_node.set_earning_wallet(
            Wallet::from_str("0x2955a94429b1e8213f6df9c463cc2b9087b059ce").unwrap()
        ));

        assert_eq!(
            this_node.earning_wallet(),
            Wallet::from_str("0x2955a94429b1e8213f6df9c463cc2b9087b059ce").unwrap()
        );
    }

    #[test]
    fn set_earning_wallet_returns_false_when_the_wallet_does_not_change() {
        let mut this_node = make_node_record(1234, true);
        assert_eq!(
            this_node.earning_wallet(),
            Wallet::from_str("0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0").unwrap()
        );

        assert!(!this_node.set_earning_wallet(
            Wallet::from_str("0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0").unwrap()
        ));

        assert_eq!(
            this_node.earning_wallet(),
            Wallet::from_str("0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0").unwrap()
        );
    }

    #[test]
    fn update_works_when_immutable_characteristics_dont_change() {
        let mut subject = make_node_record(1234, true);
        let mut modified = subject.clone();
        modified.inner.version = 100;
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(Ok(()), result);
        assert_eq!(modified.metadata, subject.metadata);
        assert_eq!(modified.inner, subject.inner);
        assert_eq!(modified.signed_gossip, subject.signed_gossip);
        assert_eq!(modified.signature, subject.signature);
    }

    #[test]
    fn update_complains_when_public_key_tries_to_change() {
        let mut subject = make_node_record(1234, true);
        let mut modified = subject.clone();
        modified.inner.public_key = PublicKey::new(b"dangerous");
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(
            Err(
                "Updating a NodeRecord must not change its public key: AQIDBA -> ZGFuZ2Vyb3Vz"
                    .to_string()
            ),
            result
        )
    }

    #[test]
    fn update_complains_when_node_addr_opt_tries_to_change_from_existing_to_different_existing() {
        let mut subject = make_node_record(1234, true);
        let existing_node_addr_opt = subject.node_addr_opt();
        let mut modified = subject.clone();
        modified.metadata.node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &[2345],
        ));
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(
            Err("Updating a NodeRecord must not change its node_addr_opt: 1.2.3.4:1234 -> 2.3.4.5:2345".to_string()),
            result
        );
        assert_eq!(subject.node_addr_opt(), existing_node_addr_opt);
    }

    #[test]
    fn update_adopts_new_node_addr_when_current_version_has_none() {
        let mut subject = make_node_record(1234, false);
        let new_node_addr_opt = Some(NodeAddr::new(
            &IpAddr::from_str("2.3.4.5").unwrap(),
            &[2345],
        ));
        let mut modified = subject.clone();
        modified.metadata.node_addr_opt = new_node_addr_opt.clone();
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.node_addr_opt(), new_node_addr_opt);
    }

    #[test]
    fn update_keeps_existing_node_addr_when_new_version_has_none() {
        let mut subject = make_node_record(1234, true);
        let existing_node_addr_opt = subject.node_addr_opt();
        let mut modified = subject.clone();
        modified.metadata.node_addr_opt = None;
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.node_addr_opt(), existing_node_addr_opt);
    }

    #[test]
    fn update_keeps_no_node_addr_when_none_is_present_or_provided() {
        let mut subject = make_node_record(1234, false);
        let mut modified = subject.clone();
        modified.metadata.node_addr_opt = None;
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(result, Ok(()));
        assert_eq!(subject.node_addr_opt(), None);
    }

    #[test]
    fn update_complains_when_rate_pack_tries_to_change() {
        let mut subject = make_node_record(1234, true);
        let mut modified = subject.clone();
        modified.inner.rate_pack = ZERO_RATE_PACK.clone();
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(
            result,
            Err("Updating a NodeRecord must not change its rate pack: 1235|1434|1237|1634 -> 0|0|0|0".to_string()),
        )
    }

    #[test]
    fn from_gnr_to_nri_when_gossip_is_corrupt() {
        let corrupt_gnr = GossipNodeRecord {
            signed_data: PlainData::new(&[1, 2, 3, 4]),
            signature: CryptData::new(&[]),
            node_addr_opt: None,
        };

        let result = NodeRecordInner_0v1::try_from(corrupt_gnr);

        assert_eq!(Err(String::from ("ErrorImpl { code: Message(\"invalid type: integer `1`, expected struct NodeRecordInner_0v1\"), offset: 0 }")), result);
    }

    #[test]
    fn regenerate_signed_data_regenerates_signed_gossip_and_resigns() {
        let mut subject = make_node_record(1234, true);
        let cryptde = CryptDENull::from(subject.public_key(), TEST_DEFAULT_CHAIN);
        let initial_signed_gossip = subject.signed_gossip().clone();
        subject.increment_version();

        subject.regenerate_signed_gossip(&cryptde);

        let final_signed_gossip = subject.signed_gossip().clone();
        let final_signature = subject.signature().clone();
        assert_ne!(initial_signed_gossip, final_signed_gossip);
        assert_eq!(
            true,
            cryptde.verify_signature(&final_signed_gossip, &final_signature, cryptde.public_key())
        );
        let final_serialized = serde_cbor::ser::to_vec(&subject.inner).unwrap();
        assert_eq!(&final_serialized[..], final_signed_gossip.as_slice());
    }
}
