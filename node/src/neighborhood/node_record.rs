// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::neighborhood::gossip::GossipNodeRecord;
use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::neighborhood::{regenerate_signed_gossip, AccessibleGossipRecord};
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData, PublicKey};
use crate::sub_lib::data_version::DataVersion;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use serde_derive::{Deserialize, Serialize};
use std::collections::btree_set::BTreeSet;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::iter::FromIterator;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NodeRecordInner {
    pub data_version: DataVersion,
    pub public_key: PublicKey,
    pub earning_wallet: Wallet,
    pub rate_pack: RatePack,
    pub neighbors: BTreeSet<PublicKey>,
    pub accepts_connections: bool,
    pub routes_data: bool,
    pub version: u32,
}

impl NodeRecordInner {
    pub fn data_version() -> DataVersion {
        DataVersion::new(1, 0).expect("Internal Error")
    }
}

impl TryFrom<GossipNodeRecord> for NodeRecordInner {
    type Error = String;

    fn try_from(gnr: GossipNodeRecord) -> Result<Self, Self::Error> {
        match serde_cbor::from_slice(gnr.signed_data.as_slice()) {
            Ok(inner) => Ok(inner),
            Err(e) => Err(format!("{:?}", e)),
        }
    }
}

impl TryFrom<&GossipNodeRecord> for NodeRecordInner {
    type Error = String;

    fn try_from(gnr_addr_ref: &GossipNodeRecord) -> Result<Self, Self::Error> {
        NodeRecordInner::try_from(gnr_addr_ref.clone())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NodeRecordError {
    SelfNeighborAttempt(PublicKey),
}

#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub inner: NodeRecordInner,
    pub metadata: NodeRecordMetadata,
    pub signed_gossip: PlainData,
    pub signature: CryptData,
}

impl NodeRecord {
    pub fn new(
        public_key: &PublicKey,
        earning_wallet: Wallet,
        rate_pack: RatePack,
        accepts_connections: bool,
        routes_data: bool,
        version: u32,
        cryptde: &dyn CryptDE, // Must be the new NodeRecord's CryptDE: used for signing
    ) -> NodeRecord {
        let mut node_record = NodeRecord {
            metadata: NodeRecordMetadata::new(),
            inner: NodeRecordInner {
                data_version: NodeRecordInner::data_version(),
                public_key: public_key.clone(),
                earning_wallet,
                rate_pack,
                accepts_connections,
                routes_data,
                neighbors: BTreeSet::new(),
                version,
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

    pub fn node_descriptor(&self, cryptde: &dyn CryptDE, chain_id: u8) -> String {
        NodeDescriptor::from(self).to_string(cryptde, chain_id)
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

    pub fn unset_node_addr(&mut self) {
        self.metadata.node_addr_opt = None
    }

    pub fn half_neighbor_keys(&self) -> HashSet<&PublicKey> {
        HashSet::from_iter(self.inner.neighbors.iter())
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

    pub fn is_desirable(&self) -> bool {
        self.metadata.desirable
    }

    pub fn set_desirable(&mut self, is_desirable: bool) {
        self.metadata.desirable = is_desirable
    }

    pub fn update(&mut self, agr: AccessibleGossipRecord) -> Result<(), String> {
        if &agr.inner.public_key != self.public_key() {
            return Err("Updating a NodeRecord must not change its public key".to_string());
        }
        if agr.node_addr_opt != self.node_addr_opt() {
            return Err("Updating a NodeRecord must not change its node_addr_opt".to_string());
        }
        if &agr.inner.rate_pack != self.rate_pack() {
            return Err("Updating a NodeRecord must not change its rate pack".to_string());
        }
        self.metadata.node_addr_opt = agr.node_addr_opt;
        self.signed_gossip = agr.signed_gossip;
        self.signature = agr.signature;
        self.inner = agr.inner;
        Ok(())
    }
}

impl From<AccessibleGossipRecord> for NodeRecord {
    fn from(agr: AccessibleGossipRecord) -> Self {
        let mut node_record = NodeRecord {
            inner: agr.inner,
            metadata: NodeRecordMetadata::new(),
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
        let inner = NodeRecordInner::try_from(gnr)?;
        let mut node_record = NodeRecord {
            inner,
            metadata: NodeRecordMetadata::new(),
            signed_gossip: gnr.signed_data.clone(),
            signature: gnr.signature.clone(),
        };
        node_record.metadata.node_addr_opt = gnr.node_addr_opt.clone();
        Ok(node_record)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeRecordMetadata {
    pub desirable: bool,
    pub node_addr_opt: Option<NodeAddr>,
}

impl NodeRecordMetadata {
    pub fn new() -> NodeRecordMetadata {
        NodeRecordMetadata {
            desirable: true,
            node_addr_opt: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::neighborhood::neighborhood_test_utils::db_from_node;
    use crate::neighborhood::neighborhood_test_utils::make_node_record;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::neighborhood::ZERO_RATE_PACK;
    use crate::test_utils::{assert_contains, cryptde, make_wallet, rate_pack, DEFAULT_CHAIN_ID};
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

        let actual_node_record =
            NodeRecord::try_from(builder.build().node_records.first().unwrap()).unwrap();

        assert_eq!(expected_node_record, actual_node_record);
    }

    #[test]
    fn set_node_addr_works_once_but_not_twice() {
        let mut subject = make_node_record(1234, false);
        assert_eq!(subject.node_addr_opt(), None);
        let first_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &vec![4321]);
        let result = subject.set_node_addr(&first_node_addr);
        assert_eq!(result, Ok(true));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr.clone()));
        let second_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5432]);
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
        let first_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &vec![4321]);
        let result = subject.set_node_addr(&first_node_addr);
        assert_eq!(result, Ok(true));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr.clone()));
        let second_node_addr = NodeAddr::new(&IpAddr::from_str("4.3.2.1").unwrap(), &vec![4321]);
        let result = subject.set_node_addr(&second_node_addr);
        assert_eq!(result, Ok(false));
        assert_eq!(subject.node_addr_opt(), Some(first_node_addr));
    }

    #[test]
    fn node_descriptor_works_when_node_addr_is_present() {
        let mut subject = make_node_record(1234, true);
        subject.metadata.node_addr_opt = Some(NodeAddr::new(
            &subject.metadata.node_addr_opt.unwrap().ip_addr(),
            &vec![1234, 2345],
        ));

        let result = subject.node_descriptor(cryptde(), DEFAULT_CHAIN_ID);

        assert_eq!(result, "AQIDBA:1.2.3.4:1234;2345".to_string());
    }

    #[test]
    fn node_descriptor_works_when_node_addr_is_not_present() {
        let subject: NodeRecord = make_node_record(1234, false);

        let result = subject.node_descriptor(cryptde(), DEFAULT_CHAIN_ID);

        assert_eq!(result, "AQIDBA::".to_string());
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
            HashSet::from_iter(
                vec![
                    full_neighbor_one.public_key(),
                    full_neighbor_two.public_key()
                ]
                .into_iter()
            )
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
        let exemplar = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        let duplicate = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        let mut with_neighbor = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        let mod_key = NodeRecord::new(
            &PublicKey::new(&b"kope"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        with_neighbor
            .add_half_neighbor_key(mod_key.public_key().clone())
            .unwrap();
        let mut mod_node_addr = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        mod_node_addr
            .set_node_addr(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.5").unwrap(),
                &vec![1234],
            ))
            .unwrap();
        let mod_earning_wallet = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            make_wallet("booga"),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        let mod_rate_pack = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(200),
            true,
            true,
            0,
            cryptde(),
        );
        let mod_accepts_connections = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            false,
            true,
            0,
            cryptde(),
        );
        let mod_routes_data = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            false,
            0,
            cryptde(),
        );
        let mut mod_signed_gossip = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        mod_signed_gossip.signed_gossip = mod_rate_pack.signed_gossip.clone();
        let mut mod_signature = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            0,
            cryptde(),
        );
        mod_signature.signature = CryptData::new(&[]);
        let mod_version = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            earning_wallet.clone(),
            rate_pack(100),
            true,
            true,
            1,
            cryptde(),
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
    fn set_desirable_when_no_change_from_default() {
        let mut this_node = make_node_record(5432, true);

        assert!(
            this_node.is_desirable(),
            "initial state should have been desirable"
        );
        this_node.set_desirable(true);
        assert!(
            this_node.is_desirable(),
            "Should be desirable after being set to true."
        );
    }

    #[test]
    fn set_desirable_to_false() {
        let mut this_node = make_node_record(5432, true);

        assert!(
            this_node.is_desirable(),
            "initial state should have been desirable"
        );
        this_node.set_desirable(false);
        assert!(
            !this_node.is_desirable(),
            "Should be undesirable after being set to false."
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
            Err("Updating a NodeRecord must not change its public key".to_string()),
            result
        )
    }

    #[test]
    fn update_complains_when_node_addr_opt_tries_to_change() {
        let mut subject = make_node_record(1234, true);
        let mut modified = subject.clone();
        modified.metadata.node_addr_opt = None;
        modified.resign();
        let agr = AccessibleGossipRecord::from(&modified);

        let result = subject.update(agr);

        assert_eq!(
            Err("Updating a NodeRecord must not change its node_addr_opt".to_string()),
            result
        )
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
            Err("Updating a NodeRecord must not change its rate pack".to_string()),
            result
        )
    }

    #[test]
    fn from_gnr_to_nri_when_gossip_is_corrupt() {
        let corrupt_gnr = GossipNodeRecord {
            signed_data: PlainData::new(&[1, 2, 3, 4]),
            signature: CryptData::new(&[]),
            node_addr_opt: None,
        };

        let result = NodeRecordInner::try_from(corrupt_gnr);

        assert_eq!(Err(String::from ("ErrorImpl { code: Message(\"invalid type: integer `1`, expected struct NodeRecordInner\"), offset: 0 }")), result);
    }

    #[test]
    fn regenerate_signed_data_regenerates_signed_gossip_and_resigns() {
        let mut subject = make_node_record(1234, true);
        let cryptde = CryptDENull::from(subject.public_key(), DEFAULT_CHAIN_ID);
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
