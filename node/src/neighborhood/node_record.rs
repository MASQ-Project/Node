// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::neighborhood::neighborhood_database::{NeighborhoodDatabase, NeighborhoodDatabaseError};
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData, PublicKey};
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::iter::FromIterator;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NodeRecordInner {
    pub public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>, // Note: this should not be signed or versioned data. This says whether _other_ Nodes know this Node's NodeAddr, and that's not part of this Node's state.
    pub earning_wallet: Wallet,
    pub consuming_wallet: Option<Wallet>,
    pub rate_pack: RatePack,
    pub is_bootstrap_node: bool,
    pub neighbors: HashSet<PublicKey>,
    pub version: u32,
}

impl NodeRecordInner {
    // TODO fail gracefully
    // For now, this is only called at initialization time (NeighborhoodDatabase) and in tests, so panicking is OK.
    // When we start signing NodeRecords at other times, we should probably not panic
    pub fn generate_signature(&self, cryptde: &dyn CryptDE) -> CryptData {
        let serialized = match serde_cbor::ser::to_vec(&self) {
            Ok(inner) => inner,
            Err(_) => panic!("NodeRecord content {:?} could not be serialized", &self),
        };

        let mut hash = sha1::Sha1::new();
        hash.update(&serialized[..]);

        cryptde
            .sign(&PlainData::new(&hash.digest().bytes()))
            .expect(&format!(
                "NodeRecord content {:?} could not be signed",
                &self
            ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeSignatures {
    pub complete: CryptData,
    pub obscured: CryptData,
}

impl NodeSignatures {
    pub fn new(complete: CryptData, obscured: CryptData) -> NodeSignatures {
        NodeSignatures { complete, obscured }
    }

    pub fn from(cryptde: &dyn CryptDE, node_record_inner: &NodeRecordInner) -> Self {
        let complete_signature = node_record_inner.generate_signature(cryptde);

        let obscured_inner = NodeRecordInner {
            public_key: node_record_inner.clone().public_key,
            node_addr_opt: None,
            earning_wallet: node_record_inner.earning_wallet.clone(),
            consuming_wallet: node_record_inner.consuming_wallet.clone(),
            rate_pack: node_record_inner.rate_pack.clone(),
            is_bootstrap_node: node_record_inner.is_bootstrap_node,
            neighbors: node_record_inner.neighbors.clone(),
            version: node_record_inner.version,
        };
        let obscured_signature = obscured_inner.generate_signature(cryptde);

        NodeSignatures::new(complete_signature, obscured_signature)
    }

    pub fn complete(&self) -> &CryptData {
        &self.complete
    }

    pub fn obscured(&self) -> &CryptData {
        &self.obscured
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeRecord {
    pub inner: NodeRecordInner,
    pub metadata: NodeRecordMetadata,
    // TODO: Replace this with a retransmittable representation of the signed packet/signature from the incoming Gossip.
    pub signatures: Option<NodeSignatures>,
}

impl NodeRecord {
    pub fn new(
        public_key: &PublicKey,
        node_addr_opt: Option<&NodeAddr>,
        earning_wallet: Wallet,
        consuming_wallet: Option<Wallet>,
        rate_pack: RatePack,
        is_bootstrap_node: bool,
        signatures: Option<NodeSignatures>,
        version: u32,
    ) -> NodeRecord {
        NodeRecord {
            metadata: NodeRecordMetadata::new(),
            inner: NodeRecordInner {
                public_key: public_key.clone(),
                node_addr_opt: match node_addr_opt {
                    Some(node_addr) => Some(node_addr.clone()),
                    None => None,
                },
                earning_wallet,
                consuming_wallet,
                rate_pack,
                is_bootstrap_node,
                neighbors: HashSet::new(),
                version,
            },
            signatures,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.inner.public_key
    }

    pub fn node_addr_opt(&self) -> Option<NodeAddr> {
        self.inner.node_addr_opt.clone()
    }

    pub fn is_bootstrap_node(&self) -> bool {
        self.inner.is_bootstrap_node
    }

    pub fn is_not_bootstrap_node(&self) -> bool {
        !self.is_bootstrap_node()
    }

    pub fn set_node_addr(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Result<bool, NeighborhoodDatabaseError> {
        match self.inner.node_addr_opt {
            Some(ref inner_node_addr) if node_addr == inner_node_addr => Ok(false),
            Some(ref inner_node_addr) => Err(NeighborhoodDatabaseError::NodeAddrAlreadySet(
                inner_node_addr.clone(),
            )),
            None => {
                self.inner.node_addr_opt = Some(node_addr.clone());
                Ok(true)
            }
        }
    }

    pub fn unset_node_addr(&mut self) {
        self.inner.node_addr_opt = None
    }

    pub fn set_signatures(&mut self, signatures: NodeSignatures) -> bool {
        let existing_signatures = self.signatures.clone();
        match &existing_signatures {
            Some(ref existing) if existing == &signatures => false,
            Some(_) => {
                self.signatures = Some(signatures);
                true
            }
            None => {
                self.signatures = Some(signatures);
                true
            }
        }
    }

    pub fn half_neighbor_keys(&self) -> HashSet<&PublicKey> {
        HashSet::from_iter(self.inner.neighbors.iter())
    }

    pub fn has_half_neighbor(&self, key: &PublicKey) -> bool {
        self.inner.neighbors.contains(key)
    }

    pub fn add_half_neighbor_key(&mut self, key: PublicKey) {
        self.inner.neighbors.insert(key);
    }

    pub fn add_half_neighbor_keys(&mut self, keys: Vec<PublicKey>) {
        keys.into_iter().for_each(|k| self.add_half_neighbor_key(k));
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
                    .expect(format!("Node with key {} magically disappeared", k).as_str())
            })
            .collect()
    }

    // Keep in mind that this is a O(n^2) method
    pub fn full_neighbor_keys(&self, db: &NeighborhoodDatabase) -> HashSet<&PublicKey> {
        self.half_neighbor_keys()
            .into_iter()
            .filter(|k| {
                if let Some(node_record_ref) = db.node_by_key(k) {
                    let result = node_record_ref.is_not_bootstrap_node()
                        && node_record_ref.has_half_neighbor(self.public_key());
                    result
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
            Some(neighbor) => {
                neighbor.half_neighbor_keys().contains(self.public_key())
                    && !neighbor.is_bootstrap_node()
            }
            None => false,
        }
    }

    pub fn signatures(&self) -> Option<NodeSignatures> {
        self.signatures.clone()
    }

    pub fn sign(&mut self, cryptde: &dyn CryptDE) {
        self.signatures = Some(NodeSignatures::from(cryptde, &self.inner))
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

    pub fn consuming_wallet(&self) -> Option<Wallet> {
        self.inner.consuming_wallet.clone()
    }

    pub fn set_wallets(
        &mut self,
        earning_wallet: Wallet,
        consuming_wallet: Option<Wallet>,
    ) -> bool {
        let earning_change = if self.inner.earning_wallet == earning_wallet {
            false
        } else {
            self.inner.earning_wallet = earning_wallet;
            true
        };
        let consuming_change = if self.inner.consuming_wallet == consuming_wallet {
            false
        } else {
            self.inner.consuming_wallet = consuming_wallet;
            true
        };
        earning_change || consuming_change
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

    #[cfg(test)]
    pub fn remove_signatures(&mut self) {
        self.signatures = None;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeRecordMetadata {
    desirable: bool,
}

impl NodeRecordMetadata {
    pub fn new() -> NodeRecordMetadata {
        NodeRecordMetadata { desirable: true }
    }
}

#[cfg(test)]
mod tests {
    use super::super::neighborhood_test_utils::make_node_record;
    use super::*;
    use crate::neighborhood::neighborhood_test_utils::db_from_node;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::test_utils::{assert_contains, rate_pack};
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn set_node_addr_works_once_but_not_twice() {
        let mut subject = make_node_record(1234, false, false);
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
        let mut subject = make_node_record(1234, false, false);
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
    fn unset_node_addr() {
        let mut subject = make_node_record(1234, true, false);

        subject.unset_node_addr();

        assert_eq!(None, subject.node_addr_opt());
    }

    #[test]
    fn set_signatures_returns_true_when_signatures_are_not_set() {
        let subject_signed = make_node_record(1234, false, false);
        let mut subject = NodeRecord::new(
            subject_signed.public_key(),
            subject_signed.node_addr_opt().as_ref(),
            Wallet::new("0x1234"),
            Some(Wallet::new("0x2345")),
            rate_pack(100),
            subject_signed.is_bootstrap_node(),
            None,
            0,
        );

        assert_eq!(subject.signatures(), None);

        let signatures = NodeSignatures::new(
            CryptData::new(&[123, 56, 89]),
            CryptData::new(&[87, 54, 21]),
        );

        let result = subject.set_signatures(signatures.clone());

        assert_eq!(result, true);
        assert_eq!(subject.signatures(), Some(signatures.clone()));
    }

    #[test]
    fn set_signatures_returns_false_when_new_signatures_are_identical() {
        let mut subject = make_node_record(1234, false, false);

        let signatures = subject.signatures().unwrap();
        let result = subject.set_signatures(signatures.clone());

        assert_eq!(result, false);
    }

    #[test]
    fn set_signatures_returns_true_when_existing_signatures_are_changed() {
        let mut subject = make_node_record(1234, false, false);

        let signatures = NodeSignatures::new(
            CryptData::new(&[123, 56, 89]),
            CryptData::new(&[87, 54, 21]),
        );
        let result = subject.set_signatures(signatures);

        assert_eq!(result, true);
    }

    #[test]
    fn half_neighbor_manipulation() {
        let mut subject = make_node_record(1234, false, false);

        assert_eq!(subject.half_neighbor_keys().is_empty(), true);

        let neighbor_one = PublicKey::new(&b"one"[..]);
        let neighbor_two = PublicKey::new(&b"two"[..]);
        let neighbor_three = PublicKey::new(&b"three"[..]);
        let neighbor_four = PublicKey::new(&b"four"[..]);

        subject.add_half_neighbor_key(neighbor_one.clone());
        subject.add_half_neighbor_keys(vec![neighbor_two.clone(), neighbor_three.clone()]);
        subject.add_half_neighbor_key(neighbor_one.clone());

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
    fn full_neighbor_exploration() {
        let this_node = make_node_record(1000, true, false);
        let mut database = db_from_node(&this_node);
        let half_neighbor_one = make_node_record(1001, true, false);
        let half_neighbor_two = make_node_record(1002, true, false);
        let mut half_neighbor_reverse = make_node_record(1003, true, false);
        let half_neighbor_bootstrap = make_node_record(1004, true, true);
        let mut full_neighbor_one = make_node_record(1005, true, false);
        let mut full_neighbor_two = make_node_record(1006, true, false);
        let mut full_neighbor_bootstrap = make_node_record(1007, true, true);
        let disconnected = make_node_record(1008, false, false);
        let nonexistent = make_node_record(1009, false, false);

        {
            let this_node = database.root_mut();
            this_node.add_half_neighbor_keys(vec![
                half_neighbor_one.public_key().clone(),
                half_neighbor_two.public_key().clone(),
                half_neighbor_bootstrap.public_key().clone(),
                full_neighbor_one.public_key().clone(),
                full_neighbor_two.public_key().clone(),
                full_neighbor_bootstrap.public_key().clone(),
            ]);
        }
        let this_node = database.root();
        vec![
            &mut half_neighbor_reverse,
            &mut full_neighbor_one,
            &mut full_neighbor_two,
            &mut full_neighbor_bootstrap,
        ]
        .into_iter()
        .for_each(|n| n.add_half_neighbor_key(this_node.public_key().clone()));

        vec![
            &half_neighbor_one,
            &half_neighbor_two,
            &half_neighbor_reverse,
            &half_neighbor_bootstrap,
            &full_neighbor_one,
            &full_neighbor_two,
            &full_neighbor_bootstrap,
            &disconnected,
        ]
        .into_iter()
        .for_each(|n| {
            database.add_node(n).unwrap();
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
            this_node.has_full_neighbor(&database, full_neighbor_bootstrap.public_key()),
            false
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, half_neighbor_one.public_key()),
            false
        );
        assert_eq!(
            this_node.has_full_neighbor(&database, half_neighbor_bootstrap.public_key()),
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
    fn node_signatures_can_be_created_from_node_record_inner() {
        let to_be_signed = NodeRecordInner {
            public_key: PublicKey::new(&[1, 2, 3, 4]),
            node_addr_opt: Some(NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
            is_bootstrap_node: true,
            earning_wallet: Wallet::new("0x2345"),
            consuming_wallet: Some(Wallet::new("0x1234")),
            rate_pack: rate_pack(100),
            neighbors: HashSet::new(),
            version: 0,
        };
        let cryptde = CryptDENull::from(&to_be_signed.public_key);

        let result = NodeSignatures::from(&cryptde, &to_be_signed);

        assert_eq!(
            result.complete(),
            &to_be_signed.generate_signature(&cryptde)
        );
        let mut to_be_signed_obscured = to_be_signed.clone();
        to_be_signed_obscured.node_addr_opt = None;
        assert_eq!(
            result.obscured(),
            &to_be_signed_obscured.generate_signature(&cryptde)
        )
    }

    #[test]
    fn node_record_partial_eq() {
        let node_addr = NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]);
        let node_addr_opt = Some(&node_addr);
        let earning_wallet = Wallet::new("wallet");
        let consuming_wallet = Wallet::new("wallet");
        let exemplar = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let duplicate = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mut with_neighbor = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mod_key = NodeRecord::new(
            &PublicKey::new(&b"kope"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mod_node_addr = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            Some(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.5").unwrap(),
                &vec![1234],
            )),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mod_earning_wallet = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            Wallet::new("booga"),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mod_consuming_wallet = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(Wallet::new("booga")),
            rate_pack(100),
            true,
            None,
            0,
        );
        let mod_rate_pack = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(200),
            true,
            None,
            0,
        );
        let mod_is_bootstrap = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            false,
            None,
            0,
        );
        let mod_signatures = NodeRecord::new(
            &PublicKey::new(&b"poke"[..]),
            node_addr_opt.clone(),
            earning_wallet.clone(),
            Some(consuming_wallet.clone()),
            rate_pack(100),
            true,
            Some(NodeSignatures::new(
                CryptData::new(b""),
                CryptData::new(b""),
            )),
            0,
        );
        with_neighbor.add_half_neighbor_key(mod_key.public_key().clone());

        assert_eq!(exemplar, exemplar);
        assert_eq!(exemplar, duplicate);
        assert_ne!(exemplar, with_neighbor);
        assert_ne!(exemplar, mod_key);
        assert_ne!(exemplar, mod_node_addr);
        assert_ne!(exemplar, mod_earning_wallet);
        assert_ne!(exemplar, mod_consuming_wallet);
        assert_ne!(exemplar, mod_rate_pack);
        assert_ne!(exemplar, mod_is_bootstrap);
        assert_ne!(exemplar, mod_signatures);
    }

    #[test]
    fn increment_version_increments_node_record_version_by_1() {
        let mut this_node = make_node_record(123, true, false);

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
        let mut this_node = make_node_record(123, true, false);
        assert_eq!(this_node.version(), 0);

        this_node.set_version(10000);

        assert_eq!(this_node.version(), 10000);
    }

    #[test]
    fn set_wallets_returns_true_when_the_earning_wallet_changes() {
        let mut this_node = make_node_record(1234, true, false);
        assert_eq!(this_node.earning_wallet(), Wallet::new("0x1234"));
        assert_eq!(this_node.consuming_wallet(), Some(Wallet::new("0x4321")));

        assert!(this_node.set_wallets(Wallet::new("0x2345"), Some(Wallet::new("0x4321"))));

        assert_eq!(this_node.earning_wallet(), Wallet::new("0x2345"));
    }

    #[test]
    fn set_wallets_returns_true_when_the_consuming_wallet_changes() {
        let mut this_node = make_node_record(1234, true, false);
        assert_eq!(this_node.earning_wallet(), Wallet::new("0x1234"));
        assert_eq!(this_node.consuming_wallet(), Some(Wallet::new("0x4321")));

        assert!(this_node.set_wallets(Wallet::new("0x1234"), Some(Wallet::new("0x2345"))));

        assert_eq!(this_node.consuming_wallet(), Some(Wallet::new("0x2345")));
    }

    #[test]
    fn set_wallets_returns_false_when_the_wallet_does_not_change() {
        let mut this_node = make_node_record(1234, true, false);
        assert_eq!(this_node.earning_wallet(), Wallet::new("0x1234"));
        assert_eq!(this_node.consuming_wallet(), Some(Wallet::new("0x4321")));

        assert!(!this_node.set_wallets(Wallet::new("0x1234"), Some(Wallet::new("0x4321"))));

        assert_eq!(this_node.earning_wallet(), Wallet::new("0x1234"));
        assert_eq!(this_node.consuming_wallet(), Some(Wallet::new("0x4321")));
    }

    #[test]
    fn is_bootstrap_node_and_is_not_bootstrap_node_are_opposites() {
        let bootstrap = make_node_record(1234, true, true);
        let standard = make_node_record(2345, true, false);

        assert!(bootstrap.is_bootstrap_node());
        assert!(!bootstrap.is_not_bootstrap_node());
        assert!(!standard.is_bootstrap_node());
        assert!(standard.is_not_bootstrap_node());
    }

    #[test]
    fn set_desirable_when_no_change_from_default() {
        let mut this_node = make_node_record(5432, true, false);

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
        let mut this_node = make_node_record(5432, true, false);

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
}
