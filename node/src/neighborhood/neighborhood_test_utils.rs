// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::neighborhood_database::NeighborhoodDatabase;
use super::node_record::NodeRecord;
use crate::bootstrapper::BootstrapperConfig;
use crate::neighborhood::gossip::GossipNodeRecord;
use crate::neighborhood::node_record::NodeRecordInner;
use crate::neighborhood::{AccessibleGossipRecord, Neighborhood};
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, PlainData};
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::neighborhood::{NeighborhoodConfig, NeighborhoodMode, NodeDescriptor};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::*;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::net::Ipv4Addr;

impl From<(&NeighborhoodDatabase, &PublicKey, bool)> for AccessibleGossipRecord {
    fn from(
        (database, public_key, reveal_node_addr): (&NeighborhoodDatabase, &PublicKey, bool),
    ) -> Self {
        let intermediate_gnr = GossipNodeRecord::from((database, public_key, reveal_node_addr));
        AccessibleGossipRecord::try_from(intermediate_gnr).unwrap()
    }
}

pub fn make_node_record(n: u16, has_ip: bool) -> NodeRecord {
    let a = ((n / 1000) % 10) as u8;
    let b = ((n / 100) % 10) as u8;
    let c = ((n / 10) % 10) as u8;
    let d = (n % 10) as u8;
    let key = PublicKey::new(&[a, b, c, d]);
    let ip_addr = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    let node_addr = NodeAddr::new(&ip_addr, &vec![n % 10000]);

    NodeRecord::new_for_tests(
        &key,
        if has_ip { Some(&node_addr) } else { None },
        n as u64,
        true,
        true,
    )
}

pub fn make_node_record_f(
    n: u16,
    has_ip: bool,
    accepts_connections: bool,
    routes_data: bool,
) -> NodeRecord {
    let mut result = make_node_record(n, has_ip);
    result.inner.accepts_connections = accepts_connections;
    result.inner.routes_data = routes_data;
    result
}

pub fn make_global_cryptde_node_record(n: u16, has_ip: bool) -> NodeRecord {
    let mut node_record = make_node_record(n, has_ip);
    node_record.inner.public_key = cryptde().public_key().clone();
    node_record.resign();
    node_record
}

pub fn make_meaningless_db() -> NeighborhoodDatabase {
    let node = make_node_record(9898, true);
    db_from_node(&node)
}

pub fn db_from_node(node: &NodeRecord) -> NeighborhoodDatabase {
    NeighborhoodDatabase::new(
        node.public_key(),
        node.into(),
        node.earning_wallet(),
        &CryptDENull::from(node.public_key(), DEFAULT_CHAIN_ID),
    )
}

pub fn neighborhood_from_nodes(
    root: &NodeRecord,
    neighbor_opt: Option<&NodeRecord>,
) -> Neighborhood {
    let cryptde = cryptde();
    if root.public_key() != cryptde.public_key() {
        panic!("Neighborhood must be built on root node with public key from cryptde()");
    }
    let mut config = BootstrapperConfig::new();
    config.neighborhood_config = match neighbor_opt {
        Some(neighbor) => NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                root.node_addr_opt().expect("Test-drive me!"),
                vec![NodeDescriptor::from(neighbor).to_string(cryptde, DEFAULT_CHAIN_ID)],
                root.rate_pack().clone(),
            ),
        },
        None => NeighborhoodConfig {
            mode: NeighborhoodMode::ZeroHop,
        },
    };
    config.earning_wallet = root.earning_wallet();
    config.consuming_wallet = Some(make_paying_wallet(b"consuming"));
    Neighborhood::new(cryptde, &config)
}

impl From<&NodeRecord> for NeighborhoodMode {
    // Note: not a general-purpose function. Doesn't detect ZeroHop and doesn't reconstruct neighbor_configs.
    fn from(node: &NodeRecord) -> Self {
        match (
            node.node_addr_opt(),
            node.accepts_connections(),
            node.routes_data(),
        ) {
            (Some(node_addr), true, true) => {
                NeighborhoodMode::Standard(node_addr, vec![], node.rate_pack().clone())
            }
            (_, false, true) => NeighborhoodMode::OriginateOnly(vec![], node.rate_pack().clone()),
            (_, false, false) => NeighborhoodMode::ConsumeOnly(vec![]),
            (node_addr_opt, accepts_connections, routes_data) => panic!(
                "Cannot determine NeighborhoodMode from triple: ({:?}, {}, {})",
                node_addr_opt, accepts_connections, routes_data
            ),
        }
    }
}

impl NodeRecord {
    pub fn earning_wallet_from_key(public_key: &PublicKey) -> Wallet {
        match Self::consuming_wallet_from_key(public_key) {
            Some(wallet) => wallet,
            None => panic!("Failed to create earning wallet"),
        }
    }

    pub fn consuming_wallet_from_key(public_key: &PublicKey) -> Option<Wallet> {
        let mut data = [0u8; 64];
        let key_slice = public_key.as_slice();
        data[64 - key_slice.len()..].copy_from_slice(key_slice);
        match ethsign::PublicKey::from_slice(&data) {
            Ok(public) => Some(Wallet::from(web3::types::Address {
                0: *public.address(),
            })),
            Err(_) => None,
        }
    }

    pub fn new_for_tests(
        public_key: &PublicKey,
        node_addr_opt: Option<&NodeAddr>,
        base_rate: u64,
        accepts_connections: bool,
        routes_data: bool,
    ) -> NodeRecord {
        let mut node_record = NodeRecord::new(
            public_key,
            NodeRecord::earning_wallet_from_key(public_key),
            rate_pack(base_rate),
            accepts_connections,
            routes_data,
            0,
            &CryptDENull::from(public_key, DEFAULT_CHAIN_ID),
        );
        if let Some(node_addr) = node_addr_opt {
            node_record.set_node_addr(node_addr).unwrap();
        }
        node_record.signed_gossip =
            PlainData::from(serde_cbor::ser::to_vec(&node_record.inner).unwrap());
        node_record.regenerate_signed_gossip(&CryptDENull::from(&public_key, DEFAULT_CHAIN_ID));
        node_record
    }

    pub fn resign(&mut self) {
        let cryptde = CryptDENull::from(self.public_key(), DEFAULT_CHAIN_ID);
        self.regenerate_signed_gossip(&cryptde);
    }
}

impl AccessibleGossipRecord {
    pub fn resign(&mut self) {
        let cryptde = CryptDENull::from(&self.inner.public_key, DEFAULT_CHAIN_ID);
        self.regenerate_signed_gossip(&cryptde);
    }
}

impl PartialEq for NodeRecord {
    fn eq(&self, other: &NodeRecord) -> bool {
        if self.inner != other.inner {
            return false;
        }
        if self.metadata != other.metadata {
            return false;
        }
        if self.signature != other.signature {
            return false;
        }
        let self_nri: NodeRecordInner =
            serde_cbor::de::from_slice(self.signed_gossip.as_slice()).unwrap();
        let other_nri: NodeRecordInner =
            serde_cbor::de::from_slice(other.signed_gossip.as_slice()).unwrap();
        self_nri == other_nri
    }
}

impl NeighborhoodDatabase {
    // These methods are intended for use only in tests. Do not use them in production code.
    pub fn add_arbitrary_half_neighbor(
        &mut self,
        node_key: &PublicKey,
        new_neighbor: &PublicKey,
    ) -> bool {
        if self.has_half_neighbor(node_key, new_neighbor) {
            false
        } else {
            let node_ref = self.node_by_key_mut(node_key).unwrap();
            node_ref
                .add_half_neighbor_key(new_neighbor.clone())
                .unwrap();
            node_ref.resign();
            true
        }
    }

    pub fn add_arbitrary_full_neighbor(
        &mut self,
        node_key: &PublicKey,
        new_neighbor: &PublicKey,
    ) -> bool {
        if self.has_full_neighbor(node_key, new_neighbor) {
            false
        } else {
            let over = self.add_arbitrary_half_neighbor(node_key, new_neighbor);
            let back = self.add_arbitrary_half_neighbor(new_neighbor, node_key);
            over || back
        }
    }

    pub fn remove_arbitrary_half_neighbor(
        &mut self,
        node_key: &PublicKey,
        neighbor_key: &PublicKey,
    ) -> bool {
        if let Some(node) = self.node_by_key_mut(node_key) {
            if node.remove_half_neighbor_key(neighbor_key) {
                node.resign();
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn resign_node(&mut self, public_key: &PublicKey) {
        let node_record = {
            let mut node_record = self.node_by_key(public_key).unwrap().clone();
            node_record.resign();
            node_record
        };
        let node_ref = self.node_by_key_mut(public_key).unwrap();
        node_ref.signed_gossip = node_record.signed_gossip;
        node_ref.signature = node_record.signature;
    }
}

impl From<&NodeRecord> for AccessibleGossipRecord {
    fn from(node_record: &NodeRecord) -> Self {
        AccessibleGossipRecord {
            signed_gossip: node_record.signed_gossip.clone(),
            signature: node_record.signature.clone(),
            node_addr_opt: node_record.node_addr_opt(),
            inner: node_record.inner.clone(),
        }
    }
}
