// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::bootstrapper::BootstrapperConfig;
use crate::neighborhood::gossip::{GossipBuilder, GossipNodeRecord, Gossip_0v1};
use crate::neighborhood::neighborhood_database::NeighborhoodDatabase;
use crate::neighborhood::node_location::NodeLocation;
use crate::neighborhood::node_record::{NodeRecord, NodeRecordInner_0v1, NodeRecordInputs};
use crate::neighborhood::{AccessibleGossipRecord, Neighborhood, DEFAULT_MIN_HOPS};
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, PlainData};
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::neighborhood::{Hops, NeighborhoodConfig, NeighborhoodMode, NodeDescriptor};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::*;
use ethereum_types::H160;
use masq_lib::blockchains::chains::Chain;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::net::Ipv4Addr;

pub const MIN_HOPS_FOR_TEST: Hops = DEFAULT_MIN_HOPS;
pub const DB_PATCH_SIZE_FOR_TEST: u8 = DEFAULT_MIN_HOPS as u8;

lazy_static! {
    pub static ref COUNTRY_CODE_DIGEST: Vec<(IpAddr, String, bool)> = vec![
        (
            IpAddr::V4(Ipv4Addr::new(123, 123, 123, 123)),
            "FR".to_string(),
            true
        ),
        (
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 123)),
            "US".to_string(),
            true
        ),
        (
            IpAddr::V4(Ipv4Addr::new(99, 99, 99, 99)),
            "AU".to_string(),
            true
        ),
        (
            IpAddr::V4(Ipv4Addr::new(180, 223, 223, 123)),
            "AU".to_string(),
            true
        ),
        (
            IpAddr::V4(Ipv4Addr::new(101, 0, 0, 255)),
            "AU".to_string(),
            true
        ),
        (
            IpAddr::V4(Ipv4Addr::new(255, 0, 0, 220)),
            "FR".to_string(),
            true
        ),
    ];
}

impl From<(&NeighborhoodDatabase, &PublicKey, bool)> for AccessibleGossipRecord {
    fn from(
        (database, public_key, reveal_node_addr): (&NeighborhoodDatabase, &PublicKey, bool),
    ) -> Self {
        let intermediate_gnr = GossipNodeRecord::from((database, public_key, reveal_node_addr));
        AccessibleGossipRecord::try_from(intermediate_gnr).unwrap()
    }
}

pub fn make_node_record(n: u16, has_ip: bool) -> NodeRecord {
    let seg1 = ((n / 1000) % 10) as u8;
    let seg2 = ((n / 100) % 10) as u8;
    let seg3 = ((n / 10) % 10) as u8;
    let seg4 = (n % 10) as u8;
    let key = PublicKey::new(&[seg1, seg2, seg3, seg4]);
    let ip_addr = IpAddr::V4(Ipv4Addr::new(seg1, seg2, seg3, seg4));
    let node_addr = NodeAddr::new(&ip_addr, &[n % 10000]);
    let (_ip, country_code, free_world_bit) = pick_country_code_record(n as u32 % 6);
    let location = match country_code.is_empty() {
        false => Some(NodeLocation {
            country_code,
            free_world_bit,
        }),
        true => None,
    };

    NodeRecord::new_for_tests(
        &key,
        if has_ip { Some(&node_addr) } else { None },
        u64::from(n),
        true,
        true,
        location,
    )
}

pub fn pick_country_code_record(n: u32) -> (IpAddr, String, bool) {
    COUNTRY_CODE_DIGEST[n as usize % COUNTRY_CODE_DIGEST.len()].clone()
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
    node_record.inner.public_key = main_cryptde().public_key().clone();
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
        &CryptDENull::from(node.public_key(), TEST_DEFAULT_CHAIN),
    )
}

// Note: If you don't supply a neighbor_opt, here, your root node's IP address will be removed.
pub fn neighborhood_from_nodes(
    root: &NodeRecord,
    neighbor_opt: Option<&NodeRecord>,
) -> Neighborhood {
    let cryptde: &dyn CryptDE = main_cryptde();
    if root.public_key() != cryptde.public_key() {
        panic!("Neighborhood must be built on root node with public key from cryptde()");
    }
    let mut config = BootstrapperConfig::new();
    config.neighborhood_config = match neighbor_opt {
        Some(neighbor) => NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                root.node_addr_opt().unwrap(),
                vec![NodeDescriptor::from((neighbor, Chain::EthRopsten, cryptde))],
                *root.rate_pack(),
            ),
            min_hops: MIN_HOPS_FOR_TEST,
        },
        None => NeighborhoodConfig {
            mode: NeighborhoodMode::ZeroHop,
            min_hops: MIN_HOPS_FOR_TEST,
        },
    };
    config.earning_wallet = root.earning_wallet();
    config.consuming_wallet_opt = Some(make_paying_wallet(b"consuming"));
    config.db_password_opt = Some("password".to_string());
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
                NeighborhoodMode::Standard(node_addr, vec![], *node.rate_pack())
            }
            (_, false, true) => NeighborhoodMode::OriginateOnly(vec![], *node.rate_pack()),
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
            Ok(public) => Some(Wallet::from(H160(*public.address()))),
            Err(_) => None,
        }
    }

    pub fn new_for_tests(
        public_key: &PublicKey,
        node_addr_opt: Option<&NodeAddr>,
        base_rate: u64,
        accepts_connections: bool,
        routes_data: bool,
        node_location: Option<NodeLocation>,
    ) -> NodeRecord {
        let node_record_data = NodeRecordInputs {
            earning_wallet: NodeRecord::earning_wallet_from_key(public_key),
            rate_pack: rate_pack(base_rate),
            accepts_connections,
            routes_data,
            version: 0,
            location: node_location,
        };
        let mut node_record = NodeRecord::new(
            public_key,
            &CryptDENull::from(public_key, TEST_DEFAULT_CHAIN),
            node_record_data,
        );
        if let Some(node_addr) = node_addr_opt {
            node_record.set_node_addr(node_addr).unwrap();
        }
        node_record.signed_gossip =
            PlainData::from(serde_cbor::ser::to_vec(&node_record.inner).unwrap());
        node_record.regenerate_signed_gossip(&CryptDENull::from(public_key, TEST_DEFAULT_CHAIN));
        node_record
    }

    pub fn resign(&mut self) {
        let cryptde = CryptDENull::from(self.public_key(), TEST_DEFAULT_CHAIN);
        self.regenerate_signed_gossip(&cryptde);
    }
}

impl AccessibleGossipRecord {
    pub fn resign(&mut self) {
        let cryptde = CryptDENull::from(&self.inner.public_key, TEST_DEFAULT_CHAIN);
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
        let self_nri: NodeRecordInner_0v1 =
            serde_cbor::de::from_slice(self.signed_gossip.as_slice()).unwrap();
        let other_nri: NodeRecordInner_0v1 =
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

pub fn make_ip(nonce: u8) -> IpAddr {
    Ipv4Addr::new(1, 1, 1, nonce).into()
}

pub fn make_node_descriptor(ip_addr: IpAddr) -> NodeDescriptor {
    NodeDescriptor {
        blockchain: Chain::EthRopsten,
        encryption_public_key: PublicKey::from(&b"bitcoin is real money"[..]),
        node_addr_opt: Some(NodeAddr::new(&ip_addr, &[1, 2, 3])),
    }
}

pub fn make_node(nonce: u8) -> (IpAddr, NodeDescriptor) {
    let ip_addr = make_ip(nonce);
    let node_descriptor = make_node_descriptor(ip_addr);

    (ip_addr, node_descriptor)
}

pub fn make_node_records(count: u16) -> Vec<NodeRecord> {
    (1..=count)
        .into_iter()
        .map(|i| make_node_record(i, true))
        .collect::<Vec<NodeRecord>>()
}

pub fn linearly_connect_nodes(nodes: &[NodeRecord]) -> NeighborhoodDatabase {
    let root_node = nodes.first().unwrap();
    let mut database = db_from_node(root_node);
    let nodes_count = nodes.len();
    for i in 1..nodes_count {
        database.add_node(nodes[i].clone()).unwrap();
        database.add_arbitrary_full_neighbor(nodes[i - 1].public_key(), nodes[i].public_key());
    }

    database
}

pub fn gossip_about_nodes_from_database(
    database: &NeighborhoodDatabase,
    nodes: &[NodeRecord],
) -> Gossip_0v1 {
    nodes
        .iter()
        .fold(GossipBuilder::new(database), |builder, node| {
            builder.node(node.public_key(), false)
        })
        .build()
}

pub fn public_keys_from_node_records(nodes: &[NodeRecord]) -> HashSet<PublicKey> {
    nodes
        .iter()
        .map(|node| node.public_key().clone())
        .collect::<HashSet<PublicKey>>()
}

pub fn cryptdes_from_node_records(nodes: &[NodeRecord]) -> Vec<CryptDENull> {
    nodes
        .iter()
        .map(|node| CryptDENull::from(node.public_key(), TEST_DEFAULT_CHAIN))
        .collect::<Vec<CryptDENull>>()
}
