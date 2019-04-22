// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg(test)]

use super::neighborhood_database::NeighborhoodDatabase;
use super::node_record::NodeRecord;
use crate::neighborhood::neighborhood::Neighborhood;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::test_utils::cryptde;
use crate::test_utils::test_utils::rate_pack;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn make_node_record(n: u16, has_ip: bool, is_bootstrap_node: bool) -> NodeRecord {
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
        is_bootstrap_node,
    )
}

pub fn make_global_cryptde_node_record(
    n: u16,
    has_ip: bool,
    is_bootstrap_node: bool,
) -> NodeRecord {
    let mut node_record = make_node_record(n, has_ip, is_bootstrap_node);
    node_record.inner.public_key = cryptde().public_key().clone();
    node_record
}

pub fn db_from_node(node: &NodeRecord) -> NeighborhoodDatabase {
    NeighborhoodDatabase::new(
        node.public_key(),
        &node.node_addr_opt().unwrap_or(NodeAddr::new(
            &IpAddr::from_str("200.200.200.200").unwrap(),
            &vec![200],
        )),
        node.earning_wallet(),
        node.consuming_wallet(),
        node.rate_pack().clone(),
        node.is_bootstrap_node(),
        &CryptDENull::from(node.public_key()),
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
    Neighborhood::new(
        cryptde,
        NeighborhoodConfig {
            neighbor_configs: match neighbor_opt {
                None => vec![],
                Some(neighbor) => vec![(
                    neighbor.public_key().clone(),
                    neighbor
                        .node_addr_opt()
                        .expect("Neighbor has to have NodeAddr"),
                )],
            },
            is_bootstrap_node: root.is_bootstrap_node(),
            local_ip_addr: root
                .node_addr_opt()
                .expect("Root has to have NodeAddr")
                .ip_addr(),
            clandestine_port_list: root.node_addr_opt().unwrap().ports(),
            earning_wallet: root.earning_wallet(),
            consuming_wallet: root.consuming_wallet(),
            rate_pack: root.rate_pack().clone(),
        },
    )
}

impl NodeRecord {
    pub fn earning_wallet_from_key(public_key: &PublicKey) -> Wallet {
        let mut result = String::from("0x");
        for i in public_key.as_slice() {
            result.push_str(&format!("{:x}", i));
        }
        Wallet { address: result }
    }

    pub fn consuming_wallet_from_key(public_key: &PublicKey) -> Option<Wallet> {
        let mut result = String::from("0x");
        let mut reversed_public_key_data = Vec::from(public_key.as_slice());
        reversed_public_key_data.reverse();
        for i in &reversed_public_key_data {
            result.push_str(&format!("{:x}", i));
        }
        Some(Wallet { address: result })
    }

    pub fn new_for_tests(
        public_key: &PublicKey,
        node_addr_opt: Option<&NodeAddr>,
        base_rate: u64,
        is_bootstrap_node: bool,
    ) -> NodeRecord {
        let mut node_record = NodeRecord::new(
            public_key,
            node_addr_opt,
            NodeRecord::earning_wallet_from_key(public_key),
            NodeRecord::consuming_wallet_from_key(public_key),
            rate_pack(base_rate),
            is_bootstrap_node,
            None,
            0,
        );
        node_record.sign(&CryptDENull::from(&public_key));
        node_record
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
            self.node_by_key_mut(node_key)
                .unwrap()
                .add_half_neighbor_key(new_neighbor.clone());
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
            node.remove_half_neighbor_key(neighbor_key)
        } else {
            false
        }
    }
}
