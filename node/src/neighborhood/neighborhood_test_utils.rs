// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use super::neighborhood_database::NeighborhoodDatabase;
use super::neighborhood_database::NodeRecord;
use crate::neighborhood::neighborhood_database::NeighborhoodDatabaseError;
use crate::neighborhood::neighborhood_database::NeighborhoodDatabaseError::NodeKeyNotFound;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::wallet::Wallet;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::IpAddr;
use std::net::Ipv4Addr;

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
        is_bootstrap_node,
    )
}

pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
where
    T: Eq + Hash,
{
    let set: HashSet<T> = vec.into_iter().collect();
    set
}

pub fn neighbor_keys_of<'a>(
    database_ref: &'a NeighborhoodDatabase,
    node_record: &NodeRecord,
) -> Vec<&'a PublicKey> {
    let public_key_ref = node_record.public_key();
    let node_ref = database_ref.node_by_key(public_key_ref).unwrap();
    node_ref.neighbors().iter().map(|key_ref| key_ref).collect()
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
        is_bootstrap_node: bool,
    ) -> NodeRecord {
        let mut node_record = NodeRecord::new(
            public_key,
            node_addr_opt,
            NodeRecord::earning_wallet_from_key(public_key),
            NodeRecord::consuming_wallet_from_key(public_key),
            is_bootstrap_node,
            None,
            0,
        );
        node_record.sign(&CryptDENull::from(&public_key));
        node_record
    }
}

impl NeighborhoodDatabase {
    // This method is intended for use only in tests. Do not use it in production code.
    pub fn add_arbitrary_neighbor(
        &mut self,
        node_key: &PublicKey,
        new_neighbor: &PublicKey,
    ) -> Result<bool, NeighborhoodDatabaseError> {
        if !self.keys().contains(new_neighbor) {
            return Err(NodeKeyNotFound(new_neighbor.clone()));
        };
        if self.has_neighbor(node_key, new_neighbor) {
            return Ok(false);
        }
        match self.node_by_key_mut(node_key) {
            Some(node) => {
                node.neighbors_mut().push(new_neighbor.clone());
                Ok(true)
            }
            None => Err(NodeKeyNotFound(node_key.clone())),
        }
    }
}
