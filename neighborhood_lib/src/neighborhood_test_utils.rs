// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use neighborhood_database::NeighborhoodDatabase;
use neighborhood_database::NodeRecord;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::node_addr::NodeAddr;

pub fn make_node_record(n: u16, has_ip: bool, is_bootstrap_node: bool) -> NodeRecord {
    let a = ((n / 1000) % 10) as u8;
    let b = ((n / 100) % 10) as u8;
    let c = ((n / 10) % 10) as u8;
    let d = (n % 10) as u8;
    let key = Key::new(&[a, b, c, d]);
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
) -> Vec<&'a Key> {
    let public_key_ref = node_record.public_key();
    let node_ref = database_ref.node_by_key(public_key_ref).unwrap();
    node_ref.neighbors().iter().map(|key_ref| key_ref).collect()
}

impl NodeRecord {
    pub fn new_for_tests(
        public_key: &Key,
        node_addr_opt: Option<&NodeAddr>,
        is_bootstrap_node: bool,
    ) -> NodeRecord {
        let mut node_record =
            NodeRecord::new(public_key, node_addr_opt, is_bootstrap_node, None, 0);
        node_record.sign(&CryptDENull::from(&public_key));
        node_record
    }
}
