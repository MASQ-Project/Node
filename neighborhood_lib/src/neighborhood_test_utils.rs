// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use neighborhood_database::NodeRecord;
use std::net::Ipv4Addr;
use sub_lib::cryptde::Key;
use sub_lib::node_addr::NodeAddr;
use std::net::IpAddr;
use std::collections::HashSet;
use neighborhood_database::NeighborhoodDatabase;
use std::hash::Hash;
use neighborhood_database::NodeRecordInner;
use sub_lib::cryptde::PlainData;
use sub_lib::cryptde::CryptDE;
use sha1;
use serde_cbor;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::cryptde::CryptData;

pub fn make_node_record(n: u16, has_ip: bool, is_bootstrap_node: bool) -> NodeRecord {
    let a = ((n / 1000) % 10) as u8;
    let b = ((n / 100) % 10) as u8;
    let c = ((n / 10) % 10) as u8;
    let d = (n % 10) as u8;
    let key = Key::new (&[a, b, c, d]);
    let ip_addr = IpAddr::V4 (Ipv4Addr::new (a, b, c, d));
    let node_addr = NodeAddr::new (&ip_addr, &vec! (n % 10000));

    NodeRecord::new_for_tests(&key, if has_ip {Some(&node_addr)} else {None}, is_bootstrap_node)
}

pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T> where T: Eq + Hash {
    let set: HashSet<T> = vec.into_iter().collect();
    set
}

pub fn neighbor_keys_of<'a>(database_ref: &'a NeighborhoodDatabase, node_record: &NodeRecord) -> HashSet<&'a Key> {
    let public_key_ref = node_record.public_key();
    let node_ref = database_ref.node_by_key(public_key_ref).unwrap();
    let neighbor_key_refs: HashSet<&Key> = node_ref.neighbors().iter().map(|key_ref| key_ref).collect();
    neighbor_key_refs
}

impl NodeRecord {
    pub fn new_for_tests(public_key: &Key, node_addr_opt: Option<&NodeAddr>, is_bootstrap_node: bool) -> NodeRecord {
        // It would be nice to move the actual signing into a convenient NodeRecord constructor, but NodeRecord constructors shouldn't panic.
        // It's fine for NeighborhoodDatabase constructor to panic, though, since it happens only once at initialization time.
        let inner = NodeRecordInner {
            public_key: public_key.clone(),
            node_addr_opt: match node_addr_opt {
                Some(node_addr_ref) => Some(node_addr_ref.clone()),
                None => None
            },
            is_bootstrap_node,
        };
        let signature = NodeRecord::sign(&inner);

        let obscured_inner = NodeRecordInner {
            public_key: public_key.clone(),
            node_addr_opt: None,
            is_bootstrap_node,
        };
        let obscured_signature = NodeRecord::sign(&obscured_inner);

        NodeRecord::new(&public_key, node_addr_opt, is_bootstrap_node, Some(signature), Some(obscured_signature))
    }

    fn sign(inner: &NodeRecordInner) -> CryptData {
        let cryptde = CryptDENull::from(&inner.public_key);
        let serialized_inner = match serde_cbor::ser::to_vec (inner) {
            Ok(inner) => inner,
            Err(_) => {
                panic!("You put something in your test NodeRecord that could not be serialized")
            }
        };
        let mut hash = sha1::Sha1::new();
        hash.update (&serialized_inner[..]);
        cryptde.sign(&PlainData::new(&hash.digest ().bytes ())).expect("You put something in your test NodeRecord that could not be signed")

    }
}
