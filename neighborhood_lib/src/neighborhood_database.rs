// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::node_addr::NodeAddr;
use sub_lib::cryptde::Key;
use std::collections::HashMap;
use std::net::IpAddr;
use neighborhood_database::NeighborhoodDatabaseError::NodeKeyNotFound;
use std::collections::HashSet;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::PlainData;
use sub_lib::cryptde::CryptDE;
use serde_cbor;
use sha1;

#[derive (Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NodeRecordInner {
    pub public_key: Key,
    pub node_addr_opt: Option<NodeAddr>,
    pub is_bootstrap_node: bool,
}

impl NodeRecordInner {
    // TODO fail gracefully
    // For now, this is only called at initialization time (NeighborhoodDatabase) and in tests, so panicking is OK.
    // When we start signing NodeRecords at other times, we should probably not panic
    pub fn generate_signature(&self, cryptde: &CryptDE) -> CryptData {
        let serialized = match serde_cbor::ser::to_vec(&self) {
            Ok(inner) => inner,
            Err(_) => {
                panic!("NodeRecord content {:?} could not be serialized", &self)
            }
        };

        let mut hash = sha1::Sha1::new();
        hash.update(&serialized[..]);

        cryptde.sign(&PlainData::new(&hash.digest().bytes())).expect(&format!("NodeRecord content {:?} could not be signed", &self))
    }
}

#[derive (Clone, Debug)]
pub struct NodeRecord {
    neighbors: HashSet<Key>,
    // NOTE: If you add fields here, drive them into the implementation of PartialEq below.
    inner: NodeRecordInner,
    complete_signature: Option<CryptData>,
    obscured_signature: Option<CryptData>,
}

impl PartialEq for NodeRecord {
    fn eq(&self, other: &NodeRecord) -> bool {
        self.inner == other.inner &&
        self.complete_signature == other.complete_signature &&
        self.obscured_signature == other.obscured_signature
    }
}

impl NodeRecord {
    pub fn new (public_key: &Key, node_addr_opt: Option<&NodeAddr>, is_bootstrap_node: bool, complete_signature: Option<CryptData>, obscured_signature: Option<CryptData>) -> NodeRecord {
        NodeRecord {
            neighbors: HashSet::new (),
            inner: NodeRecordInner{
                public_key: public_key.clone(),
                node_addr_opt: match node_addr_opt {
                    Some(node_addr) => Some(node_addr.clone()),
                    None => None
                },
                is_bootstrap_node,
            },
            complete_signature,
            obscured_signature,
        }
    }

    pub fn public_key(&self) -> &Key {
        &self.inner.public_key
    }

    pub fn node_addr_opt (&self) -> Option<NodeAddr> {
        self.inner.node_addr_opt.clone ()
    }

    pub fn is_bootstrap_node (&self) -> bool {
        self.inner.is_bootstrap_node
    }

    pub fn set_node_addr (&mut self, node_addr: &NodeAddr) -> Result<(), NeighborhoodDatabaseError> {
        match self.inner.node_addr_opt {
            Some (ref node_addr) => Err (NeighborhoodDatabaseError::NodeAddrAlreadySet(node_addr.clone ())),
            None => {
                self.inner.node_addr_opt = Some (node_addr.clone ());
                Ok (())
            }
        }
    }

    pub fn neighbors(&self) -> &HashSet<Key> {
        &self.neighbors
    }

    pub fn neighbors_mut(&mut self) -> &HashSet<Key> {
        &mut self.neighbors
    }

    pub fn has_neighbor (&self, public_key: &Key) -> bool {
        self.neighbors.contains (public_key)
    }

    pub fn complete_signature(&self) -> Option<CryptData> {
        self.complete_signature.clone()
    }

    pub fn obscured_signature(&self) -> Option<CryptData> {
        self.obscured_signature.clone()
    }

    pub fn sign(&mut self, cryptde: &CryptDE) {
        self.complete_signature = Some(self.inner.generate_signature(cryptde));

        let obscured_inner = NodeRecordInner {
            public_key: self.inner.clone().public_key,
            node_addr_opt: None,
            is_bootstrap_node: self.inner.is_bootstrap_node,
        };
        self.obscured_signature = Some(obscured_inner.generate_signature(cryptde));
    }
}

#[derive (Debug)]
pub struct NeighborhoodDatabase {
    this_node: Key,
    by_public_key: HashMap<Key, NodeRecord>,
    by_ip_addr: HashMap<IpAddr, Key>,
}

impl NeighborhoodDatabase {
    pub fn new (public_key: &Key, node_addr: &NodeAddr, is_bootstrap_node: bool, cryptde: &CryptDE) -> NeighborhoodDatabase {
        let mut result = NeighborhoodDatabase {
            this_node: public_key.clone (),
            by_public_key: HashMap::new (),
            by_ip_addr: HashMap::new (),
        };

        let mut node_record = NodeRecord::new (public_key, Some(node_addr), is_bootstrap_node, None, None);
        node_record.sign(cryptde);
        result.add_node (&node_record).expect ("Unable to add self NodeRecord to Neighborhood");
        result
    }

    pub fn root (&self) -> &NodeRecord {
        self.node_by_key (&self.this_node).expect ("Internal error")
    }

    pub fn keys (&self) -> HashSet<&Key> {
        self.by_public_key.keys ().into_iter ().collect ()
    }

    pub fn node_by_key (&self, public_key: &Key) -> Option<&NodeRecord> {
        self.by_public_key.get(public_key)
    }

    pub fn node_by_key_mut (&mut self, public_key: &Key) -> Option<&mut NodeRecord> {
        self.by_public_key.get_mut (public_key)
    }

    pub fn node_by_ip(&self, ip_addr: &IpAddr) -> Option<&NodeRecord> {
        match self.by_ip_addr.get(ip_addr) {
            Some(key) => self.node_by_key(key),
            None => None
        }
    }

    pub fn has_neighbor (&self, from: &Key, to: &Key) -> bool {
        match self.node_by_key (from) {
            Some(f) => f.has_neighbor(to),
            None => false
        }
    }

    pub fn add_node (&mut self, node_record: &NodeRecord) -> Result<(), NeighborhoodDatabaseError> {
        if self.keys ().contains (&node_record.inner.public_key) {
            return Err(NeighborhoodDatabaseError::NodeKeyCollision(node_record.inner.public_key.clone()));
        }
        self.by_public_key.insert (node_record.inner.public_key.clone (), node_record.clone ());
        match node_record.inner.node_addr_opt {
            Some (ref node_addr) => {self.by_ip_addr.insert (node_addr.ip_addr (), node_record.inner.public_key.clone ());},
            None => ()
        }
        Ok (())
    }

    pub fn remove_node (&mut self, node_key: &Key) -> Result<(), String> {
        if self.root ().public_key () == node_key {
            return Err (format! ("Can't remove self"))
        }
        let to_remove = match self.by_public_key.remove (node_key) {
            None => {
                return Err (format!("No knowledge of node {}: can't remove", node_key))
            },
            Some(node_record) => node_record
        };
        match to_remove.node_addr_opt () {
            None => (),
            Some (node_addr) => {self.by_ip_addr.remove (&node_addr.ip_addr ()); ()}
        };
        self.by_public_key.values_mut ().for_each (|node_record| {
            node_record.neighbors.remove (node_key);
        });
        Ok (())
    }

    pub fn add_neighbor (&mut self, node_key: &Key, new_neighbor: &Key) -> Result<(), NeighborhoodDatabaseError> {
        if !self.keys ().contains (new_neighbor) {return Err (NodeKeyNotFound (new_neighbor.clone ()))};
        match self.node_by_key_mut (node_key) {
            Some(node) => {
                node.neighbors.insert (new_neighbor.clone ());
                Ok(())
            },
            None => Err(NodeKeyNotFound(node_key.clone()))
        }
    }
}

#[derive (Debug, PartialEq)]
pub enum NeighborhoodDatabaseError {
    NodeKeyNotFound (Key),
    NodeKeyCollision (Key),
    NodeAddrAlreadySet (NodeAddr),
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;
    use std::str::FromStr;
    use neighborhood_test_utils::make_node_record;
    use sub_lib::cryptde_null::CryptDENull;

    #[test]
    fn a_brand_new_database_has_the_expected_contents () {
        let this_node = make_node_record(1234, true, false);

        let subject = NeighborhoodDatabase::new (&this_node.public_key(), this_node.node_addr_opt().as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        assert_eq! (subject.this_node, this_node.public_key().clone ());
        assert_eq! (subject.by_public_key, [(this_node.public_key().clone (), this_node.clone ())].iter ().cloned ().collect ());
        assert_eq! (subject.by_ip_addr, [(this_node.node_addr_opt().as_ref ().unwrap().ip_addr (), this_node.public_key().clone ())].iter ().cloned ().collect ());
        let root = subject.root ();
        assert_eq! (*root, this_node);
    }

    #[test]
    fn cant_add_a_node_twice () {
        let this_node = make_node_record(1234, true, false);
        let first_copy = make_node_record (2345, true, false);
        let second_copy = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        let first_result = subject.add_node (&first_copy);

        let second_result = subject.add_node (&second_copy);

        assert_eq! (first_result.unwrap (), ());
        assert_eq! (second_result.err ().unwrap (), NeighborhoodDatabaseError::NodeKeyCollision(second_copy.inner.public_key.clone ()))
    }

    #[test]
    fn node_by_key_works() {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(4567, true, false);
        let another_node = make_node_record (5678, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        subject.add_node(&one_node).unwrap();

        assert_eq! (subject.node_by_key(&this_node.inner.public_key).unwrap().clone(), this_node);
        assert_eq! (subject.node_by_key(&one_node.inner.public_key).unwrap().clone(), one_node);
        assert_eq! (subject.node_by_key(&another_node.inner.public_key), None);
    }

    #[test]
    fn node_by_ip_works() {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(4567, true, false);
        let another_node = make_node_record (5678, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        subject.add_node(&one_node).unwrap();

        assert_eq! (subject.node_by_ip(&this_node.inner.node_addr_opt.as_ref().unwrap().ip_addr()).unwrap().clone(), this_node);
        assert_eq! (subject.node_by_ip(&one_node.inner.node_addr_opt.as_ref().unwrap().ip_addr()).unwrap().clone(), one_node);
        assert_eq! (subject.node_by_ip(&another_node.inner.node_addr_opt.unwrap().ip_addr()), None);
    }

    #[test]
    fn add_neighbor_works () {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(2345, false, false);
        let another_node = make_node_record(3456, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        subject.add_node (&one_node).unwrap ();
        subject.add_node (&another_node).unwrap ();

        subject.add_neighbor (&one_node.inner.public_key, &this_node.inner.public_key).unwrap ();
        subject.add_neighbor (&one_node.inner.public_key, &another_node.inner.public_key).unwrap ();
        subject.add_neighbor (&another_node.inner.public_key, &this_node.inner.public_key).unwrap ();
        subject.add_neighbor (&another_node.inner.public_key, &one_node.inner.public_key).unwrap ();

        assert_eq! (subject.node_by_key (&this_node.inner.public_key).unwrap ().has_neighbor (&this_node.inner.public_key), false);
        assert_eq! (subject.node_by_key (&this_node.inner.public_key).unwrap ().has_neighbor (&one_node.inner.public_key), false);
        assert_eq! (subject.node_by_key (&this_node.inner.public_key).unwrap ().has_neighbor (&another_node.inner.public_key), false);
        assert_eq! (subject.node_by_key (&one_node.inner.public_key).unwrap ().has_neighbor (&this_node.inner.public_key), true);
        assert_eq! (subject.node_by_key (&one_node.inner.public_key).unwrap ().has_neighbor (&one_node.inner.public_key), false);
        assert_eq! (subject.node_by_key (&one_node.inner.public_key).unwrap ().has_neighbor (&another_node.inner.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.inner.public_key).unwrap ().has_neighbor (&this_node.inner.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.inner.public_key).unwrap ().has_neighbor (&one_node.inner.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.inner.public_key).unwrap ().has_neighbor (&another_node.inner.public_key), false);
        assert_eq! (subject.keys (), HashSet::from_iter (vec! (&this_node.inner.public_key, &one_node.inner.public_key, &another_node.inner.public_key).into_iter ()));
    }

    #[test]
    fn add_neighbor_complains_if_from_node_doesnt_exist () {
        let this_node = make_node_record(1234, true, false);
        let nonexistent_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        let result = subject.add_neighbor (nonexistent_node.public_key (), this_node.public_key ());

        assert_eq! (result, Err (NeighborhoodDatabaseError::NodeKeyNotFound(nonexistent_node.public_key().clone ())))
    }

    #[test]
    fn add_neighbor_complains_if_to_node_doesnt_exist () {
        let this_node = make_node_record(1234, true, false);
        let nonexistent_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        let result = subject.add_neighbor (this_node.public_key (),nonexistent_node.public_key ());

        assert_eq! (result, Err (NeighborhoodDatabaseError::NodeKeyNotFound(nonexistent_node.public_key().clone ())))
    }

    #[test]
    fn set_node_addr_works_once_but_not_twice () {
        let mut subject = make_node_record(1234, false, false);
        assert_eq! (subject.node_addr_opt (), None);
        let first_node_addr = NodeAddr::new (&IpAddr::from_str ("4.3.2.1").unwrap (), &vec! (4321));
        let result = subject.set_node_addr (&first_node_addr);
        assert_eq! (result, Ok (()));
        assert_eq! (subject.node_addr_opt (), Some (first_node_addr.clone ()));
        let second_node_addr = NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (5432));
        let result = subject.set_node_addr (&second_node_addr);
        assert_eq! (result, Err (NeighborhoodDatabaseError::NodeAddrAlreadySet (first_node_addr.clone ())));
        assert_eq! (subject.node_addr_opt (), Some (first_node_addr));
    }

    #[test]
    fn node_record_partial_eq () {
        let exemplar = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None, None);
        let duplicate = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None, None);
        let mut with_neighbor = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None, None);
        let mod_key = NodeRecord::new (&Key::new (&b"kope"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None, None);
        let mod_node_addr = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.5").unwrap (), &vec! (1234))), true, None, None);
        let mod_is_bootstrap = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), false, None, None);
        let mod_complete_signature = NodeRecord::new (&Key::new(&b"poke"[..]), Some(&NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec!(1234))), true, Some(CryptData::new(b"")), exemplar.obscured_signature().clone());
        let mod_obscured_signature = NodeRecord::new (&Key::new(&b"poke"[..]), Some(&NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec!(1234))), true, exemplar.complete_signature().clone(), Some(CryptData::new(b"")));
        with_neighbor.neighbors.insert (mod_key.public_key ().clone ());

        assert_eq! (exemplar, exemplar);
        assert_eq! (exemplar, duplicate);
        assert_eq! (exemplar, with_neighbor);
        assert_ne! (exemplar, mod_key);
        assert_ne! (exemplar, mod_node_addr);
        assert_ne! (exemplar, mod_is_bootstrap);
        assert_ne! (exemplar, mod_complete_signature);
        assert_ne! (exemplar, mod_obscured_signature);
    }
}
