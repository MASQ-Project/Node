// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::node_addr::NodeAddr;
use sub_lib::cryptde::Key;
use std::collections::HashMap;
use std::net::IpAddr;
use neighborhood_database::NeighborhoodDatabaseError::NodeKeyNotFound;
use std::collections::HashSet;

#[derive (Clone, Debug)]
pub struct NodeRecord {
    // NOTE: If you add fields here, drive them into the implementation of PartialEq below.
    public_key: Key,
    node_addr_opt: Option<NodeAddr>,
    is_bootstrap_node: bool,
    neighbors: HashSet<Key>,
}

impl PartialEq for NodeRecord {
    fn eq(&self, other: &NodeRecord) -> bool {
        self.public_key == other.public_key &&
        self.node_addr_opt == other.node_addr_opt &&
        self.is_bootstrap_node == other.is_bootstrap_node
    }
}

impl NodeRecord {
    pub fn new (public_key: &Key, node_addr_opt: Option<&NodeAddr>, is_bootstrap_node: bool) -> NodeRecord {
        NodeRecord {
            public_key: public_key.clone (),
            node_addr_opt: match node_addr_opt {Some (node_addr) => Some (node_addr.clone ()), None => None},
            is_bootstrap_node,
            neighbors: HashSet::new ()
        }
    }

    pub fn public_key<'a> (&'a self) -> &'a Key {
        &self.public_key
    }

    pub fn node_addr_opt<'a> (&'a self) -> Option<&'a NodeAddr> {
        self.node_addr_opt.as_ref ()
    }

    pub fn is_bootstrap_node (&self) -> bool {
        self.is_bootstrap_node
    }

    pub fn set_node_addr (&mut self, node_addr: &NodeAddr) -> Result<(), NeighborhoodDatabaseError> {
        match self.node_addr_opt {
            Some (ref node_addr) => Err (NeighborhoodDatabaseError::NodeAddrAlreadySet(node_addr.clone ())),
            None => {
                self.node_addr_opt = Some (node_addr.clone ());
                Ok (())
            }
        }
    }

    pub fn neighbors<'a> (&'a self) -> &'a HashSet<Key> {
        &self.neighbors
    }

    pub fn neighbors_mut<'a> (&'a mut self) -> &'a HashSet<Key> {
        &mut self.neighbors
    }

    pub fn has_neighbor (&self, public_key: &Key) -> bool {
        self.neighbors.contains (public_key)
    }
}

#[derive (Debug)]
pub struct NeighborhoodDatabase {
    this_node: Key,
    by_public_key: HashMap<Key, NodeRecord>,
    by_ip_addr: HashMap<IpAddr, Key>,
}

impl NeighborhoodDatabase {
    pub fn new (public_key: &Key, node_addr: &NodeAddr, is_bootstrap_node: bool) -> NeighborhoodDatabase {
        let mut result = NeighborhoodDatabase {
            this_node: public_key.clone (),
            by_public_key: HashMap::new (),
            by_ip_addr: HashMap::new (),
        };
        result.add_node (&NodeRecord::new (public_key, Some (node_addr), is_bootstrap_node)).expect ("Internal error");
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
        if self.keys ().contains (&node_record.public_key) {
            return Err(NeighborhoodDatabaseError::NodeKeyCollision(node_record.public_key.clone()));
        }
        self.by_public_key.insert (node_record.public_key.clone (), node_record.clone ());
        match node_record.node_addr_opt {
            Some (ref node_addr) => {self.by_ip_addr.insert (node_addr.ip_addr (), node_record.public_key.clone ());},
            None => ()
        }
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

    #[test]
    fn a_brand_new_database_has_the_expected_contents () {
        let this_node = make_node_record(1234, true, false);
        let this_node_addr_ref = this_node.node_addr_opt.as_ref ().unwrap ();

        let subject = NeighborhoodDatabase::new (&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);

        let node_record = NodeRecord::new (&this_node.public_key, Some (this_node_addr_ref), false);
        assert_eq! (subject.this_node, this_node.public_key.clone ());
        assert_eq! (subject.by_public_key, [(this_node.public_key.clone (), node_record.clone ())].iter ().cloned ().collect ());
        assert_eq! (subject.by_ip_addr, [(this_node.node_addr_opt.as_ref ().unwrap().ip_addr (), this_node.public_key.clone ())].iter ().cloned ().collect ());
        let root = subject.root ();
        assert_eq! (*root, node_record);
    }

    #[test]
    fn cant_add_a_node_twice () {
        let this_node = make_node_record(1234, true, false);
        let first_copy = make_node_record (2345, true, false);
        let second_copy = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);
        let first_result = subject.add_node (&first_copy);

        let second_result = subject.add_node (&second_copy);

        assert_eq! (first_result.unwrap (), ());
        assert_eq! (second_result.err ().unwrap (), NeighborhoodDatabaseError::NodeKeyCollision(second_copy.public_key.clone ()))
    }

    #[test]
    fn node_by_key_works() {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(4567, true, false);
        let another_node = make_node_record (5678, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);

        subject.add_node(&one_node).unwrap();

        assert_eq! (subject.node_by_key(&this_node.public_key).unwrap().clone(), this_node);
        assert_eq! (subject.node_by_key(&one_node.public_key).unwrap().clone(), one_node);
        assert_eq! (subject.node_by_key(&another_node.public_key), None);
    }

    #[test]
    fn node_by_ip_works() {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(4567, true, false);
        let another_node = make_node_record (5678, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);

        subject.add_node(&one_node).unwrap();

        assert_eq! (subject.node_by_ip(&this_node.node_addr_opt.as_ref().unwrap().ip_addr()).unwrap().clone(), this_node);
        assert_eq! (subject.node_by_ip(&one_node.node_addr_opt.as_ref().unwrap().ip_addr()).unwrap().clone(), one_node);
        assert_eq! (subject.node_by_ip(&another_node.node_addr_opt.unwrap().ip_addr()), None);
    }

    #[test]
    fn add_neighbor_works () {
        let this_node = make_node_record(1234, true, false);
        let one_node = make_node_record(2345, false, false);
        let another_node = make_node_record(3456, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);
        subject.add_node (&one_node).unwrap ();
        subject.add_node (&another_node).unwrap ();

        subject.add_neighbor (&one_node.public_key, &this_node.public_key).unwrap ();
        subject.add_neighbor (&one_node.public_key, &another_node.public_key).unwrap ();
        subject.add_neighbor (&another_node.public_key, &this_node.public_key).unwrap ();
        subject.add_neighbor (&another_node.public_key, &one_node.public_key).unwrap ();

        assert_eq! (subject.node_by_key (&this_node.public_key).unwrap ().has_neighbor (&this_node.public_key), false);
        assert_eq! (subject.node_by_key (&this_node.public_key).unwrap ().has_neighbor (&one_node.public_key), false);
        assert_eq! (subject.node_by_key (&this_node.public_key).unwrap ().has_neighbor (&another_node.public_key), false);
        assert_eq! (subject.node_by_key (&one_node.public_key).unwrap ().has_neighbor (&this_node.public_key), true);
        assert_eq! (subject.node_by_key (&one_node.public_key).unwrap ().has_neighbor (&one_node.public_key), false);
        assert_eq! (subject.node_by_key (&one_node.public_key).unwrap ().has_neighbor (&another_node.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.public_key).unwrap ().has_neighbor (&this_node.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.public_key).unwrap ().has_neighbor (&one_node.public_key), true);
        assert_eq! (subject.node_by_key (&another_node.public_key).unwrap ().has_neighbor (&another_node.public_key), false);
        assert_eq! (subject.keys (), HashSet::from_iter (vec! (&this_node.public_key, &one_node.public_key, &another_node.public_key).into_iter ()));
    }

    #[test]
    fn add_neighbor_complains_if_from_node_doesnt_exist () {
        let this_node = make_node_record(1234, true, false);
        let nonexistent_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);

        let result = subject.add_neighbor (nonexistent_node.public_key (), this_node.public_key ());

        assert_eq! (result, Err (NeighborhoodDatabaseError::NodeKeyNotFound(nonexistent_node.public_key().clone ())))
    }

    #[test]
    fn add_neighbor_complains_if_to_node_doesnt_exist () {
        let this_node = make_node_record(1234, true, false);
        let nonexistent_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new (&this_node.public_key, this_node.node_addr_opt.as_ref ().unwrap (), false);

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
        assert_eq! (subject.node_addr_opt (), Some (&first_node_addr));
        let second_node_addr = NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (5432));
        let result = subject.set_node_addr (&second_node_addr);
        assert_eq! (result, Err (NeighborhoodDatabaseError::NodeAddrAlreadySet (first_node_addr.clone ())));
        assert_eq! (subject.node_addr_opt (), Some (&first_node_addr));
    }

    #[test]
    fn node_record_partial_eq () {
        let exemplar = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true);
        let duplicate = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true);
        let mut with_neighbor = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true);
        let mod_key = NodeRecord::new (&Key::new (&b"kope"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true);
        let mod_node_addr = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.5").unwrap (), &vec! (1234))), true);
        let mod_is_bootstrap = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), false);
        with_neighbor.neighbors.insert (mod_key.public_key ().clone ());

        assert_eq! (exemplar, exemplar);
        assert_eq! (exemplar, duplicate);
        assert_eq! (exemplar, with_neighbor);
        assert_ne! (exemplar, mod_key);
        assert_ne! (exemplar, mod_node_addr);
        assert_ne! (exemplar, mod_is_bootstrap);
    }
}
