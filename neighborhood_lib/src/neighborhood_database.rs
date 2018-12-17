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
    pub neighbors: Vec<Key>,
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

#[derive (Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeSignatures {
    complete: CryptData,
    obscured: CryptData,
}

impl NodeSignatures {
    pub fn new(complete: CryptData, obscured: CryptData) -> NodeSignatures {
        NodeSignatures {
            complete,
            obscured
        }
    }

    pub fn complete(&self) -> &CryptData {
        &self.complete
    }

    pub fn obscured(&self) -> &CryptData {
        &self.obscured
    }
}

#[derive (Clone, Debug)]
pub struct NodeRecord {
    // NOTE: If you add fields here, drive them into the implementation of PartialEq below.
    inner: NodeRecordInner,
    // TODO: Replace this with a retransmittable representation of the signed packet/signature from the incoming Gossip.
    signatures: Option<NodeSignatures>,
}

impl PartialEq for NodeRecord {
    fn eq(&self, other: &NodeRecord) -> bool {
        self.inner == other.inner &&
        self.signatures == other.signatures
    }
}

impl NodeRecord {
    pub fn new (public_key: &Key, node_addr_opt: Option<&NodeAddr>, is_bootstrap_node: bool, signatures: Option<NodeSignatures>) -> NodeRecord {
        NodeRecord {
            inner: NodeRecordInner{
                public_key: public_key.clone(),
                node_addr_opt: match node_addr_opt {
                    Some(node_addr) => Some(node_addr.clone()),
                    None => None
                },
                is_bootstrap_node,
                neighbors: vec! (),
            },
            signatures,
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

    pub fn set_signatures(&mut self, signatures: NodeSignatures) -> Result<bool, NeighborhoodDatabaseError> {
        if self.signatures.is_none() {
            self.signatures = Some(signatures);
            Ok(true)
        } else {
            if &signatures == self.signatures.as_ref().unwrap() {
                Ok(false)
            } else {
                Err(NeighborhoodDatabaseError::NodeSignaturesAlreadySet(self.signatures.clone().expect("Node Signatures magically disappeared")))
            }
        }
    }

    pub fn neighbors(&self) -> &Vec<Key> {
        &self.inner.neighbors
    }

    pub fn neighbors_mut(&mut self) -> &mut Vec<Key> {
        &mut self.inner.neighbors
    }

    pub fn has_neighbor (&self, public_key: &Key) -> bool {
        self.inner.neighbors.contains (public_key)
    }

    pub fn signatures(&self) -> Option<NodeSignatures> {
        self.signatures.clone()
    }

    pub fn sign(&mut self, cryptde: &CryptDE) {
        let complete_signature = self.inner.generate_signature(cryptde);

        let obscured_inner = NodeRecordInner {
            public_key: self.inner.clone().public_key,
            node_addr_opt: None,
            is_bootstrap_node: self.inner.is_bootstrap_node,
            neighbors: self.inner.neighbors.clone (),
        };
        let obscured_signature = obscured_inner.generate_signature(cryptde);

        self.signatures = Some(NodeSignatures::new(complete_signature, obscured_signature));
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

        let mut node_record = NodeRecord::new (public_key, Some(node_addr), is_bootstrap_node, None);
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
        // Note: Not tested because it's about to be removed by merge of SC-599 (2018-12-13)
        self.by_public_key.values_mut ().for_each (|node_record| {
            match (0..(node_record.neighbors ().len ())).find (|idx| (&node_record.neighbors ()[*idx] == node_key)) {
                None => (), // Not tested; see above about SC-599
                Some (idx) => {node_record.inner.neighbors.remove (idx);}
            };
        });
        Ok (())
    }

    pub fn add_neighbor (&mut self, node_key: &Key, new_neighbor: &Key) -> Result<bool, NeighborhoodDatabaseError> {
        if !self.keys ().contains (new_neighbor) {return Err (NodeKeyNotFound (new_neighbor.clone ()))};
        if self.has_neighbor (node_key, new_neighbor) {return Ok (false)}
        match self.node_by_key_mut (node_key) {
            Some(node) => {
                node.neighbors_mut ().push(new_neighbor.clone());
                Ok(true)
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
    NodeSignaturesAlreadySet (NodeSignatures)
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
    fn cant_use_remove_node_to_remove_own_node () {
        let this_node = make_node_record(1234, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        let result = subject.remove_node (this_node.public_key ());

        assert_eq! (result, Err (String::from ("Can't remove self")))
    }

    #[test]
    fn cant_use_remove_node_to_remove_unknown_node () {
        let this_node = make_node_record(1234, true, false);
        let unknown_node = make_node_record(4321, false, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));

        let result = subject.remove_node (unknown_node.public_key ());

        assert_eq! (result, Err (format! ("No knowledge of node {}: can't remove", unknown_node.public_key ())))
    }

    #[test]
    fn remove_node_removes_node_whose_ip_addr_we_dont_know () {
        let this_node = make_node_record(1234, true, false);
        let unknown_ip_node = make_node_record(4321, false, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        subject.add_node(&unknown_ip_node).unwrap();
        subject.add_neighbor (this_node.public_key (), unknown_ip_node.public_key ()).unwrap ();
        subject.add_neighbor (unknown_ip_node.public_key (), this_node.public_key ()).unwrap ();

        let result = subject.remove_node (unknown_ip_node.public_key ());

        assert_eq! (result, Ok (()));
        assert_eq! (subject.node_by_key (unknown_ip_node.public_key()), None);
    }

    #[test]
    fn remove_node_removes_node_whose_ip_addr_we_do_know () {
        let this_node = make_node_record(1234, true, false);
        let known_ip_node = make_node_record(4321, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        subject.add_node(&known_ip_node).unwrap();
        subject.add_neighbor (this_node.public_key (), known_ip_node.public_key ()).unwrap ();
        subject.add_neighbor (known_ip_node.public_key (), this_node.public_key ()).unwrap ();

        let result = subject.remove_node (known_ip_node.public_key ());

        assert_eq! (result, Ok (()));
        assert_eq! (subject.node_by_key (known_ip_node.public_key()), None);
        assert_eq! (subject.node_by_ip (&known_ip_node.node_addr_opt().unwrap ().ip_addr()), None);
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
    fn set_signatures_returns_true_when_signatures_are_not_set() {
        let subject_signed = make_node_record(1234, false, false);
        let mut subject = NodeRecord::new(subject_signed.public_key(), subject_signed.node_addr_opt().as_ref(), subject_signed.is_bootstrap_node(), None);

        assert_eq!(subject.signatures(), None);

        let signatures = NodeSignatures::new(CryptData::new(&[123, 56, 89]), CryptData::new(&[87, 54, 21]));

        let result = subject.set_signatures(signatures.clone());

        assert_eq!(result, Ok(true));
        assert_eq!(subject.signatures(), Some(signatures.clone()));

    }

    #[test]
    fn set_signatures_returns_false_when_signatures_match() {
        let mut subject = make_node_record(1234, false, false);

        let signatures = subject.signatures().unwrap().clone();
        let result = subject.set_signatures(signatures);

        assert_eq!(result, Ok(false));
    }

    #[test]
    fn set_signatures_returns_error_when_signatures_differ() {
        let mut subject = make_node_record(1234, false, false);

        let result = subject.set_signatures(NodeSignatures::new(CryptData::new(&[1, 2, 3]), CryptData::new(&[9, 8, 7])));

        assert_eq!(result, Err(NeighborhoodDatabaseError::NodeSignaturesAlreadySet(subject.signatures().unwrap())));
    }

    #[test]
    fn node_record_partial_eq () {
        let exemplar = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None);
        let duplicate = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None);
        let mut with_neighbor = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None);
        let mod_key = NodeRecord::new (&Key::new (&b"kope"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), true, None);
        let mod_node_addr = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.5").unwrap (), &vec! (1234))), true, None);
        let mod_is_bootstrap = NodeRecord::new (&Key::new (&b"poke"[..]), Some (&NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234))), false, None);
        let mod_signatures = NodeRecord::new (&Key::new(&b"poke"[..]), Some(&NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec!(1234))), true, Some(NodeSignatures::new(CryptData::new(b""), CryptData::new(b""))));
        with_neighbor.neighbors_mut ().push (mod_key.public_key ().clone ());

        assert_eq! (exemplar, exemplar);
        assert_eq! (exemplar, duplicate);
        assert_ne! (exemplar, with_neighbor);
        assert_ne! (exemplar, mod_key);
        assert_ne! (exemplar, mod_node_addr);
        assert_ne! (exemplar, mod_is_bootstrap);
        assert_ne! (exemplar, mod_signatures);
    }

    #[test]
    fn add_neighbor_returns_true_when_new_edge_is_created() {
        let this_node = make_node_record(1234, true, false);
        let other_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        subject.add_node(&other_node).unwrap ();

        let result = subject.add_neighbor(this_node.public_key(), other_node.public_key());

        assert!(result.unwrap(), "add_neighbor done goofed");
    }

    #[test]
    fn add_neighbor_returns_false_when_edge_already_exists() {
        let this_node = make_node_record(1234, true, false);
        let other_node = make_node_record (2345, true, false);
        let mut subject = NeighborhoodDatabase::new(&this_node.inner.public_key, this_node.inner.node_addr_opt.as_ref ().unwrap (), false, &CryptDENull::from(this_node.public_key()));
        subject.add_node(&other_node).unwrap ();
        subject.add_neighbor(this_node.public_key(), other_node.public_key()).unwrap ();

        let result = subject.add_neighbor(this_node.public_key(), other_node.public_key());

        assert!(!result.unwrap(), "add_neighbor done goofed");
    }
}
