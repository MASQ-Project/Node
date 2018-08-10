// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::node_addr::NodeAddr;
use sub_lib::cryptde::Key;
use std::collections::HashMap;
use neighborhood_database::NodeRecord;

#[derive (Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GossipNodeRecord {
    pub public_key: Key,
    pub node_addr_opt: Option<NodeAddr>,
    pub is_bootstrap_node: bool,
}

impl GossipNodeRecord {
    pub fn from (node_record_ref: &NodeRecord, reveal_node_addr: bool) -> GossipNodeRecord {
        GossipNodeRecord {
            public_key: node_record_ref.public_key ().clone (),
            node_addr_opt: if reveal_node_addr {
                match node_record_ref.node_addr_opt () {
                    Some (ref node_addr) => Some ((*node_addr).clone ()),
                    None => None
                }
            }
            else {
                None
            },
            is_bootstrap_node: node_record_ref.is_bootstrap_node ()
        }
    }

    pub fn to_node_record(&self) -> NodeRecord {
        let node_addr_opt = match self.node_addr_opt {
            Some (ref node_addr) => Some (node_addr),
            None => None
        };
        NodeRecord::new (&self.public_key, node_addr_opt, self.is_bootstrap_node)
    }
}

#[derive (Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct NeighborRelationship {
    pub from: u32,
    pub to: u32
}

#[derive (Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub node_records: Vec<GossipNodeRecord>,
    pub neighbor_pairs: Vec<NeighborRelationship>,
}

pub struct GossipBuilder {
    gossip: Gossip,
    key_to_index: HashMap<Key, u32>,
}

impl GossipBuilder {
    pub fn new () -> GossipBuilder {
        GossipBuilder {
            gossip: Gossip {
                node_records: vec!(),
                neighbor_pairs: vec!(),
            },
            key_to_index: HashMap::new()
        }
    }

    pub fn node (mut self, node_record_ref: &NodeRecord, reveal_node_addr: bool) -> GossipBuilder {
        if self.key_to_index.contains_key (node_record_ref.public_key ()) {
            panic! ("GossipBuilder cannot add a node more than once")
        }
        self.gossip.node_records.push (GossipNodeRecord::from (node_record_ref, reveal_node_addr));
        self.key_to_index.insert (node_record_ref.public_key ().clone (), (self.gossip.node_records.len () - 1) as u32);
        self
    }

    pub fn neighbor_pair (mut self, from: &Key, to: &Key) -> GossipBuilder {
        {
            let from_index = self.key_to_index.get(from).expect("Internal error");
            let to_index = self.key_to_index.get(to).expect("Internal error");
            self.gossip.neighbor_pairs.push(NeighborRelationship {
                from: *from_index,
                to: *to_index
            });
        }
        self
    }

    pub fn build (self) -> Gossip {
        self.gossip
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use neighborhood_test_utils::make_node_record;

    #[test]
    #[should_panic (expected = "GossipBuilder cannot add a node more than once")]
    fn adding_node_twice_to_gossip_builder_causes_panic () {
        let node = make_node_record (1234, true, true);
        let builder = GossipBuilder::new ().node (&node, true);

        builder.node (&node, true);
    }

    #[test]
    fn adding_node_with_addr_and_reveal_results_in_node_with_addr () {
        let node = make_node_record (1234, true, false);
        let builder = GossipBuilder::new ();

        let builder = builder.node (&node, true);

        let mut gossip = builder.build ();
        assert_eq! (gossip.node_records.remove (0).node_addr_opt.unwrap (), node.node_addr_opt ().unwrap ())
    }

    #[test]
    fn adding_node_with_addr_and_no_reveal_results_in_node_with_no_addr () {
        let node = make_node_record (1234, true, false);
        let builder = GossipBuilder::new ();

        let builder = builder.node (&node, false);

        let mut gossip = builder.build ();
        assert_eq! (gossip.node_records.remove (0).node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_reveal_results_in_node_with_no_addr () {
        let node = make_node_record (1234, false, false);
        let builder = GossipBuilder::new ();

        let builder = builder.node (&node, true);

        let mut gossip = builder.build ();
        assert_eq! (gossip.node_records.remove (0).node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_no_reveal_results_in_node_with_no_addr () {
        let node = make_node_record (1234, false, false);
        let builder = GossipBuilder::new ();

        let builder = builder.node (&node, false);

        let mut gossip = builder.build ();
        assert_eq! (gossip.node_records.remove (0).node_addr_opt, None)
    }
}
