use neighborhood_lib::gossip::Gossip;
use neighborhood_lib::gossip::GossipNodeRecord;
use neighborhood_lib::gossip::NeighborRelationship;
use neighborhood_lib::neighborhood_database::NodeRecordInner;
use neighborhood_lib::neighborhood_database::NodeSignatures;
use std::ops::Range;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use substratum_node::SubstratumNode;


pub struct GossipBuilder {
    node_info: Vec<GossipBuilderNodeInfo>,
    connection_pairs: Vec<(Key, Key)>,
}

impl GossipBuilder {
    pub fn new () -> GossipBuilder {
        GossipBuilder {
            node_info: vec! (),
            connection_pairs: vec! (),
        }
    }

    pub fn add_node (mut self, node: &SubstratumNode, is_bootstrap: bool, include_ip: bool) -> Self {
        self.node_info.push (GossipBuilderNodeInfo {
            node_record_inner: NodeRecordInner {
                public_key: node.public_key(),
                node_addr_opt: match include_ip {
                    true => Some (node.node_addr()),
                    false => None
                },
                is_bootstrap_node: is_bootstrap,
                neighbors: vec! (),
            },
            cryptde: Box::new (CryptDENull::from (&node.public_key ())),
        });
        self
    }

    pub fn add_fictional_node (mut self, node_record: NodeRecordInner) -> Self {
        let key = node_record.public_key.clone ();
        self.node_info.push (GossipBuilderNodeInfo {
            node_record_inner: node_record,
            cryptde: Box::new (CryptDENull::from (&key)),
        });
        self
    }

    pub fn add_connection (mut self, from_key: &Key, to_key: &Key) -> Self {
        self.connection_pairs.push ((from_key.clone (), to_key.clone ()));
        self
    }

    pub fn build (self) -> Gossip {
        let node_records = self.node_info.into_iter ().map (|node_info| {
            let signatures = NodeSignatures::from(node_info.cryptde.as_ref(), &node_info.node_record_inner);
            GossipNodeRecord {
                inner: node_info.node_record_inner,
                signatures,
            }
        }).collect ();
        let neighbor_pairs = self.connection_pairs.into_iter ().map (|connection_pair| {
            let (from_key, to_key) = connection_pair;
            let from_index = Self::find_index_of (&node_records, &from_key);
            let to_index = Self::find_index_of (&node_records, &to_key);
            NeighborRelationship {from: from_index as u32, to: to_index as u32}
        }).collect ();
        Gossip {
            node_records,
            neighbor_pairs
        }
    }

    pub fn build_cores_package (self, from: &Key, to: &Key) -> IncipientCoresPackage {
        let gossip = self.build ();
        IncipientCoresPackage::new (
            Route::new (
                vec! (RouteSegment::new (vec! (from, to), Component::Neighborhood)),
                &CryptDENull::from (from)
            ).unwrap (),
            gossip,
            to
        )
    }

    fn find_index_of (node_records: &Vec<GossipNodeRecord>, key: &Key) -> usize {
        let mut indices: Range<usize> = 0..node_records.len ();
        let find_result = indices.find (|idx| &node_records[*idx].inner.public_key == key);
        find_result.expect (format! ("Supplied connection reference {:?} for nonexistent node", key).as_str ())
    }
}

struct GossipBuilderNodeInfo {
    node_record_inner: NodeRecordInner,
    cryptde: Box<CryptDE>,
}
