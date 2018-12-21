// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use neighborhood_database::NodeRecord;
use neighborhood_database::NodeRecordInner;
use neighborhood_database::NodeSignatures;
use std::collections::HashSet;
use sub_lib::cryptde::Key;

use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;

#[derive(Clone, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct GossipNodeRecord {
    pub inner: NodeRecordInner,
    pub signatures: NodeSignatures,
}

impl Debug for GossipNodeRecord {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.write_str(self.to_human_readable().as_str())
    }
}

impl GossipNodeRecord {
    pub fn from(node_record_ref: &NodeRecord, reveal_node_addr: bool) -> GossipNodeRecord {
        GossipNodeRecord {
            inner: NodeRecordInner {
                public_key: node_record_ref.public_key().clone(),
                node_addr_opt: if reveal_node_addr {
                    match node_record_ref.node_addr_opt() {
                        Some(ref node_addr) => Some((*node_addr).clone()),
                        None => None,
                    }
                } else {
                    None
                },
                is_bootstrap_node: node_record_ref.is_bootstrap_node(),
                neighbors: node_record_ref.neighbors().clone(),
            },
            // crashpoint
            signatures: node_record_ref
                .signatures()
                .expect("Attempted to create Gossip about an unsigned NodeRecord"),
        }
    }

    pub fn to_node_record(&self) -> NodeRecord {
        let mut node_record = NodeRecord::new(
            &self.inner.public_key,
            self.inner.node_addr_opt.as_ref(),
            self.inner.is_bootstrap_node,
            Some(self.signatures.clone()),
        );
        node_record
            .neighbors_mut()
            .extend(self.inner.neighbors.clone());
        node_record
    }

    fn to_human_readable(&self) -> String {
        let mut human_readable = String::new();
        human_readable.push_str("\nGossipNodeRecord {");
        human_readable.push_str("\n\tinner: NodeRecordInner {");
        human_readable.push_str(&format!("\n\t\tpublic_key: {:?},", self.inner.public_key));
        human_readable.push_str(&format!(
            "\n\t\tnode_addr_opt: {:?},",
            self.inner.node_addr_opt
        ));
        human_readable.push_str(&format!(
            "\n\t\tis_bootstrap_node: {:?},",
            self.inner.is_bootstrap_node
        ));
        human_readable.push_str(&format!("\n\t\tneighbors: {:?},", self.inner.neighbors));
        human_readable.push_str("\n\t},");
        human_readable.push_str("\n\tsignatures: Signatures {");
        human_readable.push_str(&format!(
            "\n\t\tcomplete: {:?},",
            self.signatures.complete()
        ));
        human_readable.push_str(&format!(
            "\n\t\tobscured: {:?},",
            self.signatures.obscured()
        ));
        human_readable.push_str("\n\t},");
        human_readable.push_str("\n}");
        human_readable
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub node_records: Vec<GossipNodeRecord>,
}

pub fn to_dot_graph(gossip: Gossip, target: &Key, source: Key) -> String {
    let mut bootstrap_keys = vec![];
    for item in gossip.node_records.clone() {
        if item.inner.is_bootstrap_node {
            bootstrap_keys.push(item.inner.public_key.clone())
        }
    }

    let mut result = String::new();
    for node in gossip.node_records {
        let key = node.inner.public_key;
        // add node descriptor
        let mut node_label = format!("{}", key);
        match node.inner.node_addr_opt {
            Some(addr) => node_label.push_str(&format!("\\n{}", addr)),
            None => {}
        };
        if node.inner.is_bootstrap_node {
            node_label.push_str("\\nbootstrap");
        }
        let mut node_str = format!("\"{}\" [label=\"{}\"]", key, node_label);
        if key == source {
            node_str.push_str(" [style=filled]");
        } else if &key == target {
            node_str.push_str(" [shape=box]");
        }
        result = format!("{}; {}", node_str, result);

        // add node neighbors
        for neighbor_key in node.inner.neighbors {
            result.push_str(&format!(" \"{}\" -> \"{}\"", key, neighbor_key));
            if node.inner.is_bootstrap_node || bootstrap_keys.contains(&neighbor_key) {
                result.push_str(" [style=dashed]");
            }
            result.push_str(";");
        }
    }

    format!("digraph db {{ {} }}", result)
}

pub struct GossipBuilder {
    gossip: Gossip,
    keys_so_far: HashSet<Key>,
}

impl GossipBuilder {
    pub fn new() -> GossipBuilder {
        GossipBuilder {
            gossip: Gossip {
                node_records: vec![],
            },
            keys_so_far: HashSet::new(),
        }
    }

    pub fn node(mut self, node_record_ref: &NodeRecord, reveal_node_addr: bool) -> GossipBuilder {
        if self.keys_so_far.contains(node_record_ref.public_key()) {
            // crashpoint
            panic!("GossipBuilder cannot add a node more than once")
        }
        if node_record_ref.signatures().is_some() {
            self.gossip
                .node_records
                .push(GossipNodeRecord::from(node_record_ref, reveal_node_addr));
            self.keys_so_far
                .insert(node_record_ref.public_key().clone());
        }
        self
    }

    pub fn build(self) -> Gossip {
        self.gossip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip::GossipBuilder;
    use neighborhood_test_utils::make_node_record;
    use std::net::IpAddr;
    use std::str::FromStr;
    use sub_lib::node_addr::NodeAddr;

    #[test]
    #[should_panic(expected = "GossipBuilder cannot add a node more than once")]
    fn adding_node_twice_to_gossip_builder_causes_panic() {
        let node = make_node_record(1234, true, true);
        let builder = GossipBuilder::new().node(&node, true);

        builder.node(&node, true);
    }

    #[test]
    fn adding_node_with_addr_and_reveal_results_in_node_with_addr() {
        let node = make_node_record(1234, true, false);
        let builder = GossipBuilder::new();

        let builder = builder.node(&node, true);

        let mut gossip = builder.build();
        assert_eq!(
            gossip.node_records.remove(0).inner.node_addr_opt.unwrap(),
            node.node_addr_opt().unwrap()
        )
    }

    #[test]
    fn adding_node_with_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, true, false);
        let builder = GossipBuilder::new();

        let builder = builder.node(&node, false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).inner.node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false, false);
        let builder = GossipBuilder::new();

        let builder = builder.node(&node, true);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).inner.node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false, false);
        let builder = GossipBuilder::new();

        let builder = builder.node(&node, false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).inner.node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_missing_signatures_results_in_no_added_node() {
        let builder = GossipBuilder::new();

        let node = NodeRecord::new(
            &Key::new(&[5, 4, 3, 2]),
            Some(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
            false,
            None,
        );
        let builder = builder.node(&node, true);

        let gossip = builder.build();
        assert_eq!(0, gossip.node_records.len());
    }

    #[test]
    #[should_panic(expected = "Attempted to create Gossip about an unsigned NodeRecord")]
    fn gossip_node_record_cannot_be_created_from_node_with_missing_signatures() {
        let node = NodeRecord::new(
            &Key::new(&[5, 4, 3, 2]),
            Some(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
            false,
            None,
        );

        let _gossip = GossipNodeRecord::from(&node, true);
    }

    #[test]
    fn gossip_node_record_is_debug_formatted_to_be_human_readable() {
        let node = make_node_record(1234, true, false);

        let gossip = GossipNodeRecord::from(&node, true);

        let result = format!("{:?}", gossip);
        let expected = format!(
            "\nGossipNodeRecord {{{}{}\n}}",
            "\n\tinner: NodeRecordInner {\n\t\tpublic_key: AQIDBA,\n\t\tnode_addr_opt: Some(1.2.3.4:[1234]),\n\t\tis_bootstrap_node: false,\n\t\tneighbors: [],\n\t},",
            "\n\tsignatures: Signatures {\n\t\tcomplete: CryptData { data: [115, 105, 103, 110, 101, 100] },\n\t\tobscured: CryptData { data: [115, 105, 103, 110, 101, 100] },\n\t},"
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn to_dot_graph_returns_gossip_in_dotgraph_format() {
        let mut target_node = make_node_record(1234, true, false);
        let mut source_node = make_node_record(2345, true, true);
        target_node.neighbors_mut().push(Key::new(b"9876"));
        source_node.neighbors_mut().push(Key::new(b"1793"));

        let builder = GossipBuilder::new();
        let gossip = builder
            .node(&target_node, true)
            .node(&source_node, true)
            .build();

        let result = to_dot_graph(
            gossip,
            target_node.public_key(),
            source_node.public_key().clone(),
        );
        let expected = format!(
            "digraph db {{ {}{} }}",
            "\"AgMEBQ\" [label=\"AgMEBQ\\n2.3.4.5:2345\\nbootstrap\"] [style=filled]; \"AQIDBA\" [label=\"AQIDBA\\n1.2.3.4:1234\"] [shape=box];  ",
            "\"AQIDBA\" -> \"OTg3Ng\"; \"AgMEBQ\" -> \"MTc5Mw\" [style=dashed];"
        );

        assert_eq!(result, expected);
    }
}
