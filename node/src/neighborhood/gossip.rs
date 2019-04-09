// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::node_record::NodeRecord;
use super::node_record::NodeRecordInner;
use super::node_record::NodeSignatures;
use crate::neighborhood::dot_graph::{
    render_dot_graph, DotRenderable, EdgeRenderable, NodeRenderable,
};
use crate::neighborhood::neighborhood_database::NeighborhoodDatabase;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::hopper::MessageType;
use crate::sub_lib::node_addr::NodeAddr;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::iter::FromIterator;
use std::net::IpAddr;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn from(
        database: &NeighborhoodDatabase,
        public_key_ref: &PublicKey,
        reveal_node_addr: bool,
    ) -> GossipNodeRecord {
        // crashpoint
        let node_record_ref = database
            .node_by_key(public_key_ref)
            .expect("Attempted to create Gossip around nonexistent Node");
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
                earning_wallet: node_record_ref.earning_wallet(),
                consuming_wallet: node_record_ref.consuming_wallet(),
                rate_pack: node_record_ref.rate_pack().clone(),
                is_bootstrap_node: node_record_ref.is_bootstrap_node(),
                neighbors: node_record_ref.inner.neighbors.clone(),
                version: node_record_ref.version(),
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
            self.inner.earning_wallet.clone(),
            self.inner.consuming_wallet.clone(),
            self.inner.rate_pack.clone(),
            self.inner.is_bootstrap_node,
            Some(self.signatures.clone()),
            self.inner.version,
        );
        node_record.add_half_neighbor_keys(self.inner.neighbors.clone().into_iter().collect());
        node_record
    }

    // TODO - should we use a json serializer to make this?
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
        human_readable.push_str(&format!(
            "\n\t\tearning_wallet: {:?},",
            self.inner.earning_wallet
        ));
        human_readable.push_str(&format!(
            "\n\t\tconsuming_wallet: {:?},",
            self.inner.consuming_wallet
        ));
        human_readable.push_str(&format!("\n\t\trate_pack: {:?},", self.inner.rate_pack));
        human_readable.push_str(&format!(
            "\n\t\tneighbors: {:?},",
            Vec::from_iter(self.inner.neighbors.clone().into_iter())
        ));
        human_readable.push_str(&format!("\n\t\tversion: {:?},", self.inner.version));
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

    pub fn public_key(&self) -> PublicKey {
        self.inner.public_key.clone()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub node_records: Vec<GossipNodeRecord>,
}

impl Into<MessageType> for Gossip {
    fn into(self) -> MessageType {
        MessageType::Gossip(self)
    }
}

#[derive(Clone)]
pub struct DotGossipEndpoint {
    pub public_key: PublicKey,
    pub node_addr_opt: Option<NodeAddr>,
}

impl From<&NodeRecord> for DotGossipEndpoint {
    fn from(input: &NodeRecord) -> Self {
        DotGossipEndpoint {
            public_key: input.public_key().clone(),
            node_addr_opt: input.node_addr_opt().clone(),
        }
    }
}

impl From<&GossipNodeRecord> for DotGossipEndpoint {
    fn from(input: &GossipNodeRecord) -> Self {
        DotGossipEndpoint {
            public_key: input.public_key(),
            node_addr_opt: input.inner.node_addr_opt.clone(),
        }
    }
}

impl From<(&NeighborhoodDatabase, &PublicKey)> for DotGossipEndpoint {
    fn from(input: (&NeighborhoodDatabase, &PublicKey)) -> Self {
        let (database, public_key) = input;
        match database.node_by_key(public_key) {
            Some(node_record) => node_record.into(),
            None => DotGossipEndpoint {
                public_key: PublicKey::new(b""),
                node_addr_opt: None,
            },
        }
    }
}

impl From<(&PublicKey, &Option<NodeAddr>)> for DotGossipEndpoint {
    fn from(input: (&PublicKey, &Option<NodeAddr>)) -> Self {
        let (public_key, node_addr) = input;
        DotGossipEndpoint {
            public_key: public_key.clone(),
            node_addr_opt: node_addr.clone(),
        }
    }
}

impl From<&PublicKey> for DotGossipEndpoint {
    fn from(input: &PublicKey) -> Self {
        DotGossipEndpoint {
            public_key: input.clone(),
            node_addr_opt: None,
        }
    }
}

impl From<IpAddr> for DotGossipEndpoint {
    fn from(input: IpAddr) -> Self {
        DotGossipEndpoint {
            public_key: PublicKey::new(b""),
            node_addr_opt: Some(NodeAddr::new(&input, &vec![0])),
        }
    }
}

struct SrcDestRenderable {
    name: String,
    prefix: String,
    node: DotGossipEndpoint,
}

impl DotRenderable for SrcDestRenderable {
    fn render(&self) -> String {
        let socket_addr_str = match &self.node.node_addr_opt {
            Some(node_addr) => format!("{}", node_addr.ip_addr()),
            None => String::from("Unknown"),
        };
        let public_key_64 = format!("{}", self.node.public_key);
        let public_key_trunc = if public_key_64.len() > 8 {
            &public_key_64[0..8]
        } else {
            &public_key_64
        };
        format!(
            "\"{}\" [label=\"{}\\n{}\\n{}\"];",
            self.name, self.prefix, public_key_trunc, socket_addr_str
        )
    }
}

impl SrcDestRenderable {
    fn src(endpoint: DotGossipEndpoint) -> SrcDestRenderable {
        SrcDestRenderable {
            name: String::from("src"),
            prefix: String::from("Gossip From:"),
            node: endpoint,
        }
    }

    fn dest(endpoint: DotGossipEndpoint) -> SrcDestRenderable {
        SrcDestRenderable {
            name: String::from("dest"),
            prefix: String::from("Gossip To:"),
            node: endpoint,
        }
    }
}

struct SrcDestEdgeRenderable {}

impl DotRenderable for SrcDestEdgeRenderable {
    fn render(&self) -> String {
        String::from("\"src\" -> \"dest\" [arrowhead=empty];")
    }
}

impl Gossip {
    // Pass in:
    //   &NodeRecord, or
    //   &GossipNodeRecord, or
    //   (&NeighborhoodDatabase, &PublicKey), or
    //   (&PublicKey, &Option<NodeAddr>), or
    //   &PublicKey, or
    //   IpAddr
    // for source and target
    pub fn to_dot_graph<S, T>(&self, source: S, target: T) -> String
    where
        S: Into<DotGossipEndpoint>,
        T: Into<DotGossipEndpoint>,
    {
        let renderables = self.to_dot_renderables(source, target);
        render_dot_graph(renderables)
    }

    fn to_dot_renderables<S, T>(&self, source_into: S, target_into: T) -> Vec<Box<DotRenderable>>
    where
        S: Into<DotGossipEndpoint>,
        T: Into<DotGossipEndpoint>,
    {
        let source: DotGossipEndpoint = source_into.into();
        let target: DotGossipEndpoint = target_into.into();
        let mut mentioned: HashSet<PublicKey> = HashSet::new();
        let mut present: HashSet<PublicKey> = HashSet::new();
        let mut node_renderables: Vec<NodeRenderable> = vec![];
        let mut edge_renderables: Vec<EdgeRenderable> = vec![];
        let bootstrap_keys: HashSet<PublicKey> = self
            .node_records
            .iter()
            .filter(|n| n.inner.is_bootstrap_node)
            .map(|n| n.public_key())
            .collect();
        self.node_records.iter().for_each(|gnr| {
            present.insert(gnr.public_key());
            let public_key = &gnr.inner.public_key;
            gnr.inner.neighbors.iter().for_each(|k| {
                mentioned.insert(k.clone());
                edge_renderables.push(EdgeRenderable {
                    from: public_key.clone(),
                    to: k.clone(),
                    known_bootstrap_edge: bootstrap_keys.contains(public_key)
                        || bootstrap_keys.contains(k),
                })
            });
            node_renderables.push(NodeRenderable {
                version: Some(gnr.inner.version),
                public_key: public_key.clone(),
                node_addr: gnr.inner.node_addr_opt.clone(),
                known_bootstrap_node: bootstrap_keys.contains(public_key),
                known_source: public_key == &source.public_key,
                known_target: public_key == &target.public_key,
                is_present: true,
            });
        });
        mentioned.difference(&present).into_iter().for_each(|k| {
            node_renderables.push(NodeRenderable {
                version: None,
                public_key: k.clone(),
                node_addr: None,
                known_bootstrap_node: false,
                known_source: false,
                known_target: false,
                is_present: false,
            })
        });
        let mut result: Vec<Box<DotRenderable>> = vec![];
        for renderable in node_renderables {
            result.push(Box::new(renderable))
        }
        for renderable in edge_renderables {
            result.push(Box::new(renderable))
        }
        result.push(Box::new(SrcDestRenderable::src(source)));
        result.push(Box::new(SrcDestRenderable::dest(target)));
        result.push(Box::new(SrcDestEdgeRenderable {}));
        result
    }
}

pub struct GossipBuilder<'a> {
    db: &'a NeighborhoodDatabase,
    gossip: Gossip,
    keys_so_far: HashSet<PublicKey>,
}

impl<'a> GossipBuilder<'a> {
    pub fn new(db: &NeighborhoodDatabase) -> GossipBuilder {
        GossipBuilder {
            db,
            gossip: Gossip {
                node_records: vec![],
            },
            keys_so_far: HashSet::new(),
        }
    }

    pub fn empty() -> Gossip {
        Gossip {
            node_records: vec![],
        }
    }

    pub fn node(mut self, public_key_ref: &PublicKey, reveal_node_addr: bool) -> GossipBuilder<'a> {
        if self.keys_so_far.contains(public_key_ref) {
            // crashpoint
            panic!("GossipBuilder cannot add a Node more than once")
        }
        match self.db.node_by_key(public_key_ref) {
            // crashpoint
            None => panic!("GossipBuilder cannot add a nonexistent Node"),
            Some(node_record_ref) => {
                if node_record_ref.signatures().is_some() {
                    self.gossip.node_records.push(GossipNodeRecord::from(
                        self.db,
                        node_record_ref.public_key(),
                        reveal_node_addr,
                    ));
                    self.keys_so_far
                        .insert(node_record_ref.public_key().clone());
                }
            }
        }
        self
    }

    pub fn build(self) -> Gossip {
        self.gossip
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipBuilder;
    use super::super::neighborhood_test_utils::make_node_record;
    use super::*;
    use crate::neighborhood::neighborhood_test_utils::db_from_node;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::test_utils::{assert_string_contains, rate_pack, vec_to_set};
    use std::str::FromStr;

    #[test]
    fn can_create_a_node_record() {
        let mut expected_node_record = make_node_record(1234, true, true);
        expected_node_record.set_version(6);
        let mut db = db_from_node(&make_node_record(2345, true, false));
        db.add_node(&expected_node_record).unwrap();
        let builder = GossipBuilder::new(&db).node(expected_node_record.public_key(), true);

        let actual_node_record = builder
            .build()
            .node_records
            .first()
            .expect("should have the gnr")
            .to_node_record();

        assert_eq!(expected_node_record, actual_node_record);
    }

    #[test]
    #[should_panic(expected = "GossipBuilder cannot add a Node more than once")]
    fn adding_node_twice_to_gossip_builder_causes_panic() {
        let node = make_node_record(1234, true, true);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db).node(node.public_key(), true);

        builder.node(node.public_key(), true);
    }

    #[test]
    fn adding_node_with_addr_and_reveal_results_in_node_with_addr() {
        let node = make_node_record(1234, true, false);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), true);

        let mut gossip = builder.build();
        assert_eq!(
            gossip.node_records.remove(0).inner.node_addr_opt.unwrap(),
            node.node_addr_opt().unwrap()
        )
    }

    #[test]
    fn adding_node_with_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, true, false);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).inner.node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false, false);
        let mut db = db_from_node(&node);
        let gossip_node = &db.add_node(&make_node_record(2345, false, false)).unwrap();
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(gossip_node, true);

        let mut gossip = builder.build();
        assert_eq!(None, gossip.node_records.remove(0).inner.node_addr_opt)
    }

    #[test]
    fn adding_node_with_no_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false, false);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).inner.node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_missing_signatures_results_in_no_added_node() {
        let node = make_node_record(2345, true, false);
        let mut db = db_from_node(&node);

        let gossip_node = NodeRecord::new(
            &PublicKey::new(&[5, 4, 3, 2]),
            Some(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
            Wallet::new("earning"),
            Some(Wallet::new("consuming")),
            rate_pack(101),
            false,
            None,
            0,
        );
        db.add_node(&gossip_node).unwrap();
        let builder = GossipBuilder::new(&db);
        let builder = builder.node(gossip_node.public_key(), true);

        let gossip = builder.build();
        assert_eq!(0, gossip.node_records.len());
    }

    #[test]
    #[should_panic(expected = "Attempted to create Gossip about an unsigned NodeRecord")]
    fn gossip_node_record_cannot_be_created_from_node_with_missing_signatures() {
        let gossip_node = NodeRecord::new(
            &PublicKey::new(&[5, 4, 3, 2]),
            Some(&NodeAddr::new(
                &IpAddr::from_str("1.2.3.4").unwrap(),
                &vec![1234],
            )),
            Wallet::new("earning"),
            Some(Wallet::new("consuming")),
            rate_pack(102),
            false,
            None,
            0,
        );
        let mut db = db_from_node(&make_node_record(2345, true, false));
        db.add_node(&gossip_node).unwrap();

        GossipNodeRecord::from(&db, gossip_node.public_key(), true);
    }

    #[test]
    fn gossip_node_record_keeps_all_half_neighbors_including_bootstraps() {
        let this_node = make_node_record(1234, true, false);
        let full_neighbor_one = make_node_record(2345, true, false);
        let full_neighbor_two = make_node_record(3456, true, false);
        let full_neighbor_bootstrap = make_node_record(4567, true, true);
        let half_neighbor = make_node_record(5678, true, false);
        let db = {
            let mut db = db_from_node(&this_node);
            let this_node_key = db.root().public_key().clone();
            db.add_node(&full_neighbor_one).unwrap();
            db.add_node(&full_neighbor_two).unwrap();
            db.add_node(&full_neighbor_bootstrap).unwrap();
            db.add_node(&half_neighbor).unwrap();
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_one.public_key());
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_two.public_key());
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_bootstrap.public_key());
            db.add_arbitrary_half_neighbor(&this_node_key, half_neighbor.public_key());
            db
        };

        let result = GossipNodeRecord::from(&db, db.root().public_key(), true);

        assert_eq!(this_node.public_key(), &result.public_key());
        assert_eq!(this_node.node_addr_opt(), result.inner.node_addr_opt);
        assert_eq!(
            this_node.is_bootstrap_node(),
            result.inner.is_bootstrap_node
        );
        assert_eq!(
            vec_to_set(vec![
                full_neighbor_one.public_key().clone(),
                full_neighbor_two.public_key().clone(),
                half_neighbor.public_key().clone(),
                full_neighbor_bootstrap.public_key().clone(),
            ]),
            result.inner.neighbors
        );
        assert_eq!(this_node.earning_wallet(), result.inner.earning_wallet);
        assert_eq!(this_node.consuming_wallet(), result.inner.consuming_wallet);
        assert_eq!(this_node.version(), result.inner.version);
        assert_eq!(this_node.signatures().unwrap(), result.signatures);
    }

    #[test]
    fn gossip_node_record_is_debug_formatted_to_be_human_readable() {
        let node = make_node_record(1234, true, false);
        let mut db = db_from_node(&node);
        db.root_mut().increment_version();
        db.root_mut().increment_version();

        let gossip = GossipNodeRecord::from(&db, node.public_key(), true);

        let result = format!("{:?}", gossip);
        let expected = format!(
            "\nGossipNodeRecord {{{}{}\n}}",
            "\n\tinner: NodeRecordInner {\n\t\tpublic_key: AQIDBA,\n\t\tnode_addr_opt: Some(1.2.3.4:[1234]),\n\t\tis_bootstrap_node: false,\n\t\tearning_wallet: Wallet { address: \"0x1234\" },\n\t\tconsuming_wallet: Some(Wallet { address: \"0x4321\" }),\n\t\trate_pack: RatePack { routing_byte_rate: 1235, routing_service_rate: 1236, exit_byte_rate: 1237, exit_service_rate: 1238 },\n\t\tneighbors: [],\n\t\tversion: 2,\n\t},",
            "\n\tsignatures: Signatures {\n\t\tcomplete: CryptData { data: [115, 105, 103, 110, 101, 100] },\n\t\tobscured: CryptData { data: [115, 105, 103, 110, 101, 100] },\n\t},"
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn to_dot_graph_returns_gossip_in_dotgraph_format() {
        let mut source_node = make_node_record(1234, true, true);
        source_node.inner.public_key = PublicKey::new(&b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..]);
        let mut target_node = make_node_record(2345, true, false);
        target_node.inner.public_key = PublicKey::new(&b"ZYXWVUTSRQPONMLKJIHGFEDCBA"[..]);
        let neighbor = make_node_record(3456, false, false);
        let mut db = db_from_node(&source_node);
        db.add_node(&target_node).unwrap();
        db.add_node(&neighbor).unwrap();
        db.add_arbitrary_full_neighbor(target_node.public_key(), source_node.public_key());
        db.add_arbitrary_full_neighbor(target_node.public_key(), neighbor.public_key());
        db.add_arbitrary_full_neighbor(source_node.public_key(), neighbor.public_key());
        db.root_mut().increment_version();
        let nonexistent_node = make_node_record(4567, false, false);
        let mut neighbor_gnr = GossipNodeRecord::from(&db, neighbor.public_key(), true);
        neighbor_gnr
            .inner
            .neighbors
            .insert(nonexistent_node.public_key().clone());

        let gossip = Gossip {
            node_records: vec![
                GossipNodeRecord::from(&db, db.root().public_key(), true),
                GossipNodeRecord::from(&db, target_node.public_key(), true),
                neighbor_gnr,
            ],
        };

        let result = gossip.to_dot_graph(&source_node, &target_node);

        assert_string_contains(&result, "digraph db { ");
        assert_string_contains(&result, "\"AwQFBg\" [label=\"v0\\nAwQFBg\"]; ");
        assert_string_contains(
            &result,
            "\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\" [label=\"v1\\nQUJDREVG\\n1.2.3.4:1234\\nbootstrap\"] [style=filled]; ",
        );
        assert_string_contains(
            &result,
            "\"WllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE\" [label=\"v0\\nWllYV1ZV\\n2.3.4.5:2345\"] [shape=box]; ",
        );
        assert_string_contains(
            &result,
            "\"src\" [label=\"Gossip From:\\nQUJDREVG\\n1.2.3.4\"]; ",
        );
        assert_string_contains(
            &result,
            "\"dest\" [label=\"Gossip To:\\nWllYV1ZV\\n2.3.4.5\"]; ",
        );
        assert_string_contains(&result, "\"BAUGBw\" [label=\"BAUGBw\"] [shape=none]; ");
        assert_string_contains(&result, "\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\" -> \"WllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE\" [style=dashed]; ");
        assert_string_contains(
            &result,
            "\"WllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE\" -> \"AwQFBg\"; ",
        );
        assert_string_contains(
            &result,
            "\"AwQFBg\" -> \"WllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE\"; ",
        );
        assert_string_contains(&result, "\"AwQFBg\" -> \"BAUGBw\"; ");
        assert_string_contains(&result, "\"src\" -> \"dest\" [arrowhead=empty]; ");
    }

    #[test]
    fn to_dot_graph_handles_gossip_node_record_refs() {
        let source = make_node_record(1234, true, false);
        let mut db = db_from_node(&source);
        let dest = make_node_record(2345, false, false);
        db.add_node(&dest).unwrap();
        let gossip = GossipBuilder::empty();
        let source_gnr = GossipNodeRecord::from(&db, source.public_key(), true);
        let dest_gnr = GossipNodeRecord::from(&db, dest.public_key(), true);

        let result = gossip.to_dot_graph(&source_gnr, &dest_gnr);

        assert_eq! (String::from ("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_db_public_key_pairs() {
        let source = make_node_record(1234, true, false);
        let mut db = db_from_node(&source);
        let dest = make_node_record(2345, false, false);
        db.add_node(&dest).unwrap();
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph((&db, source.public_key()), (&db, dest.public_key()));

        assert_eq! (String::from ("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_public_key_node_addr_opt_pairs() {
        let source = make_node_record(1234, true, false);
        let dest = make_node_record(2345, false, false);
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(
            (source.public_key(), &source.node_addr_opt()),
            (dest.public_key(), &dest.node_addr_opt()),
        );

        assert_eq! (String::from ("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_public_key_refs() {
        let source = make_node_record(1234, true, false);
        let dest = make_node_record(2345, false, false);
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(source.public_key(), dest.public_key());

        assert_eq! (String::from ("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\nUnknown\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_ip_addrs() {
        let source = IpAddr::from_str("1.2.3.4").unwrap();
        let dest = IpAddr::from_str("2.3.4.5").unwrap();
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(source, dest);

        assert_eq! (String::from ("digraph db { \"src\" [label=\"Gossip From:\\n\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\n\\n2.3.4.5\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }
}
