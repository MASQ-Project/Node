// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::node_record::NodeRecord;
use super::node_record::NodeRecordInner;
use crate::neighborhood::dot_graph::{
    render_dot_graph, DotRenderable, EdgeRenderable, NodeRenderable,
};
use crate::neighborhood::neighborhood_database::NeighborhoodDatabase;
use crate::neighborhood::AccessibleGossipRecord;
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData, PublicKey};
use crate::sub_lib::data_version::DataVersion;
use crate::sub_lib::hopper::MessageType;
use crate::sub_lib::node_addr::NodeAddr;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::iter::FromIterator;
use std::net::IpAddr;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipNodeRecord {
    pub signed_data: PlainData,
    pub signature: CryptData,
    pub node_addr_opt: Option<NodeAddr>, // Only for use in introductions
}

impl Debug for GossipNodeRecord {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.write_str(self.to_human_readable().as_str())
    }
}

impl From<(&NeighborhoodDatabase, &PublicKey, bool)> for GossipNodeRecord {
    fn from(triple: (&NeighborhoodDatabase, &PublicKey, bool)) -> Self {
        let (database, public_key_ref, reveal_node_addr) = triple;
        // crashpoint
        let node_record_ref = database
            .node_by_key(public_key_ref)
            .expect("Attempted to create Gossip around nonexistent Node");
        let mut gnr = GossipNodeRecord::from(node_record_ref.clone());
        if !reveal_node_addr {
            gnr.node_addr_opt = None
        }
        gnr
    }
}

impl From<(NodeRecordInner, Option<NodeAddr>, &dyn CryptDE)> for GossipNodeRecord {
    fn from(triple: (NodeRecordInner, Option<NodeAddr>, &dyn CryptDE)) -> Self {
        let (inner, node_addr_opt, cryptde) = triple;
        let signed_data =
            PlainData::from(serde_cbor::ser::to_vec(&inner).expect("Serialization failed"));
        let signature = cryptde.sign(&signed_data).expect("Signing failed");
        GossipNodeRecord {
            signed_data,
            signature,
            node_addr_opt,
        }
    }
}

impl From<AccessibleGossipRecord> for GossipNodeRecord {
    fn from(agr: AccessibleGossipRecord) -> Self {
        GossipNodeRecord {
            signed_data: agr.signed_gossip,
            signature: agr.signature,
            node_addr_opt: agr.node_addr_opt,
        }
    }
}

impl From<NodeRecord> for GossipNodeRecord {
    fn from(node_record: NodeRecord) -> Self {
        GossipNodeRecord {
            signed_data: node_record.signed_gossip,
            signature: node_record.signature,
            node_addr_opt: node_record.metadata.node_addr_opt,
        }
    }
}

impl GossipNodeRecord {
    // TODO - should we use a json serializer to make this?
    fn to_human_readable(&self) -> String {
        let mut human_readable = String::new();
        human_readable.push_str("\nGossipNodeRecord {");
        match NodeRecordInner::try_from(self) {
            Ok(nri) => {
                human_readable.push_str("\n\tinner: NodeRecordInner {");
                human_readable.push_str(&format!("\n\t\tpublic_key: {:?},", &nri.public_key));
                human_readable.push_str(&format!("\n\t\tnode_addr_opt: {:?},", self.node_addr_opt));
                human_readable
                    .push_str(&format!("\n\t\tearning_wallet: {:?},", nri.earning_wallet));
                human_readable.push_str(&format!("\n\t\trate_pack: {:?},", nri.rate_pack));
                human_readable.push_str(&format!(
                    "\n\t\tneighbors: {:?},",
                    Vec::from_iter(nri.neighbors.clone().into_iter())
                ));
                human_readable.push_str(&format!("\n\t\tversion: {:?},", nri.version));
                human_readable.push_str("\n\t},");
            }
            Err(_e) => human_readable.push_str("\n\tinner: <non-deserializable>"),
        };
        human_readable.push_str(&format!("\n\tnode_addr_opt: {:?},", self.node_addr_opt));
        human_readable.push_str(&format!("\n\tsigned_data: {:?},", self.signed_data));
        human_readable.push_str(&format!("\n\tsignature: {:?},", self.signature));
        human_readable.push_str("\n}");
        human_readable
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub version: DataVersion,
    pub node_records: Vec<GossipNodeRecord>,
}

impl Into<MessageType> for Gossip {
    fn into(self) -> MessageType {
        MessageType::Gossip(self)
    }
}

impl TryInto<Vec<AccessibleGossipRecord>> for Gossip {
    type Error = String;

    fn try_into(self) -> Result<Vec<AccessibleGossipRecord>, Self::Error> {
        let results: Vec<Result<AccessibleGossipRecord, String>> = self
            .node_records
            .into_iter()
            .map(AccessibleGossipRecord::try_from)
            .collect();
        if let Some(Err(msg)) = results.iter().find(|result| result.is_err()) {
            return Err(msg.clone());
        }
        Ok(results
            .into_iter()
            .map(|result| result.expect("Success suddenly turned bad"))
            .collect())
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
        match AccessibleGossipRecord::try_from(input.clone()) {
            Ok(agr) => DotGossipEndpoint::from(&agr),
            Err(_) => DotGossipEndpoint {
                public_key: PublicKey::new(&[]),
                node_addr_opt: None,
            },
        }
    }
}

impl From<&AccessibleGossipRecord> for DotGossipEndpoint {
    fn from(agr: &AccessibleGossipRecord) -> Self {
        DotGossipEndpoint {
            public_key: agr.inner.public_key.clone(),
            node_addr_opt: agr.node_addr_opt.clone(),
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

// Produces incomplete representation
impl From<&PublicKey> for DotGossipEndpoint {
    fn from(input: &PublicKey) -> Self {
        DotGossipEndpoint {
            public_key: input.clone(),
            node_addr_opt: None,
        }
    }
}

// Produces incomplete representation
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
    pub fn version() -> DataVersion {
        DataVersion::new(0, 0).expect("Internal Error")
    }

    pub fn new(node_records: Vec<GossipNodeRecord>) -> Self {
        Self {
            version: Self::version(),
            node_records,
        }
    }

    // Pass in:
    //   &NodeRecord, or
    //   &GossipNodeRecord, or
    //   &AccessibleGossipRecord, or
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

    fn to_dot_renderables<S, T>(
        &self,
        source_into: S,
        target_into: T,
    ) -> Vec<Box<dyn DotRenderable>>
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
        let inners_and_addrs: Vec<(NodeRecordInner, Option<NodeAddr>)> = self
            .node_records
            .iter()
            .map(|gnr| {
                let nri = match NodeRecordInner::try_from(gnr) {
                    Ok(nri) => nri,
                    Err(_e) => unimplemented!(),
                };
                (nri, gnr.node_addr_opt.clone())
            })
            .collect();
        inners_and_addrs.iter().for_each(|(nri, addr)| {
            present.insert(nri.public_key.clone());
            nri.neighbors.iter().for_each(|k| {
                mentioned.insert(k.clone());
                edge_renderables.push(EdgeRenderable {
                    from: nri.public_key.clone(),
                    to: k.clone(),
                })
            });
            node_renderables.push(NodeRenderable {
                version: Some(nri.version),
                public_key: nri.public_key.clone(),
                node_addr: addr.clone(),
                known_source: nri.public_key == source.public_key,
                known_target: nri.public_key == target.public_key,
                is_present: true,
            });
        });
        mentioned.difference(&present).for_each(|k| {
            node_renderables.push(NodeRenderable {
                version: None,
                public_key: k.clone(),
                node_addr: None,
                known_source: false,
                known_target: false,
                is_present: false,
            })
        });
        let mut result: Vec<Box<dyn DotRenderable>> = vec![];
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
            gossip: Gossip::new(vec![]),
            keys_so_far: HashSet::new(),
        }
    }

    pub fn empty() -> Gossip {
        Gossip::new(vec![])
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
                let mut gnr = GossipNodeRecord::from(node_record_ref.clone());
                if !reveal_node_addr {
                    gnr.node_addr_opt = None
                }
                self.gossip.node_records.push(gnr);
                self.keys_so_far
                    .insert(node_record_ref.public_key().clone());
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
    use crate::test_utils::{assert_string_contains, vec_to_btset};
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "GossipBuilder cannot add a Node more than once")]
    fn adding_node_twice_to_gossip_builder_causes_panic() {
        let node = make_node_record(1234, true);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db).node(node.public_key(), true);

        builder.node(node.public_key(), true);
    }

    #[test]
    fn adding_node_with_addr_and_reveal_results_in_node_with_addr() {
        let node = make_node_record(1234, true);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), true);

        let mut gossip = builder.build();
        assert_eq!(
            gossip.node_records.remove(0).node_addr_opt.unwrap(),
            node.node_addr_opt().unwrap()
        )
    }

    #[test]
    fn adding_node_with_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, true);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).node_addr_opt, None)
    }

    #[test]
    fn adding_node_with_no_addr_and_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false);
        let mut db = db_from_node(&node);
        let gossip_node = &db.add_node(make_node_record(2345, false)).unwrap();
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(gossip_node, true);

        let mut gossip = builder.build();
        assert_eq!(None, gossip.node_records.remove(0).node_addr_opt)
    }

    #[test]
    fn adding_node_with_no_addr_and_no_reveal_results_in_node_with_no_addr() {
        let node = make_node_record(1234, false);
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), false);

        let mut gossip = builder.build();
        assert_eq!(gossip.node_records.remove(0).node_addr_opt, None)
    }

    #[test]
    fn gossip_node_record_keeps_all_half_neighbors() {
        let mut this_node = make_node_record(1234, true);
        let full_neighbor_one = make_node_record(2345, true);
        let full_neighbor_two = make_node_record(3456, true);
        let full_neighbor_three = make_node_record(4567, true);
        let half_neighbor = make_node_record(5678, true);
        let db = {
            let mut db = db_from_node(&this_node);
            let this_node_key = db.root().public_key().clone();
            db.add_node(full_neighbor_one.clone()).unwrap();
            db.add_node(full_neighbor_two.clone()).unwrap();
            db.add_node(full_neighbor_three.clone()).unwrap();
            db.add_node(half_neighbor.clone()).unwrap();
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_one.public_key());
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_two.public_key());
            db.add_arbitrary_full_neighbor(&this_node_key, full_neighbor_three.public_key());
            db.add_arbitrary_half_neighbor(&this_node_key, half_neighbor.public_key());
            db
        };
        this_node.signature = db.root().signature().clone();

        let result = GossipNodeRecord::from((&db, db.root().public_key(), true));

        let result = AccessibleGossipRecord::try_from(result).unwrap();
        assert_eq!(this_node.public_key(), &result.inner.public_key);
        assert_eq!(this_node.node_addr_opt(), result.node_addr_opt);
        assert_eq!(
            vec_to_btset(vec![
                full_neighbor_one.public_key().clone(),
                full_neighbor_two.public_key().clone(),
                half_neighbor.public_key().clone(),
                full_neighbor_three.public_key().clone(),
            ]),
            result.inner.neighbors
        );
        assert_eq!(this_node.rate_pack(), &result.inner.rate_pack);
        assert_eq!(this_node.earning_wallet(), result.inner.earning_wallet);
        assert_eq!(this_node.version(), result.inner.version);
        assert_eq!(this_node.signature, result.signature);
    }

    #[test]
    fn gossip_into_vec_of_agrs_when_gossip_is_corrupt() {
        let one_node = make_node_record(1234, true);
        let another_node = make_node_record(2345, true);
        let mut db = db_from_node(&one_node);
        db.add_node(another_node.clone()).unwrap();
        let mut gossip = GossipBuilder::new(&mut db)
            .node(one_node.public_key(), true)
            .node(another_node.public_key(), false)
            .build();
        gossip.node_records[1].signed_data = PlainData::new(&[1, 2, 3, 4]);

        let result: Result<Vec<AccessibleGossipRecord>, String> = gossip.try_into();

        assert_eq!(
            Err(String::from(
                "invalid type: integer `1`, expected struct NodeRecordInner"
            )),
            result
        );
    }

    #[test]
    fn gossip_node_record_is_debug_formatted_to_be_human_readable() {
        let node = make_node_record(1234, true);
        let mut db = db_from_node(&node);
        db.root_mut().increment_version();
        db.root_mut().increment_version();
        db.root_mut().resign();
        let gossip = GossipNodeRecord::from((&db, node.public_key(), true));

        let result = format!("{:?}", gossip);
        let expected = format!(
            "\nGossipNodeRecord {{{}{}{}{}\n}}",
            "\n\tinner: NodeRecordInner {\n\t\tpublic_key: AQIDBA,\n\t\tnode_addr_opt: Some(1.2.3.4:[1234]),\n\t\tearning_wallet: Wallet { kind: Address(0x546900db8d6e0937497133d1ae6fdf5f4b75bcd0) },\n\t\trate_pack: RatePack { routing_byte_rate: 1235, routing_service_rate: 1236, exit_byte_rate: 1237, exit_service_rate: 1238 },\n\t\tneighbors: [],\n\t\tversion: 2,\n\t},",
            "\n\tnode_addr_opt: Some(1.2.3.4:[1234]),",
            "\n\tsigned_data: PlainData { data: [166, 108, 100, 97, 116, 97, 95, 118, 101, 114, 115, 105, 111, 110, 131, 0, 0, 0, 106, 112, 117, 98, 108, 105, 99, 95, 107, 101, 121, 68, 1, 2, 3, 4, 110, 101, 97, 114, 110, 105, 110, 103, 95, 119, 97, 108, 108, 101, 116, 161, 103, 97, 100, 100, 114, 101, 115, 115, 148, 24, 84, 24, 105, 0, 24, 219, 24, 141, 24, 110, 9, 24, 55, 24, 73, 24, 113, 24, 51, 24, 209, 24, 174, 24, 111, 24, 223, 24, 95, 24, 75, 24, 117, 24, 188, 24, 208, 105, 114, 97, 116, 101, 95, 112, 97, 99, 107, 164, 113, 114, 111, 117, 116, 105, 110, 103, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 211, 116, 114, 111, 117, 116, 105, 110, 103, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 4, 212, 110, 101, 120, 105, 116, 95, 98, 121, 116, 101, 95, 114, 97, 116, 101, 25, 4, 213, 113, 101, 120, 105, 116, 95, 115, 101, 114, 118, 105, 99, 101, 95, 114, 97, 116, 101, 25, 4, 214, 105, 110, 101, 105, 103, 104, 98, 111, 114, 115, 128, 103, 118, 101, 114, 115, 105, 111, 110, 2] },",
            "\n\tsignature: CryptData { data: [1, 2, 3, 4, 13, 203, 98, 91, 91, 124, 75, 12, 242, 126, 76, 106, 236, 12, 26, 1, 199, 218, 114, 177] },"
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn gossip_node_record_that_is_non_deserializable_is_human_readabled_properly() {
        let gnr = GossipNodeRecord {
            signed_data: PlainData::new(&[1, 2, 3, 4]),
            signature: CryptData::new(&[4, 3, 2, 1]),
            node_addr_opt: None,
        };

        let result = format!("{:?}", gnr);

        let expected = format!(
            "\nGossipNodeRecord {{{}{}{}{}\n}}",
            "\n\tinner: <non-deserializable>",
            "\n\tnode_addr_opt: None,",
            "\n\tsigned_data: PlainData { data: [1, 2, 3, 4] },",
            "\n\tsignature: CryptData { data: [4, 3, 2, 1] },"
        );

        assert_eq!(expected, result);
    }

    #[test]
    fn to_dot_graph_returns_gossip_in_dotgraph_format() {
        let mut source_node = make_node_record(1234, true);
        source_node.inner.public_key = PublicKey::new(&b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"[..]);
        let mut target_node = make_node_record(2345, true);
        target_node.inner.public_key = PublicKey::new(&b"ZYXWVUTSRQPONMLKJIHGFEDCBA"[..]);
        let neighbor = make_node_record(3456, false);
        let mut db = db_from_node(&source_node);
        db.add_node(target_node.clone()).unwrap();
        db.add_node(neighbor.clone()).unwrap();
        db.add_arbitrary_full_neighbor(target_node.public_key(), source_node.public_key());
        db.add_arbitrary_full_neighbor(target_node.public_key(), neighbor.public_key());
        db.add_arbitrary_full_neighbor(source_node.public_key(), neighbor.public_key());
        let nonexistent_node = make_node_record(4567, false);
        db.add_arbitrary_half_neighbor(neighbor.public_key(), nonexistent_node.public_key());
        db.root_mut().increment_version();
        db.root_mut().resign();
        let neighbor_gnr = GossipNodeRecord::from((&db, neighbor.public_key(), true));

        let gossip = Gossip {
            version: Gossip::version(),
            node_records: vec![
                GossipNodeRecord::from((&db, db.root().public_key(), true)),
                GossipNodeRecord::from((&db, target_node.public_key(), true)),
                neighbor_gnr,
            ],
        };

        let result = gossip.to_dot_graph(&source_node, &target_node);

        assert_string_contains(&result, "digraph db { ");
        assert_string_contains(&result, "\"AwQFBg\" [label=\"v0\\nAwQFBg\"]; ");
        assert_string_contains(
            &result,
            "\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\" [label=\"v1\\nQUJDREVG\\n1.2.3.4:1234\"] [style=filled]; ",
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
        assert_string_contains(
            &result,
            "\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\" -> \"WllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkE\"; ",
        );
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
        let source = make_node_record(1234, true);
        let mut db = db_from_node(&source);
        let dest = make_node_record(2345, false);
        db.add_node(dest.clone()).unwrap();
        let gossip = GossipBuilder::empty();
        let source_gnr = GossipNodeRecord::from((&db, source.public_key(), true));
        let dest_gnr = GossipNodeRecord::from((&db, dest.public_key(), true));

        let result = gossip.to_dot_graph(&source_gnr, &dest_gnr);

        assert_eq!(String::from("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_db_public_key_pairs() {
        let source = make_node_record(1234, true);
        let mut db = db_from_node(&source);
        let dest = make_node_record(2345, false);
        db.add_node(dest.clone()).unwrap();
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph((&db, source.public_key()), (&db, dest.public_key()));

        assert_eq!(String::from("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_public_key_node_addr_opt_pairs() {
        let source = make_node_record(1234, true);
        let dest = make_node_record(2345, false);
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(
            (source.public_key(), &source.node_addr_opt()),
            (dest.public_key(), &dest.node_addr_opt()),
        );

        assert_eq!(String::from("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_public_key_refs() {
        let source = make_node_record(1234, true);
        let dest = make_node_record(2345, false);
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(source.public_key(), dest.public_key());

        assert_eq!(String::from("digraph db { \"src\" [label=\"Gossip From:\\nAQIDBA\\nUnknown\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\nUnknown\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }

    #[test]
    fn to_dot_graph_handles_ip_addrs() {
        let source = IpAddr::from_str("1.2.3.4").unwrap();
        let dest = IpAddr::from_str("2.3.4.5").unwrap();
        let gossip = GossipBuilder::empty();

        let result = gossip.to_dot_graph(source, dest);

        assert_eq!(String::from("digraph db { \"src\" [label=\"Gossip From:\\n\\n1.2.3.4\"]; \"dest\" [label=\"Gossip To:\\n\\n2.3.4.5\"]; \"src\" -> \"dest\" [arrowhead=empty]; }"), result)
    }
}
