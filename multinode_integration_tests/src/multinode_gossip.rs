// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::substratum_node::SubstratumNode;
use node_lib::neighborhood::gossip::{Gossip, GossipNodeRecord};
use node_lib::neighborhood::neighborhood::AccessibleGossipRecord;
use node_lib::neighborhood::node_record::NodeRecordInner;
use node_lib::sub_lib::cryptde::CryptData;
use node_lib::sub_lib::cryptde::PlainData;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::wallet::Wallet;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};

pub enum GossipType {
    DebutGossip(SingleNode),
    PassGossip(SingleNode),
    IntroductionGossip(Introduction),
    StandardGossip(Standard),
    Unrecognized,
}

pub fn parse_gossip(gossip: &Gossip, sender: IpAddr) -> GossipType {
    let agrs = gossip
        .node_records
        .iter()
        .map(|gnr| AccessibleGossipRecord::try_from(gnr.clone()).unwrap())
        .collect::<Vec<AccessibleGossipRecord>>();
    match agrs.len() {
        0 => GossipType::Unrecognized,
        1 => {
            if agrs[0].node_addr_opt.as_ref().unwrap().ip_addr() == sender {
                GossipType::DebutGossip(SingleNode::from(&agrs[0]))
            } else {
                GossipType::PassGossip(SingleNode::from(&agrs[0]))
            }
        }
        2 => {
            if agrs[0].node_addr_opt.as_ref().unwrap().ip_addr() == sender {
                GossipType::IntroductionGossip(Introduction::from((&agrs[0], &agrs[1])))
            } else if agrs[1].node_addr_opt.as_ref().unwrap().ip_addr() == sender {
                GossipType::IntroductionGossip(Introduction::from((&agrs[1], &agrs[0])))
            } else {
                GossipType::Unrecognized
            }
        }
        _ => GossipType::StandardGossip(Standard::from(&agrs)),
    }
}

pub trait MultinodeGossip {
    fn nodes_of_degree(&self, degree: usize) -> Vec<PublicKey>;
    fn gnr(&self, key: &PublicKey) -> Option<GossipNodeRecord>;
    fn agr(&self, key: &PublicKey) -> Option<AccessibleGossipRecord>;
    fn agr_mut(&mut self, key: &PublicKey) -> Option<&mut AccessibleGossipRecord>;
    fn render(&self) -> Gossip;
}

pub struct SingleNode {
    node: AccessibleGossipRecord,
}

impl MultinodeGossip for SingleNode {
    fn nodes_of_degree(&self, degree: usize) -> Vec<PublicKey> {
        nodes_of_degree(&vec![self.node.clone()], degree)
    }

    fn gnr(&self, key: &PublicKey) -> Option<GossipNodeRecord> {
        if key != &self.node.inner.public_key {
            None
        } else {
            Some(GossipNodeRecord::from(self.node.clone()))
        }
    }

    fn agr(&self, key: &PublicKey) -> Option<AccessibleGossipRecord> {
        if key != &self.node.inner.public_key {
            None
        } else {
            Some(self.node.clone())
        }
    }

    fn agr_mut(&mut self, key: &PublicKey) -> Option<&mut AccessibleGossipRecord> {
        if key != &self.node.inner.public_key {
            None
        } else {
            Some(&mut self.node)
        }
    }

    fn render(&self) -> Gossip {
        Gossip {
            node_records: vec![GossipNodeRecord::from(self.node.clone())],
        }
    }
}

impl From<&AccessibleGossipRecord> for SingleNode {
    fn from(agr: &AccessibleGossipRecord) -> Self {
        SingleNode { node: agr.clone() }
    }
}

impl SingleNode {
    pub fn new(node: &SubstratumNode) -> SingleNode {
        SingleNode {
            node: AccessibleGossipRecord::from(node),
        }
    }
}

pub struct Introduction {
    introducer: AccessibleGossipRecord,
    introducee: AccessibleGossipRecord,
}

impl MultinodeGossip for Introduction {
    fn nodes_of_degree(&self, degree: usize) -> Vec<PublicKey> {
        nodes_of_degree(
            &vec![self.introducer.clone(), self.introducee.clone()],
            degree,
        )
    }

    fn gnr(&self, key: &PublicKey) -> Option<GossipNodeRecord> {
        match self.agr(key) {
            Some(agr) => Some(GossipNodeRecord::from(agr)),
            None => None,
        }
    }

    fn agr(&self, key: &PublicKey) -> Option<AccessibleGossipRecord> {
        if key == &self.introducer.inner.public_key {
            Some(self.introducer.clone())
        } else if key == &self.introducee.inner.public_key {
            Some(self.introducee.clone())
        } else {
            None
        }
    }

    fn agr_mut(&mut self, key: &PublicKey) -> Option<&mut AccessibleGossipRecord> {
        if key == &self.introducer.inner.public_key {
            Some(&mut self.introducee)
        } else if key == &self.introducee.inner.public_key {
            Some(&mut self.introducee)
        } else {
            None
        }
    }

    fn render(&self) -> Gossip {
        Gossip {
            node_records: vec![
                GossipNodeRecord::from(self.introducer.clone()),
                GossipNodeRecord::from(self.introducee.clone()),
            ],
        }
    }
}

impl From<(&AccessibleGossipRecord, &AccessibleGossipRecord)> for Introduction {
    fn from(agrs: (&AccessibleGossipRecord, &AccessibleGossipRecord)) -> Self {
        Introduction {
            introducer: agrs.0.clone(),
            introducee: agrs.1.clone(),
        }
    }
}

impl Introduction {
    pub fn new(introducer: &SubstratumNode, introducee: &SubstratumNode) -> Introduction {
        Introduction {
            introducer: AccessibleGossipRecord::from(introducer),
            introducee: AccessibleGossipRecord::from(introducee),
        }
    }
}

pub struct Standard {
    nodes: Vec<AccessibleGossipRecord>,
}

impl MultinodeGossip for Standard {
    fn nodes_of_degree(&self, degree: usize) -> Vec<PublicKey> {
        nodes_of_degree(&self.nodes, degree)
    }

    fn gnr(&self, key: &PublicKey) -> Option<GossipNodeRecord> {
        let agr = self.agr(key)?;
        Some(GossipNodeRecord::from(agr))
    }

    fn agr(&self, key: &PublicKey) -> Option<AccessibleGossipRecord> {
        match self.nodes.iter().find(|agr| &agr.inner.public_key == key) {
            Some(agr_ref) => Some(agr_ref.clone()),
            None => None,
        }
    }

    fn agr_mut(&mut self, key: &PublicKey) -> Option<&mut AccessibleGossipRecord> {
        match self
            .nodes
            .iter_mut()
            .find(|agr| &agr.inner.public_key == key)
        {
            Some(agr_ref) => Some(agr_ref),
            None => None,
        }
    }

    fn render(&self) -> Gossip {
        Gossip {
            node_records: self
                .nodes
                .iter()
                .map(|agr| GossipNodeRecord::from(agr.clone()))
                .collect(),
        }
    }
}

impl From<&Vec<AccessibleGossipRecord>> for Standard {
    fn from(agrs: &Vec<AccessibleGossipRecord>) -> Self {
        Standard {
            nodes: agrs.clone(),
        }
    }
}

impl Standard {}

pub struct StandardBuilder {
    agrs: Vec<AccessibleGossipRecord>,
}

pub enum GirderNodeDegree {
    Two,
    Three,
    Four,
}

impl StandardBuilder {
    pub fn new() -> StandardBuilder {
        StandardBuilder { agrs: vec![] }
    }

    pub fn linear_neighborhood(
        sender: &SubstratumNode,
        receiver: &PublicKey,
        node_count: usize,
    ) -> StandardBuilder {
        let builder = StandardBuilder::new()
            .add_substratum_node(sender, 1)
            .half_neighbors(sender.public_key(), receiver);
        (1..node_count)
            .into_iter()
            .fold(
                (builder, sender.public_key().clone()),
                |(builder, prev_key), index| {
                    let new_node = fictional_node(index as u8, 1, false);
                    (
                        builder
                            .add_agr(&new_node)
                            .full_neighbors(&new_node.inner.public_key, &prev_key),
                        new_node.inner.public_key.clone(),
                    )
                },
            )
            .0
    }

    pub fn bridge_girder(
        _sender: &SubstratumNode,
        _receiver: &PublicKey,
        _sender_degree: GirderNodeDegree,
        _node_count: usize,
    ) -> StandardBuilder {
        unimplemented!()
    }

    pub fn add_substratum_node(
        self,
        substratum_node: &SubstratumNode,
        version: u32,
    ) -> StandardBuilder {
        let mut agr = AccessibleGossipRecord::from(substratum_node);
        agr.inner.version = version;
        self.add_agr(&agr)
    }

    pub fn add_agr(mut self, agr: &AccessibleGossipRecord) -> StandardBuilder {
        self.agrs.push(agr.clone());
        self
    }

    pub fn half_neighbors(mut self, from: &PublicKey, to: &PublicKey) -> StandardBuilder {
        let agr = self
            .agrs
            .iter_mut()
            .find(|agr| &agr.inner.public_key == from)
            .unwrap();
        agr.inner.neighbors.insert(to.clone());
        self
    }

    pub fn full_neighbors(self, one: &PublicKey, another: &PublicKey) -> StandardBuilder {
        self.half_neighbors(one, another)
            .half_neighbors(another, one)
    }

    pub fn build(self) -> Standard {
        Standard {
            nodes: self
                .agrs
                .into_iter()
                .map(|mut agr| {
                    agr.regenerate_signed_gossip(&CryptDENull::from(&agr.inner.public_key));
                    agr
                })
                .collect(),
        }
    }
}

fn nodes_of_degree(nodes: &Vec<AccessibleGossipRecord>, degree: usize) -> Vec<PublicKey> {
    nodes
        .iter()
        .filter(|node| node.inner.neighbors.len() == degree)
        .map(|node| node.inner.public_key.clone())
        .collect::<Vec<PublicKey>>()
}

fn fictional_node(index: u8, version: u32, expose_node_addr: bool) -> AccessibleGossipRecord {
    let mut bytes: Vec<u8> = vec![];
    for _ in 0..32 {
        bytes.push(index)
    }
    let public_key = PublicKey::new(&bytes);
    let public_key_string = public_key.to_string();
    let earning_wallet = Wallet::new(&format!("E{}", public_key_string));
    let rate_pack = DEFAULT_RATE_PACK.clone();
    let ip_addr = IpAddr::V4(Ipv4Addr::new(172, 200, 18, index));
    let mut agr = AccessibleGossipRecord {
        inner: NodeRecordInner {
            public_key,
            earning_wallet,
            rate_pack,
            neighbors: BTreeSet::new(),
            version,
        },
        node_addr_opt: if expose_node_addr {
            Some(NodeAddr::new(&ip_addr, &vec![10000]))
        } else {
            None
        },
        signed_gossip: PlainData::new(b""),
        signature: CryptData::new(b""),
    };
    agr.regenerate_signed_gossip(&CryptDENull::from(&agr.inner.public_key));
    agr
}

impl From<&SubstratumNode> for AccessibleGossipRecord {
    fn from(substratum_node: &SubstratumNode) -> Self {
        let mut agr = AccessibleGossipRecord {
            inner: NodeRecordInner {
                public_key: substratum_node.public_key().clone(),
                earning_wallet: substratum_node.earning_wallet(),
                rate_pack: substratum_node.rate_pack(),
                neighbors: BTreeSet::new(),
                version: 0,
            },
            node_addr_opt: Some(substratum_node.node_addr()),
            signed_gossip: PlainData::new(b""),
            signature: CryptData::new(b""),
        };
        agr.regenerate_signed_gossip(&CryptDENull::from(&agr.inner.public_key));
        agr
    }
}
