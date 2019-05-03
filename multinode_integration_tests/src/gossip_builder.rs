// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::substratum_node::SubstratumNode;
use node_lib::neighborhood::gossip::Gossip;
use node_lib::neighborhood::gossip::GossipNodeRecord;
use node_lib::neighborhood::node_record::NodeRecordInner;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::cryptde::{CryptDE, PlainData};
use node_lib::sub_lib::cryptde_null::CryptDENull;
use node_lib::sub_lib::dispatcher::Component;
use node_lib::sub_lib::hopper::IncipientCoresPackage;
use node_lib::sub_lib::node_addr::NodeAddr;
use node_lib::sub_lib::route::Route;
use node_lib::sub_lib::route::RouteSegment;
use node_lib::sub_lib::wallet::Wallet;
use std::collections::btree_set::BTreeSet;
use std::convert::TryFrom;

pub struct GossipBuilder {
    consuming_wallet: Option<Wallet>,
    node_info: Vec<GossipBuilderNodeInfo>,
}

impl GossipBuilder {
    pub fn new(consuming_wallet: Option<Wallet>) -> GossipBuilder {
        GossipBuilder {
            consuming_wallet,
            node_info: vec![],
        }
    }

    pub fn add_node(
        mut self,
        node: &dyn SubstratumNode,
        is_bootstrap: bool,
        include_ip: bool,
    ) -> Self {
        self.node_info.push(GossipBuilderNodeInfo {
            node_record_inner: NodeRecordInner {
                public_key: node.public_key().clone(),
                is_bootstrap_node: is_bootstrap,
                earning_wallet: node.earning_wallet().clone(),
                rate_pack: node.rate_pack().clone(),
                neighbors: BTreeSet::new(),
                version: 0,
            },
            node_addr_opt: match include_ip {
                true => Some(node.node_addr()),
                false => None,
            },
            cryptde: Box::new(CryptDENull::from(&node.public_key())),
        });
        self
    }

    pub fn add_gnr(mut self, gnr: &GossipNodeRecord) -> Self {
        let inner = NodeRecordInner::try_from(gnr).unwrap();
        let public_key = inner.public_key.clone();
        self.node_info.push(GossipBuilderNodeInfo {
            node_record_inner: inner,
            node_addr_opt: gnr.node_addr_opt.clone(),
            cryptde: Box::new(CryptDENull::from(&public_key)),
        });
        self
    }

    pub fn add_fictional_node(mut self, node_record: NodeRecordInner) -> Self {
        let key = node_record.public_key.clone();
        self.node_info.push(GossipBuilderNodeInfo {
            node_record_inner: node_record,
            node_addr_opt: None,
            cryptde: Box::new(CryptDENull::from(&key)),
        });
        self
    }

    pub fn add_half_connection(mut self, from_key: &PublicKey, to_key: &PublicKey) -> Self {
        let ni = match self.node_info.iter_mut().find (|ni| &ni.node_record_inner.public_key == from_key) {
            Some (ni) => ni,
            None => panic! ("You directed that {:?} should be made a neighbor of {:?}, but {:?} has not yet been added to the GossipBuilder", to_key, from_key, from_key),
        };
        ni.node_record_inner.neighbors.insert(to_key.clone());
        self
    }

    pub fn build(self) -> Gossip {
        let node_records: Vec<GossipNodeRecord> = self
            .node_info
            .into_iter()
            .map(|node_info| {
                let signed_data =
                    PlainData::from(serde_cbor::ser::to_vec(&node_info.node_record_inner).unwrap());
                let signature = node_info.cryptde.sign(&signed_data).unwrap();
                GossipNodeRecord {
                    signed_data,
                    signature,
                    node_addr_opt: node_info.node_addr_opt,
                }
            })
            .collect();
        Gossip { node_records }
    }

    pub fn build_cores_package(self, from: &PublicKey, to: &PublicKey) -> IncipientCoresPackage {
        let consuming_wallet = self.consuming_wallet.clone();
        let gossip = self.build();
        IncipientCoresPackage::new(
            &CryptDENull::new(),
            Route::one_way(
                RouteSegment::new(vec![from, to], Component::Neighborhood),
                &CryptDENull::from(from),
                consuming_wallet,
            )
            .unwrap(),
            gossip.into(),
            to,
        )
        .unwrap()
    }
}

struct GossipBuilderNodeInfo {
    node_record_inner: NodeRecordInner,
    node_addr_opt: Option<NodeAddr>,
    cryptde: Box<dyn CryptDE>,
}
