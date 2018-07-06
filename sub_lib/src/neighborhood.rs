// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Message;
use actix::Recipient;
use actix::Syn;
use cryptde::Key;
use node_addr::NodeAddr;
use peer_actors::BindMessage;
use std::net::IpAddr;
use route::Route;
use hopper::ExpiredCoresPackage;

#[derive (Clone)]
pub struct NeighborhoodConfig {
    pub neighbor_configs: Vec<(Key, NodeAddr)>,
    pub bootstrap_configs: Vec<(Key, NodeAddr)>,
    pub is_bootstrap_node: bool,
    pub local_ip_addr: IpAddr,
    pub clandestine_port_list: Vec<u16>,
}

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub node_query: Recipient<Syn, NodeQueryMessage>,
    pub route_query: Recipient<Syn, RouteQueryMessage>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackage>
}

#[derive (Clone, Debug, PartialEq)]
pub struct NodeDescriptor {
    pub public_key: Key,
    pub node_addr_opt: Option<NodeAddr>,
}

impl NodeDescriptor {
    pub fn new (public_key: Key, node_addr_opt: Option<NodeAddr>) -> NodeDescriptor {
        NodeDescriptor {
            public_key, node_addr_opt
        }
    }
}

#[derive (Message)]
pub struct BootstrapNeighborhoodNowMessage {}

pub enum NodeQueryMessage {
    IpAddress (IpAddr),
    PublicKey (Key),
}

impl Message for NodeQueryMessage {
    type Result = Option<NodeDescriptor>;
}

pub struct RouteQueryMessage {
    pub minimum_hop_count: usize
}

impl Message for RouteQueryMessage {
    type Result = Option<Route>;
}
