// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Message;
use actix::Recipient;
use actix::Syn;
use cryptde::Key;
use node_addr::NodeAddr;
use peer_actors::BindMessage;
use std::net::IpAddr;

#[derive(Clone)]
pub struct NeighborhoodSubs {
    pub bind: Recipient<Syn, BindMessage>,
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

pub enum NodeQueryMessage {
    IpAddress (IpAddr),
    PublicKey (Key),
}

impl Message for NodeQueryMessage {
    type Result = Option<NodeDescriptor>;
}
