// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use dispatcher::Component;
use node_addr::NodeAddr;
use route::Route;
use cryptde::Key;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborhoodError {
    InvalidPublicKey,
    NoRouteAvailable,
}

pub trait Neighborhood: Send{
    fn route_one_way (&self, remote_recipient: Component) -> Result<(Route, Key), NeighborhoodError>;
    fn route_round_trip (&self, remote_recipient: Component, local_recipient: Component) -> Result<(Route, Key), NeighborhoodError>;
    fn public_key_from_ip_address(&self, ip_addr: &IpAddr) -> Option<Key>;
    fn node_addr_from_public_key(&self, public_key: &[u8]) -> Option<NodeAddr>;
    fn node_addr_from_ip_address(&self, ip_addr: &IpAddr) -> Option<NodeAddr>;
}
