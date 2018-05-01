// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use sub_lib::dispatcher::Component;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::neighborhood::NeighborhoodError;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::cryptde::Key;

pub struct NeighborhoodReal {
}

impl NeighborhoodReal {
    pub fn new() -> Self {
        NeighborhoodReal {}
    }
}

impl Neighborhood for NeighborhoodReal {
    // crashpoint - unused so far
    fn route_one_way(&self, _remote_recipient: Component) -> Result<(Route, Key), NeighborhoodError> {
        unimplemented!()
    }

    // crashpoint - unused so far
    fn route_round_trip(&self, _remote_recipient: Component, _local_recipient: Component) -> Result<(Route, Key), NeighborhoodError> {
        unimplemented!()
    }

    // crashpoint - unused so far
    fn public_key_from_ip_address(&self, _ip_addr: &IpAddr) -> Option<Key> {
        unimplemented!()
    }

    // crashpoint - unused so far
    fn node_addr_from_public_key(&self, _public_key: &[u8]) -> Option<NodeAddr> {
        unimplemented!()
    }

    // crashpoint - unused so far
    fn node_addr_from_ip_address (&self, _ip_addr: &IpAddr) -> Option<NodeAddr> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}