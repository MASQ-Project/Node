// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;
use sub_lib::dispatcher::Component;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::cryptde::Key;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::peer_actors::BindMessage;
use sub_lib::cryptde::CryptDE;

pub struct Neighborhood {
}

impl Actor for Neighborhood {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        ()
    }
}

impl Neighborhood {
    pub fn new(cryptde: Box<CryptDE>, config: Vec<(Key, NodeAddr)>) -> Self {
        Neighborhood {}
    }

    pub fn make_subs_from(addr: &Addr<Syn, Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone ().recipient::<BindMessage>(),
        }
    }

    // TODO: Turn these into actor messages
    // crashpoint - unused so far
    fn route_one_way(&self, _remote_recipient: Component) -> Result<(Route, Key), ()> {
        unimplemented!()
    }

    // crashpoint - unused so far
    fn route_round_trip(&self, _remote_recipient: Component, _local_recipient: Component) -> Result<(Route, Key), ()> {
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

    #[test]
    fn nothing () {

    }
}