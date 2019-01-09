// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use dispatcher::DispatcherSubs;
use hopper::HopperSubs;
use neighborhood::NeighborhoodSubs;
use proxy_client::ProxyClientSubs;
use proxy_server::ProxyServerSubs;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;

#[derive(Clone)]
pub struct PeerActors {
    pub proxy_server: ProxyServerSubs,
    pub dispatcher: DispatcherSubs,
    pub hopper: HopperSubs,
    pub proxy_client: ProxyClientSubs,
    pub neighborhood: NeighborhoodSubs,
}

impl Debug for PeerActors {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PeerActors")
    }
}

#[derive(Debug, Message, Clone)]
pub struct BindMessage {
    pub peer_actors: PeerActors,
}

#[cfg(test)]
mod tests {
    use actix::System;
    use test_utils::recorder::make_peer_actors;

    #[test]
    fn peer_actors_debug() {
        let _ = System::new("test");
        let subject = make_peer_actors();

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PeerActors"))
    }

}
