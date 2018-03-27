// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use actix::ResponseType;
use proxy_server::ProxyServerSubs;
use dispatcher::DispatcherSubs;
use hopper::HopperSubs;
use proxy_client::ProxyClientSubs;

#[derive(Clone)]
pub struct PeerActors {
    pub proxy_server: ProxyServerSubs,
    pub dispatcher: DispatcherSubs,
    pub hopper: HopperSubs,
    pub proxy_client: ProxyClientSubs,
//    pub neighborhood: NeighborhoodSubs,
}

impl Debug for PeerActors {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write! (f, "PeerActors")
    }
}

#[derive (Debug)]
pub struct BindMessage {
    pub peer_actors: PeerActors
}

impl ResponseType for BindMessage {
    type Item = ();
    type Error = ();
}

#[cfg (test)]
mod tests {
    use actix::System;
    use test_utils::test_utils::make_peer_actors;

    #[test]
    fn peer_actors_debug () {
        let _ = System::new ("test");
        let subject = make_peer_actors ();

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("PeerActors"))
    }

}
