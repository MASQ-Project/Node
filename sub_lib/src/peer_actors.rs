// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::AccountantSubs;
use crate::dispatcher::DispatcherSubs;
use crate::hopper::HopperSubs;
use crate::neighborhood::NeighborhoodSubs;
use crate::proxy_client::ProxyClientSubs;
use crate::proxy_server::ProxyServerSubs;
use crate::ui_gateway::UiGatewaySubs;
use actix::Message;
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
    pub accountant: AccountantSubs,
    pub ui_gateway: UiGatewaySubs,
}

impl Debug for PeerActors {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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
