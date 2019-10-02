// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::dispatcher::DispatcherSubs;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
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
    pub blockchain_bridge: BlockchainBridgeSubs,
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

#[derive(Message, Clone)]
pub struct StartMessage {}

#[cfg(test)]
mod tests {
    use crate::test_utils::recorder::peer_actors_builder;
    use actix::System;

    #[test]
    fn peer_actors_debug() {
        let _ = System::new("test");
        let subject = peer_actors_builder().build();

        let result = format!("{:?}", subject);

        assert_eq!(result, String::from("PeerActors"))
    }
}
