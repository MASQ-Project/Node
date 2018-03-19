// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::net::SocketAddr;
use actix::ResponseType;
use hopper::IncipientCoresPackage;
use hopper::ExpiredCoresPackage;
use dispatcher::OutboundClientData;
use proxy_server::ProxyServerSubs;
use dispatcher::DispatcherFacadeSubs;
use hopper::HopperSubs;
use proxy_client::ProxyClientSubs;
use dispatcher::TransmitterHandle;
use stream_handler_pool::StreamHandlerPoolSubs;

// TODO where should each of these messages live?

// ----- BindMessage -----
#[derive(Clone)]
pub struct PeerActors {
    pub proxy_server: ProxyServerSubs,
    pub dispatcher: DispatcherFacadeSubs,
    pub hopper: HopperSubs,
    pub proxy_client: ProxyClientSubs,
//    pub neighborhood: NeighborhoodSubs,
    pub stream_handler_pool: StreamHandlerPoolSubs,
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

// ----- RequestMessage ----- (Dispatcher -> ProxyServer)
#[derive(Debug, Clone)]
pub struct RequestMessage {
    pub data: OutboundClientData, // should be InboundClientData
}

impl ResponseType for RequestMessage {
    type Item = ();
    type Error = ();
}

// ----- ResponseMessage ----- (ProxyServer -> Dispatcher)
#[derive(Debug)]
pub struct ResponseMessage {
    pub socket_addr: SocketAddr,
    pub data: Vec<u8>,
}

impl ResponseType for ResponseMessage {
    type Item = ();
    type Error = ();
}

// ----- IncipientCoresPackageMessage ----- (HopperClient -> Hopper)
#[derive(Debug)]
pub struct IncipientCoresPackageMessage {
    pub pkg: IncipientCoresPackage,
}

impl ResponseType for IncipientCoresPackageMessage {
    type Item = ();
    type Error = ();
}


// ----- ExpiredCoresPackageMessage ----- (Hopper -> HopperClient)
#[derive (Debug)]
pub struct ExpiredCoresPackageMessage {
    pub pkg: ExpiredCoresPackage
}

impl ResponseType for ExpiredCoresPackageMessage {
    type Item = ();
    type Error = ();
}

// ----- TemporaryBindMessage ----- (Dispatcher -> DispatcherFacade)
pub struct TemporaryBindMessage {
    pub transmitter_handle: Box<TransmitterHandle>
}

impl ResponseType for TemporaryBindMessage {
    type Item = ();
    type Error = ();
}

impl Debug for TemporaryBindMessage {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write! (f, "TemporaryBindMessage")
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use actix::System;
    use test_utils::make_peer_actors;
    use test_utils::TransmitterHandleMock;

    #[test]
    fn peer_actors_debug () {
        let _ = System::new ("test");
        let subject = make_peer_actors ();

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("PeerActors"))
    }

    #[test]
    fn temporary_bind_message_debug () {
        let subject = TemporaryBindMessage {
            transmitter_handle: Box::new (TransmitterHandleMock::new ())
        };

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("TemporaryBindMessage"));
    }
}