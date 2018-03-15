// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
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