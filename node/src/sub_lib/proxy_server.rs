// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::hopper::ExpiredCoresPackage;
use crate::sub_lib::neighborhood::ExpectedService;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use actix::Message;
use actix::Recipient;
use serde_derive::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ProxyProtocol {
    HTTP,
    TLS,
}

// TODO: Based on the way it's used, this struct should comprise two elements: one, a nested
// struct that contains all the small, quickly-cloned things, and the other the big,
// expensively-cloned SequencedPacket.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientRequestPayload {
    pub stream_key: StreamKey,
    pub sequenced_packet: SequencedPacket,
    pub target_hostname: Option<String>,
    pub target_port: u16,
    pub protocol: ProxyProtocol,
    pub originator_public_key: PublicKey,
}

#[derive(Message)]
pub struct AddReturnRouteMessage {
    pub return_route_id: u32,
    pub expected_services: Vec<ExpectedService>,
}

#[derive(Clone)]
pub struct ProxyServerSubs {
    // ProxyServer will handle these messages:
    pub bind: Recipient<BindMessage>,
    pub from_dispatcher: Recipient<InboundClientData>,
    pub from_hopper: Recipient<ExpiredCoresPackage>,
    pub add_return_route: Recipient<AddReturnRouteMessage>,
}
