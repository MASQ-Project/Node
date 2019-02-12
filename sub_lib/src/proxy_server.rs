// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::cryptde::PublicKey;
use crate::dispatcher::InboundClientData;
use crate::hopper::ExpiredCoresPackage;
use crate::peer_actors::BindMessage;
use crate::sequence_buffer::SequencedPacket;
use crate::stream_key::StreamKey;
use actix::Recipient;
use actix::Syn;
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

#[derive(Clone)]
pub struct ProxyServerSubs {
    // ProxyServer will handle these messages:
    pub bind: Recipient<Syn, BindMessage>,
    pub from_dispatcher: Recipient<Syn, InboundClientData>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackage>,
}
