// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use cryptde::Key;
use dispatcher::InboundClientData;
use hopper::ExpiredCoresPackage;
use peer_actors::BindMessage;
use stream_key::StreamKey;
use sequence_buffer::SequencedPacket;

#[derive (Copy, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ProxyProtocol {
    HTTP,
    TLS
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientRequestPayload {
    pub stream_key: StreamKey,
    pub last_data: bool,
    pub sequenced_packet: SequencedPacket,
    pub target_hostname: Option<String>,
    pub target_port: u16,
    pub protocol: ProxyProtocol,
    pub originator_public_key: Key
}

#[derive(Clone)]
pub struct ProxyServerSubs { // ProxyServer will handle these messages:
    pub bind: Recipient<Syn, BindMessage>,
    pub from_dispatcher: Recipient<Syn, InboundClientData>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackage>,
}
