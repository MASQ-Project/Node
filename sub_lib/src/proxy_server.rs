// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use actix::Subscriber;
use cryptde::Key;
use cryptde::PlainData;
use dispatcher::InboundClientData;
use hopper::ExpiredCoresPackage;
use peer_actors::BindMessage;
use cryptde::StreamKey;

#[derive (Copy, Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum ProxyProtocol {
    HTTP,
    TLS
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientRequestPayload {
    pub stream_key: StreamKey,
    pub data: PlainData,
    pub target_hostname: Option<String>,
    pub target_port: u16,
    pub protocol: ProxyProtocol,
    pub originator_public_key: Key
}

#[derive(Clone)]
pub struct ProxyServerSubs { // ProxyServer will handle these messages:
    pub bind: Box<Subscriber<BindMessage> + Send>,
    pub from_dispatcher: Box<Subscriber<InboundClientData> + Send>,
    pub from_hopper: Box<Subscriber<ExpiredCoresPackage> + Send>,
}
