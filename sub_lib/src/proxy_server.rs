// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use std::net::SocketAddr;
use cryptde::Key;
use cryptde::PlainData;
use actor_messages::RequestMessage;
use actor_messages::BindMessage;
use actor_messages::ExpiredCoresPackageMessage;
use actix::Subscriber;

// TODO: Put a field in here that identifies the protocol of this request so that the Proxy Client
// TODO: can create the correct response Framer for it...unless we want to deduce it from the target_port.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientRequestPayload {
    pub stream_key: SocketAddr,
    pub data: PlainData,
    pub target_hostname: String,
    pub target_port: u16,
    pub originator_public_key: Key
}

#[derive(Clone)]
pub struct ProxyServerSubs { // ProxyServer will handle these messages:
    pub bind: Box<Subscriber<BindMessage> + Send>,
    pub from_dispatcher: Box<Subscriber<RequestMessage> + Send>,
    pub from_hopper: Box<Subscriber<ExpiredCoresPackageMessage> + Send>,
    // pub from_neighborhood: Box<Subscriber<RouteResponseMessage> + Send>,
}
