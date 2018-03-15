// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use cryptde::PlainData;
use std::marker::Send;
use actix::Subscriber;
use actor_messages::BindMessage;
use actor_messages::ExpiredCoresPackageMessage;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub stream_key: SocketAddr,
    pub data: PlainData
}

#[derive(Clone)]
pub struct ProxyClientSubs {
    pub bind: Box<Subscriber<BindMessage> + Send>,
    pub from_hopper: Box<Subscriber<ExpiredCoresPackageMessage> + Send>,
}
