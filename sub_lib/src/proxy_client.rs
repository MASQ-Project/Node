// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use cryptde::PlainData;
use cryptde::StreamKey;
use hopper::ExpiredCoresPackage;
use peer_actors::BindMessage;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub stream_key: StreamKey,
    pub last_response: bool,
    pub data: PlainData
}

#[derive(Clone)]
pub struct ProxyClientSubs {
    pub bind: Recipient<Syn, BindMessage>,
    pub from_hopper: Recipient<Syn, ExpiredCoresPackage>,
}
