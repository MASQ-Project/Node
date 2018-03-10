// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use std::marker::Send;
use dispatcher::DispatcherClient;
use hopper::HopperClient;
use cryptde::PlainData;

pub trait ProxyClient: DispatcherClient + HopperClient {}

pub trait ProxyServerDispatcherClient: ProxyClient {}

impl<T: ProxyClient + DispatcherClient + Send> ProxyServerDispatcherClient for T {}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientResponsePayload {
    pub stream_key: SocketAddr,
    pub data: PlainData
}
