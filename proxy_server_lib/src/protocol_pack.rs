// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::cryptde::PlainData;
use sub_lib::proxy_server::ProxyProtocol;

pub trait ProtocolPack: Send + Sync {
    fn proxy_protocol(&self) -> ProxyProtocol;
    fn find_host_name(&self, data: &PlainData) -> Option<String>;
}
