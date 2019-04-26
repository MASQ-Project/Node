// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::tls_protocol_pack::TlsProtocolPack;
use crate::sub_lib::cryptde::{PlainData, PublicKey};
use crate::sub_lib::proxy_server::ProxyProtocol;

#[derive(Clone, Debug, PartialEq)]
pub struct Host {
    pub name: String,
    pub port: Option<u16>,
}

pub trait ProtocolPack: Send + Sync {
    fn proxy_protocol(&self) -> ProxyProtocol;
    fn standard_port(&self) -> u16;
    fn find_host(&self, data: &PlainData) -> Option<Host>;
    fn server_impersonator(&self) -> Box<ServerImpersonator>;
}

pub fn for_protocol(protocol: ProxyProtocol) -> Box<ProtocolPack> {
    match protocol {
        ProxyProtocol::HTTP => Box::new(HttpProtocolPack {}),
        ProxyProtocol::TLS => Box::new(TlsProtocolPack {}),
    }
}

pub fn for_standard_port(_standard_port: u16) -> Option<Box<ProtocolPack>> {
    match _standard_port {
        80 => Some(Box::new(HttpProtocolPack {})),
        443 => Some(Box::new(TlsProtocolPack {})),
        _ => None,
    }
}

pub trait ServerImpersonator {
    fn route_query_failure_response(&self, server_name: &str) -> Vec<u8>;
    fn dns_resolution_failure_response(
        &self,
        exit_key: &PublicKey,
        server_name_opt: Option<String>,
    ) -> Vec<u8>;
}
