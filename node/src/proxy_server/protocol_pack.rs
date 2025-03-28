// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::tls_protocol_pack::TlsProtocolPack;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::proxy_server::ProxyProtocol;
use masq_lib::constants::{HTTP_PORT, TLS_PORT};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub port: u16,
}

impl Host {
    pub fn new(name: &str, port: u16) -> Host {
        Host { name: name.to_string(), port }
    }
}

pub trait ProtocolPack: Send + Sync {
    fn proxy_protocol(&self) -> ProxyProtocol;
    fn standard_port(&self) -> u16;
    fn find_host(&self, data: &PlainData) -> Option<Host>;
    fn server_impersonator(&self) -> Box<dyn ServerImpersonator>;
}

pub fn from_protocol(protocol: ProxyProtocol) -> Box<dyn ProtocolPack> {
    match protocol {
        ProxyProtocol::HTTP => Box::new(HttpProtocolPack {}),
        ProxyProtocol::TLS => Box::new(TlsProtocolPack {}),
    }
}

pub fn from_standard_port(standard_port: u16) -> Option<Box<dyn ProtocolPack>> {
    match standard_port {
        HTTP_PORT => Some(Box::new(HttpProtocolPack {})),
        TLS_PORT => Some(Box::new(TlsProtocolPack {})),
        _ => None,
    }
}

pub fn from_ibcd(ibcd: &InboundClientData) -> Result<Box<dyn ProtocolPack>, String> {
    let origin_port = match ibcd.reception_port {
        None => {
            return Err(format!(
                "No origin port specified with {}-byte non-clandestine packet: {:?}",
                ibcd.data.len(),
                ibcd.data
            ))
        }
        Some(origin_port) => origin_port,
    };
    match from_standard_port(origin_port) {
        Some(pp) => Ok(pp),
        None => Err(format!(
            "No protocol associated with origin port {} for {}-byte non-clandestine packet: {:?}",
            origin_port,
            ibcd.data.len(),
            &ibcd.data
        )),
    }
}

pub trait ServerImpersonator {
    fn route_query_failure_response(&self, server_name: &str) -> Vec<u8>;
    fn dns_resolution_failure_response(&self, server_name_opt: Option<String>) -> Vec<u8>;
    fn consuming_wallet_absent(&self) -> Vec<u8>;
}
