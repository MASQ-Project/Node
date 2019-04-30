// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

#[macro_use]
pub mod packet_facade; // public only so that it can be used by the integration test
mod dns_socket_server;
mod processing;

use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperReal;
use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;

pub struct DnsSocketServer {
    socket_wrapper: Box<dyn UdpSocketWrapperTrait>,
    buf: Option<[u8; 65536]>,
}

pub fn new_dns_socket_server() -> DnsSocketServer {
    DnsSocketServer {
        socket_wrapper: Box::new(UdpSocketWrapperReal::new()),
        buf: None,
    }
}
