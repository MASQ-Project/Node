// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::protocols::utils::ParseError;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

pub mod igdp;
pub mod pcp;
mod pcp_pmp_common;
pub mod pmp;

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapError {
    NoLocalIpAddress,
    IPv6Unsupported(Ipv6Addr),
    FindRouterError(String),
    GetPublicIpError(String),
    SocketBindingError(String),
    SocketPrepError(String),
    SocketSendError(String),
    SocketReceiveError(String),
    PacketParseError(ParseError),
    ProtocolError(String),
    AddMappingError(String),
    DeleteMappingError(String),
    TransactionFailure(String),
}

pub trait Transactor {
    fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError>;
    fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError>;
    fn add_mapping(
        &self,
        router_ip: IpAddr,
        hole_port: u16,
        lifetime: u32,
    ) -> Result<u32, AutomapError>;
    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError>;
}

pub trait LocalIpFinder {
    fn find(&self) -> Result<IpAddr, AutomapError>;
}

pub struct LocalIpFinderReal {}

impl LocalIpFinder for LocalIpFinderReal {
    fn find(&self) -> Result<IpAddr, AutomapError> {
        match local_ipaddress::get() {
            Some(ip_str) => Ok(IpAddr::from_str(&ip_str).unwrap_or_else(|_| {
                panic!("Invalid IP address from local_ipaddress::get: '{}'", ip_str)
            })),
            None => Err(AutomapError::NoLocalIpAddress),
        }
    }
}

impl Default for LocalIpFinderReal {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalIpFinderReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    pub struct LocalIpFinderMock {
        find_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
    }

    impl LocalIpFinder for LocalIpFinderMock {
        fn find(&self) -> Result<IpAddr, AutomapError> {
            self.find_results.borrow_mut().remove(0)
        }
    }

    impl LocalIpFinderMock {
        pub fn new() -> Self {
            Self {
                find_results: RefCell::new(vec![]),
            }
        }

        pub fn find_result(self, result: Result<IpAddr, AutomapError>) -> Self {
            self.find_results.borrow_mut().push(result);
            self
        }
    }
}
