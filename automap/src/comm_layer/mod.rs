// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Display, Formatter};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::protocols::utils::ParseError;

pub mod igdp;
pub mod pcp;
mod pcp_pmp_common;
pub mod pmp;

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapErrorCause {
    NetworkConfiguration,
    ProtocolNotImplemented,
    ProtocolFailed,
    Unknown,
}

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapError {
    NoLocalIpAddress,
    CantFindDefaultGateway,
    IPv6Unsupported(Ipv6Addr),
    FindRouterError(String),
    GetPublicIpError(String),
    SocketBindingError(String, SocketAddr),
    SocketPrepError(String),
    SocketSendError(String),
    SocketReceiveError(String),
    PacketParseError(ParseError),
    ProtocolError(String),
    AddMappingError(String),
    DeleteMappingError(String),
    TransactionFailure(String),
    OSCommandError(String),
}

impl AutomapError {
    pub fn cause(&self) -> AutomapErrorCause {
        unimplemented!()
    }
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
    fn method(&self) -> Method;
    fn as_any(&self) -> &dyn Any;
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
    use std::cell::RefCell;

    use super::*;

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

#[derive(PartialEq, Debug)]
pub enum Method {
    Pmp,
    Pcp,
    Igdp,
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Method::Pmp => write!(f, "PMP protocol"),
            Method::Pcp => write!(f, "PCP protocol"),
            Method::Igdp => write!(f, "IGDP protocol"),
        }
    }
}
