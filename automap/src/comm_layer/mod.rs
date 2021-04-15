// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::protocols::utils::ParseError;
use crate::control_layer::automap_control::AutomapChange;
use masq_lib::utils::AutomapProtocol;

pub mod igdp;
pub mod pcp;
mod pcp_pmp_common;
pub mod pmp;

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapErrorCause {
    UserError,
    NetworkConfiguration,
    ProtocolNotImplemented,
    ProtocolFailed,
    ProbeServerIssue,
    ProbeFailed,
    Unknown(String),
}

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapError {
    NoLocalIpAddress,
    CantFindDefaultGateway,
    IPv6Unsupported(Ipv6Addr),
    FindRouterError(String, AutomapErrorCause),
    GetPublicIpError(String),
    SocketBindingError(String, SocketAddr),
    SocketSendError(AutomapErrorCause),
    SocketReceiveError(AutomapErrorCause),
    PacketParseError(ParseError),
    ProtocolError(String),
    PermanentLeasesOnly,
    AddMappingError(String),
    ProbeServerConnectError(String),
    ProbeRequestError(AutomapErrorCause, String),
    ProbeReceiveError(String),
    DeleteMappingError(String),
    TransactionFailure(String),
    AllProtocolsFailed,
    AllRoutersFailed(AutomapProtocol),
}

impl AutomapError {
    pub fn cause(&self) -> AutomapErrorCause {
        match self {
            AutomapError::NoLocalIpAddress => AutomapErrorCause::NetworkConfiguration,
            AutomapError::CantFindDefaultGateway => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::IPv6Unsupported(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::FindRouterError(_, aec) => aec.clone(),
            AutomapError::GetPublicIpError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::SocketBindingError(_, _) => AutomapErrorCause::UserError,
            AutomapError::SocketSendError(aec) => aec.clone(),
            AutomapError::SocketReceiveError(aec) => aec.clone(),
            AutomapError::PacketParseError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::ProtocolError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::PermanentLeasesOnly => {
                AutomapErrorCause::Unknown("Can't handle permanent-only leases".to_string())
            }
            AutomapError::AddMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::ProbeServerConnectError(_) => AutomapErrorCause::ProbeServerIssue,
            AutomapError::ProbeRequestError(aec, _) => aec.clone(),
            AutomapError::ProbeReceiveError(_) => AutomapErrorCause::ProbeFailed,
            AutomapError::DeleteMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::TransactionFailure(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::AllProtocolsFailed => todo!(),
            AutomapError::AllRoutersFailed(_) => todo!(),
        }
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
    fn add_permanent_mapping(&self, router_ip: IpAddr, hole_port: u16)
        -> Result<u32, AutomapError>;
    fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError>;
    fn method(&self) -> AutomapProtocol;
    fn set_change_handler(&mut self, change_handler: Box<dyn FnMut(AutomapChange) -> ()>);
    fn as_any(&self) -> &dyn Any;
}

impl Debug for dyn Transactor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} Transactor", self.method())
    }
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

    #[test]
    fn causes_work() {
        let errors_and_expectations = vec![
            (
                AutomapError::NoLocalIpAddress,
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::CantFindDefaultGateway,
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::IPv6Unsupported(Ipv6Addr::from_str("::").unwrap()),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::FindRouterError(
                    String::new(),
                    AutomapErrorCause::NetworkConfiguration,
                ),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::GetPublicIpError(String::new()),
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::SocketBindingError(
                    String::new(),
                    SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                ),
                AutomapErrorCause::UserError,
            ),
            (
                AutomapError::SocketSendError(AutomapErrorCause::Unknown("Booga".to_string())),
                AutomapErrorCause::Unknown("Booga".to_string()),
            ),
            (
                AutomapError::SocketReceiveError(AutomapErrorCause::Unknown("Booga".to_string())),
                AutomapErrorCause::Unknown("Booga".to_string()),
            ),
            (
                AutomapError::PacketParseError(ParseError::WrongVersion(3)),
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::ProtocolError(String::new()),
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::PermanentLeasesOnly,
                AutomapErrorCause::Unknown("Can't handle permanent-only leases".to_string()),
            ),
            (
                AutomapError::AddMappingError(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::ProbeServerConnectError(String::new()),
                AutomapErrorCause::ProbeServerIssue,
            ),
            (
                AutomapError::ProbeRequestError(AutomapErrorCause::ProbeFailed, String::new()),
                AutomapErrorCause::ProbeFailed,
            ),
            (
                AutomapError::ProbeReceiveError(String::new()),
                AutomapErrorCause::ProbeFailed,
            ),
            (
                AutomapError::DeleteMappingError(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::TransactionFailure(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
        ];

        let errors_and_actuals = errors_and_expectations
            .iter()
            .map(|(error, _)| (error.clone(), error.cause()))
            .collect::<Vec<(AutomapError, AutomapErrorCause)>>();

        assert_eq!(errors_and_actuals, errors_and_expectations);
    }
}
