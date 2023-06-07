// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crossbeam_channel::Sender;

use masq_lib::utils::AutomapProtocol;

use crate::comm_layer::pcp_pmp_common::MappingConfig;
use crate::control_layer::automap_control::ChangeHandler;
use crate::protocols::utils::ParseError;

pub mod igdp;
pub mod pcp;
pub mod pcp_pmp_common;
pub mod pmp;

pub const DEFAULT_MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AutomapErrorCause {
    NetworkConfiguration,
    ProbeServerIssue,
    ProtocolFailed,
    ProtocolNotImplemented,
    ProbeFailed,
    RouterFailure,
    SocketFailure,
    Unknown(String),
    UserError,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AutomapError {
    AllProtocolsFailed(Vec<(AutomapProtocol, AutomapError)>),
    CantFindDefaultGateway,
    DeleteMappingError(String),
    FindRouterError(String),
    GetPublicIpError(String),
    HousekeeperAlreadyRunning,
    HousekeeperCrashed,
    IPv6Unsupported(Ipv6Addr),
    NoLocalIpAddress,
    PacketParseError(ParseError),
    PermanentLeasesOnly,
    PermanentMappingError(String),
    ProbeReceiveError(String),
    ProbeRequestError(AutomapErrorCause, String),
    ProbeServerConnectError(String),
    ProtocolError(String),
    SocketBindingError(String, SocketAddr),
    SocketReceiveError(AutomapErrorCause),
    SocketSendError(AutomapErrorCause),
    TemporaryMappingError(String),
    TransactionFailure(String),
    Unknown,
}

impl AutomapError {
    pub fn cause(&self) -> AutomapErrorCause {
        match self {
            AutomapError::AllProtocolsFailed(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::CantFindDefaultGateway => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::DeleteMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::FindRouterError(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::GetPublicIpError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::HousekeeperAlreadyRunning => {
                AutomapErrorCause::Unknown("Sequencing error".to_string())
            }
            AutomapError::HousekeeperCrashed => {
                AutomapErrorCause::Unknown("Thread crash".to_string())
            }
            AutomapError::IPv6Unsupported(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::NoLocalIpAddress => AutomapErrorCause::NetworkConfiguration,
            AutomapError::SocketBindingError(_, _) => AutomapErrorCause::UserError,
            AutomapError::SocketReceiveError(aec) => aec.clone(),
            AutomapError::SocketSendError(aec) => aec.clone(),
            AutomapError::PacketParseError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::PermanentLeasesOnly => {
                AutomapErrorCause::Unknown("Can't handle permanent-only leases".to_string())
            }
            AutomapError::PermanentMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::ProbeReceiveError(_) => AutomapErrorCause::ProbeFailed,
            AutomapError::ProbeRequestError(aec, _) => aec.clone(),
            AutomapError::ProbeServerConnectError(_) => AutomapErrorCause::ProbeServerIssue,
            AutomapError::ProtocolError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::TemporaryMappingError(_) => AutomapErrorCause::RouterFailure,
            AutomapError::TransactionFailure(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::Unknown => AutomapErrorCause::Unknown("Explicitly unknown".to_string()),
        }
    }

    pub fn should_crash(&self) -> bool {
        match self {
            AutomapError::AllProtocolsFailed(_) => true,
            AutomapError::CantFindDefaultGateway => true,
            AutomapError::DeleteMappingError(_) => false,
            AutomapError::FindRouterError(_) => true,
            AutomapError::GetPublicIpError(_) => true,
            AutomapError::HousekeeperAlreadyRunning => false,
            AutomapError::HousekeeperCrashed => false,
            AutomapError::IPv6Unsupported(_) => true,
            AutomapError::NoLocalIpAddress => true,
            AutomapError::PacketParseError(_) => true,
            AutomapError::PermanentLeasesOnly => false,
            AutomapError::PermanentMappingError(_) => true,
            AutomapError::ProbeReceiveError(_) => true,
            AutomapError::ProbeRequestError(_, _) => true,
            AutomapError::ProbeServerConnectError(_) => true,
            AutomapError::ProtocolError(_) => true,
            AutomapError::SocketBindingError(_, _) => true,
            AutomapError::SocketReceiveError(_) => true,
            AutomapError::SocketSendError(_) => true,
            AutomapError::TemporaryMappingError(_) => false,
            AutomapError::TransactionFailure(_) => true,
            AutomapError::Unknown => true,
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
    fn protocol(&self) -> AutomapProtocol;
    fn start_housekeeping_thread(
        &mut self,
        change_handler: ChangeHandler,
        router_ip: IpAddr,
    ) -> Result<Sender<HousekeepingThreadCommand>, AutomapError>;
    fn stop_housekeeping_thread(&mut self) -> Result<ChangeHandler, AutomapError>;
    fn as_any(&self) -> &dyn Any;
}

impl Debug for dyn Transactor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} Transactor", self.protocol())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HousekeepingThreadCommand {
    Stop,
    SetRemapIntervalMs(u64),
    InitializeMappingConfig(MappingConfig),
}

pub trait LocalIpFinder: Send {
    fn find(&self) -> Result<IpAddr, AutomapError>;
}

#[derive(Clone)]
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

    #[test]
    fn causes_work() {
        let errors_and_expectations = vec![
            (
                AutomapError::AllProtocolsFailed(vec![]),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::CantFindDefaultGateway,
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::DeleteMappingError(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::FindRouterError(String::new()),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::GetPublicIpError(String::new()),
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::HousekeeperAlreadyRunning,
                AutomapErrorCause::Unknown("Sequencing error".to_string()),
            ),
            (
                AutomapError::IPv6Unsupported(Ipv6Addr::from_str("::").unwrap()),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::NoLocalIpAddress,
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::PacketParseError(ParseError::WrongVersion(3)),
                AutomapErrorCause::ProtocolNotImplemented,
            ),
            (
                AutomapError::PermanentLeasesOnly,
                AutomapErrorCause::Unknown("Can't handle permanent-only leases".to_string()),
            ),
            (
                AutomapError::PermanentMappingError(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::ProbeReceiveError(String::new()),
                AutomapErrorCause::ProbeFailed,
            ),
            (
                AutomapError::ProbeRequestError(AutomapErrorCause::ProbeFailed, String::new()),
                AutomapErrorCause::ProbeFailed,
            ),
            (
                AutomapError::ProbeServerConnectError(String::new()),
                AutomapErrorCause::ProbeServerIssue,
            ),
            (
                AutomapError::ProtocolError(String::new()),
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
                AutomapError::SocketReceiveError(AutomapErrorCause::Unknown("Booga".to_string())),
                AutomapErrorCause::Unknown("Booga".to_string()),
            ),
            (
                AutomapError::SocketSendError(AutomapErrorCause::Unknown("Booga".to_string())),
                AutomapErrorCause::Unknown("Booga".to_string()),
            ),
            (
                AutomapError::TemporaryMappingError(String::new()),
                AutomapErrorCause::RouterFailure,
            ),
            (
                AutomapError::TransactionFailure(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::Unknown,
                AutomapErrorCause::Unknown("Explicitly unknown".to_string()),
            ),
        ];

        let errors_and_actuals = errors_and_expectations
            .iter()
            .map(|(error, _)| (error.clone(), error.cause()))
            .collect::<Vec<(AutomapError, AutomapErrorCause)>>();

        assert_eq!(errors_and_actuals, errors_and_expectations);
    }

    #[test]
    fn should_crash_works() {
        vec![
            (AutomapError::AllProtocolsFailed(vec![]), true),
            (AutomapError::CantFindDefaultGateway, true),
            (AutomapError::DeleteMappingError("".to_string()), false),
            (AutomapError::FindRouterError("".to_string()), true),
            (AutomapError::GetPublicIpError("".to_string()), true),
            (AutomapError::HousekeeperAlreadyRunning, false),
            (AutomapError::HousekeeperCrashed, false),
            (AutomapError::IPv6Unsupported(Ipv6Addr::UNSPECIFIED), true),
            (AutomapError::NoLocalIpAddress, true),
            (
                AutomapError::PacketParseError(ParseError::WrongVersion(0)),
                true,
            ),
            (AutomapError::PermanentLeasesOnly, false),
            (AutomapError::PermanentMappingError("".to_string()), true),
            (AutomapError::ProbeServerConnectError("".to_string()), true),
            (AutomapError::ProbeReceiveError("".to_string()), true),
            (
                AutomapError::ProbeRequestError(AutomapErrorCause::ProbeFailed, "".to_string()),
                true,
            ),
            (AutomapError::ProtocolError("".to_string()), true),
            (
                AutomapError::SocketBindingError(
                    "".to_string(),
                    SocketAddr::from_str("0.0.0.0:0").unwrap(),
                ),
                true,
            ),
            (
                AutomapError::SocketReceiveError(AutomapErrorCause::Unknown("".to_string())),
                true,
            ),
            (
                AutomapError::SocketSendError(AutomapErrorCause::Unknown("".to_string())),
                true,
            ),
            (AutomapError::TemporaryMappingError("".to_string()), false),
            (AutomapError::TransactionFailure("".to_string()), true),
            (AutomapError::Unknown, true),
        ]
        .into_iter()
        .for_each(|(error, should_crash)| {
            assert_eq!(
                error.should_crash(),
                should_crash,
                "{:?}.should_crash should be {}, but was {}",
                error,
                should_crash,
                !should_crash
            )
        })
    }
}
