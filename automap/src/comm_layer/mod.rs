// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

use crossbeam_channel::Sender;
use socket2::{Domain, SockAddr, Socket, Type};
use masq_lib::utils::AutomapProtocol;

use crate::comm_layer::pcp_pmp_common::MappingConfig;
use crate::control_layer::automap_control::ChangeHandler;
use crate::protocols::utils::ParseError;

pub mod igdp;
pub mod pcp;
pub mod pcp_pmp_common;
pub mod pmp;

pub const DEFAULT_MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapErrorCause {
    UserError,
    NetworkConfiguration,
    ProtocolNotImplemented,
    ProtocolFailed,
    ProbeServerIssue,
    ProbeFailed,
    SocketFailure,
    RouterFailure,
    Unknown(String),
}

#[derive(Clone, PartialEq, Debug)]
pub enum AutomapError {
    Unknown,
    NoLocalIpAddress,
    CantFindDefaultGateway,
    IPv6Unsupported(Ipv6Addr),
    FindRouterError(String),
    GetPublicIpError(String),
    SocketBindingError(String, SocketAddr),
    SocketSendError(AutomapErrorCause),
    SocketReceiveError(AutomapErrorCause),
    PacketParseError(ParseError),
    ProtocolError(String),
    PermanentLeasesOnly,
    TemporaryMappingError(String),
    PermanentMappingError(String),
    ProbeServerConnectError(String),
    ProbeRequestError(AutomapErrorCause, String),
    ProbeReceiveError(String),
    DeleteMappingError(String),
    TransactionFailure(String),
    AllProtocolsFailed(Vec<(AutomapProtocol, AutomapError)>),
    HousekeeperAlreadyRunning,
    HousekeeperCrashed,
}

impl AutomapError {
    pub fn cause(&self) -> AutomapErrorCause {
        match self {
            AutomapError::Unknown => AutomapErrorCause::Unknown("Explicitly unknown".to_string()),
            AutomapError::NoLocalIpAddress => AutomapErrorCause::NetworkConfiguration,
            AutomapError::CantFindDefaultGateway => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::IPv6Unsupported(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::FindRouterError(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::GetPublicIpError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::SocketBindingError(_, _) => AutomapErrorCause::UserError,
            AutomapError::SocketSendError(aec) => aec.clone(),
            AutomapError::SocketReceiveError(aec) => aec.clone(),
            AutomapError::PacketParseError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::ProtocolError(_) => AutomapErrorCause::ProtocolNotImplemented,
            AutomapError::PermanentLeasesOnly => {
                AutomapErrorCause::Unknown("Can't handle permanent-only leases".to_string())
            }
            AutomapError::PermanentMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::TemporaryMappingError(_) => AutomapErrorCause::RouterFailure,
            AutomapError::ProbeServerConnectError(_) => AutomapErrorCause::ProbeServerIssue,
            AutomapError::ProbeRequestError(aec, _) => aec.clone(),
            AutomapError::ProbeReceiveError(_) => AutomapErrorCause::ProbeFailed,
            AutomapError::DeleteMappingError(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::TransactionFailure(_) => AutomapErrorCause::ProtocolFailed,
            AutomapError::AllProtocolsFailed(_) => AutomapErrorCause::NetworkConfiguration,
            AutomapError::HousekeeperAlreadyRunning => {
                AutomapErrorCause::Unknown("Sequencing error".to_string())
            }
            AutomapError::HousekeeperCrashed => {
                AutomapErrorCause::Unknown("Thread crash".to_string())
            }
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

#[derive(Clone, Copy, PartialEq, Debug)]
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

const ROUTER_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new (224, 0, 0, 1);

fn create_polite_multicast_socket(interface_and_port: SocketAddr) -> Result<UdpSocket, std::io::Error> {
    let (interface_v4, port) = match interface_and_port {
        SocketAddr::V4(socket_addr_v4) => (socket_addr_v4.ip().clone(), socket_addr_v4.port()),
        SocketAddr::V6(_) => unimplemented!("IPv6 is not yet supported for multicast"),
    };
    //creates new UDP socket on ipv4 address
    let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
    //linux/macos have reuse_port exposed so we can flag it for non-windows systems
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    //windows has reuse_port hidden and implicitly flagged with reuse_address
    socket.set_reuse_address(true)?;
    //subscribes to multicast group on the interface
    socket.join_multicast_v4(&ROUTER_MULTICAST_GROUP, &interface_v4)?;
    //binds to the multicast interface and port
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            IpAddr::from(interface_v4),
            port,
        )))?;
    //converts socket2 socket into a std::net socket, required for correct recv_from method
    Ok (socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes_work() {
        let errors_and_expectations = vec![
            (
                AutomapError::Unknown,
                AutomapErrorCause::Unknown("Explicitly unknown".to_string()),
            ),
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
                AutomapError::FindRouterError(String::new()),
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
                AutomapError::PermanentMappingError(String::new()),
                AutomapErrorCause::ProtocolFailed,
            ),
            (
                AutomapError::TemporaryMappingError(String::new()),
                AutomapErrorCause::RouterFailure,
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
            (
                AutomapError::AllProtocolsFailed(vec![]),
                AutomapErrorCause::NetworkConfiguration,
            ),
            (
                AutomapError::HousekeeperAlreadyRunning,
                AutomapErrorCause::Unknown("Sequencing error".to_string()),
            ),
        ];

        let errors_and_actuals = errors_and_expectations
            .iter()
            .map(|(error, _)| (error.clone(), error.cause()))
            .collect::<Vec<(AutomapError, AutomapErrorCause)>>();

        assert_eq!(errors_and_actuals, errors_and_expectations);
    }
}
