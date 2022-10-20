// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;

use crossbeam_channel::Sender;
use masq_lib::utils::AutomapProtocol;
use socket2::{Domain, SockAddr, Type};

use crate::comm_layer::pcp_pmp_common::MappingConfig;
use crate::control_layer::automap_control::ChangeHandler;
use crate::protocols::utils::ParseError;

pub mod igdp;
pub mod pcp;
pub mod pcp_pmp_common;
pub mod pmp;

//TEMPORARY
pub mod multicast_spike;
//TEMPORARY

pub const DEFAULT_MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive(Clone, PartialEq, Eq, Debug)]
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
    MulticastBindingError(String, MulticastInfo),
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
            AutomapError::MulticastBindingError(_, _) => todo!(),
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

// TODO: Don't merge like this
#[allow(dead_code)]
const ROUTER_MULTICAST_GROUP: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastInfo {
    pub interface: IpAddr,
    pub multicast_group: u8,
    pub port: u16,
}

impl Default for MulticastInfo {
    fn default() -> Self {
        MulticastInfo::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, 5350)
    }
}

impl MulticastInfo {
    pub fn new(interface: IpAddr, multicast_group: u8, port: u16) -> Self {
        Self {
            interface,
            multicast_group,
            port,
        }
    }

    pub fn multicast_group_address(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, self.multicast_group))
    }

    pub fn multicast_addr(&self) -> SocketAddr {
        SocketAddr::new(self.multicast_group_address(), self.port)
    }

    pub fn create_polite_socket(&self) -> Result<UdpSocket, std::io::Error> {
        //creates new UDP socket on ipv4 address
        let socket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
        //linux/macos have reuse_port exposed so we can call it for non-windows systems
        //windows has reuse_port hidden and implicitly flagged with reuse_address
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        let interface_v4 = match self.interface {
            IpAddr::V4(ipv4addr) => ipv4addr,
            IpAddr::V6(_) => unimplemented!("IPv6 is not yet supported for router announcements"),
        };
        let multicast_group_address_v4 = match self.multicast_group_address() {
            IpAddr::V4(ipv4addr) => ipv4addr,
            IpAddr::V6(_) => unimplemented!("IPv6 is not yet supported for router announcements"),
        };
        //subscribes to multicast group on the interface
        socket.join_multicast_v4(&multicast_group_address_v4, &interface_v4)?;
        //binds to the multicast interface and port
        socket.bind(&SockAddr::from(SocketAddr::new(self.interface, self.port)))?;
        //converts socket2 socket into a std::net socket, required for correct recv_from method
        Ok(socket.into())
    }
}

#[cfg(test)]
use masq_lib::utils::find_free_port;
#[cfg(test)]
impl MulticastInfo {
    pub fn for_test(multicast_group: u8) -> Self {
        Self::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            multicast_group,
            find_free_port(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_info_creates_socket_addr() {
        let subject = MulticastInfo::new(IpAddr::from_str("1.2.3.4").unwrap(), 5, 6);

        let result = subject.multicast_addr();

        assert_eq!(
            result,
            SocketAddr::new(IpAddr::from_str("224.0.0.5").unwrap(), 6)
        );
    }

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
