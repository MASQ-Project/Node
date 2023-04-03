// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod finsaas_code;
pub mod linux_specific;
mod macos_specific;
mod windows_specific;

#[cfg(target_os = "linux")]
use crate::comm_layer::pcp_pmp_common::linux_specific::{
    linux_find_routers, LinuxFindRoutersCommand,
};
#[cfg(target_os = "macos")]
use crate::comm_layer::pcp_pmp_common::macos_specific::{
    macos_find_routers, MacOsFindRoutersCommand,
};
#[cfg(target_os = "windows")]
use crate::comm_layer::pcp_pmp_common::windows_specific::{
    windows_find_routers, WindowsFindRoutersCommand,
};
use crate::comm_layer::{AutomapError, LocalIpFinder, LocalIpFinderReal};
use masq_lib::utils::find_free_port;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io;
pub use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;
use crate::mocks::TestMulticastSocketHolder;

pub const ROUTER_PORT: u16 = 5351; // from the PCP and PMP RFCs
pub const ANNOUNCEMENT_PORT: u16 = 5350; // from the PCP and PMP RFCs
pub const ANNOUNCEMENT_MULTICAST_GROUP: u8 = 1;
pub const ANNOUNCEMENT_READ_TIMEOUT_MILLIS: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingConfig {
    pub hole_port: u16,
    pub next_lifetime: Duration,
    pub remap_interval: Duration,
}

impl MappingConfig {
    pub fn next_lifetime_secs(&self) -> u32 {
        self.next_lifetime.as_secs() as u32
    }
}

pub trait UdpSocketWrapper: Send {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn connect(&self, addr: SocketAddr) -> io::Result<()>;
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    fn send(&self, buf: &[u8]) -> io::Result<usize>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()>;
}

pub struct UdpSocketReal {
    delegate: UdpSocket,
}

impl UdpSocketWrapper for UdpSocketReal {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.delegate.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.delegate.peer_addr()
    }

    fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.delegate.connect(addr)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.delegate.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.delegate.send_to(buf, addr)
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.delegate.send(buf)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.delegate.set_read_timeout(dur)
    }

    fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.delegate.leave_multicast_v4(multiaddr, interface)
    }
}

impl UdpSocketReal {
    pub fn new(delegate: UdpSocket) -> Self {
        Self { delegate }
    }
}

pub trait UdpSocketWrapperFactory: Send {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>>;
    fn make_multicast(
        &self,
        multicast_group: u8,
        port: u16,
    ) -> io::Result<Box<dyn UdpSocketWrapper>>;
}

pub struct UdpSocketWrapperFactoryReal {}

impl UdpSocketWrapperFactory for UdpSocketWrapperFactoryReal {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        Ok(Box::new(UdpSocketReal::new(UdpSocket::bind(addr)?)))
    }

    fn make_multicast(
        &self,
        multicast_group: u8,
        port: u16,
    ) -> io::Result<Box<dyn UdpSocketWrapper>> {
        let multicast_interface = Ipv4Addr::UNSPECIFIED;
        let multicast_address = IpAddr::V4(Ipv4Addr::new(224, 0, 0, multicast_group));
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        //Linux/macOS have reuse_port exposed so we can flag it for non-Windows systems
        #[cfg(not(target_os = "windows"))]
        socket.set_reuse_port(true)?;
        //Windows has reuse_port hidden and implicitly flagged with reuse_address
        socket.set_reuse_address(true)?;
        let multicast_ipv4 = match multicast_address {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(addr) => panic!("Multicast IP is IPv6! {}", addr),
        };
        socket.join_multicast_v4(&multicast_ipv4, &multicast_interface)?;
        socket.bind(&SockAddr::from(SocketAddr::new(
            IpAddr::from(multicast_interface),
            port,
        )))?;
        let delegate = UdpSocket::from(socket);
        // delegate.connect(
        //     delegate.local_addr().expect ("Local address suddenly disappeared")
        // )?;
        Ok(Box::new(UdpSocketReal::new(delegate)))
    }
}

impl UdpSocketWrapperFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for UdpSocketWrapperFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

pub trait FreePortFactory: Send {
    fn make(&self) -> u16;
}

pub struct FreePortFactoryReal {}

impl FreePortFactory for FreePortFactoryReal {
    fn make(&self) -> u16 {
        find_free_port()
    }
}

impl FreePortFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for FreePortFactoryReal {
    fn default() -> Self {
        Self::new()
    }
}

pub trait FindRoutersCommand {
    fn execute(&self) -> Result<String, String>;

    // TODO: Consider having the error case be either a String from stderr or an Error object.
    fn execute_command(&self, command: &str) -> Result<String, String> {
        let command_string = command.to_string();
        let words: Vec<&str> = command_string
            .split(' ')
            .filter(|s| !s.is_empty())
            .collect();
        if words.is_empty() {
            return Err("Command is blank".to_string());
        }
        let mut command = &mut Command::new(words[0]);
        for word in &words[1..] {
            command = command.arg(*word)
        }
        match command.output() {
            Ok(output) => match (
                String::from_utf8_lossy(&output.stdout).to_string(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            ) {
                (_, stderr) if !stderr.is_empty() => Err(stderr),
                (stdout, _) => Ok(stdout),
            },
            Err(e) => Err(format!("{:?}", e)),
        }
    }
}

pub fn find_routers() -> Result<Vec<IpAddr>, AutomapError> {
    #[cfg(target_os = "linux")]
    {
        linux_find_routers(&LinuxFindRoutersCommand::new())
    }
    #[cfg(target_os = "windows")]
    {
        windows_find_routers(&WindowsFindRoutersCommand::new())
    }
    #[cfg(target_os = "macos")]
    {
        macos_find_routers(&MacOsFindRoutersCommand::new())
    }
}

pub fn make_local_socket_address(is_ipv4: bool, free_port: u16) -> SocketAddr {
    let ip_addr = if is_ipv4 {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    } else {
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    };
    SocketAddr::new(ip_addr, free_port)
}

pub fn make_announcement_socket(
    factory: &dyn UdpSocketWrapperFactory,
    announcement_multicast_group: u8,
    announcement_port: u16,
) -> Result<Box<dyn UdpSocketWrapper>, AutomapError> {
    let socket_result = factory.make_multicast(
        announcement_multicast_group,
        announcement_port
    );
    let socket = match socket_result {
        Ok(s) => s,
        Err(e) => {
            let multicast = Ipv4Addr::new(224, 0, 0, announcement_multicast_group);
            return Err(AutomapError::SocketBindingError(
                format!("{:?}", e),
                SocketAddr::new(IpAddr::V4(multicast), announcement_port),
            ));
        }
    };
    Ok(socket)
}

pub struct RouterConnections {
    pub holder: TestMulticastSocketHolder,
    pub announcement_port: u16,
    pub router_ip: IpAddr,
    pub router_port: u16,
    pub multicast_address: SocketAddr
}

pub fn make_router_connections() -> RouterConnections {
    let announcement_port = find_free_port();
    let holder = TestMulticastSocketHolder::checkout(announcement_port);
    let router_port = find_free_port();
    let router_ip = LocalIpFinderReal::new().find().unwrap();
    let multicast_address = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, holder.group)),
        announcement_port,
    );
    return RouterConnections {
        holder,
        announcement_port,
        router_ip,
        router_port,
        multicast_address
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use masq_lib::utils::localhost;
    use std::io::ErrorKind;
    use std::net::SocketAddrV4;
    use std::sync::{Arc, Mutex};
    use crate::mocks::UdpSocketWrapperFactoryMock;

    #[test]
    fn change_handler_config_next_lifetime_secs_handles_greater_than_one_second() {
        let subject = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(1001),
            remap_interval: Duration::from_millis(0),
        };

        let result = subject.next_lifetime_secs();

        assert_eq!(result, 1);
    }

    #[test]
    fn change_handler_config_next_lifetime_secs_handles_less_than_one_second() {
        let subject = MappingConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(999),
            remap_interval: Duration::from_millis(2000),
        };

        let result = subject.next_lifetime_secs();

        assert_eq!(result, 0);
    }

    #[test]
    fn free_port_factory_works() {
        let subject = FreePortFactoryReal::new();
        for attempt in 0..10 {
            let port = subject.make();
            {
                let result = UdpSocket::bind(SocketAddr::new(localhost(), port));
                assert_eq!(
                    result.is_ok(),
                    true,
                    "Attempt {} found port {} which wasn't open",
                    attempt + 1,
                    port
                );
            }
        }
    }

    #[test]
    fn udp_socket_wrapper_factory_make_multicast_works() {
        // Note: for some reason, at least on Dan's machine, Ipv4Addr::UNSPECIFIED is the only value
        // that works here. Anything definite will fail because the receiving socket can't hear
        // the sending socket. There shouldn't be any security threat in using UNSPECIFIED, because
        // multicast addresses are not routed out to the Internet; but this is still puzzling.
        let multicast_port = find_free_port();
        let multicast_group = 253u8;
        let subject = UdpSocketWrapperFactoryReal::new();
        let socket_sender = subject
            .make_multicast(multicast_group, multicast_port)
            .unwrap();
        let socket_receiver_1 = subject
            .make_multicast(multicast_group, multicast_port)
            .unwrap();
        let socket_receiver_2 = subject
            .make_multicast(multicast_group, multicast_port)
            .unwrap();
        let message = b"Taxation is theft!";
        let multicast_address =
            SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, multicast_group), multicast_port);
        socket_sender
            .send_to(message, SocketAddr::V4(multicast_address))
            .unwrap();
        let mut buf = [0u8; 100];
        let (size, source) = socket_receiver_1.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], message);
        let (size, source) = socket_receiver_2.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..size], message);
    }

    #[test]
    fn udp_socket_wrapper_factory_make_multicast_fails_when_socket_is_already_connected() {
        let multicast_port = find_free_port();
        let multicast_group = 254u8;
        let subject = UdpSocketWrapperFactoryReal::new();
        let blocker_socket = subject.make(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            multicast_port,
        ));

        let result = subject.make_multicast(multicast_group, multicast_port);

        assert_eq!(result.err().unwrap().kind(), ErrorKind::AddrInUse);
    }

    struct TameFindRoutersCommand {}

    impl FindRoutersCommand for TameFindRoutersCommand {
        fn execute(&self) -> Result<String, String> {
            panic!("Don't call me!")
        }
    }

    #[test]
    fn find_routers_command_works_when_command_is_blank() {
        let subject = TameFindRoutersCommand {};

        let result = subject.execute_command("");

        assert_eq!(result, Err("Command is blank".to_string()))
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn find_routers_command_works_when_stderr_is_populated() {
        let subject = TameFindRoutersCommand {};

        let result = subject.execute_command("ls booga");

        match result {
            Err(stderr) if stderr.contains("No such file or directory") => (),
            Err(stderr) => panic!("Unexpected content in stderr: '{}'", stderr),
            x => panic!("Expected error message in stderr; got {:?}", x),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn find_routers_command_works_when_stderr_is_populated() {
        let subject = TameFindRoutersCommand {};

        let result = subject.execute_command("dir booga");

        match result {
            Err(stderr)
                if stderr.contains("The system cannot find the file specified")
                    || stderr.contains("No such file or directory") =>
            {
                ()
            }
            Err(stderr) => panic!("Unexpected content in stderr: '{}'", stderr),
            x => panic!("Expected error message in stderr; got {:?}", x),
        }
    }

    #[test]
    fn make_announcement_socket_failure_is_handled() {
        let announcement_multicast_group = 134;
        let announcement_port = 1234;
        let make_multicast_params_arc = Arc::new(Mutex::new(vec![]));
        let socket_factory = UdpSocketWrapperFactoryMock::new()
            .make_multicast_params(&make_multicast_params_arc)
            .make_multicast_result(Err(std::io::Error::from(ErrorKind::AddrInUse)));

        let result = make_announcement_socket(
            &socket_factory,
            announcement_multicast_group,
            announcement_port
        );

        assert_eq!(
            result.err().unwrap(),
            AutomapError::SocketBindingError(
                "Kind(AddrInUse)".to_string(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 134)), 1234)
            )
        );
        let make_multicast_params = make_multicast_params_arc.lock().unwrap();
        assert_eq!(*make_multicast_params, vec![(134, 1234)]);
    }
}
