// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

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
use crate::comm_layer::AutomapError;
use masq_lib::utils::find_free_port;
use std::io;
pub use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

pub const ROUTER_PORT: u16 = 5351; // from the PCP and PMP RFCs
pub const HOUSEKEEPING_THREAD_LOOP_DELAY_MILLIS: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq)]
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
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
}

pub struct UdpSocketReal {
    delegate: UdpSocket,
}

impl UdpSocketWrapper for UdpSocketReal {
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.delegate.recv_from(buf)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.delegate.send_to(buf, addr)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.delegate.set_read_timeout(dur)
    }
}

impl UdpSocketReal {
    pub fn new(delegate: UdpSocket) -> Self {
        Self { delegate }
    }
}

pub trait UdpSocketWrapperFactory: Send {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>>;
}

pub struct UdpSocketFactoryReal {}

impl UdpSocketWrapperFactory for UdpSocketFactoryReal {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        Ok(Box::new(UdpSocketReal::new(UdpSocket::bind(addr)?)))
    }
}

impl UdpSocketFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for UdpSocketFactoryReal {
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use masq_lib::utils::localhost;

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
}
