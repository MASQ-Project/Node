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

pub const ROUTER_PORT: u16 = 5351;
pub const CHANGE_HANDLER_PORT: u16 = 5350;
pub const READ_TIMEOUT_MILLIS: u64 = 1000;

#[derive(Clone, Debug, PartialEq)]
pub struct ChangeHandlerConfig {
    pub hole_port: u16,
    pub next_lifetime: Duration,
    pub remap_interval: Duration,
}

impl ChangeHandlerConfig {
    pub fn next_lifetime_secs(&self) -> u32 {
        self.next_lifetime.as_secs() as u32
    }

    pub fn remap_interval_secs(&self) -> u32 {
        self.remap_interval.as_secs() as u32
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

pub trait UdpSocketFactory: Send {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>>;
}

pub struct UdpSocketFactoryReal {}

impl UdpSocketFactory for UdpSocketFactoryReal {
    fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
        Ok(Box::new(UdpSocketReal::new(UdpSocket::bind(addr)?)))
    }
}

impl UdpSocketFactoryReal {
    pub fn new() -> Self {
        Self {}
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

pub fn make_local_socket_address(router_ip: IpAddr, free_port: u16) -> SocketAddr {
    match router_ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), free_port),
        IpAddr::V6(_) => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), free_port)
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use super::*;
    use masq_lib::utils::localhost;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use std::io::ErrorKind;

    pub struct UdpSocketMock {
        recv_from_params: Arc<Mutex<Vec<()>>>,
        recv_from_results: RefCell<Vec<(io::Result<(usize, SocketAddr)>, Vec<u8>)>>,
        send_to_params: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
        send_to_results: RefCell<Vec<io::Result<usize>>>,
        set_read_timeout_params: Arc<Mutex<Vec<Option<Duration>>>>,
        set_read_timeout_results: RefCell<Vec<io::Result<()>>>,
    }

    impl UdpSocketWrapper for UdpSocketMock {
        fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.recv_from_params.lock().unwrap().push(());
            if self.recv_from_results.borrow().is_empty() {
                return Err (io::Error::from (ErrorKind::WouldBlock))
            }
            let (result, bytes) = self.recv_from_results.borrow_mut().remove(0);
            for n in 0..bytes.len() {
                buf[n] = bytes[n];
            }
            result
        }

        fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.send_to_params
                .lock()
                .unwrap()
                .push((buf.to_vec(), addr));
            self.send_to_results.borrow_mut().remove(0)
        }

        fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout_params.lock().unwrap().push(dur);
            self.set_read_timeout_results.borrow_mut().remove(0)
        }
    }

    impl UdpSocketMock {
        pub fn new() -> Self {
            Self {
                recv_from_params: Arc::new(Mutex::new(vec![])),
                recv_from_results: RefCell::new(vec![]),
                send_to_params: Arc::new(Mutex::new(vec![])),
                send_to_results: RefCell::new(vec![]),
                set_read_timeout_params: Arc::new(Mutex::new(vec![])),
                set_read_timeout_results: RefCell::new(vec![]),
            }
        }

        pub fn recv_from_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.recv_from_params = params.clone();
            self
        }

        pub fn recv_from_result(
            self,
            result: io::Result<(usize, SocketAddr)>,
            bytes: Vec<u8>,
        ) -> Self {
            self.recv_from_results.borrow_mut().push((result, bytes));
            self
        }

        pub fn send_to_params(mut self, params: &Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>) -> Self {
            self.send_to_params = params.clone();
            self
        }

        pub fn send_to_result(self, result: io::Result<usize>) -> Self {
            self.send_to_results.borrow_mut().push(result);
            self
        }

        pub fn set_read_timeout_params(
            mut self,
            params: &Arc<Mutex<Vec<Option<Duration>>>>,
        ) -> Self {
            self.set_read_timeout_params = params.clone();
            self
        }

        pub fn set_read_timeout_result(self, result: io::Result<()>) -> Self {
            self.set_read_timeout_results.borrow_mut().push(result);
            self
        }
    }

    pub struct UdpSocketFactoryMock {
        make_params: Arc<Mutex<Vec<SocketAddr>>>,
        make_results: RefCell<Vec<io::Result<UdpSocketMock>>>,
    }

    impl UdpSocketFactory for UdpSocketFactoryMock {
        fn make(&self, addr: SocketAddr) -> io::Result<Box<dyn UdpSocketWrapper>> {
            self.make_params.lock().unwrap().push(addr);
            Ok(Box::new(self.make_results.borrow_mut().remove(0)?))
        }
    }

    impl UdpSocketFactoryMock {
        pub fn new() -> Self {
            Self {
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_params(mut self, params: &Arc<Mutex<Vec<SocketAddr>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        pub fn make_result(self, result: io::Result<UdpSocketMock>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    pub struct FreePortFactoryMock {
        make_results: RefCell<Vec<u16>>,
    }

    impl FreePortFactory for FreePortFactoryMock {
        fn make(&self) -> u16 {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl FreePortFactoryMock {
        pub fn new() -> Self {
            Self {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_result(self, result: u16) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    pub struct FindRoutersCommandMock {
        result: Result<String, String>,
    }

    impl FindRoutersCommand for FindRoutersCommandMock {
        fn execute(&self) -> Result<String, String> {
            self.result.clone()
        }
    }

    impl FindRoutersCommandMock {
        pub fn new(result: Result<&str, &str>) -> Self {
            Self {
                result: match result {
                    Ok(s) => Ok(s.to_string()),
                    Err(s) => Err(s.to_string()),
                },
            }
        }
    }

    #[test]
    fn change_handler_config_next_lifetime_secs_handles_greater_than_one_second() {
        let subject = ChangeHandlerConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(1001),
            remap_interval: Duration::from_millis(0),
        };

        let result = subject.next_lifetime_secs();

        assert_eq! (result, 1);
    }

    #[test]
    fn change_handler_config_next_lifetime_secs_handles_less_than_one_second() {
        let subject = ChangeHandlerConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(999),
            remap_interval: Duration::from_millis(2000),
        };

        let result = subject.next_lifetime_secs();

        assert_eq! (result, 0);
    }

    #[test]
    fn change_handler_config_remap_interval_secs_handles_greater_than_one_second() {
        let subject = ChangeHandlerConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(0),
            remap_interval: Duration::from_millis(1001),
        };

        let result = subject.remap_interval_secs();

        assert_eq! (result, 1);
    }

    #[test]
    fn change_handler_config_remap_interval_secs_handles_less_than_one_second() {
        let subject = ChangeHandlerConfig {
            hole_port: 0,
            next_lifetime: Duration::from_millis(2000),
            remap_interval: Duration::from_millis(999),
        };

        let result = subject.remap_interval_secs();

        assert_eq! (result, 0);
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
