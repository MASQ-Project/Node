// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use processor::ProcessorReal;
use processor::ProcessorTrait;
use std::borrow::BorrowMut;
use std::net::IpAddr;
use std::net::IpAddr::V4;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;
use sub_lib::logger::Logger;
use sub_lib::main_tools::StdStreams;
use sub_lib::socket_server::SocketServer;
use sub_lib::udp_socket_wrapper::UdpSocketWrapperReal;
use sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub struct DnsSocketServer {
    dns_target: Option<IpAddr>,
    socket_wrapper: Box<UdpSocketWrapperTrait>,
    processor: Option<Box<ProcessorTrait>>,
    buf: Option<[u8; 65536]>,
}

impl Future for DnsSocketServer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let logger = Logger::new("EntryDnsServer");
        loop {
            let mut buffer = self
                .buf
                .expect("Missing buffer - was initialize_as_privileged called?");
            let (len, socket_addr) = match self.socket_wrapper.recv_from(buffer.borrow_mut()) {
                Ok(Async::Ready((len, socket_addr))) => (len, socket_addr),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    logger.error(format!(
                        "Unrecoverable error receiving from UdpSocket: {}",
                        e
                    ));
                    return Err(());
                }
            };
            let processor_unwrapped = self
                .processor
                .as_ref()
                .expect("Missing Processor - was initialized_as_privileged called?");
            let response_length =
                processor_unwrapped.process(buffer.borrow_mut(), len, &socket_addr, &logger);
            match self
                .socket_wrapper
                .send_to(&buffer[0..response_length], socket_addr)
            {
                Err(e) => {
                    logger.error(format!("Unrecoverable error sending to UdpSocket: {}", e));
                    return Err(());
                }
                Ok(_) => {}
            }
        }
    }
}

impl SocketServer for DnsSocketServer {
    fn name(&self) -> String {
        String::from("EntryDnsServer")
    }

    fn initialize_as_privileged(&mut self, args: &Vec<String>, _streams: &mut StdStreams) {
        self.dns_target = Some(get_dns_target(args));
        let socket_addr = SocketAddr::new(V4(Ipv4Addr::from(0)), get_dns_port(args));
        // The following expect() will cause an appropriate panic if the port can't be opened
        self.socket_wrapper
            .bind(socket_addr)
            .expect(&format!("Cannot bind socket to {:?}", socket_addr));
    }

    fn initialize_as_unprivileged(&mut self) {
        let processor_real = ProcessorReal::new(
            self.dns_target
                .expect("Missing dns_target - was initialize_as_privileged called?"),
        );
        self.processor = Some(Box::new(processor_real));
        self.buf = Some([0; 65536]);
    }
}

// TODO: why not use the `::new` convention?
pub fn new_dns_socket_server() -> DnsSocketServer {
    DnsSocketServer {
        dns_target: None,
        socket_wrapper: Box::new(UdpSocketWrapperReal::new()),
        processor: None,
        buf: None,
    }
}

fn get_dns_target(args: &Vec<String>) -> IpAddr {
    let finder = ParameterFinder::new(args);
    let ip_addr_str = match finder.find_value_after(
        "--dns_target",
        "must be followed by IP address to redirect to (default 127.0.0.1)",
    ) {
        Some(s) => s,
        None => String::from("127.0.0.1"),
    };
    match Ipv4Addr::from_str(&ip_addr_str) {
        Ok(ip_addr) => V4(ip_addr),
        Err(_) => panic!("Invalid IP address for --dns_target: {}", ip_addr_str),
    }
}

fn get_dns_port(args: &Vec<String>) -> u16 {
    let finder = ParameterFinder::new(args);
    let port_str = match finder.find_value_after(
        "--dns_port",
        "must be followed by port number on which DNS server listens (default 53)",
    ) {
        Some(s) => s,
        None => String::from("53"),
    };
    let port: u64 = match port_str.parse() {
        Ok(p) => p,
        Err(_) => panic!("DNS server port must be numeric, not '{}'", port_str),
    };
    if port < 1 || port > 65535 {
        panic!("DNS server port must be in the range 1-65535, not {}", port)
    }
    port as u16
}

struct ParameterFinder<'a> {
    args: &'a Vec<String>,
}

impl<'a> ParameterFinder<'a> {
    fn new(args: &'a Vec<String>) -> ParameterFinder<'a> {
        ParameterFinder { args }
    }

    fn find_value_after(&self, parameter_tag: &str, msg: &str) -> Option<String> {
        let mut index = 0;
        while index < self.args.len() {
            if self.args[index] == parameter_tag {
                if index == self.args.len() - 1 {
                    // crashpoint - return none?
                    panic!("{} {}", parameter_tag, msg);
                }
                let value: &str = &self.args[index + 1];
                if value.starts_with("-") {
                    // crashpoint - return none?
                    panic!("{} {}", parameter_tag, msg);
                } else {
                    return Some(String::from(value));
                }
            }
            // TODO: Should probably skip 2 if this item had a parameter
            index += 1;
        }
        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_facade::PacketFacade;
    use std::borrow::Borrow;
    use std::borrow::BorrowMut;
    use std::clone::Clone;
    use std::cmp::min;
    use std::io;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::ops::DerefMut;
    use std::sync::Arc;
    use std::sync::Mutex;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::test_utils::FakeStreamHolder;
    use tokio;

    struct UdpSocketWrapperMockGuts {
        log: Vec<String>,
        buf: [u8; 12],
    }

    #[derive(Clone)]
    struct UdpSocketWrapperMock {
        guts: Arc<Mutex<UdpSocketWrapperMockGuts>>,
        recv_from_results: Arc<Mutex<Vec<Result<Async<(usize, SocketAddr)>, Error>>>>,
        send_to_results: Arc<Mutex<Vec<Result<Async<(usize)>, Error>>>>,
    }

    impl UdpSocketWrapperTrait for UdpSocketWrapperMock {
        fn bind(&mut self, addr: SocketAddr) -> io::Result<bool> {
            let mut unwrapped_guts = self.guts.lock().unwrap();
            let guts_ref = unwrapped_guts.borrow_mut();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut();
            guts.log.push(format!("bind ('{:?}')", addr));
            Ok(true)
        }

        fn recv_from(&mut self, buf: &mut [u8]) -> Result<Async<(usize, SocketAddr)>, Error> {
            let mut unwrapped_guts = self.guts.lock().unwrap();
            let guts_ref = unwrapped_guts.borrow_mut();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut();
            UdpSocketWrapperMock::copy(buf, &guts.buf);
            let result = self
                .recv_from_results
                .lock()
                .unwrap()
                .borrow_mut()
                .remove(0);
            guts.log.push(format!("recv_from ({:?})", result));
            result
        }

        fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<Async<(usize)>, Error> {
            let mut unwrapped_guts = self.guts.lock().unwrap();
            let guts_ref = unwrapped_guts.borrow_mut();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut();
            guts.log.push(format!("send_to (buf, {:?})", addr));
            UdpSocketWrapperMock::copy(&mut guts.buf, buf);
            self.send_to_results.lock().unwrap().borrow_mut().remove(0)
        }
    }

    impl UdpSocketWrapperMock {
        fn new(buf: &[u8]) -> UdpSocketWrapperMock {
            assert_eq!(
                buf.len() <= 12,
                true,
                "Mock accepts buffer of up to 12 bytes, not {}",
                buf.len()
            );
            let result = UdpSocketWrapperMock {
                guts: Arc::new(Mutex::new(UdpSocketWrapperMockGuts {
                    log: Vec::new(),
                    buf: [0; 12],
                })),
                recv_from_results: Arc::new(Mutex::new(vec![])),
                send_to_results: Arc::new(Mutex::new(vec![])),
            };
            result
                .guts
                .lock()
                .unwrap()
                .borrow_mut()
                .deref_mut()
                .buf
                .copy_from_slice(&buf);
            result
        }

        fn copy(destination: &mut [u8], source: &[u8]) {
            let to_copy = min(destination.len(), source.len());
            for i in 0..to_copy {
                destination[i] = source[i];
            }
        }
    }

    #[test]
    fn knows_its_name() {
        let subject = new_dns_socket_server();

        let result = subject.name();

        assert_eq!(&result, "EntryDnsServer");
    }

    #[test]
    #[should_panic(
        expected = "--dns_target must be followed by IP address to redirect to (default 127.0.0.1)"
    )]
    fn complains_about_missing_dns_target() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_target"),
                String::from("--something_else"),
            ],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(
        expected = "--dns_target must be followed by IP address to redirect to (default 127.0.0.1)"
    )]
    fn complains_about_missing_dns_target_at_end() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("irrelevant"), String::from("--dns_target")],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --dns_target: lots.and.lots.of.dots")]
    fn complains_about_dns_target_with_too_many_dots() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_target"),
                String::from("lots.and.lots.of.dots"),
            ],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --dns_target: only.two.dots")]
    fn complains_about_dns_target_with_too_few_dots() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_target"), String::from("only.two.dots")],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --dns_target: 123.124.125.booga")]
    fn complains_about_dns_target_with_nonnumeric_components() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_target"),
                String::from("123.124.125.booga"),
            ],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --dns_target: 123.124.125.256")]
    fn complains_about_dns_target_with_numeric_components_too_large() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_target"),
                String::from("123.124.125.256"),
            ],
            &mut holder.streams(),
        );
    }

    #[test]
    fn accepts_valid_dns_target() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_target"),
                String::from("123.124.125.126"),
            ],
            &mut holder.streams(),
        );

        assert_eq!(
            subject.dns_target,
            Some(V4(Ipv4Addr::from_str("123.124.125.126").unwrap()))
        );
    }

    #[test]
    fn defaults_unspecified_dns_target() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(&vec![], &mut holder.streams());

        assert_eq!(
            subject.dns_target,
            Some(V4(Ipv4Addr::from_str("127.0.0.1").unwrap()))
        );
    }

    #[test]
    #[should_panic(
        expected = "--dns_port must be followed by port number on which DNS server listens (default 53)"
    )]
    fn complains_about_missing_dns_port() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_port"), String::from("--something_else")],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "DNS server port must be numeric, not 'booga'")]
    fn complains_if_dns_server_port_is_not_numeric() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_port"), String::from("booga")],
            &mut holder.streams(),
        );
    }

    #[test]
    #[should_panic(expected = "DNS server port must be in the range 1-65535, not 0")]
    fn complains_if_dns_server_port_is_too_small() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_port"), String::from("0")],
            &mut holder.streams(),
        );

        panic!("Wrong message");
    }

    #[test]
    #[should_panic(expected = "DNS server port must be in the range 1-65535, not 65536")]
    fn complains_if_dns_server_port_is_too_large() {
        let mut holder = FakeStreamHolder::new();
        let mut subject = make_instrumented_subject(make_socket_wrapper_mock());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_port"), String::from("65536")],
            &mut holder.streams(),
        );

        panic!("Wrong message");
    }

    #[test]
    fn accepts_valid_dns_port() {
        let mut holder = FakeStreamHolder::new();
        let socket_wrapper = make_socket_wrapper_mock();
        let mut subject = make_instrumented_subject(socket_wrapper.clone());

        subject.initialize_as_privileged(
            &vec![String::from("--dns_port"), String::from("5454")],
            &mut holder.streams(),
        );

        let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
        let borrowed_guts = unwrapped_guts.borrow();
        let log = &borrowed_guts.log;
        assert_eq!(log[0], "bind ('V4(0.0.0.0:5454)')")
    }

    #[test]
    fn defaults_unspecified_dns_port() {
        let mut holder = FakeStreamHolder::new();
        let socket_wrapper = make_socket_wrapper_mock();
        let mut subject = make_instrumented_subject(socket_wrapper.clone());

        subject.initialize_as_privileged(&vec![], &mut holder.streams());

        let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
        let borrowed_guts = unwrapped_guts.borrow();
        let log = &borrowed_guts.log;
        assert_eq!(log[0], "bind ('V4(0.0.0.0:53)')")
    }

    #[test]
    fn serves_multiple_requests_then_short_circuit_on_error() {
        init_test_logging();
        let (log, mut buf) = {
            let socket_wrapper = make_socket_wrapper_mock();
            socket_wrapper
                .recv_from_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready((
                    socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                    SocketAddr::from_str("0.0.0.0:0").unwrap(),
                ))));
            socket_wrapper
                .recv_from_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready((
                    socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                    SocketAddr::from_str("1.0.0.0:0").unwrap(),
                ))));
            socket_wrapper
                .recv_from_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready((
                    socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                    SocketAddr::from_str("2.0.0.0:0").unwrap(),
                ))));
            socket_wrapper
                .recv_from_results
                .lock()
                .unwrap()
                .push(Err(Error::from(ErrorKind::BrokenPipe)));

            socket_wrapper
                .send_to_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready(12)));
            socket_wrapper
                .send_to_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready(12)));
            socket_wrapper
                .send_to_results
                .lock()
                .unwrap()
                .push(Ok(Async::Ready(12)));

            let mut subject = make_instrumented_subject(socket_wrapper.clone());
            subject.dns_target = Some(V4(Ipv4Addr::from_str("1.2.3.4").unwrap()));

            subject.initialize_as_unprivileged();
            tokio::run(subject);

            let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
            let borrowed_guts = unwrapped_guts.borrow();

            let log = &borrowed_guts.log;
            let buf = &borrowed_guts.buf;

            (log.clone(), buf.clone())
        };

        assert_eq!(
            &log,
            &vec!(
                String::from("recv_from (Ok(Ready((12, V4(0.0.0.0:0)))))"),
                String::from("send_to (buf, V4(0.0.0.0:0))"),
                String::from("recv_from (Ok(Ready((12, V4(1.0.0.0:0)))))"),
                String::from("send_to (buf, V4(1.0.0.0:0))"),
                String::from("recv_from (Ok(Ready((12, V4(2.0.0.0:0)))))"),
                String::from("send_to (buf, V4(2.0.0.0:0))"),
                String::from("recv_from (Err(Kind(BrokenPipe)))")
            )
        );
        let facade = PacketFacade::new(&mut buf, 12);
        assert_eq!(facade.get_transaction_id(), Some(0x1234));
        assert_eq!(facade.get_rcode(), Some(0x4));
        TestLogHandler::new ().await_log_matching (r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d ThreadId\(\d+\): INFO: EntryDnsServer: \d+ns: 0\.0\.0\.0:0 RQF \(\) -> RS4 \(\)", 1000);
    }

    #[test]
    fn poll_handles_error_receiving_from_udp_socket_wrapper() {
        init_test_logging();
        let socket_wrapper = make_socket_wrapper_mock();
        socket_wrapper
            .recv_from_results
            .lock()
            .unwrap()
            .push(Err(Error::from(ErrorKind::BrokenPipe)));

        let mut subject = make_instrumented_subject(socket_wrapper.clone());
        subject.dns_target = Some(V4(Ipv4Addr::from_str("1.2.3.4").unwrap()));

        subject.initialize_as_unprivileged();

        let result = subject.poll();

        assert!(result.is_err());
        TestLogHandler::new().await_log_matching(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d ThreadId\(\d+\): ERROR: EntryDnsServer: Unrecoverable error receiving from UdpSocket: broken pipe", 1000);
    }

    #[test]
    fn poll_handles_error_sending_to_udp_socket_wrapper() {
        init_test_logging();
        let socket_wrapper = make_socket_wrapper_mock();
        socket_wrapper
            .recv_from_results
            .lock()
            .unwrap()
            .push(Ok(Async::Ready((
                socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                SocketAddr::from_str("0.0.0.0:0").unwrap(),
            ))));
        socket_wrapper
            .send_to_results
            .lock()
            .unwrap()
            .push(Err(Error::from(ErrorKind::BrokenPipe)));

        let mut subject = make_instrumented_subject(socket_wrapper.clone());
        subject.dns_target = Some(V4(Ipv4Addr::from_str("1.2.3.4").unwrap()));

        subject.initialize_as_unprivileged();

        let result = subject.poll();

        assert!(result.is_err());
        TestLogHandler::new().await_log_matching(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d ThreadId\(\d+\): ERROR: EntryDnsServer: Unrecoverable error sending to UdpSocket: broken pipe", 1000);
    }

    fn make_socket_wrapper_mock() -> Box<UdpSocketWrapperMock> {
        Box::new(UdpSocketWrapperMock::new(&[
            0x12, 0x34, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]))
    }

    fn make_instrumented_subject(socket_wrapper: Box<UdpSocketWrapperMock>) -> DnsSocketServer {
        DnsSocketServer {
            dns_target: None,
            socket_wrapper,
            processor: None,
            buf: None,
        }
    }
}
