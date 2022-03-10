// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::socket_server::ConfiguredByPrivilege;
use masq_lib::command::StdStreams;
use masq_lib::logger::Logger;
use std::net::SocketAddr;
use tokio::prelude::Async;
use tokio::prelude::Future;

const DNS_PORT: u16 = 53;

use crate::entry_dns::processing;
use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperReal;
use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::localhost;

pub struct DnsSocketServer {
    socket_wrapper: Box<dyn UdpSocketWrapperTrait>,
    buf: [u8; 65536],
}

impl Future for DnsSocketServer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let logger = Logger::new("EntryDnsServer");
        loop {
            let mut buffer = self.buf;
            let (len, socket_addr) = match self.socket_wrapper.recv_from(&mut buffer) {
                Ok(Async::Ready((len, socket_addr))) => (len, socket_addr),
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => {
                    error!(
                        logger,
                        "Unrecoverable error receiving from UdpSocket: {}", e
                    );
                    return Err(());
                }
            };
            let response_length = processing::process(&mut buffer, len, &socket_addr, &logger);
            if let Err(e) = self
                .socket_wrapper
                .send_to(&buffer[0..response_length], socket_addr)
            {
                error!(logger, "Unrecoverable error sending to UdpSocket: {}", e);
                return Err(());
            }
        }
    }
}

impl ConfiguredByPrivilege for DnsSocketServer {
    fn initialize_as_privileged(
        &mut self,
        _multi_config: &MultiConfig,
    ) -> Result<(), ConfiguratorError> {
        let socket_addr = SocketAddr::new(localhost(), DNS_PORT);
        self.socket_wrapper
            .bind(socket_addr)
            .unwrap_or_else(|e| panic!("Cannot bind socket to {:?}: {:?}", socket_addr, e));
        Ok(())
    }

    fn initialize_as_unprivileged(
        &mut self,
        _multi_config: &MultiConfig,
        _streams: &mut StdStreams<'_>,
    ) -> Result<(), ConfiguratorError> {
        self.buf = [0; 65536];
        Ok(())
    }
}

impl DnsSocketServer {
    pub fn new() -> DnsSocketServer {
        DnsSocketServer {
            socket_wrapper: Box::new(UdpSocketWrapperReal::new()),
            buf: [0; 65536],
        }
    }
}

impl Default for DnsSocketServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::packet_facade::PacketFacade;
    use super::*;
    use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
    use crate::test_utils::unshared_test_utils::make_simplified_multi_config;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::borrow::Borrow;
    use std::borrow::BorrowMut;
    use std::clone::Clone;
    use std::cmp::min;
    use std::io;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::ops::DerefMut;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use tokio;
    use trust_dns::op::ResponseCode;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DNS_PORT, 53);
    }

    struct UdpSocketWrapperMockGuts {
        log: Vec<String>,
        buf: [u8; 12],
    }

    #[derive(Clone)]
    struct UdpSocketWrapperMock {
        guts: Arc<Mutex<UdpSocketWrapperMockGuts>>,
        recv_from_results: Arc<Mutex<Vec<Result<Async<(usize, SocketAddr)>, Error>>>>,
        send_to_results: Arc<Mutex<Vec<Result<Async<usize>, Error>>>>,
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

        fn send_to(&mut self, buf: &[u8], addr: SocketAddr) -> Result<Async<usize>, Error> {
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
    fn uses_standard_dns_port() {
        let socket_wrapper = make_socket_wrapper_mock();
        let mut subject = make_instrumented_subject(socket_wrapper.clone());

        subject
            .initialize_as_privileged(&make_simplified_multi_config([]))
            .unwrap();

        let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
        let borrowed_guts = unwrapped_guts.borrow();
        let log = &borrowed_guts.log;
        assert_eq!(log[0], "bind ('127.0.0.1:53')")
    }

    #[test]
    fn serves_multiple_requests_then_short_circuit_on_error() {
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
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

            subject
                .initialize_as_unprivileged(
                    &make_simplified_multi_config([]),
                    &mut holder.streams(),
                )
                .unwrap();
            tokio::run(subject);

            let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
            let borrowed_guts = unwrapped_guts.borrow();

            let log = &borrowed_guts.log;
            let buf = &borrowed_guts.buf;

            (log.clone(), buf.clone())
        };

        assert_eq!(
            log,
            vec![
                String::from("recv_from (Ok(Ready((12, 0.0.0.0:0))))"),
                String::from("send_to (buf, 0.0.0.0:0)"),
                String::from("recv_from (Ok(Ready((12, 1.0.0.0:0))))"),
                String::from("send_to (buf, 1.0.0.0:0)"),
                String::from("recv_from (Ok(Ready((12, 2.0.0.0:0))))"),
                String::from("send_to (buf, 2.0.0.0:0)"),
                String::from("recv_from (Err(Kind(BrokenPipe)))")
            ]
        );
        let facade = PacketFacade::new(&mut buf, 12);
        assert_eq!(Some(0x1234), facade.get_transaction_id());
        assert_eq!(Some(ResponseCode::NoError.low()), facade.get_rcode());
        TestLogHandler::new().await_log_matching(
            r"TRACE: EntryDnsServer: \d+ns: 0\.0\.0\.0:0 Query \(\) -> No Error \(\)",
            1000,
        );
    }

    #[test]
    fn poll_handles_error_receiving_from_udp_socket_wrapper() {
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
        let socket_wrapper = make_socket_wrapper_mock();
        socket_wrapper
            .recv_from_results
            .lock()
            .unwrap()
            .push(Err(Error::from(ErrorKind::BrokenPipe)));

        let mut subject = make_instrumented_subject(socket_wrapper.clone());

        subject
            .initialize_as_unprivileged(&make_simplified_multi_config([]), &mut holder.streams())
            .unwrap();

        let result = subject.poll();

        assert!(result.is_err());
        TestLogHandler::new().await_log_containing(
            "ERROR: EntryDnsServer: Unrecoverable error receiving from UdpSocket: broken pipe",
            1000,
        );
    }

    #[test]
    fn poll_handles_error_sending_to_udp_socket_wrapper() {
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
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

        subject
            .initialize_as_unprivileged(&make_simplified_multi_config([]), &mut holder.streams())
            .unwrap();

        let result = subject.poll();

        assert!(result.is_err());
        TestLogHandler::new().await_log_containing(
            "ERROR: EntryDnsServer: Unrecoverable error sending to UdpSocket: broken pipe",
            1000,
        );
    }

    fn make_socket_wrapper_mock() -> Box<UdpSocketWrapperMock> {
        Box::new(UdpSocketWrapperMock::new(&[
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]))
    }

    fn make_instrumented_subject(socket_wrapper: Box<UdpSocketWrapperMock>) -> DnsSocketServer {
        DnsSocketServer {
            socket_wrapper,
            buf: [0; 65536],
        }
    }
}
