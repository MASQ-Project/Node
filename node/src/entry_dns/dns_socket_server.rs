// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::entry_dns::processing;
use crate::sub_lib::socket_server::{ConfiguredByPrivilege, SpawnableConfiguredByPrivilege};
use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperReal;
use crate::sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
use async_trait::async_trait;
use masq_lib::command::StdStreams;
use masq_lib::logger::Logger;
use masq_lib::multi_config::MultiConfig;
use masq_lib::shared_schema::ConfiguratorError;
use masq_lib::utils::localhost;
use std::net::SocketAddr;

const DNS_PORT: u16 = 53;

pub struct DnsSocketServer {
    socket_wrapper: Box<dyn UdpSocketWrapperTrait>,
    logger: Logger,
    // TODO: I think this field is unnecessary. It's only used in the async block below, so it could be a local variable.
    buf: [u8; 65536],
}

#[async_trait(?Send)]
impl ConfiguredByPrivilege for DnsSocketServer {
    async fn initialize_as_privileged(
        &mut self,
        _multi_config: &MultiConfig,
    ) -> Result<(), ConfiguratorError> {
        let socket_addr = SocketAddr::new(localhost(), DNS_PORT);
        self.socket_wrapper
            .bind(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Cannot bind socket to {:?}: {:?}", socket_addr, e));
        Ok(())
    }

    async fn initialize_as_unprivileged(
        &mut self,
        _multi_config: &MultiConfig,
        _streams: &mut StdStreams<'_>,
    ) -> Result<(), ConfiguratorError> {
        self.buf = [0; 65536];
        self.logger = Logger::new("EntryDnsServer");
        Ok(())
    }
}

#[async_trait]
impl SpawnableConfiguredByPrivilege for DnsSocketServer {
    async fn make_server_future(&mut self) -> std::io::Result<()> {
        loop {
            let mut buffer = self.buf;
            let (len, socket_addr) = match self.socket_wrapper.recv_from(&mut buffer).await {
                Ok((len, socket_addr)) => (len, socket_addr),
                Err(e) => {
                    error!(
                        self.logger,
                        "Unrecoverable error receiving from UdpSocket: {}", e
                    );
                    return Err(e);
                }
            };
            let response_length = processing::process(&mut buffer, len, &socket_addr, &self.logger);
            if let Err(e) = self
                .socket_wrapper
                .send_to(&buffer[0..response_length], socket_addr)
                .await
            {
                error!(
                    self.logger,
                    "Unrecoverable error sending to UdpSocket: {}", e
                );
                return Err(e);
            }
        }
    }
}

impl DnsSocketServer {
    pub fn new() -> DnsSocketServer {
        DnsSocketServer {
            socket_wrapper: Box::new(UdpSocketWrapperReal::new()),
            logger: Logger::new("DNS Socket Server"),
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
    use async_trait::async_trait;
    use hickory_proto::op::ResponseCode;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::make_rt;
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
        recv_from_results: Arc<Mutex<Vec<io::Result<(usize, SocketAddr)>>>>,
        send_to_results: Arc<Mutex<Vec<io::Result<usize>>>>,
    }

    #[async_trait]
    impl UdpSocketWrapperTrait for UdpSocketWrapperMock {
        async fn bind(&mut self, addr: SocketAddr) -> io::Result<bool> {
            let mut unwrapped_guts = self.guts.lock().unwrap();
            let guts_ref = unwrapped_guts.borrow_mut();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut();
            guts.log.push(format!("bind ('{:?}')", addr));
            Ok(true)
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
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

        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
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

    #[tokio::test]
    async fn uses_standard_dns_port() {
        let socket_wrapper = make_socket_wrapper_mock();
        let mut subject = make_instrumented_subject(socket_wrapper.clone());

        subject
            .initialize_as_privileged(&make_simplified_multi_config([]))
            .await
            .unwrap();

        let unwrapped_guts = socket_wrapper.guts.lock().unwrap();
        let borrowed_guts = unwrapped_guts.borrow();
        let log = &borrowed_guts.log;
        assert_eq!(log[0], "bind ('127.0.0.1:53')")
    }

    #[tokio::test]
    async fn serves_multiple_requests_then_short_circuits_on_error() {
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
        let (log, mut buf) = {
            let socket_wrapper = make_socket_wrapper_mock();
            socket_wrapper.recv_from_results.lock().unwrap().push(Ok((
                socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                SocketAddr::from_str("0.0.0.0:0").unwrap(),
            )));
            socket_wrapper.recv_from_results.lock().unwrap().push(Ok((
                socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                SocketAddr::from_str("1.0.0.0:0").unwrap(),
            )));
            socket_wrapper.recv_from_results.lock().unwrap().push(Ok((
                socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
                SocketAddr::from_str("2.0.0.0:0").unwrap(),
            )));
            socket_wrapper
                .recv_from_results
                .lock()
                .unwrap()
                .push(Err(Error::from(ErrorKind::BrokenPipe)));

            socket_wrapper.send_to_results.lock().unwrap().push(Ok(12));
            socket_wrapper.send_to_results.lock().unwrap().push(Ok(12));
            socket_wrapper.send_to_results.lock().unwrap().push(Ok(12));
            let mut subject = make_instrumented_subject(socket_wrapper.clone());
            subject
                .initialize_as_unprivileged(
                    &make_simplified_multi_config([]),
                    &mut holder.streams(),
                )
                .await
                .unwrap();

            let _ = subject.make_server_future().await.unwrap();

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

    #[tokio::test]
    async fn server_handles_error_receiving_from_udp_socket_wrapper() {
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
            .await
            .unwrap();

        let result = subject.make_server_future().await;

        assert!(result.is_err());
        TestLogHandler::new().await_log_containing(
            "ERROR: EntryDnsServer: Unrecoverable error receiving from UdpSocket: broken pipe",
            1000,
        );
    }

    #[tokio::test]
    async fn poll_handles_error_sending_to_udp_socket_wrapper() {
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
        let socket_wrapper = make_socket_wrapper_mock();
        socket_wrapper.recv_from_results.lock().unwrap().push(Ok((
            socket_wrapper.guts.lock().unwrap().borrow().buf.len(),
            SocketAddr::from_str("0.0.0.0:0").unwrap(),
        )));
        socket_wrapper
            .send_to_results
            .lock()
            .unwrap()
            .push(Err(Error::from(ErrorKind::BrokenPipe)));
        let mut subject = make_instrumented_subject(socket_wrapper.clone());
        subject
            .initialize_as_unprivileged(&make_simplified_multi_config([]), &mut holder.streams())
            .await
            .unwrap();

        let result = subject.make_server_future().await;

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
            logger: Logger::new("Test DNS Socket Server"),
            buf: [0; 65536],
        }
    }
}
