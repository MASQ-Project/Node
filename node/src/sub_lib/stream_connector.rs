// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::tokio_wrappers::ReadHalfWrapper;
use crate::sub_lib::tokio_wrappers::ReadHalfWrapperReal;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapperReal;
use async_trait::async_trait;
use masq_lib::logger::Logger;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream as StdTcpStream;
use std::time::Duration;
use tokio::io;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

pub const CONNECT_TIMEOUT_MS: u64 = 5000;

pub struct ConnectionInfo {
    pub reader: Box<dyn ReadHalfWrapper>,
    pub writer: Box<dyn WriteHalfWrapper>,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

#[async_trait]
pub trait StreamConnector: Send {
    async fn connect(
        &self,
        socket_addr: SocketAddr,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error>;
    fn connect_one(
        &self,
        ip_addrs: Vec<IpAddr>,
        target_hostname: &str,
        target_port: u16,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error>;
    fn split_stream(&self, stream: TcpStream, logger: &Logger) -> Option<ConnectionInfo>;
    fn dup(&self) -> Box<dyn StreamConnector>;
}

#[derive(Clone)]
pub struct StreamConnectorReal {}

#[async_trait]
impl StreamConnector for StreamConnectorReal {
    async fn connect(
        &self,
        socket_addr: SocketAddr,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error> {
        let future_logger = logger.clone();
        let timeout_result = timeout_at(
            Instant::now() + Duration::from_millis(CONNECT_TIMEOUT_MS),
            async {
                let connect_result = TcpStream::connect(&socket_addr).await;
                match connect_result {
                    Ok(stream) => {
                        let local_addr = stream.local_addr().unwrap_or_else(|e| {
                            panic!(
                                "Newly-connected stream to {} has no local_addr: {:?}",
                                socket_addr, e
                            )
                        });
                        let peer_addr = stream.peer_addr().unwrap_or_else(|e| {
                            // Untested code below: we couldn't figure out how to make this happen in captivity
                            panic!(
                                "Newly-connected stream to {} has no peer_addr: {:?}",
                                socket_addr, e
                            );
                        });
                        let (read_half, write_half) = stream.into_split();
                        Ok(ConnectionInfo {
                            reader: Box::new(ReadHalfWrapperReal::new(read_half)),
                            writer: Box::new(WriteHalfWrapperReal::new(write_half)),
                            local_addr,
                            peer_addr,
                        })
                    }
                    Err(e) => {
                        error!(
                            future_logger,
                            "Could not connect TCP stream to {}", socket_addr
                        );
                        Err(e)
                    }
                }
            },
        );
        timeout_result
            .await
            .unwrap_or_else(|_| Err(io::Error::from(ErrorKind::TimedOut)))
    }

    fn connect_one(
        &self,
        ip_addrs: Vec<IpAddr>,
        target_hostname: &str,
        target_port: u16,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error> {
        let mut last_error = io::Error::from(ErrorKind::Other);
        let mut socket_addrs_tried = vec![];

        for ip_addr in ip_addrs {
            let socket_addr = SocketAddr::new(ip_addr, target_port);

            match StdTcpStream::connect(&socket_addr) {
                Ok(stream) => {
                    debug!(logger, "Connected new stream to {}", socket_addr);
                    let tokio_stream =
                        TcpStream::from_std(stream).expect("Tokio could not create a TcpStream");
                    return Ok(self.split_stream(tokio_stream, logger).unwrap_or_else(|| {
                        panic!("Stream to {} could not be split", socket_addr)
                    }));
                }
                Err(e) => {
                    last_error = e;
                    socket_addrs_tried.push(format!("{}", socket_addr));
                    continue;
                }
            };
        }

        error!(
            logger,
            "Could not connect to any of the IP addresses supplied for {}: {:?}",
            target_hostname,
            socket_addrs_tried
        );
        Err(last_error)
    }

    fn split_stream(&self, stream: TcpStream, logger: &Logger) -> Option<ConnectionInfo> {
        let local_addr = stream
            .local_addr()
            .expect("Stream has no local_addr before splitting");
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!(logger, "Stream has no peer_addr before splitting: {}", e);
                return None;
            }
        };
        let (read_half, write_half) = stream.into_split();
        Some(ConnectionInfo {
            reader: Box::new(ReadHalfWrapperReal::new(read_half)),
            writer: Box::new(WriteHalfWrapperReal::new(write_half)),
            local_addr,
            peer_addr,
        })
    }

    fn dup(&self) -> Box<dyn StreamConnector> {
        Box::new(StreamConnectorReal {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::little_tcp_server::LittleTcpServer;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::utils::{find_free_port, localhost};
    use std::net::{IpAddr, Shutdown};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;
    use tokio;
    use tokio::io::ErrorKind;
    use tokio::runtime::Runtime;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CONNECT_TIMEOUT_MS, 5000);
    }

    #[test]
    fn stream_connector_can_fail_to_connect() {
        init_test_logging();
        let dead_port = find_free_port();
        let socket_addr = SocketAddr::new(localhost(), dead_port);
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};

        let future = subject.connect(socket_addr, &logger);

        let result = Runtime::new().unwrap().block_on(future);
        let actual = result.err().unwrap().kind();
        assert_eq!(
            actual,
            ErrorKind::ConnectionRefused,
            "Expected {:?}, got {:?}",
            ErrorKind::ConnectionRefused,
            actual
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: test: Could not connect TCP stream to 127.0.0.1:{}",
            dead_port
        ));
    }

    #[test]
    fn stream_connector_can_succeed_to_connect() {
        let server = LittleTcpServer::start();
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};

        let future = subject.connect(server.socket_addr(), &logger);

        let result = Runtime::new().unwrap().block_on(future);
        let connection_info = result.unwrap();
        assert_eq!(connection_info.local_addr.ip(), localhost());
        assert_eq!(connection_info.peer_addr, server.socket_addr());
    }

    #[test]
    fn stream_connector_can_try_connections_until_it_succeeds_then_use_the_successful_one() {
        init_test_logging();
        let logger = Logger::new("test");
        let server = LittleTcpServer::start();
        let socket_addr = server.socket_addr();

        let bogus_ip = IpAddr::from_str("255.255.255.255").unwrap();
        let good_ip = socket_addr.ip();

        let subject = StreamConnectorReal {};
        let ip_addrs = vec![bogus_ip, good_ip];

        let connection_result = subject.connect_one(
            ip_addrs,
            &"some hostname".to_string(),
            socket_addr.port(),
            &logger,
        );

        assert!(connection_result.is_ok());
        let connection_info = connection_result.unwrap();
        assert_eq!(connection_info.peer_addr, socket_addr);
        assert_eq!(connection_info.local_addr.ip(), socket_addr.ip());
    }

    #[test]
    fn stream_connector_only_tries_connecting_until_successful() {
        init_test_logging();
        let logger = Logger::new("test");
        let server = LittleTcpServer::start();
        let socket_addr = server.socket_addr();

        let ip_addr = socket_addr.ip();

        let subject = StreamConnectorReal {};
        let ip_addrs = vec![ip_addr, ip_addr];

        let connection_result = subject.connect_one(
            ip_addrs,
            &"some hostname".to_string(),
            socket_addr.port(),
            &logger,
        );

        assert!(connection_result.is_ok());
        let connection_info = connection_result.unwrap();
        assert_eq!(connection_info.peer_addr, socket_addr);
        assert_eq!(connection_info.local_addr.ip(), socket_addr.ip());

        assert_eq!(server.count_connections(Duration::from_millis(200)), 1);
    }

    #[test]
    fn stream_connector_returns_err_when_it_cannot_connect_to_any_of_the_provided_ip_addrs() {
        init_test_logging();
        let logger = Logger::new("test");

        let bogus_ip = IpAddr::from_str("255.255.255.255").unwrap();

        let subject = StreamConnectorReal {};
        let ip_addrs = vec![bogus_ip];

        let connection_result =
            subject.connect_one(ip_addrs, &"some hostname".to_string(), 9876, &logger);

        assert!(connection_result.is_err());
        TestLogHandler::new().exists_log_matching("Could not connect to any of the IP addresses supplied for some hostname: \\[\"255\\.255\\.255\\.255:\\d+\"\\]");
    }

    #[test]
    fn closed_stream_either_splits_properly_or_doesnt_split_and_logs() {
        init_test_logging();
        let server = LittleTcpServer::start();
        let std_stream = StdTcpStream::connect(server.socket_addr()).unwrap();
        let local_addr = std_stream.local_addr().unwrap();
        let peer_addr = std_stream.peer_addr().unwrap();
        std_stream.shutdown(Shutdown::Both).unwrap();
        thread::sleep(Duration::from_millis(100)); // Shutdown apparently needs time to propagate
        let stream = TcpStream::from_std(std_stream).unwrap();
        let logger = Logger::new("either/or");
        let subject = StreamConnectorReal {};

        let result = subject.split_stream(stream, &logger);

        match result {
            Some(connection_info) => {
                // If the split proceeds (Windows), the ConnectionInfo had better be filled out and there'd better be no log
                assert_eq!(local_addr, connection_info.local_addr);
                assert_eq!(peer_addr, connection_info.peer_addr);
                TestLogHandler::new().exists_no_log_containing("either/or");
            }
            None => {
                // If the split fails (Linux, macOS), there'd better be a log
                TestLogHandler::new().exists_log_containing(
                    "ERROR: either/or: Stream has no peer_addr before splitting:",
                );
            }
        }
    }
}
