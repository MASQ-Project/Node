// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use futures::future::ok;
use logger::Logger;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream as StdTcpStream;
use tokio::io;
use tokio::io::AsyncRead;
use tokio::net::TcpStream;
use tokio::prelude::Future;
use tokio::reactor::Handle;
use tokio_wrappers::ReadHalfWrapper;
use tokio_wrappers::ReadHalfWrapperReal;
use tokio_wrappers::WriteHalfWrapper;
use tokio_wrappers::WriteHalfWrapperReal;

pub type ConnectionInfoFuture = Box<Future<Item = ConnectionInfo, Error = io::Error> + Send>;

pub struct ConnectionInfo {
    pub reader: Box<ReadHalfWrapper>,
    pub writer: Box<WriteHalfWrapper>,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

pub trait StreamConnector {
    fn connect(&self, socket_addr: SocketAddr, logger: &Logger) -> ConnectionInfoFuture;
    fn connect_one(
        &self,
        ip_addrs: Vec<IpAddr>,
        target_hostname: &String,
        target_port: u16,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error>;
    fn split_stream(&self, stream: TcpStream, logger: &Logger) -> ConnectionInfo;
    fn split_stream_fut(&self, stream: TcpStream, logger: &Logger) -> ConnectionInfoFuture;
}

pub struct StreamConnectorReal {}

impl StreamConnector for StreamConnectorReal {
    fn connect(&self, socket_addr: SocketAddr, logger: &Logger) -> ConnectionInfoFuture {
        let future_logger = logger.clone();
        Box::new(
            TcpStream::connect(&socket_addr).then(move |result| match result {
                Ok(stream) => {
                    let local_addr = stream
                        .local_addr()
                        .expect("Connected stream has no local_addr");
                    let peer_addr = stream
                        .peer_addr()
                        .expect("Connected stream has no peer_addr");
                    let (read_half, write_half) = stream.split();
                    Ok(ConnectionInfo {
                        reader: Box::new(ReadHalfWrapperReal::new(read_half)),
                        writer: Box::new(WriteHalfWrapperReal::new(write_half)),
                        local_addr,
                        peer_addr,
                    })
                }
                Err(e) => {
                    future_logger.error(format!("Could not connect TCP stream to {}", socket_addr));
                    Err(e)
                }
            }),
        )
    }

    fn connect_one(
        &self,
        ip_addrs: Vec<IpAddr>,
        target_hostname: &String,
        target_port: u16,
        logger: &Logger,
    ) -> Result<ConnectionInfo, io::Error> {
        let mut last_error = io::Error::from(ErrorKind::Other);
        let mut socket_addrs_tried = vec![];

        for ip_addr in ip_addrs {
            let socket_addr = SocketAddr::new(ip_addr, target_port);

            match StdTcpStream::connect(&socket_addr) {
                Ok(stream) => {
                    logger.debug(format!("Connected new stream to {}", socket_addr));
                    let tokio_stream = TcpStream::from_std(stream, &Handle::default())
                        .expect("Tokio could not create a TcpStream");
                    return Ok(self.split_stream(tokio_stream, logger));
                }
                Err(e) => {
                    last_error = e;
                    socket_addrs_tried.push(format!("{}", socket_addr));
                    continue;
                }
            };
        }

        logger.error(format!(
            "Could not connect to any of the IP addresses supplied for {}: {:?}",
            target_hostname, socket_addrs_tried
        ));
        Err(last_error)
    }

    fn split_stream(&self, stream: TcpStream, _logger: &Logger) -> ConnectionInfo {
        let local_addr = stream
            .local_addr()
            .expect("Connected stream has no local_addr");
        let peer_addr = stream
            .peer_addr()
            .expect("Connected stream has no peer_addr");
        let (read_half, write_half) = stream.split();
        ConnectionInfo {
            reader: Box::new(ReadHalfWrapperReal::new(read_half)),
            writer: Box::new(WriteHalfWrapperReal::new(write_half)),
            local_addr,
            peer_addr,
        }
    }

    fn split_stream_fut(&self, stream: TcpStream, logger: &Logger) -> ConnectionInfoFuture {
        let connection_info_future =
            ok::<ConnectionInfo, io::Error>(self.split_stream(stream, logger));
        Box::new(connection_info_future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::lazy;
    use futures::future::ok;
    use std::io::Read;
    use std::io::Write;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::TcpListener;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::sync::mpsc::Sender;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::test_utils::find_free_port;
    use tokio;
    use tokio::io::read_exact;
    use tokio::io::write_all;
    use tokio::io::ErrorKind;

    #[test]
    fn stream_connector_can_fail_to_connect() {
        init_test_logging();
        let dead_port = find_free_port();
        let socket_addr = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), dead_port);
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};

        let future = subject.connect(socket_addr, &logger);

        FutureAsserter::new(future).assert(move |result| {
            assert_eq!(result.err().unwrap().kind(), ErrorKind::ConnectionRefused);
            success()
        });
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

        FutureAsserter::new(future).assert(move |result| {
            let connection_info = result.unwrap();
            assert_eq!(
                connection_info.local_addr.ip(),
                IpAddr::from_str("127.0.0.1").unwrap()
            );
            assert_eq!(connection_info.peer_addr, server.socket_addr());
            success()
        });
    }

    #[test]
    fn stream_connector_can_split_existing_stream() {
        let server = LittleTcpServer::start();
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};
        let stream = TcpStream::connect(&server.socket_addr()).wait().unwrap();

        let future = subject.split_stream_fut(stream, &logger);

        let connection_info = future.wait().unwrap();
        assert_eq!(
            connection_info.local_addr.ip(),
            IpAddr::from_str("127.0.0.1").unwrap()
        );
        assert_eq!(connection_info.peer_addr, server.socket_addr());
        let write_future = write_all(connection_info.writer, &b"Booga!"[..]);
        write_future.wait().unwrap();
        let read_future = read_exact(connection_info.reader, [0u8; 6]);
        assert_eq!(&read_future.wait().unwrap().1, b"Booga!");
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

        let (tx, rx) = mpsc::channel();
        let test_future = lazy(move || {
            let connection_result = subject.connect_one(
                ip_addrs,
                &"some hostname".to_string(),
                socket_addr.port(),
                &logger,
            );
            tx.send(connection_result).unwrap();
            Ok(())
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let connection_result = rx.recv().unwrap();

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

        let (connection_info_tx, connection_info_rx) = mpsc::channel();
        let test_future = lazy(move || {
            let connection_result = subject.connect_one(
                ip_addrs,
                &"some hostname".to_string(),
                socket_addr.port(),
                &logger,
            );
            connection_info_tx.send(connection_result).unwrap();
            Ok(())
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let connection_result = connection_info_rx.recv().unwrap();

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

        let (tx, rx) = mpsc::channel();
        let test_future = lazy(move || {
            let connection_result =
                subject.connect_one(ip_addrs, &"some hostname".to_string(), 9876, &logger);
            tx.send(connection_result).unwrap();
            Ok(())
        });

        thread::spawn(move || {
            tokio::run(test_future);
        });

        let connection_result = rx.recv().unwrap();

        assert!(connection_result.is_err());
        TestLogHandler::new().exists_log_matching("Could not connect to any of the IP addresses supplied for some hostname: \\[\"255\\.255\\.255\\.255:\\d+\"\\]");
    }

    struct FutureAsserter<I: 'static, E: 'static> {
        future: Box<Future<Item = I, Error = E> + Send>,
    }

    impl<I: 'static, E: 'static> FutureAsserter<I, E> {
        fn new(future: impl Future<Item = I, Error = E> + Send + 'static) -> FutureAsserter<I, E> {
            FutureAsserter {
                future: Box::new(future),
            }
        }

        fn assert<A: 'static>(self, assertions: A)
        where
            A: Send + FnOnce(Result<I, E>) -> Box<Future<Item = (), Error = ()>>,
        {
            let success = Arc::new(Mutex::new(false));
            let inner_success = Arc::clone(&success);

            tokio::run(self.future.then(move |result| {
                match assertions(result).wait() {
                    Ok(_) => {
                        let mut succ = inner_success.lock().unwrap();
                        *succ = true;
                    }
                    Err(_) => (),
                };
                ok(())
            }));
            assert!(*success.lock().unwrap());
        }
    }

    fn success() -> Box<Future<Item = (), Error = ()>> {
        Box::new(ok(()))
    }

    struct LittleTcpServer {
        port: u16,
        tx: Sender<()>,
        count_rx: Receiver<()>,
    }

    impl Drop for LittleTcpServer {
        fn drop(&mut self) {
            self.tx.send(()).unwrap();
        }
    }

    impl LittleTcpServer {
        fn start() -> LittleTcpServer {
            let listener =
                TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
                    .unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, rx) = mpsc::channel();
            let (count_tx, count_rx) = mpsc::channel();
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    if rx.try_recv().is_ok() {
                        return;
                    }
                    match listener.accept() {
                        Err(_) => continue,
                        Ok((mut stream, _)) => {
                            count_tx.send(()).is_ok();
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            loop {
                                if rx.try_recv().is_ok() {
                                    return;
                                }
                                match stream.read(&mut buf) {
                                    Err(_) => break,
                                    Ok(len) if len == 0 => break,
                                    Ok(_) => stream.write(&buf).unwrap(),
                                };
                            }
                        }
                    }
                }
            });
            LittleTcpServer { port, tx, count_rx }
        }

        fn socket_addr(&self) -> SocketAddr {
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), self.port)
        }

        fn count_connections(&self, wait_for: Duration) -> u16 {
            thread::sleep(wait_for);
            let mut count = 0;
            while self.count_rx.try_recv().is_ok() {
                count += 1;
            }
            count
        }
    }
}
