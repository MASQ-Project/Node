// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use futures::future::ok;
use tokio::io;
use tokio::io::AsyncRead;
use tokio::net::TcpStream;
use tokio::prelude::Future;
use sub_lib::logger::Logger;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::tokio_wrappers::ReadHalfWrapperReal;
use sub_lib::tokio_wrappers::WriteHalfWrapperReal;

pub type ConnectionInfoFuture = Box<Future<Item = ConnectionInfo, Error = io::Error> + Send>;

pub struct ConnectionInfo {
    pub reader: Box<ReadHalfWrapper>,
    pub writer: Box<WriteHalfWrapper>,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

pub trait StreamConnector {
    fn connect_pair (&self, socket_addr: SocketAddr, logger: &Logger) -> ConnectionInfoFuture;
    fn split_stream (&self, stream: TcpStream, logger: &Logger) -> ConnectionInfo;
    fn split_stream_fut(&self, stream: TcpStream, logger: &Logger) -> ConnectionInfoFuture;
}

pub struct StreamConnectorReal {}

impl StreamConnector for StreamConnectorReal {
    fn connect_pair(&self, socket_addr: SocketAddr, logger: &Logger) -> ConnectionInfoFuture {
        let future_logger = logger.clone ();
        Box::new(
            TcpStream::connect(&socket_addr)
                .then(move |result| {
                    match result {
                        Ok(stream) => {
                            let local_addr = stream.local_addr().expect("Connected stream has no local_addr");
                            let peer_addr = stream.peer_addr().expect("Connected stream has no peer_addr");
                            let (read_half, write_half) = stream.split();
                            Ok(ConnectionInfo {
                                reader: Box::new(ReadHalfWrapperReal::new(read_half)),
                                writer: Box::new(WriteHalfWrapperReal::new(write_half)),
                                local_addr,
                                peer_addr,
                            })
                        },
                        Err(e) => {
                            future_logger.error(format!("Could not connect TCP stream to {}", socket_addr));
                            Err(e)
                        },
                    }
                })
        )
    }

    fn split_stream (&self, stream: TcpStream, _logger: &Logger) -> ConnectionInfo {
        let local_addr = stream.local_addr().expect("Connected stream has no local_addr");
        let peer_addr = stream.peer_addr().expect("Connected stream has no peer_addr");
        let (read_half, write_half) = stream.split();
        ConnectionInfo {
            reader: Box::new(ReadHalfWrapperReal::new(read_half)),
            writer: Box::new(WriteHalfWrapperReal::new(write_half)),
            local_addr,
            peer_addr,
        }
    }

    fn split_stream_fut(&self, stream: TcpStream, logger: &Logger) -> ConnectionInfoFuture {
        let connection_info_future = ok::<ConnectionInfo, io::Error>(
            self.split_stream (stream, logger)
        );
        Box::new(connection_info_future)
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::net::Ipv4Addr;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::mpsc::Sender;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::thread;
    use futures::future::ok;
    use tokio;
    use tokio::io::write_all;
    use tokio::io::read_exact;
    use tokio::io::ErrorKind;
    use test_utils::test_utils::find_free_port;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLogHandler;

    #[test]
    fn stream_connector_can_fail_to_connect_pair() {
        init_test_logging();
        let dead_port = find_free_port();
        let socket_addr = SocketAddr::new(IpAddr::from_str ("127.0.0.1").unwrap (), dead_port);
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};

        let future = subject.connect_pair(socket_addr, &logger);

        FutureAsserter::new (future).assert (move |result| {
            assert_eq!(result.err().unwrap().kind(), ErrorKind::ConnectionRefused);
            success ()
        });
        TestLogHandler::new().exists_log_containing(&format!("ERROR: test: Could not connect TCP stream to 127.0.0.1:{}", dead_port));
    }

    #[test]
    fn stream_connector_can_succeed_to_connect_pair() {
        let server = LittleTcpServer::start ();
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};

        let future = subject.connect_pair(server.socket_addr (), &logger);

        FutureAsserter::new (future).assert (move |result| {
            let connection_info = result.unwrap ();
            assert_eq!(connection_info.local_addr.ip (), IpAddr::from_str ("127.0.0.1").unwrap ());
            assert_eq!(connection_info.peer_addr, server.socket_addr ());
            success ()
        });
    }

    #[test]
    fn stream_connector_can_split_existing_stream () {
        let server = LittleTcpServer::start ();
        let logger = Logger::new("test");
        let subject = StreamConnectorReal {};
        let stream = TcpStream::connect (&server.socket_addr ()).wait ().unwrap ();

        let future = subject.split_stream_fut(stream, &logger);

        let connection_info = future.wait ().unwrap ();
        assert_eq!(connection_info.local_addr.ip (), IpAddr::from_str ("127.0.0.1").unwrap ());
        assert_eq!(connection_info.peer_addr, server.socket_addr ());
        let write_future = write_all (connection_info.writer, &b"Booga!"[..]);
        write_future.wait ().unwrap ();
        let read_future = read_exact (connection_info.reader, [0u8; 6]);
        assert_eq! (&read_future.wait ().unwrap ().1, b"Booga!");
    }

    struct FutureAsserter<I: 'static, E: 'static> {
        future: Box<Future<Item = I, Error = E> + Send>,
    }

    impl<I: 'static, E: 'static> FutureAsserter<I, E> {
        fn new(future: impl Future<Item=I, Error=E> + Send + 'static) -> FutureAsserter<I, E> {
            FutureAsserter {
                future: Box::new(future),
            }
        }

        fn assert<A: 'static>(self, assertions: A) where A: Send + FnOnce(Result<I, E>) -> Box<Future<Item=(), Error=()>> {
            let success = Arc::new(Mutex::new(false));
            let inner_success = Arc::clone(&success);

            tokio::run(self.future
                .then( move |result| {
                    match assertions(result).wait() {
                        Ok(_) => {
                            let mut succ = inner_success.lock().unwrap();
                            *succ = true;
                        },
                        Err(_) => ()
                    };
                    ok(())
                })
            );
            assert!(*success.lock().unwrap());
        }
    }

    fn success () -> Box<Future<Item = (), Error = ()>> {
        Box::new (ok (()))
    }

    struct LittleTcpServer {
        port: u16,
        tx: Sender<()>,
    }

    impl Drop for LittleTcpServer {
        fn drop(&mut self) {
            self.tx.send(()).unwrap ();
        }
    }

    impl LittleTcpServer {
        fn start() -> LittleTcpServer {
            let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)).unwrap();
            let port = listener.local_addr().unwrap().port ();
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let mut buf = [0u8; 1024];
                loop {
                    if rx.try_recv().is_ok() { return; }
                    match listener.accept() {
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                            continue
                        },
                        Ok((mut stream, _)) => {
                            stream.set_read_timeout(Some(Duration::from_millis(100))).unwrap ();
                            loop {
                                if rx.try_recv().is_ok() { return; }
                                match stream.read(&mut buf) {
                                    Err(_) => break,
                                    Ok(len) if len == 0 => break,
                                    Ok(_) => stream.write (&buf).unwrap (),
                                };
                            }
                        }
                    }
                }
            });
            LittleTcpServer {port, tx}
        }

        fn socket_addr (&self) -> SocketAddr {
            SocketAddr::new(IpAddr::from_str ("127.0.0.1").unwrap (), self.port)
        }
    }
}