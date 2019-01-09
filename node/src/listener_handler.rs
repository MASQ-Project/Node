// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Recipient;
use actix::Syn;
use configuration::PortConfiguration;
use std::io;
use std::marker::Send;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use stream_messages::AddStreamMsg;
use sub_lib::logger::Logger;
use sub_lib::stream_connector::StreamConnector;
use sub_lib::stream_connector::StreamConnectorReal;
use sub_lib::tokio_wrappers::TokioListenerWrapper;
use sub_lib::tokio_wrappers::TokioListenerWrapperReal;
use tokio::prelude::Async;
use tokio::prelude::Future;

pub trait ListenerHandler: Send + Future {
    fn bind_port_and_configuration(
        &mut self,
        port: u16,
        port_configuration: PortConfiguration,
    ) -> io::Result<()>;
    fn bind_subs(&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>);
}

pub trait ListenerHandlerFactory: Send {
    fn make(&self) -> Box<ListenerHandler<Item = (), Error = ()>>;
}

pub struct ListenerHandlerReal {
    port: Option<u16>,
    port_configuration: Option<PortConfiguration>,
    listener: Box<TokioListenerWrapper>,
    add_stream_sub: Option<Recipient<Syn, AddStreamMsg>>,
    logger: Logger,
}

impl ListenerHandler for ListenerHandlerReal {
    fn bind_port_and_configuration(
        &mut self,
        port: u16,
        port_configuration: PortConfiguration,
    ) -> io::Result<()> {
        self.port = Some(port);
        self.port_configuration = Some(port_configuration);
        self.logger = Logger::new(&format!("ListenerHandler {}", port));
        self.listener
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), port))
    }

    fn bind_subs(&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>) {
        self.add_stream_sub = Some(add_stream_sub);
    }
}

impl Future for ListenerHandlerReal {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        loop {
            let result = self.listener.poll_accept();
            match result {
                Ok(Async::Ready((stream, _socket_addr))) => {
                    self.add_stream_sub
                        .as_ref()
                        .expect("Internal error: StreamHandlerPool unbound")
                        .try_send(AddStreamMsg::new(
                            StreamConnectorReal {}.split_stream(stream, &self.logger),
                            self.port,
                            self.port_configuration
                                .as_ref()
                                .expect("Internal error: port_configuration is None")
                                .clone(),
                        ))
                        .expect("Internal error: StreamHandlerPool is dead");
                }
                Err(e) => {
                    // TODO FIXME we should kill the entire node if there is a fatal error in a listener_handler
                    // TODO this could be exploitable and inefficient: if we keep getting errors, we go into a tight loop and do not return
                    self.logger
                        .error(format!("Could not accept connection: {}", e));
                }
                Ok(Async::NotReady) => return Ok(Async::NotReady),
            }
        }
    }
}

impl ListenerHandlerReal {
    fn new() -> ListenerHandlerReal {
        ListenerHandlerReal {
            port: None,
            port_configuration: None,
            listener: Box::new(TokioListenerWrapperReal::new()),
            add_stream_sub: None,
            logger: Logger::new("Uninitialized Listener"),
        }
    }
}

pub struct ListenerHandlerFactoryReal {}

impl ListenerHandlerFactory for ListenerHandlerFactoryReal {
    fn make(&self) -> Box<ListenerHandler<Item = (), Error = ()>> {
        Box::new(ListenerHandlerReal::new())
    }
}

impl ListenerHandlerFactoryReal {
    pub fn new() -> ListenerHandlerFactoryReal {
        ListenerHandlerFactoryReal {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Actor;
    use actix::Addr;
    use actix::System;
    use configuration::PortConfiguration;
    use node_test_utils::NullDiscriminatorFactory;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net;
    use std::net::Shutdown;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLog;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::test_utils::find_free_port;
    use tokio;
    use tokio::net::TcpStream;

    struct TokioListenerWrapperMock {
        log: Arc<TestLog>,
        bind_results: Vec<io::Result<()>>,
        poll_accept_results: RefCell<Vec<io::Result<Async<(TcpStream, SocketAddr)>>>>,
    }

    impl TokioListenerWrapperMock {
        fn new() -> TokioListenerWrapperMock {
            TokioListenerWrapperMock {
                log: Arc::new(TestLog::new()),
                bind_results: vec![],
                poll_accept_results: RefCell::new(vec![]),
            }
        }
    }

    impl TokioListenerWrapper for TokioListenerWrapperMock {
        fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
            self.log.log(format!("bind ({:?})", addr));
            self.bind_results.remove(0)
        }

        fn poll_accept(&mut self) -> io::Result<Async<(TcpStream, SocketAddr)>> {
            self.poll_accept_results.borrow_mut().remove(0)
        }
    }

    impl TokioListenerWrapperMock {
        pub fn bind_result(mut self, result: io::Result<()>) -> TokioListenerWrapperMock {
            self.bind_results.push(result);
            self
        }

        pub fn poll_accept_results(
            self,
            result_vec: Vec<Result<Async<(TcpStream, SocketAddr)>, io::Error>>,
        ) -> TokioListenerWrapperMock {
            result_vec
                .into_iter()
                .for_each(|result| self.poll_accept_results.borrow_mut().push(result));
            self
        }
    }

    #[test]
    #[should_panic(expected = "TcpListener not initialized - bind to a SocketAddr")]
    fn panics_if_tried_to_run_without_initializing() {
        let subject = ListenerHandlerReal::new();
        let _result = subject.wait();
    }

    #[test]
    fn handles_bind_port_and_configuration_failure() {
        let listener = TokioListenerWrapperMock::new()
            .bind_result(Err(Error::from(ErrorKind::AddrNotAvailable)));
        let discriminator_factory = NullDiscriminatorFactory::new();
        let mut subject = ListenerHandlerReal::new();
        subject.listener = Box::new(listener);

        let result = subject.bind_port_and_configuration(
            1234,
            PortConfiguration::new(vec![Box::new(discriminator_factory)], false),
        );

        assert_eq!(result.err().unwrap().kind(), ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn handles_bind_port_and_configuration_success() {
        let listener = TokioListenerWrapperMock::new().bind_result(Ok(()));
        let listener_log = listener.log.clone();
        let discriminator_factory =
            NullDiscriminatorFactory::new().discriminator_nature(vec![b"booga".to_vec()]);
        let mut subject = ListenerHandlerReal::new();
        subject.listener = Box::new(listener);

        let result = subject.bind_port_and_configuration(
            2345,
            PortConfiguration::new(vec![Box::new(discriminator_factory)], true),
        );

        assert_eq!(result.unwrap(), ());
        assert_eq!(
            listener_log.dump(),
            vec!(format!("bind (V4(0.0.0.0:2345))"))
        );
        assert_eq!(subject.port, Some(2345));
        let mut port_configuration = subject.port_configuration.unwrap();
        let factory = port_configuration.discriminator_factories.remove(0);
        let mut discriminator = factory.make();
        let chunk = discriminator.take_chunk().unwrap();
        assert_eq!(chunk.chunk, b"booga".to_vec());
        assert!(port_configuration.is_clandestine);
    }

    #[test]
    fn handles_connection_errors() {
        init_test_logging();
        let (stream_handler_pool, _, recording_arc) = make_recorder();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("handles_connection_errors");
            let add_stream_sub = start_recorder(stream_handler_pool);
            tx.send(add_stream_sub).is_ok();
            system.run();
        });

        let port = find_free_port();
        thread::spawn(move || {
            let add_stream_sub = rx.recv().unwrap();
            let tokio_listener_wrapper = TokioListenerWrapperMock::new()
                .bind_result(Ok(()))
                .poll_accept_results(vec![
                    Err(Error::from(ErrorKind::AddrInUse)),
                    Err(Error::from(ErrorKind::AddrNotAvailable)),
                    Ok(Async::NotReady),
                ]);
            let mut subject = ListenerHandlerReal::new();
            subject.listener = Box::new(tokio_listener_wrapper);
            subject.bind_subs(add_stream_sub);
            subject
                .bind_port_and_configuration(port, PortConfiguration::new(vec![], false))
                .unwrap();
            tokio::run(subject)
        });
        let tlh = TestLogHandler::new();
        tlh.await_log_containing("address not available", 1000);
        tlh.assert_logs_contain_in_order(vec![
            &format!(
                "ERROR: ListenerHandler {}: Could not accept connection: address in use",
                port
            )[..],
            &format!(
                "ERROR: ListenerHandler {}: Could not accept connection: address not available",
                port
            )[..],
        ]);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn converts_connections_into_connection_infos() {
        let (stream_handler_pool, awaiter, recording_arc) = make_recorder();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("converts_connections_into_connection_infos");
            let add_stream_sub = start_recorder(stream_handler_pool);
            tx.send(add_stream_sub).is_ok();
            system.run();
        });

        let port = find_free_port();
        thread::spawn(move || {
            let add_stream_sub = rx.recv().unwrap();
            let mut subject = ListenerHandlerReal::new();
            subject.bind_subs(add_stream_sub);
            subject
                .bind_port_and_configuration(port, PortConfiguration::new(vec![], false))
                .unwrap();
            tokio::run(subject)
        });

        // todo fixme wait for listener to be running in a better way
        thread::sleep(Duration::from_millis(100));

        let socket_addr = SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), port);
        let x = net::TcpStream::connect(socket_addr).unwrap();
        let y = net::TcpStream::connect(socket_addr).unwrap();
        let z = net::TcpStream::connect(socket_addr).unwrap();
        let (x_addr, y_addr, z_addr) = (
            x.local_addr().unwrap(),
            y.local_addr().unwrap(),
            z.local_addr().unwrap(),
        );
        x.shutdown(Shutdown::Both).unwrap();
        y.shutdown(Shutdown::Both).unwrap();
        z.shutdown(Shutdown::Both).unwrap();

        awaiter.await_message_count(3);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(
            recording
                .get_record::<AddStreamMsg>(0)
                .connection_info
                .peer_addr,
            x_addr
        );
        assert_eq!(
            recording
                .get_record::<AddStreamMsg>(1)
                .connection_info
                .peer_addr,
            y_addr
        );
        assert_eq!(
            recording
                .get_record::<AddStreamMsg>(2)
                .connection_info
                .peer_addr,
            z_addr
        );
        assert_eq!(recording.len(), 3);
    }

    fn start_recorder(recorder: Recorder) -> Recipient<Syn, AddStreamMsg> {
        let recorder_addr: Addr<Syn, Recorder> = recorder.start();
        recorder_addr.recipient::<AddStreamMsg>()
    }
}
