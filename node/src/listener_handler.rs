// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use actix::Recipient;
use actix::Syn;
use tokio::prelude::Async;
use tokio::prelude::Future;
use sub_lib::tokio_wrappers::TokioListenerWrapper;
use sub_lib::tokio_wrappers::TokioListenerWrapperReal;
use sub_lib::logger::Logger;
use discriminator::DiscriminatorFactory;
use stream_messages::AddStreamMsg;

pub trait ListenerHandler: Send + Future {
    fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()>;
    fn bind_subs (&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>);
}

pub trait ListenerHandlerFactory: Send {
    fn make (&self) -> Box<ListenerHandler<Item=(), Error=()>>;
}

pub struct ListenerHandlerReal {
    port: Option<u16>,
    discriminator_factories: Vec<Box<DiscriminatorFactory>>,
    listener: Box<TokioListenerWrapper>,
    add_stream_sub: Option<Recipient<Syn, AddStreamMsg>>,
}

impl ListenerHandler for ListenerHandlerReal {
    fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()> {
        self.port = Some (port);
        self.discriminator_factories = discriminator_factories;
        self.listener.bind (SocketAddr::new (IpAddr::V4 (Ipv4Addr::from (0)), port))
    }

    fn bind_subs (&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>) {
        self.add_stream_sub = Some (add_stream_sub);
    }
}

impl Future for ListenerHandlerReal {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        let logger = Logger::new (&format! ("{:?} Listener",
                                            &self.port.expect ("Tried to run without initializing"))
        );
        loop {
            let result = self.listener.poll_accept();
            match result {
                Ok(Async::Ready((stream, _socket_addr))) => {
                    let discriminator_factories = self.discriminator_factories.iter ()
                        .map (|df| {df.duplicate ()}).collect ();
                    self.add_stream_sub.as_ref ().expect ("Internal error: StreamHandlerPool unbound")
                        .try_send (AddStreamMsg {
                            stream: Some(stream),
                            origin_port: self.port,
                            discriminator_factories,
                        }).expect ("Internal error: StreamHandlerPool is dead");
                },
                Err(e) => {
                    // TODO FIXME we should kill the entire node if there is a fatal error in a listener_handler
                    // TODO this could be... inefficient, if we keep getting non-fatal errors. (we do not return)
                    logger.log(format!("Accepting connection failed: {}", e));
                },
                Ok(Async::NotReady) => {
                    return Ok(Async::NotReady)
                },
            }
        }
    }
}

impl ListenerHandlerReal {
    fn new () -> ListenerHandlerReal {
        ListenerHandlerReal {
            port: None,
            discriminator_factories: Vec::new (),
            listener: Box::new (TokioListenerWrapperReal::new ()),
            add_stream_sub: None,
        }
    }
}

pub struct ListenerHandlerFactoryReal {}

impl ListenerHandlerFactory for ListenerHandlerFactoryReal {
    fn make(&self) -> Box<ListenerHandler<Item=(), Error=()>> {
        Box::new (ListenerHandlerReal::new ())
    }
}

impl ListenerHandlerFactoryReal {
    pub fn new () -> ListenerHandlerFactoryReal {
        ListenerHandlerFactoryReal {}
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::thread;
    use actix::Actor;
    use actix::Addr;
    use actix::Arbiter;
    use actix::msgs;
    use actix::System;
    use tokio;
    use tokio::net::TcpStream;
    use node_test_utils::NullDiscriminatorFactory;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLog;
    use test_utils::test_utils::TestLogHandler;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::make_recorder;

    struct TokioListenerWrapperMock {
        log: Arc<TestLog>,
        bind_result: Option<io::Result<()>>,
        poll_accept_results: RefCell<Vec<io::Result<Async<(TcpStream, SocketAddr)>>>>
    }

    impl TokioListenerWrapperMock {
        fn new () -> TokioListenerWrapperMock {
            TokioListenerWrapperMock {
                log: Arc::new (TestLog::new ()),
                bind_result: None,
                poll_accept_results: RefCell::new(vec!())
            }
        }
    }

    impl TokioListenerWrapper for TokioListenerWrapperMock {
        fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
            self.log.log (format! ("bind ({:?})", addr));
            self.bind_result.take ().unwrap ()
        }

        fn poll_accept (&mut self) -> io::Result<Async<(TcpStream, SocketAddr)>> {
            self.poll_accept_results.borrow_mut().remove(0)
        }
    }

    #[test]
    #[should_panic (expected = "Tried to run without initializing")]
    fn start_a_listener_handler_and_get_panicked() {
        let listener_handler_future = ListenerHandlerReal::new();
            let waited = listener_handler_future.wait();
            match waited {
                Ok(_) => panic!("thread did not panic!"),
                Err(_) => {},
            };
    }

    #[test]
    fn handles_bind_port_and_discriminator_factories_failure () {
        let mut listener = TokioListenerWrapperMock::new ();
        listener.bind_result = Some (Err (Error::from (ErrorKind::AddrNotAvailable)));
        let discriminator_factory = NullDiscriminatorFactory::new ();
        let mut subject = ListenerHandlerReal::new ();
        subject.listener = Box::new (listener);

        let result = subject.bind_port_and_discriminator_factories (1234,
            vec! (Box::new (discriminator_factory)));

        assert_eq! (result.err ().unwrap ().kind (), ErrorKind::AddrNotAvailable);
    }

    #[test]
    fn handles_bind_port_and_discriminator_factories_success () {
        let mut listener = TokioListenerWrapperMock::new ();
        listener.bind_result = Some (Ok (()));
        let listener_log = listener.log.clone ();
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature (vec! (b"booga".to_vec()));
        let mut subject = ListenerHandlerReal::new ();
        subject.listener = Box::new (listener);

        let result = subject.bind_port_and_discriminator_factories (2345,
            vec! (Box::new (discriminator_factory)));

        assert_eq! (result.unwrap (), ());
        assert_eq! (listener_log.dump (), vec! (format! ("bind (V4(0.0.0.0:2345))")));
        assert_eq! (subject.port, Some (2345));
        let factory = subject.discriminator_factories.remove (0);
        let mut discriminator = factory.make ();
        let chunk = discriminator.take_chunk ().unwrap ();
        assert_eq! (chunk.chunk, b"booga".to_vec());
        assert_eq! (subject.discriminator_factories.len (), 0);
    }

    #[test]
    fn handles_failed_accepts () {
        init_test_logging();
        let mut listener = TokioListenerWrapperMock::new ();
        listener.poll_accept_results = RefCell::new (vec! (
            Err (Error::from (ErrorKind::BrokenPipe)),
            Err (Error::from (ErrorKind::AlreadyExists)),
            Ok (Async::NotReady)
        ));
        let mut subject = ListenerHandlerReal::new ();
        subject.port = Some (1239);
        subject.listener = Box::new (listener);

        let _result = subject.poll();

        let tlh = TestLogHandler::new ();
        tlh.exists_log_containing("1239 Listener: Accepting connection failed: broken pipe");
        tlh.exists_log_containing("1239 Listener: Accepting connection failed: entity already exists");
    }

    // This is a bad test, but A) it passes (really, not false positive), and B) it's about to be merged out of existence,
    // so I have removed references to httpbin.org but not improved it.
    #[test]
    #[allow (unused_variables)] // 'result' below must not become '_' or disappear, or the test will not run properly
    fn handles_successful_accepts_integration () {
        init_test_logging();
        let example_com_socket_addr = SocketAddr::from_str ("93.184.216.34:80").unwrap ();
        let future = TcpStream::connect(&example_com_socket_addr).then(move |result| {
            match result {
                Ok(stream) => {
                    let expected_peer_addr = stream.peer_addr().unwrap();
                    let mut listener = TokioListenerWrapperMock::new ();
                    listener.poll_accept_results = RefCell::new (vec! (
                        Ok (Async::Ready((stream, example_com_socket_addr))),
                        Ok (Async::NotReady)
                    ));
                    listener.bind_result = Some (Ok (()));
                    let discriminator_factory = NullDiscriminatorFactory::new ()
                        .discriminator_nature(vec! ());
                    let (recorder, awaiter, recording_arc) = make_recorder ();
                    thread::spawn (move || {
                        let system = System::new("test");
                        let add_stream_sub = start_recorder (recorder);
                        let mut subject = ListenerHandlerReal::new();
                        subject.listener = Box::new(listener);
                        subject.bind_port_and_discriminator_factories(1234,
                                                                      vec! (Box::new (discriminator_factory))).unwrap ();
                        subject.bind_subs(add_stream_sub);

                        let _result = subject.poll();

                        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
                        system.run ();
                    });

                    awaiter.await_message_count (1);
                    let recording = recording_arc.lock ().unwrap ();
                    let first_msg = recording.get_record::<AddStreamMsg> (0);
                    let actual_peer_addr = first_msg.stream.as_ref().unwrap().peer_addr().unwrap();
                    assert_eq! (actual_peer_addr, expected_peer_addr);
                    assert_eq! (first_msg.origin_port, Some (1234));
                    assert_eq! (first_msg.discriminator_factories.len (), 1);
                    let tlh = TestLogHandler::new ();
                    tlh.exists_no_log_containing("93.184.216.34:80");
                    return Ok(())
                },
                Err(e) => {
                    panic!("FAILED Could not connect to example.com, got: {:?}", e)
                }
            }
        });

        let result = thread::spawn(move || {
            tokio::run(future);
        }).join();
    }

    fn start_recorder (recorder: Recorder) -> Recipient<Syn, AddStreamMsg> {
        let recorder_addr: Addr<Syn, Recorder> = recorder.start ();
        recorder_addr.recipient::<AddStreamMsg> ()
    }
}
