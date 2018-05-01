// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::marker::Send;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use actix::Subscriber;
use sub_lib::tcp_wrappers::TcpListenerWrapper;
use sub_lib::tcp_wrappers::TcpListenerWrapperReal;
use sub_lib::limiter::Limiter;
use sub_lib::logger::Logger;
use discriminator::DiscriminatorFactory;
use stream_handler_pool::AddStreamMsg;

pub trait ListenerHandler: Send {
    fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()>;
    fn bind_subs (&mut self, add_stream_sub: Box<Subscriber<AddStreamMsg> + Send>);
    fn handle_traffic (&mut self);
}

pub trait ListenerHandlerFactory: Send {
    fn make (&self) -> Box<ListenerHandler>;
}

pub struct ListenerHandlerReal {
    port: Option<u16>,
    discriminator_factories: Vec<Box<DiscriminatorFactory>>,
    listener: Box<TcpListenerWrapper>,
    add_stream_sub: Option<Box<Subscriber<AddStreamMsg> + Send>>,
    limiter: Limiter
}

impl ListenerHandler for ListenerHandlerReal {
    fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()> {
        self.port = Some (port);
        self.discriminator_factories = discriminator_factories;
        self.listener.bind (SocketAddr::new (IpAddr::V4 (Ipv4Addr::from (0)), port))
    }

    fn bind_subs (&mut self, add_stream_sub: Box<Subscriber<AddStreamMsg> + Send>) {
        self.add_stream_sub = Some (add_stream_sub);
    }

    fn handle_traffic(&mut self) {
        let logger = Logger::new (&format! ("{:?} Listener",
            &self.port.expect ("Tried to run without initializing")));
        while self.limiter.should_continue () {
            let (stream, _socket_addr) = match self.listener.accept() {
                Ok((stream, socket_addr)) => (stream, socket_addr),
                Err(e) => {
                    logger.log(format!("Accepting connection failed: {}", e));
                    continue;
                }
            };
            let discriminator_factories = self.discriminator_factories.iter ().map (|df| {df.duplicate ()}).collect ();
            self.add_stream_sub.as_ref ().expect ("Internal error: StreamHandlerPool unbound")
                .send (AddStreamMsg {
                    stream,
                    origin_port: self.port,
                    discriminator_factories,
                }).ok ();
        }
    }
}

impl ListenerHandlerReal {
    fn new () -> ListenerHandlerReal {
        ListenerHandlerReal {
            port: None,
            discriminator_factories: Vec::new (),
            listener: Box::new (TcpListenerWrapperReal::new ()),
            add_stream_sub: None,
            limiter: Limiter::new ()
        }
    }
}

pub struct ListenerHandlerFactoryReal {}

impl ListenerHandlerFactory for ListenerHandlerFactoryReal {
    fn make(&self) -> Box<ListenerHandler> {
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
    use std::net::Incoming;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use std::thread;
    use actix::SyncAddress;
    use actix::Actor;
    use actix::System;
    use sub_lib::limiter::Limiter;
    use sub_lib::tcp_wrappers::TcpStreamWrapper;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use sub_lib::dispatcher::Component;
    use test_utils::test_utils::TestLog;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;
    use node_test_utils::TcpStreamWrapperMock;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::Recording;
    use test_utils::test_utils::RecordAwaiter;
    use node_test_utils::NullDiscriminatorFactory;

    struct TcpListenerWrapperMock {
        log: Arc<TestLog>,
        bind_result: Option<io::Result<()>>,
        accept_results: RefCell<Vec<io::Result<(Box<TcpStreamWrapper>, SocketAddr)>>>,
        local_addr_result: RefCell<Option<io::Result<SocketAddr>>>
    }

    impl TcpListenerWrapperMock {
        fn new () -> TcpListenerWrapperMock {
            TcpListenerWrapperMock {
                log: Arc::new (TestLog::new ()),
                bind_result: None,
                accept_results: RefCell::new (vec! ()),
                local_addr_result: RefCell::new (None)
            }
        }
    }

    impl TcpListenerWrapper for TcpListenerWrapperMock {
        fn bind(&mut self, addr: SocketAddr) -> io::Result<()> {
            self.log.log (format! ("bind ({:?})", addr));
            self.bind_result.take ().unwrap ()
        }

        fn accept (&self) -> io::Result<(Box<TcpStreamWrapper>, SocketAddr)> {
            self.log.log (format! ("accept (...)"));
            self.accept_results.borrow_mut ().remove (0)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.local_addr_result.borrow_mut().take ().unwrap ()
        }

        fn incoming(&self) -> Incoming {unimplemented!()}
        fn set_ttl(&self, _ttl: u32) -> io::Result<()> {unimplemented!()}
        fn ttl(&self) -> io::Result<u32> {unimplemented!()}
        fn take_error(&self) -> io::Result<Option<io::Error>> {unimplemented!()}
        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {unimplemented!()}
    }

    #[test]
    fn handles_bind_port_and_discriminator_factories_failure () {
        let mut listener = TcpListenerWrapperMock::new ();
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
        let mut listener = TcpListenerWrapperMock::new ();
        listener.bind_result = Some (Ok (()));
        let listener_log = listener.log.clone ();
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature (Component::Hopper, vec! (vec! ()));
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
        assert_eq! (chunk.component, Component::Hopper);
        assert_eq! (subject.discriminator_factories.len (), 0);
    }

    #[test]
    fn handles_failed_accepts () {
        LoggerInitializerWrapperMock::new ().init ();
        let mut listener = TcpListenerWrapperMock::new ();
        listener.accept_results = RefCell::new (vec! (
            Err (Error::from (ErrorKind::BrokenPipe)),
            Err (Error::from (ErrorKind::AlreadyExists))
        ));
        let mut subject = ListenerHandlerReal::new ();
        subject.port = Some (1239);
        subject.listener = Box::new (listener);
        subject.limiter = Limiter::with_only (2);

        subject.handle_traffic();

        let tlh = TestLogHandler::new ();
        tlh.exists_log_containing("1239 Listener: Accepting connection failed: broken pipe");
        tlh.exists_log_containing("1239 Listener: Accepting connection failed: entity already exists");
    }

    #[test]
    fn handles_successful_accepts () {
        LoggerInitializerWrapperMock::new ().init ();
        let first_socket_addr = SocketAddr::from_str ("2.3.4.5:2349").unwrap ();
        let first_data = "first data".as_bytes ();
        let mut first_stream = Box::new (TcpStreamWrapperMock::new ());
        first_stream.read_results = vec! ((Vec::from (first_data), Ok (first_data.len ())));
        let first_stream_addr = first_stream.as_ref () as *const TcpStreamWrapperMock;
        let second_socket_addr = SocketAddr::from_str ("3.4.5.6:3459").unwrap ();
        let second_data = "second data".as_bytes ();
        let mut second_stream = Box::new (TcpStreamWrapperMock::new ());
        second_stream.read_results = vec! ((Vec::from (second_data), Ok (second_data.len ())));
        let second_stream_addr = second_stream.as_ref () as *const TcpStreamWrapperMock;
        let mut listener = TcpListenerWrapperMock::new ();
        listener.accept_results = RefCell::new (vec! (
            Ok ((first_stream, first_socket_addr)),
            Ok ((second_stream, second_socket_addr))
        ));
        listener.bind_result = Some (Ok (()));
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature(Component::Hopper, vec! ());
        let (recorder, recording_arc, awaiter) = make_recorder ();
        thread::spawn (move || {
            let system = System::new("test");
            let add_stream_sub = start_recorder (recorder);
            let mut subject = ListenerHandlerReal::new();
            subject.listener = Box::new(listener);
            subject.limiter = Limiter::with_only(2);
            subject.bind_port_and_discriminator_factories(1234,
                vec! (Box::new (discriminator_factory))).unwrap ();
            subject.bind_subs(add_stream_sub);

            subject.handle_traffic();

            system.run ();
        });

        awaiter.await_message_count (2);
        let recording = recording_arc.lock ().unwrap ();
        let first_msg = recording.get_record::<AddStreamMsg> (0);
        let second_msg = recording.get_record::<AddStreamMsg> (1);
        assert_eq! (first_msg.stream.as_ref () as *const TcpStreamWrapper, first_stream_addr);
        assert_eq! (first_msg.origin_port, Some (1234));
        assert_eq! (first_msg.discriminator_factories.len (), 1);
        assert_eq! (second_msg.stream.as_ref () as *const TcpStreamWrapper, second_stream_addr);
        assert_eq! (second_msg.origin_port, Some (1234));
        assert_eq! (second_msg.discriminator_factories.len (), 1);
        let tlh = TestLogHandler::new ();
        tlh.exists_no_log_containing("2.3.4.5:2349");
        tlh.exists_no_log_containing("3.4.5.6:3459");
    }

    fn make_recorder () -> (Recorder, Arc<Mutex<Recording>>, RecordAwaiter) {
        let recorder = Recorder::new ();
        let recording = recorder.get_recording ();
        let awaiter = recorder.get_awaiter();
        (recorder, recording, awaiter)
    }

    fn start_recorder (recorder: Recorder) -> Box<Subscriber<AddStreamMsg> + Send> {
        let recorder_addr: SyncAddress<_> = recorder.start ();
        recorder_addr.subscriber::<AddStreamMsg> ()
    }
}
