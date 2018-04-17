// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::io;
use std::net::SocketAddr;
use std::net::Shutdown;
use std::string::ToString;
use std::thread;
use std::time::Duration;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::ResponseType;
use actix::Subscriber;
use actix::SyncAddress;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::logger::Logger;
use sub_lib::dispatcher;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::dispatcher::Endpoint;
use sub_lib::node_addr::NodeAddr;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::utils::indicates_dead_stream;
use discriminator::Discriminator;
use discriminator::DiscriminatorFactory;

trait StreamReader {
    fn handle_traffic (&mut self);
}

trait StreamWriter {
    fn transmit (&mut self, data: &[u8]) -> io::Result<usize>;
}

pub struct AddStreamMsg {
    pub stream: Box<TcpStreamWrapper>,
    pub origin_port: Option<u16>,
    pub discriminator_factories: Vec<Box<DiscriminatorFactory>>
}

impl ResponseType for AddStreamMsg {
    type Item = ();
    type Error = io::Error;
}

#[derive (Debug)]
pub struct RemoveStreamMsg {
    pub socket_addr: SocketAddr
}

impl ResponseType for RemoveStreamMsg {
    type Item = ();
    type Error = io::Error;
}

pub struct StreamHandlerPoolSubs {
    pub add_sub: Box<Subscriber<AddStreamMsg> + Send>,
    pub transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
    pub remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>,
    pub bind: Box<Subscriber<PoolBindMessage> + Send>,
}

impl Clone for StreamHandlerPoolSubs {
    fn clone(&self) -> Self {
        StreamHandlerPoolSubs {
            add_sub: self.add_sub.clone (),
            transmit_sub: self.transmit_sub.clone (),
            remove_sub: self.remove_sub.clone (),
            bind: self.bind.clone(),
        }
    }
}

struct StreamReaderReal {
    stream: Box<TcpStreamWrapper>,
    origin_port: Option<u16>,
    ibcd_sub: Box<Subscriber<dispatcher::InboundClientData> + Send>,
    remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>,
    discriminators: Vec<Box<Discriminator>>,
    logger: Logger
}

impl StreamReader for StreamReaderReal {
    fn handle_traffic(&mut self) {
        let port = self.stream.local_addr().expect ("Internal error").port ();
        self.logger.debug (format! ("StreamReader for port {} starting with no read timeout", port));
        self.stream.set_read_timeout (None).expect ("Internal error");
        let mut buf: [u8; 0x10000] = [0; 0x10000];
        loop {
            match self.stream.read(&mut buf) {
                Ok(length) => {
                    if length == 0 {
                        thread::sleep (Duration::from_millis (100));
                    } else {
                        self.logger.debug (format! ("Read {}-byte chunk from port {}", length, port));
                        self.wrangle_discriminators(&buf, length)
                    }
                },
                Err(e) => if indicates_dead_stream (e.kind ()) {
                    self.logger.debug (format! ("Stream on port {} is dead: {}", port, e));
                    let socket_addr = self.stream.peer_addr ().expect ("Internal error");
                    self.remove_sub.send (RemoveStreamMsg {socket_addr}).expect ("Internal error");
                    self.stream.shutdown (Shutdown::Both).ok (); // can't do anything about failure
                    break;
                }
                else {
                    self.logger.warning (format! ("Continuing after read error on port {}: {}", port, e.to_string ()))
                }
            }
        }
        self.logger.debug (format! ("StreamReader for port {} shutting down", port));
    }
}

impl StreamReaderReal {
    fn new (stream: Box<TcpStreamWrapper>, origin_port: Option<u16>, ibcd_sub: Box<Subscriber<dispatcher::InboundClientData> + Send>,
            remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> StreamReaderReal {
        let socket_addr = stream.peer_addr ().expect ("Internal error");
        let name = format! ("Dispatcher for {:?}", socket_addr);
        StreamReaderReal {
            stream,
            origin_port,
            ibcd_sub,
            remove_sub,
            // Skinny implementation
            discriminators: vec! (discriminator_factories[0].make ()),
            logger: Logger::new (&name)
        }
    }

    fn wrangle_discriminators (&mut self, buf: &[u8], length: usize) {
        // Skinny implementation
        let discriminator = self.discriminators[0].as_mut ();
        self.logger.debug (format! ("Adding {} bytes to discriminator", length));
        discriminator.add_data (&buf[..length]);
        loop {
            match discriminator.take_chunk() {
                Some(unmasked_chunk) => {
                    let msg = dispatcher::InboundClientData {
                        socket_addr: self.stream.peer_addr().expect ("Internal error"),
                        origin_port: self.origin_port,
                        component: unmasked_chunk.component,
                        data: unmasked_chunk.chunk.clone ()
                    };
                    self.logger.debug (format! ("Discriminator framed and unmasked {} bytes for {}; transmitting to {:?} via Hopper",
                                                 unmasked_chunk.chunk.len (), msg.socket_addr, unmasked_chunk.component));
                    self.ibcd_sub.send(msg).expect("Internal error");
                }
                None => {
                    self.logger.debug (format!("Discriminator has no more data framed"));
                    break
                }
            }
        }
    }
}

struct StreamWriterReal {
    stream: Box<TcpStreamWrapper>,
    remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>,
    logger: Logger
}

impl StreamWriter for StreamWriterReal {
    fn transmit(&mut self, data: &[u8]) -> io::Result<usize> {
        match self.stream.write (data) {
            Ok (size) => Ok (size),
            Err (e) => {
                if indicates_dead_stream (e.kind ()) {
                    let socket_addr = self.stream.peer_addr ().expect ("Internal error");
                    self.stream.shutdown (Shutdown::Both).ok (); // can't do anything about failure
                    self.remove_sub.send (RemoveStreamMsg {socket_addr}).expect ("Internal error");
                }
                self.logger.log (format! ("Cannot transmit {} bytes: {}", data.len (), e.to_string ()));
                Err(e)
            }
        }
    }
}

impl StreamWriterReal {
    fn new (stream: Box<TcpStreamWrapper>, remove_sub: Box<Subscriber<RemoveStreamMsg> + Send>) -> StreamWriterReal {
        let socket_addr = stream.peer_addr ().expect ("Internal error");
        let name = format! ("Dispatcher for {:?}", socket_addr);
        let logger = Logger::new (&name[..]);
        StreamWriterReal {
            stream,
            remove_sub,
            logger
        }
    }
}

pub struct StreamHandlerPool {
    stream_writers: HashMap<SocketAddr, Box<StreamWriter>>,
    dispatcher_subs: Option<DispatcherSubs>,
    self_subs: Option<StreamHandlerPoolSubs>,
    logger: Logger
}

impl Actor for StreamHandlerPool {
    type Context = Context<Self>;
}

impl StreamHandlerPool {

    pub fn new() -> StreamHandlerPool {
        StreamHandlerPool {
            stream_writers: HashMap::new (),
            dispatcher_subs: None,
            self_subs: None,
            logger: Logger::new ("Dispatcher"),
        }
    }

    pub fn make_subs_from(pool_addr: &SyncAddress<StreamHandlerPool>) -> StreamHandlerPoolSubs {
        StreamHandlerPoolSubs {
            add_sub: pool_addr.subscriber::<AddStreamMsg>(),
            transmit_sub: pool_addr.subscriber::<TransmitDataMsg>(),
            remove_sub: pool_addr.subscriber::<RemoveStreamMsg>(),
            bind: pool_addr.subscriber::<PoolBindMessage>(),
        }
    }

    fn set_up_stream_reader (&mut self, read_stream: Box<TcpStreamWrapper>, origin_port: Option<u16>,
            discriminator_factories: Vec<Box<DiscriminatorFactory>>) {
        let ibcd_sub: Box<Subscriber<dispatcher::InboundClientData> + Send> =
            self.dispatcher_subs.as_ref().expect("StreamHandlerPool is unbound").ibcd_sub.clone ();
        let remove_sub: Box<Subscriber<RemoveStreamMsg> + Send> =
            self.self_subs.as_ref().expect("StreamHandlerPool is unbound").remove_sub.clone ();
        thread::spawn(move || {
            let ibcd_sub = ibcd_sub.clone ();
            let remove_sub = remove_sub.clone();
            let mut stream_reader = StreamReaderReal::new(read_stream, origin_port,
                ibcd_sub, remove_sub, discriminator_factories);
            stream_reader.handle_traffic();
        });
    }

    fn set_up_stream_writer (&mut self, write_stream: Box<TcpStreamWrapper>) {
        let socket_addr = write_stream.peer_addr ().expect ("Internal error");
        let stream_writer = StreamWriterReal::new (
            write_stream,
            self.self_subs.as_ref().expect("StreamHandlerPool is unbound").remove_sub.clone (),
        );
        self.stream_writers.insert (socket_addr, Box::new (stream_writer));
    }
}

impl Handler<AddStreamMsg> for StreamHandlerPool {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) -> Self::Result {
        let stream_ref = msg.stream.as_ref();
        let read_stream = match stream_ref.try_clone() {
            Ok(stream) => stream,
            Err(e) => return Err (e)
        };
        let write_stream = match stream_ref.try_clone() {
            Ok(stream) => stream,
            Err(e) => return Err (e)
        };

        self.set_up_stream_writer(write_stream);
        self.set_up_stream_reader(read_stream, msg.origin_port, msg.discriminator_factories);
        Ok (())
    }
}

impl Handler<RemoveStreamMsg> for StreamHandlerPool {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) -> Self::Result {
        match self.stream_writers.remove (&msg.socket_addr) {
            Some (_) => Ok (()),
            None => Ok (())
        }
    }
}

impl Handler<TransmitDataMsg> for StreamHandlerPool {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) -> Self::Result {
        let node_addr = match msg.endpoint {
            Endpoint::Key (_) => unimplemented!(),
            Endpoint::Ip (_) => unimplemented!(),
            Endpoint::Socket (socket_addr) => NodeAddr::from (&socket_addr)
        };
        // TODO: Taking just the first address should be eliminated when this moves into the StreamHandlerPool.
        let mut socket_addrs: Vec<SocketAddr> = node_addr.into ();
        let socket_addr = socket_addrs.remove (0);

        match self.stream_writers.get_mut (&socket_addr) {
            Some (stream_writer_box) => {
                match stream_writer_box.transmit (&msg.data[..]) {
                    Ok (_) => Ok (()),
                    Err (_) => Ok (())
                }
            },
            None => {
                self.logger.log (format! ("Cannot transmit {} bytes to {:?}: nonexistent stream",
                    msg.data.len (), socket_addr));
                return Ok (())
            }
        }
    }
}

pub struct PoolBindMessage {
    pub dispatcher_subs: DispatcherSubs,
    pub stream_handler_pool_subs: StreamHandlerPoolSubs
}

impl Debug for PoolBindMessage {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write! (f, "PoolBindMessage")
    }
}

impl ResponseType for PoolBindMessage {
    type Item = ();
    type Error = io::Error;
}

impl Handler<PoolBindMessage> for StreamHandlerPool {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: PoolBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.dispatcher_subs = Some(msg.dispatcher_subs);
        self.self_subs = Some(msg.stream_handler_pool_subs);
        Ok (())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use std::cell::RefCell;
    use std::ops::Deref;
    use std::sync::mpsc;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use sub_lib::dispatcher::Component;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use test_utils::test_utils::make_peer_actors;
    use test_utils::test_utils::make_peer_actors_from;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::TestLogHandler;
    use node_test_utils::NullDiscriminatorFactory;
    use node_test_utils::TcpStreamWrapperMock;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use node_test_utils::wait_until;

    #[test]
    fn a_newly_added_stream_produces_stream_handler_that_sends_received_data_to_dispatcher () {
        let dispatcher = Recorder::new ();
        let dispatcher_recording = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let origin_port = Some (8081);
        let one_http_req = Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes());
        let one_http_req_a = one_http_req.clone ();
        let another_http_req = Vec::from("DELETE http://there.com HTTP/1.1\r\n\r\n".as_bytes());
        let another_http_req_a = another_http_req.clone ();
        let athird_http_req = Vec::from("HEAD http://everywhere.com HTTP/1.1\r\n\r\n".as_bytes());
        let a_third_http_req_a = athird_http_req.clone ();
        let mut second_chunk = Vec::new ();
        second_chunk.extend (another_http_req.clone ());
        second_chunk.extend (Vec::from ("glorp".as_bytes ()));
        second_chunk.extend (athird_http_req.clone ());
        let awaiter = dispatcher.get_awaiter ();
        let mut read_stream = TcpStreamWrapperMock::new();
        let read_stream_log = read_stream.log.clone ();
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature(Component::ProxyServer, vec! (
                one_http_req.clone (),
                another_http_req.clone (),
                athird_http_req.clone ()
            ));
        thread::spawn (move || {
            let system = System::new("test");
            read_stream.peer_addr_result = Ok(socket_addr);
            read_stream.set_read_timeout_results = RefCell::new (vec! (Ok (())));
            read_stream.read_results = vec!(
                (one_http_req.clone(), Ok(one_http_req.len())),
                (second_chunk.clone (), Ok(second_chunk.len())),
                (Vec::new (), Err(Error::from(ErrorKind::BrokenPipe))),
                (one_http_req.clone(), Ok(one_http_req.len ()))
            );
            read_stream.shutdown_results = RefCell::new (vec! (Ok (())));
            let mut write_stream = TcpStreamWrapperMock::new();
            write_stream.peer_addr_result = Ok (socket_addr);
            let mut stream = TcpStreamWrapperMock::new();
            stream.try_clone_results = RefCell::new(vec!(Ok(Box::new(read_stream)), Ok(Box::new(write_stream))));
            let subject = StreamHandlerPool::new();
            let subject_addr: SyncAddress<_> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None);

            subject_subs.bind.send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();
            subject_subs.add_sub.send(AddStreamMsg {
                stream: Box::new(stream),
                origin_port,
                discriminator_factories: vec! (Box::new (discriminator_factory))
            }).ok ();

            system.run ();
        });

        awaiter.await_message_count (3);
        let recording = dispatcher_recording.lock ().unwrap ();
        assert_eq! (recording.get_record::<dispatcher::InboundClientData> (0), &dispatcher::InboundClientData {
            socket_addr,
            origin_port,
            component: Component::ProxyServer,
            data: one_http_req_a
        });
        assert_eq! (recording.get_record::<dispatcher::InboundClientData> (1), &dispatcher::InboundClientData {
            socket_addr,
            origin_port,
            component: Component::ProxyServer,
            data: another_http_req_a
        });
        assert_eq! (recording.get_record::<dispatcher::InboundClientData> (2), &dispatcher::InboundClientData {
            socket_addr,
            origin_port,
            component: Component::ProxyServer,
            data: a_third_http_req_a
        });
        assert_eq! (read_stream_log.lock ().unwrap ().dump ()[0], "set_read_timeout (None)");
    }

    #[test]
    fn non_dead_stream_read_errors_log_but_do_not_terminate_handling () {
        LoggerInitializerWrapperMock::new ().init ();
        let dispatcher = Recorder::new ();
        let dispatcher_recording = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let origin_port = Some (4321);
        let http_req = Vec::from("GET http://here.com HTTP/1.1\r\n\r\n".as_bytes());
        let http_req_a = http_req.clone ();
        let awaiter = dispatcher.get_awaiter ();
        let mut read_stream = TcpStreamWrapperMock::new();
        read_stream.peer_addr_result = Ok(socket_addr);
        read_stream.set_read_timeout_results = RefCell::new (vec! (Ok (())));
        read_stream.read_results = vec!(
            (Vec::new (), Err(Error::from(ErrorKind::Other))), // no shutdown
            (http_req.clone(), Ok(http_req.len ())),
            (Vec::new (), Err(Error::from(ErrorKind::BrokenPipe))) // shutdown
        );
        read_stream.shutdown_results = RefCell::new (vec! (Ok (())));
        let mut write_stream = TcpStreamWrapperMock::new();
        write_stream.peer_addr_result = Ok (socket_addr);
        let mut stream = TcpStreamWrapperMock::new();
        stream.try_clone_results = RefCell::new(vec!(Ok(Box::new(read_stream)), Ok(Box::new(write_stream))));
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature(Component::ProxyServer, vec! (http_req.clone ()));
        thread::spawn (move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new();
            let subject_addr: SyncAddress<_> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None);

            subject_subs.bind.send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();

            subject_subs.add_sub.send(AddStreamMsg {
                stream: Box::new(stream),
                origin_port,
                discriminator_factories: vec! (Box::new (discriminator_factory))
            }).ok ();

            system.run ();
        });

        awaiter.await_message_count (1);
        TestLogHandler::new ().exists_log_matching("ThreadId\\(\\d+\\): WARN: Dispatcher for V4\\(1\\.2\\.3\\.4:5678\\): Continuing after read error on port 6789: other os error");
        let recording = dispatcher_recording.lock ().unwrap ();
        assert_eq! (recording.get_record::<dispatcher::InboundClientData> (0), &dispatcher::InboundClientData {
            socket_addr,
            origin_port,
            component: Component::ProxyServer,
            data: http_req_a
        });
    }

    #[test]
    fn receiving_from_a_dead_existing_stream_removes_writer_but_writes_no_error_log () {
        LoggerInitializerWrapperMock::new ().init ();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5676").unwrap();
        let mut read_stream = TcpStreamWrapperMock::new();
        read_stream.peer_addr_result = Ok(socket_addr);
        read_stream.set_read_timeout_results = RefCell::new (vec! (Ok(())));
        read_stream.read_results = vec! ((Vec::new (), Err (Error::from (ErrorKind::ConnectionRefused))));
        read_stream.shutdown_results = RefCell::new (vec! (Ok (())));
        let read_stream_log = read_stream.log.clone ();
        let mut write_stream = TcpStreamWrapperMock::new();
        write_stream.peer_addr_result = Ok(socket_addr);
        let mut stream = TcpStreamWrapperMock::new();
        stream.try_clone_results = RefCell::new(vec!(Ok(Box::new(read_stream)), Ok(Box::new(write_stream))));
        let discriminator_factory = NullDiscriminatorFactory::new ()
            .discriminator_nature(Component::ProxyServer, vec! (Vec::from (&b"booga"[..])));
        let (sub_tx, sub_rx) = mpsc::channel ();
        thread::spawn (move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new();
            let subject_addr: SyncAddress<_> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();

            sub_tx.send (subject_subs).unwrap ();
            system.run();
        });

        let subject_subs = sub_rx.recv ().unwrap ();
        subject_subs.add_sub.send(AddStreamMsg {
            stream: Box::new(stream),
            origin_port: None,
            discriminator_factories: vec! (Box::new (discriminator_factory))
        }).ok ();
        wait_until (|| {
            read_stream_log.lock ().unwrap ().dump ().len () == 3
        });

        subject_subs.transmit_sub.send(TransmitDataMsg { endpoint: Endpoint::Socket(socket_addr), data: vec!(0x12, 0x34) }).ok ();
        TestLogHandler::new ().exists_no_log_matching("WARN.*1\\.2\\.3\\.4:5676.*Continuing after read error");

        assert_eq! (read_stream_log.lock ().unwrap ().dump (), vec! (
            "set_read_timeout (None)",
            "read (65536-byte buf)",
            "shutdown (Both)"
        ));
    }

    #[test]
    fn transmitting_down_a_smoothly_operating_existing_stream_works_fine () {
        LoggerInitializerWrapperMock::new ().init ();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let mut write_stream = TcpStreamWrapperMock::new();
        write_stream.peer_addr_result = Ok (socket_addr);
        write_stream.write_results = vec! (Ok (2));
        let write_stream_params_arc = write_stream.write_params.clone ();
        let system = System::new("test");
        let mut read_stream = TcpStreamWrapperMock::new();
        read_stream.peer_addr_result = Ok(socket_addr);
        let mut stream = TcpStreamWrapperMock::new();
        stream.try_clone_results = RefCell::new(vec!(Ok(Box::new(read_stream)), Ok(Box::new(write_stream))));
        let subject = StreamHandlerPool::new();
        let subject_addr: SyncAddress<_> = subject.start();
        let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
        let peer_actors = make_peer_actors();
        subject_subs.bind.send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();

        subject_subs.add_sub.send(AddStreamMsg {
            stream: Box::new(stream),
            origin_port: None,
            discriminator_factories: vec! ()
        }).ok ();

        subject_subs.transmit_sub.send(TransmitDataMsg {endpoint: Endpoint::Socket(socket_addr), data: vec!(0x12, 0x34)}).ok ();

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();
        let write_stream_params = write_stream_params_arc.lock ().unwrap ();
        TestLogHandler::new ().exists_no_log_matching("ERROR:.*1\\.2\\.3\\.4:5673");
        assert_eq! (write_stream_params.deref (), &vec! (vec! (0x12, 0x34)));
    }

    #[test]
    fn transmitting_down_a_recalcitrant_existing_stream_produces_an_error_log_and_removes_writer () {
        LoggerInitializerWrapperMock::new ().init ();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5679").unwrap();
        let mut read_stream = TcpStreamWrapperMock::new();
        read_stream.peer_addr_result = Ok(socket_addr);
        read_stream.read_results = vec! ((Vec::from ("block".as_bytes ()), Ok(5)));
        let mut write_stream = TcpStreamWrapperMock::new();
        write_stream.peer_addr_result = Ok(socket_addr);
        write_stream.write_results = vec!(Err(Error::from(ErrorKind::BrokenPipe)));
        write_stream.shutdown_results = RefCell::new (vec! (Ok (())));
        let write_stream_log = write_stream.log.clone ();
        let mut stream = TcpStreamWrapperMock::new();
        stream.try_clone_results = RefCell::new(vec!(Ok(Box::new(read_stream)),
            Ok(Box::new (write_stream))));
        let (sub_tx, sub_rx) = mpsc::channel ();

        thread::spawn (move || {
            let system = System::new("test");
            let subject = StreamHandlerPool::new();
            let subject_addr: SyncAddress<_> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();

            subject_subs.bind.send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();
            sub_tx.send (subject_subs).ok ();
            system.run();
        });

        let tlh = TestLogHandler::new ();
        let subject_subs = sub_rx.recv ().unwrap ();
        subject_subs.add_sub.send(AddStreamMsg {
            stream: Box::new(stream),
            origin_port: None,
            discriminator_factories: vec! ()
        }).ok ();

        subject_subs.transmit_sub.send(TransmitDataMsg { endpoint: Endpoint::Socket(socket_addr), data: vec!(0x12, 0x34) }).ok ();
        tlh.await_log_containing ("ERROR: Dispatcher for V4(1.2.3.4:5679): Cannot transmit 2 bytes: broken pipe", 5000);

        subject_subs.transmit_sub.send(TransmitDataMsg { endpoint: Endpoint::Socket(socket_addr), data: vec!(0x12, 0x34) }).ok ();
        tlh.await_log_containing ("ERROR: Dispatcher: Cannot transmit 2 bytes to V4(1.2.3.4:5679): nonexistent stream", 5000);

        assert_eq! (write_stream_log.lock ().unwrap ().dump (), vec! (
            "shutdown (Both)"
        ));
    }

    #[test]
    fn transmitting_on_an_unknown_socket_addr_produces_an_error_log () {
        LoggerInitializerWrapperMock::new ().init ();
        thread::spawn (move || {
            let system = System::new("test");
            let socket_addr = SocketAddr::from_str("1.2.3.4:5677").unwrap();
            let subject = StreamHandlerPool::new();
            let subject_addr: SyncAddress<_> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone ()
            }).unwrap ();

            subject_subs.transmit_sub.send(TransmitDataMsg {endpoint: Endpoint::Socket(socket_addr), data: vec!(0x12, 0x34)}).ok ();

            system.run();
        });

        TestLogHandler::new ().await_log_containing("ERROR: Dispatcher: Cannot transmit 2 bytes to V4(1.2.3.4:5677): nonexistent stream", 5000);
    }

    #[test]
    fn indicates_dead_stream_identifies_dead_stream_errors () {
        vec! (ErrorKind::BrokenPipe, ErrorKind::ConnectionRefused, ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted, ErrorKind::TimedOut).iter ().for_each (|kind| {

            let result = indicates_dead_stream (*kind);

            assert_eq! (result, true, "indicates_dead_stream ({:?}) should have been true but was false", kind)
        });
    }

    #[test]
    fn indicates_dead_stream_identifies_non_dead_stream_errors () {
        vec! (ErrorKind::NotFound, ErrorKind::PermissionDenied, ErrorKind::NotConnected,
              ErrorKind::AddrInUse, ErrorKind::AddrNotAvailable, ErrorKind::AlreadyExists,
              ErrorKind::WouldBlock, ErrorKind::InvalidInput, ErrorKind::InvalidData,
              ErrorKind::WriteZero, ErrorKind::Interrupted, ErrorKind::Other,
              ErrorKind::UnexpectedEof).iter ().for_each (|kind| {

            let result = indicates_dead_stream (*kind);

            assert_eq! (result, false, "indicates_dead_stream ({:?}) should have been false but was true", kind)
        });
    }

    #[test]
    fn pool_bind_message_is_debug () {
        let _system = System::new ("test");
        let dispatcher_subs = make_peer_actors().dispatcher;
        let stream_handler_pool_subs = make_stream_handler_pool_subs_from (None);
        let subject = PoolBindMessage {dispatcher_subs, stream_handler_pool_subs};

        let result = format! ("{:?}", subject);

        assert_eq! (result, String::from ("PoolBindMessage"));
    }
}
