// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use std::net::SocketAddr;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use tokio::net::TcpStream;
use tokio;
use discriminator::DiscriminatorFactory;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::dispatcher;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::dispatcher::Endpoint;
use sub_lib::logger::Logger;
use sub_lib::node_addr::NodeAddr;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;
use stream_messages::*;
use stream_reader::*;
use stream_writer::*;
use sub_lib::tokio_wrappers::ReadHalfWrapperReal;
use sub_lib::tokio_wrappers::WriteHalfWrapperReal;
use tokio::io::AsyncRead;

pub struct StreamHandlerPoolSubs {
    pub add_sub: Recipient<Syn, AddStreamMsg>,
    pub transmit_sub: Recipient<Syn, TransmitDataMsg>,
    pub remove_sub: Recipient<Syn, RemoveStreamMsg>,
    pub bind: Recipient<Syn, PoolBindMessage>,
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

trait StreamSplitter {
    fn split_stream(&self, stream: Option<TcpStream>) -> (Box<ReadHalfWrapper>, Box<WriteHalfWrapper>, SocketAddr, SocketAddr);
}

struct StreamSplitterReal {}

impl StreamSplitter for StreamSplitterReal {
    fn split_stream(&self, stream: Option<TcpStream>) -> (Box<ReadHalfWrapper>, Box<WriteHalfWrapper>, SocketAddr, SocketAddr) {
        let stream_unwrapped = stream.expect("Got a bad stream from ListenerHandler");
        let peer_addr = stream_unwrapped.peer_addr().expect ("Internal error: no peer address preparing stream reader/writer");
        let local_addr = stream_unwrapped.local_addr().expect ("Internal error: no local address preparing stream reader/writer");
        let (reader, writer) = stream_unwrapped.split();
        (
            Box::new(ReadHalfWrapperReal::new(reader)),
            Box::new(WriteHalfWrapperReal::new(writer)),
            peer_addr,
            local_addr
        )
    }
}

pub struct StreamHandlerPool {
    stream_writers: HashMap<SocketAddr, Box<SenderWrapper>>,
    dispatcher_subs: Option<DispatcherSubs>,
    self_subs: Option<StreamHandlerPoolSubs>,
    logger: Logger,
    stream_splitter: Box<StreamSplitter>,
    channel_factory: Box<FuturesChannelFactory>,
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
            stream_splitter: Box::new(StreamSplitterReal {}),
            channel_factory: Box::new(FuturesChannelFactoryReal {})
        }
    }

    pub fn make_subs_from(pool_addr: &Addr<Syn, StreamHandlerPool>) -> StreamHandlerPoolSubs {
        StreamHandlerPoolSubs {
            add_sub: pool_addr.clone ().recipient::<AddStreamMsg>(),
            transmit_sub: pool_addr.clone ().recipient::<TransmitDataMsg>(),
            remove_sub: pool_addr.clone ().recipient::<RemoveStreamMsg>(),
            bind: pool_addr.clone ().recipient::<PoolBindMessage>(),
        }
    }

    fn set_up_stream_reader (&mut self, read_stream: Box<ReadHalfWrapper>, origin_port: Option<u16>,
            discriminator_factories: Vec<Box<DiscriminatorFactory>>, socket_addr: SocketAddr, local_addr: SocketAddr) {
        let ibcd_sub: Recipient<Syn, dispatcher::InboundClientData> =
            self.dispatcher_subs.as_ref().expect("StreamHandlerPool is unbound").ibcd_sub.clone ();
        let remove_sub: Recipient<Syn, RemoveStreamMsg> =
            self.self_subs.as_ref().expect("StreamHandlerPool is unbound").remove_sub.clone ();
        let ibcd_sub = ibcd_sub.clone ();
        let remove_sub = remove_sub.clone();
        let stream_reader = StreamReaderReal::new(read_stream, origin_port,
            ibcd_sub, remove_sub, discriminator_factories, socket_addr, local_addr);
        tokio::spawn(stream_reader);
    }

    fn set_up_stream_writer (&mut self, write_stream: Box<WriteHalfWrapper>, socket_addr: SocketAddr) {
        let (tx, rx) = self.channel_factory.make();
        let stream_writer = StreamWriterReal::new (
            write_stream,
            self.self_subs.as_ref().expect("StreamHandlerPool is unbound").remove_sub.clone (),
            socket_addr,
            rx,
        );
        self.stream_writers.insert (socket_addr, tx);
        tokio::spawn(stream_writer);
    }
}

impl Handler<AddStreamMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) {
        let (read_stream, write_stream, peer_addr, local_addr) = self.stream_splitter.split_stream(msg.stream);

        self.set_up_stream_writer(write_stream, peer_addr);
        self.set_up_stream_reader(read_stream, msg.origin_port, msg.discriminator_factories, peer_addr, local_addr);
    }
}

impl Handler<RemoveStreamMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) {
        self.stream_writers.remove (&msg.socket_addr).is_some (); // can't do anything if it fails
    }
}

impl Handler<TransmitDataMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) {
        let node_addr = match msg.endpoint {
            Endpoint::Key (_) => unimplemented!(),
            Endpoint::Ip (_) => unimplemented!(),
            Endpoint::Socket (socket_addr) => NodeAddr::from (&socket_addr)
        };
        // TODO: Taking just the first address should be eliminated when this moves into the StreamHandlerPool.
        let mut socket_addrs: Vec<SocketAddr> = node_addr.into ();
        let socket_addr = socket_addrs.remove (0);

        let mut to_remove = false;
        match self.stream_writers.get_mut (&socket_addr) {
            Some (tx_box) => {
                match tx_box.unbounded_send (SequencedPacket::from(&msg)) {
                    Err(_) => to_remove = true,
                    Ok(_) => {
                        if msg.last_data {
                            to_remove = true;
                        }
                    }
                }
            },
            None => {
                self.logger.log (format! ("Cannot transmit {} bytes to {:?}: nonexistent stream",
                msg.data.len (), socket_addr));
            }
        }
        if to_remove {
            self.logger.trace(format!("Removing stream writer for {:?}", socket_addr));
            self.stream_writers.remove(&socket_addr);
        }
    }
}

impl Handler<PoolBindMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.dispatcher_subs = Some(msg.dispatcher_subs);
        self.self_subs = Some(msg.stream_handler_pool_subs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use actix::System;
    use http_request_start_finder::HttpRequestDiscriminatorFactory;
    use node_test_utils::FuturesChannelFactoryMock;
    use node_test_utils::ReadHalfWrapperMock;
    use node_test_utils::ReceiverWrapperMock;
    use node_test_utils::SenderWrapperMock;
    use node_test_utils::WriteHalfWrapperMock;
    use test_utils::test_utils::init_test_logging;
    use test_utils::recorder::make_peer_actors;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::Recorder;
    use test_utils::test_utils::TestLogHandler;
    use tokio::prelude::Async;
    use std::thread;

    struct StreamSplitterMock {
        pub peer_addr: SocketAddr,
        pub local_addr: SocketAddr,
        pub poll_read_results: RefCell<Option<Vec<(Vec<u8>, Result<Async<usize>, Error>)>>>,
        pub poll_write_params: Arc<Mutex<Vec<Vec<u8>>>>,
        pub poll_write_results: RefCell<Option<Vec<(Result<Async<usize>, Error>)>>>,
    }

    impl StreamSplitter for StreamSplitterMock {
        fn split_stream(&self, _stream: Option<TcpStream>) -> (Box<ReadHalfWrapper>, Box<WriteHalfWrapper>, SocketAddr, SocketAddr) {
            (
                Box::new(ReadHalfWrapperMock {
                    poll_read_results: self.poll_read_results.borrow_mut().take().unwrap()
                }),
                Box::new(WriteHalfWrapperMock {
                    poll_write_params: self.poll_write_params.clone(),
                    poll_write_results: self.poll_write_results.borrow_mut().take().unwrap()
                }),
                self.peer_addr,
                self.local_addr,
            )
        }
    }

    impl StreamSplitterMock {
        pub fn new(peer_addr: SocketAddr, local_addr: SocketAddr) -> StreamSplitterMock {
            StreamSplitterMock {
                peer_addr,
                local_addr,
                poll_read_results: RefCell::new(Some(vec!())),
                poll_write_params: Arc::new(Mutex::new(vec!())),
                poll_write_results: RefCell::new(Some(vec!()))
            }
        }
    }

    #[test]
    fn a_newly_added_stream_produces_stream_handler_that_sends_received_data_to_dispatcher () {
        let dispatcher = Recorder::new ();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let peer_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:80").unwrap();
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
        let mut stream_splitter = StreamSplitterMock::new(peer_addr, local_addr);
        stream_splitter.poll_read_results = RefCell::new( Some(vec!(
            (one_http_req.clone(), Ok(Async::Ready(one_http_req.len()))),
            (second_chunk.clone (), Ok(Async::Ready(second_chunk.len()))),
            (Vec::new (), Err(Error::from(ErrorKind::BrokenPipe))),
            (one_http_req.clone(), Ok(Async::Ready(one_http_req.len ())))
        )));

        thread::spawn (move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new();
            subject.stream_splitter = Box::new(stream_splitter);
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None, None);

            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();
            subject_subs.add_sub.try_send(AddStreamMsg {
                stream: None, // the stream splitter mock will return mocked reader/writer
                origin_port,
                discriminator_factories: vec! (Box::new (HttpRequestDiscriminatorFactory::new ()))
            }).unwrap ();

            system.run ();
        });

        awaiter.await_message_count (4);
        let dispatcher_recording = dispatcher_recording_arc.lock ().unwrap ();
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (0), &dispatcher::InboundClientData {
            socket_addr: peer_addr,
            origin_port,
            last_data: false,
            sequence_number: Some(0),
            data: one_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (1), &dispatcher::InboundClientData {
            socket_addr: peer_addr,
            origin_port,
            last_data: false,
            sequence_number: Some(1),
            data: another_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (2), &dispatcher::InboundClientData {
            socket_addr: peer_addr,
            origin_port,
            last_data: false,
            sequence_number: Some(2),
            data: a_third_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (3), &dispatcher::InboundClientData {
            socket_addr: peer_addr,
            origin_port,
            last_data: true,
            sequence_number: Some(3),
            data: Vec::new ()
        });
        assert_eq! (dispatcher_recording.len (), 4);
    }

    #[test]
    fn stream_handler_pool_writes_data_to_stream_writer() {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();
        let mut stream_splitter = StreamSplitterMock::new(socket_addr, local_addr);
        stream_splitter.poll_write_results = RefCell::new(Some(vec! (Err(Error::from(ErrorKind::Other)), Ok (Async::Ready(5)), Ok(Async::NotReady))));
        stream_splitter.poll_read_results = RefCell::new(Some(vec!((vec!(), Ok(Async::NotReady)))));
        let write_stream_params_arc = stream_splitter.poll_write_params.clone ();
        let mut sender = SenderWrapperMock::new();
        sender.unbounded_send_results = vec!( Ok(()) );
        let sender_params = sender.unbounded_send_params.clone();
        let mut receiver = ReceiverWrapperMock::new();
        receiver.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let channel_factory = FuturesChannelFactoryMock { results: vec!((Box::new(sender), Box::new(receiver)))};

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new();
            subject.stream_splitter = Box::new(stream_splitter);
            subject.channel_factory = Box::new(channel_factory);

            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone() }).unwrap();

            subject_subs.add_sub.try_send(AddStreamMsg {
                stream: None,
                origin_port: None,
                discriminator_factories: vec!(Box::new(HttpRequestDiscriminatorFactory::new()))
            }).unwrap();

            subject_subs.transmit_sub.try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: b"hello".to_vec()
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_matching("ThreadId\\(\\d+\\): WARN: Dispatcher for V4\\(1\\.2\\.3\\.4:5678\\): Continuing after write error: other os error", 1000);

        let mut shp_to_sw_params = sender_params.lock().unwrap();
        assert_eq!(shp_to_sw_params.len(), 1);
        assert_eq!(shp_to_sw_params.remove(0), SequencedPacket::new(b"hello".to_vec(), 0, true));

        let mut sw_to_stream_params = write_stream_params_arc.lock().unwrap();
        assert_eq!(sw_to_stream_params.len(), 2);
        assert_eq!(sw_to_stream_params.remove(0), b"hello".to_vec());
    }

    #[test]
    fn terminal_packet_is_transmitted_and_then_stream_is_shut_down () {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:5673").unwrap();
        let mut stream_splitter = StreamSplitterMock::new(socket_addr, local_addr);
        let write_stream_params_arc = stream_splitter.poll_write_params.clone ();
        let (sub_tx, sub_rx) = mpsc::channel ();

        thread::spawn(move || {
            let system = System::new("test");
            stream_splitter.poll_write_results = RefCell::new(Some(vec! (Ok (Async::Ready(2)))));

            let mut subject = StreamHandlerPool::new();
            subject.stream_splitter = Box::new(stream_splitter);
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone() }).unwrap();

            sub_tx.send(subject_subs).is_ok();
            system.run();
        });

        let subject_subs = sub_rx.recv().unwrap();

        subject_subs.add_sub.try_send(AddStreamMsg {
            stream: None,
            origin_port: None,
            discriminator_factories: vec!(Box::new(HttpRequestDiscriminatorFactory::new()))
        }).unwrap();

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: true,
            sequence_number: Some(0),
            data: vec!(0x12, 0x34)
        }).unwrap();

        TestLogHandler::new ().await_log_containing("Removing stream writer for V4(1.2.3.4:5673)", 1000);

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: true,
            sequence_number: Some(0),
            data: vec!(0x56, 0x78)
        }).unwrap();

        TestLogHandler::new ().await_log_containing("Cannot transmit 2 bytes to V4(1.2.3.4:5673): nonexistent stream", 1000);

        let write_stream_params = write_stream_params_arc.lock ().unwrap ();
        assert_eq!(write_stream_params.len(), 1);
        assert_eq! (write_stream_params.deref (), &vec! (vec! (0x12, 0x34)));
    }

    #[test]
    fn stream_handler_pool_removes_stream_when_it_gets_the_remove_stream_msg() {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:5673").unwrap();
        let mut stream_splitter = StreamSplitterMock::new(socket_addr, local_addr);

        thread::spawn(move || {
            let system = System::new("test");
            stream_splitter.poll_write_results = RefCell::new(Some(vec! (Ok (Async::Ready(2)))));

            let mut subject = StreamHandlerPool::new();
            subject.stream_splitter = Box::new(stream_splitter);
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone() }).unwrap();

            subject_subs.add_sub.try_send(AddStreamMsg {
                stream: None,
                origin_port: None,
                discriminator_factories: vec!(Box::new(HttpRequestDiscriminatorFactory::new()))
            }).unwrap();

            subject_subs.remove_sub.try_send(RemoveStreamMsg { socket_addr }).unwrap();

            subject_subs.transmit_sub.try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: vec!(0x12, 0x34)
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_containing("Cannot transmit 2 bytes to V4(1.2.3.4:5673): nonexistent stream", 1000);
    }

    #[test]
    fn transmitting_down_a_recalcitrant_existing_stream_produces_an_error_log_and_removes_writer () {
        init_test_logging();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5679").unwrap();
        let local_addr = SocketAddr::from_str("1.2.3.5:5679").unwrap();
        let mut stream_splitter = StreamSplitterMock::new(socket_addr, local_addr);
        stream_splitter.poll_read_results = RefCell::new(Some(vec! ((Vec::from ("block".as_bytes ()), Ok(Async::Ready(5))))));
        stream_splitter.poll_write_results = RefCell::new(Some(vec!(Err(Error::from(ErrorKind::BrokenPipe)))));
        let (sub_tx, sub_rx) = mpsc::channel ();

        thread::spawn (move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new();
            subject.stream_splitter = Box::new(stream_splitter);
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();

            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone ()}).unwrap ();
            sub_tx.send (subject_subs).ok ();
            system.run();
        });

        let tlh = TestLogHandler::new ();
        let subject_subs = sub_rx.recv ().unwrap ();
        subject_subs.add_sub.try_send(AddStreamMsg {
            stream: None,
            origin_port: None,
            discriminator_factories: vec! (Box::new (HttpRequestDiscriminatorFactory::new ()))
        }).unwrap ();

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            sequence_number: Some(0),
            data: vec!(0x12, 0x34)
        }).unwrap ();
        tlh.await_log_containing ("ERROR: Dispatcher for V4(1.2.3.4:5679): Cannot transmit 2 bytes: broken pipe", 5000);

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            sequence_number: Some(0),
            data: vec!(0x12, 0x34)
        }).unwrap ();
        tlh.await_log_containing ("ERROR: Dispatcher: Cannot transmit 2 bytes to V4(1.2.3.4:5679): nonexistent stream", 5000);
    }

    #[test]
    fn transmitting_on_an_unknown_socket_addr_produces_an_error_log () {
        init_test_logging();
        thread::spawn (move || {
            let system = System::new("test");
            let socket_addr = SocketAddr::from_str("1.2.3.4:5677").unwrap();
            let subject = StreamHandlerPool::new();
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone ()
            }).unwrap ();

            subject_subs.transmit_sub.try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: false,
                sequence_number: Some(0),
                data: vec!(0x12, 0x34)
            }).unwrap ();

            system.run();
        });

        TestLogHandler::new ().await_log_containing("ERROR: Dispatcher: Cannot transmit 2 bytes to V4(1.2.3.4:5677): nonexistent stream", 5000);
    }
}
