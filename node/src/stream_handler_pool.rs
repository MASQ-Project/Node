// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use tokio;
use tokio::prelude::Future;
use configuration::PortConfiguration;
use discriminator::DiscriminatorFactory;
use json_masquerader::JsonMasquerader;
use masquerader::Masquerader;
use stream_connector::StreamConnector;
use stream_connector::StreamConnectorReal;
use stream_messages::*;
use stream_reader::*;
use stream_writer::*;
use sub_lib::channel_wrappers::FuturesChannelFactory;
use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::Key;
use sub_lib::dispatcher;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::dispatcher::Endpoint;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::DispatcherNodeQueryMessage;
use sub_lib::neighborhood::NodeDescriptor;
use sub_lib::neighborhood::NodeQueryMessage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::tokio_wrappers::WriteHalfWrapper;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;

pub struct StreamHandlerPoolSubs {
    pub add_sub: Recipient<Syn, AddStreamMsg>,
    pub transmit_sub: Recipient<Syn, TransmitDataMsg>,
    pub remove_sub: Recipient<Syn, RemoveStreamMsg>,
    pub bind: Recipient<Syn, PoolBindMessage>,
    pub node_query_response: Recipient<Syn, DispatcherNodeQueryResponse>
}

impl Clone for StreamHandlerPoolSubs {
    fn clone(&self) -> Self {
        StreamHandlerPoolSubs {
            add_sub: self.add_sub.clone (),
            transmit_sub: self.transmit_sub.clone (),
            remove_sub: self.remove_sub.clone (),
            bind: self.bind.clone(),
            node_query_response: self.node_query_response.clone(),
        }
    }
}

pub struct StreamHandlerPool {
    stream_writers: HashMap<SocketAddr, Option<Box<SenderWrapper<SequencedPacket>>>>,
    dispatcher_subs: Option<DispatcherSubs>,
    self_subs: Option<StreamHandlerPoolSubs>,
    to_neighborhood: Option<Recipient<Syn, DispatcherNodeQueryMessage>>,
    logger: Logger,
    stream_connector: Box<StreamConnector>,
    channel_factory: Box<FuturesChannelFactory<SequencedPacket>>,
    clandestine_discriminator_factories: Vec<Box<DiscriminatorFactory>>,
}

impl Actor for StreamHandlerPool {
    type Context = Context<Self>;
}

impl Handler<AddStreamMsg> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) -> <Self as Handler<AddStreamMsg>>::Result {
        self.set_up_stream_writer(msg.connection_info.writer, msg.connection_info.peer_addr, msg.writer_config);
        self.set_up_stream_reader(msg.connection_info.reader, msg.origin_port, msg.port_configuration, msg.connection_info.peer_addr, msg.connection_info.local_addr);
        ()
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

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut <Self as Actor>::Context) {
        // TODO Can be recombined with DispatcherNodeQueryMessage after SC-358
        let node_query_response_recipient = self.self_subs.as_ref().expect("StreamHandlerPool is unbound.").node_query_response.clone();
        match msg.endpoint.clone() {
            Endpoint::Key(key) => {
                let request = DispatcherNodeQueryMessage { query: NodeQueryMessage::PublicKey(key.clone()), context: msg, recipient: node_query_response_recipient };
                self.to_neighborhood.as_ref().expect("StreamHandlerPool is unbound.").try_send(request).expect("Neighborhood is Dead")
            },
            Endpoint::Ip(_) => unimplemented!(),
            Endpoint::Socket(socket_addr) => node_query_response_recipient.try_send (DispatcherNodeQueryResponse {
                result: Some(NodeDescriptor::new(Key::new(&[]), Some(NodeAddr::from(&socket_addr)))),
                context: msg
            }).expect("StreamHandlerPool is dead?")
        };
        ()
    }
}

impl Handler<DispatcherNodeQueryResponse> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: DispatcherNodeQueryResponse, _ctx: &mut Self::Context) {
        // TODO Can be recombined with TransmitDataMsg after SC-358
        let node_addr = match msg.result.clone() {
            Some (node_descriptor) => match node_descriptor.node_addr_opt {
                Some (node_addr) => node_addr,
                None => {
                    self.logger.error (format! ("No known IP for neighbor in route with key: {}", node_descriptor.public_key));
                    return
                }
            },
            None => {
                self.logger.error (format! ("No neighbor found at endpoint {:?}", msg.context.endpoint));
                return
            }
        };

        if node_addr.ports ().is_empty () {
            // If the NodeAddr has no ports, then either we are a 0-hop-only node or something has gone terribly wrong with the Neighborhood's state, so we should blow up.
            panic!("Neighborhood has returned a NodeDescriptor with no ports. This indicates an irrecoverable error.")
        }

        // TODO: Picking the first port is a temporary hack. TODO create a card about this and remove this line
        let peer_addr = SocketAddr::new (node_addr.ip_addr(), node_addr.ports ()[0]);

        let mut to_remove = false;
        if self.stream_writers.contains_key (&peer_addr) {
            let tx_opt = self.stream_writers.get_mut(&peer_addr).expect("StreamWriter magically disappeared");
            match tx_opt {
                Some(tx_box) => {
                    match tx_box.unbounded_send(SequencedPacket::from(&msg.context)) { // TODO FIXME stream_handler_pool should be able to accept Vec<u8> for clandestine data (when TDM sequence# is None)
                        Err(_) => {
                            to_remove = true
                        },
                        Ok(_) => {
                            if msg.context.last_data {
                                to_remove = true;
                            }
                        }
                    }
                },
                None => { // a connection is already in progress. resubmit this message, to give the connection time to complete
                    self.logger.info(format!("INFO: connection for {} in progress, resubmitting {} bytes", peer_addr, msg.context.data.len()));
                    let recipient = self.self_subs.as_ref().expect("StreamHandlerPool is unbound.").node_query_response.clone();
                    // TODO FIXME revisit once SC-358 is done (idea: create an actor for delaying messages?)
                    thread::spawn(move || { // to avoid getting into too-tight a resubmit loop, add a delay; in a separate thread, to avoid delaying other traffic
                        thread::sleep(Duration::from_millis(100));
                        recipient.try_send(msg).expect("StreamHandlerPool is dead");
                    });
                    ()
                }
            }
        } else {
            self.logger.debug (format! ("No existing stream to {}: creating one", peer_addr));

            let subs = self.self_subs.clone ().expect ("Internal error");
            let add_stream_sub = subs.add_sub;
            let node_query_response_sub = subs.node_query_response;
            let remove_sub = subs.remove_sub;

            self.stream_writers.insert(peer_addr, None);
            let logger = self.logger.clone ();
            let clandestine_discriminator_factories = self.clandestine_discriminator_factories.clone ();
            let msg_data_len = msg.context.data.len ();
            let peer_addr_e = peer_addr.clone();

            let connect_future = self.stream_connector.connect_pair (peer_addr, &self.logger)
                .map (move |connection_info| {
                    let origin_port = connection_info.local_addr.port ();
                    add_stream_sub.try_send (AddStreamMsg {
                        connection_info,
                        origin_port: Some (origin_port),
                        port_configuration: PortConfiguration::new (clandestine_discriminator_factories, true),
                        writer_config: Box::new(JsonMasquerader::new()),
                    }).expect ("StreamHandlerPool is dead");
                    node_query_response_sub.try_send (msg).expect ("StreamHandlerPool is dead");
                    ()
                })
                .map_err (move |err| { // connection was unsuccessful
                    logger.error (format! ("Stream to {} does not exist and could not be connected; discarding {} bytes: {}", peer_addr, msg_data_len, err));
                    remove_sub.try_send(RemoveStreamMsg { socket_addr: peer_addr_e }).expect("StreamHandlerPool is dead");
                    ()
                });

            tokio::spawn(
                connect_future
            );
        }

        if to_remove {
            self.logger.trace(format!("Removing stream writer for {}", peer_addr));
            self.stream_writers.remove(&peer_addr);
        }
    }
}

impl Handler<PoolBindMessage> for StreamHandlerPool {
    type Result = ();

    fn handle(&mut self, msg: PoolBindMessage, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.dispatcher_subs = Some(msg.dispatcher_subs);
        self.self_subs = Some(msg.stream_handler_pool_subs);
        self.to_neighborhood = Some(msg.neighborhood_subs.dispatcher_node_query);
    }
}

impl StreamHandlerPool {
    pub fn new(clandestine_discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> StreamHandlerPool {
        StreamHandlerPool {
            stream_writers: HashMap::new (),
            dispatcher_subs: None,
            self_subs: None,
            to_neighborhood: None,
            logger: Logger::new ("Dispatcher"),
            stream_connector: Box::new (StreamConnectorReal {}),
            channel_factory: Box::new(FuturesChannelFactoryReal {}),
            clandestine_discriminator_factories,
        }
    }

    pub fn make_subs_from(pool_addr: &Addr<Syn, StreamHandlerPool>) -> StreamHandlerPoolSubs {
        StreamHandlerPoolSubs {
            add_sub: pool_addr.clone ().recipient::<AddStreamMsg>(),
            transmit_sub: pool_addr.clone ().recipient::<TransmitDataMsg>(),
            remove_sub: pool_addr.clone ().recipient::<RemoveStreamMsg>(),
            bind: pool_addr.clone ().recipient::<PoolBindMessage>(),
            node_query_response: pool_addr.clone().recipient::<DispatcherNodeQueryResponse>(),
        }
    }

    fn set_up_stream_reader (
        &mut self,
        read_stream: Box<ReadHalfWrapper>,
        origin_port: Option<u16>,
        port_configuration: PortConfiguration,
        socket_addr: SocketAddr,
        local_addr: SocketAddr
    ) {
        let ibcd_sub: Recipient<Syn, dispatcher::InboundClientData> =
            self.dispatcher_subs.as_ref().expect("Dispatcher is unbound").ibcd_sub.clone ();
        let remove_sub: Recipient<Syn, RemoveStreamMsg> =
            self.self_subs.as_ref().expect("StreamHandlerPool is unbound").remove_sub.clone ();
        let stream_reader = StreamReaderReal::new(
            read_stream,
            origin_port,
            ibcd_sub,
            remove_sub,
            port_configuration.discriminator_factories,
            port_configuration.is_clandestine,
            socket_addr,
            local_addr
        );
        tokio::spawn(stream_reader);
    }

    fn set_up_stream_writer (
        &mut self,
        write_stream: Box<WriteHalfWrapper>,
        socket_addr: SocketAddr,
        writer_config: Box<Masquerader>,
    ) {
        let (tx, rx) = self.channel_factory.make();
        let stream_writer = StreamWriter::new (
            write_stream,
            socket_addr,
            rx,
            writer_config,
        );
        self.stream_writers.insert (socket_addr, Some(tx));
        tokio::spawn(stream_writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::cell::RefCell;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::net::Ipv4Addr;
    use actix::Actor;
    use actix::Addr;
    use actix::Syn;
    use actix::System;
    use futures::future::result;
    use tokio::io;
    use tokio::prelude::Async;
    use http_request_start_finder::HttpRequestDiscriminatorFactory;
    use json_discriminator_factory::JsonDiscriminatorFactory;
    use json_masquerader::JsonMasquerader;
    use masquerader::Masquerader;
    use null_masquerader::NullMasquerader;
    use stream_connector::ConnectionInfo;
    use stream_connector::ConnectionInfoFuture;
    use sub_lib::dispatcher::InboundClientData;
    use sub_lib::cryptde::CryptDE;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::neighborhood::NodeDescriptor;
    use test_utils::channel_wrapper_mocks::FuturesChannelFactoryMock;
    use test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::recorder::make_peer_actors;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::Recording;
    use test_utils::test_utils::await_messages;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use tokio::net::TcpStream;

    struct StreamConnectorMock {
        connect_pair_params: Arc<Mutex<Vec<SocketAddr>>>,
        connect_pair_results: RefCell<Vec<Result<ConnectionInfo, io::Error>>>,
    }

    impl StreamConnector for StreamConnectorMock {
        fn connect_pair(&self, socket_addr: SocketAddr, _logger: &Logger) -> ConnectionInfoFuture {
            self.connect_pair_params.lock ().unwrap ().push (socket_addr);
            let connection_info_result = self.connect_pair_results.borrow_mut ().remove (0);
            Box::new (result (connection_info_result))
        }

        fn split_stream(&self, _stream: TcpStream, _logger: &Logger) -> ConnectionInfo {
            unimplemented!()
        }

        fn split_stream_fut(&self, _stream: TcpStream, _logger: &Logger) -> ConnectionInfoFuture {
            unimplemented!()
        }
    }

    impl StreamConnectorMock {
        pub fn new () -> StreamConnectorMock {
            Self {
                connect_pair_params: Arc::new (Mutex::new (vec! ())),
                connect_pair_results: RefCell::new (vec! ())
            }
        }

        pub fn connection (
            self,
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
            reads: Vec<(Vec<u8>, Result<Async<usize>, io::Error>)>,
            writes: Vec<Result<Async<usize>, io::Error>>,
        ) -> StreamConnectorMock {
            let read_half = reads.into_iter ().fold (ReadHalfWrapperMock::new (), |so_far, elem| {
                so_far.poll_read_result (elem.0, elem.1)
            });
            let write_half = writes.into_iter ().fold (WriteHalfWrapperMock::new (), |so_far, elem| {
                so_far.poll_write_result (elem)
            });
            let connection_info = ConnectionInfo {
                reader: Box::new (read_half),
                writer: Box::new (write_half),
                local_addr,
                peer_addr,
            };
            self.connect_pair_result (Ok (connection_info))
        }

        pub fn connect_pair_params (mut self, params_arc: &Arc<Mutex<Vec<SocketAddr>>>) -> StreamConnectorMock {
            self.connect_pair_params = params_arc.clone ();
            self
        }

        pub fn connect_pair_result (self, result: Result<ConnectionInfo, io::Error>) -> StreamConnectorMock {
            self.connect_pair_results.borrow_mut ().push (result);
            self
        }
    }

    #[test]
    fn a_newly_added_stream_produces_stream_handler_that_sends_received_data_to_dispatcher () {
        let dispatcher = Recorder::new ();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let peer_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let peer_addr_a = peer_addr.clone ();
        let local_addr = SocketAddr::from_str("1.2.3.5:80").unwrap();
        let origin_port = Some (8081);
        let is_clandestine = false;
        let one_http_req = b"GET http://here.com HTTP/1.1\r\n\r\n".to_vec();
        let one_http_req_a = one_http_req.clone ();
        let another_http_req = b"DELETE http://there.com HTTP/1.1\r\n\r\n".to_vec();
        let another_http_req_a = another_http_req.clone ();
        let a_third_http_req = b"HEAD http://everywhere.com HTTP/1.1\r\n\r\n".to_vec();
        let a_third_http_req_a = a_third_http_req.clone ();
        let mut second_chunk = Vec::new ();
        second_chunk.extend (another_http_req.clone ());
        second_chunk.extend (Vec::from ("glorp".as_bytes ()));
        second_chunk.extend (a_third_http_req.clone ());
        let awaiter = dispatcher.get_awaiter ();

        thread::spawn (move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ()); // TODO: Maybe should put a factory in here and assert on it
            subject.stream_connector = Box::new (StreamConnectorMock::new ());
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None, None);

            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone (),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap ();

            let connection_info = ConnectionInfo {
                reader: Box::new (ReadHalfWrapperMock::new ()
                    .poll_read_ok(one_http_req.clone ())
                    .poll_read_ok(second_chunk.clone ())
                    .poll_read_result (vec! (), Err (Error::from (ErrorKind::BrokenPipe)))),
                writer: Box::new (WriteHalfWrapperMock::new ()
                    .poll_write_result(Ok (Async::Ready (one_http_req.len ())))
                    .poll_write_result(Ok (Async::Ready (second_chunk.len ())))),
                local_addr,
                peer_addr,
            };

            subject_subs.add_sub.try_send(AddStreamMsg::new (
                connection_info, // the stream splitter mock will return mocked reader/writer
                origin_port,
                PortConfiguration::new(vec! (Box::new (HttpRequestDiscriminatorFactory::new ())), is_clandestine),
                Box::new(NullMasquerader::new())
            )).unwrap ();

            system.run ();
        });

        awaiter.await_message_count (4);
        let dispatcher_recording = dispatcher_recording_arc.lock ().unwrap ();
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (0), &dispatcher::InboundClientData {
            socket_addr: peer_addr_a,
            origin_port,
            last_data: false,
            is_clandestine,
            sequence_number: Some(0),
            data: one_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (1), &dispatcher::InboundClientData {
            socket_addr: peer_addr_a,
            origin_port,
            last_data: false,
            is_clandestine,
            sequence_number: Some(1),
            data: another_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (2), &dispatcher::InboundClientData {
            socket_addr: peer_addr_a,
            origin_port,
            last_data: false,
            is_clandestine,
            sequence_number: Some(2),
            data: a_third_http_req_a
        });
        assert_eq! (dispatcher_recording.get_record::<dispatcher::InboundClientData> (3), &dispatcher::InboundClientData {
            socket_addr: peer_addr_a,
            origin_port,
            last_data: true,
            is_clandestine,
            sequence_number: Some(3),
            data: Vec::new ()
        });
        assert_eq! (dispatcher_recording.len (), 4);
    }

    #[test]
    fn stream_handler_pool_writes_data_to_stream_writer() {
        init_test_logging();
        let mut sender = SenderWrapperMock::new();
        sender.unbounded_send_results = vec!( Ok(()) );
        let sender_params = sender.unbounded_send_params.clone();
        let mut receiver = ReceiverWrapperMock::new();
        receiver.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, false)))),
            Ok(Async::NotReady)
        );
        let channel_factory = FuturesChannelFactoryMock { results: vec!((Box::new(sender), Box::new(receiver)))};
        let reader = ReadHalfWrapperMock::new ()
            .poll_read_result(vec! (), Ok (Async::NotReady));
        let write_stream_params_arc = Arc::new (Mutex::new (vec! ()));
        let writer = WriteHalfWrapperMock::new ()
            .poll_write_result(Err (Error::from (ErrorKind::Other)))
            .poll_write_result(Ok (Async::Ready (5)))
            .poll_write_result(Ok (Async::NotReady))
            .poll_write_params (&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:6789").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();


        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.channel_factory = Box::new(channel_factory);

            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new (reader),
                writer: Box::new (writer),
                local_addr,
                peer_addr,
            };

            subject_subs.add_sub.try_send(AddStreamMsg::new (
                connection_info,
                None,
                PortConfiguration::new(vec!(Box::new(HttpRequestDiscriminatorFactory::new())), true),
                Box::new(NullMasquerader::new())
            )).unwrap();

            subject_subs.transmit_sub.try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr),
                last_data: true,
                sequence_number: Some(0),
                data: b"hello".to_vec()
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_containing("WARN: StreamWriter for 1.2.3.5:6789: Continuing after write error: other os error", 1000);

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
        let (sub_tx, sub_rx) = mpsc::channel ();

        thread::spawn(move || {
            let system = System::new("test");

            let mut subject = StreamHandlerPool::new(vec! ());
            subject.stream_connector = Box::new (StreamConnectorMock::new ()
                .connect_pair_result (Err(Error::from(ErrorKind::ConnectionRefused))));
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage { dispatcher_subs: peer_actors.dispatcher, stream_handler_pool_subs: subject_subs.clone (),
                neighborhood_subs: peer_actors.neighborhood,}).unwrap ();

            sub_tx.send(subject_subs).is_ok();
            system.run();
        });

        let subject_subs = sub_rx.recv().unwrap();

        let reader = ReadHalfWrapperMock::new ()
            .poll_read_result(vec! (), Ok (Async::NotReady));
        let poll_write_params_arc = Arc::new (Mutex::new (vec! ()));
        let writer = WriteHalfWrapperMock::new ()
            .poll_write_result(Ok (Async::Ready(2)))
            .poll_write_result(Ok (Async::NotReady))
            .poll_write_params (&poll_write_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:5673").unwrap();
        let connection_info = ConnectionInfo {
            reader: Box::new (reader),
            writer: Box::new (writer),
            local_addr,
            peer_addr,
        };

        subject_subs.add_sub.try_send(AddStreamMsg::new (
            connection_info,
            None,
            PortConfiguration::new(vec!(Box::new(HttpRequestDiscriminatorFactory::new())), false),
            Box::new(NullMasquerader::new())
        )).unwrap();

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr),
            last_data: true,
            sequence_number: Some(0),
            data: vec!(0x12, 0x34)
        }).unwrap();

        TestLogHandler::new ().await_log_containing("Removing stream writer for 1.2.3.5:5673", 1000);

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc.lock ().expect ("is this really the poison error? NO!");
        assert_eq!(poll_write_params.len(), 1);
        assert_eq! (poll_write_params.deref (), &vec! (vec! (0x12, 0x34)));

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr),
            last_data: true,
            sequence_number: Some(0),
            data: vec!(0x56, 0x78)
        }).unwrap();

        TestLogHandler::new ().await_log_containing("No existing stream to 1.2.3.5:5673: creating one", 1000);
    }

    #[test]
    fn stream_handler_pool_removes_stream_when_it_gets_the_remove_stream_msg() {
        init_test_logging();
        let reader = ReadHalfWrapperMock::new ()
            .poll_read_result(vec! (), Ok (Async::NotReady));
        let write_stream_params_arc = Arc::new (Mutex::new (vec! ()));
        let writer = WriteHalfWrapperMock::new ()
            .poll_write_result(Ok (Async::Ready(2)))
            .poll_write_params (&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:5673").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:5673").unwrap();

        thread::spawn(move || {
            let system = System::new("test");

            let mut subject = StreamHandlerPool::new(vec! (Box::new (JsonDiscriminatorFactory {})));
            subject.stream_connector = Box::new (StreamConnectorMock::new ()
                .connection (local_addr, peer_addr, vec! ((vec!(), Ok(Async::NotReady))), vec! (Ok (Async::Ready (2)))));
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new (reader),
                writer: Box::new (writer),
                local_addr,
                peer_addr,
            };

            subject_subs.add_sub.try_send(AddStreamMsg::new (
                connection_info,
                None,
                PortConfiguration::new(vec!(Box::new(HttpRequestDiscriminatorFactory::new())), true),
                Box::new(NullMasquerader::new())
            )).unwrap();

            subject_subs.remove_sub.try_send(RemoveStreamMsg { socket_addr: peer_addr }).unwrap();

            subject_subs.transmit_sub.try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(peer_addr),
                last_data: true,
                sequence_number: Some(0),
                data: vec!(0x12, 0x34)
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_containing("No existing stream to 1.2.3.5:5673: creating one", 1000);
    }

    #[test]
    fn when_stream_handler_pool_fails_to_create_nonexistent_stream_for_write_then_it_logs_and_discards () {
        init_test_logging ();
        let public_key = Key { data: vec![0, 1, 2, 3] };
        let connect_pair_params_arc = Arc::new (Mutex::new (vec! ()));
        let connect_pair_params_arc_a = connect_pair_params_arc.clone ();
        thread::spawn (move || {
            let system = System::new("when_stream_handler_pool_fails_to_create_nonexistent_stream_for_write_then_it_logs_and_discards");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.stream_connector = Box::new (StreamConnectorMock::new()
                .connect_pair_result(Err(Error::from(ErrorKind::Other)))
                .connect_pair_params(&connect_pair_params_arc));
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, None, None, None, None);
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
                result: Some(NodeDescriptor::new(public_key.clone(), Some(NodeAddr::new(&IpAddr::V4 (Ipv4Addr::new (1, 2, 3, 5)), &vec!(7000))))),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(public_key),
                    last_data: false,
                    sequence_number: None,
                    data: b"hello".to_vec(),
                }
            }).unwrap();

            system.run();
        });
        TestLogHandler::new ().await_log_containing("ERROR: Dispatcher: Stream to 1.2.3.5:7000 does not exist and could not be connected; discarding 5 bytes: other os error", 1000);
        let connect_pair_params = connect_pair_params_arc_a.lock ().unwrap ();
        let connect_pair_params_vec: &Vec<SocketAddr> = connect_pair_params.as_ref ();
        assert_eq! (connect_pair_params_vec, &vec! (SocketAddr::from_str ("1.2.3.5:7000").unwrap ()));
    }

    #[test]
    fn stream_handler_pool_creates_nonexistent_stream_for_reading_and_writing () {
        let public_key = Key { data: vec![0, 1, 2, 3] };
        let masquerader = JsonMasquerader::new ();
        let incoming_unmasked = b"Incoming data".to_vec ();
        let incoming_masked = masquerader.mask (&incoming_unmasked).unwrap ();
        let outgoing_unmasked = b"Outgoing data".to_vec ();
        let outgoing_masked = masquerader.mask (&outgoing_unmasked).unwrap ();
        let outgoing_masked_len = outgoing_masked.len ();
        let (dispatcher, dispatcher_awaiter, dispatcher_recording_arc) = make_recorder();
        let (neighborhood, neighborhood_awaiter, neighborhood_recording_arc) = make_recorder();
        let poll_write_params_arc = Arc::new (Mutex::new (vec! ()));
        let poll_write_params_arc_a = poll_write_params_arc.clone ();
        let (tx, rx) = mpsc::channel();
        thread::spawn (move || {
            let system = System::new("stream_handler_pool_creates_nonexistent_stream_for_reading_and_writing");
            let discriminator_factory = JsonDiscriminatorFactory::new ();
            let mut subject = StreamHandlerPool::new(vec! (Box::new (discriminator_factory)));
            subject.stream_connector = Box::new (StreamConnectorMock::new()
                .connect_pair_result(Ok (ConnectionInfo {
                    reader: Box::new (ReadHalfWrapperMock::new ()
                        .poll_read_ok (incoming_masked)
                        .poll_read_result (vec! (),Ok (Async::NotReady))),
                    writer: Box::new (WriteHalfWrapperMock::new ()
                        .poll_write_ok (outgoing_masked_len)
                        .poll_write_result (Ok (Async::NotReady))
                        .poll_write_params (&poll_write_params_arc)),
                    local_addr: SocketAddr::from_str ("127.0.0.1:54321").unwrap (),
                    peer_addr: SocketAddr::from_str ("1.2.3.5:7000").unwrap (),
                })));
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None, Some(neighborhood));
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            tx.send(subject_subs).unwrap();

            system.run();
        });

        let subject_subs = rx.recv().unwrap();

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Key(public_key.clone()),
            last_data: false,
            sequence_number: Some(0),
            data: outgoing_unmasked,
        }).unwrap();

        neighborhood_awaiter.await_message_count(1);
        let node_query_msg = Recording::get::<DispatcherNodeQueryMessage>(&neighborhood_recording_arc, 0);
        subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
            result: Some(NodeDescriptor::new(public_key, Some(NodeAddr::new(&IpAddr::V4 (Ipv4Addr::new (1, 2, 3, 5)), &vec!(7000))))),
            context: node_query_msg.context,
        }).unwrap();

        await_messages (1, &poll_write_params_arc_a);
        let poll_write_params = poll_write_params_arc_a.lock ().unwrap ();
        assert_eq! (poll_write_params[0], outgoing_masked);

        dispatcher_awaiter.await_message_count (1);
        let dispatcher_recording = dispatcher_recording_arc.lock ().unwrap ();
        let ibcd = dispatcher_recording.get_record::<InboundClientData> (0);
        assert_eq! (ibcd, &InboundClientData {
            socket_addr: SocketAddr::from_str ("1.2.3.5:7000").unwrap (),
            origin_port: Some (54321),
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: incoming_unmasked,
        });
    }

    #[test]
    fn transmit_data_msg_handler_finds_ip_from_neighborhood_and_transmits_message() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let reader = ReadHalfWrapperMock::new ()
            .poll_read_result(vec! (), Ok (Async::NotReady));
        let write_stream_params_arc = Arc::new (Mutex::new (vec! ()));
        let writer = WriteHalfWrapperMock::new ()
            .poll_write_result(Err(Error::from(ErrorKind::Other)))
            .poll_write_result (Ok (Async::Ready(5)))
            .poll_write_result (Ok (Async::NotReady))
            .poll_write_params (&write_stream_params_arc);
        let local_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let peer_addr = SocketAddr::from_str("1.2.3.5:6789").unwrap();

        let mut sender = SenderWrapperMock::new();
        sender.unbounded_send_results = vec!( Ok(()) );
        let sender_params = sender.unbounded_send_params.clone();
        let mut receiver = ReceiverWrapperMock::new();
        receiver.poll_results = vec!(
            Ok(Async::Ready(Some(SequencedPacket::new(b"hello".to_vec(), 0, true)))),
            Ok(Async::NotReady)
        );
        let channel_factory: FuturesChannelFactoryMock<SequencedPacket> = FuturesChannelFactoryMock { results: vec!((Box::new(sender), Box::new(receiver)))};
        let (neighborhood, awaiter, recording_arc) = make_recorder();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.channel_factory = Box::new(channel_factory);

            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors_from(None, None, None, None, Some(neighborhood));
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            let connection_info = ConnectionInfo {
                reader: Box::new (reader),
                writer: Box::new (writer),
                local_addr,
                peer_addr,
            };

            subject_subs.add_sub.try_send(AddStreamMsg::new (
                connection_info,
                None,
                PortConfiguration::new(vec!(Box::new(JsonDiscriminatorFactory::new())), true),
                Box::new(NullMasquerader::new())
            )).unwrap();

            tx.send(subject_subs).unwrap();

            system.run();
        });

        let subject_subs = rx.recv().unwrap();

        subject_subs.transmit_sub.try_send(TransmitDataMsg {
            endpoint: Endpoint::Key(key.clone()),
            last_data: true,
            sequence_number: Some(0),
            data: b"hello".to_vec(),
        }).unwrap();

        awaiter.await_message_count(1);
        let node_query_msg = Recording::get::<DispatcherNodeQueryMessage>(&recording_arc, 0);
        subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
            result: Some(NodeDescriptor::new(key, Some(NodeAddr::new(&IpAddr::V4 (Ipv4Addr::new (1, 2, 3, 5)), &vec!(6789))))),
            context: node_query_msg.context,
        }).unwrap();

        await_messages(1, &sender_params);
        let mut shp_to_sw_params = sender_params.lock().unwrap();
        assert_eq!(shp_to_sw_params.len(), 1);
        assert_eq!(shp_to_sw_params.remove(0), SequencedPacket::new(b"hello".to_vec(), 0, true));

        await_messages(2, &write_stream_params_arc);
        let mut sw_to_stream_params = write_stream_params_arc.lock().unwrap();
        assert_eq!(sw_to_stream_params.len(), 2);
        assert_eq!(sw_to_stream_params.remove(0), b"hello");
    }

    #[test]
    fn node_query_response_handler_does_not_try_to_write_when_neighbor_is_not_found() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let sender = SenderWrapperMock::new();
        let sender_params = sender.unbounded_send_params.clone();
        let receiver = ReceiverWrapperMock::new();
        let channel_factory = FuturesChannelFactoryMock { results: vec!((Box::new(sender), Box::new(receiver)))};

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.channel_factory = Box::new(channel_factory);

            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            subject_subs.node_query_response.try_send( DispatcherNodeQueryResponse {
                result: None,
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(key),
                    last_data: false,
                    sequence_number: Some(0),
                    data: b"hello".to_vec(),
                }
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_containing(format!("ERROR: Dispatcher: No neighbor found at endpoint {:?}", Endpoint::Key (cryptde.public_key())).as_str(), 1000);

        let shp_to_sw_params = sender_params.lock().unwrap();
        assert_eq!(shp_to_sw_params.len(), 0);
    }

    #[test]
    fn node_query_response_handler_does_not_try_to_write_when_neighbor_ip_is_not_known() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let sender = SenderWrapperMock::new();
        let sender_params = sender.unbounded_send_params.clone();
        let receiver = ReceiverWrapperMock::new();
        let channel_factory = FuturesChannelFactoryMock { results: vec!((Box::new(sender), Box::new(receiver)))};

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.channel_factory = Box::new(channel_factory);

            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
                result: Some(NodeDescriptor::new(key.clone(), None)),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(key),
                    last_data: true,
                    sequence_number: None,
                    data: b"hello".to_vec(),
                },
            }).unwrap();

            system.run();
        });

        TestLogHandler::new ().await_log_containing(format!("ERROR: Dispatcher: No known IP for neighbor in route with key: {}", cryptde.public_key()).as_str(), 1000);

        let shp_to_sw_params = sender_params.lock().unwrap();
        assert_eq!(shp_to_sw_params.len(), 0);
    }

    #[test]
    fn node_query_response_handler_resends_transmit_data_msg_when_connection_is_in_progress() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let peer_addr_a = peer_addr.clone();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: true,
            sequence_number: Some(0),
            data: b"hello".to_vec(),
        };
        let msg_a = msg.clone();

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.stream_writers.insert(peer_addr.clone(), None);
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
                result: Some(NodeDescriptor::new(key, Some(NodeAddr::new(&peer_addr.ip(), &vec!(peer_addr.port()))))),
                context: msg,
            }).unwrap();

            tx.send(subject_subs).expect("Tx failure");

            system.run();
        });
        let subject_subs = rx.recv().unwrap();

        TestLogHandler::new ().await_log_containing(format!("INFO: connection for {} in progress, resubmitting {} bytes", peer_addr_a, msg_a.data.len()).as_str(), 1000);

        let local_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let poll_write_params_arc = Arc::new(Mutex::new(Vec::new()));

        let connection_info = ConnectionInfo {
            reader: Box::new (ReadHalfWrapperMock::new ()
                .poll_read_result (vec! (), Ok(Async::NotReady))),
            writer: Box::new (WriteHalfWrapperMock::new ()
                .poll_write_result(Ok (Async::NotReady))
                .poll_write_params(&poll_write_params_arc)
            ),
            local_addr,
            peer_addr: peer_addr_a,
        };

        subject_subs.add_sub.try_send(AddStreamMsg::new(
            connection_info,
            Some(80u16),
            PortConfiguration::new(
                vec!(Box::new(HttpRequestDiscriminatorFactory::new())),
                false),
            Box::new(NullMasquerader::new()))).unwrap();

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc.lock().unwrap();

        assert_eq!(poll_write_params[0], msg_a.data);
    }

    #[test]
    fn when_a_new_connection_fails_the_stream_writer_flag_is_removed_and_another_connection_is_attempted_for_the_next_message_with_the_same_stream_key() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let peer_addr_a = peer_addr.clone();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: true,
            sequence_number: Some(0),
            data: b"hello".to_vec(),
        };
        let msg_a = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: true,
            sequence_number: Some(0),
            data: b"worlds".to_vec(),
        };

        let local_addr = SocketAddr::from_str("1.2.3.4:80").unwrap();
        let poll_write_params_arc = Arc::new(Mutex::new(Vec::new()));

        let connection_info = ConnectionInfo {
            reader: Box::new (ReadHalfWrapperMock::new ()
                .poll_read_result (vec! (), Ok(Async::NotReady))),
            writer: Box::new (WriteHalfWrapperMock::new ()
                .poll_write_params(&poll_write_params_arc)
                .poll_write_result(Ok (Async::Ready(5)))
            ),
            local_addr,
            peer_addr: peer_addr_a,
        };

        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("test");
            let mut subject = StreamHandlerPool::new(vec! ());
            subject.stream_connector = Box::new(StreamConnectorMock::new()
                .connect_pair_result(Err(Error::from(ErrorKind::Other)))
                .connect_pair_result(Ok(connection_info)));
            subject.clandestine_discriminator_factories = vec!(Box::new(HttpRequestDiscriminatorFactory::new()));
            let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
            let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
            let peer_actors = make_peer_actors();
            subject_subs.bind.try_send(PoolBindMessage {
                dispatcher_subs: peer_actors.dispatcher,
                stream_handler_pool_subs: subject_subs.clone(),
                neighborhood_subs: peer_actors.neighborhood,
            }).unwrap();

            subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
                result: Some(NodeDescriptor::new(key, Some(NodeAddr::new(&peer_addr.ip(), &vec!(peer_addr.port()))))),
                context: msg,
            }).unwrap();

            tx.send(subject_subs).expect("Tx failure");

            system.run();
        });
        let subject_subs = rx.recv().unwrap();

        let expected_data = JsonMasquerader::new().mask(&msg_a.data).unwrap();
        subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
            result: Some(NodeDescriptor::new(cryptde.public_key(), Some(NodeAddr::new(&peer_addr.ip(), &vec!(peer_addr.port()))))),
            context: msg_a,
        }).unwrap();

        await_messages(1, &poll_write_params_arc);
        let poll_write_params = poll_write_params_arc.lock().unwrap();

        assert_eq!(poll_write_params[0], expected_data);
        assert_eq!(poll_write_params.len(), 1);
    }

    #[test]
    #[should_panic (expected = "Neighborhood has returned a NodeDescriptor with no ports. This indicates an irrecoverable error.")]
    fn when_node_query_response_node_addr_contains_no_ports_then_stream_handler_pool_panics() {
        init_test_logging();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let peer_addr = SocketAddr::from_str("5.4.3.1:8000").unwrap();
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(peer_addr.clone()),
            last_data: true,
            sequence_number: None,
            data: b"hello".to_vec(),
        };

        let system = System::new("test");
        let subject = StreamHandlerPool::new(vec! ());
        let subject_addr: Addr<Syn, StreamHandlerPool> = subject.start();
        let subject_subs = StreamHandlerPool::make_subs_from(&subject_addr);
        let peer_actors = make_peer_actors();
        subject_subs.bind.try_send(PoolBindMessage {
            dispatcher_subs: peer_actors.dispatcher,
            stream_handler_pool_subs: subject_subs.clone(),
            neighborhood_subs: peer_actors.neighborhood,
        }).unwrap();

        subject_subs.node_query_response.try_send(DispatcherNodeQueryResponse {
            result: Some(NodeDescriptor::new(key, Some(NodeAddr::new(&peer_addr.ip(), &vec!())))),
            context: msg,
        }).unwrap();

        system.run();
    }
}
