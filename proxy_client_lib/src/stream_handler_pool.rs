// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use actix::Arbiter;
use actix::Recipient;
use actix::Syn;
use futures::future::Executor;
use futures::future::Future;
use tokio;
use tokio::io::AsyncRead;
use tokio::net::TcpStream;
use resolver_wrapper::ResolverWrapper;
use stream_handler_establisher::StreamEstablisherFactory;
use stream_handler_establisher::StreamEstablisherFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::StreamKey;
use sub_lib::framer::Framer;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_packet_framer::HttpPacketFramer;
use sub_lib::http_response_start_finder::HttpResponseStartFinder;
use sub_lib::logger::Logger;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::route::Route;
use sub_lib::tls_framer::TlsFramer;
use sub_lib::tokio_wrappers::ReadHalfWrapperReal;
use sub_lib::tokio_wrappers::WriteHalfWrapperReal;
use sub_lib::tokio_wrappers::ReadHalfWrapper;
use sub_lib::tokio_wrappers::WriteHalfWrapper;

pub trait StreamConnector {
    fn connect(&self, ip_addrs: Vec<IpAddr>, target_hostname: &String, target_port: u16, logger: &Logger) -> Result<TcpStream, io::Error>;
    fn dup(&self) -> Box<StreamConnector>;
}

#[derive(Clone)]
struct StreamConnectorReal {}

impl StreamConnector for StreamConnectorReal {
    fn connect(&self, ip_addrs: Vec<IpAddr>, target_hostname: &String, target_port: u16, logger: &Logger) -> Result<TcpStream, io::Error> {
        let mut last_error = Error::from(ErrorKind::Other);
        let mut socket_addrs_tried = vec!();
        // TODO spike: can we do this with something like OrderedFutures?
        for ip_addr in ip_addrs {
            let (tx, rx) = mpsc::channel();
            let socket_addr = SocketAddr::new(ip_addr, target_port);
            let future = TcpStream::connect(&socket_addr)
                .then(move |result| {
                    tx.send(result).is_ok();
                    Ok(())
                });
            tokio::spawn(future);
            loop {
                match rx.recv() {
                    Ok(Ok(stream)) => {
                        logger.debug(format!("Connected new stream to {}", socket_addr));
                        return Ok(stream);
                    },
                    Ok(Err(e)) => {
                        last_error = e;
                        socket_addrs_tried.push(format!("{}", socket_addr));
                        break;
                    },
                    Err(_) => break,
                }
            }
        }

        logger.error(format!("Could not connect to any of the IP addresses supplied for {}: {:?}",
                             target_hostname, socket_addrs_tried));
        Err(last_error)
    }
    fn dup(&self) -> Box<StreamConnector> {
        Box::new(self.clone())
    }
}

pub trait StreamSplitter {
    fn split_stream(&self, stream: io::Result<TcpStream>) -> io::Result<(Box<ReadHalfWrapper>, Box<WriteHalfWrapper>, io::Result<SocketAddr>)>;
    fn dup(&self) -> Box<StreamSplitter>;
}

#[derive(Clone)]
struct StreamSplitterReal {}

impl StreamSplitter for StreamSplitterReal {
    fn split_stream(&self, stream: io::Result<TcpStream>) -> io::Result<(Box<ReadHalfWrapper>, Box<WriteHalfWrapper>, io::Result<SocketAddr>)> {
        match stream {
            Ok(stream_unwrapped) => {
                let peer_addr = stream_unwrapped.peer_addr();
                let (reader, writer) = stream_unwrapped.split();
                Ok((
                    Box::new(ReadHalfWrapperReal::new(reader)),
                    Box::new(WriteHalfWrapperReal::new(writer)),
                    peer_addr,
                ))
            }
            Err(e) => Err(e)
        }
    }
    fn dup(&self) -> Box<StreamSplitter> {
        Box::new(self.clone())
    }
}

pub trait StreamHandlerPool {
    fn process_package(&mut self, package: ExpiredCoresPackage);
}

pub struct StreamHandlerPoolReal {
    hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    stream_writer_channels: HashMap<StreamKey, Box<SenderWrapper<ExpiredCoresPackage>>>,
    stream_adder_rx: Receiver<(StreamKey, Box<SenderWrapper<ExpiredCoresPackage>>)>,
    stream_killer_rx: Receiver<StreamKey>,
    resolver: Box<ResolverWrapper>,
    _cryptde: &'static CryptDE, // This is not used now, but a version of it may be used in the future when ser/de and en/decrypt are combined.
    logger: Logger,
    establisher_factory: Box<StreamEstablisherFactory>,
}

impl StreamHandlerPool for StreamHandlerPoolReal {
    fn process_package(&mut self, package: ExpiredCoresPackage) {
        self.logger.debug(format!("Received ExpiredCoresPackage with {}-byte payload", package.payload.data.len()));
        self.do_housekeeping();

        let mut to_remove = None;
        let payload = match self.extract_payload(&package) {
            Ok(p) => p,
            Err(_) => {
                self.logger.error(format!("Could not extract ClientRequestPayload from ExpiredCoresPackage: {:?}", &package));
                return;
            }
        };
        match self.stream_writer_channels.get_mut(&payload.stream_key) {
            Some(ref mut writer_channel) => {
                match StreamHandlerPoolReal::perform_write(package.clone(), writer_channel) {
                    Ok (_) => {
                        if payload.last_data {
                            to_remove = Some(payload.stream_key.clone());
                        }
                        ()
                    },
                    Err (_) => {
                        to_remove = Some(payload.stream_key.clone());
                        self.logger.debug(format!("Writing {} bytes to {} over existing stream", payload.data.data.len(), &payload.stream_key));
                        StreamHandlerPoolReal::send_terminating_package(package.clone().remaining_route, &payload, &self.hopper_sub)
                    }
                }
            },
            None => {
                // TODO: Figure out what to do if a flurry of requests for a particular stream key
                // come flooding in so densely that several of them arrive in the time it takes to
                // resolve the first one and add it to the stream_writers map.
                self.logger.debug(format!("No stream to {:?} exists; resolving host", &payload.target_hostname));
                let mut fqdn = match &payload.target_hostname {
                    &None => {
                        self.logger.error(format!("Cannot open new stream with key {}: no hostname supplied", payload.stream_key));
                        StreamHandlerPoolReal::send_terminating_package(package.remaining_route, &payload, &self.hopper_sub);
                        return;
                    },
                    &Some(ref s) => s.clone()
                };
                fqdn.push('.');
                let mut establisher = self.establisher_factory.make();
                let future = self.resolver.lookup_ip(&fqdn[..]).then(move |lookup_result| {
                    establisher.logger.debug (format! ("Resolution closure beginning"));
                        let remaining_route = package.remaining_route.clone();
                        establisher.establish_stream(&payload, &package, lookup_result)
                            .and_then(|mut stream_writer| {
                                StreamHandlerPoolReal::perform_write(package, &mut stream_writer)
                            })
                            .map_err(|_| {
                                StreamHandlerPoolReal::send_terminating_package(remaining_route, &payload, &establisher.hopper_sub);
                            })
                });
                self.logger.debug (format! ("Host resolution scheduled"));
                Arbiter::handle ().execute (future).expect ("Actix executor failed for TRustDNSResolver");
            }
        }

        if let Some(socket_addr) = to_remove {
            self.logger.trace(format!("Removing stream writer for {}", socket_addr));
            self.stream_writer_channels.remove(&socket_addr);
        }
    }
}

impl StreamHandlerPoolReal {
    pub fn new(resolver: Box<ResolverWrapper>, cryptde: &'static CryptDE, hopper_sub: Recipient<Syn, IncipientCoresPackage>) -> StreamHandlerPoolReal {
        let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
        let (stream_adder_tx, stream_adder_rx) = mpsc::channel();
        StreamHandlerPoolReal {
            establisher_factory: Box::new(StreamEstablisherFactoryReal {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorReal {}),
                stream_splitter: Box::new(StreamSplitterReal {}),
                hopper_sub: hopper_sub.clone(),
                logger: Logger::new("Proxy Client"),
            }),
            hopper_sub,
            stream_writer_channels: HashMap::new(),
            stream_adder_rx,
            stream_killer_rx,
            resolver,
            _cryptde: cryptde,
            logger: Logger::new("Proxy Client"),
        }
    }

    fn do_housekeeping(&mut self) {
        self.clean_up_dead_streams();
        self.add_new_streams();
    }

    fn clean_up_dead_streams(&mut self) {
        loop {
            match self.stream_killer_rx.try_recv() {
                Ok(stream_key) => {
                    match self.stream_writer_channels.remove(&stream_key) {
                        Some(_) => self.logger.debug(format!("Killed StreamWriter under key {}", stream_key)),
                        None => self.logger.debug(format!("Tried to kill StreamWriter for key {}, but it was not found", stream_key))
                    }
                },
                Err(_) => break,
            };
        }
    }

    fn add_new_streams(&mut self) {
        loop {
            match self.stream_adder_rx.try_recv() {
                Err(_) => break,
                Ok((stream_key, stream_writer_channel)) => {
                    self.logger.debug(format!("Persisting StreamWriter under key {}", stream_key));
                    self.stream_writer_channels.insert(stream_key, stream_writer_channel)
                }
            };
        }
    }

    fn extract_payload(&self, package: &ExpiredCoresPackage) -> io::Result<ClientRequestPayload> {
        match package.payload::<ClientRequestPayload>() {
            Err(e) => {
                self.logger.error(format!("Error ('{}') interpreting payload for transmission: {:?}", e, package.payload.data));
                Err(Error::from(ErrorKind::Other))
            }
            Ok(payload) => Ok(payload)
        }
    }

    fn perform_write(package: ExpiredCoresPackage, writer_ref: &mut Box<SenderWrapper<ExpiredCoresPackage>>) -> io::Result<()> {
        writer_ref.unbounded_send(package).map_err(|_| Error::from(ErrorKind::BrokenPipe))
    }

    pub fn framer_from_protocol(protocol: ProxyProtocol) -> Box<Framer> {
        match protocol {
            ProxyProtocol::HTTP => Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {}))),
            ProxyProtocol::TLS => Box::new(TlsFramer::new())
        }
    }

    fn send_terminating_package(route: Route, request: &ClientRequestPayload, hopper_sub: &Recipient<Syn, IncipientCoresPackage>) {
        let response = ClientResponsePayload::make_terminating_payload(request.stream_key);
        let package = IncipientCoresPackage::new(route, response, &request.originator_public_key);
        hopper_sub.try_send(package).expect("Hopper died");
    }
}

pub trait StreamHandlerPoolFactory {
    fn make(&self, resolver: Box<ResolverWrapper>, cryptde: &'static CryptDE,
            hopper_sub: Recipient<Syn, IncipientCoresPackage>) -> Box<StreamHandlerPool>;
}

pub struct StreamHandlerPoolFactoryReal {}

impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
    fn make(&self, resolver: Box<ResolverWrapper>, cryptde: &'static CryptDE,
            hopper_sub: Recipient<Syn, IncipientCoresPackage>) -> Box<StreamHandlerPool> {
        Box::new(StreamHandlerPoolReal::new(resolver, cryptde, hopper_sub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use actix::Actor;
    use actix::Addr;
    use actix::Context;
    use actix::Handler;
    use actix::System;
    use futures::lazy;
    use futures::Stream;
    use futures::sync::mpsc::unbounded;
    use serde_cbor;
    use tokio;
    use tokio::prelude::Async;
    use trust_dns_resolver::error::ResolveError;
    use trust_dns_resolver::error::ResolveErrorKind;
    use local_test_utils::make_send_error;
    use local_test_utils::ResolverWrapperMock;
    use local_test_utils::StreamConnectorMock;
    use local_test_utils::StreamSplitterMock;
    use stream_handler_establisher::StreamHandlerEstablisher;
    use stream_handler_establisher::StreamEstablisherFactory;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::channel_wrapper_mocks::FuturesChannelFactoryMock;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use test_utils::test_utils;
    use test_utils::recorder;
    use test_utils::test_utils::cryptde;
    use test_utils::logging::init_test_logging;
    use test_utils::recorder::Recorder;
    use test_utils::logging::TestLogHandler;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::make_peer_actors_from;
    use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
    use sub_lib::channel_wrappers::SenderWrapperReal;
    use test_utils::test_utils::await_messages;

    #[derive(Message)]
    struct TriggerSubject {
        package: ExpiredCoresPackage
    }

    struct TestActor {
        subject: StreamHandlerPoolReal
    }

    impl Actor for TestActor {
        type Context = Context<Self>;
    }

    impl Handler<TriggerSubject> for TestActor {
        type Result = ();

        fn handle(&mut self, msg: TriggerSubject, _ctx: &mut Self::Context) -> <Self as Handler<TriggerSubject>>::Result {
            self.subject.process_package(msg.package);
            ()
        }
    }

    struct StreamEstablisherFactoryMock {
        make_results: RefCell<Vec<StreamHandlerEstablisher>>
    }

    impl StreamEstablisherFactory for StreamEstablisherFactoryMock {
        fn make(&self) -> StreamHandlerEstablisher {
            self.make_results.borrow_mut().remove(0)
        }
    }

    #[test]
    fn invalid_package_is_logged_and_discarded() {
        init_test_logging();
        let hopper = Recorder::new();
        let recording = hopper.get_recording();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None).hopper.from_hopper_client;
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&b"invalid"[..]));
            let subject = StreamHandlerPoolReal::new(Box::new(ResolverWrapperMock::new()),
                                                     cryptde(), hopper_sub);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        TestLogHandler::new().await_log_containing("ERROR: Proxy Client: Error ('EOF while parsing a value at offset 7') interpreting payload for transmission: [105, 110, 118, 97, 108, 105, 100]", 1000);
        assert_eq!(recording.lock().unwrap().len(), 0);
    }

    #[test]
    fn non_terminal_payload_can_be_sent_over_existing_connection() {
        let client_request_payload = ClientRequestPayload {
            stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            last_data: false,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
            sequence_number: 0,
        };
        let mut tx_to_write = Box::new(SenderWrapperMock::new());
        tx_to_write.unbounded_send_results = vec!(Ok(()));
        let write_parameters = tx_to_write.unbounded_send_params.clone();
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));

        let expected_package = package.clone();

        thread::spawn(move || {
            let system = System::new("test");

            let hopper = Recorder::new();
            let hopper_sub = make_peer_actors_from(None, None, Some(hopper), None, None).hopper.from_hopper_client;
            let mut subject = StreamHandlerPoolReal::new(Box::new(ResolverWrapperMock::new()),
                                                         cryptde(), hopper_sub);
            subject.stream_writer_channels.insert(client_request_payload.stream_key,
                                                  tx_to_write);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &write_parameters.clone());

        assert_eq!(write_parameters.lock().unwrap().remove(0), expected_package);
    }

    #[test]
    fn write_failure_for_nonexisting_stream_generates_termination_message() {
        init_test_logging();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let mut tx_to_write: SenderWrapperMock<ExpiredCoresPackage> = SenderWrapperMock::new();
            tx_to_write.unbounded_send_results = vec!(make_send_error(package.clone()));

            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         cryptde(), hopper_sub);
            subject.stream_writer_channels.insert(client_request_payload.stream_key,
                                          Box::new(tx_to_write));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let payload = serde_cbor::de::from_slice::<ClientResponsePayload>(&package.payload.data[..]).unwrap();
        assert_eq!(payload.last_response, true);
    }

    #[test]
    fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message() {
        init_test_logging();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let payload = serde_cbor::de::from_slice::<ClientResponsePayload>(&package.payload.data[..]).unwrap();
        assert_eq!(payload.last_response, true);
        TestLogHandler::new().exists_log_containing("ERROR: Proxy Client: Cannot open new stream with key 1.2.3.4:5678: no hostname supplied");
    }

    #[test]
    fn nonexistent_connection_springs_into_being_and_is_persisted_to_handle_transaction() {
        let lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec!()));
        let expected_write_parameters = write_parameters.clone();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap(), IpAddr::from_str("3.4.5.6").unwrap()));
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = Box::new(ReadHalfWrapperMock { poll_read_results: vec!((b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))), (vec!(), Err(Error::from(ErrorKind::ConnectionAborted)))) });
            let writer = Box::new(WriteHalfWrapperMock { poll_write_params: write_parameters, poll_write_results: vec!(Ok(Async::Ready(123))) });
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamHandlerEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock { connect_params: Arc::new(Mutex::new(vec!())) }),
                stream_splitter: Box::new(StreamSplitterMock { split_stream_results: RefCell::new(vec!((reader, writer, Ok(peer_addr)))) }),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock { make_results: RefCell::new(vec!(establisher)) });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        assert_eq!(expected_lookup_ip_parameters.lock().unwrap().deref(), &vec!(String::from("that.try.")));
        assert_eq!(expected_write_parameters.lock().unwrap().remove(0), b"These are the times".to_vec());
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(*record, IncipientCoresPackage::new(
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_response: false,
                sequence_number: 0,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"men's souls"[..]),
        ));
    }

    #[test]
    fn stream_splitter_returns_error_when_connection_result_sent_in_is_error() {
        let subject = StreamSplitterReal {};

        let result = subject.split_stream(Err(Error::from(ErrorKind::Other)));

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::Other);
    }

    #[test]
    fn failing_to_make_a_connection_sends_an_error_response() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key,
                last_data: false,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap(), IpAddr::from_str("3.4.5.6").unwrap()));
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let broken_stream_splitter = StreamSplitterMock { split_stream_results: RefCell::new(vec!())};
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamHandlerEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock { connect_params: Arc::new(Mutex::new(vec!())) }),
                stream_splitter: Box::new(broken_stream_splitter),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock { make_results: RefCell::new(vec!(establisher)) });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(client_response_payload, ClientResponsePayload::make_terminating_payload(stream_key));
    }

    #[test]
    fn trying_to_write_to_disconnected_stream_writer_sends_an_error_response() {
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
        let write_parameters = Arc::new(Mutex::new(vec!()));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn (move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;

            let client_request_payload = ClientRequestPayload {
                stream_key,
                last_data: false,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap(), IpAddr::from_str("3.4.5.6").unwrap()));
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = Box::new(ReadHalfWrapperMock { poll_read_results: vec!((b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))), (vec!(), Err(Error::from(ErrorKind::ConnectionAborted)))) });
            let writer = Box::new(WriteHalfWrapperMock { poll_write_params: write_parameters, poll_write_results: vec!(Ok(Async::Ready(123))) });
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let disconnected_sender = Box::new(SenderWrapperMock {
                unbounded_send_params: Arc::new(Mutex::new(vec![])),
                unbounded_send_results: vec![make_send_error(package.clone())],
            });
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamHandlerEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock { connect_params: Arc::new(Mutex::new(vec!())) }),
                stream_splitter: Box::new(StreamSplitterMock { split_stream_results: RefCell::new(vec!((reader, writer, Ok(peer_addr)))) }),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryMock {
                    results: vec![(disconnected_sender, Box::new(ReceiverWrapperMock {poll_results: vec![]}))]
                }),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock { make_results: RefCell::new(vec!(establisher)) });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(client_response_payload, ClientResponsePayload::make_terminating_payload(stream_key));
    }

    #[test]
    fn bad_dns_lookup_produces_log_and_sends_error_response() {
        init_test_logging();
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let recording_arc = hopper.get_recording();
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key,
                last_data: true,
                sequence_number: 0,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let mut lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&mut lookup_ip_parameters)
                .lookup_ip_failure(ResolveError::from(ResolveErrorKind::Io));
            let subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        TestLogHandler::new().await_log_containing("ERROR: Proxy Client: Could not find IP address for host that.try: io error", 1000);
        hopper_awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(client_response_payload, ClientResponsePayload::make_terminating_payload(stream_key));
    }

    #[test]
    fn after_writing_last_data_the_stream_should_close() {
        init_test_logging();
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let (tx_to_write, mut rx_to_write) = unbounded();
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            last_data: true,
            sequence_number: 0,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let package_a = package.clone();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new();
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            subject.stream_writer_channels.insert(stream_key, Box::new(SenderWrapperReal::new(tx_to_write)));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        let test_future = lazy(move || {
            let _ = tx.send(rx_to_write.poll());
            let _ = tx.send(rx_to_write.poll());
            Ok(())
        });

        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            tokio::run(test_future);
        });

        let rx_to_write_params = rx.recv().unwrap();
        assert_eq!(rx_to_write_params, Ok(Async::Ready(Some(package_a))));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");

        let rx_to_write_result = rx.recv().unwrap();
        assert_eq!(rx_to_write_result, Ok(Async::Ready(None))); // Ok(Async::Ready(None)) indicates that all TXs to the channel are gone
    }

    #[test]
    fn error_from_tx_to_writer_removes_stream() {
        init_test_logging();
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            last_data: true,
            sequence_number: 0,
            data: PlainData::new(&b"These are the times"[..]),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                               PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
        let package_a = package.clone();
        let mut sender_wrapper = SenderWrapperMock::new();
        sender_wrapper.unbounded_send_results = vec!(make_send_error(package.clone()));
        let send_params = sender_wrapper.unbounded_send_params.clone();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub =
                recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new();

            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            subject.stream_writer_channels.insert(stream_key, Box::new(sender_wrapper));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> = addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &send_params);
        assert_eq!(*send_params.lock().unwrap(), vec!(package_a));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");
    }
}
