// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use actix::Arbiter;
use actix::Subscriber;
use futures::future::Executor;
use futures::future::Future;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
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
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactory;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactoryReal;
use sub_lib::tls_framer::TlsFramer;
use resolver_wrapper::ResolverWrapper;
use stream_writer::StreamWriter;
use stream_handler_establisher::StreamHandlerEstablisher;
use std::net::Shutdown;

pub trait StreamHandlerPool {
    fn process_package (&mut self, package: ExpiredCoresPackage);
}

pub struct StreamHandlerPoolReal {
    pub hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>,
    pub stream_writers: HashMap<StreamKey, StreamWriter>,
    pub stream_adder_tx: Sender<(StreamKey, StreamWriter)>,
    pub stream_adder_rx: Receiver<(StreamKey, StreamWriter)>,
    pub stream_killer_tx: Sender<StreamKey>,
    pub stream_killer_rx: Receiver<StreamKey>,
    pub tcp_stream_wrapper_factory: Box<TcpStreamWrapperFactory>,
    resolver: Box<ResolverWrapper>,
    cryptde: Box<CryptDE>,
    logger: Logger,
}

impl StreamHandlerPool for StreamHandlerPoolReal {

    fn process_package (&mut self, package: ExpiredCoresPackage) {
        self.logger.debug (format! ("Received ExpiredCoresPackage with {}-byte payload", package.payload.data.len ()));
        self.do_housekeeping ();
        let payload = match self.extract_payload (&package) {
            Ok (p) => p,
            Err (_) => {
                self.logger.error (format! ("Could not extract ClientRequestPayload from ExpiredCoresPackage: {:?}", &package));
                return
            }
        };
        let hopper_sub = self.hopper_sub.clone ();
        let mut establisher = StreamHandlerEstablisher::new (self);
        let mut stream_writer_ref_opt = self.stream_writers.get_mut (&payload.stream_key);
        match stream_writer_ref_opt {
            Some (ref mut writer_ref) => {
                self.logger.debug (format! ("Writing {} bytes to {} over existing stream", payload.data.data.len (), writer_ref.peer_addr ()));
                match StreamHandlerPoolReal::perform_write (&payload, writer_ref) {
                    Ok (_) => (),
                    Err (_) => {
                        StreamHandlerPoolReal::send_terminating_package(package.remaining_route, &payload, &hopper_sub)
                    }
                }
            },
            None => {
                // TODO: Figure out what to do if a flurry of requests for a particular stream key
                // come flooding in so densely that several of them arrive in the time it takes to
                // resolve the first one and add it to the stream_writers map.
                self.logger.debug (format! ("No stream to {:?} exists; resolving host", &payload.target_hostname));
                let mut fqdn = match &payload.target_hostname {
                    &None => {
                        self.logger.error (format! ("Cannot open new stream with key {}: no hostname supplied", payload.stream_key));
                        StreamHandlerPoolReal::send_terminating_package(package.remaining_route, &payload, &hopper_sub);
                        return
                    },
                    &Some (ref s) => s.clone ()
                };
                fqdn.push('.');
                let future = self.resolver.lookup_ip(&fqdn[..]).then(move |lookup_result| {
                    establisher.logger.debug (format! ("Resolution closure beginning"));
                    let write_result = establisher.after_resolution (&payload, &package, lookup_result).and_then (|mut stream_writer| {
                        StreamHandlerPoolReal::perform_write (&payload, &mut stream_writer)
                    });
                    match write_result {
                        Ok (_) => (),
                        Err (_) => {
                            StreamHandlerPoolReal::send_terminating_package(package.remaining_route, &payload, &establisher.hopper_sub)
                        }
                    }
                    let result: Result<(), ()> = Ok (());
                    result
                });
                self.logger.debug (format! ("Host resolution scheduled"));
                Arbiter::handle ().execute (future).expect ("Actix executor failed for TRustDNSResolver");
                self.logger.debug (format! ("Closure spawned"));
            }
        }
    }
}

impl StreamHandlerPoolReal {
    pub fn new (resolver: Box<ResolverWrapper>, cryptde: Box<CryptDE>, hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>) -> StreamHandlerPoolReal {
        let (stream_killer_tx, stream_killer_rx) = mpsc::channel ();
        let (stream_adder_tx, stream_adder_rx) = mpsc::channel ();
        StreamHandlerPoolReal {
            hopper_sub,
            stream_writers: HashMap::new (),
            stream_adder_tx,
            stream_adder_rx,
            stream_killer_tx,
            stream_killer_rx,
            tcp_stream_wrapper_factory: Box::new (TcpStreamWrapperFactoryReal {}),
            resolver,
            cryptde,
            logger: Logger::new ("Proxy Client")
        }
    }

    fn do_housekeeping (&mut self) {
        self.clean_up_dead_streams ();
        self.add_new_streams ();
    }

    fn clean_up_dead_streams (&mut self) {
        loop {
            match self.stream_killer_rx.try_recv () {
                Err (_) => break,
                Ok (stream_key) => {
                    match self.stream_writers.remove (&stream_key) {
                        Some (writer_ref) => self.logger.debug (format! ("Killed StreamWriter for stream to {} under key {}", writer_ref.peer_addr (), stream_key)),
                        None => self.logger.debug (format! ("Tried to kill StreamWriter for key {}, but it was not found", stream_key))
                    }
                }
            };
        }
    }

    fn add_new_streams (&mut self) {
        loop {
            match self.stream_adder_rx.try_recv () {
                Err (_) => break,
                Ok ((stream_key, stream_writer)) => {
                    self.logger.debug (format! ("Persisting StreamWriter to {} under key {}", stream_writer.peer_addr (), stream_key));
                    self.stream_writers.insert (stream_key, stream_writer)
                }
            };
        }
    }

    fn extract_payload (&self, package: &ExpiredCoresPackage) -> io::Result<ClientRequestPayload> {
        match package.payload::<ClientRequestPayload> () {
            Err(e) => {
                self.logger.error(format!("Error ('{}') interpreting payload for transmission: {:?}", e, package.payload.data));
                Err (Error::from (ErrorKind::Other))
            },
            Ok(payload) => Ok (payload)
        }
    }

    fn perform_write (payload_ref: &ClientRequestPayload, writer_ref: &mut StreamWriter) -> io::Result<()> {
        let logger = Logger::new ("Proxy Client");
        match writer_ref.write (&payload_ref.data.data[..]) {
            Err (e) => {
                logger.error (format! ("Error writing {} bytes to {}: {}", payload_ref.data.data.len (), writer_ref.peer_addr (), e));
                Err (e)
            },
            Ok (_) => {
                logger.debug (format! ("Wrote {} bytes to {}", &payload_ref.data.data.len (), writer_ref.peer_addr ()));
                Ok (())
            }
        }.and_then (|_count| {
            if payload_ref.last_data {
                writer_ref.shutdown (Shutdown::Both)
            }
            else {
                Ok (())
            }
        })
    }

    pub fn connect_stream (stream: &mut Box<TcpStreamWrapper>, ip_addrs: Vec<IpAddr>, target_hostname: &String, target_port: u16, logger: &Logger) -> io::Result<()> {
        let mut last_error = Error::from (ErrorKind::Other);
        let mut socket_addrs_tried = vec! ();
        for ip_addr in ip_addrs {
            let socket_addr = SocketAddr::new (ip_addr, target_port);
            match stream.connect (socket_addr) {
                Err (e) =>  {
                    last_error = e;
                    socket_addrs_tried.push (format! ("{}", socket_addr));
                },
                Ok (()) => {
                    logger.debug (format! ("Connected new stream to {}", socket_addr));
                    return Ok (())
                }
            }
        }
        logger.error (format! ("Could not connect to any of the IP addresses supplied for {}: {:?}",
                                    target_hostname, socket_addrs_tried));
        Err (last_error)
    }

    pub fn framer_from_protocol (protocol: ProxyProtocol) -> Box<Framer> {
        match protocol {
            ProxyProtocol::HTTP => Box::new (HttpPacketFramer::new (Box::new (HttpResponseStartFinder{}))),
            ProxyProtocol::TLS => Box::new (TlsFramer::new ())
        }
    }

    fn send_terminating_package(route: Route, request: &ClientRequestPayload, hopper_sub: &Box<Subscriber<IncipientCoresPackage> + Send>) {
        let response = ClientResponsePayload {
            stream_key: request.stream_key,
            last_response: true,
            data: PlainData::new (&[]),
        };
        let package = IncipientCoresPackage::new (route, response,
            &request.originator_public_key);
        hopper_sub.send (package).expect("Hopper died");
    }
}



pub trait StreamHandlerPoolFactory {
    fn make (&self, resolver: Box<ResolverWrapper>, cryptde: Box<CryptDE>,
        hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>) -> Box<StreamHandlerPool>;
}

pub struct StreamHandlerPoolFactoryReal {}

impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
    fn make(&self, resolver: Box<ResolverWrapper>, cryptde: Box<CryptDE>,
            hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>) -> Box<StreamHandlerPool> {
        Box::new(StreamHandlerPoolReal::new (resolver, cryptde, hopper_sub))
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use actix::System;
    use serde_cbor;
    use trust_dns_resolver::error::ResolveError;
    use trust_dns_resolver::error::ResolveErrorKind;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::test_utils;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::TestLogHandler;
    use local_test_utils::ResolverWrapperMock;
    use local_test_utils::TcpStreamWrapperFactoryMock;
    use local_test_utils::TcpStreamWrapperMock;
    use std::net::Shutdown;

    #[test]
    fn invalid_package_is_logged_and_discarded () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new ();
        let recording = hopper.get_recording ();
        thread::spawn (move || {
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some (hopper), None).hopper.from_hopper_client;
            let package = ExpiredCoresPackage::new (test_utils::make_meaningless_route (),
                PlainData::new (&b"invalid"[..]));
            let mut subject = StreamHandlerPoolReal::new (Box::new (ResolverWrapperMock::new ()),
                                                          Box::new (CryptDENull::new ()), hopper_sub);

            subject.process_package(package);

            system.run ();
        });

        TestLogHandler::new ().await_log_containing("ERROR: Proxy Client: Error ('EOF while parsing a value at offset 7') interpreting payload for transmission: [105, 110, 118, 97, 108, 105, 100]", 1000);
        assert_eq! (recording.lock ().unwrap ().len (), 0);
    }

    #[test]
    fn non_terminal_payload_can_be_sent_over_existing_connection () {
        let client_request_payload = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            last_data: false,
            data: PlainData::new (&b"These are the times"[..]),
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new (&b"men's souls"[..])
        };
        let package = ExpiredCoresPackage::new (test_utils::make_meaningless_route (),
                                                PlainData::new (&(serde_cbor::ser::to_vec (&client_request_payload).unwrap ())[..]));
        let _system = System::new("test");
        let hopper = Recorder::new ();
        let hopper_sub =
            test_utils::make_peer_actors_from(None, None, Some (hopper), None).hopper.from_hopper_client;
        let mut write_parameters = Arc::new (Mutex::new (vec! ()));
        let mut shutdown_parameters = Arc::new (Mutex::new (vec! ()));
        let write_stream = TcpStreamWrapperMock::new ()
            .peer_addr_result (Err (Error::from (ErrorKind::AddrInUse)))
            .write_parameters (&mut write_parameters)
            .write_result (Ok (123))
            .shutdown_parameters (&mut shutdown_parameters);
        let mut subject = StreamHandlerPoolReal::new (Box::new (ResolverWrapperMock::new ()),
                                                      Box::new (CryptDENull::new ()), hopper_sub);
        subject.stream_writers.insert (client_request_payload.stream_key,
                                       StreamWriter::new (Box::new (write_stream)));

        subject.process_package(package);

        assert_eq! (write_parameters.lock ().unwrap ().remove (0), client_request_payload.data.data);
        assert_eq! (shutdown_parameters.lock ().unwrap ().len (), 0);
    }

    #[test]
    fn terminal_payload_will_close_existing_connection () {
        let client_request_payload = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            last_data: true,
            data: PlainData::new (&b"These are the times"[..]),
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new (&b"men's souls"[..])
        };
        let package = ExpiredCoresPackage::new (test_utils::make_meaningless_route (),
           PlainData::new (&(serde_cbor::ser::to_vec (&client_request_payload).unwrap ())[..]));
        let _system = System::new("test");
        let hopper = Recorder::new ();
        let hopper_sub =
            test_utils::make_peer_actors_from(None, None, Some (hopper), None).hopper.from_hopper_client;
        let mut write_parameters = Arc::new (Mutex::new (vec! ()));
        let mut shutdown_parameters = Arc::new (Mutex::new (vec! ()));
        let write_stream = TcpStreamWrapperMock::new ()
            .peer_addr_result (Err (Error::from (ErrorKind::AddrInUse)))
            .write_parameters (&mut write_parameters)
            .write_result (Ok (123))
            .shutdown_parameters (&mut shutdown_parameters)
            .shutdown_result (Ok (()));
        let mut subject = StreamHandlerPoolReal::new (Box::new (ResolverWrapperMock::new ()),
                                                      Box::new (CryptDENull::new ()), hopper_sub);
        subject.stream_writers.insert (client_request_payload.stream_key,
           StreamWriter::new (Box::new (write_stream)));

        subject.process_package(package);

        assert_eq! (write_parameters.lock ().unwrap ().remove (0), client_request_payload.data.data);
        assert_eq! (shutdown_parameters.lock ().unwrap ().remove (0), Shutdown::Both);
    }

    #[test]
    fn write_failure_for_existing_stream_generates_log_and_termination_message () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None).hopper.from_hopper_client;
            let stream = TcpStreamWrapperMock::new()
                .peer_addr_result(Ok(SocketAddr::from_str("2.3.4.5:80").unwrap()))
                .write_result(Err(Error::from(ErrorKind::BrokenPipe)));
            let mut subject = StreamHandlerPoolReal::new(Box::new(ResolverWrapperMock::new()),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.stream_writers.insert(client_request_payload.stream_key,
                                          StreamWriter::new(Box::new(stream)));

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let package = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&package.payload.data[..]).unwrap ();
        assert_eq! (payload.last_response, true);
        TestLogHandler::new ().await_log_containing("ERROR: Proxy Client: Error writing 19 bytes to 2.3.4.5:80: broken pipe", 1000);
    }

    #[test]
    fn write_failure_for_nonexistent_stream_generates_log_and_termination_message () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let read_stream =  TcpStreamWrapperMock::new()
                .peer_addr_result(Ok(SocketAddr::from_str("3.4.5.6:80").unwrap()))
                .read_delay (0xFFFFFFFF);
            let second_write_stream = TcpStreamWrapperMock::new ()
                .write_result(Err (Error::from (ErrorKind::AlreadyExists)));
            let write_stream = TcpStreamWrapperMock::new ()
                .peer_addr_result(Ok(SocketAddr::from_str("3.4.5.6:80").unwrap()))
                .connect_result(Ok(()))
                .set_read_timeout_result(Ok(()))
                .try_clone_result (Ok (Box::new (read_stream)))
                .try_clone_result (Ok (Box::new (second_write_stream)));
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(write_stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let package = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&package.payload.data[..]).unwrap ();
        assert_eq! (payload.last_response, true);
        TestLogHandler::new ().await_log_containing("ERROR: Proxy Client: Error writing 19 bytes to 3.4.5.6:80: entity already exists", 1000);
    }

    #[test]
    fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let stream = TcpStreamWrapperMock::new()
                .mocked_try_clone(false);
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let package = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&package.payload.data[..]).unwrap ();
        assert_eq! (payload.last_response, true);
        TestLogHandler::new ().exists_log_containing("ERROR: Proxy Client: Cannot open new stream with key 1.2.3.4:5678: no hostname supplied");
    }

    #[test]
    fn nonexistent_connection_springs_into_being_and_is_persisted_to_handle_transaction () {
        let lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
        let lookup_ip_parameters_a = lookup_ip_parameters.clone ();
        let connect_parameters = Arc::new(Mutex::new(vec!()));
        let connect_parameters_a = connect_parameters.clone ();
        let set_read_timeout_parameters = Arc::new(Mutex::new(vec!()));
        let set_read_timeout_parameters_a = set_read_timeout_parameters.clone ();
        let write_parameters = Arc::new(Mutex::new(vec!()));
        let write_parameters_a = write_parameters.clone ();
        let hopper = Recorder::new();
        let hopper_recording_arc = hopper.get_recording();
        let hopper_awaiter = hopper.get_awaiter();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap(), IpAddr::from_str("3.4.5.6").unwrap()));
            let stream = TcpStreamWrapperMock::new()
                // preparations for reading
                .peer_addr_result(Ok(SocketAddr::from_str("3.4.5.6:80").unwrap()))
                .read_buffer(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
                .read_result(Ok(19))
                .read_result(Err(Error::from(ErrorKind::ConnectionAborted)))
                // preparations for writing
                .connect_parameters(&connect_parameters)
                .connect_result(Err(Error::from(ErrorKind::InvalidInput)))
                .connect_result(Ok(()))
                .set_read_timeout_parameters(&set_read_timeout_parameters)
                .set_read_timeout_result(Ok(()))
                .write_parameters(&write_parameters)
                .write_result(Ok(123))
                .mocked_try_clone(false);
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count (1);
        assert_eq! (lookup_ip_parameters_a.lock ().unwrap ().deref (), &vec! (String::from ("that.try.")));
        assert_eq! (connect_parameters_a.lock ().unwrap ().remove (0), SocketAddr::from_str ("2.3.4.5:80").unwrap ());
        assert_eq! (connect_parameters_a.lock ().unwrap ().remove (0), SocketAddr::from_str ("3.4.5.6:80").unwrap ());
        assert_eq! (set_read_timeout_parameters_a.lock ().unwrap ().remove (0), None);
        assert_eq! (write_parameters_a.lock ().unwrap ().remove (0), b"These are the times".to_vec ());
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        assert_eq! (*record, IncipientCoresPackage::new (
            test_utils::make_meaningless_route(),
            ClientResponsePayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_response: false,
                data: PlainData::new (&b"HTTP/1.1 200 OK\r\n\r\n"[..]),
            },
            &Key::new(&b"men's souls"[..])
        ));
    }

    #[test]
    fn if_none_of_the_resolved_ips_work_we_get_a_log_and_an_error_result () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap(), IpAddr::from_str("3.4.5.6").unwrap()));
            let write_stream = TcpStreamWrapperMock::new()
                .connect_result(Err(Error::from(ErrorKind::InvalidInput)))
                .connect_result(Err(Error::from(ErrorKind::AlreadyExists)));
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(write_stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (client_response_payload.last_response, true);
        TestLogHandler::new ().await_log_containing ("ERROR: Proxy Client: Could not connect to any of the IP addresses supplied for that.try: [\"2.3.4.5:80\", \"3.4.5.6:80\"]", 1000);
    }

    #[test]
    fn if_setting_read_timeout_fails_we_get_a_log_and_an_error_result () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: true,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let write_stream = TcpStreamWrapperMock::new()
                .peer_addr_result(Ok(SocketAddr::from_str("1.2.3.4:5678").unwrap()))
                .connect_result(Ok(()))
                .set_read_timeout_result(Err(Error::from(ErrorKind::AddrNotAvailable)));
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(write_stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (client_response_payload.last_response, true);
        TestLogHandler::new ().await_log_containing ("ERROR: Proxy Client: Could not set the read timeout for connection to 1.2.3.4:5678", 1000);
    }

    #[test]
    fn if_setting_read_timeout_fails_and_peer_addr_fails_we_get_a_log_and_an_error_result () {
        LoggerInitializerWrapperMock::new ().init ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let write_stream = TcpStreamWrapperMock::new()
                .peer_addr_result(Err(Error::from(ErrorKind::AddrNotAvailable)))
                .connect_result(Ok(()))
                .set_read_timeout_result(Err(Error::from(ErrorKind::AddrNotAvailable)));
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(write_stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run();
        });
        hopper_awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (client_response_payload.last_response, true);
        TestLogHandler::new ().await_log_containing ("ERROR: Proxy Client: Could not set the read timeout for connection to that.try", 1000);
    }

    #[test]
    fn bad_dns_lookup_produces_log_and_sends_error_response () {
        LoggerInitializerWrapperMock::new().init();
        let stream_key = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: stream_key,
                last_data: true,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let mut lookup_ip_parameters = Arc::new(Mutex::new(vec!()));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&mut lookup_ip_parameters)
                .lookup_ip_failure(ResolveError::from(ResolveErrorKind::Io));
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new(CryptDENull::new()), hopper_sub);

            subject.process_package(package);

            system.run();
        });
        TestLogHandler::new ().await_log_containing ("ERROR: Proxy Client: Could not find IP address for host that.try: io error", 1000);
        hopper_awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();
        let record = recording.get_record::<IncipientCoresPackage> (0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (client_response_payload, ClientResponsePayload {
            stream_key,
            last_response: true,
            data: PlainData::new (&[]),
        });
    }

    #[test]
    fn try_clone_error_is_logged_and_returned () {
        LoggerInitializerWrapperMock::new ().init ();
        let cryptde = CryptDENull::new ();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording_arc = hopper.get_recording ();
        thread::spawn (move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                last_data: false,
                data: PlainData::new(&b"These are the times"[..]),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..])
            };
            let package = ExpiredCoresPackage::new(test_utils::make_meaningless_route(),
                                                   PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]));
            let system = System::new("test");
            let hopper_sub =
                test_utils::make_peer_actors_from(None, None, Some(hopper), None)
                    .hopper.from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec!(IpAddr::from_str("2.3.4.5").unwrap()));
            let write_stream = TcpStreamWrapperMock::new()
                .peer_addr_result(Ok(SocketAddr::from_str("2.3.4.5:80").unwrap()))
                .connect_result(Ok(()))
                .set_read_timeout_result(Ok(()))
                .try_clone_result(Err(Error::from (ErrorKind::ConnectionReset)))
                .write_result(Ok(123));
            let stream_factory = TcpStreamWrapperFactoryMock::new()
                .tcp_stream_wrapper(write_stream);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver),
                                                         Box::new (cryptde), hopper_sub);
            subject.tcp_stream_wrapper_factory = Box::new(stream_factory);

            subject.process_package(package);

            system.run ();
        });
        hopper_awaiter.await_message_count (1);
        let hopper_recording = hopper_recording_arc.lock ().unwrap ();
        let record = hopper_recording.get_record::<IncipientCoresPackage> (0);
        let client_response_payload = serde_cbor::de::from_slice::<ClientResponsePayload> (&record.payload.data[..]).unwrap ();
        assert_eq! (client_response_payload.last_response, true);
        TestLogHandler::new ().await_log_containing ("Could not clone stream: connection reset", 1000);
    }
}
