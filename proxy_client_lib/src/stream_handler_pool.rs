// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use actix::Arbiter;
use actix::Recipient;
use actix::Syn;
use futures::future::Executor;
use futures::future::Future;
use resolver_wrapper::ResolverWrapper;
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use stream_establisher::StreamEstablisherFactory;
use stream_establisher::StreamEstablisherFactoryReal;
use sub_lib::channel_wrappers::SenderWrapper;
use sub_lib::cryptde::CryptDE;
use sub_lib::framer::Framer;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_packet_framer::HttpPacketFramer;
use sub_lib::http_response_start_finder::HttpResponseStartFinder;
use sub_lib::logger::Logger;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::route::Route;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::stream_key::StreamKey;
use sub_lib::tls_framer::TlsFramer;

pub trait StreamHandlerPool {
    fn process_package(&mut self, payload: ClientRequestPayload, route: Route);
}

pub struct StreamHandlerPoolReal {
    hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    stream_writer_channels: HashMap<StreamKey, Box<SenderWrapper<SequencedPacket>>>,
    stream_adder_rx: Receiver<(StreamKey, Box<SenderWrapper<SequencedPacket>>)>,
    stream_killer_rx: Receiver<StreamKey>,
    resolver: Box<ResolverWrapper>,
    _cryptde: &'static CryptDE, // This is not used now, but a version of it may be used in the future when ser/de and en/decrypt are combined.
    logger: Logger,
    establisher_factory: Box<StreamEstablisherFactory>,
}

impl StreamHandlerPool for StreamHandlerPoolReal {
    fn process_package(&mut self, payload: ClientRequestPayload, return_route: Route) {
        self.logger.debug(format!(
            "Received ExpiredCoresPackage with {}-byte payload",
            payload.sequenced_packet.data.len()
        ));
        self.do_housekeeping();

        let mut to_remove: Option<(StreamKey, SocketAddr)> = None;
        match self.stream_writer_channels.get_mut(&payload.stream_key) {
            Some(ref mut writer_channel) => {
                match StreamHandlerPoolReal::perform_write(
                    payload.sequenced_packet.clone(),
                    writer_channel,
                ) {
                    Ok(_) => {
                        if payload.sequenced_packet.last_data {
                            to_remove =
                                Some((payload.stream_key.clone(), writer_channel.peer_addr()));
                        }
                        ()
                    }
                    Err(_) => {
                        to_remove = Some((payload.stream_key.clone(), writer_channel.peer_addr()));
                        self.logger.debug(format!(
                            "Writing {} bytes to {} over existing stream",
                            payload.sequenced_packet.data.len(),
                            writer_channel.peer_addr()
                        ));
                        StreamHandlerPoolReal::send_terminating_package(
                            return_route,
                            &payload,
                            &self.hopper_sub,
                        )
                    }
                }
            }
            None => {
                // TODO: Figure out what to do if a flurry of requests for a particular stream key
                // come flooding in so densely that several of them arrive in the time it takes to
                // resolve the first one and add it to the stream_writers map.

                if payload.sequenced_packet.last_data && payload.sequenced_packet.data.len() == 0 {
                    self.logger.debug(format!(
                        "Empty last_data message received for nonexistent stream {:?}. Returning.",
                        payload.stream_key
                    ));
                    return;
                }

                self.logger.debug(format!(
                    "No stream to {:?} exists; resolving host",
                    &payload.target_hostname
                ));
                let mut fqdn = match &payload.target_hostname {
                    &None => {
                        self.logger.error(format!(
                            "Cannot open new stream with key {:?}: no hostname supplied",
                            payload.stream_key
                        ));
                        StreamHandlerPoolReal::send_terminating_package(
                            return_route,
                            &payload,
                            &self.hopper_sub,
                        );
                        return;
                    }
                    &Some(ref s) => s.clone(),
                };
                fqdn.push('.');
                let mut establisher = self.establisher_factory.make();
                let payload_clone = payload.clone();
                let future = self
                    .resolver
                    .lookup_ip(&fqdn[..])
                    .then(move |lookup_result| {
                        establisher
                            .logger
                            .debug(format!("Resolution closure beginning"));
                        let remaining_route = return_route.clone();
                        establisher
                            .establish_stream(&payload_clone, &return_route, lookup_result)
                            .and_then(|mut stream_writer| {
                                StreamHandlerPoolReal::perform_write(
                                    payload.sequenced_packet,
                                    &mut stream_writer,
                                )
                            })
                            .map_err(|_| {
                                StreamHandlerPoolReal::send_terminating_package(
                                    remaining_route,
                                    &payload_clone,
                                    &establisher.hopper_sub,
                                );
                            })
                    });
                self.logger.debug(format!("Host resolution scheduled"));
                Arbiter::handle()
                    .execute(future)
                    .expect("Actix executor failed for TRustDNSResolver");
            }
        }

        if let Some((stream_key, socket_addr)) = to_remove {
            self.logger
                .debug(format!("Removing stream writer for {}", socket_addr));
            self.stream_writer_channels.remove(&stream_key);
        }
    }
}

impl StreamHandlerPoolReal {
    pub fn new(
        resolver: Box<ResolverWrapper>,
        cryptde: &'static CryptDE,
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    ) -> StreamHandlerPoolReal {
        let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
        let (stream_adder_tx, stream_adder_rx) = mpsc::channel();
        StreamHandlerPoolReal {
            establisher_factory: Box::new(StreamEstablisherFactoryReal {
                stream_adder_tx,
                stream_killer_tx,
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
                Ok(stream_key) => match self.stream_writer_channels.remove(&stream_key) {
                    Some(writer_channel) => self.logger.debug(format!(
                        "Killed StreamWriter to {}",
                        writer_channel.peer_addr()
                    )),
                    None => self.logger.debug(format!(
                        "Tried to kill StreamWriter for key {:?}, but it was not found",
                        stream_key
                    )),
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
                    self.logger.debug(format!(
                        "Persisting StreamWriter to {} under key {:?}",
                        stream_writer_channel.peer_addr(),
                        stream_key
                    ));
                    self.stream_writer_channels
                        .insert(stream_key, stream_writer_channel)
                }
            };
        }
    }

    fn perform_write(
        sequenced_packet: SequencedPacket,
        writer_ref: &mut Box<SenderWrapper<SequencedPacket>>,
    ) -> io::Result<()> {
        writer_ref
            .unbounded_send(sequenced_packet)
            .map_err(|_| Error::from(ErrorKind::BrokenPipe))
    }

    pub fn framer_from_protocol(protocol: ProxyProtocol) -> Box<Framer> {
        match protocol {
            ProxyProtocol::HTTP => {
                Box::new(HttpPacketFramer::new(Box::new(HttpResponseStartFinder {})))
            }
            ProxyProtocol::TLS => Box::new(TlsFramer::new()),
        }
    }

    fn send_terminating_package(
        return_route: Route,
        request: &ClientRequestPayload,
        hopper_sub: &Recipient<Syn, IncipientCoresPackage>,
    ) {
        let response = ClientResponsePayload::make_terminating_payload(request.stream_key);
        let package =
            IncipientCoresPackage::new(return_route, response, &request.originator_public_key);
        hopper_sub.try_send(package).expect("Hopper died");
    }
}

pub trait StreamHandlerPoolFactory {
    fn make(
        &self,
        resolver: Box<ResolverWrapper>,
        cryptde: &'static CryptDE,
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    ) -> Box<StreamHandlerPool>;
}

pub struct StreamHandlerPoolFactoryReal {}

impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryReal {
    fn make(
        &self,
        resolver: Box<ResolverWrapper>,
        cryptde: &'static CryptDE,
        hopper_sub: Recipient<Syn, IncipientCoresPackage>,
    ) -> Box<StreamHandlerPool> {
        Box::new(StreamHandlerPoolReal::new(resolver, cryptde, hopper_sub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::Actor;
    use actix::Addr;
    use actix::Context;
    use actix::Handler;
    use actix::System;
    use futures::lazy;
    use futures::sync::mpsc::unbounded;
    use futures::Stream;
    use local_test_utils::make_send_error;
    use local_test_utils::ResolverWrapperMock;
    use serde_cbor;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::ops::Deref;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use stream_establisher::StreamEstablisher;
    use sub_lib::channel_wrappers::FuturesChannelFactoryReal;
    use sub_lib::channel_wrappers::SenderWrapperReal;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::channel_wrapper_mocks::FuturesChannelFactoryMock;
    use test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use test_utils::channel_wrapper_mocks::SenderWrapperMock;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::stream_connector_mock::StreamConnectorMock;
    use test_utils::test_utils;
    use test_utils::test_utils::await_messages;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_stream_key;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use tokio;
    use tokio::prelude::Async;
    use trust_dns_resolver::error::ResolveError;
    use trust_dns_resolver::error::ResolveErrorKind;

    #[derive(Message)]
    struct TriggerSubject {
        package: ExpiredCoresPackage,
    }

    struct TestActor {
        subject: StreamHandlerPoolReal,
    }

    impl Actor for TestActor {
        type Context = Context<Self>;
    }

    impl Handler<TriggerSubject> for TestActor {
        type Result = ();

        fn handle(
            &mut self,
            msg: TriggerSubject,
            _ctx: &mut Self::Context,
        ) -> <Self as Handler<TriggerSubject>>::Result {
            let payload = msg.package.payload::<ClientRequestPayload>().unwrap();
            let route = msg.package.remaining_route;
            self.subject.process_package(payload, route);
            ()
        }
    }

    struct StreamEstablisherFactoryMock {
        make_results: RefCell<Vec<StreamEstablisher>>,
    }

    impl StreamEstablisherFactory for StreamEstablisherFactoryMock {
        fn make(&self) -> StreamEstablisher {
            self.make_results.borrow_mut().remove(0)
        }
    }

    #[test]
    fn non_terminal_payload_can_be_sent_over_existing_connection() {
        let stream_key = make_meaningless_stream_key();
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
        };
        let mut tx_to_write = Box::new(SenderWrapperMock::new(
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ));
        tx_to_write.unbounded_send_results = vec![Ok(())];
        let write_parameters = tx_to_write.unbounded_send_params.clone();
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );

        thread::spawn(move || {
            let system = System::new("test");

            let hopper = Recorder::new();
            let hopper_sub = make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let mut subject = StreamHandlerPoolReal::new(
                Box::new(ResolverWrapperMock::new()),
                cryptde(),
                hopper_sub,
            );
            subject
                .stream_writer_channels
                .insert(stream_key, tx_to_write);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &write_parameters);

        assert_eq!(
            write_parameters.lock().unwrap().remove(0),
            client_request_payload.sequenced_packet
        );
    }

    #[test]
    fn write_failure_for_nonexistent_stream_generates_termination_message() {
        init_test_logging();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording_arc = hopper.get_recording();
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec![IpAddr::from_str("2.3.4.5").unwrap()]);
            let mut tx_to_write: SenderWrapperMock<SequencedPacket> =
                SenderWrapperMock::new(SocketAddr::from_str("2.3.4.5:80").unwrap());
            tx_to_write.unbounded_send_results = vec![make_send_error(
                client_request_payload.sequenced_packet.clone(),
            )];

            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            subject
                .stream_writer_channels
                .insert(client_request_payload.stream_key, Box::new(tx_to_write));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(&package.payload.data[..]).unwrap();
        assert_eq!(payload.sequenced_packet.last_data, true);
    }

    #[test]
    fn missing_hostname_for_nonexistent_stream_generates_log_and_termination_message() {
        init_test_logging();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_success(vec![IpAddr::from_str("2.3.4.5").unwrap()]);
            let subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(&package.payload.data[..]).unwrap();
        assert_eq!(payload.sequenced_packet.last_data, true);
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: Proxy Client: Cannot open new stream with key {:?}: no hostname supplied",
                make_meaningless_stream_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn nonexistent_connection_springs_into_being_and_is_persisted_to_handle_transaction() {
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let expected_lookup_ip_parameters = lookup_ip_parameters.clone();
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let expected_write_parameters = write_parameters.clone();
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Ok(Async::Ready(19))),
                    (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Ok(Async::Ready(123))],
                shutdown_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new().with_connection(
                    peer_addr.clone(),
                    peer_addr.clone(),
                    reader,
                    writer,
                )),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                make_results: RefCell::new(vec![establisher]),
            });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        assert_eq!(
            expected_lookup_ip_parameters.lock().unwrap().deref(),
            &vec!(String::from("that.try."))
        );
        assert_eq!(
            expected_write_parameters.lock().unwrap().remove(0),
            b"These are the times".to_vec()
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(
            *record,
            IncipientCoresPackage::new(
                test_utils::make_meaningless_route(),
                ClientResponsePayload {
                    stream_key: make_meaningless_stream_key(),
                    sequenced_packet: SequencedPacket {
                        data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                        sequence_number: 0,
                        last_data: false
                    },
                },
                &Key::new(&b"men's souls"[..]),
            )
        );
    }

    #[test]
    fn failing_to_make_a_connection_sends_an_error_response() {
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: false,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(
                    StreamConnectorMock::new()
                        .connect_pair_result(Err(Error::from(ErrorKind::Other))),
                ),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryReal {}),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                make_results: RefCell::new(vec![establisher]),
            });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    fn trying_to_write_to_disconnected_stream_writer_sends_an_error_response() {
        let stream_key = make_meaningless_stream_key();
        let lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
        let write_parameters = Arc::new(Mutex::new(vec![]));
        let (hopper, hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let sequenced_packet = SequencedPacket {
                data: b"These are the times".to_vec(),
                sequence_number: 0,
                last_data: false,
            };

            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: sequenced_packet.clone(),
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&lookup_ip_parameters)
                .lookup_ip_success(vec![
                    IpAddr::from_str("2.3.4.5").unwrap(),
                    IpAddr::from_str("3.4.5.6").unwrap(),
                ]);
            let peer_addr = SocketAddr::from_str("3.4.5.6:80").unwrap();
            let reader = ReadHalfWrapperMock {
                poll_read_results: vec![
                    (vec![], Ok(Async::NotReady)),
                    (vec![], Err(Error::from(ErrorKind::ConnectionAborted))),
                ],
            };
            let writer = WriteHalfWrapperMock {
                poll_write_params: write_parameters,
                poll_write_results: vec![Ok(Async::NotReady)],
                shutdown_results: Arc::new(Mutex::new(vec![])),
            };
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            let disconnected_sender = Box::new(SenderWrapperMock {
                peer_addr,
                unbounded_send_params: Arc::new(Mutex::new(vec![])),
                unbounded_send_results: vec![make_send_error(sequenced_packet)],
            });
            let (stream_killer_tx, stream_killer_rx) = mpsc::channel();
            subject.stream_killer_rx = stream_killer_rx;
            let (stream_adder_tx, _stream_adder_rx) = mpsc::channel();
            let establisher = StreamEstablisher {
                stream_adder_tx,
                stream_killer_tx,
                stream_connector: Box::new(StreamConnectorMock::new().with_connection(
                    peer_addr.clone(),
                    peer_addr.clone(),
                    reader,
                    writer,
                )),
                hopper_sub: subject.hopper_sub.clone(),
                logger: subject.logger.clone(),
                channel_factory: Box::new(FuturesChannelFactoryMock {
                    results: vec![(
                        disconnected_sender,
                        Box::new(ReceiverWrapperMock {
                            poll_results: vec![],
                        }),
                    )],
                }),
            };

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                make_results: RefCell::new(vec![establisher]),
            });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    fn bad_dns_lookup_produces_log_and_sends_error_response() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let recording_arc = hopper.get_recording();
        thread::spawn(move || {
            let client_request_payload = ClientRequestPayload {
                stream_key,
                sequenced_packet: SequencedPacket {
                    data: b"These are the times".to_vec(),
                    sequence_number: 0,
                    last_data: true,
                },
                target_hostname: Some(String::from("that.try")),
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let mut lookup_ip_parameters = Arc::new(Mutex::new(vec![]));
            let resolver = ResolverWrapperMock::new()
                .lookup_ip_parameters(&mut lookup_ip_parameters)
                .lookup_ip_failure(ResolveError::from(ResolveErrorKind::Io));
            let subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });
        TestLogHandler::new().await_log_containing(
            "ERROR: Proxy Client: Could not find IP address for host that.try: io error",
            1000,
        );
        hopper_awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        let client_response_payload =
            serde_cbor::de::from_slice::<ClientResponsePayload>(&record.payload.data[..]).unwrap();
        assert_eq!(
            client_response_payload,
            ClientResponsePayload::make_terminating_payload(stream_key)
        );
    }

    #[test]
    fn after_writing_last_data_the_stream_should_close() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let hopper = Recorder::new();
        let (tx_to_write, mut rx_to_write) = unbounded();
        let sequenced_packet = SequencedPacket {
            data: b"These are the times".to_vec(),
            sequence_number: 0,
            last_data: true,
        };
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: sequenced_packet.clone(),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let resolver = ResolverWrapperMock::new();
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            subject.stream_writer_channels.insert(
                stream_key,
                Box::new(SenderWrapperReal::new(
                    SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                    tx_to_write,
                )),
            );

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
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
        assert_eq!(rx_to_write_params, Ok(Async::Ready(Some(sequenced_packet))));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");

        let rx_to_write_result = rx.recv().unwrap();
        assert_eq!(rx_to_write_result, Ok(Async::Ready(None))); // Ok(Async::Ready(None)) indicates that all TXs to the channel are gone
    }

    #[test]
    fn error_from_tx_to_writer_removes_stream() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let hopper = Recorder::new();
        let sequenced_packet = SequencedPacket {
            data: b"These are the times".to_vec(),
            sequence_number: 0,
            last_data: true,
        };
        let client_request_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: sequenced_packet.clone(),
            target_hostname: Some(String::from("that.try")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"men's souls"[..]),
        };
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route(),
            PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
        );
        let mut sender_wrapper =
            SenderWrapperMock::new(SocketAddr::from_str("1.2.3.4:5678").unwrap());
        sender_wrapper.unbounded_send_results = vec![make_send_error(sequenced_packet.clone())];
        let send_params = sender_wrapper.unbounded_send_params.clone();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let resolver = ResolverWrapperMock::new();

            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);
            subject
                .stream_writer_channels
                .insert(stream_key, Box::new(sender_wrapper));

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        await_messages(1, &send_params);
        assert_eq!(*send_params.lock().unwrap(), vec!(sequenced_packet));

        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("Removing stream writer for 1.2.3.4:5678");
    }

    #[test]
    fn process_package_does_not_create_new_connection_for_last_data_message_with_no_data_and_sends_no_messages(
    ) {
        init_test_logging();
        let (hopper, _hopper_awaiter, hopper_recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("test");
            let hopper_sub = recorder::make_peer_actors_from(None, None, Some(hopper), None, None)
                .hopper
                .from_hopper_client;
            let client_request_payload = ClientRequestPayload {
                stream_key: make_meaningless_stream_key(),
                sequenced_packet: SequencedPacket {
                    data: vec![],
                    sequence_number: 0,
                    last_data: true,
                },
                target_hostname: None,
                target_port: 80,
                protocol: ProxyProtocol::HTTP,
                originator_public_key: Key::new(&b"men's souls"[..]),
            };
            let package = ExpiredCoresPackage::new(
                test_utils::make_meaningless_route(),
                PlainData::new(&(serde_cbor::ser::to_vec(&client_request_payload).unwrap())[..]),
            );
            let resolver = ResolverWrapperMock::new();
            let mut subject = StreamHandlerPoolReal::new(Box::new(resolver), cryptde(), hopper_sub);

            subject.establisher_factory = Box::new(StreamEstablisherFactoryMock {
                make_results: RefCell::new(vec![]),
            });

            let test_actor = TestActor { subject };
            let addr: Addr<Syn, TestActor> = test_actor.start();
            let test_trigger: Recipient<Syn, TriggerSubject> =
                addr.clone().recipient::<TriggerSubject>();
            test_trigger.try_send(TriggerSubject { package }).is_ok();

            system.run();
        });

        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            &format!(
                "Empty last_data message received for nonexistent stream {:?}. Returning.",
                make_meaningless_stream_key()
            )[..],
            500,
        );

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
    }
}
