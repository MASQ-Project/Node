// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MailboxError;
use actix::Recipient;
use actix::Syn;
use client_request_payload_factory::ClientRequestPayloadFactory;
use std::net::SocketAddr;
use sub_lib::bidi_hashmap::BidiHashMap;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_server_impersonator;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::RouteQueryMessage;
use sub_lib::neighborhood::RouteQueryResponse;
use sub_lib::peer_actors::BindMessage;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_server::ProxyProtocol;
use sub_lib::proxy_server::ProxyServerSubs;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::stream_key::StreamKey;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;
use tokio;
use tokio::prelude::Future;

pub struct ProxyServer {
    dispatcher: Option<Recipient<Syn, TransmitDataMsg>>,
    hopper: Option<Recipient<Syn, IncipientCoresPackage>>,
    route_source: Option<Recipient<Syn, RouteQueryMessage>>,
    client_request_payload_factory: ClientRequestPayloadFactory,
    stream_key_factory: Box<StreamKeyFactory>,
    keys_and_addrs: BidiHashMap<StreamKey, SocketAddr>,
    is_decentralized: bool, // TODO: This should be replaced by something more general and configurable.
    cryptde: &'static CryptDE,
    logger: Logger,
}

impl Actor for ProxyServer {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.dispatcher = Some(msg.peer_actors.dispatcher.from_dispatcher_client);
        self.hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        self.route_source = Some(msg.peer_actors.neighborhood.route_query);
        ()
    }
}

impl Handler<InboundClientData> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        let route_source = self
            .route_source
            .as_ref()
            .expect("Neighborhood unbound in ProxyServer")
            .clone();
        let hopper = self
            .hopper
            .as_ref()
            .expect("Hopper unbound in ProxyServer")
            .clone();
        let dispatcher = self
            .dispatcher
            .as_ref()
            .expect("Dispatcher unbound in ProxyServer")
            .clone();
        let source_addr = msg.peer_addr;
        let payload = match self.make_payload(msg) {
            Ok(payload) => payload,
            Err(_) => return (),
        };
        let logger = self.logger.clone();
        let minimum_hop_count = if self.is_decentralized { 2 } else { 0 };
        tokio::spawn(
            route_source
                .send(RouteQueryMessage::data_indefinite_route_request(
                    minimum_hop_count,
                ))
                .then(move |route_result| {
                    ProxyServer::try_transmit_to_hopper(
                        hopper,
                        route_result,
                        payload,
                        logger,
                        source_addr,
                        dispatcher,
                    )
                }),
        );
        ()
    }
}

impl Handler<ExpiredCoresPackage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        match msg.payload::<ClientResponsePayload>() {
            Ok(payload) => {
                self.logger.debug(format!(
                    "Relaying {}-byte ExpiredCoresPackage payload from Hopper to Dispatcher",
                    payload.sequenced_packet.data.len()
                ));
                match self.keys_and_addrs.a_to_b(&payload.stream_key) {
                    Some(socket_addr) => {
                        let last_data = payload.sequenced_packet.last_data;
                        self.dispatcher
                            .as_ref()
                            .expect("Dispatcher unbound in ProxyServer")
                            .try_send(TransmitDataMsg {
                                endpoint: Endpoint::Socket(socket_addr),
                                last_data,
                                sequence_number: Some(payload.sequenced_packet.sequence_number),
                                data: payload.sequenced_packet.data.clone(),
                            })
                            .expect("Dispatcher is dead");
                        if last_data {
                            self.keys_and_addrs.remove_b(&socket_addr);
                        }
                    }
                    None => self.logger.error(format!(
                        "Discarding {}-byte packet {} from an unrecognized stream key: {:?}",
                        payload.sequenced_packet.data.len(),
                        payload.sequenced_packet.sequence_number,
                        payload.stream_key
                    )),
                }
                ()
            }
            Err(_) => {
                self.logger
                    .error(format!("ClientResponsePayload is not OK"));
                return ();
            }
        }
        ()
    }
}

impl ProxyServer {
    pub fn new(cryptde: &'static CryptDE, is_decentralized: bool) -> ProxyServer {
        ProxyServer {
            dispatcher: None,
            hopper: None,
            route_source: None,
            client_request_payload_factory: ClientRequestPayloadFactory::new(),
            stream_key_factory: Box::new(StreamKeyFactoryReal {}),
            keys_and_addrs: BidiHashMap::new(),
            is_decentralized,
            cryptde,
            logger: Logger::new("Proxy Server"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            from_dispatcher: addr.clone().recipient::<InboundClientData>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage>(),
        }
    }

    fn make_payload(&mut self, msg: InboundClientData) -> Result<ClientRequestPayload, ()> {
        let stream_key = match self.keys_and_addrs.b_to_a(&msg.peer_addr) {
            Some(stream_key) => stream_key,
            None => {
                let stream_key = self
                    .stream_key_factory
                    .make(&self.cryptde.public_key(), msg.peer_addr);
                self.keys_and_addrs
                    .insert(stream_key.clone(), msg.peer_addr);
                stream_key
            }
        };
        match self
            .client_request_payload_factory
            .make(&msg, stream_key, self.cryptde, &self.logger)
        {
            None => {
                self.logger
                    .error(format!("Couldn't create ClientRequestPayload"));
                Err(())
            }
            Some(payload) => Ok(payload),
        }
    }

    fn try_transmit_to_hopper(
        hopper: Recipient<Syn, IncipientCoresPackage>,
        route_result: Result<Option<RouteQueryResponse>, MailboxError>,
        payload: ClientRequestPayload,
        logger: Logger,
        source_addr: SocketAddr,
        dispatcher: Recipient<Syn, TransmitDataMsg>,
    ) -> Result<(), ()> {
        match route_result {
            Ok(Some(response)) => {
                let payload_destination_key = response
                    .segment_endpoints
                    .first()
                    .expect("no segment endpoints");
                let pkg =
                    IncipientCoresPackage::new(response.route, payload, &payload_destination_key);
                hopper.try_send(pkg).expect("Hopper is dead");
            }
            Ok(None) => {
                let target_hostname = ProxyServer::hostname(&payload);
                ProxyServer::send_route_failure(payload, source_addr, dispatcher);
                logger.error(format!("Failed to find route to {}", target_hostname));
            }
            Err(e) => {
                let msg = format!("Neighborhood refused to answer route request: {}", e);
                logger.error(msg);
            }
        };
        Ok(())
    }

    fn send_route_failure(
        payload: ClientRequestPayload,
        source_addr: SocketAddr,
        dispatcher: Recipient<Syn, TransmitDataMsg>,
    ) {
        let data = match payload.protocol {
            ProxyProtocol::HTTP => {
                let target_hostname = ProxyServer::hostname(&payload);
                http_server_impersonator::make_error_response (
                    503,
                   "Routing Problem",
                    format! ("Can't find a route to {}", target_hostname).as_str (),
                    format! ("Substratum can't find a route through the Network yet to a Node that knows \
                    where to find {}. Maybe later enough will be known about the Network to \
                    find that Node, but we can't guarantee it. We're sorry.", target_hostname).as_str ()
                )
            }
            ProxyProtocol::TLS => vec![],
        };
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(source_addr),
            last_data: true,
            sequence_number: Some(0),
            data,
        };
        dispatcher.try_send(msg).expect("Dispatcher is dead");
    }

    fn hostname(payload: &ClientRequestPayload) -> String {
        match payload.target_hostname {
            Some(ref thn) => thn.clone(),
            None => "<unknown>".to_string(),
        }
    }
}

trait StreamKeyFactory: Send {
    fn make(&self, public_key: &Key, peer_addr: SocketAddr) -> StreamKey;
}

struct StreamKeyFactoryReal {}

impl StreamKeyFactory for StreamKeyFactoryReal {
    fn make(&self, public_key: &Key, peer_addr: SocketAddr) -> StreamKey {
        // TODO: Replace this implementation
        StreamKey::new(public_key.clone(), peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::http_server_impersonator;
    use sub_lib::proxy_client::ClientResponsePayload;
    use sub_lib::proxy_server::ClientRequestPayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use sub_lib::sequence_buffer::SequencedPacket;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_stream_key;
    use test_utils::test_utils::route_to_proxy_server;
    use test_utils::test_utils::zero_hop_route_response;

    struct StreamKeyFactoryMock {
        make_parameters: Arc<Mutex<Vec<(Key, SocketAddr)>>>,
        make_results: RefCell<Vec<StreamKey>>,
    }

    impl StreamKeyFactory for StreamKeyFactoryMock {
        fn make(&self, key: &Key, peer_addr: SocketAddr) -> StreamKey {
            self.make_parameters
                .lock()
                .unwrap()
                .push((key.clone(), peer_addr));
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl StreamKeyFactoryMock {
        fn new() -> StreamKeyFactoryMock {
            StreamKeyFactoryMock {
                make_parameters: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        fn make_parameters(
            mut self,
            params: &Arc<Mutex<Vec<(Key, SocketAddr)>>>,
        ) -> StreamKeyFactoryMock {
            self.make_parameters = params.clone();
            self
        }

        fn make_result(self, stream_key: StreamKey) -> StreamKeyFactoryMock {
            self.make_results.borrow_mut().push(stream_key);
            self
        }
    }

    #[test]
    fn proxy_server_receives_http_request_with_new_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(80),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.data.clone(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let make_parameters_arc_a = make_parameters_arc.clone();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&make_parameters_arc)
                .make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(cryptde, false);
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
        let mut make_parameters = make_parameters_arc_a.lock().unwrap();
        assert_eq!(
            make_parameters.remove(0),
            (cryptde.public_key(), socket_addr)
        );
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(0));
    }

    #[test]
    fn proxy_server_receives_http_request_with_existing_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let neighborhood_mock = Recorder::new().route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(80),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.data.clone(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(cryptde, false);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_then_sends_multihop_cores_package_to_hopper(
    ) {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let payload_destination_key = Key::new(&[3]);
        let route = Route::new(
            vec![
                RouteSegment::new(
                    vec![
                        &cryptde.public_key(),
                        &Key::new(&[1]),
                        &Key::new(&[2]),
                        &payload_destination_key,
                    ],
                    Component::ProxyClient,
                ),
                RouteSegment::new(
                    vec![
                        &payload_destination_key,
                        &Key::new(&[2]),
                        &Key::new(&[1]),
                        &cryptde.public_key(),
                    ],
                    Component::ProxyServer,
                ),
            ],
            cryptde,
        )
        .unwrap();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: route.clone(),
            segment_endpoints: vec![Key::new(&[3]), cryptde.public_key()],
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(80),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.data.clone(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(route.clone(), expected_payload, &payload_destination_key);
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(cryptde, true);
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(2));
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route() {
        init_test_logging();
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(None);
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(80),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(cryptde, true);
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, Some(dispatcher), None, None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        dispatcher_awaiter.await_message_count(1);
        let recording = dispatcher_recording_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        let expected_msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:5678").unwrap()),
            last_data: true,
            sequence_number: Some(0),
            data: http_server_impersonator::make_error_response(
                503,
                "Routing Problem",
                "Can't find a route to nowhere.com",
                "Substratum can't find a route through the Network yet to a Node that knows \
                 where to find nowhere.com. Maybe later enough will be known about the Network to \
                 find that Node, but we can't guarantee it. We're sorry.",
            ),
        };
        assert_eq!(record, &expected_msg);
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(2));
        TestLogHandler::new()
            .exists_log_containing("ERROR: Proxy Server: Failed to find route to nowhere.com");
    }

    #[test]
    fn proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper() {
        let tls_request = &[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ];
        let cryptde = cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let neighborhood_mock = Recorder::new().route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(cryptde, false);
        subject.stream_key_factory =
            Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.data.clone(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("server.com")),
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_handshake_packet_other_than_client_hello_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let tls_request = &[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x10, // handshake_type: ClientKeyExchange (not important--just not ClientHello)
            0x00, 0x00, 0x00, // length: 0
        ];
        let cryptde = cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let neighborhood_mock = Recorder::new().route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(cryptde, false);
        subject.stream_key_factory =
            Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.data.clone(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_packet_other_than_handshake_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let tls_request = &[
            0xFF, // content_type: don't care, just not Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
        ];
        let cryptde = cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let neighborhood_mock = Recorder::new().route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(cryptde, false);
        subject.stream_key_factory =
            Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(443),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.data.clone(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: None,
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, None, Some(hopper_mock), None, Some(neighborhood_mock));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_client_hello_from_dispatcher_but_neighborhood_cant_make_route() {
        init_test_logging();
        let cryptde = cryptde();
        let tls_request = [
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8,
            'o' as u8, 'm' as u8, // server_name
        ]
        .to_vec();
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let neighborhood = Recorder::new().route_query_response(None);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(443),
            sequence_number: Some(0),
            last_data: true,
            data: tls_request,
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(cryptde, false);
            let subject_addr: Addr<Syn, ProxyServer> = subject.start();
            let mut peer_actors =
                make_peer_actors_from(None, Some(dispatcher), None, None, Some(neighborhood));
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });
        dispatcher_awaiter.await_message_count(1);
        let recording = dispatcher_recording_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        let expected_msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:5678").unwrap()),
            last_data: true,
            sequence_number: Some(0),
            data: vec![],
        };
        assert_eq!(record, &expected_msg);

        TestLogHandler::new()
            .exists_log_containing("ERROR: Proxy Server: Failed to find route to server.com");
    }

    #[test]
    fn proxy_server_receives_terminal_response_from_hopper() {
        init_test_logging();
        let system = System::new("proxy_server_receives_response_from_hopper");
        let dispatcher_mock = Recorder::new();
        let dispatcher_log_arc = dispatcher_mock.get_recording();
        let dispatcher_awaiter = dispatcher_mock.get_awaiter();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let key = cryptde.public_key();
        let subject_addr: Addr<Syn, ProxyServer> = subject.start();
        let remaining_route = route_to_proxy_server(&key, cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"16 bytes of data".to_vec(),
                sequence_number: 12345678,
                last_data: true,
            },
        };
        let incipient_cores_package =
            IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let first_expired_cores_package =
            ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);
        let second_expired_cores_package = first_expired_cores_package.clone();
        let mut peer_actors = make_peer_actors_from(None, Some(dispatcher_mock), None, None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap();
        subject_addr.try_send(second_expired_cores_package).unwrap(); // should generate log because stream key is now unknown

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        dispatcher_awaiter.await_message_count(1);

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, true);
        assert_eq!(record.data, b"16 bytes of data".to_vec());
        TestLogHandler::new ().exists_log_containing (&format!("ERROR: Proxy Server: Discarding 16-byte packet 12345678 from an unrecognized stream key: {:?}", stream_key));
    }

    #[test]
    fn proxy_server_receives_nonterminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let dispatcher_mock = Recorder::new();
        let dispatcher_log_arc = dispatcher_mock.get_recording();
        let dispatcher_awaiter = dispatcher_mock.get_awaiter();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let key = cryptde.public_key();
        let subject_addr: Addr<Syn, ProxyServer> = subject.start();
        let remaining_route = route_to_proxy_server(&key, cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: stream_key,
            sequenced_packet: SequencedPacket {
                data: b"data".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
        };
        let incipient_cores_package =
            IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let first_expired_cores_package =
            ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);
        let second_expired_cores_package = first_expired_cores_package.clone();
        let mut peer_actors = make_peer_actors_from(None, Some(dispatcher_mock), None, None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap();
        subject_addr.try_send(second_expired_cores_package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        dispatcher_awaiter.await_message_count(2);

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, false);
        assert_eq!(record.data, b"data".to_vec());
        let record = recording.get_record::<TransmitDataMsg>(1);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, false);
        assert_eq!(record.data, b"data".to_vec());
    }

    #[test]
    #[should_panic(expected = "Dispatcher unbound in ProxyServer")]
    fn panics_if_dispatcher_is_unbound() {
        let system = System::new("panics_if_dispatcher_is_unbound");
        let cryptde = cryptde();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(cryptde, false);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let key = cryptde.public_key();
        let subject_addr: Addr<Syn, ProxyServer> = subject.start();
        let remaining_route = route_to_proxy_server(&key, cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: stream_key,
            sequenced_packet: SequencedPacket {
                data: b"data".to_vec(),
                sequence_number: 0,
                last_data: true,
            },
        };
        let incipient_cores_package =
            IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let expired_cores_package =
            ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);

        subject_addr.try_send(expired_cores_package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Neighborhood unbound in ProxyServer")]
    fn panics_if_hopper_is_unbound() {
        let system = System::new("panics_if_hopper_is_unbound");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let subject = ProxyServer::new(cryptde(), false);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(53),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let subject_addr: Addr<Syn, ProxyServer> = subject.start();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }
}
