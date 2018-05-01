// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use actix::Actor;
use actix::Context;
use actix::SyncAddress;
use actix::Handler;
use actix::Subscriber;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::cryptde::CryptDE;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ProxyServerSubs;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use client_request_payload_factory::ClientRequestPayloadFactory;

pub struct ProxyServer {
    dispatcher: Option<Box<Subscriber<TransmitDataMsg> + Send>>,
    hopper: Option<Box<Subscriber<IncipientCoresPackage> + Send>>,
    client_request_payload_factory: ClientRequestPayloadFactory,
    logger: Logger
}

impl Actor for ProxyServer {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.dispatcher = Some(msg.peer_actors.dispatcher.from_proxy_server);
        self.hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        ()
    }
}

impl Handler<InboundClientData> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        let hopper = self.hopper.as_ref ().expect ("Hopper unbound in ProxyServer");
        let cryptde = CryptDENull::new();
        let payload = match self.client_request_payload_factory.make (&msg, &cryptde, &self.logger) {
            None => { self.logger.error(format! ("Couldn't create ClientRequestPayload")); return (); },
            Some (payload) => payload
        };
        // TODO this should come from the Neighborhood
        let route = Route::new(vec! (
                RouteSegment::new(vec! (&cryptde.public_key(), &cryptde.public_key ()), Component::ProxyClient),
                RouteSegment::new(vec!(&cryptde.public_key(), &cryptde.public_key()), Component::ProxyServer)
            ), &cryptde).expect("Couldn't create route");
        let pkg = IncipientCoresPackage::new(route, payload, &cryptde.public_key());
        hopper.send(pkg ).expect ("Hopper is dead")
    }
}

impl Handler<ExpiredCoresPackage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        match msg.payload::<ClientResponsePayload>() {
            Ok(payload) => {
                self.logger.debug (format! ("Relaying {}-byte ExpiredCoresPackage payload from Hopper to Dispatcher", payload.data.data.len ()));
                self.dispatcher.as_ref().expect("Dispatcher unbound in ProxyServer")
                    .send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(payload.stream_key),
                        last_data: payload.last_response,
                        data: payload.data.data.clone()
                    }).expect ("Dispatcher is dead");
                ()
            },
            Err(_) => { self.logger.error(format! ("ClientResponsePayload is not OK")); return (); },
        }
        ()
    }
}

impl ProxyServer {
    pub fn new() -> ProxyServer {
        ProxyServer {
            dispatcher: None,
            hopper: None,
            client_request_payload_factory: ClientRequestPayloadFactory::new (),
            logger: Logger::new ("Proxy Server"),
        }
    }

    pub fn make_subs_from(addr: &SyncAddress<ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_dispatcher: addr.subscriber::<InboundClientData>(),
            from_hopper: addr.subscriber::<ExpiredCoresPackage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use sub_lib::cryptde::PlainData;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::proxy_client::ClientResponsePayload;
    use sub_lib::proxy_server::ClientRequestPayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::test_utils::make_peer_actors_from;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::route_from_proxy_server;
    use test_utils::test_utils::route_to_proxy_server;

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper() {
        let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            socket_addr: socket_addr.clone(),
            origin_port: Some (80),
            component: Component::ProxyServer,
            last_data: true,
            data: expected_data.clone()
        };
        let expected_http_request = PlainData::new(http_request);
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let route = route_from_proxy_server(&key, &cryptde);
        let expected_payload = ClientRequestPayload {
            stream_key: socket_addr.clone(),
            last_data: true,
            data: expected_http_request.clone(),
            target_hostname: Some (String::from("nowhere.com")),
            target_port: 80,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone()
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        let subject_addr: SyncAddress<_> = subject.start();
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper_mock), None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper() {
        let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
        let tls_request = &[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x01, // handshake_type: ClientHello
            0x00, 0x00, 0x00, 0x00, 0x00, // length, version: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // random: don't care
            0x00, // session_id_length
            0x00, 0x00, // cipher_suites_length
            0x00, // compression_methods_length
            0x00, 0x13, // extensions_length
            0x00, 0x00, // extension_type: server_name
            0x00, 0x0F, // extension_length
            0x00, 0x0D, // server_name_list_length
            0x00, // server_name_type
            0x00, 0x0A, // server_name_length
            's' as u8, 'e' as u8, 'r' as u8, 'v' as u8, 'e' as u8, 'r' as u8, '.' as u8, 'c' as u8, 'o' as u8, 'm' as u8, // server_name
        ];
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            socket_addr: socket_addr.clone(),
            origin_port: Some (443),
            component: Component::ProxyServer,
            last_data: false,
            data: expected_data.clone()
        };
        let expected_tls_request = PlainData::new(tls_request);
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let route = route_from_proxy_server(&key, &cryptde);
        let expected_payload = ClientRequestPayload {
            stream_key: socket_addr.clone(),
            last_data: false,
            data: expected_tls_request.clone(),
            target_hostname: Some (String::from("server.com")),
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone()
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        let subject_addr: SyncAddress<_> = subject.start();
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper_mock), None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_handshake_packet_other_than_client_hello_from_dispatcher_then_sends_cores_package_to_hopper() {
        let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
        let tls_request = &[
            0x16, // content_type: Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
            0x10, // handshake_type: ClientKeyExchange (not important--just not ClientHello)
            0x00, 0x00, 0x00, // length: 0
        ];
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            socket_addr: socket_addr.clone(),
            origin_port: Some (443),
            component: Component::ProxyServer,
            last_data: false,
            data: expected_data.clone()
        };
        let expected_tls_request = PlainData::new(tls_request);
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let route = route_from_proxy_server(&key, &cryptde);
        let expected_payload = ClientRequestPayload {
            stream_key: socket_addr.clone(),
            last_data: false,
            data: expected_tls_request.clone(),
            target_hostname: None,
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone()
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        let subject_addr: SyncAddress<_> = subject.start();
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper_mock), None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_tls_packet_other_than_handshake_from_dispatcher_then_sends_cores_package_to_hopper() {
        let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
        let tls_request = &[
            0xFF, // content_type: don't care, just not Handshake
            0x00, 0x00, 0x00, 0x00, // version, length: don't care
        ];
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            socket_addr: socket_addr.clone(),
            origin_port: Some (443),
            component: Component::ProxyServer,
            last_data: true,
            data: expected_data.clone()
        };
        let expected_tls_request = PlainData::new(tls_request);
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let route = route_from_proxy_server(&key, &cryptde);
        let expected_payload = ClientRequestPayload {
            stream_key: socket_addr.clone(),
            last_data: true,
            data: expected_tls_request.clone(),
            target_hostname: None,
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone()
        };
        let expected_pkg = IncipientCoresPackage::new(route.clone(), expected_payload, &key);
        let subject_addr: SyncAddress<_> = subject.start();
        let mut peer_actors = make_peer_actors_from(None, None, Some(hopper_mock), None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        hopper_awaiter.await_message_count(1);
        let recording = hopper_log_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_receives_terminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let dispatcher_mock = Recorder::new();
        let dispatcher_log_arc = dispatcher_mock.get_recording();
        let dispatcher_awaiter = dispatcher_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let subject_addr: SyncAddress<_> = subject.start();
        let remaining_route = route_to_proxy_server(&key, &cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: socket_addr.clone(),
            last_response: true,
            data: PlainData::new(b"data")
        };
        let incipient_cores_package = IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let expired_cores_package = ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);
        let mut peer_actors = make_peer_actors_from(None, Some(dispatcher_mock), None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(expired_cores_package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        dispatcher_awaiter.await_message_count(1);

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, true);
        assert_eq!(record.data, b"data".to_vec());
    }

    #[test]
    fn proxy_server_receives_nonterminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let dispatcher_mock = Recorder::new();
        let dispatcher_log_arc = dispatcher_mock.get_recording();
        let dispatcher_awaiter = dispatcher_mock.get_awaiter();
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let subject_addr: SyncAddress<_> = subject.start();
        let remaining_route = route_to_proxy_server(&key, &cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: socket_addr.clone(),
            last_response: false,
            data: PlainData::new(b"data")
        };
        let incipient_cores_package = IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let expired_cores_package = ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);
        let mut peer_actors = make_peer_actors_from(None, Some(dispatcher_mock), None, None);
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.send(BindMessage { peer_actors });

        subject_addr.send(expired_cores_package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        dispatcher_awaiter.await_message_count(1);

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, false);
        assert_eq!(record.data, b"data".to_vec());
    }

    #[test]
    #[should_panic (expected = "Dispatcher unbound in ProxyServer")]
    fn panics_if_dispatcher_is_unbound() {
        let system = System::new("panics_if_dispatcher_is_unbound");
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();
        let subject_addr: SyncAddress<_> = subject.start();
        let remaining_route = route_to_proxy_server(&key, &cryptde);
        let client_response_payload = ClientResponsePayload {
            stream_key: socket_addr,
            last_response: true,
            data: PlainData::new(b"data")
        };
        let incipient_cores_package = IncipientCoresPackage::new(remaining_route.clone(), client_response_payload, &key);
        let expired_cores_package = ExpiredCoresPackage::new(remaining_route, incipient_cores_package.payload);

        subject_addr.send(expired_cores_package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }

    #[test]
    #[should_panic (expected = "Hopper unbound in ProxyServer")]
    fn panics_if_hopper_is_unbound() {
        let system = System::new("panics_if_hopper_is_unbound");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let subject = ProxyServer::new();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            socket_addr: socket_addr.clone(),
            origin_port: Some (53),
            component: Component::ProxyServer,
            last_data: false,
            data: expected_data.clone()
        };
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(msg_from_dispatcher);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }
}
