// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::borrow::Borrow;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::HopperTemporaryTransmitDataMsg;
use sub_lib::hop::Hop;
use sub_lib::route::Route;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::hopper::HopperSubs;
use sub_lib::peer_actors::BindMessage;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::logger::Logger;
use actix::Subscriber;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::SyncAddress;
use serde_cbor;
use sub_lib::cryptde::CryptdecError;

pub struct Hopper {
    cryptde: Box<CryptDE>,
    to_proxy_server: Option<Box<Subscriber<ExpiredCoresPackage> + Send>>,
    to_proxy_client: Option<Box<Subscriber<ExpiredCoresPackage> + Send>>,
    // TODO when we are decentralized, change this to a TransmitDataMsg
    to_dispatcher: Option<Box<Subscriber<HopperTemporaryTransmitDataMsg> + Send>>,
    logger: Logger,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_hopper);
        self.to_proxy_client = Some(msg.peer_actors.proxy_client.from_hopper);
        self.to_dispatcher = Some(msg.peer_actors.dispatcher.from_hopper);
        ()
    }
}

impl Handler<IncipientCoresPackage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format! ("Received IncipientCoresPackage with {}-byte payload", msg.payload.data.len ()));
        let (live_package, key) = LiveCoresPackage::from_incipient(msg, self.cryptde.borrow());

        let serialized_package = match serde_cbor::ser::to_vec (&live_package) {
            Ok(package) => package,
            Err(_) => {
                self.logger.error(format! ("Couldn't serialize package"));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ()
            }
        };

        let encrypted_package = match self.cryptde.encode(&key, &PlainData::new(&serialized_package[..])) {
            Ok(package) => package,
            Err (_) => {
                self.logger.error(format! ("Couldn't encode package"));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ()
            }
        };

        // TODO when we are decentralized, change this to a TransmitDataMsg
        let transmit_msg = HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Key(key),
            last_data: false, // Hopper-to-Hopper streams are never remotely killed
            data: encrypted_package.data,
        };

        self.logger.debug (format! ("Sending TransmitDataMsg with {}-byte payload to Dispatcher", transmit_msg.data.len ()));
        self.to_dispatcher.as_ref().expect("Dispatcher unbound in Hopper").send(transmit_msg).expect("Dispatcher is dead");
        ()
    }
}

impl Handler<InboundClientData> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format! ("Received {} bytes of InboundClientData from Dispatcher", msg.data.len ()));
        let decrypted_package = match self.cryptde.decode(&self.cryptde.private_key(), &CryptData::new(&msg.data[..])) {
            Ok(package) => package,
            Err (e) => {
                self.logger.error(format! ("{:?}", e));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ()
            }
        };
        let live_package = match serde_cbor::de::from_slice::<LiveCoresPackage>(&decrypted_package.data[..]) {
            Ok(package) => package,
            Err(_) => {
                self.logger.error(format!("Couldn't deserialize package"));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ()
            }

        };

        let next_hop = live_package.next_hop(self.cryptde.borrow());

        match next_hop.component {
            Some(Component::ProxyServer) => {
                let expired_package = live_package.to_expired(self.cryptde.borrow());
                self.logger.debug (format! ("Forwarding ExpiredCoresPackage to Proxy Server: {:?}", expired_package));
                self.to_proxy_server.as_ref().expect("ProxyServer unbound in Hopper").send(expired_package).expect("Proxy Server is dead")
            },
            Some(Component::ProxyClient) => {
                let expired_package = live_package.to_expired(self.cryptde.borrow());
                self.logger.debug (format! ("Forwarding ExpiredCoresPackage to Proxy Client: {:?}", expired_package));
                self.to_proxy_client.as_ref ().expect ("ProxyClient unbound in Hopper").send (expired_package ).expect ("Proxy Client is dead")
            },
            Some(Component::Neighborhood) => unimplemented!(),
            // crashpoint - can we remove the Option by using Component::Hopper to indicate a relay node?
            Some(_) => panic!("Unexpected component"),
            None => {
                let transmit_msg = match self.to_transmit_msg (live_package, msg.last_data) {
                    // crashpoint - need to figure out how to bubble up different kinds of errors, or just log and return
                    Err (_) => unimplemented! (),
                    Ok (m) => m
                };
                self.logger.debug (format! ("Relaying {}-byte LiveCoresPackage Dispatcher inside a TransmitDataMsg", transmit_msg.data.len ()));
                self.to_dispatcher.as_ref().expect("Dispatcher unbound in Hopper").send(transmit_msg).expect("Dispatcher is dead");
            },
        };
        ()
    }
}

impl Hopper {
    pub fn new (cryptde: Box<CryptDE>) -> Hopper {
        Hopper {
            cryptde,
            to_proxy_server: None,
            to_proxy_client: None,
            to_dispatcher: None,
            logger: Logger::new ("Hopper"),
        }
    }

    pub fn make_subs_from(addr: &SyncAddress<Hopper>) -> HopperSubs {
        HopperSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_hopper_client: addr.subscriber::<IncipientCoresPackage>(),
            from_dispatcher: addr.subscriber::<InboundClientData>(),
        }
    }

    // TODO when we are decentralized, change this type to a TransmitDataMsg
    pub fn to_transmit_msg (&self, live_package: LiveCoresPackage, last_data: bool) -> Result<HopperTemporaryTransmitDataMsg, CryptdecError> {
        let (next_key, next_live_package) = match live_package.to_next_live (self.cryptde.borrow ()) {
            // crashpoint - log error and return None?
            Err (_) => unimplemented! (),
            Ok (p) => p
        };
        let next_live_package_ser = match serde_cbor::ser::to_vec (&next_live_package) {
            // crashpoint - log error and return None?
            Err (_) => unimplemented! (),
            Ok (p) => p
        };
        let next_live_package_enc = match self.cryptde.encode (&next_key, &PlainData::new (&next_live_package_ser[..])) {
            // crashpoint - log error and return None?
            Err (_) => unimplemented! (),
            Ok (p) => p
        };
        // TODO when we are decentralized, change this to a TransmitDataMsg
        Ok (HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Key(next_key),
            last_data,
            data: next_live_package_enc.data
        })
    }
}

#[derive (Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveCoresPackage {
    pub route: Route,
    pub payload: CryptData
}

impl LiveCoresPackage {
    pub fn new (route: Route, payload: CryptData) -> LiveCoresPackage {
        LiveCoresPackage { route, payload}
    }

    pub fn from_incipient (incipient: IncipientCoresPackage, cryptde: &CryptDE) -> (LiveCoresPackage, Key) {
        // crashpoint - should discuss as a team
        let encrypted_payload = cryptde.encode (&incipient.payload_destination_key, &incipient.payload).expect ("Encode error");
        let mut route = incipient.route.clone ();
        let next_hop = match route.shift (&cryptde.private_key (), cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!(),
            Some (h) => h
        };
        match next_hop.public_key {
            // crashpoint - should discuss as a team
            None => unimplemented! (), // can't send over Substratum Network if no destination
            Some (key) => (LiveCoresPackage::new (route, encrypted_payload), key)
        }
    }

    pub fn to_expired (self, cryptde: &CryptDE) -> ExpiredCoresPackage {
        let payload = match cryptde.decode (&cryptde.private_key (), &self.payload) {
            Ok (payload) => payload,
            // crashpoint - should discuss as a team
            Err (e) => panic! ("{:?}", e)
        };
        ExpiredCoresPackage::new (self.route, payload)
    }

    pub fn to_next_live (mut self, cryptde: &CryptDE) -> Result<(Key, LiveCoresPackage), CryptdecError> {
        let next_hop = match self.route.shift (&cryptde.private_key (), cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented! (),
            Some (h) => h
        };
        let next_key = match next_hop.public_key {
            // crashpoint - should discuss as a team
            None => unimplemented! (),
            Some (k) => k
        };
        let next_live = LiveCoresPackage::new (self.route, self.payload);
        Ok ((next_key, next_live))
    }

    pub fn next_hop (&self, cryptde: &CryptDE) -> Hop {
        match self.route.next_hop (&cryptde.private_key (), cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented! (),
            Some (h) => h
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;
    use actix::msgs;
    use actix::Actor;
    use actix::Arbiter;
    use actix::SyncAddress;
    use actix::System;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::dispatcher::Component;
    use sub_lib::hop::Hop;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use test_utils::test_utils::make_peer_actors_from;
    use test_utils::test_utils::PayloadMock;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::route_to_proxy_client;
    use test_utils::test_utils::route_to_proxy_server;
    use sub_lib::hopper::HopperTemporaryTransmitDataMsg;

    #[test]
    fn live_cores_package_can_be_constructed_from_scratch () {
        let payload = CryptData::new (&[5, 6]);
        let cryptde = CryptDENull::new();
        let route = Route::new(vec!(RouteSegment::new(vec!(&Key::new(&[1, 2]), &Key::new(&[3, 4])),
                      Component::Neighborhood)), &cryptde).unwrap();

        let subject = LiveCoresPackage::new (route.clone(), payload.clone ());

        assert_eq! (subject.route, route);
        assert_eq! (subject.payload, payload);
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_incipient_cores_package () {
        let cryptde = CryptDENull::new ();
        let key12 = cryptde.public_key ();
        let key34 = Key::new (&[3, 4]);
        let key56 = Key::new (&[5, 6]);
        let mut route = Route::new(vec! (
            RouteSegment::new (vec! (&key12, &key34, &key56), Component::Neighborhood)
        ), &cryptde).unwrap ();
        let payload = PayloadMock::new ();
        let incipient = IncipientCoresPackage::new (
            route.clone (),
            payload.clone (),
            &key56
        );

        let (subject, next_stop) = LiveCoresPackage::from_incipient (incipient, &cryptde);

        assert_eq! (next_stop, key34);
        route.shift (&cryptde.private_key (), &cryptde).unwrap ();
        assert_eq! (subject.route, route);
        assert_eq! (subject.payload, cryptde.encode (&key56, &PlainData::new (&serde_cbor::ser::to_vec (&payload).unwrap ())).unwrap ());
    }

    #[test]
    fn converts_incipient_message_to_live_and_sends_to_dispatcher () {
        let cryptde = CryptDENull::new ();
        let cryptde_t = cryptde.clone ();
        let dispatcher = Recorder::new ();
        let dispatcher_recording_arc = dispatcher.get_recording ();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let destination_key = Key::new (&[65, 65, 65]);
        let route = Route::new (
            vec! (RouteSegment::new (vec! (&cryptde.public_key (), &destination_key.clone ()), Component::Neighborhood)),
            &cryptde
        ).unwrap ();
        let payload = PlainData::new (&b"abcd"[..]);
        let incipient_cores_package = IncipientCoresPackage::new (route.clone (),
            payload, &destination_key);
        let incipient_cores_package_a = incipient_cores_package.clone ();
        thread::spawn (move || {
            let system = System::new ("converts_incipient_message_to_live_and_sends_to_dispatcher");
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None);
            let subject = Hopper::new (Box::new (cryptde_t));
            let subject_addr: SyncAddress<_> = subject.start ();
            subject_addr.send (BindMessage {peer_actors});

            subject_addr.send (incipient_cores_package);

            system.run ();
        });
        dispatcher_awaiter.await_message_count(1);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<HopperTemporaryTransmitDataMsg>(0);
        let expected_lcp = LiveCoresPackage::from_incipient (incipient_cores_package_a, &cryptde).0;
        let expected_lcp_ser = PlainData::new (&serde_cbor::ser::to_vec (&expected_lcp).unwrap ());
        let expected_lcp_enc = cryptde.encode (&destination_key, &expected_lcp_ser).unwrap ();
        assert_eq! (*record, HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Key (destination_key.clone ()),
            last_data: false,
            data: expected_lcp_enc.data
        });
    }

    #[test]
    fn converts_live_message_to_expired_for_proxy_client () {
        let cryptde = CryptDENull::new ();
        let cryptde_t = cryptde.clone ();
        let component = Recorder::new ();
        let component_recording_arc = component.get_recording ();
        let component_awaiter = component.get_awaiter ();
        let hop = Hop {public_key: None, component: Some (Component::ProxyClient)};
        let route = Route {hops: vec! (cryptde.encode (&cryptde.public_key (), &PlainData::new (&serde_cbor::ser::to_vec (&hop).unwrap ())).unwrap ())};
        let payload = PlainData::new (&b"abcd"[..]);
        let lcp = LiveCoresPackage::new (route, cryptde.encode (&cryptde.public_key (), &payload).unwrap ());
        let lcp_a = lcp.clone ();
        let data_ser = PlainData::new (&serde_cbor::ser::to_vec (&lcp).unwrap ()[..]);
        let data_enc = cryptde.encode (&cryptde.public_key (), &data_ser).unwrap ();
        let inbound_client_data = InboundClientData {
            socket_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            origin_port: None,
            component: Component::Hopper,
            last_data: false,
            data: data_enc.data
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_client");
            let peer_actors = make_peer_actors_from(None, None, None, Some(component));
            let subject = Hopper::new (Box::new (cryptde_t));
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage { peer_actors });

            subject_addr.send(inbound_client_data );

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage>(0);
        let expected_ecp = lcp_a.to_expired (&cryptde);
        assert_eq! (*record, expected_ecp);
    }

    #[test]
    fn converts_live_message_to_expired_for_proxy_server () {
        let cryptde = CryptDENull::new ();
        let cryptde_t = cryptde.clone ();
        let component = Recorder::new ();
        let component_recording_arc = component.get_recording ();
        let component_awaiter = component.get_awaiter ();
        let hop = Hop {public_key: None, component: Some (Component::ProxyServer)};
        let route = Route {hops: vec! (cryptde.encode (&cryptde.public_key (), &PlainData::new (&serde_cbor::ser::to_vec (&hop).unwrap ())).unwrap ())};
        let payload = PlainData::new (&b"abcd"[..]);
        let lcp = LiveCoresPackage::new (route, cryptde.encode (&cryptde.public_key (), &payload).unwrap ());
        let lcp_a = lcp.clone ();
        let data_ser = PlainData::new (&serde_cbor::ser::to_vec (&lcp).unwrap ()[..]);
        let data_enc = cryptde.encode (&cryptde.public_key (), &data_ser).unwrap ();
        let inbound_client_data = InboundClientData {
            socket_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            origin_port: None,
            component: Component::Hopper,
            last_data: false,
            data: data_enc.data
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_server");
            let peer_actors = make_peer_actors_from(Some (component), None, None, None);
            let subject = Hopper::new (Box::new (cryptde_t));
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage { peer_actors });

            subject_addr.send(inbound_client_data );

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage>(0);
        let expected_ecp = lcp_a.to_expired (&cryptde);
        assert_eq! (*record, expected_ecp);
    }

    #[test]
    fn passes_on_inbound_client_data_not_meant_for_this_node () {
        let cryptde = CryptDENull::new ();
        let cryptde_t = cryptde.clone ();
        let dispatcher = Recorder::new ();
        let dispatcher_recording_arc = dispatcher.get_recording ();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let next_key = Key::new (&[65, 65, 65]);
        let route = Route::new (vec! (
            RouteSegment::new (vec! (&cryptde.public_key (), &next_key), Component::Neighborhood)
        ), &cryptde).unwrap ();
        let payload = PlainData::new (&b"abcd"[..]);
        let lcp = LiveCoresPackage::new (route, cryptde.encode (&next_key, &payload).unwrap ());
        let lcp_a = lcp.clone ();
        let data_ser = PlainData::new (&serde_cbor::ser::to_vec (&lcp).unwrap ()[..]);
        let data_enc = cryptde.encode (&cryptde.public_key (), &data_ser).unwrap ();
        let inbound_client_data = InboundClientData {
            socket_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            origin_port: None,
            component: Component::Hopper,
            last_data: true,
            data: data_enc.data
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_server");
            let peer_actors = make_peer_actors_from(None, Some (dispatcher), None, None);
            let subject = Hopper::new (Box::new (cryptde_t));
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage { peer_actors });

            subject_addr.send(inbound_client_data );

            system.run();
        });
        dispatcher_awaiter.await_message_count(1);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<HopperTemporaryTransmitDataMsg>(0);
        let expected_lcp = lcp_a.to_next_live (&cryptde).unwrap ().1;
        let expected_lcp_ser = PlainData::new (&serde_cbor::ser::to_vec (&expected_lcp).unwrap ());
        let expected_lcp_enc = cryptde.encode (&next_key, &expected_lcp_ser).unwrap ();
        assert_eq! (*record, HopperTemporaryTransmitDataMsg {
            endpoint: Endpoint::Key (next_key.clone ()),
            last_data: true,
            data: expected_lcp_enc.data
        });
    }

    #[test]
    #[should_panic (expected = "ProxyServer unbound in Hopper")]
    fn panics_if_proxy_server_is_unbound() {
        let cryptde = CryptDENull::new ();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_server(&cryptde.public_key(), &cryptde);
        let serialized_payload = serde_cbor::ser::to_vec (&PayloadMock::new()).unwrap ();
        let data = cryptde.encode(&cryptde.public_key(), &PlainData::new(&serialized_payload[..])).unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec (&live_package).unwrap ()[..]);
        let encrypted_package = cryptde.encode(&cryptde.public_key(), &live_data).unwrap().data;

        let inbound_client_data = InboundClientData {
            socket_addr,
            origin_port: None,
            component: Component::Hopper,
            last_data: false,
            data: encrypted_package,
        };
        let system = System::new("panics_if_proxy_server_is_unbound");
        let subject = Hopper::new (Box::new (cryptde));
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(inbound_client_data );

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }

    #[test]
    #[should_panic (expected = "ProxyClient unbound in Hopper")]
    fn panics_if_proxy_client_is_unbound() {
        let cryptde = CryptDENull::new ();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_client(&cryptde.public_key(), &cryptde);
        let serialized_payload = serde_cbor::ser::to_vec (&PayloadMock::new()).unwrap ();
        let data = cryptde.encode(&cryptde.public_key(), &PlainData::new(&serialized_payload[..])).unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec (&live_package).unwrap ()[..]);
        let encrypted_package = cryptde.encode(&cryptde.public_key(), &live_data).unwrap().data;

        let inbound_client_data = InboundClientData {
            socket_addr,
            origin_port: None,
            component: Component::Hopper,
            last_data: false,
            data: encrypted_package,
        };
        let system = System::new("panics_if_proxy_client_is_unbound");
        let subject = Hopper::new (Box::new (cryptde));
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(inbound_client_data );

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }

    #[test]
    #[should_panic (expected = "Dispatcher unbound in Hopper")]
    fn panics_if_dispatcher_is_unbound() {
        let cryptde = CryptDENull::new ();
        let next_key = Key::new (&[65, 65, 65]);
        let route = Route::new (vec! (
            RouteSegment::new (vec! (&cryptde.public_key (), &next_key), Component::Neighborhood)
        ), &cryptde).unwrap ();
        let incipient_package = IncipientCoresPackage::new (
            route,
            PayloadMock::new (), &cryptde.public_key ()
        );
        let system = System::new("panics_if_dispatcher_is_unbound");
        let subject = Hopper::new (Box::new (cryptde));
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(incipient_package );

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }
}
