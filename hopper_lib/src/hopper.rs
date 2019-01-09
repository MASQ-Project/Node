// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use serde_cbor;
use std::borrow::Borrow;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::CryptdecError;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hop::Hop;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::ExpiredCoresPackagePackage;
use sub_lib::hopper::HopperSubs;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::route::Route;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;

pub struct Hopper {
    cryptde: &'static CryptDE,
    is_bootstrap_node: bool,
    to_proxy_server: Option<Recipient<Syn, ExpiredCoresPackage>>,
    to_proxy_client: Option<Recipient<Syn, ExpiredCoresPackage>>,
    to_neighborhood: Option<Recipient<Syn, ExpiredCoresPackagePackage>>,
    to_dispatcher: Option<Recipient<Syn, TransmitDataMsg>>,
    logger: Logger,
    to_self: Option<Recipient<Syn, InboundClientData>>,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.to_proxy_server = Some(msg.peer_actors.proxy_server.from_hopper);
        self.to_proxy_client = Some(msg.peer_actors.proxy_client.from_hopper);
        self.to_neighborhood = Some(msg.peer_actors.neighborhood.from_hopper);
        self.to_dispatcher = Some(msg.peer_actors.dispatcher.from_dispatcher_client);
        self.to_self = Some(msg.peer_actors.hopper.from_dispatcher);
        ()
    }
}

impl Handler<IncipientCoresPackage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug(format!(
            "Received IncipientCoresPackage with {}-byte payload",
            msg.payload.data.len()
        ));
        let (live_package, key) = LiveCoresPackage::from_incipient(msg, self.cryptde.borrow());

        let serialized_package = match serde_cbor::ser::to_vec(&live_package) {
            Ok(package) => package,
            Err(_) => {
                self.logger.error(format!("Couldn't serialize package"));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ();
            }
        };

        let encrypted_package = match self
            .cryptde
            .encode(&key, &PlainData::new(&serialized_package[..]))
        {
            Ok(package) => package,
            Err(_) => {
                self.logger.error(format!("Couldn't encode package"));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ();
            }
        };

        if self.cryptde.public_key() == key {
            // to allow 0-hop Routes
            let inbound_client_data = InboundClientData {
                peer_addr: SocketAddr::from_str("1.2.3.4:5678")
                    .expect("Something terrible has happened"), // irrelevant
                reception_port: None, // irrelevant
                last_data: false,     // irrelevant
                sequence_number: None,
                is_clandestine: true,
                data: encrypted_package.data,
            };
            self.logger.debug(format!(
                "Sending InboundClientData with {}-byte payload to Hopper",
                inbound_client_data.data.len()
            ));
            self.to_self
                .as_ref()
                .expect("Hopper unbound in Hopper")
                .try_send(inbound_client_data)
                .expect("Hopper is dead");
        } else {
            let transmit_msg = TransmitDataMsg {
                endpoint: Endpoint::Key(key),
                last_data: false, // Hopper-to-Hopper streams are never remotely killed
                data: encrypted_package.data,
                sequence_number: None,
            };

            self.logger.debug(format!(
                "Sending TransmitDataMsg with {}-byte payload to Dispatcher",
                transmit_msg.data.len()
            ));
            self.to_dispatcher
                .as_ref()
                .expect("Dispatcher unbound in Hopper")
                .try_send(transmit_msg)
                .expect("Dispatcher is dead");
        }
        ()
    }
}

impl Handler<InboundClientData> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug(format!(
            "Received {} bytes of InboundClientData from Dispatcher",
            msg.data.len()
        ));
        let decrypted_package = match self.cryptde.decode(&CryptData::new(&msg.data[..])) {
            Ok(package) => package,
            Err(e) => {
                self.logger
                    .error(format!("Couldn't decrypt CORES package: {:?}", e));
                // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                return ();
            }
        };
        let live_package =
            match serde_cbor::de::from_slice::<LiveCoresPackage>(&decrypted_package.data[..]) {
                Ok(package) => package,
                Err(e) => {
                    self.logger
                        .error(format!("Couldn't deserialize CORES package: {}", e));
                    // TODO what should we do here? (nothing is unbound --so we don't need to blow up-- but we can't send this package)
                    return ();
                }
            };

        let next_hop = live_package.next_hop(self.cryptde.borrow());

        if self.should_route_data(next_hop.component) {
            let sender_ip = msg.peer_addr.ip();
            match next_hop.component {
                Component::ProxyServer => {
                    self.handle_endpoint(next_hop.component, &self.to_proxy_server, live_package)
                }
                Component::ProxyClient => {
                    self.handle_endpoint(next_hop.component, &self.to_proxy_client, live_package)
                }
                Component::Neighborhood => self.handle_ip_endpoint(
                    next_hop.component,
                    &self.to_neighborhood,
                    live_package,
                    sender_ip,
                ),
                Component::Hopper => {
                    let transmit_msg = match self.to_transmit_msg(live_package, msg.last_data) {
                        // crashpoint - need to figure out how to bubble up different kinds of errors, or just log and return
                        Err(_) => unimplemented!(),
                        Ok(m) => m,
                    };
                    self.logger.debug(format!(
                        "Relaying {}-byte LiveCoresPackage Dispatcher inside a TransmitDataMsg",
                        transmit_msg.data.len()
                    ));
                    self.to_dispatcher
                        .as_ref()
                        .expect("Dispatcher unbound in Hopper")
                        .try_send(transmit_msg)
                        .expect("Dispatcher is dead");
                }
            }
        };
        ()
    }
}

impl Hopper {
    pub fn new(cryptde: &'static CryptDE, is_bootstrap_node: bool) -> Hopper {
        Hopper {
            cryptde,
            is_bootstrap_node,
            to_proxy_server: None,
            to_proxy_client: None,
            to_neighborhood: None,
            to_dispatcher: None,
            logger: Logger::new("Hopper"),
            to_self: None,
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, Hopper>) -> HopperSubs {
        HopperSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            from_hopper_client: addr.clone().recipient::<IncipientCoresPackage>(),
            from_dispatcher: addr.clone().recipient::<InboundClientData>(),
        }
    }

    pub fn to_transmit_msg(
        &self,
        live_package: LiveCoresPackage,
        last_data: bool,
    ) -> Result<TransmitDataMsg, CryptdecError> {
        let (next_key, next_live_package) = match live_package.to_next_live(self.cryptde.borrow()) {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        let next_live_package_ser = match serde_cbor::ser::to_vec(&next_live_package) {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        let next_live_package_enc = match self
            .cryptde
            .encode(&next_key, &PlainData::new(&next_live_package_ser[..]))
        {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        Ok(TransmitDataMsg {
            endpoint: Endpoint::Key(next_key),
            last_data,
            data: next_live_package_enc.data,
            sequence_number: None,
        })
    }

    fn should_route_data(&self, component: Component) -> bool {
        if component == Component::Neighborhood {
            true
        } else if self.is_bootstrap_node {
            self.logger.error(format!(
                "Request for Bootstrap Node to route data to {:?}: rejected",
                component
            ));
            false
        } else {
            true
        }
    }

    fn handle_endpoint(
        &self,
        component: Component,
        recipient: &Option<Recipient<Syn, ExpiredCoresPackage>>,
        live_package: LiveCoresPackage,
    ) {
        let expired_package = live_package.to_expired(self.cryptde.borrow());
        self.logger.trace(format!(
            "Forwarding ExpiredCoresPackage to {:?}: {:?}",
            component, expired_package
        ));
        recipient
            .as_ref()
            .expect(&format!("{:?} unbound in Hopper", component))
            .try_send(expired_package)
            .expect(&format!("{:?} is dead", component))
    }

    fn handle_ip_endpoint(
        &self,
        component: Component,
        recipient: &Option<Recipient<Syn, ExpiredCoresPackagePackage>>,
        live_package: LiveCoresPackage,
        sender_ip: IpAddr,
    ) {
        let expired_package = live_package.to_expired(self.cryptde.borrow());
        let expired_package_package = ExpiredCoresPackagePackage {
            expired_cores_package: expired_package,
            sender_ip,
        };
        self.logger.trace(format!(
            "Forwarding ExpiredCoresPackagePackage to {:?}: {:?}",
            component, expired_package_package
        ));
        recipient
            .as_ref()
            .expect(&format!("{:?} unbound in Hopper", component))
            .try_send(expired_package_package)
            .expect(&format!("{:?} is dead", component))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LiveCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

impl LiveCoresPackage {
    pub fn new(route: Route, payload: CryptData) -> LiveCoresPackage {
        LiveCoresPackage { route, payload }
    }

    pub fn from_incipient(
        incipient: IncipientCoresPackage,
        cryptde: &CryptDE,
    ) -> (LiveCoresPackage, Key) {
        // crashpoint - should discuss as a team
        let encrypted_payload = cryptde
            .encode(&incipient.payload_destination_key, &incipient.payload)
            .expect("Encode error");
        let mut route = incipient.route.clone();
        let next_hop = match route.shift(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!("no next_hop shifted out of route"),
            Some(h) => h,
        };

        (
            LiveCoresPackage::new(route, encrypted_payload),
            next_hop.public_key,
        )
    }

    pub fn to_expired(self, cryptde: &CryptDE) -> ExpiredCoresPackage {
        let payload = match cryptde.decode(&self.payload) {
            Ok(payload) => payload,
            // crashpoint - should discuss as a team
            Err(e) => panic!("{:?}", e),
        };
        ExpiredCoresPackage::new(self.route, payload)
    }

    pub fn to_next_live(
        mut self,
        cryptde: &CryptDE,
    ) -> Result<(Key, LiveCoresPackage), CryptdecError> {
        let next_hop = match self.route.shift(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!(),
            Some(h) => h,
        };
        let next_key = next_hop.public_key;
        let next_live = LiveCoresPackage::new(self.route, self.payload);
        Ok((next_key, next_live))
    }

    pub fn next_hop(&self, cryptde: &CryptDE) -> Hop {
        match self.route.next_hop(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!(),
            Some(h) => h,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Actor;
    use actix::Arbiter;
    use actix::System;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;
    use sub_lib::cryptde::PlainData;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use test_utils::test_utils::route_to_proxy_client;
    use test_utils::test_utils::route_to_proxy_server;
    use test_utils::test_utils::zero_hop_route_response;
    use test_utils::test_utils::PayloadMock;

    #[test]
    fn live_cores_package_can_be_constructed_from_scratch() {
        let payload = CryptData::new(&[5, 6]);
        let cryptde = cryptde();
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&Key::new(&[1, 2]), &Key::new(&[3, 4])],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();

        let subject = LiveCoresPackage::new(route.clone(), payload.clone());

        assert_eq!(subject.route, route);
        assert_eq!(subject.payload, payload);
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_incipient_cores_package() {
        let cryptde = cryptde();
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let mut route = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        let payload = PayloadMock::new();
        let incipient = IncipientCoresPackage::new(route.clone(), payload.clone(), &key56);

        let (subject, next_stop) = LiveCoresPackage::from_incipient(incipient, cryptde);

        assert_eq!(next_stop, key34);
        route.shift(cryptde).unwrap();
        assert_eq!(subject.route, route);
        assert_eq!(
            subject.payload,
            cryptde
                .encode(
                    &key56,
                    &PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap())
                )
                .unwrap()
        );
    }

    #[test]
    fn converts_incipient_message_to_live_and_sends_to_dispatcher() {
        let cryptde = cryptde();
        let dispatcher = Recorder::new();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let destination_key = Key::new(&[65, 65, 65]);
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &destination_key.clone()],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let incipient_cores_package =
            IncipientCoresPackage::new(route.clone(), payload, &destination_key);
        let incipient_cores_package_a = incipient_cores_package.clone();
        thread::spawn(move || {
            let system = System::new("converts_incipient_message_to_live_and_sends_to_dispatcher");
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None, None);
            let subject = Hopper::new(cryptde, false);
            let subject_addr: Addr<Syn, Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(incipient_cores_package).unwrap();

            system.run();
        });
        dispatcher_awaiter.await_message_count(1);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let expected_lcp = LiveCoresPackage::from_incipient(incipient_cores_package_a, cryptde).0;
        let expected_lcp_ser = PlainData::new(&serde_cbor::ser::to_vec(&expected_lcp).unwrap());
        let expected_lcp_enc = cryptde.encode(&destination_key, &expected_lcp_ser).unwrap();
        assert_eq!(
            *record,
            TransmitDataMsg {
                endpoint: Endpoint::Key(destination_key.clone()),
                last_data: false,
                sequence_number: None,
                data: expected_lcp_enc.data,
            }
        );
    }

    #[test]
    fn converts_live_message_to_expired_for_proxy_client() {
        let cryptde = cryptde();
        let component = Recorder::new();
        let component_recording_arc = component.get_recording();
        let component_awaiter = component.get_awaiter();
        let route = route_to_proxy_client(&cryptde.public_key(), cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.data,
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_client");
            let peer_actors = make_peer_actors_from(None, None, None, Some(component), None);
            let subject = Hopper::new(cryptde, false);
            let subject_addr: Addr<Syn, Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(inbound_client_data).unwrap();

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage>(0);
        let expected_ecp = lcp_a.to_expired(cryptde);
        assert_eq!(*record, expected_ecp);
    }

    #[test]
    fn converts_live_message_to_expired_for_proxy_server() {
        let cryptde = cryptde();
        let component = Recorder::new();
        let component_recording_arc = component.get_recording();
        let component_awaiter = component.get_awaiter();
        let route = route_to_proxy_server(&cryptde.public_key(), cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: data_enc.data,
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_server");
            let peer_actors = make_peer_actors_from(Some(component), None, None, None, None);
            let subject = Hopper::new(cryptde, false);
            let subject_addr: Addr<Syn, Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(inbound_client_data).unwrap();

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage>(0);
        let expected_ecp = lcp_a.to_expired(cryptde);
        assert_eq!(*record, expected_ecp);
    }

    #[test]
    fn refuses_data_for_proxy_client_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let route = route_to_proxy_client(&cryptde.public_key(), cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: data_enc.data,
        };
        let system = System::new("refuses_data_for_proxy_client_if_is_bootstrap_node");
        let subject = Hopper::new(cryptde, true);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: Hopper: Request for Bootstrap Node to route data to ProxyClient: rejected",
        );
    }

    #[test]
    fn refuses_data_for_proxy_server_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let route = route_to_proxy_server(&cryptde.public_key(), cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.data,
        };
        let system = System::new("refuses_data_for_proxy_server_if_is_bootstrap_node");
        let subject = Hopper::new(cryptde, true);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: Hopper: Request for Bootstrap Node to route data to ProxyServer: rejected",
        );
    }

    #[test]
    fn refuses_data_for_hopper_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::Hopper,
            )],
            cryptde,
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.data,
        };
        let system = System::new("refuses_data_for_hopper_if_is_bootstrap_node");
        let subject = Hopper::new(cryptde, true);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: Hopper: Request for Bootstrap Node to route data to Hopper: rejected",
        );
    }

    #[test]
    fn accepts_data_for_neighborhood_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let mut route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        route.shift(cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.data,
        };
        let system = System::new("accepts_data_for_neighborhood_if_is_bootstrap_node");
        let subject = Hopper::new(cryptde, true);
        let subject_addr: Addr<Syn, Hopper> = subject.start();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = make_peer_actors_from(None, None, None, None, Some(neighborhood));
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data.clone()).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let message: &ExpiredCoresPackagePackage = neighborhood_recording.get_record(0);
        assert_eq!(
            message.clone().expired_cores_package.payload_data(),
            payload
        );
        assert_eq!(
            message.clone().sender_ip,
            IpAddr::from_str("1.2.3.4").unwrap()
        );
        TestLogHandler::new().exists_no_log_containing(
            "ERROR: Hopper: Request for Bootstrap Node to route data to Neighborhood: rejected",
        );
    }

    #[test]
    fn rejects_data_for_non_neighborhood_component_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let mut route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::ProxyClient,
            )],
            cryptde,
        )
        .unwrap();
        route.shift(cryptde);
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            cryptde.encode(&cryptde.public_key(), &payload).unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.data,
        };
        let system =
            System::new("rejects_data_for_non_neighborhood_component_if_is_bootstrap_node");
        let subject = Hopper::new(cryptde, true);
        let subject_addr: Addr<Syn, Hopper> = subject.start();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let peer_actors = make_peer_actors_from(None, None, None, Some(proxy_client), None);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data.clone()).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(proxy_client_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            "ERROR: Hopper: Request for Bootstrap Node to route data to ProxyClient: rejected",
        );
    }

    #[test]
    fn passes_on_inbound_client_data_not_meant_for_this_node() {
        let cryptde = cryptde();
        let dispatcher = Recorder::new();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let next_key = Key::new(&[65, 65, 65]);
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &next_key],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(route, cryptde.encode(&next_key, &payload).unwrap());
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: false,
            sequence_number: None,
            data: data_enc.data,
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_server");
            let peer_actors = make_peer_actors_from(None, Some(dispatcher), None, None, None);
            let subject = Hopper::new(cryptde, false);
            let subject_addr: Addr<Syn, Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(inbound_client_data).unwrap();

            system.run();
        });
        dispatcher_awaiter.await_message_count(1);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let expected_lcp = lcp_a.to_next_live(cryptde).unwrap().1;
        let expected_lcp_ser = PlainData::new(&serde_cbor::ser::to_vec(&expected_lcp).unwrap());
        let expected_lcp_enc = cryptde.encode(&next_key, &expected_lcp_ser).unwrap();
        assert_eq!(
            *record,
            TransmitDataMsg {
                endpoint: Endpoint::Key(next_key.clone()),
                last_data: true,
                sequence_number: None,
                data: expected_lcp_enc.data,
            }
        );
    }

    #[test]
    #[should_panic(expected = "ProxyServer unbound in Hopper")]
    fn panics_if_proxy_server_is_unbound() {
        let cryptde = cryptde();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_server(&cryptde.public_key(), cryptde);
        let serialized_payload = serde_cbor::ser::to_vec(&PayloadMock::new()).unwrap();
        let data = cryptde
            .encode(
                &cryptde.public_key(),
                &PlainData::new(&serialized_payload[..]),
            )
            .unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec(&live_package).unwrap()[..]);
        let encrypted_package = cryptde
            .encode(&cryptde.public_key(), &live_data)
            .unwrap()
            .data;

        let inbound_client_data = InboundClientData {
            peer_addr,
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: encrypted_package,
        };
        let system = System::new("panics_if_proxy_server_is_unbound");
        let subject = Hopper::new(cryptde, false);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "ProxyClient unbound in Hopper")]
    fn panics_if_proxy_client_is_unbound() {
        let cryptde = cryptde();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_client(&cryptde.public_key(), cryptde);
        let serialized_payload = serde_cbor::ser::to_vec(&PayloadMock::new()).unwrap();
        let data = cryptde
            .encode(
                &cryptde.public_key(),
                &PlainData::new(&serialized_payload[..]),
            )
            .unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec(&live_package).unwrap()[..]);
        let encrypted_package = cryptde
            .encode(&cryptde.public_key(), &live_data)
            .unwrap()
            .data;

        let inbound_client_data = InboundClientData {
            peer_addr,
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: encrypted_package,
        };
        let system = System::new("panics_if_proxy_client_is_unbound");
        let subject = Hopper::new(cryptde, false);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Dispatcher unbound in Hopper")]
    fn panics_if_dispatcher_is_unbound() {
        let cryptde = cryptde();
        let next_key = Key::new(&[65, 65, 65]);
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &next_key],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        let incipient_package =
            IncipientCoresPackage::new(route, PayloadMock::new(), &cryptde.public_key());
        let system = System::new("panics_if_dispatcher_is_unbound");
        let subject = Hopper::new(cryptde, false);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(incipient_package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    fn live_cores_package_serialization_deserialization() {
        let original = LiveCoresPackage {
            route: make_meaningless_route(),
            payload: CryptData::new(&[1, 2, 3, 4]),
        };

        let serialized = serde_cbor::ser::to_vec(&original).unwrap();

        let deserialized = serde_cbor::de::from_slice::<LiveCoresPackage>(&serialized[..]).unwrap();

        assert_eq!(deserialized, original);
    }

    #[test]
    fn hopper_sends_incipient_cores_package_to_recipient_component_when_next_hop_key_is_the_same_as_the_public_key_of_this_node(
    ) {
        let cryptde = cryptde();
        let (component, component_awaiter, component_recording_arc) = make_recorder();
        let destination_key = cryptde.public_key();
        let route = zero_hop_route_response(&cryptde.public_key(), cryptde).route;
        let payload = PlainData::new(&b"abcd"[..]);
        let incipient_cores_package = IncipientCoresPackage::new(route, payload, &destination_key);
        let incipient_cores_package_a = incipient_cores_package.clone();
        let (lcp, _key) = LiveCoresPackage::from_incipient(incipient_cores_package_a, cryptde);
        thread::spawn(move || {
            let system = System::new ("hopper_sends_incipient_cores_package_to_recipient_component_when_next_hop_key_is_the_same_as_the_public_key_of_this_node");
            let mut peer_actors = make_peer_actors_from(None, None, None, Some(component), None);
            let subject = Hopper::new(cryptde, false);
            let subject_addr: Addr<Syn, Hopper> = subject.start();
            let subject_subs = Hopper::make_subs_from(&subject_addr);
            peer_actors.hopper = subject_subs;
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(incipient_cores_package).unwrap();

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage>(0);
        let expected_ecp = lcp.to_expired(cryptde);
        assert_eq!(*record, expected_ecp);
    }
}
