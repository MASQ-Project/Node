// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::live_cores_package::LiveCoresPackage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::CryptdecError;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::dispatcher::Endpoint;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::hop::LiveHop;
use crate::sub_lib::hopper::{ExpiredCoresPackage, MessageType};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use std::borrow::Borrow;
use std::net::IpAddr;

pub struct RoutingService {
    cryptde: &'static dyn CryptDE,
    is_bootstrap_node: bool,
    proxy_client_subs: ProxyClientSubs,
    proxy_server_subs: ProxyServerSubs,
    neighborhood_subs: NeighborhoodSubs,
    to_dispatcher: Recipient<TransmitDataMsg>,
    to_accountant_routing: Recipient<ReportRoutingServiceProvidedMessage>,
    per_routing_service: u64,
    per_routing_byte: u64,
    logger: Logger,
}

impl RoutingService {
    pub fn new(
        cryptde: &'static dyn CryptDE,
        is_bootstrap_node: bool,
        proxy_client_subs: ProxyClientSubs,
        proxy_server_subs: ProxyServerSubs,
        neighborhood_subs: NeighborhoodSubs,
        to_dispatcher: Recipient<TransmitDataMsg>,
        to_accountant_routing: Recipient<ReportRoutingServiceProvidedMessage>,
        per_routing_service: u64,
        per_routing_byte: u64,
    ) -> RoutingService {
        RoutingService {
            cryptde,
            is_bootstrap_node,
            proxy_client_subs,
            proxy_server_subs,
            neighborhood_subs,
            to_dispatcher,
            to_accountant_routing,
            per_routing_service,
            per_routing_byte,
            logger: Logger::new("RoutingService"),
        }
    }

    pub fn route(&self, ibcd: InboundClientData) {
        let data_size = ibcd.data.len();
        self.logger.debug(format!(
            "Received {} bytes of InboundClientData from Dispatcher",
            data_size
        ));
        let sender_ip = ibcd.peer_addr.ip();
        let last_data = ibcd.last_data;
        let live_package = match self.decrypt_and_deserialize_lcp(ibcd) {
            Ok(package) => package,
            Err(_) => return, // log already written
        };

        let next_hop = match live_package.route.next_hop(self.cryptde.borrow()) {
            Ok(hop) => hop,
            Err(e) => {
                self.logger
                    .error(format!("Invalid {}-byte CORES package: {:?}", data_size, e));
                return;
            }
        };

        if self.should_route_data(next_hop.component) {
            self.route_data(sender_ip, next_hop, live_package, last_data);
        }
    }

    fn route_data(
        &self,
        sender_ip: IpAddr,
        next_hop: LiveHop,
        live_package: LiveCoresPackage,
        last_data: bool,
    ) {
        if next_hop.component == Component::Hopper {
            self.route_data_externally(live_package, next_hop.consuming_wallet, last_data);
        } else {
            self.route_data_internally(next_hop.component, sender_ip, live_package)
        }
    }

    fn route_data_internally(
        &self,
        component: Component,
        immediate_neighbor_ip: IpAddr,
        live_package: LiveCoresPackage,
    ) {
        let data_len = live_package.payload.len();
        let expired_package =
            match live_package.to_expired(immediate_neighbor_ip, self.cryptde.borrow()) {
                Ok(pkg) => pkg,
                Err(e) => {
                    self.logger.error(format!(
                        "Couldn't expire CORES package with {}-byte payload: {:?}",
                        data_len, e
                    ));
                    return;
                }
            };
        self.logger.trace(format!(
            "Forwarding ExpiredCoresPackage to {:?}: {:?}",
            component, expired_package
        ));
        match (component, expired_package.payload) {
            (Component::ProxyClient, MessageType::ClientRequest(client_request)) => self
                .proxy_client_subs
                .from_hopper
                .try_send(ExpiredCoresPackage::new(
                    expired_package.immediate_neighbor_ip,
                    expired_package.consuming_wallet,
                    expired_package.remaining_route,
                    client_request,
                    expired_package.payload_len,
                ))
                .expect("Proxy Client is dead"),
            (Component::ProxyServer, MessageType::ClientResponse(client_reponse)) => self
                .proxy_server_subs
                .from_hopper
                .try_send(ExpiredCoresPackage::new(
                    expired_package.immediate_neighbor_ip,
                    expired_package.consuming_wallet,
                    expired_package.remaining_route,
                    client_reponse,
                    expired_package.payload_len,
                ))
                .expect("Proxy Client is dead"),
            (Component::Neighborhood, MessageType::Gossip(gossip)) => self
                .neighborhood_subs
                .from_hopper
                .try_send(ExpiredCoresPackage::new(
                    expired_package.immediate_neighbor_ip,
                    expired_package.consuming_wallet,
                    expired_package.remaining_route,
                    gossip,
                    expired_package.payload_len,
                ))
                .expect("Proxy Client is dead"),
            (Component::ProxyServer, MessageType::DnsResolveFailed) => unimplemented!("SC-743"),
            (destination, payload) => self.logger.error(format!(
                "Attempt to send invalid combination {:?} to {:?}",
                payload, destination
            )),
        };
    }

    fn route_data_externally(
        &self,
        live_package: LiveCoresPackage,
        consuming_wallet_opt: Option<Wallet>,
        last_data: bool,
    ) {
        let payload_size = live_package.payload.len();
        match consuming_wallet_opt {
            Some(consuming_wallet) => {
                self.to_accountant_routing
                    .try_send(ReportRoutingServiceProvidedMessage {
                        consuming_wallet,
                        payload_size,
                        service_rate: self.per_routing_service,
                        byte_rate: self.per_routing_byte,
                    })
                    .expect("Accountant is dead");
            }
            None => {
                self.logger.error(format!(
                    "Refusing to route CORES package with {}-byte payload without consuming wallet",
                    payload_size
                ));
                return;
            }
        }

        let transmit_msg = match self.to_transmit_data_msg(live_package, last_data) {
            // crashpoint - need to figure out how to bubble up different kinds of errors, or just log and return
            Err(_) => unimplemented!(),
            Ok(m) => m,
        };

        self.logger.debug(format!(
            "Relaying {}-byte LiveCoresPackage Dispatcher inside a TransmitDataMsg",
            transmit_msg.data.len()
        ));
        self.to_dispatcher
            .try_send(transmit_msg)
            .expect("Dispatcher is dead");
    }

    fn to_transmit_data_msg(
        &self,
        live_package: LiveCoresPackage,
        last_data: bool,
    ) -> Result<TransmitDataMsg, CryptdecError> {
        let (next_hop, next_live_package) = match live_package.to_next_live(self.cryptde.borrow()) {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        let next_live_package_ser = match serde_cbor::ser::to_vec(&next_live_package) {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        let next_live_package_enc = match self.cryptde.encode(
            &next_hop.public_key,
            &PlainData::new(&next_live_package_ser[..]),
        ) {
            // crashpoint - log error and return None?
            Err(_) => unimplemented!(),
            Ok(p) => p,
        };
        Ok(TransmitDataMsg {
            endpoint: Endpoint::Key(next_hop.public_key),
            last_data,
            data: next_live_package_enc.into(),
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

    fn decrypt_and_deserialize_lcp(&self, ibcd: InboundClientData) -> Result<LiveCoresPackage, ()> {
        let decrypted_package = match self.cryptde.decode(&CryptData::new(&ibcd.data[..])) {
            Ok(package) => package,
            Err(e) => {
                self.logger.error(format!(
                    "Couldn't decrypt CORES package from {}-byte buffer: {:?}",
                    ibcd.data.len(),
                    e
                ));
                return Err(());
            }
        };
        let live_package =
            match serde_cbor::de::from_slice::<LiveCoresPackage>(decrypted_package.as_slice()) {
                Ok(package) => package,
                Err(e) => {
                    self.logger
                        .error(format!("Couldn't deserialize CORES package: {}", e));
                    return Err(());
                }
            };
        return Ok(live_package);
    }
}

#[cfg(test)]
mod tests {
    use super::super::hopper::Hopper;
    use super::*;
    use crate::neighborhood::gossip::{Gossip, GossipBuilder};
    use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
    use crate::sub_lib::cryptde::{encodex, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::hopper::{HopperConfig, MessageType};
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::sub_lib::proxy_client::ClientResponsePayload;
    use crate::sub_lib::proxy_server::ClientRequestPayload;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::test_utils::route_to_proxy_client;
    use crate::test_utils::test_utils::route_to_proxy_server;
    use crate::test_utils::test_utils::{cryptde, make_request_payload};
    use crate::test_utils::test_utils::{make_response_payload, rate_pack_routing};
    use crate::test_utils::test_utils::{rate_pack_routing_byte, route_from_proxy_client};
    use actix::Actor;
    use actix::Addr;
    use actix::System;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::thread;

    #[test]
    fn logs_and_ignores_message_that_cannot_be_decoded() {
        init_test_logging();
        let cryptde = cryptde();
        let route = route_from_proxy_client(&cryptde.public_key(), cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex(cryptde, &cryptde.public_key(), &[42u8]).unwrap(),
        );
        let data_enc = encodex(cryptde, &cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let peer_actors = peer_actors_builder().build();
        let subject = RoutingService::new(
            cryptde,
            false,
            peer_actors.proxy_client,
            peer_actors.proxy_server,
            peer_actors.neighborhood,
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.accountant.report_routing_service_provided,
            100,
            200,
        );
        subject.route(inbound_client_data);
        TestLogHandler::new().await_log_matching(
            "Couldn't expire CORES package with \\d+-byte payload: .*",
            1000,
        );
    }

    #[test]
    fn logs_and_ignores_message_that_had_invalid_destination() {
        init_test_logging();
        let cryptde = cryptde();
        let route = route_from_proxy_client(&cryptde.public_key(), cryptde);
        let payload = GossipBuilder::new().build();
        let lcp = LiveCoresPackage::new(
            route,
            encodex(
                cryptde,
                &cryptde.public_key(),
                &MessageType::Gossip(payload),
            )
            .unwrap(),
        );
        let data_enc = encodex(cryptde, &cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let peer_actors = peer_actors_builder().build();
        let subject = RoutingService::new(
            cryptde,
            false,
            peer_actors.proxy_client,
            peer_actors.proxy_server,
            peer_actors.neighborhood,
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.accountant.report_routing_service_provided,
            100,
            200,
        );
        subject.route(inbound_client_data);
        TestLogHandler::new()
            .await_log_matching("Attempt to send invalid combination .* to .*", 1000);
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn converts_live_message_to_expired_for_proxy_client() {
        let cryptde = cryptde();
        let component = Recorder::new();
        let component_recording_arc = component.get_recording();
        let component_awaiter = component.get_awaiter();
        let route = route_to_proxy_client(&cryptde.public_key(), cryptde);
        let payload = make_request_payload(0, cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(cryptde, &cryptde.public_key(), &payload.clone().into())
                .unwrap(),
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
            data: data_enc.into(),
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_client");
            let peer_actors = peer_actors_builder().proxy_client(component).build();
            let subject = Hopper::new(HopperConfig {
                cryptde,
                is_bootstrap_node: false,
                per_routing_service: rate_pack_routing(103),
                per_routing_byte: rate_pack_routing_byte(103),
            });
            let subject_addr: Addr<Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(inbound_client_data).unwrap();

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage<ClientRequestPayload>>(0);
        let expected_ecp = lcp_a
            .to_expired(IpAddr::from_str("1.2.3.4").unwrap(), cryptde)
            .unwrap();
        assert_eq!(
            record.immediate_neighbor_ip,
            expected_ecp.immediate_neighbor_ip
        );
        assert_eq!(record.consuming_wallet, expected_ecp.consuming_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, payload);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn converts_live_message_to_expired_for_proxy_server() {
        let cryptde = cryptde();
        let component = Recorder::new();
        let component_recording_arc = component.get_recording();
        let component_awaiter = component.get_awaiter();
        let route = route_to_proxy_server(&cryptde.public_key(), cryptde);
        let payload = make_response_payload(0, cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(cryptde, &cryptde.public_key(), &payload.clone().into())
                .unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.3.2.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: data_enc.into(),
        };
        thread::spawn(move || {
            let system = System::new("converts_live_message_to_expired_for_proxy_server");
            let peer_actors = peer_actors_builder().proxy_server(component).build();
            let subject = Hopper::new(HopperConfig {
                cryptde,
                is_bootstrap_node: false,
                per_routing_service: rate_pack_routing(103),
                per_routing_byte: rate_pack_routing_byte(103),
            });
            let subject_addr: Addr<Hopper> = subject.start();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(inbound_client_data).unwrap();

            system.run();
        });
        component_awaiter.await_message_count(1);
        let component_recording = component_recording_arc.lock().unwrap();
        let record =
            component_recording.get_record::<ExpiredCoresPackage<ClientResponsePayload>>(0);
        let expected_ecp = lcp_a
            .to_expired(IpAddr::from_str("1.3.2.4").unwrap(), cryptde)
            .unwrap();
        assert_eq!(
            record.immediate_neighbor_ip,
            expected_ecp.immediate_neighbor_ip
        );
        assert_eq!(record.consuming_wallet, expected_ecp.consuming_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, payload);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
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
            data: data_enc.into(),
        };
        let system = System::new("refuses_data_for_proxy_client_if_is_bootstrap_node");
        let subject = Hopper::new(HopperConfig {
            cryptde,
            is_bootstrap_node: true,
            per_routing_service: rate_pack_routing(103),
            per_routing_byte: rate_pack_routing_byte(103),
        });
        let subject_addr: Addr<Hopper> = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Request for Bootstrap Node to route data to ProxyClient: rejected",
        );
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
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
            data: data_enc.into(),
        };
        let system = System::new("refuses_data_for_proxy_server_if_is_bootstrap_node");
        let subject = Hopper::new(HopperConfig {
            cryptde,
            is_bootstrap_node: true,
            per_routing_service: rate_pack_routing(103),
            per_routing_byte: rate_pack_routing_byte(103),
        });
        let subject_addr: Addr<Hopper> = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Request for Bootstrap Node to route data to ProxyServer: rejected",
        );
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn refuses_data_for_hopper_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::one_way(
            RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::Hopper,
            ),
            cryptde,
            Some(consuming_wallet),
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
            data: data_enc.into(),
        };
        let system = System::new("refuses_data_for_hopper_if_is_bootstrap_node");
        let subject = Hopper::new(HopperConfig {
            cryptde,
            is_bootstrap_node: true,
            per_routing_service: rate_pack_routing(103),
            per_routing_byte: rate_pack_routing_byte(103),
        });
        let subject_addr: Addr<Hopper> = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Request for Bootstrap Node to route data to Hopper: rejected",
        );
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn accepts_data_for_neighborhood_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let mut route = Route::one_way(
            RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::Neighborhood,
            ),
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        route.shift(cryptde).unwrap();
        let payload = GossipBuilder::new().build();
        let encrypted_payload =
            encodex::<MessageType>(cryptde, &cryptde.public_key(), &payload.clone().into())
                .unwrap();
        let lcp = LiveCoresPackage::new(route, encrypted_payload.clone());
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new("accepts_data_for_neighborhood_if_is_bootstrap_node");
        let subject = Hopper::new(HopperConfig {
            cryptde,
            is_bootstrap_node: true,
            per_routing_service: rate_pack_routing(103),
            per_routing_byte: rate_pack_routing_byte(103),
        });
        let subject_addr: Addr<Hopper> = subject.start();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data.clone()).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let message = neighborhood_recording.get_record::<ExpiredCoresPackage<Gossip>>(0);
        assert_eq!(message.clone().payload, payload);
        assert_eq!(
            message.clone().immediate_neighbor_ip,
            IpAddr::from_str("1.2.3.4").unwrap()
        );
        TestLogHandler::new().exists_no_log_containing(
            "ERROR: RoutingService: Request for Bootstrap Node to route data to Neighborhood: rejected",
        );
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn rejects_data_for_non_neighborhood_component_if_is_bootstrap_node() {
        init_test_logging();
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let mut route = Route::one_way(
            RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::ProxyClient,
            ),
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        route.shift(cryptde).unwrap();
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
            data: data_enc.into(),
        };
        let system =
            System::new("rejects_data_for_non_neighborhood_component_if_is_bootstrap_node");
        let subject = Hopper::new(HopperConfig {
            cryptde,
            is_bootstrap_node: true,
            per_routing_service: rate_pack_routing(103),
            per_routing_byte: rate_pack_routing_byte(103),
        });
        let subject_addr: Addr<Hopper> = subject.start();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(inbound_client_data.clone()).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(proxy_client_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Request for Bootstrap Node to route data to ProxyClient: rejected",
        );
    }

    #[test] // TODO: Rewrite test so that subject is RoutingService rather than Hopper
    fn passes_on_inbound_client_data_not_meant_for_this_node() {
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let (dispatcher, dispatcher_awaiter, dispatcher_recording_arc) = make_recorder();
        let (accountant, accountant_awaiter, accountant_recording_arc) = make_recorder();
        let next_key = PublicKey::new(&[65, 65, 65]);
        let route = Route::one_way(
            RouteSegment::new(
                vec![&cryptde.public_key(), &next_key],
                Component::Neighborhood,
            ),
            cryptde,
            Some(consuming_wallet.clone()),
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
            data: data_enc.into(),
        };
        thread::spawn(move || {
            let system = System::new("passes_on_inbound_client_data_not_meant_for_this_node");
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .accountant(accountant)
                .build();
            let subject = Hopper::new(HopperConfig {
                cryptde,
                is_bootstrap_node: false,
                per_routing_service: rate_pack_routing(103),
                per_routing_byte: rate_pack_routing_byte(103),
            });
            let subject_addr: Addr<Hopper> = subject.start();
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
                data: expected_lcp_enc.into(),
            }
        );
        accountant_awaiter.await_message_count(1);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ReportRoutingServiceProvidedMessage>(0);
        assert_eq!(
            *message,
            ReportRoutingServiceProvidedMessage {
                consuming_wallet,
                payload_size: lcp.payload.len(),
                service_rate: rate_pack_routing(103),
                byte_rate: rate_pack_routing_byte(103),
            }
        )
    }

    #[test]
    fn route_logs_and_ignores_cores_package_that_demands_routing_without_consuming_wallet() {
        init_test_logging();
        let cryptde = cryptde();
        let origin_key = PublicKey::new(&[1, 2]);
        let origin_cryptde = CryptDENull::from(&origin_key);
        let destination_key = PublicKey::new(&[3, 4]);
        let payload = MessageType::DnsResolveFailed;
        let route = Route::one_way(
            RouteSegment::new(
                vec![&origin_key, &cryptde.public_key(), &destination_key],
                Component::ProxyClient,
            ),
            &origin_cryptde,
            None,
        )
        .unwrap();
        let icp =
            IncipientCoresPackage::new(&origin_cryptde, route, payload, &destination_key).unwrap();
        let (lcp, _) = LiveCoresPackage::from_incipient(icp, &origin_cryptde).unwrap();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new(
            "route_logs_and_ignores_cores_package_that_demands_routing_without_consuming_wallet",
        );
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .build();
        let subject = RoutingService::new(
            cryptde,
            false,
            peer_actors.proxy_client,
            peer_actors.proxy_server,
            peer_actors.neighborhood,
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.accountant.report_routing_service_provided,
            100,
            200,
        );

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_matching(
            "ERROR: RoutingService: Refusing to route CORES package with \\d+-byte payload without consuming wallet",
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_inbound_client_data_that_doesnt_deserialize_properly() {
        init_test_logging();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: vec![],
        };
        let system = System::new("consume_logs_error_when_given_bad_input_data");
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .build();
        let subject = RoutingService::new(
            cryptde(),
            false,
            peer_actors.proxy_client,
            peer_actors.proxy_server,
            peer_actors.neighborhood,
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.accountant.report_routing_service_provided,
            100,
            200,
        );

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Couldn't decrypt CORES package from 0-byte buffer: EmptyData",
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_invalid_live_cores_package() {
        init_test_logging();
        let cryptde = cryptde();
        let lcp = LiveCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]));
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = cryptde.encode(&cryptde.public_key(), &data_ser).unwrap();
        let inbound_client_data = InboundClientData {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new("consume_logs_error_when_given_bad_input_data");
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .build();
        let subject = RoutingService::new(
            cryptde,
            false,
            peer_actors.proxy_client,
            peer_actors.proxy_server,
            peer_actors.neighborhood,
            peer_actors.dispatcher.from_dispatcher_client,
            peer_actors.accountant.report_routing_service_provided,
            100,
            200,
        );

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Invalid 36-byte CORES package: EmptyRoute",
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
    }
}
