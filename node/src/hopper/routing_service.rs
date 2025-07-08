// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::live_cores_package::LiveCoresPackage;
use crate::blockchain::payer::Payer;
use crate::bootstrapper::CryptDEPair;
use crate::neighborhood::gossip::Gossip_0v1;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::cryptde::{decodex, encodex, CryptData, CryptdecError};
use crate::sub_lib::dispatcher::{Component, Endpoint, InboundClientData};
use crate::sub_lib::hop::LiveHop;
use crate::sub_lib::hopper::{ExpiredCoresPackage, HopperSubs, MessageType};
use crate::sub_lib::neighborhood::{GossipFailure_0v1, NeighborhoodSubs};
use crate::sub_lib::proxy_client::{
    ClientResponsePayload_0v1, DnsResolveFailure_0v1, ProxyClientSubs,
};
use crate::sub_lib::proxy_server::{ClientRequestPayload_0v1, ProxyServerSubs};
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use actix::Recipient;
use masq_lib::logger::Logger;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::time::SystemTime;

pub struct RoutingServiceSubs {
    pub proxy_client_subs_opt: Option<ProxyClientSubs>,
    pub proxy_server_subs: ProxyServerSubs,
    pub neighborhood_subs: NeighborhoodSubs,
    pub hopper_subs: HopperSubs,
    pub to_dispatcher: Recipient<TransmitDataMsg>,
    pub to_accountant_routing: Recipient<ReportRoutingServiceProvidedMessage>,
}

pub struct RoutingService {
    cryptdes: CryptDEPair,
    routing_service_subs: RoutingServiceSubs,
    per_routing_service: u64,
    per_routing_byte: u64,
    logger: Logger,
    is_decentralized: bool,
}

impl RoutingService {
    pub fn new(
        cryptdes: CryptDEPair,
        routing_service_subs: RoutingServiceSubs,
        per_routing_service: u64,
        per_routing_byte: u64,
        is_decentralized: bool,
    ) -> RoutingService {
        RoutingService {
            cryptdes,
            routing_service_subs,
            per_routing_service,
            per_routing_byte,
            logger: Logger::new("RoutingService"),
            is_decentralized,
        }
    }

    pub fn route(&self, ibcd: InboundClientData) {
        let data_size = ibcd.data.len();
        debug!(
            self.logger,
            "Instructed to route {} bytes of InboundClientData ({}) from Dispatcher",
            data_size,
            ibcd.client_addr
        );
        let peer_addr = ibcd.client_addr;
        let last_data = ibcd.last_data;
        let ibcd_but_data = ibcd.clone_but_data();

        let live_package = match decodex::<LiveCoresPackage>(
            self.cryptdes.main,
            &CryptData::new(&ibcd.data[..]),
        ) {
            Ok(lcp) => lcp,
            Err(e) => {
                error!(
                    self.logger,
                    "Couldn't decode CORES package in {}-byte buffer from {}: {:?}",
                    ibcd.data.len(),
                    ibcd.client_addr,
                    e
                );
                return;
            }
        };

        let next_hop = match live_package.route.next_hop(self.cryptdes.main.borrow()) {
            Ok(hop) => hop,
            Err(e) => {
                error!(
                    self.logger,
                    "Invalid {}-byte CORES package: {:?}", data_size, e
                );
                return;
            }
        };

        self.route_data(peer_addr, next_hop, live_package, last_data, &ibcd_but_data);
    }

    fn route_data(
        &self,
        sender_addr: SocketAddr,
        next_hop: LiveHop,
        live_package: LiveCoresPackage,
        last_data: bool,
        ibcd_but_data: &InboundClientData,
    ) {
        if (next_hop.component == Component::Hopper) && (!self.is_destined_for_here(&next_hop)) {
            debug!(
                self.logger,
                "Routing LiveCoresPackage with {}-byte payload to {}",
                live_package.payload.len(),
                next_hop.public_key
            );
            self.route_data_externally(live_package, next_hop.payer, last_data);
        } else {
            debug!(
                self.logger,
                "Transferring LiveCoresPackage with {}-byte payload to {:?}",
                live_package.payload.len(),
                next_hop.component
            );
            self.route_data_internally(&next_hop, sender_addr, live_package, ibcd_but_data)
        }
    }

    fn is_destined_for_here(&self, next_hop: &LiveHop) -> bool {
        &next_hop.public_key == self.cryptdes.main.public_key()
    }

    fn route_data_internally(
        &self,
        next_hop: &LiveHop,
        immediate_neighbor_addr: SocketAddr,
        live_package: LiveCoresPackage,
        ibcd_but_data: &InboundClientData,
    ) {
        let payload_size = live_package.payload.len();
        if next_hop.component == Component::Hopper {
            self.route_data_around_again(live_package, ibcd_but_data)
        } else {
            match &next_hop.payer {
                None => (),
                Some(payer) => {
                    if payer.is_delinquent() {
                        warning!(self.logger,
                        "Node with consuming wallet {} is delinquent; electing not to route {}-byte payload to {:?}",
                        payer.wallet,
                        payload_size,
                        next_hop.component,
                    );
                        return;
                    }
                }
            }
            self.route_data_to_peripheral_component(
                next_hop.component,
                immediate_neighbor_addr,
                live_package,
                next_hop.payer_owns_secret_key(&self.cryptdes.main.digest()),
            )
        }
    }

    fn route_data_around_again(
        &self,
        live_package: LiveCoresPackage,
        ibcd_but_data: &InboundClientData,
    ) {
        let (_, next_lcp) = match live_package.into_next_live(self.cryptdes.main) {
            Ok(x) => x,
            Err(e) => {
                error!(self.logger, "bad zero-hop route: {:?}", e);
                return;
            }
        };
        let payload = encodex(
            self.cryptdes.main,
            self.cryptdes.main.public_key(),
            &next_lcp,
        )
        .expect("Encryption of LiveCoresPackage failed");
        let inbound_client_data = InboundClientData {
            timestamp: ibcd_but_data.timestamp,
            client_addr: ibcd_but_data.client_addr,
            reception_port: ibcd_but_data.reception_port,
            last_data: ibcd_but_data.last_data,
            is_clandestine: ibcd_but_data.is_clandestine,
            sequence_number: ibcd_but_data.sequence_number,
            data: payload.into(),
        };
        self.routing_service_subs
            .hopper_subs
            .from_dispatcher
            .try_send(inbound_client_data)
            .expect("Hopper is dead");
    }

    fn route_data_to_peripheral_component(
        &self,
        component: Component,
        immediate_neighbor_addr: SocketAddr,
        live_package: LiveCoresPackage,
        payer_owns_secret_key: bool,
    ) {
        let expired_package =
            match self.extract_expired_package(immediate_neighbor_addr, live_package, component) {
                None => return,
                Some(p) => p,
            };
        trace!(
            self.logger,
            "Forwarding ExpiredCoresPackage to {:?}",
            component
        );
        self.route_expired_package(component, expired_package, payer_owns_secret_key)
    }

    fn extract_expired_package(
        &self,
        immediate_neighbor_addr: SocketAddr,
        live_package: LiveCoresPackage,
        component: Component,
    ) -> Option<ExpiredCoresPackage<MessageType>> {
        let data_len = live_package.payload.len();
        let (payload_cryptde, cryptde_name) = match component {
            Component::ProxyServer => (self.cryptdes.alias, "alias"),
            _ => (self.cryptdes.main, "main"),
        };
        let expired_package = match live_package.to_expired(
            immediate_neighbor_addr,
            self.cryptdes.main,
            payload_cryptde,
        ) {
            Ok(pkg) => pkg,
            Err(e) => {
                error!(
                    self.logger,
                    "Couldn't expire CORES package with {}-byte payload to {:?} using {} key: {:?}",
                    data_len,
                    component,
                    cryptde_name,
                    e
                );
                return None;
            }
        };
        Some(expired_package)
    }

    fn route_expired_package(
        &self,
        component: Component,
        expired_package: ExpiredCoresPackage<MessageType>,
        payer_owns_secret_key: bool,
    ) {
        let immediate_neighbor = expired_package.immediate_neighbor;
        match (component, expired_package.payload) {
            (Component::ProxyClient, MessageType::ClientRequest(vd)) => {
                if !self.is_decentralized || payer_owns_secret_key {
                    let proxy_client_subs = match &self.routing_service_subs.proxy_client_subs_opt {
                        Some(pcs) => pcs,
                        None => {
                            warning!(self.logger, "Received CORES package from {:?} for Proxy Client, but Proxy Client isn't running", immediate_neighbor);
                            return;
                        }
                    };
                    let client_request = match ClientRequestPayload_0v1::try_from(vd) {
                        Ok(crp) => crp,
                        Err(e) => {
                            error!(
                                self.logger,
                                "Received unmigratable ClientRequestPayload: {:?}", e
                            );
                            return;
                        }
                    };
                    proxy_client_subs
                        .from_hopper
                        .try_send(ExpiredCoresPackage::new(
                            expired_package.immediate_neighbor,
                            expired_package.paying_wallet,
                            expired_package.remaining_route,
                            client_request,
                            expired_package.payload_len,
                        ))
                        .expect("ProxyClient is dead")
                } else {
                    let payload_len = &expired_package.payload_len;
                    let address = match &expired_package.paying_wallet {
                        Some(wallet) => format!("{} ", wallet),
                        None => String::from(""),
                    };
                    warning!(
                        self.logger,
                            "Refusing to route Expired CORES package with {}-byte payload without proof of {}paying wallet ownership.",
                        payload_len, address
                    );
                }
            }
            (Component::ProxyServer, MessageType::ClientResponse(vd)) => {
                let client_response = match ClientResponsePayload_0v1::try_from(vd) {
                    Ok(crp) => crp,
                    Err(e) => {
                        error!(
                            self.logger,
                            "Received unmigratable ClientResponsePayload: {:?}", e
                        );
                        return;
                    }
                };
                self.routing_service_subs
                    .proxy_server_subs
                    .from_hopper
                    .try_send(ExpiredCoresPackage::new(
                        expired_package.immediate_neighbor,
                        expired_package.paying_wallet,
                        expired_package.remaining_route,
                        client_response,
                        expired_package.payload_len,
                    ))
                    .expect("ProxyServer is dead")
            }
            (Component::ProxyServer, MessageType::DnsResolveFailed(vd)) => {
                let failure = match DnsResolveFailure_0v1::try_from(vd) {
                    Ok(f) => f,
                    Err(e) => {
                        error!(
                            self.logger,
                            "Received unmigratable DnsResolveFailed: {:?}", e
                        );
                        return;
                    }
                };
                self.routing_service_subs
                    .proxy_server_subs
                    .dns_failure_from_hopper
                    .try_send(ExpiredCoresPackage::new(
                        expired_package.immediate_neighbor,
                        expired_package.paying_wallet,
                        expired_package.remaining_route,
                        failure,
                        expired_package.payload_len,
                    ))
                    .expect("ProxyServer is dead")
            }
            (Component::Neighborhood, MessageType::Gossip(vd)) => {
                let gossip = match Gossip_0v1::try_from(vd) {
                    Ok(g) => g,
                    Err(e) => {
                        error!(self.logger, "Received unmigratable Gossip: {:?}", e);
                        return;
                    }
                };
                self.routing_service_subs
                    .neighborhood_subs
                    .from_hopper
                    .try_send(ExpiredCoresPackage::new(
                        expired_package.immediate_neighbor,
                        expired_package.paying_wallet,
                        expired_package.remaining_route,
                        gossip,
                        expired_package.payload_len,
                    ))
                    .expect("Neighborhood is dead")
            }
            (Component::Neighborhood, MessageType::GossipFailure(vd)) => {
                let failure = match GossipFailure_0v1::try_from(vd) {
                    Ok(f) => f,
                    Err(e) => {
                        error!(self.logger, "Received unmigratable GossipFailure: {:?}", e);
                        return;
                    }
                };
                self.routing_service_subs
                    .neighborhood_subs
                    .gossip_failure
                    .try_send(ExpiredCoresPackage::new(
                        expired_package.immediate_neighbor,
                        expired_package.paying_wallet,
                        expired_package.remaining_route,
                        failure,
                        expired_package.payload_len,
                    ))
                    .expect("Neighborhood is dead")
            }
            (destination, payload) => error!(
                self.logger,
                "Attempt to send invalid combination {:?} to {:?}", payload, destination
            ),
        };
    }

    fn route_data_externally(
        &self,
        live_package: LiveCoresPackage,
        payer: Option<Payer>,
        last_data: bool,
    ) {
        let payload_size = live_package.payload.len();
        match payer {
            Some(payer) => {
                if !payer.owns_secret_key(&self.cryptdes.main.digest()) {
                    warning!(self.logger,
                        "Refusing to route Live CORES package with {}-byte payload without proof of {} paying wallet ownership.",
                        payload_size, payer.wallet
                    );
                    return;
                }
                if payer.is_delinquent() {
                    warning!(self.logger,
                        "Node with consuming wallet {} is delinquent; electing not to route {}-byte payload further",
                        payer.wallet,
                        payload_size,
                    );
                    return;
                }
                match self.routing_service_subs.to_accountant_routing.try_send(
                    ReportRoutingServiceProvidedMessage {
                        timestamp: SystemTime::now(),
                        paying_wallet: payer.wallet,
                        payload_size,
                        service_rate: self.per_routing_service,
                        byte_rate: self.per_routing_byte,
                    },
                ) {
                    Ok(_) => (),
                    Err(e) => {
                        fatal!(self.logger, "Accountant is dead: {:?}", e);
                    }
                }
            }
            None => {
                warning!(
                    self.logger,
                    "Refusing to route Live CORES package with {}-byte payload without paying wallet",
                    payload_size
                );
                return;
            }
        }

        let transmit_msg = match self.to_transmit_data_msg(live_package, last_data) {
            Ok(m) => m,
            Err(e) => {
                error!(self.logger, "{:?}", e);
                return;
            }
        };

        debug!(
            self.logger,
            "Relaying {}-byte LiveCoresPackage to Dispatcher inside a TransmitDataMsg",
            transmit_msg.data.len()
        );
        self.routing_service_subs
            .to_dispatcher
            .try_send(transmit_msg)
            .expect("Dispatcher is dead");
    }

    fn to_transmit_data_msg(
        &self,
        live_package: LiveCoresPackage,
        last_data: bool,
    ) -> Result<TransmitDataMsg, CryptdecError> {
        let (next_hop, next_live_package) =
            match live_package.into_next_live(self.cryptdes.main.borrow()) {
                Err(e) => {
                    let msg = format!(
                        "Couldn't get next hop and outgoing LCP from incoming LCP: {:?}",
                        e
                    );
                    error!(self.logger, "{}", &msg);
                    return Err(CryptdecError::OtherError(msg));
                }
                Ok(p) => p,
            };
        let next_live_package_enc =
            match encodex(self.cryptdes.main, &next_hop.public_key, &next_live_package) {
                Ok(nlpe) => nlpe,
                Err(e) => {
                    let msg = format!("Couldn't serialize or encrypt outgoing LCP: {:?}", e);
                    error!(self.logger, "{}", &msg);
                    return Err(CryptdecError::OtherError(msg));
                }
            };
        Ok(TransmitDataMsg {
            endpoint: Endpoint::Key(next_hop.public_key),
            last_data,
            data: next_live_package_enc.into(),
            sequence_number: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::banned_dao::BAN_CACHE;
    use crate::bootstrapper::Bootstrapper;
    use crate::neighborhood::gossip::{GossipBuilder, Gossip_0v1};
    use crate::node_test_utils::check_timestamp;
    use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
    use crate::sub_lib::cryptde::{encodex, CryptDE, PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::cryptde_real::CryptDEReal;
    use crate::sub_lib::hopper::{IncipientCoresPackage, MessageType, MessageType::ClientRequest};
    use crate::sub_lib::neighborhood::GossipFailure_0v1;
    use crate::sub_lib::peer_actors::PeerActors;
    use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
    use crate::sub_lib::proxy_server::{ClientRequestPayload_0v1, ProxyProtocol};
    use crate::sub_lib::route::{Route, RouteSegment};
    use crate::sub_lib::sequence_buffer::SequencedPacket;
    use crate::sub_lib::stream_key::StreamKey;
    use crate::sub_lib::versioned_data::VersionedData;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};
    use crate::test_utils::unshared_test_utils::{make_request_payload, make_response_payload};
    use crate::test_utils::{
        alias_cryptde, main_cryptde, make_cryptde_pair, make_meaningless_message_type,
        make_paying_wallet, rate_pack_routing, rate_pack_routing_byte, route_from_proxy_client,
        route_to_proxy_client, route_to_proxy_server,
    };
    use actix::System;
    use masq_lib::test_utils::environment_guard::EnvironmentGuard;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::SystemTime;

    #[test]
    fn dns_resolution_failures_are_reported_to_the_proxy_server() {
        let cryptdes = make_cryptde_pair();
        let route = route_to_proxy_server(&cryptdes.main.public_key(), cryptdes.main);
        let stream_key = StreamKey::make_meaningless_stream_key();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let lcp = LiveCoresPackage::new(
            route,
            encodex(
                cryptdes.alias,
                &cryptdes.alias.public_key(),
                &MessageType::DnsResolveFailed(VersionedData::new(
                    &crate::sub_lib::migrations::dns_resolve_failure::MIGRATIONS,
                    &dns_resolve_failure.clone(),
                )),
            )
            .unwrap(),
        );
        let data_enc = encodex(cryptdes.main, &cryptdes.main.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let (proxy_server, _, proxy_server_recording) = make_recorder();

        let system = System::new("dns_resolution_failures_are_reported_to_the_proxy_server");
        let peer_actors = peer_actors_builder().proxy_server(proxy_server).build();
        let subject = RoutingService::new(
            cryptdes,
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();

        let recordings = proxy_server_recording.lock().unwrap();
        let message = recordings.get_record::<ExpiredCoresPackage<DnsResolveFailure_0v1>>(0);
        assert_eq!(dns_resolve_failure, message.payload);
    }

    #[test]
    fn logs_and_ignores_message_that_cannot_be_deserialized() {
        init_test_logging();
        let test_name = "logs_and_ignores_message_that_cannot_be_deserialized";
        let cryptdes = make_cryptde_pair();
        let route = route_from_proxy_client(&cryptdes.main.public_key(), cryptdes.main);
        let lcp = LiveCoresPackage::new(
            route,
            encodex(cryptdes.main, &cryptdes.main.public_key(), &[42u8]).unwrap(),
        );
        let data_enc = encodex(cryptdes.main, &cryptdes.main.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let peer_actors = peer_actors_builder().build();
        let mut subject = RoutingService::new(
            cryptdes,
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Couldn't expire CORES package with 35-byte payload to ProxyClient using main key"),
        );
    }

    #[test]
    fn logs_and_ignores_message_that_cannot_be_decrypted() {
        init_test_logging();
        let test_name = "logs_and_ignores_message_that_cannot_be_decrypted";
        let (main_cryptde, alias_cryptde) = {
            //initialization to real CryptDEs
            let pair = Bootstrapper::pub_initialize_cryptdes_for_testing(&None, &None);
            (pair.main, pair.alias)
        };
        let rogue_cryptde = CryptDEReal::new(TEST_DEFAULT_CHAIN);
        let route = route_from_proxy_client(main_cryptde.public_key(), main_cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex(&rogue_cryptde, rogue_cryptde.public_key(), &[42u8]).unwrap(),
        );
        let data_enc = encodex(main_cryptde, main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let peer_actors = peer_actors_builder().build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Couldn't expire CORES package with 51-byte payload to ProxyClient using main key: DecryptionError(OpeningFailed)")
        );
    }

    #[test]
    fn logs_and_ignores_message_that_had_invalid_destination() {
        init_test_logging();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let route = route_from_proxy_client(&main_cryptde.public_key(), main_cryptde);
        let payload = GossipBuilder::empty();
        let lcp = LiveCoresPackage::new(
            route,
            encodex(
                main_cryptde,
                &main_cryptde.public_key(),
                &MessageType::Gossip(payload.into()),
            )
            .unwrap(),
        );
        let data_enc = encodex(main_cryptde, &main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: false,
            is_clandestine: false,
            data: data_enc.into(),
        };
        let peer_actors = peer_actors_builder().build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.route(inbound_client_data);
        TestLogHandler::new().exists_log_matching("Attempt to send invalid combination .* to .*");
    }

    #[test]
    fn converts_live_message_to_expired_for_existing_proxy_client() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let (component, _, component_recording_arc) = make_recorder();
        let route = route_to_proxy_client(&main_cryptde.public_key(), main_cryptde);
        let payload = make_request_payload(0, main_cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(
                main_cryptde,
                &main_cryptde.public_key(),
                &payload.clone().into(),
            )
            .unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: true,
            is_clandestine: false,
            data: data_enc.into(),
        };

        let system = System::new("converts_live_message_to_expired_for_proxy_client");
        let peer_actors = peer_actors_builder().proxy_client(component).build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            0,
            0,
            false,
        );

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let component_recording = component_recording_arc.lock().unwrap();
        let record =
            component_recording.get_record::<ExpiredCoresPackage<ClientRequestPayload_0v1>>(0);
        let expected_ecp = lcp_a
            .to_expired(
                SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                main_cryptde,
                main_cryptde,
            )
            .unwrap();
        assert_eq!(record.immediate_neighbor, expected_ecp.immediate_neighbor);
        assert_eq!(record.paying_wallet, expected_ecp.paying_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, payload);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test]
    fn complains_about_live_message_for_nonexistent_proxy_client() {
        let _eg = EnvironmentGuard::new();
        init_test_logging();
        BAN_CACHE.clear();
        let test_name = "complains_about_live_message_for_nonexistent_proxy_client";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let route = route_to_proxy_client(&main_cryptde.public_key(), main_cryptde);
        let payload = make_request_payload(0, main_cryptde);
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(
                main_cryptde,
                &main_cryptde.public_key(),
                &payload.clone().into(),
            )
            .unwrap(),
        );
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            sequence_number: None,
            last_data: true,
            is_clandestine: false,
            data: data_enc.into(),
        };

        let system = System::new("converts_live_message_to_expired_for_proxy_client");
        let peer_actors = peer_actors_builder().build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: None,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            0,
            0,
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let tlh = TestLogHandler::new();
        tlh.exists_no_log_containing("Couldn't decode CORES package in 8-byte buffer");
        tlh.exists_log_containing(&format!("WARN: {test_name}: Received CORES package from 1.2.3.4:5678 for Proxy Client, but Proxy Client isn't running"));
    }

    #[test]
    fn converts_live_message_to_expired_for_proxy_server() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let route = route_to_proxy_server(&main_cryptde.public_key(), main_cryptde);
        let payload = make_response_payload(0);
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(
                alias_cryptde,
                &alias_cryptde.public_key(),
                &payload.clone().into(),
            )
            .unwrap(),
        );
        let lcp_a = lcp.clone();
        let lcp_enc = encodex(main_cryptde, main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.3.2.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: lcp_enc.into(),
        };

        let system = System::new("converts_live_message_to_expired_for_proxy_server");
        let peer_actors = peer_actors_builder().proxy_server(proxy_server).build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            0,
            0,
            false,
        );

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        let record =
            proxy_server_recording.get_record::<ExpiredCoresPackage<ClientResponsePayload_0v1>>(0);
        let expected_ecp = lcp_a
            .to_expired(
                SocketAddr::from_str("1.3.2.4:5678").unwrap(),
                main_cryptde,
                alias_cryptde,
            )
            .unwrap();
        assert_eq!(record.immediate_neighbor, expected_ecp.immediate_neighbor);
        assert_eq!(record.paying_wallet, expected_ecp.paying_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, payload);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test]
    fn converts_live_gossip_message_to_expired_for_neighborhood() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let (component, _, component_recording_arc) = make_recorder();
        let mut route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &main_cryptde.public_key()],
                Component::Neighborhood,
            ),
            main_cryptde,
            None,
            None,
        )
        .unwrap();
        route.shift(main_cryptde).unwrap();
        let payload = GossipBuilder::empty();
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(
                main_cryptde,
                &main_cryptde.public_key(),
                &payload.clone().into(),
            )
            .unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_enc = encodex(main_cryptde, &main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.3.2.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };

        let system = System::new("converts_live_gossip_message_to_expired_for_neighborhood");
        let peer_actors = peer_actors_builder().neighborhood(component).build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            0,
            0,
            false,
        );

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage<Gossip_0v1>>(0);
        let expected_ecp = lcp_a
            .to_expired(
                SocketAddr::from_str("1.3.2.4:5678").unwrap(),
                main_cryptde,
                main_cryptde,
            )
            .unwrap();
        assert_eq!(record.immediate_neighbor, expected_ecp.immediate_neighbor);
        assert_eq!(record.paying_wallet, expected_ecp.paying_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, payload);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test]
    fn converts_live_gossip_failure_message_to_expired_for_neighborhood() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let cryptde = main_cryptde();
        let (component, _, component_recording_arc) = make_recorder();
        let mut route = Route::one_way(
            RouteSegment::new(
                vec![&cryptde.public_key(), &cryptde.public_key()],
                Component::Neighborhood,
            ),
            cryptde,
            None,
            None,
        )
        .unwrap();
        route.shift(cryptde).unwrap();
        let payload = MessageType::GossipFailure(VersionedData::new(
            &crate::sub_lib::migrations::gossip_failure::MIGRATIONS,
            &GossipFailure_0v1::NoNeighbors,
        ));
        let lcp = LiveCoresPackage::new(
            route,
            encodex::<MessageType>(cryptde, &cryptde.public_key(), &payload).unwrap(),
        );
        let data_enc = encodex(cryptde, &cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.3.2.4:5678").unwrap(),
            reception_port: None,
            last_data: false,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };

        let system =
            System::new("converts_live_gossip_failure_message_to_expired_for_neighborhood");
        let peer_actors = peer_actors_builder().neighborhood(component).build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: cryptde,
                alias: alias_cryptde(),
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            0,
            0,
            true,
        );

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let component_recording = component_recording_arc.lock().unwrap();
        let record = component_recording.get_record::<ExpiredCoresPackage<GossipFailure_0v1>>(0);
        let expected_ecp = lcp
            .to_expired(
                SocketAddr::from_str("1.3.2.4:5678").unwrap(),
                cryptde,
                cryptde,
            )
            .unwrap();
        assert_eq!(record.immediate_neighbor, expected_ecp.immediate_neighbor);
        assert_eq!(record.paying_wallet, expected_ecp.paying_wallet);
        assert_eq!(record.remaining_route, expected_ecp.remaining_route);
        assert_eq!(record.payload, GossipFailure_0v1::NoNeighbors);
        assert_eq!(record.payload_len, expected_ecp.payload_len);
    }

    #[test]
    fn passes_on_inbound_client_data_not_meant_for_this_node() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let address_paying_wallet = Wallet::from(paying_wallet.address());
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let next_key = PublicKey::new(&[65, 65, 65]);
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &next_key],
                Component::Neighborhood,
            ),
            main_cryptde,
            Some(paying_wallet.clone()),
            Some(contract_address.clone()),
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(route, main_cryptde.encode(&next_key, &payload).unwrap());
        let lcp_a = lcp.clone();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };

        let system = System::new("passes_on_inbound_client_data_not_meant_for_this_node");
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            rate_pack_routing(103),
            rate_pack_routing_byte(103),
            false,
        );
        let before = SystemTime::now();

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let expected_lcp = lcp_a.into_next_live(main_cryptde).unwrap().1;
        let expected_lcp_ser = PlainData::new(&serde_cbor::ser::to_vec(&expected_lcp).unwrap());
        let expected_lcp_enc = main_cryptde.encode(&next_key, &expected_lcp_ser).unwrap();
        assert_eq!(
            *record,
            TransmitDataMsg {
                endpoint: Endpoint::Key(next_key.clone()),
                last_data: true,
                sequence_number: None,
                data: expected_lcp_enc.into(),
            }
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<ReportRoutingServiceProvidedMessage>(0);
        check_timestamp(before, message.timestamp, after);
        assert!(message.paying_wallet.congruent(&paying_wallet));
        assert_eq!(
            *message,
            ReportRoutingServiceProvidedMessage {
                timestamp: message.timestamp,
                paying_wallet: address_paying_wallet,
                payload_size: lcp.payload.len(),
                service_rate: rate_pack_routing(103),
                byte_rate: rate_pack_routing_byte(103),
            }
        )
    }

    #[test]
    fn reprocesses_inbound_client_data_meant_for_this_node_and_destined_for_hopper() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &main_cryptde.public_key()],
                Component::Neighborhood,
            ),
            main_cryptde,
            Some(paying_wallet.clone()),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            main_cryptde
                .encode(&main_cryptde.public_key(), &payload)
                .unwrap(),
        );
        let lcp_a = lcp.clone();
        let data_enc = encodex(main_cryptde, &main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };

        let system = System::new(
            "reprocesses_inbound_client_data_meant_for_this_node_and_destined_for_hopper",
        );
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            rate_pack_routing(103),
            rate_pack_routing_byte(103),
            false,
        );
        let before = SystemTime::now();

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let record = hopper_recording.get_record::<InboundClientData>(0);
        check_timestamp(before, record.timestamp, after);
        let expected_lcp = lcp_a.into_next_live(main_cryptde).unwrap().1;
        let expected_lcp_enc =
            encodex(main_cryptde, &main_cryptde.public_key(), &expected_lcp).unwrap();
        assert_eq!(
            *record,
            InboundClientData {
                timestamp: record.timestamp,
                client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                reception_port: None,
                last_data: true,
                is_clandestine: true,
                sequence_number: None,
                data: expected_lcp_enc.into()
            }
        );
    }

    #[test]
    fn route_logs_and_ignores_cores_package_that_demands_routing_without_paying_wallet() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        init_test_logging();
        let test_name =
            "route_logs_and_ignores_cores_package_that_demands_routing_without_paying_wallet";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let origin_key = PublicKey::new(&[1, 2]);
        let origin_cryptde = CryptDENull::from(&origin_key, TEST_DEFAULT_CHAIN);
        let destination_key = PublicKey::new(&[3, 4]);
        let payload = make_meaningless_message_type();
        let route = Route::one_way(
            RouteSegment::new(
                vec![&origin_key, &main_cryptde.public_key(), &destination_key],
                Component::ProxyClient,
            ),
            &origin_cryptde,
            None,
            None,
        )
        .unwrap();
        let icp =
            IncipientCoresPackage::new(&origin_cryptde, route, payload, &destination_key).unwrap();
        let (lcp, _) = LiveCoresPackage::from_incipient(icp, &origin_cryptde).unwrap();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new(test_name);
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            true,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_matching(
            &format!("WARN: {test_name}: Refusing to route Live CORES package with \\d+-byte payload without paying wallet"),
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_cores_package_that_demands_proxy_client_routing_with_paying_wallet_that_cant_pay(
    ) {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        init_test_logging();
        let test_name = "route_logs_and_ignores_cores_package_that_demands_proxy_client_routing_with_paying_wallet_that_cant_pay";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let public_key = main_cryptde.public_key();
        let payload = ClientRequest(VersionedData::new(
            &crate::sub_lib::migrations::client_response_payload::MIGRATIONS,
            &make_request_payload(0, main_cryptde),
        ));
        let paying_wallet = Some(make_paying_wallet(b"paying wallet"));
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let live_hops: Vec<LiveHop> = vec![
            LiveHop::new(
                &public_key,
                paying_wallet
                    .clone()
                    .map(|w| w.as_payer(&public_key, &contract_address)),
                Component::Hopper,
            ),
            LiveHop::new(
                &public_key,
                paying_wallet
                    .clone()
                    .map(|w| w.as_payer(&PublicKey::new(b"can't pay"), &contract_address)),
                Component::ProxyClient,
            ),
        ];
        let hops = live_hops
            .iter()
            .map(|hop| match hop.encode(&hop.public_key, main_cryptde) {
                Ok(cryptdata) => cryptdata,
                Err(e) => panic!("Couldn't encode hop: {:?}", e),
            })
            .collect();
        let route = Route { hops };
        let icp = IncipientCoresPackage::new(main_cryptde, route, payload, public_key).unwrap();
        let (lcp, _) = LiveCoresPackage::from_incipient(icp, main_cryptde).unwrap();
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new(test_name);
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            true,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_matching(
            &format!("WARN: {test_name}: Refusing to route Expired CORES package with \\d+-byte payload without proof of 0x0a26dc9ebb2124baf1efe9d460f1ce59cd7944bd paying wallet ownership."),
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_cores_package_that_demands_hopper_routing_with_paying_wallet_that_cant_pay(
    ) {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        init_test_logging();
        let test_name = "route_logs_and_ignores_cores_package_that_demands_hopper_routing_with_paying_wallet_that_cant_pay";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let current_key = main_cryptde.public_key();
        let origin_key = PublicKey::new(&[1, 2]);
        let destination_key = PublicKey::new(&[5, 6]);
        let destination_cryptde = CryptDENull::from(&destination_key, TEST_DEFAULT_CHAIN);

        let payload = ClientRequest(VersionedData::new(
            &crate::sub_lib::migrations::client_response_payload::MIGRATIONS,
            &make_request_payload(0, &destination_cryptde),
        ));
        let paying_wallet = Some(make_paying_wallet(b"paying wallet"));
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let live_hops: Vec<LiveHop> = vec![
            LiveHop::new(
                &current_key,
                paying_wallet
                    .clone()
                    .map(|w| w.as_payer(&origin_key, &contract_address)),
                Component::Hopper,
            ),
            LiveHop::new(
                &destination_key,
                paying_wallet
                    .clone()
                    .map(|w| w.as_payer(&PublicKey::new(b"can't pay"), &contract_address)),
                Component::Hopper,
            ),
        ];

        let hops = live_hops
            .iter()
            .map(|hop| match hop.encode(&hop.public_key, main_cryptde) {
                Ok(cryptdata) => cryptdata,
                Err(e) => panic!("Couldn't encode hop: {:?}", e),
            })
            .collect();

        let route = Route { hops };

        let lcp = LiveCoresPackage::new(
            route,
            encodex(main_cryptde, &destination_key, &payload).unwrap(),
        );

        let system = System::new(test_name);
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .proxy_client(proxy_client)
            .proxy_server(proxy_server)
            .neighborhood(neighborhood)
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            true,
        );
        subject.logger = Logger::new(test_name);

        subject.route_data_externally(
            lcp,
            paying_wallet.map(|w| w.as_payer(&PublicKey::new(b"can't pay"), &contract_address)),
            true,
        );

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_matching(
            &format!("WARN: {test_name}: Refusing to route Live CORES package with \\d+-byte payload without proof of 0x0a26dc9ebb2124baf1efe9d460f1ce59cd7944bd paying wallet ownership."),
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_cores_package_from_delinquent_that_demands_external_routing() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        init_test_logging();
        let test_name =
            "route_logs_and_ignores_cores_package_from_delinquent_that_demands_external_routing";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        BAN_CACHE.insert(paying_wallet.clone());
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let next_key = PublicKey::new(&[65, 65, 65]);
        let route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &next_key],
                Component::Neighborhood,
            ),
            main_cryptde,
            Some(paying_wallet.clone()),
            Some(contract_address.clone()),
        )
        .unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(route, main_cryptde.encode(&next_key, &payload).unwrap());
        let data_enc = encodex(main_cryptde, &main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new("test");
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            rate_pack_routing(103),
            rate_pack_routing_byte(103),
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();

        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        assert_eq!(dispatcher_recording.len(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("WARN: {test_name}: Node with consuming wallet 0x71d0fc7d1c570b1ed786382b551a09391c91e33d is delinquent; electing not to route 7-byte payload further"));
    }

    #[test]
    fn route_logs_and_ignores_cores_package_from_delinquent_that_demands_internal_routing() {
        let _eg = EnvironmentGuard::new();
        BAN_CACHE.clear();
        init_test_logging();
        let test_name =
            "route_logs_and_ignores_cores_package_from_delinquent_that_demands_internal_routing";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        BAN_CACHE.insert(paying_wallet.clone());
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let mut route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &main_cryptde.public_key()],
                Component::ProxyServer,
            ),
            main_cryptde,
            Some(paying_wallet.clone()),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        route.shift(main_cryptde).unwrap();
        let payload = PlainData::new(&b"abcd"[..]);
        let lcp = LiveCoresPackage::new(
            route,
            main_cryptde
                .encode(&main_cryptde.public_key(), &payload)
                .unwrap(),
        );
        let data_enc = encodex(main_cryptde, &main_cryptde.public_key(), &lcp).unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: data_enc.into(),
        };
        let system = System::new("test");
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            rate_pack_routing(103),
            rate_pack_routing_byte(103),
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop();
        system.run();

        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        assert_eq!(dispatcher_recording.len(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("WARN: {test_name}: Node with consuming wallet 0x71d0fc7d1c570b1ed786382b551a09391c91e33d is delinquent; electing not to route 36-byte payload to ProxyServer"));
    }

    #[test]
    fn route_logs_and_ignores_inbound_client_data_that_doesnt_deserialize_properly() {
        init_test_logging();
        let test_name =
            "route_logs_and_ignores_inbound_client_data_that_doesnt_deserialize_properly";
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
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
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Couldn't decode CORES package in 0-byte buffer from 1.2.3.4:5678: DecryptionError(EmptyData)"),
        );
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_logs_and_ignores_invalid_live_cores_package() {
        init_test_logging();
        let test_name = "route_logs_and_ignores_invalid_live_cores_package";
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let lcp = LiveCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]));
        let data_ser = PlainData::new(&serde_cbor::ser::to_vec(&lcp).unwrap()[..]);
        let data_enc = main_cryptde
            .encode(&main_cryptde.public_key(), &data_ser)
            .unwrap();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
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
        let mut subject = RoutingService::new(
            CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);

        subject.route(inbound_client_data);

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: Invalid 67-byte CORES package: RoutingError(EmptyRoute)"
        ));
        assert_eq!(proxy_client_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(proxy_server_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(neighborhood_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn route_data_around_again_logs_and_ignores_bad_lcp() {
        init_test_logging();
        let test_name = "route_data_around_again_logs_and_ignores_bad_lcp";
        let peer_actors = peer_actors_builder().build();
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);
        let lcp = LiveCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]));
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: true,
            sequence_number: None,
            data: vec![],
        };

        subject.route_data_around_again(lcp, &ibcd);

        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: bad zero-hop route: RoutingError(EmptyRoute)"
        ));
    }

    fn make_routing_service_subs(peer_actors: PeerActors) -> RoutingServiceSubs {
        RoutingServiceSubs {
            proxy_client_subs_opt: peer_actors.proxy_client_opt,
            proxy_server_subs: peer_actors.proxy_server,
            neighborhood_subs: peer_actors.neighborhood,
            hopper_subs: peer_actors.hopper,
            to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
            to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
        }
    }

    fn route_data_to_peripheral_component_uses_proper_key_on_payload_for_component<F>(
        payload_factory: F,
        target_component: Component,
    ) where
        F: FnOnce(&CryptDEPair) -> CryptData,
    {
        let peer_actors = peer_actors_builder().build();
        let subject = RoutingService::new(
            make_cryptde_pair(),
            make_routing_service_subs(peer_actors),
            100,
            200,
            true,
        );
        let route = Route::single_hop(&PublicKey::new(b"1234"), subject.cryptdes.main).unwrap();
        let payload = payload_factory(&subject.cryptdes);
        let live_package = LiveCoresPackage::new(route, payload);

        subject.route_data_to_peripheral_component(
            target_component,
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            live_package,
            true,
        );

        // CryptDENull panics when you try decrypting with the wrong key; no panic means test passes
    }

    #[test]
    fn route_data_to_peripheral_component_uses_main_key_on_payload_for_proxy_client() {
        let payload_factory = |cryptdes: &CryptDEPair| {
            encodex(
                cryptdes.main,
                cryptdes.main.public_key(),
                &MessageType::ClientRequest(VersionedData::new(
                    &crate::sub_lib::migrations::client_request_payload::MIGRATIONS,
                    &ClientRequestPayload_0v1 {
                        stream_key: StreamKey::make_meaningless_stream_key(),
                        sequenced_packet: SequencedPacket::new(vec![1, 2, 3, 4], 1234, false),
                        target_hostname: Some("hostname".to_string()),
                        target_port: 1234,
                        protocol: ProxyProtocol::TLS,
                        originator_public_key: PublicKey::new(b"1234"),
                    },
                )),
            )
            .unwrap()
        };
        route_data_to_peripheral_component_uses_proper_key_on_payload_for_component(
            payload_factory,
            Component::ProxyClient,
        );
    }

    #[test]
    fn route_data_to_peripheral_component_uses_alias_key_on_payload_for_proxy_server() {
        let payload_factory = |cryptdes: &CryptDEPair| {
            encodex(
                cryptdes.alias,
                cryptdes.alias.public_key(),
                &MessageType::DnsResolveFailed(VersionedData::new(
                    &crate::sub_lib::migrations::dns_resolve_failure::MIGRATIONS,
                    &DnsResolveFailure_0v1 {
                        stream_key: StreamKey::make_meaningless_stream_key(),
                    },
                )),
            )
            .unwrap()
        };
        route_data_to_peripheral_component_uses_proper_key_on_payload_for_component(
            payload_factory,
            Component::ProxyServer,
        );
    }

    #[test]
    fn route_data_to_peripheral_component_uses_main_key_on_payload_for_neighborhood() {
        let payload_factory = |cryptdes: &CryptDEPair| {
            encodex(
                cryptdes.main,
                cryptdes.main.public_key(),
                &MessageType::GossipFailure(VersionedData::new(
                    &crate::sub_lib::migrations::gossip_failure::MIGRATIONS,
                    &GossipFailure_0v1::Unknown,
                )),
            )
            .unwrap()
        };
        route_data_to_peripheral_component_uses_proper_key_on_payload_for_component(
            payload_factory,
            Component::Neighborhood,
        );
    }

    #[test]
    fn route_data_to_peripheral_component_uses_main_key_on_payload_for_hopper() {
        let payload_factory = |cryptdes: &CryptDEPair| {
            encodex(
                cryptdes.main,
                cryptdes.main.public_key(),
                &MessageType::ClientResponse(VersionedData::new(
                    &crate::sub_lib::migrations::client_request_payload::MIGRATIONS,
                    &ClientResponsePayload_0v1 {
                        stream_key: StreamKey::make_meaningless_stream_key(),
                        sequenced_packet: SequencedPacket::new(vec![1, 2, 3, 4], 1234, false),
                    },
                )),
            )
            .unwrap()
        };
        route_data_to_peripheral_component_uses_proper_key_on_payload_for_component(
            payload_factory,
            Component::Hopper,
        );
    }

    #[test]
    fn route_expired_package_handles_unmigratable_gossip() {
        init_test_logging();
        let test_name = "route_expired_package_handles_unmigratable_gossip";
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);
        let expired_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            None,
            Route { hops: vec![] },
            MessageType::Gossip(VersionedData::test_new(dv!(0, 0), vec![])),
            0,
        );
        let system = System::new(test_name);

        subject.route_expired_package(Component::Neighborhood, expired_package, true);

        System::current().stop_with_code(0);
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(neighborhood_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Received unmigratable Gossip: MigrationNotFound(DataVersion {{ major: 0, minor: 0 }}, DataVersion {{ major: 0, minor: 1 }})"),
        );
    }

    #[test]
    fn route_expired_package_handles_unmigratable_client_request() {
        init_test_logging();
        let (proxy_client, _, proxy_client_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().proxy_client(proxy_client).build();
        let subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        let expired_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            None,
            Route { hops: vec![] },
            MessageType::ClientRequest(VersionedData::test_new(dv!(0, 0), vec![])),
            0,
        );
        let system = System::new("route_expired_package_handles_unmigratable_client_request");

        subject.route_expired_package(Component::ProxyClient, expired_package, true);

        System::current().stop_with_code(0);
        system.run();
        let proxy_client_recording = proxy_client_recording_arc.lock().unwrap();
        assert_eq!(proxy_client_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            "ERROR: RoutingService: Received unmigratable ClientRequestPayload: MigrationNotFound(DataVersion { major: 0, minor: 0 }, DataVersion { major: 0, minor: 1 })",
        );
    }

    #[test]
    fn route_expired_package_handles_unmigratable_client_response() {
        init_test_logging();
        let test_name = "route_expired_package_handles_unmigratable_client_response";
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().proxy_server(proxy_server).build();
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);
        let expired_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            None,
            Route { hops: vec![] },
            MessageType::ClientResponse(VersionedData::test_new(dv!(0, 0), vec![])),
            0,
        );
        let system = System::new(test_name);

        subject.route_expired_package(Component::ProxyServer, expired_package, true);

        System::current().stop_with_code(0);
        system.run();
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(proxy_server_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Received unmigratable ClientResponsePayload: MigrationNotFound(DataVersion {{ major: 0, minor: 0 }}, DataVersion {{ major: 0, minor: 1 }})"),
        );
    }

    #[test]
    fn route_expired_package_handles_unmigratable_dns_resolve_failure() {
        init_test_logging();
        let test_name = "route_expired_package_handles_unmigratable_dns_resolve_failure";
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);
        let expired_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            None,
            Route { hops: vec![] },
            MessageType::DnsResolveFailed(VersionedData::test_new(dv!(0, 0), vec![])),
            0,
        );
        let system = System::new(test_name);

        subject.route_expired_package(Component::ProxyServer, expired_package, true);

        System::current().stop_with_code(0);
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Received unmigratable DnsResolveFailed: MigrationNotFound(DataVersion {{ major: 0, minor: 0 }}, DataVersion {{ major: 0, minor: 1 }})"),
        );
    }

    #[test]
    fn route_expired_package_handles_unmigratable_gossip_failure() {
        init_test_logging();
        let test_name = "route_expired_package_handles_unmigratable_gossip_failure";
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        let mut subject = RoutingService::new(
            make_cryptde_pair(),
            RoutingServiceSubs {
                proxy_client_subs_opt: peer_actors.proxy_client_opt,
                proxy_server_subs: peer_actors.proxy_server,
                neighborhood_subs: peer_actors.neighborhood,
                hopper_subs: peer_actors.hopper,
                to_dispatcher: peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: peer_actors.accountant.report_routing_service_provided,
            },
            100,
            200,
            false,
        );
        subject.logger = Logger::new(test_name);
        let expired_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            None,
            Route { hops: vec![] },
            MessageType::GossipFailure(VersionedData::test_new(dv!(0, 0), vec![])),
            0,
        );
        let system = System::new("route_expired_package_handles_unmigratable_gossip_failure");

        subject.route_expired_package(Component::Neighborhood, expired_package, true);

        System::current().stop_with_code(0);
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(neighborhood_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            &format!("ERROR: {test_name}: Received unmigratable GossipFailure: MigrationNotFound(DataVersion {{ major: 0, minor: 0 }}, DataVersion {{ major: 0, minor: 1 }})"),
        );
    }
}
