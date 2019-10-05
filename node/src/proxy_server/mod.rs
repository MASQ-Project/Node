// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod client_request_payload_factory;
pub mod http_protocol_pack;
pub mod protocol_pack;
pub mod server_impersonator_http;
pub mod server_impersonator_tls;
pub mod tls_protocol_pack;

use crate::proxy_server::client_request_payload_factory::ClientRequestPayloadFactory;
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::protocol_pack::{from_ibcd, from_protocol, ProtocolPack};
use crate::stream_messages::NonClandestineAttributes;
use crate::stream_messages::RemovedStreamType;
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::bidi_hashmap::BidiHashMap;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{Endpoint, StreamShutdownMsg};
use crate::sub_lib::hopper::{ExpiredCoresPackage, IncipientCoresPackage};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{ExpectedService, NodeRecordMetadataMessage};
use crate::sub_lib::neighborhood::{ExpectedServices, DEFAULT_RATE_PACK};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{ClientResponsePayload, DnsResolveFailure};
use crate::sub_lib::proxy_server::ClientRequestPayload;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::proxy_server::{AddReturnRouteMessage, AddRouteMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::ttl_hashmap::TtlHashMap;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use pretty_hex::PrettyHex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use tokio;
use tokio::prelude::Future;

pub const RETURN_ROUTE_TTL: Duration = Duration::from_secs(120);

struct ProxyServerOutSubs {
    dispatcher: Recipient<TransmitDataMsg>,
    hopper: Recipient<IncipientCoresPackage>,
    accountant_exit: Recipient<ReportExitServiceConsumedMessage>,
    accountant_routing: Recipient<ReportRoutingServiceConsumedMessage>,
    route_source: Recipient<RouteQueryMessage>,
    update_node_record_metadata: Recipient<NodeRecordMetadataMessage>,
    add_return_route: Recipient<AddReturnRouteMessage>,
    add_route: Recipient<AddRouteMessage>,
    stream_shutdown_sub: Recipient<StreamShutdownMsg>,
}

pub struct ProxyServer {
    subs: Option<ProxyServerOutSubs>,
    client_request_payload_factory: ClientRequestPayloadFactory,
    stream_key_factory: Box<dyn StreamKeyFactory>,
    keys_and_addrs: BidiHashMap<StreamKey, SocketAddr>,
    tunneled_hosts: HashMap<StreamKey, String>,
    stream_key_routes: HashMap<StreamKey, RouteQueryResponse>,
    is_decentralized: bool,
    consuming_wallet_balance: Option<i64>,
    cryptde: &'static dyn CryptDE,
    logger: Logger,
    route_ids_to_return_routes: TtlHashMap<u32, AddReturnRouteMessage>,
    browser_proxy_sequence_offset: bool,
}

impl Actor for ProxyServer {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        let subs = ProxyServerOutSubs {
            dispatcher: msg.peer_actors.dispatcher.from_dispatcher_client,
            hopper: msg.peer_actors.hopper.from_hopper_client,
            accountant_exit: msg.peer_actors.accountant.report_exit_service_consumed,
            accountant_routing: msg.peer_actors.accountant.report_routing_service_consumed,
            route_source: msg.peer_actors.neighborhood.route_query,
            update_node_record_metadata: msg.peer_actors.neighborhood.update_node_record_metadata,
            add_return_route: msg.peer_actors.proxy_server.add_return_route,
            add_route: msg.peer_actors.proxy_server.add_route,
            stream_shutdown_sub: msg.peer_actors.proxy_server.stream_shutdown_sub,
        };
        self.subs = Some(subs);
    }
}

impl Handler<SetConsumingWalletMessage> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        _msg: SetConsumingWalletMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.consuming_wallet_balance = Some(0);
    }
}

impl Handler<InboundClientData> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        if msg.is_connect() {
            self.tls_connect(&msg);
            self.browser_proxy_sequence_offset = true;
        } else {
            self.handle_normal_client_data(msg, false);
        }
    }
}

impl Handler<AddReturnRouteMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: AddReturnRouteMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.route_ids_to_return_routes
            .insert(msg.return_route_id, msg);
    }
}

impl AddReturnRouteMessage {
    pub fn find_exit_node_key(&self) -> Option<&PublicKey> {
        self.expected_services
            .iter()
            .find_map(|service| match service {
                ExpectedService::Exit(public_key, _, _) => Some(public_key),
                _ => None,
            })
    }

    pub fn is_zero_hop(&self) -> bool {
        self.expected_services == vec![ExpectedService::Nothing, ExpectedService::Nothing]
    }
}

impl Handler<AddRouteMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: AddRouteMessage, _ctx: &mut Self::Context) -> Self::Result {
        debug!(self.logger, "Establishing stream key {}", msg.stream_key);
        self.stream_key_routes.insert(msg.stream_key, msg.route);
    }
}

impl Handler<ExpiredCoresPackage<DnsResolveFailure>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<DnsResolveFailure>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_dns_resolve_failure(&msg)
    }
}

impl Handler<ExpiredCoresPackage<ClientResponsePayload>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<ClientResponsePayload>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_client_response_payload(&msg)
    }
}

impl Handler<StreamShutdownMsg> for ProxyServer {
    type Result = ();

    fn handle(&mut self, _msg: StreamShutdownMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_shutdown_msg(_msg)
    }
}

impl ProxyServer {
    pub fn new(
        cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
        consuming_wallet_balance: Option<i64>,
    ) -> ProxyServer {
        ProxyServer {
            subs: None,
            client_request_payload_factory: ClientRequestPayloadFactory::new(),
            stream_key_factory: Box::new(StreamKeyFactoryReal {}),
            keys_and_addrs: BidiHashMap::new(),
            tunneled_hosts: HashMap::new(),
            stream_key_routes: HashMap::new(),
            is_decentralized,
            consuming_wallet_balance,
            cryptde,
            logger: Logger::new("ProxyServer"),
            route_ids_to_return_routes: TtlHashMap::new(RETURN_ROUTE_TTL),
            browser_proxy_sequence_offset: false,
        }
    }

    pub fn make_subs_from(addr: &Addr<ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            from_dispatcher: addr.clone().recipient::<InboundClientData>(),
            from_hopper: addr
                .clone()
                .recipient::<ExpiredCoresPackage<ClientResponsePayload>>(),
            dns_failure_from_hopper: addr
                .clone()
                .recipient::<ExpiredCoresPackage<DnsResolveFailure>>(),
            add_return_route: addr.clone().recipient::<AddReturnRouteMessage>(),
            add_route: addr.clone().recipient::<AddRouteMessage>(),
            stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
            set_consuming_wallet_sub: addr.clone().recipient::<SetConsumingWalletMessage>(),
        }
    }

    fn handle_dns_resolve_failure(&mut self, msg: &ExpiredCoresPackage<DnsResolveFailure>) {
        let return_route_info = match self.get_return_route_info(&msg.remaining_route) {
            Some(rri) => rri,
            None => return, // TODO: Eventually we'll have to do something better here, but we'll probably need some heuristics.
        };
        let exit_public_key = {
            // ugly, ugly
            let self_public_key = self.cryptde.public_key();
            return_route_info
                .find_exit_node_key()
                .unwrap_or_else(|| {
                    if return_route_info.is_zero_hop() {
                        &self_public_key
                    } else {
                        panic!(
                            "Internal error: return_route_info for {} has no exit Node",
                            return_route_info.return_route_id
                        );
                    }
                })
                .clone()
        };
        let response = &msg.payload;
        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(socket_addr) => {
                self.subs
                    .as_ref()
                    .expect("Neighborhood unbound in ProxyServer")
                    .update_node_record_metadata
                    .try_send(NodeRecordMetadataMessage::Desirable(
                        exit_public_key.clone(),
                        false,
                    ))
                    .expect("Neighborhood is dead");

                self.report_response_services_consumed(&return_route_info, 0, msg.payload_len);

                self.subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(socket_addr),
                        last_data: true,
                        sequence_number: Some(0), // DNS resolution errors always happen on the first request
                        data: from_protocol(return_route_info.protocol)
                            .server_impersonator()
                            .dns_resolution_failure_response(
                                &exit_public_key,
                                return_route_info.server_name.clone(),
                            ),
                    })
                    .expect("Dispatcher is dead");
                debug!(
                    self.logger,
                    "Retiring stream key {}: DnsResolveFailure", &response.stream_key
                );
                self.purge_stream_key(&response.stream_key);
            }
            None => {
                let server_name = match &return_route_info.server_name {
                    Some(name) => format!("\"{}\"", name),
                    None => "<unspecified server>".to_string(),
                };
                error!(self.logger,
                    "Discarding DnsResolveFailure message for {} from an unrecognized stream key {:?}",
                    server_name,
                    &response.stream_key
                )
            }
        }
    }

    fn handle_client_response_payload(&mut self, msg: &ExpiredCoresPackage<ClientResponsePayload>) {
        debug!(
            self.logger,
            "ExpiredCoresPackage remaining_route: {}",
            msg.remaining_route
                .to_string(vec![self.cryptde, self.cryptde])
        );
        let payload_data_len = msg.payload_len;
        let response = &msg.payload;
        debug!(
            self.logger,
            "Relaying ClientResponsePayload (stream key {}, sequence {}, length {}) from Hopper to Dispatcher for client",
            response.stream_key, response.sequenced_packet.sequence_number, response.sequenced_packet.data.len()
        );
        let return_route_info = match self.get_return_route_info(&msg.remaining_route) {
            Some(rri) => rri,
            None => return,
        };
        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(socket_addr) => {
                self.report_response_services_consumed(
                    &return_route_info,
                    response.sequenced_packet.data.len(),
                    payload_data_len,
                );

                let last_data = response.sequenced_packet.last_data;
                let sequence_number = Some(
                    response.sequenced_packet.sequence_number
                        + self.browser_proxy_sequence_offset as u64,
                );
                self
                    .subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(socket_addr),
                        last_data,
                        sequence_number,
                        data: response.sequenced_packet.data.clone(),
                    })
                    .expect("Dispatcher is dead");
                if last_data {
                    debug!(self.logger, "Retiring stream key {}: no more data", &response.stream_key);
                    self.purge_stream_key(&response.stream_key);
                }
            }
            None => error!(self.logger,
                "Discarding {}-byte packet {} from an unrecognized stream key: {:?}; can't send response back to client\n{:?}",
                response.sequenced_packet.data.len(),
                response.sequenced_packet.sequence_number,
                response.stream_key,
                response.sequenced_packet.data.hex_dump(),
            ),
        }
    }

    fn tls_connect(&mut self, msg: &InboundClientData) {
        let http_data = HttpProtocolPack {}.find_host(&msg.data.clone().into());
        match http_data {
            Some(ref host) if host.port == Some(443) => {
                let stream_key = self.make_stream_key(&msg);
                self.tunneled_hosts.insert(stream_key, host.name.clone());
                self.subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(msg.peer_addr),
                        last_data: false,
                        sequence_number: msg.sequence_number,
                        data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                    })
                    .expect("Dispatcher is dead");
            }
            _ => {
                self.subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(msg.peer_addr),
                        last_data: true,
                        sequence_number: msg.sequence_number,
                        data: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    })
                    .expect("Dispatcher is dead");
            }
        }
    }

    fn out_subs(&self, actor_name: &str) -> &ProxyServerOutSubs {
        self.subs
            .as_ref()
            .unwrap_or_else(|| panic!("{} unbound in ProxyServer", actor_name))
    }

    fn handle_normal_client_data(&mut self, msg: InboundClientData, retire_stream_key: bool) {
        let route_source = self.out_subs("Neighborhood").route_source.clone();
        let hopper = self.out_subs("Hopper").hopper.clone();
        let accountant_exit_sub = self.out_subs("Accountant").accountant_exit.clone();
        let accountant_routing_sub = self.out_subs("Accountant").accountant_routing.clone();
        let dispatcher = self.out_subs("Dispatcher").dispatcher.clone();
        let add_return_route_sub = self.out_subs("ProxyServer").add_return_route.clone();
        let add_route_sub = self.out_subs("ProxyServer").add_route.clone();
        let stream_shutdown_sub = self.out_subs("ProxyServer").stream_shutdown_sub.clone();
        let source_addr = msg.peer_addr;
        if self.consuming_wallet_balance.is_none() && self.is_decentralized {
            let protocol_pack = match from_ibcd(&msg, &self.logger) {
                None => return,
                Some(pp) => pp,
            };
            let data = protocol_pack
                .server_impersonator()
                .consuming_wallet_absent();
            let msg = TransmitDataMsg {
                endpoint: Endpoint::Socket(source_addr),
                last_data: true,
                sequence_number: Some(0),
                data,
            };
            dispatcher.try_send(msg).expect("Dispatcher is dead");
            error!(
                self.logger,
                "Browser request rejected due to missing consuming wallet"
            );
            return;
        }
        let stream_key = self.make_stream_key(&msg);
        let payload = match self.make_payload(msg, &stream_key) {
            Ok(payload) => payload,
            Err(_e) => {
                return;
            }
        };
        let logger = self.logger.clone();
        let minimum_hop_count = if self.is_decentralized { 3 } else { 0 };
        let cryptde = self.cryptde.dup();
        match self.stream_key_routes.get(&stream_key) {
            Some(route_query_response) => {
                debug!(
                    logger,
                    "Transmitting down existing stream {}: sequence {}, length {}",
                    stream_key,
                    payload.sequenced_packet.sequence_number,
                    payload.sequenced_packet.data.len()
                );
                ProxyServer::try_transmit_to_hopper(
                    cryptde,
                    &hopper,
                    route_query_response.clone(),
                    payload,
                    logger,
                    source_addr,
                    &dispatcher,
                    &accountant_exit_sub,
                    &accountant_routing_sub,
                    &add_return_route_sub,
                    if retire_stream_key {
                        Some(&stream_shutdown_sub)
                    } else {
                        None
                    },
                )
                .expect("Could not transmit to hopper");
            }
            None => {
                debug!(logger,
                    "Getting route and opening new stream with key {} to transmit: sequence {}, length {}",
                    stream_key, payload.sequenced_packet.sequence_number, payload.sequenced_packet.data.len()
                );
                tokio::spawn(
                    route_source
                        .send(RouteQueryMessage::data_indefinite_route_request(
                            minimum_hop_count,
                        ))
                        .then(move |route_result| {
                            match route_result {
                                Ok(Some(route_query_response)) => {
                                    add_route_sub
                                        .try_send(AddRouteMessage {
                                            stream_key,
                                            route: route_query_response.clone(),
                                        })
                                        .expect("ProxyServer is dead");
                                    ProxyServer::try_transmit_to_hopper(
                                        cryptde,
                                        &hopper,
                                        route_query_response,
                                        payload,
                                        logger,
                                        source_addr,
                                        &dispatcher,
                                        &accountant_exit_sub,
                                        &accountant_routing_sub,
                                        &add_return_route_sub,
                                        if retire_stream_key {
                                            Some(&stream_shutdown_sub)
                                        } else {
                                            None
                                        },
                                    )
                                    .expect("Could not transmit to hopper");
                                }
                                Ok(None) => {
                                    ProxyServer::handle_route_failure(
                                        payload,
                                        &logger,
                                        source_addr,
                                        &dispatcher,
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        logger,
                                        "Neighborhood refused to answer route request: {}", e
                                    );
                                }
                            };
                            Ok(())
                        }),
                );
            }
        }
    }

    fn handle_stream_shutdown_msg(&mut self, msg: StreamShutdownMsg) {
        let nca = match msg.stream_type {
            RemovedStreamType::Clandestine => {
                panic!("ProxyServer should never get ShutdownStreamMsg about clandestine stream")
            }
            RemovedStreamType::NonClandestine(nca) => nca,
        };
        let msg_peer_addr = msg.peer_addr;
        let stream_key = match self.keys_and_addrs.b_to_a(&msg.peer_addr) {
            None => {
                warning!(
                    self.logger,
                    "Received instruction to shut down nonexistent stream to peer {} - ignoring",
                    msg_peer_addr
                );
                return;
            }
            Some(sk) => sk,
        };
        if msg.report_to_counterpart {
            debug!(
                self.logger,
                "Reporting shutdown of {} to counterpart", &stream_key
            );
            let ibcd = InboundClientData {
                peer_addr: msg.peer_addr,
                reception_port: Some(nca.reception_port),
                last_data: true,
                is_clandestine: false,
                sequence_number: Some(nca.sequence_number),
                data: vec![],
            };
            self.handle_normal_client_data(ibcd, true);
        } else {
            debug!(
                self.logger,
                "Retiring stream key {}: StreamShutdownMsg for peer {}", &stream_key, msg_peer_addr
            );
            self.purge_stream_key(&stream_key);
        }
    }

    fn make_stream_key(&mut self, ibcd: &InboundClientData) -> StreamKey {
        match self.keys_and_addrs.b_to_a(&ibcd.peer_addr) {
            Some(stream_key) => {
                debug!(
                    self.logger,
                    "make_stream_key() retrieved existing key {} for {}",
                    &stream_key,
                    ibcd.peer_addr
                );
                stream_key
            }
            None => {
                let stream_key = self
                    .stream_key_factory
                    .make(&self.cryptde.public_key(), ibcd.peer_addr);
                self.keys_and_addrs.insert(stream_key, ibcd.peer_addr);
                debug!(
                    self.logger,
                    "make_stream_key() inserted new key {} for {}", &stream_key, ibcd.peer_addr
                );
                stream_key
            }
        }
    }

    fn purge_stream_key(&mut self, stream_key: &StreamKey) {
        let _ = self.keys_and_addrs.remove_a(stream_key);
        let _ = self.stream_key_routes.remove(stream_key);
        let _ = self.tunneled_hosts.remove(stream_key);
    }

    fn make_payload(
        &mut self,
        ibcd: InboundClientData,
        stream_key: &StreamKey,
    ) -> Result<ClientRequestPayload, ()> {
        let tunnelled_host = self.tunneled_hosts.get(stream_key);
        let new_ibcd = match tunnelled_host {
            Some(_) => InboundClientData {
                reception_port: Some(443),
                ..ibcd
            },
            None => ibcd.clone(),
        };
        match self.client_request_payload_factory.make(
            &new_ibcd,
            stream_key.clone(),
            self.cryptde,
            &self.logger,
        ) {
            None => {
                error!(self.logger, "Couldn't create ClientRequestPayload");
                Err(())
            }
            Some(payload) => match tunnelled_host {
                Some(hostname) => Ok(ClientRequestPayload {
                    version: ClientRequestPayload::version(),
                    target_hostname: Some(hostname.clone()),
                    ..payload
                }),
                None => Ok(payload),
            },
        }
    }

    fn try_transmit_to_hopper(
        cryptde: Box<dyn CryptDE>,
        hopper: &Recipient<IncipientCoresPackage>,
        route_query_response: RouteQueryResponse,
        payload: ClientRequestPayload,
        logger: Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
        accountant_exit_sub: &Recipient<ReportExitServiceConsumedMessage>,
        accountant_routing_sub: &Recipient<ReportRoutingServiceConsumedMessage>,
        add_return_route_sub: &Recipient<AddReturnRouteMessage>,
        retire_stream_key_via: Option<&Recipient<StreamShutdownMsg>>,
    ) -> Result<(), ()> {
        match route_query_response.expected_services {
            ExpectedServices::RoundTrip(over, back, return_route_id) => {
                let return_route_info = AddReturnRouteMessage {
                    return_route_id,
                    expected_services: back.clone(),
                    protocol: payload.protocol,
                    server_name: payload.target_hostname.clone(),
                };
                debug!(
                    logger,
                    "Adding expectant return route info: {:?}", return_route_info
                );
                add_return_route_sub
                    .try_send(return_route_info)
                    .expect("ProxyServer is dead");
                ProxyServer::report_exit_service(
                    accountant_exit_sub,
                    over.clone(),
                    &payload,
                    &logger,
                );
                ProxyServer::transmit_to_hopper(
                    cryptde,
                    hopper,
                    payload,
                    &route_query_response.route,
                    over.clone(),
                    &logger,
                    source_addr,
                    dispatcher,
                    accountant_routing_sub,
                    retire_stream_key_via,
                );
            }
            _ => panic!("Expected RoundTrip ExpectedServices but got OneWay"),
        }
        Ok(())
    }

    fn report_routing_service(
        accountant_routing_sub: &Recipient<ReportRoutingServiceConsumedMessage>,
        expected_services: Vec<ExpectedService>,
        payload_size: usize,
        logger: &Logger,
    ) {
        let earning_wallets_and_rates: Vec<(&Wallet, &RatePack)> = expected_services
            .iter()
            .filter_map(|service| match service {
                ExpectedService::Routing(_, earning_wallet, rate_pack) => {
                    Some((earning_wallet, rate_pack))
                }
                _ => None,
            })
            .collect();
        if earning_wallets_and_rates.is_empty() {
            debug!(logger, "No routing services requested.");
        }
        earning_wallets_and_rates
            .into_iter()
            .for_each(|(earning_wallet, _rate_pack)| {
                let report_routing_service_consumed = ReportRoutingServiceConsumedMessage {
                    earning_wallet: earning_wallet.clone(),
                    payload_size,
                    service_rate: DEFAULT_RATE_PACK.routing_service_rate,
                    byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
                };
                accountant_routing_sub
                    .try_send(report_routing_service_consumed)
                    .expect("Accountant is dead");
            });
    }

    fn report_exit_service(
        accountant_exit_sub: &Recipient<ReportExitServiceConsumedMessage>,
        expected_services: Vec<ExpectedService>,
        payload: &ClientRequestPayload,
        logger: &Logger,
    ) {
        match expected_services
            .iter()
            .find_map(|expected_service| match expected_service {
                ExpectedService::Exit(_, earning_wallet, rate_pack) => {
                    Some((earning_wallet, rate_pack))
                }
                _ => None,
            }) {
            Some((earning_wallet, _rate_pack)) => {
                let payload_size = payload.sequenced_packet.data.len();
                let report_exit_service_consumed_message = ReportExitServiceConsumedMessage {
                    earning_wallet: earning_wallet.clone(),
                    payload_size,
                    service_rate: DEFAULT_RATE_PACK.exit_service_rate,
                    byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
                };
                accountant_exit_sub
                    .try_send(report_exit_service_consumed_message)
                    .expect("Accountant is dead");
            }
            None => debug!(logger, "No exit service requested."),
        };
    }

    fn transmit_to_hopper(
        cryptde: Box<dyn CryptDE>,
        hopper: &Recipient<IncipientCoresPackage>,
        payload: ClientRequestPayload,
        route: &Route,
        expected_services: Vec<ExpectedService>,
        logger: &Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
        accountant_routing_sub: &Recipient<ReportRoutingServiceConsumedMessage>,
        retire_stream_key_via: Option<&Recipient<StreamShutdownMsg>>,
    ) {
        let destination_key_opt = if !expected_services.is_empty()
            && expected_services
                .iter()
                .all(|expected_service| match expected_service {
                    ExpectedService::Nothing => true,
                    _ => false,
                }) {
            Some(payload.originator_public_key.clone())
        } else {
            expected_services.iter().find_map(|service| match service {
                ExpectedService::Exit(public_key, _, _) => Some(public_key.clone()),
                _ => None,
            })
        };

        match destination_key_opt {
            None => ProxyServer::handle_route_failure(payload, &logger, source_addr, dispatcher),
            Some(payload_destination_key) => {
                debug!(
                    logger,
                    "transmit to hopper with destination key {:?}", payload_destination_key
                );
                let stream_key = payload.stream_key;
                let pkg = IncipientCoresPackage::new(
                    cryptde.as_ref(),
                    route.clone(),
                    payload.into(),
                    &payload_destination_key,
                )
                .expect("Key magically disappeared");
                ProxyServer::report_routing_service(
                    accountant_routing_sub,
                    expected_services,
                    pkg.payload.len(),
                    &logger,
                );
                hopper.try_send(pkg).expect("Hopper is dead");
                if let Some(shutdown_sub) = retire_stream_key_via {
                    debug!(
                        logger,
                        "Last data is on the way; directing shutdown of stream {}", stream_key
                    );
                    shutdown_sub
                        .try_send(StreamShutdownMsg {
                            peer_addr: source_addr,
                            stream_type: RemovedStreamType::NonClandestine(
                                NonClandestineAttributes {
                                    // No report to counterpart; these are irrelevant
                                    reception_port: 0,
                                    sequence_number: 0,
                                },
                            ),
                            report_to_counterpart: false,
                        })
                        .expect("Proxy Server is dead");
                }
            }
        }
    }

    fn handle_route_failure(
        payload: ClientRequestPayload,
        logger: &Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) {
        let target_hostname = ProxyServer::hostname(&payload);
        ProxyServer::send_route_failure(payload, source_addr, dispatcher);
        error!(logger, "Failed to find route to {}", target_hostname);
    }

    fn send_route_failure(
        payload: ClientRequestPayload,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) {
        let data = from_protocol(payload.protocol)
            .server_impersonator()
            .route_query_failure_response(&ProxyServer::hostname(&payload));
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

    fn get_return_route_info(&self, remaining_route: &Route) -> Option<Rc<AddReturnRouteMessage>> {
        let mut mut_remaining_route = remaining_route.clone();
        mut_remaining_route
            .shift(self.cryptde)
            .expect("Internal error: remaining route in ProxyServer with no hops");
        let return_route_id = match mut_remaining_route.id(self.cryptde) {
            Ok(rri) => rri,
            Err(e) => {
                error!(self.logger, "Can't report services consumed: {}", e);
                return None;
            }
        };
        match self.route_ids_to_return_routes.get(&return_route_id) {
            Some(rri) => Some(rri),
            None => {
                error!(self.logger, "Can't report services consumed: received response with bogus return-route ID {}. Ignoring", return_route_id);
                None
            }
        }
    }

    fn report_response_services_consumed(
        &self,
        return_route_info: &AddReturnRouteMessage,
        exit_size: usize,
        routing_size: usize,
    ) {
        return_route_info
            .expected_services
            .iter()
            .for_each(|service| match service {
                ExpectedService::Nothing => (),
                ExpectedService::Exit(_, wallet, _rate_pack) => self
                    .subs
                    .as_ref()
                    .expect("ProxyServer unbound")
                    .accountant_exit
                    .try_send(ReportExitServiceConsumedMessage {
                        earning_wallet: wallet.clone(),
                        payload_size: exit_size,
                        service_rate: DEFAULT_RATE_PACK.exit_service_rate,
                        byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
                    })
                    .expect("Accountant is dead"),
                ExpectedService::Routing(_, wallet, _rate_pack) => self
                    .subs
                    .as_ref()
                    .expect("ProxyServer unbound")
                    .accountant_routing
                    .try_send(ReportRoutingServiceConsumedMessage {
                        earning_wallet: wallet.clone(),
                        payload_size: routing_size,
                        service_rate: DEFAULT_RATE_PACK.routing_service_rate,
                        byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
                    })
                    .expect("Accountant is dead"),
            });
    }
}

trait StreamKeyFactory: Send {
    fn make(&self, public_key: &PublicKey, peer_addr: SocketAddr) -> StreamKey;
}

struct StreamKeyFactoryReal {}

impl StreamKeyFactory for StreamKeyFactoryReal {
    fn make(&self, public_key: &PublicKey, peer_addr: SocketAddr) -> StreamKey {
        // TODO: Replace this implementation
        StreamKey::new(public_key.clone(), peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::contract_address;
    use crate::persistent_configuration::{HTTP_PORT, TLS_PORT};
    use crate::proxy_server::protocol_pack::ServerImpersonator;
    use crate::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
    use crate::proxy_server::server_impersonator_tls::ServerImpersonatorTls;
    use crate::stream_messages::{NonClandestineAttributes, RemovedStreamType};
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::cryptde::{decodex, CryptData};
    use crate::sub_lib::cryptde::{encodex, PlainData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::data_version::DataVersion;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::ExpectedServices;
    use crate::sub_lib::neighborhood::{ExpectedService, DEFAULT_RATE_PACK};
    use crate::sub_lib::proxy_client::{ClientResponsePayload, DnsResolveFailure};
    use crate::sub_lib::proxy_server::ClientRequestPayload;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::sub_lib::sequence_buffer::SequencedPacket;
    use crate::sub_lib::ttl_hashmap::TtlHashMap;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::rate_pack;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::zero_hop_route_response;
    use crate::test_utils::{cryptde, make_wallet};
    use crate::test_utils::{make_meaningless_route, make_paying_wallet};
    use crate::test_utils::{make_meaningless_stream_key, DEFAULT_CHAIN_ID};
    use actix::System;
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::thread;

    const STANDARD_CONSUMING_WALLET_BALANCE: i64 = 0;

    impl Default for ProxyServerOutSubs {
        fn default() -> Self {
            let recorder = Recorder::new();
            let addr = recorder.start();
            ProxyServerOutSubs {
                dispatcher: addr.clone().recipient::<TransmitDataMsg>(),
                hopper: addr.clone().recipient::<IncipientCoresPackage>(),
                accountant_exit: addr.clone().recipient::<ReportExitServiceConsumedMessage>(),
                accountant_routing: addr
                    .clone()
                    .recipient::<ReportRoutingServiceConsumedMessage>(),
                route_source: addr.clone().recipient::<RouteQueryMessage>(),
                update_node_record_metadata: addr.clone().recipient::<NodeRecordMetadataMessage>(),
                add_return_route: addr.clone().recipient::<AddReturnRouteMessage>(),
                add_route: addr.clone().recipient::<AddRouteMessage>(),
                stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
            }
        }
    }

    struct StreamKeyFactoryMock {
        make_parameters: Arc<Mutex<Vec<(PublicKey, SocketAddr)>>>,
        make_results: RefCell<Vec<StreamKey>>,
    }

    impl StreamKeyFactory for StreamKeyFactoryMock {
        fn make(&self, key: &PublicKey, peer_addr: SocketAddr) -> StreamKey {
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
            params: &Arc<Mutex<Vec<(PublicKey, SocketAddr)>>>,
        ) -> StreamKeyFactoryMock {
            self.make_parameters = params.clone();
            self
        }

        fn make_result(self, stream_key: StreamKey) -> StreamKeyFactoryMock {
            self.make_results.borrow_mut().push(stream_key);
            self
        }
    }

    fn return_route_with_id(cryptde: &dyn CryptDE, return_route_id: u32) -> Route {
        let cover_hop = make_cover_hop(cryptde);
        let id_hop = cryptde
            .encode(
                &cryptde.public_key(),
                &PlainData::from(serde_cbor::ser::to_vec(&return_route_id).unwrap()),
            )
            .unwrap();
        Route {
            hops: vec![cover_hop, id_hop],
        }
    }

    fn make_cover_hop(cryptde: &dyn CryptDE) -> CryptData {
        encodex(
            cryptde,
            &cryptde.public_key(),
            &LiveHop {
                public_key: cryptde.public_key().clone(),
                payer: None,
                component: Component::ProxyServer,
            },
        )
        .unwrap()
    }

    fn check_exit_report(
        accountant_recording: &MutexGuard<Recording>,
        idx: usize,
        wallet: &Wallet,
        payload_size: usize,
    ) {
        assert_eq!(
            accountant_recording.get_record::<ReportExitServiceConsumedMessage>(idx),
            &ReportExitServiceConsumedMessage {
                earning_wallet: wallet.clone(),
                payload_size,
                service_rate: DEFAULT_RATE_PACK.exit_service_rate,
                byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
            }
        );
    }

    fn check_routing_report(
        accountant_recording: &MutexGuard<Recording>,
        idx: usize,
        wallet: &Wallet,
        payload_size: usize,
    ) {
        assert_eq!(
            accountant_recording.get_record::<ReportRoutingServiceConsumedMessage>(idx),
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: wallet.clone(),
                payload_size,
                service_rate: DEFAULT_RATE_PACK.routing_service_rate,
                byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
            }
        );
    }

    #[test]
    fn proxy_server_receives_http_request_with_new_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (hopper_mock, hopper_awaiter, hopper_log_arc) = make_recorder();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let make_parameters_arc_a = make_parameters_arc.clone();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&make_parameters_arc)
                .make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .proxy_server(proxy_server_mock)
                .build();
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
            (cryptde.public_key().clone(), socket_addr)
        );
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(0));
        let recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname() {
        let cryptde = cryptde();
        let key = cryptde.public_key();
        let http_request = b"CONNECT https://realdomain.nu:443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";
        let (hopper_mock, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));
        let route = zero_hop_route_response(&key, cryptde).route;
        let (dispatcher_mock, _, dispatcher_recording_arc) = make_recorder();

        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: request_data.clone(),
        };

        let tunnelled_msg = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: b"client hello".to_vec(),
        };

        let expected_tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr.clone()),
            last_data: false,
            sequence_number: Some(0),
            data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        };

        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"client hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("realdomain.nu")),
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();

        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let make_parameters_arc_thread = make_parameters_arc.clone();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&make_parameters_arc_thread)
                .make_result(stream_key);
            let system = System::new(
                "proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname",
            );
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();
            subject_addr.try_send(tunnelled_msg).unwrap();
            system.run();
        });

        hopper_awaiter.await_message_count(1);

        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let dispatcher_record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(dispatcher_record, &expected_tdm);
        let mut make_parameters = make_parameters_arc.lock().unwrap();
        assert_eq!(
            make_parameters.remove(0),
            (cryptde.public_key().clone(), socket_addr)
        );

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let hopper_record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(hopper_record, &expected_pkg);

        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let neighborhood_record = neighborhood_recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(
            neighborhood_record,
            &RouteQueryMessage::data_indefinite_route_request(0)
        );
    }

    #[test]
    fn handle_client_response_payload_increments_sequence_number_when_browser_proxy_sequence_offset_is_true(
    ) {
        let system = System::new("handle_client_response_payload_increments_sequence_number_when_browser_proxy_sequence_offset_is_true");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![ExpectedService::Nothing],
                protocol: ProxyProtocol::TLS,
                server_name: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let http_request = b"CONNECT https://realdomain.nu:443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";
        let request_data = http_request.to_vec();
        let inbound_client_data = InboundClientData {
            peer_addr: socket_addr,
            reception_port: Some(443),
            last_data: false,
            is_clandestine: false,
            sequence_number: Some(0),
            data: request_data,
        };

        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
        };

        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                client_response_payload.into(),
                0,
            );

        let mut peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr.try_send(inbound_client_data).unwrap();

        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();

        System::current().stop();
        system.run();

        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(1);

        assert_eq!(record.sequence_number.unwrap(), 1);
    }

    #[test]
    fn proxy_server_sends_route_failure_for_connect_requests_to_ports_other_than_443() {
        let cryptde = cryptde();
        let http_request = b"CONNECT https://realdomain.nu:8443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";

        let (hopper_mock, _hopper_awaiter, _hopper_recording_arc) = make_recorder();
        let (neighborhood_mock, _, _neighborhood_recording_arc) = make_recorder();
        let (dispatcher_mock, _dispatcher_awaiter, dispatcher_recording_arc) = make_recorder();

        let neighborhood_mock = neighborhood_mock.route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));

        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: request_data.clone(),
        };

        let stream_key_parameters_arc = Arc::new(Mutex::new(vec![]));
        let stream_key_parameters_arc_thread = stream_key_parameters_arc.clone();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&stream_key_parameters_arc_thread)
                .make_result(stream_key);
            let system = System::new(
                "proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname",
            );
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();
            system.run();
        });

        thread::sleep(Duration::from_millis(500));

        let expected_transmit_data_msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: true,
            sequence_number: Some(0),
            data: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
        };

        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);

        assert_eq!(record, &expected_transmit_data_msg);
    }

    #[test]
    fn proxy_server_sends_error_and_shuts_down_stream_when_connect_host_unparseable() {
        let cryptde = cryptde();
        let http_request = "CONNECT λ:🥓:λ HTTP/1.1\r\nHost: 🥓:🥔:🥔\r\n\r\n".as_bytes();

        let (hopper_mock, _hopper_awaiter, _hopper_recording_arc) = make_recorder();
        let (neighborhood_mock, _, _neighborhood_recording_arc) = make_recorder();
        let (dispatcher_mock, _dispatcher_awaiter, dispatcher_recording_arc) = make_recorder();

        let neighborhood_mock = neighborhood_mock.route_query_response(Some(
            zero_hop_route_response(&cryptde.public_key(), cryptde),
        ));

        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: request_data.clone(),
        };

        let stream_key_parameters_arc = Arc::new(Mutex::new(vec![]));
        let stream_key_parameters_arc_thread = stream_key_parameters_arc.clone();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&stream_key_parameters_arc_thread)
                .make_result(stream_key);
            let system = System::new(
                "proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname",
            );
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();
            system.run();
        });

        thread::sleep(Duration::from_millis(500));

        let expected_transmit_data_msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: true,
            sequence_number: Some(0),
            data: b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
        };

        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);

        assert_eq!(&expected_transmit_data_msg, record);
    }

    #[test]
    fn proxy_server_receives_http_request_with_no_consuming_wallet_and_sends_impersonated_response()
    {
        init_test_logging();
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (hopper, _, hopper_log_arc) = make_recorder();
        let (neighborhood, _, neighborhood_log_arc) = make_recorder();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, true, None);
        subject.stream_key_factory = Box::new(stream_key_factory);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let mut peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .hopper(hopper)
            .neighborhood(neighborhood)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        assert!(neighborhood_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert!(hopper_recording.is_empty());
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let server_impersonator = ServerImpersonatorHttp {};
        assert_eq!(
            record,
            &TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: server_impersonator.consuming_wallet_absent(),
            }
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: ProxyServer: Browser request rejected due to missing consuming wallet",
        );
    }

    #[test]
    fn proxy_server_receives_tls_request_with_no_consuming_wallet_and_sends_impersonated_response()
    {
        init_test_logging();
        let cryptde = cryptde();
        let tls_request = b"Fake TLS request";
        let (hopper, _, hopper_log_arc) = make_recorder();
        let (neighborhood, _, neighborhood_log_arc) = make_recorder();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, true, None);
        subject.stream_key_factory = Box::new(stream_key_factory);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let mut peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .hopper(hopper)
            .neighborhood(neighborhood)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        assert!(neighborhood_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert!(hopper_recording.is_empty());
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        let server_impersonator = ServerImpersonatorTls {};
        assert_eq!(
            record,
            &TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: server_impersonator.consuming_wallet_absent(),
            }
        );
        TestLogHandler::new().exists_log_containing(
            "ERROR: ProxyServer: Browser request rejected due to missing consuming wallet",
        );
    }

    #[test]
    fn proxy_server_receives_http_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally(
    ) {
        init_test_logging();
        let cryptde = cryptde();
        let expected_data = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n".to_vec();
        let expected_data_inner = expected_data.clone();
        let expected_route = zero_hop_route_response(cryptde.public_key(), cryptde);
        let stream_key = make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let neighborhood_log_arc = neighborhood.get_recording();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                peer_addr: socket_addr.clone(),
                reception_port: Some(HTTP_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject = ProxyServer::new(cryptde, false, None);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .hopper(hopper)
                .neighborhood(neighborhood)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        assert_eq!(
            neighborhood_recording.get_record::<RouteQueryMessage>(0),
            &RouteQueryMessage {
                target_key_opt: None,
                target_component: Component::ProxyClient,
                minimum_hop_count: 0,
                return_component_opt: Some(Component::ProxyServer)
            }
        );
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        assert!(dispatcher_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert_eq!(
            hopper_recording.get_record::<IncipientCoresPackage>(0),
            &IncipientCoresPackage::new(
                cryptde,
                expected_route.route,
                MessageType::ClientRequest(ClientRequestPayload {
                    version: ClientRequestPayload::version(),
                    stream_key,
                    sequenced_packet: SequencedPacket::new(expected_data, 0, true),
                    target_hostname: Some("nowhere.com".to_string()),
                    target_port: 80,
                    protocol: ProxyProtocol::HTTP,
                    originator_public_key: cryptde.public_key().clone(),
                }),
                cryptde.public_key()
            )
            .unwrap()
        );
    }

    #[test]
    fn proxy_server_receives_tls_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally(
    ) {
        init_test_logging();
        let cryptde = cryptde();
        let expected_data = b"Fake TLS request".to_vec();
        let expected_data_inner = expected_data.clone();
        let expected_route = zero_hop_route_response(cryptde.public_key(), cryptde);
        let stream_key = make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let neighborhood_log_arc = neighborhood.get_recording();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                peer_addr: socket_addr.clone(),
                reception_port: Some(TLS_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject = ProxyServer::new(cryptde, false, None);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .hopper(hopper)
                .neighborhood(neighborhood)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        assert_eq!(
            neighborhood_recording.get_record::<RouteQueryMessage>(0),
            &RouteQueryMessage {
                target_key_opt: None,
                target_component: Component::ProxyClient,
                minimum_hop_count: 0,
                return_component_opt: Some(Component::ProxyServer)
            }
        );
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        assert!(dispatcher_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert_eq!(
            hopper_recording.get_record::<IncipientCoresPackage>(0),
            &IncipientCoresPackage::new(
                cryptde,
                expected_route.route,
                MessageType::ClientRequest(ClientRequestPayload {
                    version: ClientRequestPayload::version(),
                    stream_key,
                    sequenced_packet: SequencedPacket::new(expected_data, 0, true),
                    target_hostname: None,
                    target_port: 443,
                    protocol: ProxyProtocol::TLS,
                    originator_public_key: cryptde.public_key().clone(),
                }),
                cryptde.public_key()
            )
            .unwrap()
        );
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
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
    fn proxy_server_applies_late_wallet_information() {
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
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_applies_late_wallet_information");
            let mut subject = ProxyServer::new(cryptde, false, None);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr
                .try_send(SetConsumingWalletMessage {
                    wallet: make_wallet("Consuming wallet"),
                })
                .unwrap();

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
        let consuming_wallet = make_paying_wallet(b"paying wallet");
        let earning_wallet = make_wallet("earning wallet");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let payload_destination_key = PublicKey::new(&[3]);
        let route = Route::round_trip(
            RouteSegment::new(
                vec![
                    &cryptde.public_key(),
                    &PublicKey::new(&[1]),
                    &PublicKey::new(&[2]),
                    &payload_destination_key,
                ],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![
                    &payload_destination_key,
                    &PublicKey::new(&[2]),
                    &PublicKey::new(&[1]),
                    &cryptde.public_key(),
                ],
                Component::ProxyServer,
            ),
            cryptde,
            Some(consuming_wallet),
            1234,
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: route.clone(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        earning_wallet.clone(),
                        rate_pack(101),
                    ),
                    ExpectedService::Nothing,
                ],
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Exit(PublicKey::new(&[3]), earning_wallet, rate_pack(102)),
                ],
                1234,
            ),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let key = cryptde.public_key();
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: key.clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            cryptde,
            route.clone(),
            expected_payload.into(),
            &payload_destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(3));
    }

    #[test]
    fn proxy_server_adds_route_for_stream_key() {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (proxy_server_mock, proxy_server_awaiter, proxy_server_recording_arc) = make_recorder();
        let route_query_response = Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
        });
        let (neighborhood_mock, _, _) = make_recorder();
        let neighborhood_mock =
            neighborhood_mock.route_query_response(route_query_response.clone());
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_adds_route_for_stream_key");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .proxy_server(proxy_server_mock)
                .neighborhood(neighborhood_mock)
                .build();
            // Get the add_route recipient so we can partially mock it...
            let add_route_recipient = peer_actors.proxy_server.add_route;
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            peer_actors.proxy_server.add_route = add_route_recipient; //Partial mocking
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        let expected_add_route_message = AddRouteMessage {
            stream_key,
            route: route_query_response.unwrap(),
        };

        proxy_server_awaiter.await_message_count(1);
        let recording = proxy_server_recording_arc.lock().unwrap();
        let record = recording.get_record::<AddRouteMessage>(0);
        assert_eq!(record, &expected_add_route_message);
    }

    #[test]
    fn proxy_server_uses_existing_route() {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let route_query_response = Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing],
                vec![],
                1234,
            ),
        });
        let (hopper_mock, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: PlainData::new(http_request).into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            cryptde,
            Route { hops: vec![] },
            expected_payload.into(),
            &cryptde.public_key().clone(),
        )
        .unwrap();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_uses_existing_route");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder().hopper(hopper_mock).build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr
                .try_send(AddRouteMessage {
                    stream_key,
                    route: route_query_response.unwrap(),
                })
                .unwrap();
            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });

        hopper_awaiter.await_message_count(1);
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record, &expected_pkg);
    }

    #[test]
    fn proxy_server_sends_message_to_accountant_for_request_routing_service_consumed() {
        let cryptde = cryptde();
        let exit_earning_wallet = make_wallet("exit earning wallet");
        let route_1_earning_wallet = make_wallet("route 1 earning wallet");
        let route_2_earning_wallet = make_wallet("route 2 earning wallet");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let (hopper_mock, _, hopper_recording_arc) = make_recorder();
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let route_query_response = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Routing(
                        PublicKey::new(&[1]),
                        route_1_earning_wallet.clone(),
                        rate_pack(101),
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[2]),
                        route_2_earning_wallet.clone(),
                        rate_pack(102),
                    ),
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        exit_earning_wallet.clone(),
                        rate_pack(103),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        exit_earning_wallet.clone(),
                        rate_pack(104),
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[2]),
                        route_2_earning_wallet.clone(),
                        rate_pack(105),
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[1]),
                        route_1_earning_wallet.clone(),
                        rate_pack(106),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let system =
            System::new("proxy_server_sends_message_to_accountant_for_routing_service_consumed");
        let peer_actors = peer_actors_builder()
            .accountant(accountant_mock)
            .hopper(hopper_mock)
            .proxy_server(proxy_server_mock)
            .build();
        let payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");

        ProxyServer::try_transmit_to_hopper(
            cryptde.dup(),
            &peer_actors.hopper.from_hopper_client,
            route_query_response,
            payload.clone(),
            logger,
            socket_addr,
            &peer_actors.dispatcher.from_dispatcher_client,
            &peer_actors.accountant.report_exit_service_consumed,
            &peer_actors.accountant.report_routing_service_consumed,
            &peer_actors.proxy_server.add_return_route,
            None,
        )
        .unwrap();

        System::current().stop();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        let payload_enc = &record.payload;
        let recording = accountant_recording_arc.lock().unwrap();
        let record = recording.get_record::<ReportRoutingServiceConsumedMessage>(1);
        assert_eq!(
            record,
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: route_1_earning_wallet,
                payload_size: payload_enc.len(),
                service_rate: DEFAULT_RATE_PACK.routing_service_rate,
                byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
            }
        );
        let record = recording.get_record::<ReportRoutingServiceConsumedMessage>(2);
        assert_eq!(
            record,
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: route_2_earning_wallet,
                payload_size: payload_enc.len(),
                service_rate: DEFAULT_RATE_PACK.routing_service_rate,
                byte_rate: DEFAULT_RATE_PACK.routing_byte_rate,
            }
        );
        let recording = proxy_server_recording_arc.lock().unwrap();
        let _ = recording.get_record::<AddReturnRouteMessage>(0); // don't care about this, other than type
        assert_eq!(recording.len(), 1); // No StreamShutdownMsg: that's the important thing
    }

    #[test]
    fn try_transmit_to_hopper_orders_stream_shutdown_if_directed_to_do_so() {
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let route_query_response = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing],
                vec![ExpectedService::Nothing],
                0,
            ),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let system =
            System::new("proxy_server_sends_message_to_accountant_for_routing_service_consumed");
        let peer_actors = peer_actors_builder()
            .proxy_server(proxy_server_mock)
            .build();
        let payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");

        ProxyServer::try_transmit_to_hopper(
            cryptde.dup(),
            &peer_actors.hopper.from_hopper_client,
            route_query_response,
            payload.clone(),
            logger,
            socket_addr,
            &peer_actors.dispatcher.from_dispatcher_client,
            &peer_actors.accountant.report_exit_service_consumed,
            &peer_actors.accountant.report_routing_service_consumed,
            &peer_actors.proxy_server.add_return_route,
            Some(&peer_actors.proxy_server.stream_shutdown_sub),
        )
        .unwrap();

        System::current().stop();
        system.run();
        let recording = proxy_server_recording_arc.lock().unwrap();
        let record = recording.get_record::<AddReturnRouteMessage>(0);
        assert_eq!(
            record,
            &AddReturnRouteMessage {
                return_route_id: 0,
                expected_services: vec![ExpectedService::Nothing],
                protocol: ProxyProtocol::HTTP,
                server_name: Some("nowhere.com".to_string())
            }
        );
        let record = recording.get_record::<StreamShutdownMsg>(1);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr: socket_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: 0,
                    sequence_number: 0,
                }),
                report_to_counterpart: false
            }
        );
    }

    #[test]
    fn proxy_server_logs_messages_when_routing_services_are_not_requested() {
        init_test_logging();
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, _, accountant_log_arc) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let zero_hop_route_reponse = zero_hop_route_response(&cryptde.public_key(), cryptde);
        let neighborhood_mock =
            neighborhood_mock.route_query_response(Some(zero_hop_route_reponse.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system =
                System::new("proxy_server_logs_messages_when_routing_services_are_not_requested");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .accountant(accountant_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr.try_send(msg_from_dispatcher).unwrap();
            system.run();
        });

        TestLogHandler::new()
            .await_log_containing("DEBUG: ProxyServer: No routing services requested.", 1000);

        assert_eq!(accountant_log_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn proxy_server_sends_message_to_accountant_for_request_exit_service_consumed() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning wallet");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, accountant_awaiter, accountant_log_arc) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        earning_wallet.clone(),
                        rate_pack(101),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        earning_wallet.clone(),
                        rate_pack(102),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system =
                System::new("proxy_server_sends_message_to_accountant_for_exit_service_consumed");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .accountant(accountant_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr.try_send(msg_from_dispatcher).unwrap();
            system.run();
        });

        accountant_awaiter.await_message_count(1);
        let recording = accountant_log_arc.lock().unwrap();
        let record = recording.get_record::<ReportExitServiceConsumedMessage>(0);
        assert_eq!(
            record,
            &ReportExitServiceConsumedMessage {
                earning_wallet,
                payload_size: expected_data.len(),
                service_rate: DEFAULT_RATE_PACK.exit_service_rate,
                byte_rate: DEFAULT_RATE_PACK.exit_byte_rate,
            }
        );
    }

    #[test]
    fn proxy_server_logs_message_when_exit_services_are_not_requested() {
        init_test_logging();
        let cryptde = cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, _, accountant_log_arc) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let zero_hop_route_reponse = zero_hop_route_response(&cryptde.public_key(), cryptde);
        let neighborhood_mock =
            neighborhood_mock.route_query_response(Some(zero_hop_route_reponse.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system =
                System::new("proxy_server_logs_message_when_exit_services_are_not_consumed");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .accountant(accountant_mock)
                .neighborhood(neighborhood_mock)
                .build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr.try_send(msg_from_dispatcher).unwrap();
            system.run();
        });

        TestLogHandler::new()
            .await_log_containing("DEBUG: ProxyServer: No exit service requested.", 1000);

        assert_eq!(accountant_log_arc.lock().unwrap().len(), 0);
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
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .neighborhood(neighborhood_mock)
                .build();
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
            data: ServerImpersonatorHttp {}.route_query_failure_response("nowhere.com"),
        };
        assert_eq!(record, &expected_msg);
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(3));
        TestLogHandler::new()
            .exists_log_containing("ERROR: ProxyServer: Failed to find route to nowhere.com");
    }

    #[test]
    #[should_panic(expected = "Expected RoundTrip ExpectedServices but got OneWay")]
    fn proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route() {
        let _system = System::new("proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route");
        let peer_actors = peer_actors_builder().build();

        let cryptde = cryptde();
        let route_result = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::OneWay(vec![
                ExpectedService::Nothing,
                ExpectedService::Routing(
                    PublicKey::new(&[1]),
                    make_wallet("earning wallet 1"),
                    rate_pack(101),
                ),
                ExpectedService::Routing(
                    PublicKey::new(&[2]),
                    make_wallet("earning wallet 2"),
                    rate_pack(102),
                ),
                ExpectedService::Exit(
                    PublicKey::new(&[3]),
                    make_wallet("exit earning wallet"),
                    rate_pack(103),
                ),
            ]),
        };
        let payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: make_meaningless_stream_key(),
            sequenced_packet: SequencedPacket {
                data: vec![],
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 0,
            protocol: ProxyProtocol::TLS,
            originator_public_key: cryptde.public_key().clone(),
        };
        let logger = Logger::new("ProxyServer");
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        ProxyServer::try_transmit_to_hopper(
            cryptde.dup(),
            &peer_actors.hopper.from_hopper_client,
            route_result,
            payload,
            logger,
            source_addr,
            &peer_actors.dispatcher.from_dispatcher_client,
            &peer_actors.accountant.report_exit_service_consumed,
            &peer_actors.accountant.report_routing_service_consumed,
            &peer_actors.proxy_server.add_return_route,
            None,
        )
        .unwrap();
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route_with_no_expected_services(
    ) {
        init_test_logging();
        let cryptde = cryptde();
        let public_key = &cryptde.public_key();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let route_query_response = RouteQueryResponse {
            route: Route::round_trip(
                RouteSegment::new(vec![public_key, public_key], Component::ProxyClient),
                RouteSegment::new(vec![public_key, public_key], Component::ProxyServer),
                cryptde,
                None,
                1234,
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
        };
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(route_query_response));
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .neighborhood(neighborhood_mock)
                .build();
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
            data: ServerImpersonatorHttp {}.route_query_failure_response("nowhere.com"),
        };
        assert_eq!(record, &expected_msg);
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(3));
        TestLogHandler::new()
            .exists_log_containing("ERROR: ProxyServer: Failed to find route to nowhere.com");
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
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("server.com")),
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        thread::spawn(move || {
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        thread::spawn(move || {
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let key = cryptde.public_key();
        let route = zero_hop_route_response(&key, cryptde).route;
        let expected_payload = ClientRequestPayload {
            version: ClientRequestPayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: None,
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: key.clone(),
        };
        let expected_pkg =
            IncipientCoresPackage::new(cryptde, route.clone(), expected_payload.into(), &key)
                .unwrap();
        thread::spawn(move || {
            let mut subject =
                ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: tls_request,
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .neighborhood(neighborhood)
                .build();
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
            data: ServerImpersonatorTls {}.route_query_failure_response("ignored"),
        };
        assert_eq!(record, &expected_msg);

        TestLogHandler::new()
            .exists_log_containing("ERROR: ProxyServer: Failed to find route to server.com");
    }

    #[test]
    fn proxy_server_receives_terminal_response_from_hopper() {
        init_test_logging();
        let system = System::new("proxy_server_receives_response_from_hopper");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![ExpectedService::Nothing],
                protocol: ProxyProtocol::TLS,
                server_name: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let remaining_route = return_route_with_id(cryptde, 1234);
        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"16 bytes of data".to_vec(),
                sequence_number: 12345678,
                last_data: true,
            },
        };
        let first_expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("consuming")),
            remaining_route,
            client_response_payload,
            0,
        );
        let second_expired_cores_package = first_expired_cores_package.clone();
        let mut peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap();
        subject_addr.try_send(second_expired_cores_package).unwrap(); // should generate log because stream key is now unknown

        System::current().stop_with_code(0);
        system.run();

        let recording = dispatcher_log_arc.lock().unwrap();
        let record = recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, true);
        assert_eq!(record.data, b"16 bytes of data".to_vec());
        TestLogHandler::new().exists_log_containing(&format!("ERROR: ProxyServer: Discarding 16-byte packet 12345678 from an unrecognized stream key: {:?}", stream_key));
    }

    #[test]
    fn handle_client_response_payload_purges_stream_keys_for_terminal_response() {
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        subject.subs = Some(ProxyServerOutSubs::default());

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_key_routes.insert(
            stream_key.clone(),
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        subject
            .tunneled_hosts
            .insert(stream_key.clone(), "hostname".to_string());
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![],
                protocol: ProxyProtocol::HTTP,
                server_name: None,
            },
        );

        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket::new(vec![], 1, true),
        };

        let (dispatcher_mock, _, _) = make_recorder();

        let peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();

        subject.subs.as_mut().unwrap().dispatcher = peer_actors.dispatcher.from_dispatcher_client;

        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                client_response_payload.into(),
                0,
            );

        subject.handle_client_response_payload(&expired_cores_package);

        assert!(subject.keys_and_addrs.is_empty());
        assert!(subject.stream_key_routes.is_empty());
        assert!(subject.tunneled_hosts.is_empty());
    }

    #[test]
    fn proxy_server_receives_nonterminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_d_wallet.clone(),
                        rate_pack(101),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_e_wallet.clone(),
                        rate_pack(102),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_f_wallet.clone(),
                        rate_pack(103),
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name: None,
            },
        );
        let incoming_route_g_wallet = make_wallet("G Earning");
        let incoming_route_h_wallet = make_wallet("H Earning");
        let incoming_route_i_wallet = make_wallet("I Earning");
        subject.route_ids_to_return_routes.insert(
            1235,
            AddReturnRouteMessage {
                return_route_id: 1235,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_g_wallet.clone(),
                        rate_pack(104),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_h_wallet.clone(),
                        rate_pack(105),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_i_wallet.clone(),
                        rate_pack(106),
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let first_client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let first_exit_size = first_client_response_payload.sequenced_packet.data.len();
        let first_expired_cores_package: ExpiredCoresPackage<ClientResponsePayload> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                first_client_response_payload.into(),
                0,
            );
        let routing_size = first_expired_cores_package.payload_len;

        let second_client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"other data".to_vec(),
                sequence_number: 4322,
                last_data: false,
            },
        };
        let second_exit_size = second_client_response_payload.sequenced_packet.data.len();
        let second_expired_cores_package: ExpiredCoresPackage<ClientResponsePayload> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.5:1235").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1235),
                second_client_response_payload.into(),
                0,
            );
        let mut peer_actors = peer_actors_builder()
            .dispatcher(dispatcher_mock)
            .accountant(accountant)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(first_expired_cores_package.clone())
            .unwrap();
        subject_addr
            .try_send(second_expired_cores_package.clone())
            .unwrap();

        System::current().stop_with_code(0);
        system.run();

        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, false);
        assert_eq!(record.data, b"some data".to_vec());
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(1);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, false);
        assert_eq!(record.data, b"other data".to_vec());
        let accountant_recording = accountant_recording_arc.lock().unwrap();

        check_exit_report(
            &accountant_recording,
            0,
            &incoming_route_d_wallet,
            first_exit_size,
        );
        check_routing_report(
            &accountant_recording,
            1,
            &incoming_route_e_wallet,
            routing_size,
        );
        check_routing_report(
            &accountant_recording,
            2,
            &incoming_route_f_wallet,
            routing_size,
        );
        let routing_size = second_expired_cores_package.payload_len;
        check_exit_report(
            &accountant_recording,
            3,
            &incoming_route_g_wallet,
            second_exit_size,
        );
        check_routing_report(
            &accountant_recording,
            4,
            &incoming_route_h_wallet,
            routing_size,
        );
        check_routing_report(
            &accountant_recording,
            5,
            &incoming_route_i_wallet,
            routing_size,
        );
        assert_eq!(accountant_recording.len(), 6);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_dispatcher() {
        let system = System::new("proxy_server_receives_response_from_routing_services");

        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                dns_resolve_failure.into(),
                0,
            );

        let mut peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr
            .try_send(AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![ExpectedService::Exit(
                    exit_public_key.clone(),
                    exit_wallet,
                    rate_pack(10),
                )],
                protocol: ProxyProtocol::HTTP,
                server_name: Some("server.com".to_string()),
            })
            .unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop_with_code(0);
        system.run();

        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(
            TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: ServerImpersonatorHttp {}.dns_resolution_failure_response(
                    &exit_public_key,
                    Some("server.com".to_string()),
                ),
            },
            *record
        );
    }

    #[test]
    fn handle_dns_resolve_failure_reports_services_consumed() {
        let system = System::new("proxy_server_records_accounting");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_d_wallet.clone(),
                        rate_pack(101),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_e_wallet.clone(),
                        rate_pack(102),
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_f_wallet.clone(),
                        rate_pack(103),
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name: Some("server.com".to_string()),
            },
        );

        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure_payload = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                dns_resolve_failure_payload.into(),
                0,
            );
        let routing_size = expired_cores_package.payload_len;

        let mut peer_actors = peer_actors_builder().accountant(accountant).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();

        System::current().stop_with_code(0);
        system.run();

        let accountant_recording = accountant_recording_arc.lock().unwrap();
        check_exit_report(&accountant_recording, 0, &incoming_route_d_wallet, 0);
        check_routing_report(
            &accountant_recording,
            1,
            &incoming_route_e_wallet,
            routing_size,
        );
        check_routing_report(
            &accountant_recording,
            2,
            &incoming_route_f_wallet,
            routing_size,
        );
        assert_eq!(accountant_recording.len(), 3);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_neighborhood() {
        let system = System::new("test");

        let (neighborhood_mock, _, neighborhood_log_arc) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![ExpectedService::Exit(
                    exit_public_key.clone(),
                    exit_wallet,
                    rate_pack(10),
                )],
                protocol: ProxyProtocol::HTTP,
                server_name: Some("server.com".to_string()),
            },
        );

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                dns_resolve_failure.into(),
                0,
            );

        let mut peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();

        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        let record = neighborhood_recording.get_record::<NodeRecordMetadataMessage>(0);
        assert_eq!(
            record,
            &NodeRecordMetadataMessage::Desirable(exit_public_key, false)
        );
    }

    #[test]
    fn handle_dns_resolve_failure_logs_when_stream_key_be_gone_but_server_name_be_not() {
        init_test_logging();
        let system = System::new("test");

        let (neighborhood_mock, _, _) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));

        let stream_key = make_meaningless_stream_key();
        let return_route_id = 1234;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.route_ids_to_return_routes.insert(
            return_route_id,
            AddReturnRouteMessage {
                return_route_id,
                expected_services: vec![ExpectedService::Exit(
                    exit_public_key.clone(),
                    exit_wallet,
                    rate_pack(10),
                )],
                protocol: ProxyProtocol::HTTP,
                server_name: Some("server.com".to_string()),
            },
        );

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, return_route_id),
                dns_resolve_failure.into(),
                0,
            );

        let already_used_expired_cores_package = expired_cores_package.clone();

        let mut peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        subject_addr
            .try_send(already_used_expired_cores_package)
            .unwrap();

        System::current().stop_with_code(0);
        system.run();

        TestLogHandler::new().exists_log_containing(
            format!("Discarding DnsResolveFailure message for \"server.com\" from an unrecognized stream key {:?}", stream_key).as_str());
    }

    #[test]
    fn handle_dns_resolve_failure_logs_when_stream_key_and_server_name_are_both_missing() {
        init_test_logging();
        let system = System::new("test");

        let (neighborhood_mock, _, _) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));

        let stream_key = make_meaningless_stream_key();
        let return_route_id = 1234;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.route_ids_to_return_routes.insert(
            return_route_id,
            AddReturnRouteMessage {
                return_route_id,
                expected_services: vec![ExpectedService::Exit(
                    exit_public_key.clone(),
                    exit_wallet,
                    rate_pack(10),
                )],
                protocol: ProxyProtocol::HTTP,
                server_name: None,
            },
        );

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, return_route_id),
                dns_resolve_failure.into(),
                0,
            );

        let already_used_expired_cores_package = expired_cores_package.clone();

        let mut peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        subject_addr
            .try_send(already_used_expired_cores_package)
            .unwrap();

        System::current().stop_with_code(0);
        system.run();

        TestLogHandler::new().exists_log_containing(
            format!("Discarding DnsResolveFailure message for <unspecified server> from an unrecognized stream key {:?}", stream_key).as_str());
    }

    #[test]
    fn handle_dns_resolve_failure_purges_stream_keys() {
        let cryptde = cryptde();
        let (neighborhood_mock, _, _) = make_recorder();
        let (dispatcher_mock, _, _) = make_recorder();

        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        subject.subs = Some(ProxyServerOutSubs::default());

        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .dispatcher(dispatcher_mock)
            .build();
        subject.subs.as_mut().unwrap().update_node_record_metadata =
            peer_actors.neighborhood.update_node_record_metadata;
        subject.subs.as_mut().unwrap().dispatcher = peer_actors.dispatcher.from_dispatcher_client;

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject
            .tunneled_hosts
            .insert(stream_key.clone(), "tunneled host".to_string());
        subject.stream_key_routes.insert(
            stream_key.clone(),
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::OneWay(vec![]),
            },
        );
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![ExpectedService::Nothing, ExpectedService::Nothing],
                protocol: ProxyProtocol::HTTP,
                server_name: None,
            },
        );
        let dns_resolve_failure = DnsResolveFailure::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                dns_resolve_failure.into(),
                0,
            );

        subject.handle_dns_resolve_failure(&expired_cores_package);

        assert!(subject.keys_and_addrs.is_empty());
        assert!(subject.stream_key_routes.is_empty());
        assert!(subject.tunneled_hosts.is_empty());
    }

    #[test]
    #[should_panic(expected = "Dispatcher unbound in ProxyServer")]
    fn panics_if_dispatcher_is_unbound() {
        let system = System::new("panics_if_dispatcher_is_unbound");
        let cryptde = cryptde();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(cryptde, false, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let remaining_route = return_route_with_id(cryptde, 4321);
        subject.route_ids_to_return_routes.insert(
            4321,
            AddReturnRouteMessage {
                return_route_id: 4321,
                expected_services: vec![ExpectedService::Nothing],
                protocol: ProxyProtocol::HTTP,
                server_name: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();

        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"data".to_vec(),
                sequence_number: 0,
                last_data: true,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("consuming")),
            remaining_route,
            client_response_payload,
            0,
        );

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(expected = "Neighborhood unbound in ProxyServer")]
    fn panics_if_hopper_is_unbound() {
        let system = System::new("panics_if_hopper_is_unbound");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let subject = ProxyServer::new(cryptde(), false, None);
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
        let subject_addr: Addr<ProxyServer> = subject.start();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    fn report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unrecognized(
    ) {
        init_test_logging();
        let cryptde = cryptde();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unrecognized");
        let mut subject = ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key, SocketAddr::from_str("1.2.3.4:5678").unwrap());
        let subject_addr: Addr<ProxyServer> = subject.start();
        let mut peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("irrelevant")),
            return_route_with_id(cryptde, 1234),
            client_response_payload,
            0,
        );
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing("ERROR: ProxyServer: Can't report services consumed: received response with bogus return-route ID 1234. Ignoring");
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unreadable(
    ) {
        init_test_logging();
        let cryptde = cryptde();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unreadable");
        let mut subject = ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let stream_key = make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key, SocketAddr::from_str("1.2.3.4:5678").unwrap());
        let subject_addr: Addr<ProxyServer> = subject.start();
        let mut peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("irrelevant")),
            Route {
                hops: vec![make_cover_hop(cryptde), CryptData::new(&[0])],
            },
            client_response_payload,
            0,
        );
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: ProxyServer: Can't report services consumed: Decryption error: InvalidKey(\"Could not decrypt with",
        );
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn return_route_ids_expire_when_instructed() {
        init_test_logging();
        let cryptde = cryptde();
        let stream_key = make_meaningless_stream_key();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_does_not_exist");
            let mut subject =
                ProxyServer::new(cryptde, true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
            subject.route_ids_to_return_routes = TtlHashMap::new(Duration::from_millis(250));
            subject
                .keys_and_addrs
                .insert(stream_key, SocketAddr::from_str("1.2.3.4:5678").unwrap());
            subject.route_ids_to_return_routes.insert(
                1234,
                AddReturnRouteMessage {
                    return_route_id: 1234,
                    expected_services: vec![],
                    protocol: ProxyProtocol::TLS,
                    server_name: None,
                },
            );
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder().build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            tx.send(subject_addr).unwrap();

            system.run();
        });

        let subject_addr = rx.recv().unwrap();

        thread::sleep(Duration::from_millis(300));

        let client_response_payload = ClientResponsePayload {
            version: ClientResponsePayload::version(),
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("irrelevant")),
            return_route_with_id(cryptde, 1234),
            client_response_payload,
            0,
        );
        subject_addr.try_send(expired_cores_package).unwrap();

        TestLogHandler::new().await_log_containing("ERROR: ProxyServer: Can't report services consumed: received response with bogus return-route ID 1234. Ignoring", 1000);
    }

    #[test]
    fn handle_stream_shutdown_msg_handles_unknown_peer_addr() {
        let mut subject = ProxyServer::new(cryptde(), true, None);
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject.stream_key_routes.insert(
            unaffected_stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        subject
            .tunneled_hosts
            .insert(unaffected_stream_key, "blah".to_string());

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: true,
        });

        // Subject is unbound but didn't panic; therefore, no attempt to send to Hopper: perfect!
        assert!(subject
            .keys_and_addrs
            .a_to_b(&unaffected_stream_key)
            .is_some());
        assert!(subject
            .stream_key_routes
            .contains_key(&unaffected_stream_key));
        assert!(subject.tunneled_hosts.contains_key(&unaffected_stream_key));
    }

    #[test]
    fn handle_stream_shutdown_msg_reports_to_counterpart_through_tunnel_when_necessary() {
        let system = System::new("test");
        let mut subject =
            ProxyServer::new(cryptde(), true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), affected_socket_addr);
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), DEFAULT_CHAIN_ID);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(affected_stream_key, affected_socket_addr);
        subject.stream_key_routes.insert(
            unaffected_stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        let affected_route = Route::round_trip(
            RouteSegment::new(
                vec![cryptde().public_key(), affected_cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![affected_cryptde.public_key(), cryptde().public_key()],
                Component::ProxyServer,
            ),
            cryptde(),
            Some(make_paying_wallet(b"consuming")),
            1234,
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();
        let affected_expected_services = vec![ExpectedService::Exit(
            affected_cryptde.public_key().clone(),
            make_paying_wallet(b"1234"),
            DEFAULT_RATE_PACK,
        )];
        subject.stream_key_routes.insert(
            affected_stream_key,
            RouteQueryResponse {
                route: affected_route.clone(),
                expected_services: ExpectedServices::RoundTrip(
                    affected_expected_services,
                    vec![],
                    1234,
                ),
            },
        );
        subject
            .tunneled_hosts
            .insert(unaffected_stream_key, "blah".to_string());
        subject
            .tunneled_hosts
            .insert(affected_stream_key, "tunneled.com".to_string());
        let subject_addr = subject.start();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .hopper(hopper)
            .proxy_server(proxy_server)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(StreamShutdownMsg {
                peer_addr: affected_socket_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: TLS_PORT,
                    sequence_number: 1234,
                }),
                report_to_counterpart: true,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record.route, affected_route);
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(payload) => assert_eq!(
                payload,
                ClientRequestPayload {
                    version: DataVersion::new(0, 0).unwrap(),
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: Some(String::from("tunneled.com")),
                    target_port: 443,
                    protocol: ProxyProtocol::TLS,
                    originator_public_key: cryptde().public_key().clone(),
                }
            ),
            other => panic!("Wrong payload type: {:?}", other),
        }
        let recording = proxy_server_recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(recording.len() - 1);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr: affected_socket_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: 0,
                    sequence_number: 0
                }),
                report_to_counterpart: false
            }
        );
    }

    #[test]
    fn handle_stream_shutdown_msg_reports_to_counterpart_without_tunnel_when_necessary() {
        let system = System::new("test");
        let mut subject =
            ProxyServer::new(cryptde(), true, Some(STANDARD_CONSUMING_WALLET_BALANCE));
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), affected_socket_addr);
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), DEFAULT_CHAIN_ID);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(affected_stream_key, affected_socket_addr);
        subject.stream_key_routes.insert(
            unaffected_stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        let affected_route = Route::round_trip(
            RouteSegment::new(
                vec![cryptde().public_key(), affected_cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![affected_cryptde.public_key(), cryptde().public_key()],
                Component::ProxyServer,
            ),
            cryptde(),
            Some(make_paying_wallet(b"consuming")),
            1234,
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();
        let affected_expected_services = vec![ExpectedService::Exit(
            affected_cryptde.public_key().clone(),
            make_paying_wallet(b"1234"),
            DEFAULT_RATE_PACK,
        )];
        subject.stream_key_routes.insert(
            affected_stream_key,
            RouteQueryResponse {
                route: affected_route.clone(),
                expected_services: ExpectedServices::RoundTrip(
                    affected_expected_services,
                    vec![],
                    1234,
                ),
            },
        );
        let subject_addr = subject.start();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .hopper(hopper)
            .proxy_server(proxy_server)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(StreamShutdownMsg {
                peer_addr: affected_socket_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: HTTP_PORT,
                    sequence_number: 1234,
                }),
                report_to_counterpart: true,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record.route, affected_route);
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(payload) => assert_eq!(
                payload,
                ClientRequestPayload {
                    version: DataVersion::new(0, 0).unwrap(),
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: None,
                    target_port: HTTP_PORT,
                    protocol: ProxyProtocol::HTTP,
                    originator_public_key: cryptde().public_key().clone(),
                }
            ),
            other => panic!("Wrong payload type: {:?}", other),
        }
        let recording = proxy_server_recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(recording.len() - 1);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr: affected_socket_addr,
                stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                    reception_port: 0,
                    sequence_number: 0
                }),
                report_to_counterpart: false
            }
        );
    }

    #[test]
    fn handle_stream_shutdown_msg_does_not_report_to_counterpart_when_unnecessary() {
        let mut subject = ProxyServer::new(cryptde(), true, None);
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(cryptde().public_key().clone(), affected_socket_addr);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(affected_stream_key, affected_socket_addr);
        subject.stream_key_routes.insert(
            unaffected_stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        subject.stream_key_routes.insert(
            affected_stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 1234),
            },
        );
        subject
            .tunneled_hosts
            .insert(unaffected_stream_key, "blah".to_string());
        subject
            .tunneled_hosts
            .insert(affected_stream_key, "blah".to_string());

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: affected_socket_addr,
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: false,
        });

        // Subject is unbound but didn't panic; therefore, no attempt to send to Hopper: perfect!
        assert!(subject
            .keys_and_addrs
            .a_to_b(&unaffected_stream_key)
            .is_some());
        assert!(subject
            .stream_key_routes
            .contains_key(&unaffected_stream_key));
        assert!(subject.tunneled_hosts.contains_key(&unaffected_stream_key));
        assert!(subject
            .keys_and_addrs
            .a_to_b(&affected_stream_key)
            .is_none());
        assert!(!subject.stream_key_routes.contains_key(&affected_stream_key));
        assert!(!subject.tunneled_hosts.contains_key(&affected_stream_key));
    }

    #[test]
    #[should_panic(
        expected = "ProxyServer should never get ShutdownStreamMsg about clandestine stream"
    )]
    fn handle_stream_shutdown_complains_about_clandestine_message() {
        let system = System::new("test");
        let subject = ProxyServer::new(cryptde(), true, None);
        let subject_addr = subject.start();

        subject_addr
            .try_send(StreamShutdownMsg {
                peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                stream_type: RemovedStreamType::Clandestine,
                report_to_counterpart: false,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
    }
}
