// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::proxy_server::client_request_payload_factory::ClientRequestPayloadFactory;
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::protocol_pack::{for_protocol, ProtocolPack};
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::bidi_hashmap::BidiHashMap;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::Endpoint;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::hopper::{ExpiredCoresPackage, IncipientCoresPackage};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::neighborhood::ExpectedServices;
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{ExpectedService, NodeRecordMetadataMessage};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{ClientResponsePayload, DnsResolveFailure};
use crate::sub_lib::proxy_server::AddReturnRouteMessage;
use crate::sub_lib::proxy_server::ClientRequestPayload;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::route::Route;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::ttl_hashmap::TtlHashMap;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MailboxError;
use actix::Recipient;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use tokio;
use tokio::prelude::Future;

pub const RETURN_ROUTE_TTL: Duration = Duration::from_secs(120);

pub struct ProxyServer {
    dispatcher: Option<Recipient<TransmitDataMsg>>,
    hopper: Option<Recipient<IncipientCoresPackage>>,
    accountant_exit: Option<Recipient<ReportExitServiceConsumedMessage>>,
    accountant_routing: Option<Recipient<ReportRoutingServiceConsumedMessage>>,
    route_source: Option<Recipient<RouteQueryMessage>>,
    update_node_record_metadata: Option<Recipient<NodeRecordMetadataMessage>>,
    add_return_route: Option<Recipient<AddReturnRouteMessage>>,
    client_request_payload_factory: ClientRequestPayloadFactory,
    stream_key_factory: Box<dyn StreamKeyFactory>,
    keys_and_addrs: BidiHashMap<StreamKey, SocketAddr>,
    tunneled_hosts: HashMap<StreamKey, String>,
    is_decentralized: bool,
    // TODO: This should be replaced by something more general and configurable.
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
        self.dispatcher = Some(msg.peer_actors.dispatcher.from_dispatcher_client);
        self.hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        self.accountant_exit = Some(msg.peer_actors.accountant.report_exit_service_consumed);
        self.accountant_routing = Some(msg.peer_actors.accountant.report_routing_service_consumed);
        self.route_source = Some(msg.peer_actors.neighborhood.route_query);
        self.update_node_record_metadata =
            Some(msg.peer_actors.neighborhood.update_node_record_metadata);
        self.add_return_route = Some(msg.peer_actors.proxy_server.add_return_route);
    }
}

impl Handler<InboundClientData> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        if msg.is_connect() {
            self.tls_connect(&msg);
            self.browser_proxy_sequence_offset = true;
        } else {
            self.handle_normal_client_data(msg);
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

impl Handler<ExpiredCoresPackage<DnsResolveFailure>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<DnsResolveFailure>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
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
        let response = msg.payload;
        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(socket_addr) => {
                self.update_node_record_metadata
                    .as_ref()
                    .expect("Neighborhood is unbound in ProxyServer")
                    .try_send(NodeRecordMetadataMessage::Desirable(
                        exit_public_key.clone(),
                        false,
                    ))
                    .expect("Neighborhood is dead");

                self.report_response_services_consumed(&return_route_info, 0, msg.payload_len);

                self.dispatcher
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(socket_addr),
                        last_data: true,
                        sequence_number: Some(0), // DNS resolution errors always happen on the first request
                        data: for_protocol(return_route_info.protocol)
                            .server_impersonator()
                            .dns_resolution_failure_response(
                                &exit_public_key,
                                return_route_info.server_name.clone(),
                            ),
                    })
                    .expect("Dispatcher is dead");
                self.keys_and_addrs.remove_a(&response.stream_key);
            }
            None => {
                let server_name = match &return_route_info.server_name {
                    Some(name) => format!("\"{}\"", name),
                    None => "<unspecified server>".to_string(),
                };
                self.logger.error(format!(
                    "Discarding DnsResolveFailure message for {} from an unrecognized stream key {:?}",
                    server_name,
                    &response.stream_key
                ))
            }
        }
    }
}

impl Handler<ExpiredCoresPackage<ClientResponsePayload>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<ClientResponsePayload>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let payload_data_len = msg.payload_len;
        let response = msg.payload;
        self.logger.debug(format!(
            "Relaying {}-byte ExpiredCoresPackage payload from Hopper to Dispatcher",
            response.sequenced_packet.data.len()
        ));
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
                self.dispatcher
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(socket_addr),
                        last_data,
                        sequence_number,
                        data: response.sequenced_packet.data.clone(),
                    })
                    .expect("Dispatcher is dead");
                if last_data {
                    self.keys_and_addrs.remove_b(&socket_addr);
                }
            }
            None => self.logger.error(format!(
                "Discarding {}-byte packet {} from an unrecognized stream key: {:?}",
                response.sequenced_packet.data.len(),
                response.sequenced_packet.sequence_number,
                response.stream_key
            )),
        }
    }
}

impl ProxyServer {
    pub fn new(cryptde: &'static dyn CryptDE, is_decentralized: bool) -> ProxyServer {
        ProxyServer {
            dispatcher: None,
            hopper: None,
            accountant_exit: None,
            accountant_routing: None,
            route_source: None,
            update_node_record_metadata: None,
            add_return_route: None,
            client_request_payload_factory: ClientRequestPayloadFactory::new(),
            stream_key_factory: Box::new(StreamKeyFactoryReal {}),
            keys_and_addrs: BidiHashMap::new(),
            tunneled_hosts: HashMap::new(),
            is_decentralized,
            cryptde,
            logger: Logger::new("Proxy Server"),
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
        }
    }

    fn tls_connect(&mut self, msg: &InboundClientData) {
        let http_data = HttpProtocolPack {}.find_host(&msg.data.clone().into());
        match http_data {
            Some(ref host) if host.port == Some(443) => {
                let stream_key = self.make_stream_key(&msg);
                self.tunneled_hosts.insert(stream_key, host.name.clone());
                self.dispatcher
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(msg.peer_addr),
                        last_data: false,
                        sequence_number: msg.sequence_number,
                        data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                    })
                    .expect("Dispatcher is dead");
            }
            _ => {
                self.dispatcher
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
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

    fn handle_normal_client_data(&mut self, msg: InboundClientData) {
        let cryptde = self.cryptde.clone();
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
        let accountant_exit_sub = self
            .accountant_exit
            .as_ref()
            .expect("Accountant unbound in ProxyServer")
            .clone();
        let accountant_routing_sub = self
            .accountant_routing
            .as_ref()
            .expect("Accountant unbound in ProxyServer")
            .clone();
        let dispatcher = self
            .dispatcher
            .as_ref()
            .expect("Dispatcher unbound in ProxyServer")
            .clone();
        let add_return_route_sub = self
            .add_return_route
            .as_ref()
            .expect("ProxyServer unbound in ProxyServer")
            .clone();
        let source_addr = msg.peer_addr;
        let payload = match self.make_payload(msg) {
            Ok(payload) => payload,
            Err(_e) => {
                return;
            }
        };
        let logger = self.logger.clone();
        let minimum_hop_count = if self.is_decentralized { 3 } else { 0 };
        tokio::spawn(
            route_source
                .send(RouteQueryMessage::data_indefinite_route_request(
                    minimum_hop_count,
                ))
                .then(move |route_result| {
                    ProxyServer::try_transmit_to_hopper(
                        cryptde,
                        &hopper,
                        route_result,
                        payload,
                        logger,
                        source_addr,
                        &dispatcher,
                        &accountant_exit_sub,
                        &accountant_routing_sub,
                        &add_return_route_sub,
                    )
                }),
        );
    }

    fn make_stream_key(&mut self, ibcd: &InboundClientData) -> StreamKey {
        match self.keys_and_addrs.b_to_a(&ibcd.peer_addr) {
            Some(stream_key) => stream_key,
            None => {
                let stream_key = self
                    .stream_key_factory
                    .make(&self.cryptde.public_key(), ibcd.peer_addr);
                self.keys_and_addrs.insert(stream_key, ibcd.peer_addr);
                stream_key
            }
        }
    }

    fn make_payload(&mut self, ibcd: InboundClientData) -> Result<ClientRequestPayload, ()> {
        let stream_key = self.make_stream_key(&ibcd);
        let tunnelled_host = self.tunneled_hosts.get(&stream_key);
        let new_ibcd = match tunnelled_host {
            Some(_) => InboundClientData {
                reception_port: Some(443),
                ..ibcd
            },
            None => ibcd.clone(),
        };
        match self.client_request_payload_factory.make(
            &new_ibcd,
            stream_key,
            self.cryptde,
            &self.logger,
        ) {
            None => {
                self.logger
                    .error(format!("Couldn't create ClientRequestPayload"));
                Err(())
            }
            Some(payload) => match tunnelled_host {
                Some(hostname) => Ok(ClientRequestPayload {
                    target_hostname: Some(hostname.clone()),
                    ..payload
                }),
                None => Ok(payload),
            },
        }
    }

    fn try_transmit_to_hopper(
        cryptde: &'static dyn CryptDE,
        hopper: &Recipient<IncipientCoresPackage>,
        route_result: Result<Option<RouteQueryResponse>, MailboxError>,
        payload: ClientRequestPayload,
        logger: Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
        accountant_exit_sub: &Recipient<ReportExitServiceConsumedMessage>,
        accountant_routing_sub: &Recipient<ReportRoutingServiceConsumedMessage>,
        add_return_route_sub: &Recipient<AddReturnRouteMessage>,
    ) -> Result<(), ()> {
        match route_result {
            Ok(Some(route_query_response)) => match route_query_response.expected_services {
                ExpectedServices::RoundTrip(over, back, return_route_id) => {
                    let return_route_info = AddReturnRouteMessage {
                        return_route_id,
                        expected_services: back.clone(),
                        protocol: payload.protocol,
                        server_name: payload.target_hostname.clone(),
                    };
                    logger.debug(format!(
                        "Adding expectant return route info: {:?}",
                        return_route_info
                    ));
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
                    );
                }
                _ => panic!("Expected RoundTrip ExpectedServices but got OneWay"),
            },
            Ok(None) => {
                ProxyServer::handle_route_failure(payload, &logger, source_addr, dispatcher);
            }
            Err(e) => {
                let msg = format!("Neighborhood refused to answer route request: {}", e);
                logger.error(msg);
            }
        };
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
            logger.debug("No routing services requested.".to_string());
        }
        earning_wallets_and_rates
            .into_iter()
            .for_each(|earning_wallet_and_rate| {
                let report_routing_service_consumed = ReportRoutingServiceConsumedMessage {
                    earning_wallet: earning_wallet_and_rate.0.clone(),
                    payload_size,
                    service_rate: earning_wallet_and_rate.1.routing_service_rate,
                    byte_rate: earning_wallet_and_rate.1.routing_byte_rate,
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
            Some((earning_wallet, rate_pack)) => {
                let payload_size = payload.sequenced_packet.data.len();
                let report_exit_service_consumed_message = ReportExitServiceConsumedMessage {
                    earning_wallet: earning_wallet.clone(),
                    payload_size,
                    service_rate: rate_pack.exit_service_rate,
                    byte_rate: rate_pack.exit_byte_rate,
                };
                accountant_exit_sub
                    .try_send(report_exit_service_consumed_message)
                    .expect("Accountant is dead");
            }
            None => logger.debug("No exit service requested.".to_string()),
        };
    }

    fn transmit_to_hopper(
        cryptde: &'static dyn CryptDE,
        hopper: &Recipient<IncipientCoresPackage>,
        payload: ClientRequestPayload,
        route: &Route,
        expected_services: Vec<ExpectedService>,
        logger: &Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
        accountant_routing_sub: &Recipient<ReportRoutingServiceConsumedMessage>,
    ) {
        let destination_key_opt = if !expected_services.is_empty()
            & &expected_services
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
                logger.debug(format!(
                    "transmit to hopper with destination key {:?}",
                    payload_destination_key
                ));
                let pkg = IncipientCoresPackage::new(
                    cryptde,
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
        logger.error(format!("Failed to find route to {}", target_hostname));
    }

    fn send_route_failure(
        payload: ClientRequestPayload,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) {
        let data = for_protocol(payload.protocol)
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
                self.logger
                    .error(format!("Can't report services consumed: {}", e));
                return None;
            }
        };
        match self.route_ids_to_return_routes.get(&return_route_id) {
            Some(rri) => Some(rri),
            None => {
                self.logger.error(format!("Can't report services consumed: received response with bogus return-route ID {}. Ignoring", return_route_id));
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
                ExpectedService::Exit(_, wallet, rate_pack) => self
                    .accountant_exit
                    .as_ref()
                    .expect("ProxyServer unbound")
                    .try_send(ReportExitServiceConsumedMessage {
                        earning_wallet: wallet.clone(),
                        payload_size: exit_size,
                        service_rate: rate_pack.exit_service_rate,
                        byte_rate: rate_pack.exit_byte_rate,
                    })
                    .expect("Accountant is dead"),
                ExpectedService::Routing(_, wallet, rate_pack) => self
                    .accountant_routing
                    .as_ref()
                    .expect("ProxyServer unbound")
                    .try_send(ReportRoutingServiceConsumedMessage {
                        earning_wallet: wallet.clone(),
                        payload_size: routing_size,
                        service_rate: rate_pack.routing_service_rate,
                        byte_rate: rate_pack.routing_byte_rate,
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
    use crate::persistent_configuration::{HTTP_PORT, TLS_PORT};
    use crate::proxy_server::protocol_pack::ServerImpersonator;
    use crate::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
    use crate::proxy_server::server_impersonator_tls::ServerImpersonatorTls;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::cryptde::CryptData;
    use crate::sub_lib::cryptde::{encodex, PlainData};
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::ExpectedService;
    use crate::sub_lib::neighborhood::ExpectedServices;
    use crate::sub_lib::neighborhood::RatePack;
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
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::cryptde;
    use crate::test_utils::test_utils::make_meaningless_route;
    use crate::test_utils::test_utils::make_meaningless_stream_key;
    use crate::test_utils::test_utils::rate_pack;
    use crate::test_utils::test_utils::rate_pack_exit;
    use crate::test_utils::test_utils::rate_pack_exit_byte;
    use crate::test_utils::test_utils::rate_pack_routing;
    use crate::test_utils::test_utils::rate_pack_routing_byte;
    use crate::test_utils::test_utils::zero_hop_route_response;
    use actix::System;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::thread;

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

    fn return_route_with_id(cryptde: &CryptDE, return_route_id: u32) -> Route {
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
                consuming_wallet: None,
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
        rate_pack: &RatePack,
    ) {
        assert_eq!(
            accountant_recording.get_record::<ReportExitServiceConsumedMessage>(idx),
            &ReportExitServiceConsumedMessage {
                earning_wallet: wallet.clone(),
                payload_size,
                service_rate: rate_pack.exit_service_rate,
                byte_rate: rate_pack.exit_byte_rate,
            }
        );
    }

    fn check_routing_report(
        accountant_recording: &MutexGuard<Recording>,
        idx: usize,
        wallet: &Wallet,
        payload_size: usize,
        rate_pack: &RatePack,
    ) {
        assert_eq!(
            accountant_recording.get_record::<ReportRoutingServiceConsumedMessage>(idx),
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: wallet.clone(),
                payload_size,
                service_rate: rate_pack.routing_service_rate,
                byte_rate: rate_pack.routing_byte_rate,
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
            let mut subject = ProxyServer::new(cryptde, false);
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
        let mut make_parameters = make_parameters_arc_a.lock().unwrap();
        assert_eq!(
            make_parameters.remove(0),
            (cryptde.public_key().clone(), socket_addr)
        );
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(record, &RouteQueryMessage::data_indefinite_route_request(0));
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
            let mut subject = ProxyServer::new(cryptde, false);
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
        let mut subject = ProxyServer::new(cryptde, false);
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
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
        };

        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
            let mut subject = ProxyServer::new(cryptde, false);
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
            let mut subject = ProxyServer::new(cryptde, false);
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
            let mut subject = ProxyServer::new(cryptde, false);
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
    fn proxy_server_receives_http_request_from_dispatcher_then_sends_multihop_cores_package_to_hopper(
    ) {
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("consuming wallet");
        let earning_wallet = Wallet::new("earning wallet");
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
            let mut subject = ProxyServer::new(cryptde, true);
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
    fn proxy_server_sends_message_to_accountant_for_request_routing_service_consumed() {
        let cryptde = cryptde();
        let exit_earning_wallet = Wallet::new("exit earning wallet");
        let route_1_earning_wallet = Wallet::new("route 1 earning wallet");
        let route_2_earning_wallet = Wallet::new("route 2 earning wallet");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, accountant_awaiter, accountant_log_arc) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
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
            let system = System::new(
                "proxy_server_sends_message_to_accountant_for_routing_service_consumed",
            );
            let mut subject = ProxyServer::new(cryptde, true);
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

        let exit_key = PublicKey::new(&[3]);
        let payload = MessageType::ClientRequest(ClientRequestPayload {
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: exit_key,
        });
        let payload_ser = PlainData::from(serde_cbor::ser::to_vec(&payload).unwrap());
        let payload_enc = cryptde.encode(&cryptde.public_key(), &payload_ser).unwrap();

        accountant_awaiter.await_message_count(3);
        let recording = accountant_log_arc.lock().unwrap();
        let record = recording.get_record::<ReportRoutingServiceConsumedMessage>(1);
        assert_eq!(
            record,
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: route_1_earning_wallet,
                payload_size: payload_enc.len(),
                service_rate: rate_pack_routing(101),
                byte_rate: rate_pack_routing_byte(101),
            }
        );
        let record = recording.get_record::<ReportRoutingServiceConsumedMessage>(2);
        assert_eq!(
            record,
            &ReportRoutingServiceConsumedMessage {
                earning_wallet: route_2_earning_wallet,
                payload_size: payload_enc.len(),
                service_rate: rate_pack_routing(102),
                byte_rate: rate_pack_routing_byte(102),
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
            let mut subject = ProxyServer::new(cryptde, true);
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
            .await_log_containing("DEBUG: Proxy Server: No routing services requested.", 1000);

        assert_eq!(accountant_log_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn proxy_server_sends_message_to_accountant_for_request_exit_service_consumed() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning wallet");
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
            let mut subject = ProxyServer::new(cryptde, true);
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
                service_rate: rate_pack_exit(101),
                byte_rate: rate_pack_exit_byte(101),
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
            let mut subject = ProxyServer::new(cryptde, true);
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
            .await_log_containing("DEBUG: Proxy Server: No exit service requested.", 1000);

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
            let subject = ProxyServer::new(cryptde, true);
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
            .exists_log_containing("ERROR: Proxy Server: Failed to find route to nowhere.com");
    }

    #[test]
    #[should_panic(expected = "Expected RoundTrip ExpectedServices but got OneWay")]
    fn proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route() {
        let _system = System::new("proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route");
        let peer_actors = peer_actors_builder().build();

        let cryptde = cryptde();
        let route_result = Ok(Some(RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::OneWay(vec![
                ExpectedService::Nothing,
                ExpectedService::Routing(
                    PublicKey::new(&[1]),
                    Wallet::new("earning wallet 1"),
                    rate_pack(101),
                ),
                ExpectedService::Routing(
                    PublicKey::new(&[2]),
                    Wallet::new("earning wallet 2"),
                    rate_pack(102),
                ),
                ExpectedService::Exit(
                    PublicKey::new(&[3]),
                    Wallet::new("exit earning wallet"),
                    rate_pack(103),
                ),
            ]),
        }));
        let payload = ClientRequestPayload {
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
            cryptde,
            &peer_actors.hopper.from_hopper_client,
            route_result,
            payload,
            logger,
            source_addr,
            &peer_actors.dispatcher.from_dispatcher_client,
            &peer_actors.accountant.report_exit_service_consumed,
            &peer_actors.accountant.report_routing_service_consumed,
            &peer_actors.proxy_server.add_return_route,
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
            let subject = ProxyServer::new(cryptde, true);
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
            let mut subject = ProxyServer::new(cryptde, false);
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
            let mut subject = ProxyServer::new(cryptde, false);
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
            let mut subject = ProxyServer::new(cryptde, false);
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
            let subject = ProxyServer::new(cryptde, false);
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
            .exists_log_containing("ERROR: Proxy Server: Failed to find route to server.com");
    }

    #[test]
    fn proxy_server_receives_terminal_response_from_hopper() {
        init_test_logging();
        let system = System::new("proxy_server_receives_response_from_hopper");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);
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
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"16 bytes of data".to_vec(),
                sequence_number: 12345678,
                last_data: true,
            },
        };
        let first_expired_cores_package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("consuming")),
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
        TestLogHandler::new().exists_log_containing(&format!("ERROR: Proxy Server: Discarding 16-byte packet 12345678 from an unrecognized stream key: {:?}", stream_key));
    }

    #[test]
    fn proxy_server_receives_nonterminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_response_from_hopper");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = Wallet::new("D Earning");
        let incoming_route_e_wallet = Wallet::new("E Earning");
        let incoming_route_f_wallet = Wallet::new("F Earning");
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
        let incoming_route_g_wallet = Wallet::new("G Earning");
        let incoming_route_h_wallet = Wallet::new("H Earning");
        let incoming_route_i_wallet = Wallet::new("I Earning");
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
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
                return_route_with_id(cryptde, 1234),
                first_client_response_payload.into(),
                0,
            );
        let routing_size = first_expired_cores_package.payload_len;

        let second_client_response_payload = ClientResponsePayload {
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
                IpAddr::from_str("1.2.3.5").unwrap(),
                Some(Wallet::new("irrelevant")),
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
            &rate_pack(101),
        );
        check_routing_report(
            &accountant_recording,
            1,
            &incoming_route_e_wallet,
            routing_size,
            &rate_pack(102),
        );
        check_routing_report(
            &accountant_recording,
            2,
            &incoming_route_f_wallet,
            routing_size,
            &rate_pack(103),
        );
        let routing_size = second_expired_cores_package.payload_len;
        check_exit_report(
            &accountant_recording,
            3,
            &incoming_route_g_wallet,
            second_exit_size,
            &rate_pack(104),
        );
        check_routing_report(
            &accountant_recording,
            4,
            &incoming_route_h_wallet,
            routing_size,
            &rate_pack(105),
        );
        check_routing_report(
            &accountant_recording,
            5,
            &incoming_route_i_wallet,
            routing_size,
            &rate_pack(106),
        );
        assert_eq!(accountant_recording.len(), 6);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_dispatcher() {
        let system = System::new("proxy_server_receives_response_from_routing_services");

        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = Wallet::new("exit wallet");

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure { stream_key };

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
        let mut subject = ProxyServer::new(cryptde, false);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = Wallet::new("D Earning");
        let incoming_route_e_wallet = Wallet::new("E Earning");
        let incoming_route_f_wallet = Wallet::new("F Earning");
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
        let dns_resolve_failure_payload = DnsResolveFailure { stream_key };

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
        check_exit_report(
            &accountant_recording,
            0,
            &incoming_route_d_wallet,
            0,
            &rate_pack(101),
        );
        check_routing_report(
            &accountant_recording,
            1,
            &incoming_route_e_wallet,
            routing_size,
            &rate_pack(102),
        );
        check_routing_report(
            &accountant_recording,
            2,
            &incoming_route_f_wallet,
            routing_size,
            &rate_pack(103),
        );
        assert_eq!(accountant_recording.len(), 3);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_neighborhood() {
        let system = System::new("test");

        let (neighborhood_mock, _, neighborhood_log_arc) = make_recorder();

        let cryptde = cryptde();
        let mut subject = ProxyServer::new(cryptde, false);

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = Wallet::new("exit wallet");
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

        let dns_resolve_failure = DnsResolveFailure { stream_key };

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
        let mut subject = ProxyServer::new(cryptde, false);

        let stream_key = make_meaningless_stream_key();
        let return_route_id = 1234;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = Wallet::new("exit wallet");
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

        let dns_resolve_failure = DnsResolveFailure { stream_key };

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
        let mut subject = ProxyServer::new(cryptde, false);

        let stream_key = make_meaningless_stream_key();
        let return_route_id = 1234;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());

        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = Wallet::new("exit wallet");
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

        let dns_resolve_failure = DnsResolveFailure { stream_key };

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure> =
            ExpiredCoresPackage::new(
                IpAddr::from_str("1.2.3.4").unwrap(),
                Some(Wallet::new("irrelevant")),
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
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"data".to_vec(),
                sequence_number: 0,
                last_data: true,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("consuming")),
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
        let mut subject = ProxyServer::new(cryptde, true);
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
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("irrelevant")),
            return_route_with_id(cryptde, 1234),
            client_response_payload,
            0,
        );
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
        TestLogHandler::new().exists_log_containing("ERROR: Proxy Server: Can't report services consumed: received response with bogus return-route ID 1234. Ignoring");
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
        let mut subject = ProxyServer::new(cryptde, true);
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
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("irrelevant")),
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
            "ERROR: Proxy Server: Can't report services consumed: Decryption error: InvalidKey(\"Could not decrypt with",
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
            let mut subject = ProxyServer::new(cryptde, true);
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
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            Some(Wallet::new("irrelevant")),
            return_route_with_id(cryptde, 1234),
            client_response_payload,
            0,
        );
        subject_addr.try_send(expired_cores_package).unwrap();

        TestLogHandler::new().await_log_containing("ERROR: Proxy Server: Can't report services consumed: received response with bogus return-route ID 1234. Ignoring", 1000);
    }
}
