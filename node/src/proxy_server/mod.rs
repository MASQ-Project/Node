// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod client_request_payload_factory;
pub mod http_protocol_pack;
pub mod protocol_pack;
pub mod server_impersonator_http;
pub mod server_impersonator_tls;
pub mod tls_protocol_pack;
pub mod utils;

use crate::proxy_server::client_request_payload_factory::{
    ClientRequestPayloadFactory, ClientRequestPayloadFactoryReal,
};
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::protocol_pack::{from_ibcd, from_protocol, ProtocolPack};
use crate::proxy_server::utils::local::{TTHCommonArgs, TTHLocalArgs, TTHMovableArgs};
use crate::proxy_server::ExitServiceSearch::{Definite, ZeroHop};
use crate::stream_messages::NonClandestineAttributes;
use crate::stream_messages::RemovedStreamType;
use crate::sub_lib::accountant::RoutingServiceConsumed;
use crate::sub_lib::accountant::{ExitServiceConsumed, ReportServicesConsumedMessage};
use crate::sub_lib::bidi_hashmap::BidiHashMap;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::dispatcher::{Endpoint, StreamShutdownMsg};
use crate::sub_lib::hopper::{ExpiredCoresPackage, IncipientCoresPackage};
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{ExpectedService, NodeRecordMetadataMessage};
use crate::sub_lib::neighborhood::{ExpectedServices, RatePack};
use crate::sub_lib::neighborhood::{NRMetadataChange, RouteQueryMessage};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::proxy_server::{AddReturnRouteMessage, AddRouteMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::ttl_hashmap::TtlHashMap;
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::{Actor, MailboxError};
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::{ExpectValue, MutabilityConflictHelper};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, SystemTime};
use tokio::prelude::Future;

pub const CRASH_KEY: &str = "PROXYSERVER";
pub const RETURN_ROUTE_TTL: Duration = Duration::from_secs(120);

struct ProxyServerOutSubs {
    dispatcher: Recipient<TransmitDataMsg>,
    hopper: Recipient<IncipientCoresPackage>,
    accountant: Recipient<ReportServicesConsumedMessage>,
    route_source: Recipient<RouteQueryMessage>,
    update_node_record_metadata: Recipient<NodeRecordMetadataMessage>,
    add_return_route: Recipient<AddReturnRouteMessage>,
    add_route: Recipient<AddRouteMessage>,
    stream_shutdown_sub: Recipient<StreamShutdownMsg>,
}

pub struct ProxyServer {
    subs: Option<ProxyServerOutSubs>,
    client_request_payload_factory: Box<dyn ClientRequestPayloadFactory>,
    stream_key_factory: Box<dyn StreamKeyFactory>,
    keys_and_addrs: BidiHashMap<StreamKey, SocketAddr>,
    tunneled_hosts: HashMap<StreamKey, String>,
    stream_key_routes: HashMap<StreamKey, RouteQueryResponse>,
    is_decentralized: bool,
    consuming_wallet_balance: Option<i64>,
    main_cryptde: &'static dyn CryptDE,
    alias_cryptde: &'static dyn CryptDE,
    crashable: bool,
    logger: Logger,
    route_ids_to_return_routes: TtlHashMap<u32, AddReturnRouteMessage>,
    browser_proxy_sequence_offset: bool,
    inbound_client_data_helper_opt: Option<Box<dyn IBCDHelper>>,
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
            accountant: msg.peer_actors.accountant.report_services_consumed,
            route_source: msg.peer_actors.neighborhood.route_query,
            update_node_record_metadata: msg.peer_actors.neighborhood.update_node_record_metadata,
            add_return_route: msg.peer_actors.proxy_server.add_return_route,
            add_route: msg.peer_actors.proxy_server.add_route,
            stream_shutdown_sub: msg.peer_actors.proxy_server.stream_shutdown_sub,
        };
        self.subs = Some(subs);
    }
}

//TODO comes across as basically dead code
// I think the idea was to supply the wallet if wallets hadn't been generated until recently, without the need to kill the Node
// I also found out that there is a test for this, but it changes nothing on it's normally unused
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
        } else if let Err(e) =
            self.help(|helper, proxy| helper.handle_normal_client_data(proxy, msg, false))
        {
            error!(self.logger, "{}", e)
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

impl Handler<ExpiredCoresPackage<DnsResolveFailure_0v1>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<DnsResolveFailure_0v1>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_dns_resolve_failure(&msg)
    }
}

impl Handler<ExpiredCoresPackage<ClientResponsePayload_0v1>> for ProxyServer {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<ClientResponsePayload_0v1>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_client_response_payload(msg)
    }
}

impl Handler<StreamShutdownMsg> for ProxyServer {
    type Result = ();

    fn handle(&mut self, _msg: StreamShutdownMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_shutdown_msg(_msg)
    }
}

impl Handler<NodeFromUiMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl ProxyServer {
    pub fn new(
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
        consuming_wallet_balance: Option<i64>,
        crashable: bool,
    ) -> ProxyServer {
        ProxyServer {
            subs: None,
            client_request_payload_factory: Box::new(ClientRequestPayloadFactoryReal::new()),
            stream_key_factory: Box::new(StreamKeyFactoryReal {}),
            keys_and_addrs: BidiHashMap::new(),
            tunneled_hosts: HashMap::new(),
            stream_key_routes: HashMap::new(),
            is_decentralized,
            consuming_wallet_balance,
            main_cryptde,
            alias_cryptde,
            crashable,
            logger: Logger::new("ProxyServer"),
            route_ids_to_return_routes: TtlHashMap::new(RETURN_ROUTE_TTL),
            browser_proxy_sequence_offset: false,
            inbound_client_data_helper_opt: Some(Box::new(IBCDHelperReal {})),
        }
    }

    pub fn make_subs_from(addr: &Addr<ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: recipient!(addr, BindMessage),
            from_dispatcher: recipient!(addr, InboundClientData),
            from_hopper: recipient!(addr, ExpiredCoresPackage<ClientResponsePayload_0v1>),
            dns_failure_from_hopper: recipient!(addr, ExpiredCoresPackage<DnsResolveFailure_0v1>),
            add_return_route: recipient!(addr, AddReturnRouteMessage),
            add_route: recipient!(addr, AddRouteMessage),
            stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
            set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
            node_from_ui: recipient!(addr, NodeFromUiMessage),
        }
    }

    fn handle_dns_resolve_failure(&mut self, msg: &ExpiredCoresPackage<DnsResolveFailure_0v1>) {
        let return_route_info = match self.get_return_route_info(&msg.remaining_route) {
            Some(rri) => rri,
            None => return, // TODO: Eventually we'll have to do something better here, but we'll probably need some heuristics.
        };
        let exit_public_key = {
            // ugly, ugly
            let self_public_key = self.main_cryptde.public_key();
            return_route_info
                .find_exit_node_key()
                .unwrap_or_else(|| {
                    if return_route_info.is_zero_hop() {
                        self_public_key
                    } else {
                        panic!(
                            "Internal error: return_route_info for {} has no exit Node",
                            return_route_info.return_route_id
                        );
                    }
                })
                .clone()
        };
        let server_name_opt = return_route_info.server_name_opt.clone();
        let response = &msg.payload;
        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(socket_addr) => {
                if let Some(server_name) = server_name_opt {
                    self.subs
                        .as_ref()
                        .expect("Neighborhood unbound in ProxyServer")
                        .update_node_record_metadata
                        .try_send(NodeRecordMetadataMessage {
                            public_key: exit_public_key.clone(),
                            metadata_change: NRMetadataChange::AddUnreachableHost {
                                hostname: server_name,
                            },
                        })
                        .expect("Neighborhood is dead");
                }
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
                                return_route_info.server_name_opt.clone(),
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
                error!(self.logger,
                    "Discarding DnsResolveFailure message for {} from an unrecognized stream key {:?}",
                    server_name_opt.unwrap_or_else(|| "<unspecified_server>".to_string()),
                    &response.stream_key
                )
            }
        }
    }

    fn handle_client_response_payload(
        &mut self,
        msg: ExpiredCoresPackage<ClientResponsePayload_0v1>,
    ) {
        debug!(
            self.logger,
            "ExpiredCoresPackage remaining_route: {}",
            msg.remaining_route
                .to_string(vec![self.main_cryptde, self.main_cryptde])
        );
        let payload_data_len = msg.payload_len;
        let response = msg.payload;
        debug!(
            self.logger,
            "Relaying ClientResponsePayload (stream key {}, sequence {}, length {}) from Hopper to Dispatcher for client",
            response.stream_key, response.sequenced_packet.sequence_number, response.sequenced_packet.data.len()
        );
        let return_route_info = match self.get_return_route_info(&msg.remaining_route) {
            Some(rri) => rri,
            None => return,
        };
        self.report_response_services_consumed(
            &return_route_info,
            response.sequenced_packet.data.len(),
            payload_data_len,
        );
        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(socket_addr) => {
                let last_data = response.sequenced_packet.last_data;
                let stream_key = response.stream_key;
                let sequence_number = Some(
                    response.sequenced_packet.sequence_number
                        + self.browser_proxy_sequence_offset as u64,
                );
                self.subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(socket_addr),
                        last_data,
                        sequence_number,
                        data: response.sequenced_packet.data,
                    })
                    .expect("Dispatcher is dead");
                if last_data {
                    debug!(
                        self.logger,
                        "Retiring stream key {}: no more data", &stream_key
                    );
                    self.purge_stream_key(&stream_key);
                }
            }
            None => {
                // TODO GH-608: It would be really nice to be able to send an InboundClientData with last_data: true
                // back to the ProxyClient (and the distant server) so that the server could shut down
                // its stream, since the browser has shut down _its_ stream and no more data will
                // ever be accepted from the server on that stream; but we don't have enough information
                // to do so, since our stream key has been purged and all the information it keyed
                // is gone. Sorry, server!
                warning!(self.logger,
                    "Discarding {}-byte packet {} from an unrecognized stream key: {:?}; can't send response back to client",
                    response.sequenced_packet.data.len(),
                    response.sequenced_packet.sequence_number,
                    response.stream_key,
                )
            }
        }
    }

    fn tls_connect(&mut self, msg: &InboundClientData) {
        let http_data = HttpProtocolPack {}.find_host(&msg.data.clone().into());
        match http_data {
            Some(ref host) if host.port == Some(443) => {
                let stream_key = self.make_stream_key(msg);
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

    fn handle_stream_shutdown_msg(&mut self, msg: StreamShutdownMsg) {
        let nca = match msg.stream_type {
            RemovedStreamType::Clandestine => {
                panic!("ProxyServer should never get ShutdownStreamMsg about clandestine stream")
            }
            RemovedStreamType::NonClandestine(nca) => nca,
        };
        let stream_key = match self.keys_and_addrs.b_to_a(&msg.peer_addr) {
            None => {
                warning!(
                    self.logger,
                    "Received instruction to shut down nonexistent stream to peer {} - ignoring",
                    msg.peer_addr
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
                timestamp: SystemTime::now(),
                peer_addr: msg.peer_addr,
                reception_port: Some(nca.reception_port),
                last_data: true,
                is_clandestine: false,
                sequence_number: Some(nca.sequence_number),
                data: vec![],
            };
            if let Err(e) =
                self.help(|helper, proxy| helper.handle_normal_client_data(proxy, ibcd, true))
            {
                error!(self.logger, "{}", e)
            };
        } else {
            debug!(
                self.logger,
                "Retiring stream key {}: StreamShutdownMsg for peer {}", &stream_key, msg.peer_addr
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
                    .make(self.main_cryptde.public_key(), ibcd.peer_addr);
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
    ) -> Result<ClientRequestPayload_0v1, String> {
        let tunnelled_host = self.tunneled_hosts.get(stream_key);
        let new_ibcd = match tunnelled_host {
            Some(_) => InboundClientData {
                reception_port: Some(443),
                ..ibcd
            },
            None => ibcd,
        };
        match self.client_request_payload_factory.make(
            &new_ibcd,
            *stream_key,
            self.alias_cryptde,
            &self.logger,
        ) {
            None => Err("Couldn't create ClientRequestPayload".to_string()),
            Some(payload) => match tunnelled_host {
                Some(hostname) => Ok(ClientRequestPayload_0v1 {
                    target_hostname: Some(hostname.clone()),
                    ..payload
                }),
                None => Ok(payload),
            },
        }
    }

    fn try_transmit_to_hopper(args: TTHLocalArgs, route_query_response: RouteQueryResponse) {
        match route_query_response.expected_services {
            ExpectedServices::RoundTrip(over, back, return_route_id) => {
                let return_route_info = AddReturnRouteMessage {
                    return_route_id,
                    expected_services: back,
                    protocol: args.common.payload.protocol,
                    server_name_opt: args.common.payload.target_hostname.clone(),
                };
                debug!(
                    args.logger,
                    "Adding expectant return route info: {:?}", return_route_info
                );
                args.add_return_route_sub
                    .try_send(return_route_info)
                    .expect("ProxyServer is dead");
                ProxyServer::transmit_to_hopper(
                    args.common.main_cryptde,
                    args.hopper_sub,
                    args.common.timestamp,
                    args.common.payload,
                    &route_query_response.route,
                    over,
                    args.logger,
                    args.common.source_addr,
                    args.dispatcher_sub,
                    args.accountant_sub,
                    args.retire_stream_key_sub_opt,
                    args.common.is_decentralized,
                );
            }
            _ => panic!("Expected RoundTrip ExpectedServices but got OneWay"),
        }
    }

    fn report_on_routing_services(
        expected_services: Vec<ExpectedService>,
        logger: &Logger,
    ) -> Vec<RoutingServiceConsumed> {
        let report_of_routing_services: Vec<RoutingServiceConsumed> = expected_services
            .into_iter()
            .filter_map(|service| match service {
                ExpectedService::Routing(_, earning_wallet, rate_pack) => {
                    Some(RoutingServiceConsumed {
                        earning_wallet,
                        service_rate: rate_pack.routing_service_rate,
                        byte_rate: rate_pack.routing_byte_rate,
                    })
                }
                _ => None,
            })
            .collect();
        if report_of_routing_services.is_empty() {
            debug!(logger, "No routing services requested.");
        }
        report_of_routing_services
    }

    fn report_on_exit_service(
        expected_services: &[ExpectedService],
        payload_size: usize,
    ) -> ExitServiceConsumed {
        match expected_services.iter().fold(
            None,
            |acc: Option<(&Wallet, &RatePack)>, current_service| {
                if acc.is_some() && matches!(current_service, ExpectedService::Exit(..)) {
                    panic!(
                        "Detected more than one exit service in one-way route: {:?}",
                        expected_services
                    )
                } else if acc.is_none() {
                    match current_service {
                        ExpectedService::Exit(_, earning_wallet, rate_pack) => {
                            Some((earning_wallet, rate_pack))
                        }
                        _ => None,
                    }
                } else {
                    acc
                }
            },
        ) {
            Some((earning_wallet, rate_pack)) => ExitServiceConsumed {
                earning_wallet: earning_wallet.clone(),
                payload_size,
                service_rate: rate_pack.exit_service_rate,
                byte_rate: rate_pack.exit_byte_rate,
            },
            None => {
                panic!(
                    "Each route must demand an exit service, but this route has no such demand: {:?}",
                    expected_services
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transmit_to_hopper(
        main_cryptde: &'static dyn CryptDE,
        hopper: &Recipient<IncipientCoresPackage>,
        timestamp: SystemTime,
        payload: ClientRequestPayload_0v1,
        route: &Route,
        expected_services: Vec<ExpectedService>,
        logger: &Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
        accountant_sub: &Recipient<ReportServicesConsumedMessage>,
        retire_stream_key_via: Option<&Recipient<StreamShutdownMsg>>,
        is_decentralized: bool,
    ) {
        let destination_key_opt = if is_decentralized {
            expected_services.iter().find_map(|service| match service {
                ExpectedService::Exit(public_key, _, _) => Some(public_key.clone()),
                _ => None,
            })
        } else {
            // In Zero Hop Mode the exit node public key is the same as this public key
            Some(main_cryptde.public_key().clone())
        };
        match destination_key_opt {
            None => ProxyServer::handle_route_failure(payload, logger, source_addr, dispatcher),
            Some(payload_destination_key) => {
                debug!(
                    logger,
                    "transmit to hopper with destination key {:?}", payload_destination_key
                );
                let payload_size = payload.sequenced_packet.data.len();
                let stream_key = payload.stream_key;
                let pkg = IncipientCoresPackage::new(
                    main_cryptde,
                    route.clone(),
                    payload.into(),
                    &payload_destination_key,
                )
                .expect("Key magically disappeared");
                if is_decentralized {
                    let exit =
                        ProxyServer::report_on_exit_service(&expected_services, payload_size);
                    let routing =
                        ProxyServer::report_on_routing_services(expected_services, logger);
                    accountant_sub
                        .try_send(ReportServicesConsumedMessage {
                            timestamp,
                            exit,
                            routing_payload_size: pkg.payload.len(),
                            routing,
                        })
                        .expect("Accountant is dead");
                }
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
        payload: ClientRequestPayload_0v1,
        logger: &Logger,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) {
        let target_hostname = ProxyServer::hostname(&payload);
        ProxyServer::send_route_failure(payload, source_addr, dispatcher);
        error!(logger, "Failed to find route to {}", target_hostname);
    }

    fn send_route_failure(
        payload: ClientRequestPayload_0v1,
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

    fn hostname(payload: &ClientRequestPayload_0v1) -> String {
        match payload.target_hostname {
            Some(ref thn) => thn.clone(),
            None => "<unknown>".to_string(),
        }
    }

    fn get_return_route_info(&self, remaining_route: &Route) -> Option<Rc<AddReturnRouteMessage>> {
        let mut mut_remaining_route = remaining_route.clone();
        mut_remaining_route
            .shift(self.main_cryptde)
            .expect("Internal error: remaining route in ProxyServer with no hops");
        let return_route_id = match mut_remaining_route.id(self.main_cryptde) {
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
        let exit_service_report: ExitServiceSearch = return_route_info
            .expected_services
            .iter()
            .filter(|service| !matches!(service, ExpectedService::Nothing))
            .fold(ZeroHop, |acc, service| {
                if let Definite(..) = acc {
                    acc
                } else {
                    match service {
                        ExpectedService::Exit(_, wallet, rate_pack) => {
                            Definite(ExitServiceConsumed {
                                earning_wallet: wallet.clone(), //sadly, the whole data structure is a reference
                                payload_size: exit_size,
                                service_rate: rate_pack.exit_service_rate,
                                byte_rate: rate_pack.exit_byte_rate,
                            })
                        }
                        _ => unreachable!(
                            "Return route has to begin with an exit service if not zero hop"
                        ),
                    }
                }
            });
        let exit_service_report = match exit_service_report {
            ZeroHop => return,
            Definite(report) => report,
        };
        let routing_service_reports = return_route_info
            .expected_services
            .iter()
            .flat_map(|service| match service {
                ExpectedService::Routing(_, wallet, rate_pack) => Some(RoutingServiceConsumed {
                    earning_wallet: wallet.clone(),
                    service_rate: rate_pack.routing_service_rate,
                    byte_rate: rate_pack.routing_byte_rate,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        let report_message = ReportServicesConsumedMessage {
            timestamp: SystemTime::now(),
            exit: exit_service_report,
            routing_payload_size: routing_size,
            routing: routing_service_reports,
        };
        self.subs
            .as_ref()
            .expect("Accountant is unbound")
            .accountant
            .try_send(report_message)
            .expect("Accountant is dead");
    }
}

impl MutabilityConflictHelper<Box<dyn IBCDHelper>> for ProxyServer {
    type Result = Result<(), String>;

    fn helper_access(&mut self) -> &mut Option<Box<dyn IBCDHelper>> {
        &mut self.inbound_client_data_helper_opt
    }
}

pub trait IBCDHelper {
    fn handle_normal_client_data(
        &self,
        proxy_s: &mut ProxyServer,
        msg: InboundClientData,
        retire_stream_key: bool,
    ) -> Result<(), String>;
}

struct IBCDHelperReal {}

impl IBCDHelper for IBCDHelperReal {
    fn handle_normal_client_data(
        &self,
        proxy: &mut ProxyServer,
        msg: InboundClientData,
        retire_stream_key: bool,
    ) -> Result<(), String> {
        let source_addr = msg.peer_addr;
        if proxy.consuming_wallet_balance.is_none() && proxy.is_decentralized {
            let protocol_pack = match from_ibcd(&msg) {
                Err(e) => return Err(e),
                Ok(pp) => pp,
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
            proxy
                .out_subs("Dispatcher")
                .dispatcher
                .try_send(msg)
                .expect("Dispatcher is dead");
            return Err("Browser request rejected due to missing consuming wallet".to_string());
        }
        let stream_key = proxy.make_stream_key(&msg);
        let timestamp = msg.timestamp;
        let payload = match proxy.make_payload(msg, &stream_key) {
            Ok(payload) => payload,
            Err(e) => return Err(e),
        };
        let local_args = TTHLocalArgs {
            common: TTHCommonArgs {
                main_cryptde: proxy.main_cryptde,
                payload,
                source_addr,
                timestamp,
                is_decentralized: proxy.is_decentralized,
            },
            hopper_sub: &proxy.out_subs("Hopper").hopper,
            logger: &proxy.logger,
            dispatcher_sub: &proxy.out_subs("Dispatcher").dispatcher,
            accountant_sub: &proxy.out_subs("Accountant").accountant,
            add_return_route_sub: &proxy.out_subs("ProxyServer").add_return_route,
            retire_stream_key_sub_opt: if retire_stream_key {
                Some(&proxy.out_subs("ProxyServer").stream_shutdown_sub)
            } else {
                None
            },
        };
        let pld = &local_args.common.payload;
        if let Some(route_query_response) = proxy.stream_key_routes.get(&pld.stream_key) {
            debug!(
                proxy.logger,
                "Transmitting down existing stream {}: sequence {}, length {}",
                pld.stream_key,
                pld.sequenced_packet.sequence_number,
                pld.sequenced_packet.data.len()
            );
            let route_query_response = route_query_response.clone();
            ProxyServer::try_transmit_to_hopper(local_args, route_query_response);
            Ok(())
        } else {
            let movable_args = TTHMovableArgs::from(local_args);
            let route_source = proxy.out_subs("Neighborhood").route_source.clone();
            let add_route_sub = proxy.out_subs("ProxyServer").add_route.clone();
            Self::request_route_and_transmit(movable_args, route_source, add_route_sub)
        }
    }
}

impl IBCDHelperReal {
    fn request_route_and_transmit(
        args: TTHMovableArgs,
        route_source: Recipient<RouteQueryMessage>,
        add_route_sub: Recipient<AddRouteMessage>,
    ) -> Result<(), String> {
        let common_args = args.common_opt.as_ref().expectv("TTH common");
        let pld = &common_args.payload;
        let hostname_opt = pld.target_hostname.clone();
        debug!(
            args.logger,
            "Getting route and opening new stream with key {} to transmit: sequence {}, length {}",
            pld.stream_key,
            pld.sequenced_packet.sequence_number,
            pld.sequenced_packet.data.len()
        );
        let payload_size = pld.sequenced_packet.data.len();
        tokio::spawn(
            route_source
                .send(RouteQueryMessage::data_indefinite_route_request(
                    hostname_opt,
                    payload_size,
                ))
                .then(move |route_result| {
                    Self::resolve_route_query_response(args, add_route_sub, route_result);
                    Ok(())
                }),
        );
        Ok(())
    }

    fn resolve_route_query_response(
        mut args: TTHMovableArgs,
        add_route_sub: Recipient<AddRouteMessage>,
        route_result: Result<Option<RouteQueryResponse>, MailboxError>,
    ) {
        match route_result {
            Ok(Some(route_query_response)) => {
                add_route_sub
                    .try_send(AddRouteMessage {
                        stream_key: args
                            .common_opt
                            .as_ref()
                            .expectv("TTH common")
                            .payload
                            .stream_key,
                        route: route_query_response.clone(),
                    })
                    .expect("ProxyServer is dead");
                ProxyServer::try_transmit_to_hopper((&mut args).into(), route_query_response)
            }
            Ok(None) => {
                let tth_common = args.common_opt.take().expectv("tth common");
                ProxyServer::handle_route_failure(
                    tth_common.payload,
                    &args.logger,
                    tth_common.source_addr,
                    &args.dispatcher_sub,
                )
            }
            Err(e) => {
                error!(
                    args.logger,
                    "Neighborhood refused to answer route request: {:?}", e
                );
            }
        }
    }
}

enum ExitServiceSearch {
    Definite(ExitServiceConsumed),
    ZeroHop,
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
    use crate::proxy_server::protocol_pack::ServerImpersonator;
    use crate::proxy_server::server_impersonator_http::ServerImpersonatorHttp;
    use crate::proxy_server::server_impersonator_tls::ServerImpersonatorTls;
    use crate::stream_messages::{NonClandestineAttributes, RemovedStreamType};
    use crate::sub_lib::accountant::RoutingServiceConsumed;
    use crate::sub_lib::cryptde::{decodex, CryptData};
    use crate::sub_lib::cryptde::{encodex, PlainData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::ExpectedServices;
    use crate::sub_lib::neighborhood::{ExpectedService, DEFAULT_RATE_PACK};
    use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
    use crate::sub_lib::proxy_server::ClientRequestPayload_0v1;
    use crate::sub_lib::proxy_server::ProxyProtocol;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::sub_lib::sequence_buffer::SequencedPacket;
    use crate::sub_lib::ttl_hashmap::TtlHashMap;
    use crate::sub_lib::versioned_data::VersionedData;
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::unshared_test_utils::prove_that_crash_request_handler_is_hooked_up;
    use crate::test_utils::zero_hop_route_response;
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::test_utils::{main_cryptde, make_meaningless_route};
    use actix::System;
    use crossbeam_channel::unbounded;
    use masq_lib::constants::{HTTP_PORT, TLS_PORT};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::SystemTime;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "PROXYSERVER");
        assert_eq!(RETURN_ROUTE_TTL, Duration::from_secs(120));
    }

    const STANDARD_CONSUMING_WALLET_BALANCE: i64 = 0;

    fn make_proxy_server_out_subs() -> ProxyServerOutSubs {
        let recorder = Recorder::new();
        let addr = recorder.start();
        ProxyServerOutSubs {
            dispatcher: recipient!(addr, TransmitDataMsg),
            hopper: recipient!(addr, IncipientCoresPackage),
            accountant: recipient!(addr, ReportServicesConsumedMessage),
            route_source: recipient!(addr, RouteQueryMessage),
            update_node_record_metadata: recipient!(addr, NodeRecordMetadataMessage),
            add_return_route: recipient!(addr, AddReturnRouteMessage),
            add_route: recipient!(addr, AddRouteMessage),
            stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
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

    #[derive(Default)]
    struct IBCDHelperMock {
        handle_normal_client_data_params: Arc<Mutex<Vec<(InboundClientData, bool)>>>,
        handle_normal_client_data_results: RefCell<Vec<Result<(), String>>>,
    }

    impl IBCDHelper for IBCDHelperMock {
        fn handle_normal_client_data(
            &self,
            _proxy_s: &mut ProxyServer,
            msg: InboundClientData,
            retire_stream_key: bool,
        ) -> Result<(), String> {
            self.handle_normal_client_data_params
                .lock()
                .unwrap()
                .push((msg, retire_stream_key));
            self.handle_normal_client_data_results
                .borrow_mut()
                .remove(0)
        }
    }

    impl IBCDHelperMock {
        fn handle_normal_client_data_params(
            mut self,
            params: &Arc<Mutex<Vec<(InboundClientData, bool)>>>,
        ) -> Self {
            self.handle_normal_client_data_params = params.clone();
            self
        }

        fn handle_normal_client_data_result(self, result: Result<(), String>) -> Self {
            self.handle_normal_client_data_results
                .borrow_mut()
                .push(result);
            self
        }
    }

    #[test]
    fn proxy_server_receives_http_request_with_new_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (hopper_mock, hopper_awaiter, hopper_log_arc) = make_recorder();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let make_parameters_arc_a = make_parameters_arc.clone();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&make_parameters_arc)
                .make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
            (main_cryptde.public_key().clone(), socket_addr)
        );
        let recording = neighborhood_recording_arc.lock().unwrap();
        let record = recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(
            record,
            &RouteQueryMessage::data_indefinite_route_request(Some("nowhere.com".to_string()), 47)
        );
        let recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
    }

    #[test]
    fn proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname() {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"CONNECT https://realdomain.nu:443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";
        let (hopper_mock, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let route = Route { hops: vec![] };
        let (dispatcher_mock, _, dispatcher_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: request_data.clone(),
        };
        let tunnelled_msg = InboundClientData {
            timestamp: SystemTime::now(),
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
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"client hello".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("realdomain.nu")),
            target_port: 443,
            protocol: ProxyProtocol::TLS,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
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
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
            (main_cryptde.public_key().clone(), socket_addr)
        );

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let hopper_record = hopper_recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(hopper_record, &expected_pkg);

        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let neighborhood_record = neighborhood_recording.get_record::<RouteQueryMessage>(0);
        assert_eq!(
            neighborhood_record,
            &RouteQueryMessage::data_indefinite_route_request(
                Some("realdomain.nu".to_string()),
                12
            )
        );
    }

    #[test]
    fn handle_client_response_payload_increments_sequence_number_when_browser_proxy_sequence_offset_is_true(
    ) {
        let system = System::new("handle_client_response_payload_increments_sequence_number_when_browser_proxy_sequence_offset_is_true");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let http_request = b"CONNECT https://realdomain.nu:443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";
        let request_data = http_request.to_vec();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr,
            reception_port: Some(443),
            last_data: false,
            is_clandestine: false,
            sequence_number: Some(0),
            data: request_data,
        };

        let client_response_payload = ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
        };

        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
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
        let cryptde = main_cryptde();
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
            timestamp: SystemTime::now(),
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
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let cryptde = main_cryptde();
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
            timestamp: SystemTime::now(),
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
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (hopper, _, hopper_log_arc) = make_recorder();
        let (neighborhood, _, neighborhood_log_arc) = make_recorder();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, alias_cryptde(), true, None, false);
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
        let cryptde = main_cryptde();
        let tls_request = b"Fake TLS request";
        let (hopper, _, hopper_log_arc) = make_recorder();
        let (neighborhood, _, neighborhood_log_arc) = make_recorder();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, alias_cryptde(), true, None, false);
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let expected_data = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n".to_vec();
        let expected_data_inner = expected_data.clone();
        let expected_route = zero_hop_route_response(main_cryptde.public_key(), main_cryptde);
        let stream_key = make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let neighborhood_log_arc = neighborhood.get_recording();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                timestamp: SystemTime::now(),
                peer_addr: socket_addr.clone(),
                reception_port: Some(HTTP_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject = ProxyServer::new(main_cryptde, alias_cryptde, false, None, false);
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
                return_component_opt: Some(Component::ProxyServer),
                payload_size: 47,
                hostname_opt: Some("nowhere.com".to_string())
            }
        );
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        assert!(dispatcher_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert_eq!(
            hopper_recording.get_record::<IncipientCoresPackage>(0),
            &IncipientCoresPackage::new(
                main_cryptde,
                expected_route.route,
                MessageType::ClientRequest(VersionedData::new(
                    &crate::sub_lib::migrations::client_request_payload::MIGRATIONS,
                    &ClientRequestPayload_0v1 {
                        stream_key,
                        sequenced_packet: SequencedPacket::new(expected_data, 0, true),
                        target_hostname: Some("nowhere.com".to_string()),
                        target_port: 80,
                        protocol: ProxyProtocol::HTTP,
                        originator_public_key: alias_cryptde.public_key().clone(),
                    }
                )),
                main_cryptde.public_key()
            )
            .unwrap()
        );
    }

    #[test]
    fn proxy_server_receives_tls_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally(
    ) {
        init_test_logging();
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let expected_data = b"Fake TLS request".to_vec();
        let expected_data_inner = expected_data.clone();
        let expected_route = zero_hop_route_response(main_cryptde.public_key(), main_cryptde);
        let stream_key = make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let neighborhood_log_arc = neighborhood.get_recording();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                timestamp: SystemTime::now(),
                peer_addr: socket_addr.clone(),
                reception_port: Some(TLS_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject = ProxyServer::new(main_cryptde, alias_cryptde, false, None, false);
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
                return_component_opt: Some(Component::ProxyServer),
                payload_size: 16,
                hostname_opt: None
            }
        );
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        assert!(dispatcher_recording.is_empty());
        let hopper_recording = hopper_log_arc.lock().unwrap();
        assert_eq!(
            hopper_recording.get_record::<IncipientCoresPackage>(0),
            &IncipientCoresPackage::new(
                main_cryptde,
                expected_route.route,
                MessageType::ClientRequest(VersionedData::new(
                    &crate::sub_lib::migrations::client_request_payload::MIGRATIONS,
                    &ClientRequestPayload_0v1 {
                        stream_key,
                        sequenced_packet: SequencedPacket::new(expected_data, 0, true),
                        target_hostname: None,
                        target_port: 443,
                        protocol: ProxyProtocol::TLS,
                        originator_public_key: alias_cryptde.public_key().clone(),
                    }
                ),),
                main_cryptde.public_key()
            )
            .unwrap()
        );
    }

    #[test]
    fn proxy_server_receives_http_request_with_existing_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = Recorder::new().route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let route_query_response = RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        };
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let route = route_query_response.route.clone();
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route,
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_applies_late_wallet_information");
            let mut subject = ProxyServer::new(main_cryptde, alias_cryptde, true, None, false);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            subject
                .stream_key_routes
                .insert(stream_key, route_query_response);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder().hopper(hopper_mock).build();
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
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
                    &main_cryptde.public_key(),
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
                    &main_cryptde.public_key(),
                ],
                Component::ProxyServer,
            ),
            main_cryptde,
            Some(consuming_wallet),
            1234,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
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
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_http_request = PlainData::new(http_request);
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_http_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &payload_destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper");
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        assert_eq!(
            record,
            &RouteQueryMessage::data_indefinite_route_request(Some("nowhere.com".to_string()), 47)
        );
    }

    #[test]
    fn proxy_server_adds_route_for_stream_key() {
        let cryptde = main_cryptde();
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
            timestamp: SystemTime::now(),
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
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let route_query_response = RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        };
        let (hopper_mock, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: PlainData::new(http_request).into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: Some(String::from("nowhere.com")),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            Route { hops: vec![] },
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_uses_existing_route");
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder().hopper(hopper_mock).build();
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr
                .try_send(AddRouteMessage {
                    stream_key,
                    route: route_query_response,
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
    fn proxy_server_sends_message_to_accountant_about_all_services_consumed_on_the_route_over() {
        let cryptde = main_cryptde();
        let now = SystemTime::now();
        let exit_earning_wallet = make_wallet("exit earning wallet");
        let route_1_earning_wallet = make_wallet("route 1 earning wallet");
        let route_2_earning_wallet = make_wallet("route 2 earning wallet");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let (hopper_mock, _, hopper_recording_arc) = make_recorder();
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let routing_node_1_rate_pack = rate_pack(101);
        let routing_node_2_rate_pack = rate_pack(102);
        let exit_node_rate_pack = rate_pack(103);
        let route_query_response = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Routing(
                        PublicKey::new(&[1]),
                        route_1_earning_wallet.clone(),
                        routing_node_1_rate_pack,
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[2]),
                        route_2_earning_wallet.clone(),
                        routing_node_2_rate_pack,
                    ),
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        exit_earning_wallet.clone(),
                        exit_node_rate_pack,
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        PublicKey::new(&[3]),
                        make_wallet("some wallet 1"),
                        rate_pack(104),
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[2]),
                        make_wallet("some wallet 2"),
                        rate_pack(105),
                    ),
                    ExpectedService::Routing(
                        PublicKey::new(&[1]),
                        make_wallet("some wallet 3"),
                        rate_pack(106),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let system =
            System::new("proxy_server_sends_message_to_accountant_for_all_services_consumed");
        let peer_actors = peer_actors_builder()
            .accountant(accountant_mock)
            .hopper(hopper_mock)
            .proxy_server(proxy_server_mock)
            .build();
        let exit_payload_size = expected_data.len();
        let payload = ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");
        let local_tth_args = TTHLocalArgs {
            common: TTHCommonArgs {
                main_cryptde: cryptde,
                payload,
                source_addr,
                timestamp: now,
                is_decentralized: true,
            },
            logger: &logger,
            hopper_sub: &peer_actors.hopper.from_hopper_client,
            dispatcher_sub: &peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: &peer_actors.accountant.report_services_consumed,
            add_return_route_sub: &peer_actors.proxy_server.add_return_route,
            retire_stream_key_sub_opt: None,
        };

        ProxyServer::try_transmit_to_hopper(local_tth_args, route_query_response);

        System::current().stop();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        let payload_enc_length = record.payload.len();
        let recording = accountant_recording_arc.lock().unwrap();
        let record = recording.get_record::<ReportServicesConsumedMessage>(0);
        assert_eq!(recording.len(), 1);
        assert_eq!(
            record,
            &ReportServicesConsumedMessage {
                timestamp: now,
                exit: ExitServiceConsumed {
                    earning_wallet: exit_earning_wallet,
                    payload_size: exit_payload_size,
                    service_rate: exit_node_rate_pack.exit_service_rate,
                    byte_rate: exit_node_rate_pack.exit_byte_rate
                },
                routing_payload_size: payload_enc_length,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: route_1_earning_wallet,
                        service_rate: routing_node_1_rate_pack.routing_service_rate,
                        byte_rate: routing_node_1_rate_pack.routing_byte_rate,
                    },
                    RoutingServiceConsumed {
                        earning_wallet: route_2_earning_wallet,
                        service_rate: routing_node_2_rate_pack.routing_service_rate,
                        byte_rate: routing_node_2_rate_pack.routing_byte_rate,
                    }
                ]
            }
        );
        let recording = proxy_server_recording_arc.lock().unwrap();
        let _ = recording.get_record::<AddReturnRouteMessage>(0); // don't care about this, other than type
        assert_eq!(recording.len(), 1); // No StreamShutdownMsg: that's the important thing
    }

    #[test]
    fn try_transmit_to_hopper_orders_stream_shutdown_if_directed_to_do_so() {
        let cryptde = main_cryptde();
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
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let system =
            System::new("proxy_server_sends_message_to_accountant_for_routing_service_consumed");
        let peer_actors = peer_actors_builder()
            .proxy_server(proxy_server_mock)
            .build();
        let payload = ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: Some("nowhere.com".to_string()),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");
        let local_tth_args = TTHLocalArgs {
            common: TTHCommonArgs {
                main_cryptde: cryptde,
                payload,
                source_addr,
                timestamp: SystemTime::now(),
                is_decentralized: false,
            },
            logger: &logger,
            hopper_sub: &peer_actors.hopper.from_hopper_client,
            dispatcher_sub: &peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: &peer_actors.accountant.report_services_consumed,
            add_return_route_sub: &peer_actors.proxy_server.add_return_route,
            retire_stream_key_sub_opt: Some(&peer_actors.proxy_server.stream_shutdown_sub),
        };

        ProxyServer::try_transmit_to_hopper(local_tth_args, route_query_response);

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
                server_name_opt: Some("nowhere.com".to_string())
            }
        );
        let record = recording.get_record::<StreamShutdownMsg>(1);
        assert_eq!(
            record,
            &StreamShutdownMsg {
                peer_addr: source_addr,
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
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, accountant_awaiter, _) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let mut route_query_response = zero_hop_route_response(&cryptde.public_key(), cryptde);
        route_query_response.expected_services = ExpectedServices::RoundTrip(
            vec![ExpectedService::Exit(
                cryptde.public_key().clone(),
                make_wallet("exit wallet"),
                rate_pack(3),
            )],
            vec![],
            0,
        );
        let neighborhood_mock =
            neighborhood_mock.route_query_response(Some(route_query_response.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
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
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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

        //report about consumed services is sent anyway, exit service is mandatory ever
        accountant_awaiter.await_message_count(1)
    }

    #[test]
    #[should_panic(
        expected = "Each route must demand an exit service, but this route has no such demand: [Routing(0x726F7574696E675F6B65795F31, \
    Wallet { kind: Address(0x00000000726f7574696e675f77616c6c65745f31) }, RatePack { routing_byte_rate: 9, \
    routing_service_rate: 208, exit_byte_rate: 11, exit_service_rate: 408 })]"
    )]
    fn proxy_server_panics_when_exit_services_are_not_requested_in_non_zero_hop_mode() {
        let expected_services = vec![ExpectedService::Routing(
            PublicKey::from(&b"routing_key_1"[..]),
            make_wallet("routing_wallet_1"),
            rate_pack(8),
        )];

        ProxyServer::report_on_exit_service(&expected_services, 10000);
    }

    #[test]
    #[should_panic(
        expected = "Detected more than one exit service in one-way route: [Exit(0x65786974206B65792031, Wallet { kind: \
    Address(0x00000000000000657869742077616c6c65742031) }, RatePack { routing_byte_rate: 7, routing_service_rate: \
    206, exit_byte_rate: 9, exit_service_rate: 406 }), Exit(0x65786974206B65792032, Wallet { kind: \
    Address(0x00000000000000657869742077616c6c65742032) }, RatePack { routing_byte_rate: 6, routing_service_rate: \
    205, exit_byte_rate: 8, exit_service_rate: 405 })]"
    )]
    fn proxy_server_panics_when_there_are_more_than_one_exit_services_in_the_route() {
        let expected_services = vec![
            ExpectedService::Exit(
                PublicKey::from(&b"exit key 1"[..]),
                make_wallet("exit wallet 1"),
                rate_pack(6),
            ),
            ExpectedService::Exit(
                PublicKey::from(&b"exit key 2"[..]),
                make_wallet("exit wallet 2"),
                rate_pack(5),
            ),
        ];

        ProxyServer::report_on_exit_service(&expected_services, 10000);
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route() {
        init_test_logging();
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(None);
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        assert_eq!(
            record,
            &RouteQueryMessage::data_indefinite_route_request(Some("nowhere.com".to_string()), 47)
        );
        TestLogHandler::new()
            .exists_log_containing("ERROR: ProxyServer: Failed to find route to nowhere.com");
    }

    #[test]
    #[should_panic(expected = "Expected RoundTrip ExpectedServices but got OneWay")]
    fn proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route() {
        let _system = System::new("proxy_server_panics_if_it_receives_a_one_way_route_from_a_request_for_a_round_trip_route");
        let peer_actors = peer_actors_builder().build();

        let cryptde = main_cryptde();
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
        let payload = ClientRequestPayload_0v1 {
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
        let local_tth_args = TTHLocalArgs {
            common: TTHCommonArgs {
                main_cryptde: cryptde,
                payload,
                source_addr,
                timestamp: SystemTime::now(),
                is_decentralized: true,
            },
            logger: &logger,
            hopper_sub: &peer_actors.hopper.from_hopper_client,
            dispatcher_sub: &peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: &peer_actors.accountant.report_services_consumed,
            add_return_route_sub: &peer_actors.proxy_server.add_return_route,
            retire_stream_key_sub_opt: None,
        };

        ProxyServer::try_transmit_to_hopper(local_tth_args, route_result);
    }

    #[test]
    #[should_panic(expected = "Return route has to begin with an exit service if not zero hop")]
    fn report_response_services_consumed_does_not_allow_for_other_order_than_started_at_exit_service(
    ) {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let subject = ProxyServer::new(
            main_cryptde,
            alias_cryptde,
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let add_return_route_message = AddReturnRouteMessage {
            return_route_id: 0,
            expected_services: vec![
                ExpectedService::Routing(
                    PublicKey::from(&b"key"[..]),
                    make_wallet("some wallet"),
                    rate_pack(10),
                ),
                ExpectedService::Exit(
                    PublicKey::from(&b"exit_key"[..]),
                    make_wallet("exit"),
                    rate_pack(11),
                ),
            ],
            protocol: ProxyProtocol::HTTP,
            server_name_opt: None,
        };

        subject.report_response_services_consumed(&add_return_route_message, 1234, 3456);
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route_with_no_expected_services(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
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
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        assert_eq!(
            record,
            &RouteQueryMessage::data_indefinite_route_request(Some("nowhere.com".to_string()), 47)
        );
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
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c', b'o', b'm', // server_name
        ];
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = Recorder::new().route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("server.com")),
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = Recorder::new().route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let hopper_mock = Recorder::new();
        let hopper_log_arc = hopper_mock.get_recording();
        let hopper_awaiter = hopper_mock.get_awaiter();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = Recorder::new().route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
                1234,
            ),
        }));
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::new(main_cryptde.public_key().clone(), source_addr);
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: source_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request);
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: true,
            },
            target_hostname: None,
            target_port: TLS_PORT,
            protocol: ProxyProtocol::TLS,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route.clone(),
            expected_payload.into(),
            &destination_key,
        )
        .unwrap();
        thread::spawn(move || {
            let subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let cryptde = main_cryptde();
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
            b's', b'e', b'r', b'v', b'e', b'r', b'.', b'c', b'o', b'm', // server_name
        ]
        .to_vec();
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let neighborhood = Recorder::new().route_query_response(None);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: tls_request,
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_but_neighborhood_cant_make_route");
            let subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let remaining_route = return_route_with_id(cryptde, 1234);
        let client_response_payload = ClientResponsePayload_0v1 {
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
        let mut peer_actors = peer_actors_builder().dispatcher(dispatcher).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap();
        subject_addr.try_send(second_expired_cores_package).unwrap(); // should generate log because stream key is now unknown

        System::current().stop();
        system.run();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(record.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(record.last_data, true);
        assert_eq!(record.data, b"16 bytes of data".to_vec());
        TestLogHandler::new().exists_log_containing(&format!("WARN: ProxyServer: Discarding 16-byte packet 12345678 from an unrecognized stream key: {:?}", stream_key));
    }

    #[test]
    fn handle_client_response_payload_purges_stream_keys_for_terminal_response() {
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        subject.subs = Some(make_proxy_server_out_subs());

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
                server_name_opt: None,
            },
        );
        let client_response_payload = ClientResponsePayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket::new(vec![], 1, true),
        };
        let (dispatcher_mock, _, _) = make_recorder();
        let peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
        subject.subs.as_mut().unwrap().dispatcher = peer_actors.dispatcher.from_dispatcher_client;
        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                client_response_payload.into(),
                0,
            );

        subject.handle_client_response_payload(expired_cores_package);

        assert!(subject.keys_and_addrs.is_empty());
        assert!(subject.stream_key_routes.is_empty());
        assert!(subject.tunneled_hosts.is_empty());
    }

    #[test]
    fn proxy_server_receives_nonterminal_response_from_hopper() {
        let system = System::new("proxy_server_receives_nonterminal_response_from_hopper");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        let rate_pack_f = rate_pack(103);
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_d_wallet.clone(),
                        rate_pack_d,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_e_wallet.clone(),
                        rate_pack_e,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_f_wallet.clone(),
                        rate_pack_f,
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name_opt: None,
            },
        );
        let incoming_route_g_wallet = make_wallet("G Earning");
        let incoming_route_h_wallet = make_wallet("H Earning");
        let incoming_route_i_wallet = make_wallet("I Earning");
        let rate_pack_g = rate_pack(104);
        let rate_pack_h = rate_pack(105);
        let rate_pack_i = rate_pack(106);
        subject.route_ids_to_return_routes.insert(
            1235,
            AddReturnRouteMessage {
                return_route_id: 1235,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_g_wallet.clone(),
                        rate_pack_g,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_h_wallet.clone(),
                        rate_pack_h,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_i_wallet.clone(),
                        rate_pack_i,
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let first_client_response_payload = ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let first_exit_size = first_client_response_payload.sequenced_packet.data.len();
        let first_expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                first_client_response_payload.into(),
                0,
            );
        let routing_size = first_expired_cores_package.payload_len;
        let second_client_response_payload = ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"other data".to_vec(),
                sequence_number: 4322,
                last_data: false,
            },
        };
        let second_exit_size = second_client_response_payload.sequenced_packet.data.len();
        let second_expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
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
        let before = SystemTime::now();

        subject_addr
            .try_send(first_expired_cores_package.clone())
            .unwrap();
        subject_addr
            .try_send(second_expired_cores_package.clone())
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
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
        let first_report = accountant_recording.get_record::<ReportServicesConsumedMessage>(0);
        let first_report_timestamp = first_report.timestamp;
        assert_eq!(
            first_report,
            &ReportServicesConsumedMessage {
                timestamp: first_report_timestamp,
                exit: ExitServiceConsumed {
                    earning_wallet: incoming_route_d_wallet,
                    payload_size: first_exit_size,
                    service_rate: rate_pack_d.exit_service_rate,
                    byte_rate: rate_pack_d.exit_byte_rate
                },
                routing_payload_size: routing_size,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_e_wallet,
                        service_rate: rate_pack_e.routing_service_rate,
                        byte_rate: rate_pack_e.routing_byte_rate
                    },
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_f_wallet,
                        service_rate: rate_pack_f.routing_service_rate,
                        byte_rate: rate_pack_f.routing_byte_rate
                    }
                ]
            }
        );
        assert!(before <= first_report_timestamp && first_report_timestamp <= after);
        let second_report = accountant_recording.get_record::<ReportServicesConsumedMessage>(1);
        let second_report_timestamp = second_report.timestamp;
        let routing_size = second_expired_cores_package.payload_len;
        assert_eq!(
            second_report,
            &ReportServicesConsumedMessage {
                timestamp: second_report_timestamp,
                exit: ExitServiceConsumed {
                    earning_wallet: incoming_route_g_wallet,
                    payload_size: second_exit_size,
                    service_rate: rate_pack_g.exit_service_rate,
                    byte_rate: rate_pack_g.exit_byte_rate
                },
                routing_payload_size: routing_size,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_h_wallet,
                        service_rate: rate_pack_h.routing_service_rate,
                        byte_rate: rate_pack_h.routing_byte_rate
                    },
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_i_wallet,
                        service_rate: rate_pack_i.routing_service_rate,
                        byte_rate: rate_pack_i.routing_byte_rate
                    }
                ]
            }
        );
        assert!(before <= second_report_timestamp && second_report_timestamp <= after);
        assert_eq!(accountant_recording.len(), 2);
    }

    #[test]
    fn proxy_server_records_services_consumed_even_after_browser_stream_is_gone() {
        let system =
            System::new("proxy_server_records_services_consumed_even_after_browser_stream_is_gone");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        // subject.keys_and_addrs contains no browser stream
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_d_wallet.clone(),
                        rate_pack_d,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_e_wallet.clone(),
                        rate_pack_e,
                    ),
                ],
                protocol: ProxyProtocol::TLS,
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let client_response_payload = ClientResponsePayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let exit_size = client_response_payload.sequenced_packet.data.len();
        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                client_response_payload.into(),
                0,
            );
        let routing_size = expired_cores_package.payload_len;
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher_mock)
            .accountant(accountant)
            .build();
        let before = SystemTime::now();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let dispatcher_recording = dispatcher_log_arc.lock().unwrap();
        assert_eq!(dispatcher_recording.len(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let services_consumed_report =
            accountant_recording.get_record::<ReportServicesConsumedMessage>(0);
        let returned_timestamp = services_consumed_report.timestamp;
        assert_eq!(
            services_consumed_report,
            &ReportServicesConsumedMessage {
                timestamp: returned_timestamp,
                exit: ExitServiceConsumed {
                    earning_wallet: incoming_route_d_wallet,
                    payload_size: exit_size,
                    service_rate: rate_pack_d.exit_service_rate,
                    byte_rate: rate_pack_d.exit_byte_rate
                },
                routing_payload_size: routing_size,
                routing: vec![RoutingServiceConsumed {
                    earning_wallet: incoming_route_e_wallet,
                    service_rate: rate_pack_e.routing_service_rate,
                    byte_rate: rate_pack_e.routing_byte_rate
                }]
            }
        );
        assert!(before <= returned_timestamp && returned_timestamp <= after);
        assert_eq!(accountant_recording.len(), 1);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_dispatcher() {
        let system = System::new("proxy_server_receives_response_from_routing_services");
        let (dispatcher_mock, _, dispatcher_log_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );

        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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
                server_name_opt: Some("server.com".to_string()),
            })
            .unwrap();
        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
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
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        let rate_pack_f = rate_pack(103);
        subject.route_ids_to_return_routes.insert(
            1234,
            AddReturnRouteMessage {
                return_route_id: 1234,
                expected_services: vec![
                    ExpectedService::Exit(
                        irrelevant_public_key.clone(),
                        incoming_route_d_wallet.clone(),
                        rate_pack_d,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_e_wallet.clone(),
                        rate_pack_e,
                    ),
                    ExpectedService::Routing(
                        irrelevant_public_key.clone(),
                        incoming_route_f_wallet.clone(),
                        rate_pack_f,
                    ),
                    ExpectedService::Nothing,
                ],
                protocol: ProxyProtocol::TLS,
                server_name_opt: Some("server.com".to_string()),
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure_payload = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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
        let before = SystemTime::now();

        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();

        System::current().stop();
        system.run();
        let after = SystemTime::now();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let services_consumed_message =
            accountant_recording.get_record::<ReportServicesConsumedMessage>(0);
        let returned_timestamp = services_consumed_message.timestamp;
        assert_eq!(
            services_consumed_message,
            &ReportServicesConsumedMessage {
                timestamp: returned_timestamp,
                exit: ExitServiceConsumed {
                    earning_wallet: incoming_route_d_wallet,
                    payload_size: 0,
                    service_rate: rate_pack_d.exit_service_rate,
                    byte_rate: rate_pack_d.exit_byte_rate
                },
                routing_payload_size: routing_size,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_e_wallet,
                        service_rate: rate_pack_e.routing_service_rate,
                        byte_rate: rate_pack_e.routing_byte_rate
                    },
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_f_wallet,
                        service_rate: rate_pack_f.routing_service_rate,
                        byte_rate: rate_pack_f.routing_byte_rate
                    }
                ]
            }
        );
        assert!(before <= returned_timestamp && returned_timestamp <= after);
        assert_eq!(accountant_recording.len(), 1);
    }

    #[test]
    fn handle_dns_resolve_failure_sends_message_to_neighborhood() {
        let system = System::new("test");
        let (neighborhood_mock, _, neighborhood_log_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
                server_name_opt: Some("server.com".to_string()),
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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
            &NodeRecordMetadataMessage {
                public_key: exit_public_key,
                metadata_change: NRMetadataChange::AddUnreachableHost {
                    hostname: "server.com".to_string()
                }
            }
        );
    }

    #[test]
    fn handle_dns_resolve_failure_does_not_send_message_to_neighborhood_when_server_is_not_specified(
    ) {
        let system = System::new("test");
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let stream_key = make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr);
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
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 1234),
                dns_resolve_failure.into(),
                0,
            );
        let mut peer_actors = peer_actors_builder().neighborhood(neighborhood).build();
        peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let record_opt = neighborhood_recording.get_record_opt::<NodeRecordMetadataMessage>(0);
        assert_eq!(record_opt, None);
    }

    #[test]
    fn handle_dns_resolve_failure_logs_when_stream_key_be_gone_but_server_name_be_not() {
        init_test_logging();
        let system = System::new("test");
        let (neighborhood_mock, _, _) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
                server_name_opt: Some("server.com".to_string()),
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            format!(
                "Discarding DnsResolveFailure message for {} from an unrecognized stream key {:?}",
                "server.com", stream_key
            )
            .as_str(),
        );
    }

    #[test]
    fn handle_dns_resolve_failure_logs_when_stream_key_and_server_name_are_both_missing() {
        init_test_logging();
        let system = System::new("test");

        let (neighborhood_mock, _, _) = make_recorder();

        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );

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
                server_name_opt: None,
            },
        );

        let subject_addr: Addr<ProxyServer> = subject.start();

        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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

        System::current().stop();
        system.run();

        TestLogHandler::new().exists_log_containing(
            &format!(
                "Discarding DnsResolveFailure message for <unspecified_server> from an unrecognized stream key {:?}",
                stream_key
            )
        );
    }

    #[test]
    fn handle_dns_resolve_failure_purges_stream_keys() {
        let cryptde = main_cryptde();
        let (neighborhood_mock, _, _) = make_recorder();
        let (dispatcher_mock, _, _) = make_recorder();

        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        subject.subs = Some(make_proxy_server_out_subs());

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
                server_name_opt: None,
            },
        );
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);

        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
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
        let cryptde = main_cryptde();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = make_meaningless_stream_key();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
                server_name_opt: None,
            },
        );
        let subject_addr: Addr<ProxyServer> = subject.start();

        let client_response_payload = ClientResponsePayload_0v1 {
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

        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Hopper unbound in ProxyServer")]
    fn panics_if_hopper_is_unbound() {
        let system = System::new("panics_if_hopper_is_unbound");
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: socket_addr.clone(),
            reception_port: Some(80),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let subject_addr: Addr<ProxyServer> = subject.start();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        System::current().stop();
        system.run();
    }

    #[test]
    fn report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unrecognized(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unrecognized");
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
        let client_response_payload = ClientResponsePayload_0v1 {
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

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing("ERROR: ProxyServer: Can't report services consumed: received response with bogus return-route ID 1234. Ignoring");
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unreadable(
    ) {
        init_test_logging();
        let cryptde = main_cryptde();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_is_unreadable");
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
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
        let client_response_payload = ClientResponsePayload_0v1 {
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

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: ProxyServer: Can't report services consumed: DecryptionError(InvalidKey(\"Could not decrypt with",
        );
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn return_route_ids_expire_when_instructed() {
        init_test_logging();
        let cryptde = main_cryptde();
        let stream_key = make_meaningless_stream_key();

        let (tx, rx) = unbounded();
        thread::spawn(move || {
            let system = System::new("report_response_services_consumed_complains_and_drops_package_if_return_route_id_does_not_exist");
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
            );
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
                    server_name_opt: None,
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

        let client_response_payload = ClientResponsePayload_0v1 {
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
        let mut subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false);
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), unaffected_socket_addr);
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
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), affected_socket_addr);
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), TEST_DEFAULT_CHAIN);
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
                vec![main_cryptde().public_key(), affected_cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![affected_cryptde.public_key(), main_cryptde().public_key()],
                Component::ProxyServer,
            ),
            main_cryptde(),
            Some(make_paying_wallet(b"consuming")),
            1234,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
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

        System::current().stop();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record.route, affected_route);
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(vd) => assert_eq!(
                vd.extract(&crate::sub_lib::migrations::client_request_payload::MIGRATIONS)
                    .unwrap(),
                ClientRequestPayload_0v1 {
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: Some(String::from("tunneled.com")),
                    target_port: 443,
                    protocol: ProxyProtocol::TLS,
                    originator_public_key: alias_cryptde().public_key().clone(),
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
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), affected_socket_addr);
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), TEST_DEFAULT_CHAIN);
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
                vec![main_cryptde().public_key(), affected_cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![affected_cryptde.public_key(), main_cryptde().public_key()],
                Component::ProxyServer,
            ),
            main_cryptde(),
            Some(make_paying_wallet(b"consuming")),
            1234,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
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

        System::current().stop();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackage>(0);
        assert_eq!(record.route, affected_route);
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(vd) => assert_eq!(
                vd.extract(&crate::sub_lib::migrations::client_request_payload::MIGRATIONS)
                    .unwrap(),
                ClientRequestPayload_0v1 {
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: None,
                    target_port: HTTP_PORT,
                    protocol: ProxyProtocol::HTTP,
                    originator_public_key: alias_cryptde().public_key().clone(),
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
        let mut subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false);
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), unaffected_socket_addr);
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key =
            StreamKey::new(main_cryptde().public_key().clone(), affected_socket_addr);
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
    fn handle_stream_shutdown_msg_logs_errors_from_handling_normal_client_data() {
        init_test_logging();
        let mut subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, Some(0), false);
        let helper = IBCDHelperMock::default()
            .handle_normal_client_data_result(Err("Our help is not welcome".to_string()));
        subject.inbound_client_data_helper_opt = Some(Box::new(helper));
        let socket_addr = SocketAddr::from_str("3.4.5.6:7777").unwrap();
        let stream_key = StreamKey::new(main_cryptde().public_key().clone(), socket_addr);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let msg = StreamShutdownMsg {
            peer_addr: socket_addr,
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: true,
        };

        subject.handle_stream_shutdown_msg(msg);

        TestLogHandler::new().exists_log_containing("ERROR: ProxyServer: Our help is not welcome");
    }

    #[test]
    fn stream_shutdown_msg_populates_correct_inbound_client_data_msg() {
        let help_to_handle_normal_client_data_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, Some(0), false);
        let icd_helper = IBCDHelperMock::default()
            .handle_normal_client_data_params(&help_to_handle_normal_client_data_params_arc)
            .handle_normal_client_data_result(Ok(()));
        subject.inbound_client_data_helper_opt = Some(Box::new(icd_helper));
        let socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let stream_key = StreamKey::new(main_cryptde().public_key().clone(), socket_addr);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        subject.stream_key_routes.insert(
            stream_key,
            RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![], 0),
            },
        );
        subject
            .tunneled_hosts
            .insert(stream_key, "blah".to_string());
        let msg = StreamShutdownMsg {
            peer_addr: socket_addr,
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: HTTP_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: true,
        };
        let before = SystemTime::now();

        subject.handle_stream_shutdown_msg(msg);

        let after = SystemTime::now();
        let handle_normal_client_data =
            help_to_handle_normal_client_data_params_arc.lock().unwrap();
        let (inbound_client_data_msg, retire_stream_key) = &handle_normal_client_data[0];
        assert_eq!(inbound_client_data_msg.peer_addr, socket_addr);
        assert_eq!(inbound_client_data_msg.data, Vec::<u8>::new());
        assert_eq!(inbound_client_data_msg.last_data, true);
        assert_eq!(inbound_client_data_msg.is_clandestine, false);
        let actual_timestamp = inbound_client_data_msg.timestamp;
        assert!(before <= actual_timestamp && actual_timestamp <= after);
        assert_eq!(*retire_stream_key, true)
    }

    #[test]
    fn help_to_handle_normal_client_data_missing_consuming_wallet_and_protocol_pack_not_found() {
        let mut proxy_server = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false);
        proxy_server.subs = Some(make_proxy_server_out_subs());
        let inbound_client_data_msg = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: SocketAddr::from_str("1.2.3.4:4578").unwrap(),
            reception_port: None,
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(123),
            data: vec![],
        };

        let result = IBCDHelperReal {}.handle_normal_client_data(
            &mut proxy_server,
            inbound_client_data_msg,
            true,
        );

        assert_eq!(
            result,
            Err("No origin port specified with 0-byte non-clandestine packet: []".to_string())
        );
    }

    #[test]
    fn resolve_route_query_response_handles_error() {
        init_test_logging();
        let recorder = Recorder::new();
        let addr = recorder.start();
        let add_route_msg_sub = recipient!(&addr, AddRouteMessage);
        let logger = Logger::new("resolve_route_query_response_handles_error");
        let movable_tth_args = TTHMovableArgs {
            common_opt: None,
            logger,
            hopper_sub: recipient!(&addr, IncipientCoresPackage),
            dispatcher_sub: recipient!(&addr, TransmitDataMsg),
            accountant_sub: recipient!(&addr, ReportServicesConsumedMessage),
            add_return_route_sub: recipient!(&addr, AddReturnRouteMessage),
            retire_stream_key_sub_opt: None,
        };

        IBCDHelperReal::resolve_route_query_response(
            movable_tth_args,
            add_route_msg_sub,
            Err(MailboxError::Timeout),
        );

        TestLogHandler::new().exists_log_containing("ERROR: resolve_route_query_response_handles_error: Neighborhood refused to answer route request: MailboxError(Message delivery timed out)");
    }

    #[derive(Default)]
    struct ClientRequestPayloadFactoryMock {
        make_results: RefCell<Vec<Option<ClientRequestPayload_0v1>>>,
    }

    impl ClientRequestPayloadFactory for ClientRequestPayloadFactoryMock {
        fn make(
            &self,
            _ibcd: &InboundClientData,
            _stream_key: StreamKey,
            _cryptde: &dyn CryptDE,
            _logger: &Logger,
        ) -> Option<ClientRequestPayload_0v1> {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl ClientRequestPayloadFactoryMock {
        fn make_result(self, result: Option<ClientRequestPayload_0v1>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn help_to_handle_normal_client_data_make_payload_failed() {
        let mut proxy_server = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
        );
        proxy_server.subs = Some(make_proxy_server_out_subs());
        proxy_server.client_request_payload_factory =
            Box::new(ClientRequestPayloadFactoryMock::default().make_result(None));
        let inbound_client_data_msg = InboundClientData {
            timestamp: SystemTime::now(),
            peer_addr: SocketAddr::from_str("1.2.3.4:4578").unwrap(),
            reception_port: Some(568),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(123),
            data: vec![],
        };

        let result = IBCDHelperReal {}.handle_normal_client_data(
            &mut proxy_server,
            inbound_client_data_msg,
            true,
        );

        assert_eq!(
            result,
            Err("Couldn't create ClientRequestPayload".to_string())
        );
    }

    #[test]
    #[should_panic(
        expected = "ProxyServer should never get ShutdownStreamMsg about clandestine stream"
    )]
    fn handle_stream_shutdown_complains_about_clandestine_message() {
        let system = System::new("test");
        let subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false);
        let subject_addr = subject.start();

        subject_addr
            .try_send(StreamShutdownMsg {
                peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                stream_type: RemovedStreamType::Clandestine,
                report_to_counterpart: false,
            })
            .unwrap();

        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn proxy_server_can_be_crashed_properly_but_not_improperly() {
        let proxy_server = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, true);

        prove_that_crash_request_handler_is_hooked_up(proxy_server, CRASH_KEY);
    }

    fn make_exit_service_from_key(public_key: PublicKey) -> ExpectedService {
        ExpectedService::Exit(public_key, make_wallet("exit wallet"), rate_pack(100))
    }
}
